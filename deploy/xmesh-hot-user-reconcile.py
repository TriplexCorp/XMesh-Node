#!/usr/bin/env python3
"""Zero-downtime Xray user reconciliation for XMesh-managed inbounds.

The signed desired configuration remains authoritative. The node may add exactly
HandlerService to the existing loopback-only XMesh API so user authorization can
be reconciled in memory without restarting the managed Xray process.

Only account-list changes are eligible for the hot path. Any structural change
or RPC failure is deliberately non-fatal here: xmesh-xray-sync then observes a
different config hash and executes its existing validated full redeploy path.
"""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys

API_ADDRESS = "127.0.0.1:10085"
API_TAG = "xmesh_stats_api"
API_INBOUND_TAG = "xmesh_stats_in"
CONTAINER = "xmesh-managed-xray"
ACTIVE = Path("/var/lib/xmesh-xray-sync/config.json")
SUPPORTED_PROTOCOLS = {"vless", "vmess", "trojan", "shadowsocks", "hysteria", "masque"}


class HotUserUnavailable(RuntimeError):
    """Expected refusal of the zero-downtime path."""


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def private_api_is_safe(config: dict, *, require_handler: bool) -> bool:
    api = config.get("api")
    if not isinstance(api, dict) or api.get("tag") != API_TAG:
        return False
    services = api.get("services")
    if not isinstance(services, list) or any(not isinstance(item, str) for item in services):
        return False
    if len(services) != len(set(services)) or "StatsService" not in services:
        return False
    if require_handler and "HandlerService" not in services:
        return False
    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list):
        return False
    stats = next(
        (
            inbound
            for inbound in inbounds
            if isinstance(inbound, dict) and inbound.get("tag") == API_INBOUND_TAG
        ),
        None,
    )
    return bool(
        isinstance(stats, dict)
        and stats.get("listen") == "127.0.0.1"
        and stats.get("port") == 10085
        and stats.get("protocol") in ("dokodemo-door", "tunnel")
    )


def augment_config(config: dict) -> None:
    """Enable HandlerService only on the already-reviewed private API."""
    if not private_api_is_safe(config, require_handler=False):
        raise ValueError("Unsafe or missing XMesh private Xray API")
    services = config["api"]["services"]
    if "HandlerService" not in services:
        services.append("HandlerService")
    if not private_api_is_safe(config, require_handler=True):
        raise ValueError("HandlerService cannot be confined to the private Xray API")


def _proxy_inbounds(config: dict) -> list[dict]:
    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list):
        raise HotUserUnavailable("missing inbound list")
    proxies = []
    for inbound in inbounds:
        if not isinstance(inbound, dict):
            raise HotUserUnavailable("invalid inbound")
        if inbound.get("tag") == API_INBOUND_TAG:
            continue
        tag = inbound.get("tag")
        protocol = inbound.get("protocol")
        if not isinstance(tag, str) or not tag or protocol not in SUPPORTED_PROTOCOLS:
            raise HotUserUnavailable("unsupported managed inbound")
        proxies.append(inbound)
    if not 1 <= len(proxies) <= 2:
        raise HotUserUnavailable("unsupported managed inbound count")
    return proxies


def _account_field(inbound: dict) -> str:
    return "clients" if inbound.get("protocol") == "vless" else "users"


def _account_map(inbound: dict) -> dict[str, dict]:
    settings = inbound.get("settings")
    if not isinstance(settings, dict):
        raise HotUserUnavailable("invalid managed inbound settings")
    field = _account_field(inbound)
    entries = settings.get(field, [])
    if not isinstance(entries, list):
        raise HotUserUnavailable("invalid managed account list")
    other = "users" if field == "clients" else "clients"
    if settings.get(other) not in (None, []):
        raise HotUserUnavailable("ambiguous managed account fields")
    mapped = {}
    for entry in entries:
        if not isinstance(entry, dict):
            raise HotUserUnavailable("invalid managed account")
        email = entry.get("email")
        if (
            not isinstance(email, str)
            or not email
            or len(email) > 255
            or email in mapped
        ):
            raise HotUserUnavailable("invalid or duplicate managed account email")
        mapped[email] = entry
    return mapped


def _strip_accounts(config: dict) -> dict:
    clone = copy.deepcopy(config)
    inbounds = clone.get("inbounds")
    if not isinstance(inbounds, list):
        raise HotUserUnavailable("missing inbound list")
    for inbound in inbounds:
        if not isinstance(inbound, dict) or inbound.get("tag") == API_INBOUND_TAG:
            continue
        settings = inbound.get("settings")
        if not isinstance(settings, dict):
            raise HotUserUnavailable("invalid managed inbound settings")
        settings.pop("clients", None)
        settings.pop("users", None)
    return clone


def build_plan(old: dict, new: dict) -> dict:
    """Return deterministic remove/add operations for a user-only config diff."""
    if not private_api_is_safe(old, require_handler=True):
        raise HotUserUnavailable("running Xray has no private HandlerService")
    if not private_api_is_safe(new, require_handler=True):
        raise HotUserUnavailable("desired Xray has no private HandlerService")
    if _strip_accounts(old) != _strip_accounts(new):
        raise HotUserUnavailable("desired Xray change is structural")

    old_inbounds = {item["tag"]: item for item in _proxy_inbounds(old)}
    new_inbounds = {item["tag"]: item for item in _proxy_inbounds(new)}
    if old_inbounds.keys() != new_inbounds.keys():
        raise HotUserUnavailable("managed inbound set changed")

    remove = []
    add = []
    for tag in sorted(old_inbounds):
        old_accounts = _account_map(old_inbounds[tag])
        new_accounts = _account_map(new_inbounds[tag])
        for email, account in old_accounts.items():
            if email not in new_accounts or new_accounts[email] != account:
                remove.append({"tag": tag, "email": email})
        for email, account in new_accounts.items():
            if email not in old_accounts or old_accounts[email] != account:
                add.append({"tag": tag, "email": email, "account": account})
    return {"remove": remove, "add": add}


def _run(args: list[str], *, payload: bytes | None = None, expected: bytes | None = None) -> bytes:
    try:
        proc = subprocess.run(
            args,
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=8,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise HotUserUnavailable("HandlerService invocation failed") from exc
    if proc.returncode != 0:
        raise HotUserUnavailable("HandlerService rejected an operation")
    if expected is not None and expected not in proc.stdout:
        # Xray user CLI commands report per-user RPC failures in stdout while
        # still exiting zero. Require their explicit one-user success summary.
        raise HotUserUnavailable("HandlerService did not confirm the operation")
    return proc.stdout


def _single_user_payload(target: dict, tag: str, account: dict) -> bytes:
    inbound = next((item for item in _proxy_inbounds(target) if item["tag"] == tag), None)
    if inbound is None:
        raise HotUserUnavailable("target inbound disappeared")
    isolated = copy.deepcopy(inbound)
    settings = isolated["settings"]
    field = _account_field(isolated)
    settings[field] = [account]
    settings.pop("users" if field == "clients" else "clients", None)
    return json.dumps(
        {"inbounds": [isolated]},
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _write_active_in_place(path: Path, config: dict) -> None:
    """Preserve the bind-mount inode while making disk state match memory."""
    payload = canonical(config)
    with open(path, "r+b") as stream:
        stream.seek(0)
        stream.write(payload)
        stream.truncate()
        stream.flush()
        os.fsync(stream.fileno())
    os.chmod(path, 0o600)


def hot_reconcile_active(target: dict, active_path: Path = ACTIVE) -> bool:
    """Apply only account-list changes to live Xray. False means full fallback."""
    if not active_path.is_file():
        return False
    try:
        with open(active_path, encoding="utf-8") as stream:
            current = json.load(stream)
        plan = build_plan(current, target)
        if not plan["remove"] and not plan["add"]:
            if canonical(current) != canonical(target):
                _write_active_in_place(active_path, target)
            return True

        running = _run(
            ["docker", "inspect", "-f", "{{.State.Running}}", CONTAINER]
        ).decode("ascii", "ignore").strip()
        if running != "true":
            raise HotUserUnavailable("managed Xray is not running")

        # Remove first so a credential rotation with the same email can be
        # re-added without colliding with the existing user identity.
        for operation in plan["remove"]:
            _run(
                [
                    "docker",
                    "exec",
                    CONTAINER,
                    "xray",
                    "api",
                    "rmu",
                    f"--server={API_ADDRESS}",
                    f"-tag={operation['tag']}",
                    operation["email"],
                ],
                expected=b"Removed 1 user(s) in total.",
            )
        for operation in plan["add"]:
            _run(
                [
                    "docker",
                    "exec",
                    "-i",
                    CONTAINER,
                    "xray",
                    "api",
                    "adu",
                    f"--server={API_ADDRESS}",
                    "stdin:",
                ],
                payload=_single_user_payload(target, operation["tag"], operation["account"]),
                expected=b"Added 1 user(s) in total.",
            )

        _write_active_in_place(active_path, target)
        print(
            "XMesh hot-user reconcile: "
            f"removed={len(plan['remove'])}, added={len(plan['add'])}; Xray process preserved",
            file=sys.stderr,
        )
        return True
    except (
        HotUserUnavailable,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        json.JSONDecodeError,
    ) as exc:
        # Do not leak credentials or subprocess output. Leaving ACTIVE unchanged
        # makes xmesh-xray-sync take its existing full validated redeploy path.
        print(f"XMesh hot-user reconcile fallback: {exc}", file=sys.stderr)
        return False


def _load(path: str) -> dict:
    with open(path, encoding="utf-8") as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise HotUserUnavailable("configuration must be an object")
    return value


def main() -> int:
    # Developer/CI utility. Production calls augment_config/hot_reconcile_active
    # from xmesh-policy-guard.py after signed-policy verification.
    if len(sys.argv) not in (3, 4):
        print("usage: xmesh-hot-user-reconcile.py augment CONFIG | plan OLD NEW", file=sys.stderr)
        return 2
    try:
        if sys.argv[1] == "augment" and len(sys.argv) == 3:
            config = _load(sys.argv[2])
            augment_config(config)
            Path(sys.argv[2]).write_bytes(canonical(config))
            return 0
        if sys.argv[1] == "plan" and len(sys.argv) == 4:
            print(json.dumps(build_plan(_load(sys.argv[2]), _load(sys.argv[3])), separators=(",", ":")))
            return 0
    except (HotUserUnavailable, OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as exc:
        print(f"hot-user reconcile unavailable: {exc}", file=sys.stderr)
        return 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
