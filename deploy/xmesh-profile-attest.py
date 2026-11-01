#!/usr/bin/env python3
"""Attest a running Xray instance against its signed desired policy.

The local autonomous policy guard may REMOVE clients from the signed base
configuration. It must never add clients or modify transport/routing fields.

For commercial zero-downtime user reconciliation the node may additionally
enable HandlerService on the already signed loopback-only XMesh API. This is
the sole local service augmentation accepted by attestation.
"""
import hashlib
import importlib.util
import json
import pathlib
import re
import subprocess
import sys

STATE = pathlib.Path("/var/lib/xmesh-xray-sync")
ACTIVE = STATE / "config.json"
ENVELOPE = STATE / "policy-envelope.json"
GUARD = pathlib.Path("/usr/local/libexec/xmesh-policy-guard.py")


def canonical(value):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _normalise_private_api(base_rest, active_rest):
    """Allow exactly one local HandlerService addition and nothing broader."""
    base_api = base_rest.get("api")
    active_api = active_rest.get("api")
    if not isinstance(base_api, dict) or not isinstance(active_api, dict):
        return False
    if base_api.get("tag") != "xmesh_stats_api" or active_api.get("tag") != "xmesh_stats_api":
        return False
    base_services = base_api.get("services")
    active_services = active_api.get("services")
    if not isinstance(base_services, list) or not isinstance(active_services, list):
        return False
    if any(not isinstance(item, str) for item in base_services + active_services):
        return False
    if len(base_services) != len(set(base_services)) or len(active_services) != len(set(active_services)):
        return False
    if "StatsService" not in base_services:
        return False
    if "HandlerService" in base_services:
        allowed = set(base_services)
    else:
        allowed = set(base_services) | {"HandlerService"}
    if set(active_services) != allowed:
        return False

    # Normalise only the service-list delta; every other API field must remain
    # byte-for-byte equivalent after canonical JSON encoding.
    active_api_copy = dict(active_api)
    active_api_copy["services"] = list(base_services)
    active_rest["api"] = active_api_copy
    return True


def is_restricted_copy(base, active):
    if not isinstance(base, dict) or not isinstance(active, dict):
        return False
    base_rest = dict(base)
    active_rest = dict(active)
    original_inbounds = base_rest.pop("inbounds", None)
    running_inbounds = active_rest.pop("inbounds", None)

    # HandlerService is a node-local operational capability, never a license to
    # change the signed API tag, listener, routing, or any other application.
    if base_rest.get("api") != active_rest.get("api"):
        if not _normalise_private_api(base_rest, active_rest):
            return False

    if canonical(base_rest) != canonical(active_rest):
        return False
    if not isinstance(original_inbounds, list) or not isinstance(running_inbounds, list):
        return False
    if len(original_inbounds) != len(running_inbounds):
        return False
    for original, running in zip(original_inbounds, running_inbounds):
        if not isinstance(original, dict) or not isinstance(running, dict):
            return False
        original = dict(original)
        running = dict(running)
        old_settings = original.pop("settings", None)
        new_settings = running.pop("settings", None)
        if canonical(original) != canonical(running):
            return False
        if not isinstance(old_settings, dict) or not isinstance(new_settings, dict):
            return False
        old_settings = dict(old_settings)
        new_settings = dict(new_settings)
        # Proxy accounts may be stored in clients (VLESS) or users (Hysteria,
        # VMess, Trojan, Shadowsocks, MASQUE). Both may only SHRINK after offline
        # enforcement; account additions or edits fail attestation.
        for account_field in ("clients", "users"):
            original_accounts = old_settings.pop(account_field, None)
            running_accounts = new_settings.pop(account_field, None)
            if original_accounts is None and running_accounts is None:
                continue
            if not isinstance(original_accounts, list) or not isinstance(running_accounts, list):
                return False
            remaining = [canonical(account) for account in original_accounts]
            for account in running_accounts:
                encoded = canonical(account)
                if encoded not in remaining:
                    return False
                remaining.remove(encoded)
        if canonical(old_settings) != canonical(new_settings):
            return False
    return True


def check():
    if not GUARD.is_file() or not ENVELOPE.is_file():
        return None, "policy_missing"
    if not ACTIVE.is_file():
        return None, "active_config_missing"
    try:
        spec = importlib.util.spec_from_file_location("xmesh_policy_guard", GUARD)
        if spec is None or spec.loader is None:
            return None, "guard_unavailable"
        guard = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guard)
        envelope = json.loads(ENVELOPE.read_text(encoding="utf-8"))
        node_id = envelope["policy"]["nodeId"]
        guard.verify_envelope(envelope, STATE, node_id, first_contact=False)
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        AttributeError,
        subprocess.SubprocessError,
    ):
        return None, "policy_invalid"
    revision = envelope["policy"].get("configSha256")
    if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}", revision):
        return None, "revision_invalid"
    if hashlib.sha256(canonical(envelope["config"])).hexdigest() != revision:
        return None, "policy_hash_mismatch"
    try:
        running = json.loads(ACTIVE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, "active_config_invalid"
    if not is_restricted_copy(envelope["config"], running):
        return None, "active_config_mismatch"
    try:
        proc = subprocess.run(
            ["docker", "inspect", "xmesh-managed-xray"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
        )
        item = json.loads(proc.stdout)[0]
        if item.get("State", {}).get("Running") is not True:
            return None, "xray_stopped"
        mounts = item.get("Mounts", [])
        if not any(
            mount.get("Destination") == "/etc/xray/config.json"
            and pathlib.Path(mount.get("Source", "")).resolve() == ACTIVE.resolve()
            and mount.get("RW") is False
            for mount in mounts
        ):
            return None, "mount_mismatch"
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
        subprocess.SubprocessError,
    ):
        return None, "container_unavailable"
    return revision, "verified"


def main():
    revision, status = check()
    if "--json" in sys.argv[1:]:
        print(json.dumps({"revision": revision, "status": status}, separators=(",", ":")))
        return 0
    if revision is None:
        print("XMesh profile attestation: " + status, file=sys.stderr)
        return 1
    print(revision)
    return 0


if __name__ == "__main__":
    sys.exit(main())
