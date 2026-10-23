#!/usr/bin/env python3
"""Offline XMesh VLESS admission guard (Python stdlib + OpenSSL).

The node trusts the panel's Ed25519 policy key only on the first successfully
TLS-authenticated HTTPS desired-config response. That key is pinned thereafter.
Neither cached JSON nor unauthenticated network errors can restore a denied UUID.
Local quota reservations are conservative and bounded, but global exact quota
accounting requires a centrally coordinated lease ledger.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time

PUBLIC_DER_PREFIX = bytes.fromhex("302a300506032b6570032100")
USER_PATTERN = re.compile(r"^user>>>xmesh-u([1-9][0-9]*)--([^>]+)>>>traffic>>>(uplink|downlink)$")
HEX_KEY = re.compile(r"^[0-9a-f]{64}$")
HEX_SIGNATURE = re.compile(r"^[0-9a-f]{128}$")
HEX_SHA = re.compile(r"^[0-9a-f]{64}$")
MAX_USERS = 4096


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def write_atomic(path, content):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".xmesh-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def load_json(path):
    with open(path, encoding="utf-8") as stream:
        return json.load(stream)


def check_signature(policy, signature, pubkey):
    if not isinstance(pubkey, str) or not HEX_KEY.fullmatch(pubkey):
        raise ValueError("Invalid panel signing identity")
    if not isinstance(signature, str) or not HEX_SIGNATURE.fullmatch(signature):
        raise ValueError("Invalid policy signature")
    der = PUBLIC_DER_PREFIX + bytes.fromhex(pubkey)
    pem = b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(der).replace(b"\n", b"") + b"\n-----END PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory(prefix="xmesh-policy-") as tmp:
        root = Path(tmp)
        (root / "public.pem").write_bytes(pem)
        (root / "policy").write_bytes(canonical(policy))
        (root / "sig").write_bytes(bytes.fromhex(signature))
        proc = subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin",
                               "-inkey", str(root / "public.pem"), "-rawin",
                               "-in", str(root / "policy"), "-sigfile", str(root / "sig")],
                              capture_output=True, timeout=5, check=False)
        if proc.returncode:
            raise ValueError("Policy signature verification failed")


def verify_envelope(document, state_dir, node_id, *, first_contact=False, now_ms=None):
    if not isinstance(document, dict):
        raise ValueError("Policy envelope is not an object")
    policy = document.get("policy")
    key = document.get("policyPublicKey")
    if not isinstance(policy, dict) or policy.get("version") != 1:
        raise ValueError("Unknown policy version")
    if type(policy.get("nodeId")) is not int or policy["nodeId"] != node_id:
        raise ValueError("Policy node identity mismatch")
    issued, expiry = policy.get("issuedAtMs"), policy.get("validUntilMs")
    if type(issued) is not int or type(expiry) is not int or expiry <= issued or expiry - issued > 7 * 86400000:
        raise ValueError("Invalid policy lifetime")
    if first_contact:
        now = int(time.time() * 1000) if now_ms is None else now_ms
        if issued > now + 300000 or expiry < now:
            raise ValueError("Stale or future signed policy")
    pinned = state_dir / "policy-public-key"
    if pinned.exists():
        if not pinned.is_file() or pinned.read_text(encoding="ascii").strip() != key:
            raise ValueError("Panel policy identity changed; explicit re-enrollment required")
    elif not first_contact:
        raise ValueError("No pinned policy signing identity")
    check_signature(policy, document.get("policySignature"), key)
    digest = policy.get("configSha256")
    if not isinstance(digest, str) or not HEX_SHA.fullmatch(digest):
        raise ValueError("Invalid policy configuration digest")
    config = document.get("config")
    if not isinstance(config, dict) or hashlib.sha256(canonical(config)).hexdigest() != digest:
        raise ValueError("Signed policy does not match Xray configuration")
    users = policy.get("users")
    if not isinstance(users, list) or len(users) > MAX_USERS:
        raise ValueError("Invalid policy user list")
    seen_id, seen_uuid = set(), set()
    for user in users:
        if not isinstance(user, dict):
            raise ValueError("Malformed user policy")
        user_id = user.get("userId")
        uid = user.get("xrayId")
        expiry_ms = user.get("expireAtMs")
        panel_usage = user.get("panelUsedBytes")
        budget = user.get("offlineBudgetBytes")
        if type(user_id) is not int or user_id <= 0 or not isinstance(uid, str) or not re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", uid):
            raise ValueError("Invalid policy user identity")
        if type(expiry_ms) is not int or expiry_ms < 0 or type(panel_usage) is not int or panel_usage < 0:
            raise ValueError("Invalid user expiry or usage")
        if budget is not None and (type(budget) is not int or not 0 <= budget <= 64 * 1024 * 1024):
            raise ValueError("Invalid offline budget")
        if user_id in seen_id or uid in seen_uuid:
            raise ValueError("Duplicate user policy")
        seen_id.add(user_id)
        seen_uuid.add(uid)
    # A signed policy may only list users actually in the signed configuration.
    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list) or len(inbounds) not in (1, 2):
        raise ValueError("Unsupported Xray inbound layout")
    if len(inbounds) == 2:
        api = inbounds[1]
        if (api.get("tag") != "xmesh_stats_in" or api.get("listen") != "127.0.0.1"
                or api.get("port") != 10085 or api.get("protocol") != "dokodemo-door"
                or config.get("api", {}).get("tag") != "xmesh_stats_api"):
            raise ValueError("Unsafe private stats listener")
    if inbounds[0].get("listen") != "127.0.0.1" or not (
            type(inbounds[0].get("port")) is int and 1 <= inbounds[0]["port"] <= 65535):
        raise ValueError("Untrusted Xray listener/port")
    if inbounds[0]["port"] != document.get("port"):
        raise ValueError("Policy port and Xray listener disagree")
    clients = inbounds[0].get("settings", {}).get("clients", [])
    if not isinstance(clients, list) or {c.get("id") for c in clients} != seen_uuid:
        raise ValueError("Signed policy and VLESS clients differ")
    if not pinned.exists():
        # TOFU is permitted only for a fresh, TLS-validated signed response.
        write_atomic(pinned, (key + "\n").encode("ascii"))
    return policy


def get_counters():
    """Return (monotonic Xray per-user raw counters, runtime ID) or (None,None)."""
    try:
        container = subprocess.run(["docker", "inspect", "-f",
                                    "{{.Id}} {{.State.StartedAt}}", "xmesh-managed-xray"],
                                   capture_output=True, text=True, timeout=5, check=True)
        runtime_id = container.stdout.strip()
        result = subprocess.run(["docker", "exec", "xmesh-managed-xray", "xray", "api",
                                 "statsquery", "--server=127.0.0.1:10085",
                                 "-pattern", "user>>>xmesh-u"],
                                capture_output=True, text=True, timeout=7, check=True)
        payload = json.loads(result.stdout)
        stats = payload.get("stat", [])
        if not isinstance(stats, list) or len(stats) > 12000:
            raise ValueError("Invalid Xray counters")
        grouped = {}
        for row in stats:
            if not isinstance(row, dict):
                continue
            match = USER_PATTERN.fullmatch(row.get("name", ""))
            if match is None:
                continue
            val = row.get("value")
            if type(val) is not int or not 0 <= val <= (1 << 63) - 1:
                continue
            user_id = match.group(1)
            grouped[user_id] = grouped.get(user_id, 0) + val
        return grouped, runtime_id
    except (OSError, subprocess.SubprocessError, ValueError, json.JSONDecodeError):
        return None, None


def enforce(policy, config, ledger, counters, runtime_id, offline, now_ms):
    """Pure admission decision; caller persists the ledger before applying JSON."""
    if not isinstance(ledger, dict):
        ledger = {}
    history = ledger.get("users", {})
    if not isinstance(history, dict):
        history = {}
    ledger["users"] = history
    ledger["maxSeenMs"] = max(int(ledger.get("maxSeenMs", 0)), now_ms)
    now_ms = ledger["maxSeenMs"]
    if counters is not None:
        prev_runtime = ledger.get("runtimeId")
        if prev_runtime != runtime_id:
            # A restarted container has fresh, lower Xray cumulative counters.
            for record in history.values():
                record["last"] = 0
        ledger["runtimeId"] = runtime_id
        for user_id, value in counters.items():
            record = history.setdefault(user_id, {})
            last = max(0, int(record.get("last", 0)))
            record["total"] = max(0, int(record.get("total", 0))) + (
                value - last if value >= last else value)
            record["last"] = value
    users = policy["users"]
    allowed = {}
    denied = {}
    for user in users:
        key = str(user["userId"])
        record = history.setdefault(key, {})
        total = max(0, int(record.get("total", 0)))
        previous = int(record.get("panelUsedBytes", -1))
        budget = user["offlineBudgetBytes"]
        # Only fresh authoritative accounting can replenish an offline lease.
        # Repeated identical pulls cannot reset a locally depleted budget.
        if "anchor" not in record or (not offline and user["panelUsedBytes"] > previous):
            record["anchor"] = total
            record["budget"] = budget
            record["panelUsedBytes"] = user["panelUsedBytes"]
            record["revoked"] = False
        else:
            if budget is None:
                record["budget"] = None
            elif record.get("budget") is not None:
                record["budget"] = min(int(record["budget"]), budget)
        reason = None
        if user["expireAtMs"] and now_ms >= user["expireAtMs"]:
            reason = "expired"
        elif offline and budget is not None:
            if counters is None:
                reason = "unverified-traffic-counter"
            elif total - int(record.get("anchor", 0)) >= int(record.get("budget") or 0):
                reason = "quota"
        if offline and now_ms > policy["validUntilMs"] and budget is not None:
            reason = "policy-expired"
        if reason and offline:
            # Persist quota denial across reconnects and process restarts.
            record["revoked"] = True
        if record.get("revoked"):
            reason = reason or "locally-revoked"
        if reason:
            denied[user["xrayId"]] = reason
        else:
            allowed[user["xrayId"]] = user["userId"]
    effective = json.loads(json.dumps(config))
    inbound = effective["inbounds"][0]
    clients = inbound.get("settings", {}).get("clients", [])
    inbound["settings"]["clients"] = [c for c in clients if c.get("id") in allowed]
    return effective, ledger, denied


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["prepare", "offline", "commit"])
    parser.add_argument("--state", required=True)
    parser.add_argument("--node-id", type=int, required=True)
    parser.add_argument("--response")
    parser.add_argument("--output")
    parser.add_argument("--now-ms", type=int)
    parser.add_argument("--stats-file", help="Test-only deterministic counters")
    args = parser.parse_args()
    state = Path(args.state)
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.action == "commit":
        pending = state / "policy-envelope.json.pending"
        if not pending.exists():
            raise ValueError("Missing validated pending policy snapshot")
        # A single atomic rename keeps config and policy bound together.
        os.replace(pending, state / "policy-envelope.json")
        return
    now_ms = int(time.time() * 1000) if args.now_ms is None else args.now_ms
    if not args.output:
        raise ValueError("Missing output file")
    if args.action == "prepare":
        if not args.response:
            raise ValueError("Missing authenticated HTTPS response")
        doc = load_json(args.response)
        policy = verify_envelope(doc, state, args.node_id, first_contact=True, now_ms=now_ms)
        base = doc["config"]
    else:
        doc = load_json(state / "policy-envelope.json")
        policy = verify_envelope(doc, state, args.node_id)
        base = doc["config"]
    ledger_file = state / "policy-usage.json"
    ledger = load_json(ledger_file) if ledger_file.exists() else {}
    if args.stats_file:
        counters, runtime_id = load_json(args.stats_file), "unit-test"
    else:
        counters, runtime_id = get_counters()
    effective, ledger, denied = enforce(policy, base, ledger, counters, runtime_id,
                                        args.action == "offline", now_ms)
    write_atomic(ledger_file, canonical(ledger))
    write_atomic(args.output, canonical(effective))
    if args.action == "prepare":
        write_atomic(state / "policy-envelope.json.pending", canonical(doc))
    print("XMesh policy: " + ("offline" if args.action == "offline" else "connected")
          + f", authorized={len(effective['inbounds'][0]['settings']['clients'])}, blocked={len(denied)}",
          file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError) as exc:
        print(f"XMesh offline policy rejected: {exc}", file=sys.stderr)
        sys.exit(1)
