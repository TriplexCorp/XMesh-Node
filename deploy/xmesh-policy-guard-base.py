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
import fcntl
import hashlib
import grp
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
from urllib.parse import unquote

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


def configured_accounts(inbound):
    """Map signed Xray runtime entries to panel UUIDs; fail closed on unknown users.

    Entries with an xmesh-u<ID>--<tag> email identify the panel user even when
    the transport credential is not a UUID (e.g. Shadowsocks 2022). For
    VLESS's older email-less clients, the UUID itself remains authoritative.
    """
    protocol = inbound.get("protocol")
    if protocol not in ("vless", "vmess", "trojan", "shadowsocks", "hysteria", "masque"):
        raise ValueError("Unsupported signed proxy protocol")
    field = "clients" if protocol == "vless" else "users"
    settings = inbound.get("settings")
    if not isinstance(settings, dict):
        raise ValueError("Invalid signed proxy settings")
    entries = settings.get(field)
    if not isinstance(entries, list):
        raise ValueError("Invalid signed proxy accounts")
    key = {"vless": "id", "vmess": "id", "trojan": "password",
           "shadowsocks": "password", "hysteria": "auth",
           "masque": "pass"}[protocol]
    return entries, key


def account_uuid(entry, credential_key, identities):
    if not isinstance(entry, dict):
        return None
    email = entry.get("email")
    if isinstance(email, str) and email.startswith("xmesh-u"):
        match = re.fullmatch(r"xmesh-u([1-9][0-9]*)--[^\s]+", email)
        if match is None:
            return None
        user = identities.get(int(match.group(1)))
        if user is None:
            return None
        credential = entry.get(credential_key)
        if not isinstance(credential, str) or not credential:
            return None
        # Shadowsocks 2022 has an independent per-user PSK.
        if identities["_protocol"] == "shadowsocks" and identities["_method"].startswith("2022-"):
            return user
        if credential != user:
            return None
        return user
    credential = entry.get(credential_key)
    if identities.get("_protocol") == "shadowsocks" and identities.get("_method", "").startswith("2022-"):
        return None
    return credential if isinstance(credential, str) else None


def verify_envelope(document, state_dir, node_id, *, first_contact=False, now_ms=None):
    if not isinstance(document, dict):
        raise ValueError("Policy envelope is not an object")
    policy = document.get("policy")
    key = document.get("policyPublicKey")
    if not isinstance(policy, dict) or policy.get("version") not in (1, 2):
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
    # Never accept an older still-valid signed snapshot after a newer policy
    # has been committed. Replaying it could restore previously revoked UUIDs.
    if first_contact:
        committed = state_dir / "policy-envelope.json"
        if committed.exists():
            previous = load_json(committed)
            old_policy = previous.get("policy", {})
            if old_policy.get("version") == 2 and policy.get("version") != 2:
                raise ValueError("Quota protocol downgrade rejected")
            old_issued = old_policy.get("issuedAtMs")
            if type(old_issued) is not int:
                raise ValueError("Stored policy revision is invalid")
            if issued < old_issued:
                raise ValueError("Signed policy rollback rejected")
            if issued == old_issued and canonical(document) != canonical(previous):
                raise ValueError("Conflicting signed policy revision")
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
        limit = user.get("limitBytes", 0)
        budget = user.get("offlineBudgetBytes")
        if type(user_id) is not int or user_id <= 0 or not isinstance(uid, str) or not re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", uid):
            raise ValueError("Invalid policy user identity")
        if type(expiry_ms) is not int or expiry_ms < 0 or type(panel_usage) is not int or panel_usage < 0:
            raise ValueError("Invalid user expiry or usage")
        if type(limit) is not int or limit < 0:
            raise ValueError("Invalid signed subscription traffic limit")
        if budget is not None and (type(budget) is not int or not 0 <= budget <= 64 * 1024 * 1024):
            raise ValueError("Invalid offline budget")
        if policy["version"] == 2 and limit > 0 and not isinstance(user.get("quotaReservation"), dict):
            raise ValueError("Limited v2 user requires a signed quota reservation")
        if user_id in seen_id or uid in seen_uuid:
            raise ValueError("Duplicate user policy")
        seen_id.add(user_id)
        seen_uuid.add(uid)
    # Validate both signed proxy listeners (if present), plus the private stats
    # listener. The policy keeps one user row per person, not per transport.
    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list) or not 1 <= len(inbounds) <= 3:
        raise ValueError("Unsupported Xray inbound layout")
    has_stats = inbounds[-1].get("tag") == "xmesh_stats_in"
    if has_stats:
        api = inbounds[-1]
        if (api.get("listen") != "127.0.0.1" or api.get("port") != 10085
                or api.get("protocol") != "dokodemo-door"
                or config.get("api", {}).get("tag") != "xmesh_stats_api"):
            raise ValueError("Unsafe private stats listener")
    proxies = inbounds[:-1] if has_stats else inbounds
    if not 1 <= len(proxies) <= 2 or (len(proxies) == 2 and not has_stats):
        raise ValueError("Unsupported managed proxy layout")

    def transport_type(inbound):
        stream = inbound.get("streamSettings", {})
        if not isinstance(stream, dict):
            raise ValueError("Invalid signed transport")
        network = stream.get("network", "raw")
        alpn = stream.get("tlsSettings", {}).get("alpn", [])
        protocol = inbound.get("protocol")
        if protocol == "hysteria" and network == "hysteria" and stream.get("security") == "tls":
            return "udp"
        if (protocol in ("vless", "vmess", "trojan", "shadowsocks")
                and network in ("raw", "tcp", "xhttp", "grpc", "ws", "httpupgrade")
                and not (network == "xhttp" and "h3" in alpn)):
            return "tcp"
        return "other"

    if len(proxies) == 2 and {transport_type(item) for item in proxies} != {"tcp", "udp"}:
        raise ValueError("Managed pair requires one TCP proxy and one Hysteria2 listener")

    identities = {u["userId"]: u["xrayId"] for u in users}
    authorized = set()
    tags = set()
    for index, inbound in enumerate(proxies):
        port = inbound.get("port")
        if (inbound.get("listen") != "127.0.0.1"
                or type(port) is not int or not 1 <= port <= 65535
                or port == 10085):
            raise ValueError("Untrusted Xray listener/port")
        if (index == 0 and port != document.get("port")
                or index == 1 and port != document.get("port", 0) + 1):
            raise ValueError("Policy port and Xray listener disagree")
        tag = inbound.get("tag")
        if len(proxies) == 2 and (not isinstance(tag, str) or not tag or tag in tags
                                  or tag == "xmesh_stats_in"):
            raise ValueError("Duplicate or missing managed inbound tag")
        tags.add(tag)
        accounts, credential_key = configured_accounts(inbound)
        scoped = dict(identities)
        scoped["_protocol"] = inbound["protocol"]
        scoped["_method"] = inbound["settings"].get("method", "")
        resolved = [account_uuid(account, credential_key, scoped) for account in accounts]
        if (None in resolved or len(set(resolved)) != len(resolved)
                or any(uuid not in seen_uuid for uuid in resolved)):
            raise ValueError("Signed policy and proxy accounts differ")
        if len(proxies) == 2:
            # For managed multi-inbound profiles, do not allow an account
            # to masquerade as being provisioned for a different inbound tag.
            from urllib.parse import quote
            suffix = "--" + quote(tag, safe="-_.~")
            if any(not isinstance(entry.get("email"), str)
                   or not entry["email"].endswith(suffix) for entry in accounts):
                raise ValueError("Signed policy and proxy accounts differ")
        authorized.update(resolved)
    if authorized != seen_uuid:
        raise ValueError("Signed policy and proxy accounts differ")
    if not pinned.exists():
        # TOFU is permitted only for a fresh, TLS-validated signed response.
        write_atomic(pinned, (key + "\n").encode("ascii"))
    return policy


def get_counters():
    """Return user totals, runtime identity and raw per-inbound Xray counters."""
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
        inbound = {}
        for row in stats:
            if not isinstance(row, dict):
                continue
            match = USER_PATTERN.fullmatch(row.get("name", ""))
            if match is None:
                continue
            raw_value = row.get("value")
            if type(raw_value) is int:
                val = raw_value
            elif isinstance(raw_value, str) and re.fullmatch(r"[0-9]{1,19}", raw_value):
                val = int(raw_value)
            else:
                continue
            if not 0 <= val <= (1 << 63) - 1:
                continue
            user_id, tag, direction = match.groups()
            tag = unquote(tag, encoding="utf-8", errors="strict")
            if not tag or len(tag) > 128 or any(ord(c) < 32 for c in tag):
                continue
            raw = inbound.setdefault((user_id, tag), {"uplink": 0, "downlink": 0})
            raw[direction] = val
        if len(inbound) > MAX_USERS:
            raise ValueError("Too many per-inbound counters")
        grouped = {}
        for (user_id, _), values in inbound.items():
            grouped[user_id] = grouped.get(user_id, 0) + sum(values.values())
        return grouped, runtime_id, inbound
    except (OSError, subprocess.SubprocessError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
        print(f"XMesh StatsService unavailable ({type(exc).__name__}); user traffic cannot be verified", file=sys.stderr)
        return None, None, None


def verified_snapshot_scope(document, state_dir, node_id):
    """Resolve (user, inbound) permissions ONLY from an already committed policy.

    verify_envelope checks Ed25519 signature, pinned signing key, node identity,
    bound Xray config digest and exact account provisioning. A prepared but not
    committed policy must never authorize telemetry publication.
    """
    policy = verify_envelope(document, state_dir, node_id)
    ids = {user["xrayId"]: user["userId"] for user in policy["users"]}
    identity_map = {user["userId"]: user["xrayId"] for user in policy["users"]}
    permitted = {}
    for inbound in document["config"]["inbounds"]:
        if inbound.get("tag") == "xmesh_stats_in":
            continue
        tag = inbound.get("tag")
        # An empty or absent tag can never be authorized by Nexus's
        # inbound-tag verifier: do not try to publish its traffic.
        if tag is None:
            # Older valid single-inbound profiles have no explicit tag.
            # They may still be admitted by Xray, but Nexus cannot authorize
            # a per-inbound counter without an actual tag. Withhold those
            # user samples rather than breaking policy commit or guessing.
            continue
        if not isinstance(tag, str) or not tag or len(tag.encode("utf-8")) > 128:
            raise ValueError("Signed proxy inbound cannot be metered without a valid tag")
        accounts, credential_key = configured_accounts(inbound)
        scoped = dict(identity_map)
        scoped["_protocol"] = inbound["protocol"]
        scoped["_method"] = inbound["settings"].get("method", "")
        for account in accounts:
            policy_uuid = account_uuid(account, credential_key, scoped)
            user_id = ids.get(policy_uuid)
            if user_id is None:
                raise ValueError("Signed proxy account is not provisioned for metering")
            permitted.setdefault(user_id, set()).add(tag)
    return permitted


def committed_snapshot_scope(state_dir, node_id):
    """Never trust pending policy or cached counters as proof of assignment."""
    committed = state_dir / "policy-envelope.json"
    if not committed.is_file():
        return None
    return verified_snapshot_scope(load_json(committed), state_dir, node_id)


def applied_revocation_proofs(policy, effective, ledger):
    """Mark lease-bound stop after the caller has verified Xray deployment.

    This is NOT a refundable final meter. The new Xray process must be
    running with the user's credential absent; outstanding offline budget
    remains held centrally even after this acknowledgement.
    """
    if not isinstance(effective, dict) or not isinstance(effective.get("inbounds"), list):
        raise ValueError("Missing applied Xray config for revocation proof")
    records = ledger.get("users", {})
    if not isinstance(records, dict):
        raise ValueError("Invalid durable Node journal")
    identities = {u["userId"]: u["xrayId"] for u in policy["users"]}
    for user in policy["users"]:
        revoke = user.get("quotaRevocation")
        if revoke is None:
            continue
        record = records.get(str(user["userId"]))
        if not isinstance(record, dict) or record.get("quotaRevocation") != revoke:
            raise ValueError("Uncommitted signed revocation cannot be acknowledged")
        for inbound in effective["inbounds"]:
            if inbound.get("tag") == "xmesh_stats_in":
                continue
            accounts, credential_key = configured_accounts(inbound)
            scoped = dict(identities)
            scoped["_protocol"] = inbound["protocol"]
            scoped["_method"] = inbound["settings"].get("method", "")
            if any(account_uuid(entry, credential_key, scoped) == user["xrayId"]
                   for entry in accounts):
                raise ValueError("Revoked Xray credential is still provisioned")
        used = record.get("total")
        if type(used) is not int or not 0 <= used < (1 << 63):
            raise ValueError("Invalid durable stopped-user counter")
        record["quotaRevocationApplied"] = {
            **revoke,
            "revision": user["quotaReservation"]["revision"],
            "usedBytes": used,
        }
    return ledger


def store_metrics_snapshot(ledger, node_id, now_ms, permitted):
    """Expose only currently signed accounts/inbounds, retaining ALL ledger history.

    User-wide counters include each currently authorized user's historical
    cumulative inbound totals, even when some inbounds have been retired.
    These totals must never decrease when a tag is removed: Nexus persists
    per-user monotonic baselines separately from per-inbound baselines.
    The per-inbound publication is restricted to current signed (user, tag)
    pairs. No historical entry is deleted from the root-owned ledger.
    """
    if not isinstance(permitted, dict):
        raise ValueError("Committed signed telemetry scope is required")
    rows = []
    totals = {}
    for key, value in ledger.get("inbounds", {}).items():
        try:
            user_id, tag = json.loads(key)
            if type(user_id) is not int or user_id <= 0 or not isinstance(tag, str):
                continue
            # Ignore history for users no longer assigned to this node.
            allowed_tags = permitted.get(user_id)
            if not isinstance(allowed_tags, set) or not allowed_tags:
                continue
            uplink = int(value["totalUp"])
            downlink = int(value["totalDown"])
            if not 0 <= uplink < (1 << 63) or not 0 <= downlink < (1 << 63):
                raise ValueError("Out-of-range durable traffic counter")
        except (ValueError, TypeError, KeyError):
            continue
        total = totals.setdefault(user_id, [0, 0])
        total[0] += uplink
        total[1] += downlink
        if tag in allowed_tags:
            rows.append({"userId": user_id, "inboundTag": tag,
                         "uplinkBytes": uplink, "downlinkBytes": downlink})
    rows.sort(key=lambda row: (row["userId"], row["inboundTag"]))
    user_rows = [{"userId": user_id, "uplinkBytes": pair[0],
                  "downlinkBytes": pair[1]} for user_id, pair in sorted(totals.items())]
    if any(not 0 <= value < (1 << 63) for row in user_rows
           for field, value in row.items() if field != "userId"):
        raise ValueError("Aggregated durable traffic counter overflow")
    # Receipts are derived from the same durable root-owned ledger as the
    # admission decision, not from the untrusted telemetry uploader. Only
    # currently signed, assigned identities can be exported.
    receipts = []
    for user_id in sorted(totals):
        record = ledger.get("users", {}).get(str(user_id), {})
        if not isinstance(record, dict):
            continue
        lease = record.get("quotaReservation")
        if not isinstance(lease, dict):
            continue
        used = record.get("total")
        if type(used) is not int or not 0 <= used < (1 << 63):
            raise ValueError("Invalid durable quota usage")
        receipts.append({"userId": user_id, "epoch": lease["epoch"],
                         "meterEpoch": lease["meterEpoch"],
                         "reservationId": lease["reservationId"],
                         "usedBytes": used})
    stop_receipts = []
    for user_id in sorted(totals):
        record = ledger.get("users", {}).get(str(user_id), {})
        proof = record.get("quotaRevocationApplied")
        if proof is not None:
            if not isinstance(proof, dict) or type(proof.get("usedBytes")) is not int:
                raise ValueError("Invalid durable revocation proof")
            stop_receipts.append({"userId": user_id, **proof})
    payload = {"nodeId": node_id, "sampledAtMs": now_ms,
               "userInboundTraffic": rows, "userTraffic": user_rows,
               "quotaReceipts": receipts, "quotaStopReceipts": stop_receipts}
    snapshot = Path("/run/xmesh-node-user-metrics.json")
    if not snapshot.parent.is_dir():
        return
    write_atomic(snapshot, canonical(payload))
    try:
        group_id = grp.getgrnam("xmesh-metrics").gr_gid
        os.chown(snapshot, 0, group_id)
        os.chmod(snapshot, 0o640)
    except KeyError:
        # A partially installed metrics agent cannot access the file.
        pass


def integrate_counters(ledger, counters, runtime_id, now_ms, inbound_counters=None):
    """Accumulate durable per-user bytes without changing admission policy."""
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
            for record in ledger.get("inbounds", {}).values():
                record["lastUp"] = 0
                record["lastDown"] = 0
        ledger["runtimeId"] = runtime_id
        for user_id, value in counters.items():
            record = history.setdefault(user_id, {})
            last = max(0, int(record.get("last", 0)))
            record["total"] = max(0, int(record.get("total", 0))) + (
                value - last if value >= last else value)
            record["last"] = value
        if inbound_counters is not None:
            inbound_history = ledger.setdefault("inbounds", {})
            for (user_id, tag), count in inbound_counters.items():
                cache_key = json.dumps([int(user_id), tag], separators=(",", ":"))
                item = inbound_history.setdefault(cache_key, {})
                for direction, suffix in (("uplink", "Up"), ("downlink", "Down")):
                    raw = count[direction]
                    last = max(0, int(item.get("last" + suffix, 0)))
                    item["total" + suffix] = max(0, int(item.get("total" + suffix, 0))) + (
                        raw - last if raw >= last else raw)
                    item["last" + suffix] = raw
    return ledger


def enforce_quota_reservation(user, record, total, now_ms):
    """Consume only a node-bound absolute ceiling from a verified v2 policy.

    This function is called only after envelope signature/node verification.
    Aggregate panelUsedBytes is deliberately not an acknowledgement.
    """
    lease = user.get("quotaReservation")
    if not isinstance(lease, dict):
        raise ValueError("Missing signed quota reservation")
    required = ("epoch", "meterEpoch", "reservationId", "revision",
                "acknowledgedBytes", "ceilingBytes", "validUntilMs")
    if set(lease) != set(required):
        raise ValueError("Invalid signed quota reservation fields")
    for field in ("epoch", "meterEpoch", "reservationId"):
        if not isinstance(lease[field], str) or not re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", lease[field]):
            raise ValueError("Invalid quota reservation identity")
    for field in ("revision", "acknowledgedBytes", "ceilingBytes", "validUntilMs"):
        if type(lease[field]) is not int or not 0 <= lease[field] < (1 << 63):
            raise ValueError("Invalid quota reservation counter")
    if lease["ceilingBytes"] < lease["acknowledgedBytes"]:
        raise ValueError("Quota acknowledgement exceeds signed ceiling")
    if lease["acknowledgedBytes"] > total:
        raise ValueError("Acknowledgement is ahead of durable local usage")
    old = record.get("quotaReservation")
    revoke = user.get("quotaRevocation")
    if revoke is not None:
        fields = ("requestId", "epoch", "meterEpoch", "reservationId")
        if not isinstance(revoke, dict) or set(revoke) != set(fields):
            raise ValueError("Malformed signed quota revocation")
        if not isinstance(revoke["requestId"], str) or not re.fullmatch(
                r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                revoke["requestId"]):
            raise ValueError("Malformed signed quota revocation identity")
        if any(revoke[field] != lease[field]
               for field in ("epoch", "meterEpoch", "reservationId")):
            raise ValueError("Quota revocation not bound to signed node lease")
    previous_revoke = record.get("quotaRevocation")
    if isinstance(previous_revoke, dict) and previous_revoke.get("epoch") == lease["epoch"]:
        if revoke != previous_revoke:
            # A newer signed policy can renew a lease, but cannot cancel a
            # previously committed revocation for the same account epoch.
            raise ValueError("Signed quota revocation rollback")
    if revoke is not None:
        record["quotaRevocation"] = dict(revoke)
    elif isinstance(previous_revoke, dict) and previous_revoke.get("epoch") != lease["epoch"]:
        record.pop("quotaRevocation", None)
    if old is not None:
        if old["meterEpoch"] != lease["meterEpoch"]:
            raise ValueError("Meter incarnation changed without reconciliation")
        if lease["acknowledgedBytes"] < old["acknowledgedBytes"]:
            raise ValueError("Quota acknowledgement rollback")
        if old["epoch"] == lease["epoch"] and (
                lease["revision"] < old["revision"] or
                lease["reservationId"] != old["reservationId"]):
            raise ValueError("Quota reservation rollback")
        if old["epoch"] == lease["epoch"] and lease["revision"] == old["revision"] and lease != old:
            raise ValueError("Conflicting quota reservation revision")
    record["quotaReservation"] = dict(lease)
    if revoke is not None:
        return "quota-revocation-pending"
    if now_ms >= lease["validUntilMs"]:
        return "quota-reservation-expired"
    if total >= lease["ceilingBytes"]:
        return "quota"
    return None


def enforce(policy, config, ledger, counters, runtime_id, offline, now_ms, inbound_counters=None):
    """Pure admission decision; caller persists the ledger before applying JSON."""
    if not isinstance(ledger, dict):
        ledger = {}
    ledger = integrate_counters(ledger, counters, runtime_id, now_ms, inbound_counters)
    history = ledger["users"]
    now_ms = ledger["maxSeenMs"]
    users = policy["users"]
    allowed = {}
    denied = {}
    for user in users:
        key = str(user["userId"])
        record = history.setdefault(key, {})
        total = max(0, int(record.get("total", 0)))
        previous = int(record.get("panelUsedBytes", -1))
        budget = user["offlineBudgetBytes"]
        limit = user.get("limitBytes", 0)
        expires = user["expireAtMs"]
        fresh = not offline and policy["issuedAtMs"] > int(record.get("authorizedAtMs", -1))
        # A genuine, newer signed panel revision may acknowledge usage, renew
        # expiry, increase the plan, or reset metering. An identical policy
        # poll never refills a depleted local allowance.
        newly_authorized = (
            fresh and (
                (user["panelUsedBytes"] != previous and (policy.get("version") != 2 or limit > 0)) or
                limit > int(record.get("limitBytes", 0)) or
                expires > int(record.get("expireAtMs", 0)) or
                record.get("revokedReason") == "policy-expired"
            )
        )
        reservation_reason = None
        if policy.get("version") == 2 and limit > 0:
            reservation_reason = enforce_quota_reservation(user, record, total, now_ms)
            if reservation_reason is None:
                record["revoked"] = False
                record.pop("revokedReason", None)
        else:
            if "anchor" not in record or newly_authorized:
                record["anchor"] = total
                record["budget"] = budget
                record["panelUsedBytes"] = user["panelUsedBytes"]
                record["revoked"] = False
                record.pop("revokedReason", None)
            else:
                if budget is None:
                    record["budget"] = None
                elif record.get("budget") is not None:
                    record["budget"] = min(int(record["budget"]), budget)
            if not offline:
                record["authorizedAtMs"] = max(int(record.get("authorizedAtMs", 0)), policy["issuedAtMs"])
                record["limitBytes"] = limit
                record["expireAtMs"] = expires
        reason = reservation_reason
        if user["expireAtMs"] and now_ms >= user["expireAtMs"]:
            reason = "expired"
        elif offline and policy.get("version") == 2 and user.get("onHold") is True:
            # A waiting subscription may bootstrap its *first* connection only
            # while Nexus can verify and activate it. Cached v2 policy cannot
            # activate trials after central contact is lost.
            reason = "subscription-awaiting-first-connection"
        elif offline and policy.get("version") == 2 and limit > 0 and counters is None:
            reason = "unverified-traffic-counter"
        elif offline and budget is not None and not (policy.get("version") == 2 and limit > 0):
            if counters is None:
                reason = "unverified-traffic-counter"
            elif total - int(record.get("anchor", 0)) >= int(record.get("budget") or 0):
                reason = "quota"
        # A signed policy has a finite validity even for unlimited subscriptions.
        # An absent offline traffic quota is not an exemption from expiration.
        if offline and now_ms >= policy["validUntilMs"]:
            reason = "policy-expired"
        if reason and offline:
            # Preserve the FIRST denial reason. An already exhausted quota
            # must not later be relabelled "policy-expired" and silently
            # reauthorized on a new lease without a real quota change.
            if not record.get("revoked"):
                record["revokedReason"] = reason
            else:
                record.setdefault("revokedReason", "locally-revoked")
            record["revoked"] = True
        if record.get("revoked"):
            reason = reason or "locally-revoked"
        if reason:
            denied[user["xrayId"]] = reason
        else:
            allowed[user["xrayId"]] = user["userId"]
    effective = json.loads(json.dumps(config))
    identities = {u["userId"]: u["xrayId"] for u in policy["users"]}
    for inbound in effective["inbounds"]:
        if inbound.get("tag") == "xmesh_stats_in":
            continue
        accounts, credential_key = configured_accounts(inbound)
        scoped = dict(identities)
        scoped["_protocol"] = inbound["protocol"]
        scoped["_method"] = inbound["settings"].get("method", "")
        field = "clients" if inbound["protocol"] == "vless" else "users"
        inbound["settings"][field] = [
            entry for entry in accounts
            if account_uuid(entry, credential_key, scoped) in allowed
        ]
    return effective, ledger, denied


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["prepare", "offline", "commit", "sample"])
    parser.add_argument("--state", required=True)
    parser.add_argument("--node-id", type=int, required=True)
    parser.add_argument("--response")
    parser.add_argument("--output")
    parser.add_argument("--now-ms", type=int)
    parser.add_argument("--stats-file", help="Test-only deterministic counters")
    args = parser.parse_args()
    state = Path(args.state)
    state.mkdir(mode=0o700, parents=True, exist_ok=True)
    if args.action == "sample":
        # Share the synchronizer's lock: both jobs mutate the SAME ledger.
        # Sample-only polling must never rewrite policy, authorization or Xray config.
        lock_fd = os.open(state / "lock", os.O_CREAT | os.O_RDWR, 0o600)
        try:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return  # The reconciler is already collecting and applying policy.
            ledger_file = state / "policy-usage.json"
            if not ledger_file.exists():
                print("XMesh user meter: waiting for the first signed policy", file=sys.stderr)
                return
            counters, runtime_id, inbound_counters = get_counters()
            if counters is None or inbound_counters is None:
                raise ValueError("Xray StatsService query failed; counters not published")
            # Verify the committed Ed25519 policy before publishing telemetry.
            scope = committed_snapshot_scope(state, args.node_id)
            if scope is None:
                raise ValueError("Missing committed signed policy for user telemetry")
            ledger = load_json(ledger_file)
            now_ms = int(time.time() * 1000)
            ledger = integrate_counters(ledger, counters, runtime_id, now_ms, inbound_counters)
            write_atomic(ledger_file, canonical(ledger))
            store_metrics_snapshot(ledger, args.node_id, now_ms, scope)
            print(f"XMesh user meter: sampled {len(inbound_counters)} user/inbound counters", file=sys.stderr)
        finally:
            os.close(lock_fd)
        return
    if args.action == "commit":
        pending = state / "policy-envelope.json.pending"
        if not pending.exists():
            raise ValueError("Missing validated pending policy snapshot")
        # The shell calls commit only after the validated managed Xray
        # config is active and its router has reconciled successfully.
        # A signed deny without that deployment is NOT a stop receipt.
        pending_doc = load_json(pending)
        pending_policy = verify_envelope(pending_doc, state, args.node_id)
        if any(user.get("quotaRevocation") is not None for user in pending_policy["users"]):
            active_config = load_json(state / "config.json")
            ledger_file = state / "policy-usage.json"
            ledger = load_json(ledger_file)
            ledger = applied_revocation_proofs(pending_policy, active_config, ledger)
            write_atomic(ledger_file, canonical(ledger))
        # A single atomic rename keeps config and policy bound together.
        os.replace(pending, state / "policy-envelope.json")
        # Immediately republish filtered counters after assignment changes.
        # In particular, do not leave retired users in the unprivileged
        # snapshot until the next sampling timer has fired.
        scope = committed_snapshot_scope(state, args.node_id)
        ledger_file = state / "policy-usage.json"
        if scope is not None and ledger_file.is_file():
            ledger = load_json(ledger_file)
            if ledger.get("inbounds"):
                store_metrics_snapshot(ledger, args.node_id,
                                       int(time.time() * 1000), scope)
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
        counters, runtime_id, inbound_counters = load_json(args.stats_file), "unit-test", None
    else:
        counters, runtime_id, inbound_counters = get_counters()
    effective, ledger, denied = enforce(policy, base, ledger, counters, runtime_id,
                                        args.action == "offline", now_ms, inbound_counters)
    write_atomic(ledger_file, canonical(ledger))
    if inbound_counters is not None:
        # The fresh prepare policy is pending. Until commit, publish only
        # against the previous committed Ed25519 authorization scope.
        scope = committed_snapshot_scope(state, args.node_id)
        if scope is not None:
            store_metrics_snapshot(ledger, args.node_id, now_ms, scope)
    write_atomic(args.output, canonical(effective))
    if args.action == "prepare":
        write_atomic(state / "policy-envelope.json.pending", canonical(doc))
    print("XMesh policy: " + ("offline" if args.action == "offline" else "connected")
          + f", authorized={len(policy['users']) - len(denied)}, blocked={len(denied)}",
          file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError) as exc:
        print(f"XMesh policy/user meter: {exc}", file=sys.stderr)
        sys.exit(1)
