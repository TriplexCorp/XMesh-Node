"""Deliver an already verified Nexus grant to the independently measured Xray.

The caller must obtain and verify Nexus's grant and its lease/policy scope
before invoking this transport. The local socket does not issue quota.
"""
import base64
import hashlib
import http.client
import json
import os
from pathlib import Path
import select
import socket
import stat
import re
import secrets
import time
import struct

# This module is colocated with the existing strict-XSP/2 WAL client and
# shares its bounded JSON handling and independent procfs verifier.
import wal_transport


def install_in_xray(path, trusted_pid, runtime, genesis, grant, scope):
    """Accept a receipt only from the same live Linux process that was measured."""
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("Xray control socket path must be absolute")
    uid = os.geteuid()
    parent = path.parent.lstat()
    endpoint = path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != uid
            or parent.st_mode & 0o077 or not stat.S_ISSOCK(endpoint.st_mode)
            or endpoint.st_uid != uid or endpoint.st_mode & 0o077):
        raise ValueError("Xray control socket is outside the private service boundary")
    # Renewal requests have an empty Genesis field. Xray validates the
    # signed kind and requires an installed permit before accepting them.
    if not (len(genesis) <= 4096 and 0 < len(grant) <= 8192):
        raise ValueError("invalid signed Xray admission lengths")
    body = json.dumps({
        "genesis": base64.b64encode(genesis).decode("ascii"),
        "grant": base64.b64encode(grant).decode("ascii"),
        "scope": scope,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    if len(body) > 18 * 1024:
        raise ValueError("oversized local admission request")
    pidfd = os.pidfd_open(trusted_pid, 0)
    try:
        poll = select.poll()
        poll.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)

        def check_runtime():
            if poll.poll(0) or wal_transport.runtime_identity.trusted_runtime_identity(trusted_pid) != runtime:
                raise ValueError("measured Xray process exited or changed")

        check_runtime()
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(12)
            conn.connect(str(path))
            peer = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            peer_pid, peer_uid, _ = struct.unpack("3i", peer)
            if peer_pid != trusted_pid or peer_uid != uid:
                raise ValueError("Unix peer is not the measured Xray process")
            check_runtime()
            client = http.client.HTTPConnection("localhost", timeout=12)
            # Never reconnect by TCP if the checked Unix peer disconnects.
            client.auto_open = False
            client.sock = conn
            try:
                client.request("POST", "/v1/quota-cap", body=body, headers={"Connection": "close"})
                response = client.getresponse()
                raw = response.read(1025)
                if response.status != 200 or len(raw) > 1024:
                    raise ValueError(f"Xray rejected quota installation (HTTP {response.status})")
            finally:
                client.close()
        receipt = wal_transport.observed.strict_json(raw)
        expected = {"runtimeId": runtime, "grantSha256": hashlib.sha256(grant).hexdigest()}
        if receipt != expected:
            raise ValueError("Xray receipt differs from the measured runtime or exact signed grant")
        check_runtime()
        return receipt
    finally:
        os.close(pidfd)

def fence_calendar_in_xray(path, trusted_pid, runtime, scope):
    """Commit a ZERO-RESTART, irreversible old-epoch user fence.

    The existing disposable Xray /v1/fence writes and fsyncs a root-private
    denial BEFORE cancelling sessions and taking its nonfinal WAL snapshot.
    This endpoint must NEVER be interpreted as a positive quota grant or as
    authorization to refund the historical reservation.
    """
    if not isinstance(scope, dict) or set(scope) != {
            "email", "nodeId", "userId", "epoch", "meterEpoch",
            "reservationId", "revision", "revocationId"}:
        raise ValueError("invalid calendar fence scope")
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("Xray calendar fence socket must be absolute")
    uid = os.geteuid()
    parent, endpoint = path.parent.lstat(), path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != uid
            or parent.st_mode & 0o077
            or not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != uid
            or endpoint.st_mode & 0o077):
        raise ValueError("calendar fence socket escaped the private process boundary")
    body = json.dumps(scope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if not 0 < len(body) <= 2048:
        raise ValueError("oversized calendar fence scope")
    pidfd = os.pidfd_open(trusted_pid, 0)
    try:
        poll = select.poll()
        poll.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)

        def check_runtime():
            if poll.poll(0) or wal_transport.runtime_identity.trusted_runtime_identity(trusted_pid) != runtime:
                raise ValueError("calendar fence Xray PID exited or changed")

        check_runtime()
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(12)
            conn.connect(str(path))
            peer = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                   struct.calcsize("3i"))
            peer_pid, peer_uid, _ = struct.unpack("3i", peer)
            if peer_pid != trusted_pid or peer_uid != uid:
                raise ValueError("calendar fence Unix peer is not the measured Xray")
            check_runtime()
            client = http.client.HTTPConnection("localhost", timeout=12)
            client.auto_open = False
            client.sock = conn
            try:
                client.request("POST", "/v1/fence", body=body,
                               headers={"Connection": "close"})
                response = client.getresponse()
                raw = response.read(16 * 1024 + 1)
                if response.status != 200 or len(raw) > 16 * 1024:
                    raise ValueError(f"Xray calendar fence not confirmed (HTTP {response.status})")
            finally:
                client.close()
        result = wal_transport.observed.strict_json(raw)
        if (not isinstance(result, dict)
                or result.get("email") != scope["email"]
                or result.get("fenced") is not True
                or result.get("active") != 0
                or result.get("drained") is not True
                or result.get("finalMeterVerified") is not False
                or result.get("refundable") is not False):
            raise ValueError("Xray calendar fence lacks the mandatory nonfinal denial")
        checkpoint = result.get("observedCheckpoint")
        if (not isinstance(checkpoint, dict)
                or any(checkpoint.get(k) != v for k, v in scope.items())
                or checkpoint.get("runtimeId") != runtime
                or checkpoint.get("drained") is not True
                or checkpoint.get("finalMeterVerified") is not False
                or checkpoint.get("refundableBytes") != 0):
            raise ValueError("calendar fence checkpoint missing or changed its old reservation")
        check_runtime()
        return result
    finally:
        os.close(pidfd)


def _verify_fresh_zero_meter_receipt(result, scope, runtime):
    """Verify a read-only measured-Xray observation without confusing it
    with signed Nexus positive admission or proof of off-host old WAL.
    """
    expected = {
        **{k: scope[k] for k in (
            "schemaVersion", "nodeId", "userId", "nonce",
            "meterEpoch", "reservationId")},
        "kind": "xmesh.quota-v2.fresh-meter-observed",
        "aliases": scope["aliases"],
        "runtimeId": runtime,
        "inventorySha256":
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "zeroInitialRawCounters": True, "isolatedNewWalRoot": True,
        "authorizedBytes": 0, "canSpend": False,
        "canStart": False, "canResume": False,
        "finalMeterVerified": False, "refundableBytes": 0,
    }
    if (not isinstance(result, dict) or set(result) != set(expected)
            or any(type(result[k]) is not type(value) or result[k] != value
                   for k, value in expected.items())):
        raise ValueError("fresh Xray zero-meter observation is malformed or authorizing")
    return result


def observe_zero_meter_in_xray(path, trusted_pid, runtime, scope):
    """Read-only proof from the *fresh* quarantined Xray Unix peer.

    Only meaningful after the Agent verifies the Nexus-signed predecessor
    preparation and independent new Docker/pidfd/WAL binding. This NEVER
    creates a reservation, resets a counter or installs a spendable cap.
    """
    required = {
        "schemaVersion", "nodeId", "userId", "nonce", "meterEpoch",
        "reservationId", "aliases",
    }
    if (not isinstance(scope, dict) or set(scope) != required
            or scope.get("schemaVersion") != 1
            or type(scope.get("nodeId")) is not int or scope["nodeId"] <= 0
            or type(scope.get("userId")) is not int or scope["userId"] <= 0
            or not isinstance(scope.get("nonce"), str)
            or len(scope["nonce"]) != 64
            or not isinstance(scope.get("aliases"), list)
            or not 1 <= len(scope["aliases"]) <= 16):
        raise ValueError("invalid independently signed successor scope")
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("fresh Xray socket must be absolute")
    uid = os.geteuid()
    parent, endpoint = path.parent.lstat(), path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != uid
            or parent.st_mode & 0o077
            or not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != uid
            or endpoint.st_mode & 0o077):
        raise ValueError("fresh Xray socket escaped the private process boundary")
    body = json.dumps(scope, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if not 0 < len(body) <= 4096:
        raise ValueError("oversized fresh zero-meter request")
    pidfd = os.pidfd_open(trusted_pid, 0)
    try:
        poll = select.poll()
        poll.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)

        def check_runtime():
            if (poll.poll(0)
                    or wal_transport.runtime_identity.trusted_runtime_identity(
                        trusted_pid) != runtime):
                raise ValueError("fresh Xray PID exited or changed")
        check_runtime()
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(12)
            conn.connect(str(path))
            peer = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                   struct.calcsize("3i"))
            peer_pid, peer_uid, _ = struct.unpack("3i", peer)
            if peer_pid != trusted_pid or peer_uid != uid:
                raise ValueError("fresh Xray Unix peer is not measured PID")
            check_runtime()
            client = http.client.HTTPConnection("localhost", timeout=12)
            client.auto_open = False
            client.sock = conn
            try:
                client.request("POST", "/v1/zero-meter", body=body,
                               headers={"Connection": "close"})
                response = client.getresponse()
                raw = response.read(4097)
                if response.status != 200 or len(raw) > 4096:
                    raise ValueError("fresh Xray refused zero-meter read-only observation")
            finally:
                client.close()
        result = wal_transport.observed.strict_json(raw)
        _verify_fresh_zero_meter_receipt(result, scope, runtime)
        check_runtime()
        return result
    finally:
        os.close(pidfd)


# A live read-only observation is NOT quota issuance or public TLS authority.
# The caller must supply the independently Ed25519-verified Nexus grant and
# the original confirmed Node lease scope. The hash of that exact signed grant
# is checked by Xray's own in-memory cap, not by a Node-maintained cache.
CAP_OBSERVE_PATH = "/v1/quota-cap-observe"
CAP_OBSERVE_REPLY_MAX = 4096
CAP_OBSERVE_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
CAP_OBSERVE_HEX128 = re.compile(r"[0-9a-f]{128}\Z")
CAP_OBSERVE_SCOPE = frozenset({
    "userId", "policySha256", "accountEpoch", "meterEpoch", "reservationId",
    "revision", "nonce", "aliases",
})


def _observed_cap_request(runtime, node, activation, signed_grant, scope, email, nonce):
    """Use the original verified grant bytes, never a caller-provided cap hash."""
    if (not isinstance(signed_grant, bytes)
            or not 0 < len(signed_grant) <= 8192
            or not isinstance(scope, dict) or set(scope) != CAP_OBSERVE_SCOPE
            or type(node) is not int or node <= 0
            or any(not isinstance(x, str) or not CAP_OBSERVE_HEX64.fullmatch(x)
                   for x in (runtime, activation, nonce))
            or type(scope["userId"]) is not int or scope["userId"] <= 0
            or not isinstance(email, str)):
        raise ValueError("unverified scoped Xray cap observation inputs")
    doc = wal_transport.observed.strict_json(signed_grant)
    if (not isinstance(doc, dict)
            or set(doc) != {"algorithm", "payload", "signature"}
            or doc["algorithm"] != "Ed25519"
            or not isinstance(doc["signature"], str)
            or not CAP_OBSERVE_HEX128.fullmatch(doc["signature"])
            or not isinstance(doc["payload"], dict)
            or signed_grant != wal_transport.observed.canonical(doc) + b"\n"):
        raise ValueError("Xray cap observation requires exact canonical signed grant bytes")
    p = doc["payload"]
    matched = {
        "nodeId": node, "activationReceiptSha256": activation,
        "runtimeId": runtime, "userId": scope["userId"],
        "policySha256": scope["policySha256"],
        "accountEpoch": scope["accountEpoch"],
        "meterEpoch": scope["meterEpoch"],
        "reservationId": scope["reservationId"],
        "reservationRevision": scope["revision"],
        "nonce": scope["nonce"],
        "aliasScopes": scope["aliases"],
        "canSpend": True, "canStart": False, "canResume": False,
        "finalMeterVerified": False, "refundableBytes": 0,
    }
    if (p.get("schemaVersion") != 1
            or p.get("kind") not in (
                "xmesh.quota-v2.xray-cap-admission",
                "xmesh.quota-v2.xray-cap-renewal")
            or any(type(p.get(k)) is not type(value) or p[k] != value
                   for k, value in matched.items())
            or not isinstance(scope["aliases"], list)
            or not 1 <= len(scope["aliases"]) <= 16
            or not any(a == {"email": email, "class": cls}
                       for a in scope["aliases"] for cls in ("main", "cdn"))
            or type(p.get("validUntilMs")) is not int
            or p["validUntilMs"] <= time.time_ns() // 1_000_000
            or any(type(p.get(k)) is not int or p[k] <= 0
                   for k in ("sharedCeilingBytes", "nodeCeilingBytes"))
            or type(p.get("cdnCeilingBytes")) is not int
            or p["cdnCeilingBytes"] < 0):
        raise ValueError("foreign, expired or malformed independently verified Xray cap")
    grant_digest = hashlib.sha256(signed_grant).hexdigest()
    return {
        "schemaVersion": 1, "userId": scope["userId"],
        "email": email, "runtimeId": runtime,
        "grantSha256": grant_digest, "nonce": nonce,
    }, p


def verify_local_cap_observation(raw, request, grant, node, activation):
    """Verify a nonce-bound, nonauthorizing answer from the measured Xray.

    Must be used only *after* SO_PEERCRED, pidfd and runtime-identity checks.
    This is not a public listener permit or off-host WAL / revocation proof.
    """
    if not isinstance(raw, bytes) or not 0 < len(raw) <= CAP_OBSERVE_REPLY_MAX:
        raise ValueError("invalid local signed-cap observation reply size")
    reply = wal_transport.observed.strict_json(raw)
    if not isinstance(reply, dict):
        raise ValueError("invalid local signed-cap reply")
    expected = {
        "schemaVersion": 1,
        "kind": "xmesh.quota-v2.local-cap-observed",
        "nonce": request["nonce"],
        "nodeId": node,
        "userId": request["userId"],
        "email": request["email"],
        "runtimeId": request["runtimeId"],
        "activationReceiptSha256": activation,
        "policySha256": grant["policySha256"],
        "accountEpoch": grant["accountEpoch"],
        "meterEpoch": grant["meterEpoch"],
        "reservationId": grant["reservationId"],
        "reservationRevision": grant["reservationRevision"],
        "grantSha256": request["grantSha256"],
        "validUntilMs": grant["validUntilMs"],
        "sharedCeilingBytes": grant["sharedCeilingBytes"],
        "nodeCeilingBytes": grant["nodeCeilingBytes"],
        "cdnCeilingBytes": grant["cdnCeilingBytes"],
        "installedLocalCap": True,
        "canServePublic": False, "canStart": False,
        "canResume": False, "finalMeterVerified": False,
        "refundableBytes": 0,
    }
    if (set(reply) != set(expected) | {"chargedBytes", "chargedCdnBytes"}
            or any(type(reply.get(k)) is not type(v) or reply[k] != v
                   for k, v in expected.items())
            or any(type(reply.get(k)) is not int or reply[k] < 0
                   for k in ("chargedBytes", "chargedCdnBytes"))
            or reply["chargedBytes"] >= min(
                grant["sharedCeilingBytes"], grant["nodeCeilingBytes"])
            or reply["chargedCdnBytes"] > reply["chargedBytes"]
            or reply["chargedCdnBytes"] > grant["cdnCeilingBytes"]
            or (request["email"].endswith("--vless-cdn")
                and reply["chargedCdnBytes"] >= grant["cdnCeilingBytes"])
            or time.time_ns() // 1_000_000 >= reply["validUntilMs"]):
        raise ValueError("local Xray cap reply changed signed scope, time or byte totals")
    # Return diagnostic state with an explicit never-positive safety boundary.
    return reply


def observe_installed_cap_in_xray(path, trusted_pid, runtime, node,
                                  activation, signed_grant, scope, email):
    """Read the *actual* live measured Xray's installed cap via root Unix IPC.

    The caller has ALREADY independently authenticated the Nexus Ed25519
    grant and Node's confirmed reservation. This routine additionally
    pins the exact Xray pidfd, kernel Unix peer, runtime, original grant bytes,
    nonce and both cumulative MAIN/CDN charges. It NEVER installs quota or
    authorizes public TLS.
    """
    if type(trusted_pid) is not int or trusted_pid <= 0:
        raise ValueError("missing measured Xray PID")
    nonce = secrets.token_hex(32)
    request, grant = _observed_cap_request(
        runtime, node, activation, signed_grant, scope, email, nonce)
    path = Path(path)
    if not path.is_absolute():
        raise ValueError("local cap observation requires absolute Unix socket")
    uid = os.geteuid()
    parent, endpoint = path.parent.lstat(), path.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != uid
            or parent.st_mode & 0o077
            or not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != uid
            or endpoint.st_mode & 0o077):
        raise ValueError("local cap observation socket outside private service boundary")
    body = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("ascii")
    if not 0 < len(body) <= 512:
        raise ValueError("oversized local cap observation request")
    pidfd = os.pidfd_open(trusted_pid, 0)
    try:
        poll = select.poll()
        poll.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)

        def check_live_runtime():
            if (poll.poll(0)
                    or wal_transport.runtime_identity.trusted_runtime_identity(
                        trusted_pid) != runtime):
                raise ValueError("observed Xray process exited or changed")

        check_live_runtime()
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(12)
            conn.connect(str(path))
            raw_peer = conn.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            peer_pid, peer_uid, _ = struct.unpack("3i", raw_peer)
            if peer_pid != trusted_pid or peer_uid != uid:
                raise ValueError("cap observation Unix peer is not the measured Xray")
            check_live_runtime()
            client = http.client.HTTPConnection("localhost", timeout=12)
            client.auto_open = False
            client.sock = conn
            try:
                client.request("POST", CAP_OBSERVE_PATH, body=body,
                               headers={"Connection": "close"})
                response = client.getresponse()
                raw = response.read(CAP_OBSERVE_REPLY_MAX + 1)
                if response.status != 200 or len(raw) > CAP_OBSERVE_REPLY_MAX:
                    raise ValueError(
                        f"no valid installed Xray cap observed (HTTP {response.status})")
            finally:
                client.close()
        result = verify_local_cap_observation(raw, request, grant, node, activation)
        check_live_runtime()
        return result
    finally:
        os.close(pidfd)
