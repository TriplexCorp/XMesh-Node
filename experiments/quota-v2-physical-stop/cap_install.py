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
