#!/usr/bin/env python3
"""CI-only signed NONFINAL Xray observation. Never a refund/settlement proof.

This deliberately has NO production sender, Nexus API route, or refund caller.
Only a committed, Ed25519-verified policy can bind an Xray observation to a
reservation before the Node identity signs it. Node authentication alone
cannot prove physical stop, writer completion, or final byte accuracy.
"""
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from runtime_identity import (
    inspect_managed_xray, trusted_runtime_identity,
    verify_live_runtime, verify_managed_xray_runtime,
)
from meter_floor import verify_monotonic_meter_floor

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "quota_observed_guard", ROOT / "deploy/xmesh-policy-guard-base.py")
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)

DOMAIN = b"XMESH_QUOTA_V2_NONFINAL_OBSERVATION_V1\x00"
KIND = "xmesh.quota-v2.nonfinal-observation"
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
CLOEXEC = getattr(os, "O_CLOEXEC", 0)
MAX_RECORD = 8192
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")


def unique_pairs(pairs):
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate evidence JSON field")
        result[name] = value
    return result


def strict_json(raw):
    if not 0 < len(raw) <= MAX_RECORD:
        raise ValueError("invalid evidence size")
    value = json.loads(
        raw, object_pairs_hook=unique_pairs,
        parse_constant=lambda _: (_ for _ in ()).throw(
            ValueError("non-finite evidence number")))
    if not isinstance(value, dict):
        raise ValueError("evidence must be an object")
    return value


def canonical(value):
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def private_directory(path):
    dfd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW | CLOEXEC)
    info = os.fstat(dfd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or (
            stat.S_IMODE(info.st_mode) != 0o700):
        os.close(dfd)
        raise ValueError("untrusted observation ledger directory")
    return dfd


def key_descriptor(key_path):
    fd = os.open(key_path, os.O_RDONLY | NOFOLLOW | CLOEXEC)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or (
            stat.S_IMODE(info.st_mode) != 0o600) or info.st_nlink != 1:
        os.close(fd)
        raise ValueError("unsafe Node signing key")
    return fd


def sign_bytes(key_path, message):
    key_fd = key_descriptor(key_path)
    try:
        # Ed25519 pkeyutl uses one-shot signing and needs a seekable input,
        # not an anonymous stdin stream.
        import tempfile
        with tempfile.TemporaryDirectory(prefix="xmesh-observation-sign-") as root:
            input_file = Path(root) / "message"
            input_file.write_bytes(message)
            proc = subprocess.run(
                ["openssl", "pkeyutl", "-sign", "-rawin", "-in",
                 str(input_file), "-inkey", "/proc/self/fd/" + str(key_fd)],
                capture_output=True, timeout=10, check=False,
                pass_fds=(key_fd,))
            if proc.returncode != 0 or len(proc.stdout) != 64:
                raise ValueError("Node Ed25519 signing failed")
            return proc.stdout.hex()
    finally:
        os.close(key_fd)


def verify_envelope(envelope, node_id, public_key_path):
    if set(envelope) != {"payload", "signature", "algorithm"} or (
            envelope["algorithm"] != "Ed25519" or
            not isinstance(envelope["signature"], str) or
            not HEX128.fullmatch(envelope["signature"])):
        raise ValueError("invalid Node signed observation envelope")
    p = envelope["payload"]
    if not isinstance(p, dict) or set(p) != {
            "schemaVersion", "kind", "nodeId", "checkpoint",
            "checkpointSha256", "boundToCommittedPolicy",
            "completeSignedInboundScopeObserved",
            "liveRuntimeIndependentlyVerified", "monotonicLedgerFloorVerified",
            "durableAbsoluteFloorBytes", "finalMeterVerified",
            "settlementEligible", "refundableBytes"} or (
            type(p["schemaVersion"]) is not int or p["schemaVersion"] != 2 or
            p["kind"] != KIND or type(p["nodeId"]) is not int or
            p["nodeId"] != node_id or node_id <= 0 or
            p["boundToCommittedPolicy"] is not True or
            p["completeSignedInboundScopeObserved"] is not True or
            p["liveRuntimeIndependentlyVerified"] is not True or
            type(p["monotonicLedgerFloorVerified"]) is not bool or
            type(p["durableAbsoluteFloorBytes"]) is not int or
            not 0 <= p["durableAbsoluteFloorBytes"] < 2**63 or
            (p["monotonicLedgerFloorVerified"] is False and
             p["durableAbsoluteFloorBytes"] != 0) or
            p["finalMeterVerified"] is not False or
            p["settlementEligible"] is not False or
            type(p["refundableBytes"]) is not int or p["refundableBytes"] != 0):
        raise ValueError("nonfinal evidence cannot confer refund authority")
    checkpoint = p["checkpoint"]
    if not isinstance(checkpoint, dict) or checkpoint.get("nodeId") != node_id or (
            type(checkpoint.get("schemaVersion")) is not int or
            checkpoint["schemaVersion"] != 3 or
            checkpoint.get("finalMeterVerified") is not False or
            type(checkpoint.get("refundableBytes")) is not int or
            checkpoint["refundableBytes"] != 0 or
            checkpoint.get("drained") is not True):
        raise ValueError("invalid nonfinal Xray checkpoint")
    rows = checkpoint.get("inboundMeters")
    if not isinstance(rows, list) or not 0 < len(rows) <= 16:
        raise ValueError("missing signed inbound meter rows")
    prev = ""
    up = down = 0
    for row in rows:
        if not isinstance(row, dict) or set(row) != {
                "email", "uplinkBytes", "downlinkBytes"}:
            raise ValueError("malformed signed inbound meter row")
        alias = row["email"]
        if not isinstance(alias, str) or not alias or alias <= prev or (
                len(alias.encode("utf-8")) > 128):
            raise ValueError("unordered or duplicate signed inbound email")
        prev = alias
        for direction in ("uplinkBytes", "downlinkBytes"):
            value = row[direction]
            if type(value) is not int or not 0 <= value < 2**63:
                raise ValueError("invalid signed inbound counter")
        up += row["uplinkBytes"]
        down += row["downlinkBytes"]
        if up + down >= 2**63:
            raise ValueError("signed inbound counter overflow")
    if (not any(row["email"] == checkpoint.get("email") for row in rows) or
            up != checkpoint.get("uplinkBytes") or
            down != checkpoint.get("downlinkBytes")):
        raise ValueError("signed inbound totals or request identity mismatch")
    if p["checkpointSha256"] != hashlib.sha256(canonical(checkpoint)).hexdigest():
        raise ValueError("signed Xray checkpoint digest mismatch")
    message = DOMAIN + canonical(p)
    # The trusted Node public key comes from the caller, NEVER the envelope.
    # An independent validator must additionally verify the committed policy.
    import tempfile
    with tempfile.TemporaryDirectory(prefix="xmesh-observation-verify-") as root:
        signature = Path(root) / "sig"
        signature.write_bytes(bytes.fromhex(envelope["signature"]))
        message_file = Path(root) / "message"
        message_file.write_bytes(message)
        proc = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-rawin", "-in",
             str(message_file), "-pubin", "-inkey", str(public_key_path),
             "-sigfile", str(signature)],
            capture_output=True, timeout=10, check=False)
        if proc.returncode != 0:
            raise ValueError("Node Ed25519 observation signature mismatch")
    return p


def receipt_name(checkpoint):
    fields = ["nodeId", "userId", "epoch", "meterEpoch",
              "reservationId", "revocationId", "revision"]
    for field in fields:
        value = checkpoint.get(field)
        if field in ("epoch", "meterEpoch", "reservationId", "revocationId"):
            if not isinstance(value, str) or not UUID.fullmatch(value):
                raise ValueError("invalid observed lease identity")
        elif type(value) is not int or value <= 0:
            raise ValueError("invalid observed node/user/revision identity")
    # One immutable observation slot per actual reservation, not per
    # revocation request/revision: changing request IDs cannot mint another
    # supposedly independent receipt for the same held bytes.
    reservation_fields = ["nodeId", "userId", "epoch",
                          "meterEpoch", "reservationId"]
    scope = {key: checkpoint[key] for key in reservation_fields}
    return "observed-" + hashlib.sha256(canonical(scope)).hexdigest() + ".json"


def read_private_record(dfd, name):
    before = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or (
            stat.S_IMODE(before.st_mode) != 0o600 or
            before.st_nlink != 1 or not 0 < before.st_size <= MAX_RECORD):
        raise ValueError("unsafe immutable Node observation")
    fd = os.open(name, os.O_RDONLY | NOFOLLOW | CLOEXEC, dir_fd=dfd)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise ValueError("Node observation was replaced during read")
        raw = os.read(fd, MAX_RECORD + 1)
        if len(raw) != before.st_size:
            raise ValueError("Node observation changed during read")
        return raw
    finally:
        os.close(fd)


def recover_pending_observations(dfd):
    """Repair ONLY fsynced, same-inode post-link crash records.

    A temp without a matching published hardlink might be a signed but
    UNPUBLISHED observation. Deleting or ignoring it would allow a different
    receipt for the same reservation after a crash. Treat it as an operator
    recovery blocker, never as an accepted proof or refundable meter.
    """
    for pending in sorted(os.listdir(dfd)):
        if not pending.startswith(".observed-pending-"):
            continue
        if not re.fullmatch(r"\.observed-pending-[0-9a-f]{32}", pending):
            raise ValueError("unrecognized pending Node observation journal")
        before = os.stat(pending, dir_fd=dfd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or
                before.st_uid != os.geteuid() or
                stat.S_IMODE(before.st_mode) != 0o600 or
                before.st_nlink != 2 or
                not 0 < before.st_size <= MAX_RECORD):
            raise ValueError("unpublished or unsafe pending Node observation")
        fd = os.open(pending, os.O_RDONLY | NOFOLLOW | CLOEXEC, dir_fd=dfd)
        try:
            opened = os.fstat(fd)
            if (opened.st_dev, opened.st_ino) != (
                    before.st_dev, before.st_ino):
                raise ValueError("pending Node observation changed during read")
            raw = os.read(fd, MAX_RECORD + 1)
            if len(raw) != before.st_size:
                raise ValueError("pending Node observation truncated during read")
        finally:
            os.close(fd)
        record = strict_json(raw)
        if raw != canonical(record) + b"\n" or (
                set(record) != {"algorithm", "payload", "signature"} or
                record["algorithm"] != "Ed25519" or
                not isinstance(record["payload"], dict) or
                not isinstance(record["payload"].get("checkpoint"), dict)):
            raise ValueError("noncanonical pending Node observation")
        published = receipt_name(record["payload"]["checkpoint"])
        try:
            final = os.stat(published, dir_fd=dfd, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise ValueError("unpublished pending Node observation") from exc
        if (not stat.S_ISREG(final.st_mode) or
                final.st_uid != before.st_uid or
                stat.S_IMODE(final.st_mode) != 0o600 or
                final.st_nlink != 2 or
                (final.st_dev, final.st_ino) != (
                    before.st_dev, before.st_ino)):
            raise ValueError("conflicting pending Node observation hardlink")
        # A crash after link() but before parent fsync may have left a
        # visible yet uncommitted name. Make it durable BEFORE unlinking
        # the validated temporary name, then fsync its removal as well.
        os.fsync(dfd)
        os.unlink(pending, dir_fd=dfd)
        os.fsync(dfd)
        if read_private_record(dfd, published) != raw:
            raise ValueError("recovered Node observation differs from journal")


def _append_only_locked(dfd, name, evidence):
    # Caller holds an EXCLUSIVE Linux flock on the verified private directory.
    # Without it, two independent signers can both see no receipt, fsync two
    # temps, and the losing hardlink leaves a permanent ambiguous pending
    # journal. Recovery itself must be serialized with publication.
    # Never sign past an interrupted publication, even when the requested
    # receipt is byte-identical to an already visible final filename.
    recover_pending_observations(dfd)
    try:
        old = read_private_record(dfd, name)
    except FileNotFoundError:
        old = None
    if old is not None:
        if old != evidence:
            raise ValueError("conflicting or corrupt immutable observation")
        os.fsync(dfd)
        return False
    temp = ".observed-pending-" + secrets.token_hex(16)
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY |
                 NOFOLLOW | CLOEXEC, 0o600, dir_fd=dfd)
    with os.fdopen(fd, "wb", closefd=True) as sink:
        sink.write(evidence)
        sink.flush()
        os.fsync(sink.fileno())
    # Persist the pending DIRECTORY ENTRY before publishing. fsync(file)
    # alone cannot guarantee that its filename survives a power failure.
    # This is done under the exclusive flock, before any new hardlink.
    os.fsync(dfd)
    # Failures after the durable temp is written MUST leave that file in
    # place. Removing it on a failed hardlink/fsync silently discards crash
    # evidence and could allow conflicting signatures on a retry.
    os.link(temp, name, src_dir_fd=dfd, dst_dir_fd=dfd,
            follow_symlinks=False)
    os.fsync(dfd)
    os.unlink(temp, dir_fd=dfd)
    os.fsync(dfd)
    if read_private_record(dfd, name) != evidence:
        raise ValueError("observation publication was not durable")
    return True


def append_only(dfd, name, evidence):
    """Atomically publish one immutable observation across Node processes.

    flock is on the already validated root-private directory inode, not on
    a replaceable/unlinkable lock filename. Every signer opens its own fd;
    Linux kernel locks serialize pending recovery, lookup, hardlink, fsync
    and cleanup. A process killed mid-write releases the lock automatically,
    leaving its fsynced pending journal for fail-closed recovery.
    """
    fcntl.flock(dfd, fcntl.LOCK_EX)
    try:
        return _append_only_locked(dfd, name, evidence)
    finally:
        fcntl.flock(dfd, fcntl.LOCK_UN)


def create_observation(state_dir, node_id, checkpoint, key_path, ledger_dir,
                       trusted_xray_host_pid=None):
    # Normal callers obtain the PID from trusted Docker, never the checkpoint.
    # Explicit host PID is for isolated direct-process tests only.
    managed_before = None
    if trusted_xray_host_pid is None:
        managed_before = inspect_managed_xray()
        verify_managed_xray_runtime(checkpoint)
        trusted_xray_host_pid = managed_before[2]
    verify_live_runtime(checkpoint, trusted_xray_host_pid)
    if type(node_id) is not int or node_id <= 0:
        raise ValueError("invalid Node ID")
    # No pending policy, raw counter, or Node heartbeat may substitute here.
    ledger = guard.load_json(Path(state_dir) / "policy-usage.json")
    bound = guard.verify_committed_observed_checkpoint(
        Path(state_dir), node_id, checkpoint, ledger)
    if (bound.get("scopeBoundToSignedPolicy") is not True or
            bound.get("completeSignedInboundScopeObserved") is not True or
            bound.get("finalMeterVerified") is not False or
            bound.get("refundableBytes") != 0):
        raise ValueError("Xray checkpoint was not safely bound to signed policy")
    # Production-style managed Docker path MUST verify this LIVE process's
    # exact durable raw-counter floors. Direct PID mode is isolated test-only,
    # and is explicitly labelled as having NO durable floor verification.
    floor = None
    if managed_before is not None:
        floor = verify_monotonic_meter_floor(ledger, checkpoint, managed_before)
    p = {
        "schemaVersion": 2, "kind": KIND, "nodeId": node_id,
        "checkpoint": checkpoint,
        "checkpointSha256": hashlib.sha256(canonical(checkpoint)).hexdigest(),
        "boundToCommittedPolicy": True,
        "completeSignedInboundScopeObserved": True,
        "liveRuntimeIndependentlyVerified": True,
        "monotonicLedgerFloorVerified": floor is not None,
        "durableAbsoluteFloorBytes": (
            floor["durableAbsoluteBytes"] if floor is not None else 0),
        "finalMeterVerified": False, "settlementEligible": False,
        "refundableBytes": 0,
    }
    signature = sign_bytes(key_path, DOMAIN + canonical(p))
    if managed_before is not None:
        # Refuse a replacement after signing but before disk publication.
        if inspect_managed_xray() != managed_before:
            raise ValueError("managed Xray replaced before receipt publication")
        verify_live_runtime(checkpoint, managed_before[2])
        latest = guard.load_json(Path(state_dir) / "policy-usage.json")
        if canonical(latest) != canonical(ledger):
            raise ValueError("durable Node meter changed during signing")
        verify_monotonic_meter_floor(latest, checkpoint, managed_before)
    envelope = {"algorithm": "Ed25519", "payload": p,
                "signature": signature}
    raw = canonical(envelope) + b"\n"
    if len(raw) > MAX_RECORD:
        raise ValueError("signed evidence too large")
    name = receipt_name(checkpoint)
    dfd = private_directory(ledger_dir)
    try:
        append_only(dfd, name, raw)
    finally:
        os.close(dfd)
    return envelope
