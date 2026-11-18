#!/usr/bin/env python3
"""CI-only signed NONFINAL Xray observation. Never a refund/settlement proof.

This deliberately has NO production sender, Nexus API route, or refund caller.
Only a committed, Ed25519-verified policy can bind an Xray observation to a
reservation before the Node identity signs it. Node authentication alone
cannot prove physical stop, writer completion, or final byte accuracy.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess

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
            "checkpointSha256", "boundToCommittedPolicy", "finalMeterVerified",
            "settlementEligible", "refundableBytes"} or (
            type(p["schemaVersion"]) is not int or p["schemaVersion"] != 1 or
            p["kind"] != KIND or type(p["nodeId"]) is not int or
            p["nodeId"] != node_id or node_id <= 0 or
            p["boundToCommittedPolicy"] is not True or
            p["finalMeterVerified"] is not False or
            p["settlementEligible"] is not False or
            type(p["refundableBytes"]) is not int or p["refundableBytes"] != 0):
        raise ValueError("nonfinal evidence cannot confer refund authority")
    checkpoint = p["checkpoint"]
    if not isinstance(checkpoint, dict) or checkpoint.get("nodeId") != node_id or (
            type(checkpoint.get("schemaVersion")) is not int or
            checkpoint["schemaVersion"] != 2 or
            checkpoint.get("finalMeterVerified") is not False or
            type(checkpoint.get("refundableBytes")) is not int or
            checkpoint["refundableBytes"] != 0 or
            checkpoint.get("drained") is not True):
        raise ValueError("invalid nonfinal Xray checkpoint")
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
    scope = {key: checkpoint[key] for key in fields}
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


def append_only(dfd, name, evidence):
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
    try:
        with os.fdopen(fd, "wb", closefd=True) as sink:
            sink.write(evidence)
            sink.flush()
            os.fsync(sink.fileno())
        # Exclusive hardlink, not replace/rename: no conflicting replay wins.
        os.link(temp, name, src_dir_fd=dfd, dst_dir_fd=dfd,
                follow_symlinks=False)
        os.fsync(dfd)
    finally:
        os.unlink(temp, dir_fd=dfd)
        os.fsync(dfd)
    if read_private_record(dfd, name) != evidence:
        raise ValueError("observation publication was not durable")
    return True


def create_observation(state_dir, node_id, checkpoint, key_path, ledger_dir):
    if type(node_id) is not int or node_id <= 0:
        raise ValueError("invalid Node ID")
    # No pending policy, raw counter, or Node heartbeat may substitute here.
    ledger = guard.load_json(Path(state_dir) / "policy-usage.json")
    bound = guard.verify_committed_observed_checkpoint(
        Path(state_dir), node_id, checkpoint, ledger)
    if bound.get("scopeBoundToSignedPolicy") is not True or (
            bound.get("finalMeterVerified") is not False or
            bound.get("refundableBytes") != 0):
        raise ValueError("Xray checkpoint was not safely bound to signed policy")
    p = {
        "schemaVersion": 1, "kind": KIND, "nodeId": node_id,
        "checkpoint": checkpoint,
        "checkpointSha256": hashlib.sha256(canonical(checkpoint)).hexdigest(),
        "boundToCommittedPolicy": True,
        "finalMeterVerified": False, "settlementEligible": False,
        "refundableBytes": 0,
    }
    signature = sign_bytes(key_path, DOMAIN + canonical(p))
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
