#!/usr/bin/env python3
"""CI-only cross-check of the actual old Xray's private meter journal.

A signed observation can be genuine yet stale: raw StatsService mutations
between the checkpoint and the old process' physical exit leave an immutable
Xray taint marker. Never issue even a NONFINAL stop chain if the old runtime's
exact fsynced fence/checkpoint is missing, was replaced, or its ledger was
tainted. This audit does NOT certify comprehensive writer or kernel finality.

The journal source comes from an independently inspected Docker bind mount,
NOT from a Node-signed assertion, user-provided receipt or HTTP payload.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat

JOURNAL_DEST = "/run/xmesh-xray-audit"
MAX_FILE = 4096
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
CLOEXEC = getattr(os, "O_CLOEXEC", 0)
EMAIL = re.compile(r"xmesh-u([1-9][0-9]{0,18})--([^\x00-\x20>]{1,128})\Z")
FIELDS = ("email", "nodeId", "userId", "epoch", "meterEpoch",
          "reservationId", "revision", "revocationId")
CHECKPOINT = (*FIELDS, "schemaVersion", "runtimeId", "uplinkBytes",
              "downlinkBytes", "inboundMeters", "drained",
              "finalMeterVerified", "refundableBytes")


def _pairs(pairs):
    result = {}
    for name, val in pairs:
        if name in result:
            raise ValueError("ambiguous duplicate Xray journal key")
        result[name] = val
    return result


def _canonical_go(record):
    # Go encoding/json uses the declaration order of the embedded struct.
    # Its HTML escaping differs from Python: disallow unsafe alias characters
    # rather than normalizing potentially conflicting byte representations.
    return json.dumps(record, ensure_ascii=False, allow_nan=False,
                      separators=(",", ":")).encode("utf-8") + b"\n"


def _validate_directory(path):
    if not isinstance(path, (str, os.PathLike)):
        raise ValueError("trusted Xray journal path must be a local filesystem path")
    path = os.fspath(path)
    if not os.path.isabs(path) or os.path.normpath(path) != path:
        raise ValueError("Xray journal requires an absolute normalized path")
    # Ensure each component is a real directory: a parent symlink can redirect
    # an apparently trusted bind source to a synthetic empty journal.
    cur = Path("/")
    for part in Path(path).parts[1:]:
        cur = cur / part
        info = os.lstat(cur)
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError("untrusted Xray journal symlink or parent")
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW | CLOEXEC)
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or
            info.st_uid != os.geteuid() or
            stat.S_IMODE(info.st_mode) != 0o700):
        os.close(fd)
        raise ValueError("Xray journal directory is not private or owned")
    return fd


def _verify_mount(docker, path):
    if not isinstance(docker, dict):
        raise ValueError("independent Docker inspection unavailable")
    mounts = docker.get("Mounts")
    if not isinstance(mounts, list):
        raise ValueError("managed Xray journal mount list unavailable")
    found = [m for m in mounts if isinstance(m, dict)
             and m.get("Destination") == JOURNAL_DEST]
    if len(found) != 1 or (found[0].get("Type") != "bind" or
                           found[0].get("Source") != path or
                           found[0].get("RW") is not True):
        raise ValueError("signed checkpoint does not bind actual managed Xray journal")
    return found[0]


def _read(dfd, filename):
    before = os.stat(filename, dir_fd=dfd, follow_symlinks=False)
    if (not stat.S_ISREG(before.st_mode) or
            stat.S_IMODE(before.st_mode) != 0o600 or
            before.st_uid != os.geteuid() or before.st_nlink != 1 or
            not 0 < before.st_size <= MAX_FILE):
        raise ValueError("unsafe immutable old-Xray journal inode")
    fd = os.open(filename, os.O_RDONLY | NOFOLLOW | CLOEXEC, dir_fd=dfd)
    try:
        opened = os.fstat(fd)
        if ((opened.st_dev,opened.st_ino,opened.st_size) !=
                (before.st_dev,before.st_ino,before.st_size)):
            raise ValueError("Xray journal inode changed while opening")
        raw = os.read(fd, MAX_FILE+1)
        if len(raw) != before.st_size:
            raise ValueError("Xray journal changed while reading")
        # Verify that the directory name still points at the same inode.
        after = os.stat(filename, dir_fd=dfd, follow_symlinks=False)
        if (after.st_dev,after.st_ino) != (before.st_dev,before.st_ino):
            raise ValueError("Xray journal file replaced after read")
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                         parse_constant=lambda _:
                         (_ for _ in ()).throw(ValueError("nonfinite Xray counter")))
        if not isinstance(obj, dict) or _canonical_go(obj) != raw:
            raise ValueError("Xray journal record not canonical Go JSON")
        return raw,obj
    finally:
        os.close(fd)


def verify_poststop_journal(checkpoint, journal_dir, docker):
    """Return a digest of exact old-Xray fence+checkpoint on a clean journal.

    Every call reopens the directory; the caller runs once before old PID
    death and AGAIN after the exact old PID has exited but before signing
    and publishing the historical stop chain. A missing/different/uncertain
    journal only denies issuance, never creates a refundable receipt.
    """
    if not isinstance(checkpoint, dict) or set(checkpoint) != set(CHECKPOINT):
        raise ValueError("untrusted Xray checkpoint shape")
    email = checkpoint["email"]
    matched = EMAIL.fullmatch(email) if isinstance(email,str) else None
    if (matched is None or type(checkpoint["userId"]) is not int or
            str(checkpoint["userId"]) != matched[1] or
            checkpoint["schemaVersion"] != 3 or
            checkpoint["drained"] is not True or
            checkpoint["finalMeterVerified"] is not False or
            checkpoint["refundableBytes"] != 0):
        raise ValueError("Xray checkpoint not a signed user-scoped nonfinal observation")
    # Avoid divergent Python/Go HTML escaping in raw journal identifiers.
    if any(char in email for char in "<>&"):
        raise ValueError("unsafe Xray journal email encoding")
    absolute = os.fspath(journal_dir)
    dfd = _validate_directory(absolute)
    try:
        _verify_mount(docker, absolute)
        account = "xmesh-u" + matched[1]
        stem = hashlib.sha256(account.encode("ascii")).hexdigest()
        pending = [n for n in os.listdir(dfd)
                   if n.startswith((".fence-pending-", ".observed-pending-",
                                    ".taint-pending-"))]
        if pending:
            raise ValueError("uncertain or uncommitted Xray journal write exists")
        if ("taint-" + stem + ".json") in os.listdir(dfd):
            raise ValueError("old Xray raw counter has a durable post-stop taint")
        fence_raw,fence = _read(dfd, "fence-" + stem + ".json")
        observed_raw,observed = _read(dfd, "observed-" + stem + ".json")
        expected_fence = {k:checkpoint[k] for k in FIELDS}
        expected_fence["schemaVersion"] = 1
        if fence != expected_fence or set(fence) != set(expected_fence):
            raise ValueError("old-Xray fsynced deny does not match signed revocation")
        if observed != checkpoint or set(observed) != set(CHECKPOINT):
            raise ValueError("old-Xray fsynced meter does not match signed observation")
        if (fence_raw != _canonical_go(expected_fence) or
                observed_raw != _canonical_go(
                    {key:checkpoint[key] for key in CHECKPOINT})):
            raise ValueError("old-Xray journal byte order or content not canonical")
        # Reject any inode replacement while reading and fsync the parent
        # before issuing the signed historical stop event.
        os.fsync(dfd)
        return hashlib.sha256(fence_raw + observed_raw).hexdigest()
    finally:
        os.close(dfd)
