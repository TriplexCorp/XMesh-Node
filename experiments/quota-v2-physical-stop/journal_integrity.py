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



# Exact struct order of durableMeterStep in injected Go Xray. This is an
# independent, read-only, post-stop verifier, NOT a claim of terminality.
METER_FIELDS = ("schemaVersion", "runtimeId", "email", "direction",
                "sequence", "previousBytes", "nextBytes",
                "previousDigest", "digest")
METER_MAX_FILE = 64 << 20


def _read_meter_wal(dfd, name):
    """Reject missing/torn/hash-rewritten/foreign/symlinked raw byte intents."""
    before = os.stat(name, dir_fd=dfd, follow_symlinks=False)
    if (not stat.S_ISREG(before.st_mode) or
            stat.S_IMODE(before.st_mode) != 0o600 or
            before.st_uid != os.geteuid() or before.st_nlink != 1 or
            not 0 < before.st_size <= METER_MAX_FILE):
        raise ValueError("unsafe old-Xray metered WAL inode")
    fd = os.open(name, os.O_RDONLY | NOFOLLOW | CLOEXEC, dir_fd=dfd)
    try:
        opened = os.fstat(fd)
        if ((opened.st_dev, opened.st_ino, opened.st_size) !=
                (before.st_dev, before.st_ino, before.st_size)):
            raise ValueError("old-Xray byte WAL was replaced during open")
        chunks = []
        count = 0
        while count <= METER_MAX_FILE:
            chunk = os.read(fd, min(65536, before.st_size - count + 1))
            if not chunk:
                break
            chunks.append(chunk)
            count += len(chunk)
            if count >= before.st_size:
                break
        raw = b"".join(chunks)
        if len(raw) != before.st_size or not raw.endswith(b"\n"):
            raise ValueError("crash-truncated or expanded Xray byte WAL")
        after = os.stat(name, dir_fd=dfd, follow_symlinks=False)
        if ((after.st_dev,after.st_ino,after.st_size) !=
                (before.st_dev,before.st_ino,before.st_size)):
            raise ValueError("old-Xray byte WAL changed while reading")
        previous = None
        for line in raw[:-1].split(b"\n"):
            if not 0 < len(line) <= 1024:
                raise ValueError("Xray WAL record is unbounded or empty")
            record = json.loads(
                line.decode("utf-8"), object_pairs_hook=_pairs,
                parse_constant=lambda _: (_ for _ in ()).throw(
                    ValueError("nonfinite WAL counter")))
            if (not isinstance(record,dict) or
                    tuple(record) != METER_FIELDS or
                    _canonical_go(record) != line+b"\n"):
                raise ValueError("noncanonical or ambiguous old-Xray WAL")
            if (type(record["schemaVersion"]) is not int or
                    record["schemaVersion"] != 1 or
                    type(record["sequence"]) is not int or
                    type(record["previousBytes"]) is not int or
                    type(record["nextBytes"]) is not int or
                    not 0 <= record["previousBytes"] <
                    record["nextBytes"] <= 2**63-1):
                raise ValueError("invalid Xray durable meter sequence or bytes")
            run = record["runtimeId"]
            email = record["email"]
            direction = record["direction"]
            if (not isinstance(run,str) or
                    re.fullmatch(r"[a-f0-9]{64}",run) is None or
                    not isinstance(email,str) or EMAIL.fullmatch(email) is None or
                    any(c in email for c in "<>&") or
                    direction not in ("uplink","downlink")):
                raise ValueError("untrusted Xray WAL scope or runtime identity")
            want = "meter-" + hashlib.sha256(
                (run+"\x00"+email+"\x00"+direction).encode("utf-8")
            ).hexdigest() + ".jsonl"
            if name != want:
                raise ValueError("meter WAL filename does not bind runtime/email/direction")
            baseline = dict(record)
            baseline["digest"] = ""
            if record["digest"] != hashlib.sha256(
                    _canonical_go(baseline)).hexdigest():
                raise ValueError("old-Xray WAL hash chain modified")
            if previous is None:
                if (record["sequence"] != 1 or
                        record["previousBytes"] != 0 or
                        record["previousDigest"] != "0"*64):
                    raise ValueError("unanchored Xray byte WAL")
            elif (record["sequence"] != previous["sequence"]+1 or
                    record["previousBytes"] != previous["nextBytes"] or
                    record["previousDigest"] != previous["digest"] or
                    any(record[k]!=previous[k]
                        for k in ("runtimeId","email","direction"))):
                raise ValueError("old-Xray byte WAL replay or sequence gap")
            previous = record
        if previous is None:
            raise ValueError("empty Xray byte intent WAL")
        return previous, hashlib.sha256(raw).hexdigest()
    finally:
        os.close(fd)


def _verify_conservative_meter_wal(dfd, checkpoint):
    """Require that EVERY observed raw byte was durably precharged.

    This is a lower bound on committed accounting intents, NOT evidence
    that the network accepted every byte, that a different old process
    had no traffic, or that every detached background writer was tracked.
    """
    expected = {}
    for row in checkpoint["inboundMeters"]:
        if (not isinstance(row,dict) or
                set(row) != {"email","uplinkBytes","downlinkBytes"} or
                EMAIL.fullmatch(row["email"]) is None or
                not row["email"].startswith("xmesh-u"+str(checkpoint["userId"])+"--")):
            raise ValueError("untrusted alias in signed Xray byte WAL scope")
        for direction in ("uplink","downlink"):
            value=row[direction+"Bytes"]
            if type(value) is not int or not 0 <= value <= 2**63-1:
                raise ValueError("invalid observed account byte total")
            key=(row["email"],direction)
            if key in expected:
                raise ValueError("duplicate signed Xray WAL alias")
            expected[key]=value
    if (sum(v for (name,d),v in expected.items() if d=="uplink") !=
            checkpoint["uplinkBytes"] or
            sum(v for (name,d),v in expected.items() if d=="downlink") !=
            checkpoint["downlinkBytes"]):
        raise ValueError("signed Xray byte totals disagree with aliases")

    seen={}
    included=[]
    account="xmesh-u"+str(checkpoint["userId"])
    names = sorted(os.listdir(dfd))
    meters=[name for name in names if name.startswith("meter-")]
    if len(meters)>512:
        raise ValueError("unbounded Xray byte WAL inventory")
    for filename in meters:
        if not re.fullmatch(r"meter-[a-f0-9]{64}\.jsonl",filename):
            raise ValueError("unexpected Xray byte journal filename")
        last,content_hash=_read_meter_wal(dfd,filename)
        email=last["email"]
        # Every historical file is integrity checked; old runtime bytes of
        # this SAME account must never disappear from a claimed current PID.
        if not email.startswith(account+"--"):
            continue
        if last["runtimeId"] != checkpoint["runtimeId"]:
            raise ValueError("historic same-account Xray byte intent unresolved")
        key=(email,last["direction"])
        if key in seen:
            raise ValueError("duplicate Xray byte WAL for same alias/direction")
        if key not in expected:
            raise ValueError("old-Xray WAL contains unseen signed inbound alias")
        if last["nextBytes"] != expected[key]:
            raise ValueError("fsynced Xray byte WAL disagrees with observed counter")
        seen[key]=last["nextBytes"]
        included.append(filename.encode("ascii")+b":"+content_hash.encode("ascii")+b"\n")
    for key,bytes_count in expected.items():
        if bytes_count != 0 and seen.get(key) != bytes_count:
            raise ValueError("nonzero Xray counter lacks pretransmit fsynced WAL")
        if bytes_count == 0 and key in seen:
            raise ValueError("unexpected positive precharge for zero-byte Xray meter")
    return b"".join(included)


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
        # Bind every per-inbound byte to the exact trusted old runtime's
        # fsynced pre-transmission journal. A later raw counter write,
        # lost/torn WAL or another incarnation of the same account may not
        # be disguised by a perfectly signed but stale observed snapshot.
        meter_digest = _verify_conservative_meter_wal(dfd, checkpoint)
        os.fsync(dfd)
        return hashlib.sha256(
            fence_raw + observed_raw + b"|conservative-meter-WAL-v1|" +
            meter_digest).hexdigest()
    finally:
        os.close(dfd)
