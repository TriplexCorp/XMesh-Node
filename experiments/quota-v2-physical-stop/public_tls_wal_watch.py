"""Dormant first-Genesis WAL readback; never a listener or spending permit.

Only a pinned strict-PQ response can distinguish signed empty remote history
from a committed birth index. Reconcile that snapshot against the original
isolated PID's complete private journal, exact first grants and live counters.
Each local stream must match its exact committed SQL charge head, even if
the immutable birth index has not changed since an earlier append.
This is NOT terminal WAL finality, pre-bootstrap completeness, or an
atomic public bind. No installer, service or public activation calls this.
"""
import hashlib
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
import time

import cap_install
import genesis_reservation
import public_tls_preflight as preflight
import qualified_runtime_image as qualification
import wal_transport as wal

DOMAIN = b"XMESH_QUOTA_V2_PUBLIC_TLS_WAL_HEAD_V2\x00"
MAX_WIRE = 8192
MAX_SCAN = 64 << 20
MAX_CHECK_NS = 9_000_000_000
MAX_AGE_MS = 2000
MAX_VALIDITY_MS = 7000
WAL_NAME = re.compile(r"meter-[0-9a-f]{64}\.jsonl\Z")
INSTANCE_LOCK = "xray-instance.lock"
MAX_METER_FDS = 4096
MAX_FDINFO = 8192


def _instance_lock(directory_fd, pid, deadline):
    """Read the measured Xray's real lifetime flock; never take it ourselves."""
    fd = os.open(INSTANCE_LOCK, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
                 | os.O_NONBLOCK, dir_fd=directory_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_nlink != 1 or info.st_size != 0):
            raise ValueError("unsafe Xray instance lock inode")
        identity = (info.st_dev, info.st_ino)
        # Inspect only the exact measured process's kernel descriptors.
        # /proc/locks can report a backing-filesystem inode for overlayfs
        # flock; fdinfo belongs to the actual open file description. Match
        # the stat of that descriptor to the journal pathname instead of
        # guessing the overlay filesystem's internal device numbering.
        proc = f"/proc/{pid}"
        matches = []
        with os.scandir(proc + "/fd") as descriptors:
            for number, item in enumerate(descriptors, 1):
                deadline()
                if number > MAX_METER_FDS or not item.name.isascii() or not item.name.isdecimal():
                    raise ValueError("meter instance descriptor scan exceeded bound")
                try:
                    actual = os.stat(item.path)
                    if (actual.st_dev, actual.st_ino) != identity:
                        continue
                    with open(proc + "/fdinfo/" + item.name, "rb") as evidence:
                        raw = evidence.read(MAX_FDINFO + 1)
                    if len(raw) > MAX_FDINFO:
                        raise ValueError("instance lock fdinfo exceeded bound")
                    locks = [line.split()[2:] for line in raw.splitlines()
                             if line.startswith(b"lock:")]
                    final = os.stat(item.path)
                    if (final.st_dev, final.st_ino) != identity:
                        raise ValueError("meter instance descriptor changed")
                except FileNotFoundError:
                    # Unrelated descriptors of the live process may close;
                    # a missing lock descriptor cannot produce a match.
                    continue
                if not locks:
                    continue
                # The per-FD kernel line binds the held flock to the open
                # file, exact host PID, exclusive write and whole file.
                if (len(locks) != 1 or len(locks[0]) != 7
                        or locks[0][:4] != [b"FLOCK", b"ADVISORY", b"WRITE",
                                           str(pid).encode("ascii")]
                        or locks[0][5:] != [b"0", b"EOF"]):
                    raise ValueError("foreign kernel lock on measured instance")
                matches.append(item.name)
        if len(matches) != 1:
            raise ValueError("instance lock not exclusively held by measured Xray PID")
        current = os.stat(INSTANCE_LOCK, dir_fd=directory_fd, follow_symlinks=False)
        if (current.st_dev, current.st_ino, current.st_nlink, current.st_size,
                current.st_uid, current.st_mode) != (
                info.st_dev, info.st_ino, info.st_nlink, info.st_size,
                info.st_uid, info.st_mode):
            raise ValueError("Xray instance lock changed during verification")
        deadline()
        return identity + (matches[0],)
    finally:
        os.close(fd)


def _snapshot(directory, roster, deadline):
    """Read actual journal files, rejecting any later/unknown ledger state."""
    fd = wal.journal._validate_directory(directory)
    try:
        anchor = os.fstat(fd)
        names = set(os.listdir(fd))
        caps = {f"positive-cap-u{user}.json": raw
                for user, (raw, _, _) in roster._grants.items()}
        streams = sorted(n for n in names if WAL_NAME.fullmatch(n))
        if (not (set(caps) | {INSTANCE_LOCK}) <= names
                or names - set(caps) - set(streams) - {wal.registry.NAME, INSTANCE_LOCK}
                or len(streams) > wal.registry.MAX_ENTRIES):
            raise ValueError("foreign, incomplete or later first-Genesis ledger")
        instance = _instance_lock(fd, roster._pid, deadline)
        # Bind the bytes persisted inside Xray, not only Agent's root copies.
        # Bound work before opening any file, and reject unsafe inodes.
        total = 0
        for name in names - {INSTANCE_LOCK}:
            deadline()
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            limit = (len(caps[name]) if name in caps else
                     wal.INDEX_LIMIT if name == wal.registry.NAME else MAX_SCAN)
            if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or not 0 < info.st_size <= limit):
                raise ValueError("unsafe first-Genesis ledger file")
            total += info.st_size
            if total > MAX_SCAN:
                raise ValueError("first-Genesis WAL scan exceeds bounded budget")
            if name in caps:
                with os.fdopen(os.open(name, os.O_RDONLY | os.O_NOFOLLOW
                                       | os.O_NONBLOCK | os.O_CLOEXEC,
                                       dir_fd=fd), "rb") as handle:
                    opened = os.fstat(handle.fileno())
                    if (opened.st_dev, opened.st_ino, opened.st_size) != (
                            info.st_dev, info.st_ino, info.st_size):
                        raise ValueError("Xray signed cap file was replaced")
                    if handle.read(len(caps[name]) + 1) != caps[name]:
                        raise ValueError("Xray durable cap differs from original signed grant")

        def read_meter(dfd, name):
            deadline()
            result = wal.journal._read_meter_wal(dfd, name)
            deadline()
            return result

        entries, raw_wal = wal.registry.verify_meter_inventory(
            fd, streams, read_meter, wal.journal._canonical_go)
        index = b"".join(wal.journal._canonical_go(entry)
                         for entry in entries.values())
        if (len(index) > wal.INDEX_LIMIT or
                wal.registry._read_inventory(fd) != (index or None)
                or set(os.listdir(fd)) != names):
            raise ValueError("meter inventory changed during snapshot")
        aliases = {email: user for user, (_, _, emails) in roster._grants.items()
                   for email in emails}
        totals = {user: [0, 0] for user in roster._grants}
        digests = {}
        heads = []
        for name, (last, digest, _) in sorted(raw_wal.items()):
            email = last["email"]
            if last["runtimeId"] != roster.runtime_id or email not in aliases:
                raise ValueError("meter WAL is outside original measured signed roster")
            total = totals[aliases[email]]
            total[0] += last["nextBytes"]
            if email.endswith("--vless-cdn"):
                total[1] += last["nextBytes"]
            if total[0] > 2**63 - 1:
                raise ValueError("meter WAL total overflows signed counter")
            digests[name] = digest
            user = aliases[email]
            # Filename commits runtime, alias and direction. Bind the exact
            # signed lease owner and class too; a matching birth count or
            # stale prefix of this stream is not a complete SQL charge.
            heads.append({
                "filename": name,
                "reservationId": roster._grants[user][1]["reservationId"],
                "userId": user,
                "lastSequence": last["sequence"],
                "lastDigest": last["digest"],
                "streamBytes": last["nextBytes"],
                "isCdn": email.endswith("--vless-cdn"),
            })
        # A re-bound directory cannot masquerade as an unchanged empty one.
        current = os.stat(directory, follow_symlinks=False)
        if (current.st_dev, current.st_ino) != (anchor.st_dev, anchor.st_ino):
            raise ValueError("first-Genesis journal directory was replaced")
        if _instance_lock(fd, roster._pid, deadline) != instance:
            raise ValueError("Xray instance lock was replaced during snapshot")
        deadline()
        return {
            "identity": (anchor.st_dev, anchor.st_ino),
            "instanceLock": instance,
            "sequence": len(entries),
            "sha256": hashlib.sha256(index).hexdigest(),
            "tail": next(reversed(entries.values()))["digest"] if entries else "0"*64,
            "totals": totals,
            "wal": digests,
            "chargeHeadsSha256": hashlib.sha256(
                wal.observed.canonical(heads)).hexdigest(),
        }
    finally:
        os.close(fd)


def _local_counters(roster, snapshot, deadline):
    for user, (raw, scope, emails) in sorted(roster._grants.items()):
        for email in emails:
            deadline()
            result = cap_install.observe_installed_cap_in_xray(
                roster._socket, roster._pid, roster.runtime_id, roster.node,
                roster.activation, raw, scope, email)
            deadline()
            expected = {
                "userId": user, "email": email, "installedLocalCap": True,
                "canServePublic": False, "canStart": False, "canResume": False,
                "finalMeterVerified": False, "refundableBytes": 0,
                "chargedBytes": snapshot["totals"][user][0],
                "chargedCdnBytes": snapshot["totals"][user][1],
            }
            if (not isinstance(result, dict)
                    or any(type(result.get(k)) is not type(v) or result[k] != v
                           for k, v in expected.items())):
                raise ValueError("live Xray counters differ from complete local WAL")


def _request(roster, user, measured):
    cid, started, pid, runtime = measured
    if (runtime != roster.runtime_id or pid != roster._pid
            or user not in roster._grants):
        raise ValueError("WAL watch is not bound to original measured first cap")
    return {"nodeId": roster.node, "operation": "public_tls_head", "proof": {
        "scope": {
            "nodeId": roster.node, "userId": user,
            "activationReceiptSha256": roster.activation,
            "genesisPolicySha256": roster.genesis_sha,
            "runtimeId": runtime, "profileRevision": roster.profile_sha256,
            "capRosterSha256": roster.roster_sha256, "requiredLifetimeMs": 7000,
        },
        "challenge": secrets.token_hex(32),
        "containerId": cid, "hostPid": pid, "startedAt": started,
    }}


def _fetch(request):
    # A 404 or old compatibility endpoint is never evidence of empty history.
    with tempfile.TemporaryDirectory(prefix="xmesh-tls-wal-head-") as temp:
        root = Path(temp)
        body, output, status = (root / name for name in ("request", "reply", "status"))
        body.write_bytes(wal.observed.canonical(request))
        subprocess.run([
            wal.PRODUCT, "request", "--path", wal.PATH, "--body-file", str(body),
            "--output-file", str(output), "--status-file", str(status),
        ], check=True, timeout=2.8)
        if status.read_text(encoding="ascii").strip() != "200":
            raise ValueError("strict-PQ Nexus did not sign WAL history")
        with output.open("rb") as handle:
            raw = handle.read(MAX_WIRE + 1)
        if not 0 < len(raw) <= MAX_WIRE:
            raise ValueError("invalid strict-PQ WAL head size")
        return raw


def _verify(raw, request, pinned, snapshot, now):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_WIRE:
        raise ValueError("missing or oversized Nexus WAL witness")
    outer = wal.observed.strict_json(raw, limit=MAX_WIRE)
    if (not isinstance(outer, dict) or set(outer) != {"signedEnvelope"}
            or not isinstance(outer["signedEnvelope"], str)):
        raise ValueError("invalid strict-PQ WAL response")
    envelope = outer["signedEnvelope"].encode("utf-8")
    doc = wal.observed.strict_json(envelope, limit=MAX_WIRE)
    if (not isinstance(doc, dict) or set(doc) != {"algorithm", "payload", "signature"}
            or doc["algorithm"] != "Ed25519" or not wal._hex(doc["signature"], 128)
            or envelope != wal.observed.canonical(doc) + b"\n"):
        raise ValueError("noncanonical signed WAL head")
    proof = request["proof"]
    expected = {key: value for key, value in proof["scope"].items()
                if key != "requiredLifetimeMs"}
    expected.update({key: proof[key] for key in
                     ("challenge", "containerId", "hostPid", "startedAt")})
    expected.update({
        "schemaVersion": 2, "kind": "xmesh.quota-v2.public-tls-wal-head",
        "preBootstrapHistoryCompletenessVerified": False,
        "liveMeterVerified": False, "finalMeterVerified": False,
        "canServePublic": False, "canSpend": False, "canStart": False,
        "canResume": False, "authorizedBytes": 0, "refundableBytes": 0,
    })
    local_history = {
        "historyState": ("committed_birth_index" if snapshot["sequence"]
                         else "empty_remote_history"),
        "inventorySequence": snapshot["sequence"],
        "inventorySha256": snapshot["sha256"], "inventoryTailDigest": snapshot["tail"],
        "committedChargeStreamCount": snapshot["sequence"],
        "committedChargeHeadsSha256": snapshot["chargeHeadsSha256"],
    }
    p = doc["payload"]
    if (not isinstance(p, dict)
            or set(p) != set(expected) | set(local_history) | {"issuedAtMs", "validUntilMs"}
            or any(type(p.get(k)) is not type(v) or p[k] != v
                   for k, v in expected.items())
            or any(type(p.get(k)) is not type(v) for k, v in local_history.items())
            or not 0 <= p["committedChargeStreamCount"] <= p["inventorySequence"] <= wal.registry.MAX_ENTRIES
            or p["historyState"] != ("committed_birth_index" if p["inventorySequence"]
                                     else "empty_remote_history")
            or any(not wal._hex(p[k], 64) for k in ("inventorySha256", "inventoryTailDigest",
                                                    "committedChargeHeadsSha256"))
            or type(p["issuedAtMs"]) is not int or type(p["validUntilMs"]) is not int
            or not 0 < p["issuedAtMs"] <= now < p["validUntilMs"]
            or now - p["issuedAtMs"] > MAX_AGE_MS
            or not 0 < p["validUntilMs"] - p["issuedAtMs"] <= MAX_VALIDITY_MS):
        raise ValueError("foreign, expired, authorizing or mismatched Nexus WAL history")
    with tempfile.TemporaryDirectory(prefix="xmesh-tls-wal-key-") as temp:
        public = Path(temp) / "nexus.pem"
        wal._write_public(pinned, public)
        wal.verifier.verify_nexus_signature(DOMAIN, p, doc["signature"], public)
    # The mismatch is reported ONLY after authenticating the exact fresh
    # server response. Fake/expired/malformed responses cannot masquerade
    # as evidence that a genuine SQL snapshot is lagging the actual meter.
    if any(p[key] != value for key, value in local_history.items()):
        raise ValueError("signed Nexus WAL history does not match complete local conservative tails")
    return p["validUntilMs"]


def _checked_evidence(roster, user, measured, directory, remeasure, deadline):
    before = _snapshot(directory, roster, deadline)
    _local_counters(roster, before, deadline)
    request = _request(roster, user, measured)
    raw = _fetch(request)
    received_mono = time.monotonic_ns()
    received_wall = time.time_ns() // 1_000_000
    deadline()
    expiry = _verify(raw, request, roster.pinned, before, received_wall)
    _local_counters(roster, before, deadline)
    after = _snapshot(directory, roster, deadline)
    if before != after or remeasure() != (measured, directory):
        raise ValueError("original runtime, journal or WAL changed during readback")
    deadline()
    mono = time.monotonic_ns()
    wall = time.time_ns() // 1_000_000
    if (mono < received_mono or wall < received_wall or wall >= expiry
            or mono >= received_mono + (expiry - received_wall) * 1_000_000
            or abs((wall - received_wall) * 1_000_000 - (mono - received_mono))
            > 2_000_000_000):
        raise ValueError("Nexus WAL witness expired or clock changed")
    # Private historical evidence for the disposable retirement verifier.
    # The bytes/digest do not establish terminality or grant any authority.
    return before, hashlib.sha256(raw).hexdigest()


def _check(roster, user, measured, directory, remeasure, deadline):
    _checked_evidence(roster, user, measured, directory, remeasure, deadline)
    # This successful diagnostic deliberately returns no reusable permit.
    return None


def probe(panel, node, user, state):
    """Root-only readback from independently verified enrolled Genesis files."""
    if (not qualification.installed_worker() or not isinstance(panel, str)
            or not panel.startswith("https://") or type(node) is not int or node <= 0
            or type(user) is not int or user <= 0):
        raise ValueError("installed enrolled root first-Genesis WAL probe required")
    start = time.monotonic_ns()

    def deadline():
        elapsed = time.monotonic_ns() - start
        if not 0 <= elapsed < MAX_CHECK_NS:
            raise ValueError("first-Genesis WAL readback exceeded time budget")

    fd, lock = preflight.quarantine._locked_private_state(state, read_only=True)
    try:
        pinned = wal._panel_pin()
        identity = preflight.quarantine._enrolled_activation(panel, node)
        activation = identity["activationReceiptSha256"]
        original = genesis_reservation._staged_original(fd, node, user, pinned, activation)
        pins = genesis_reservation._original_measurement_pins(fd, original, node, activation)
        release = qualification.read_identity(qualification.QUALIFICATION)
        if pins != (release["artifactSha256"], original["reply"]["revision"]):
            raise ValueError("original Genesis is not the installed qualified release")

        def remeasure():
            deadline()
            measured = wal._measure_quarantined_runtime(pins)
            docker, directory = wal._bound_journal()
            if ((docker["Id"], docker["State"]["StartedAt"], docker["State"]["Pid"])
                    != measured[:3]
                    or measured[3] != original["prepared"]["payload"]["candidateRuntimeId"]
                    or os.path.dirname(directory) != os.path.dirname(preflight.SOCKET)
                    or os.path.basename(directory) != "ledger"):
                raise ValueError("WAL readback is not the original private Xray mount")
            # Bind the host path to the exact process's mount namespace too;
            # Docker metadata alone cannot detect a replaced bind source.
            host = os.stat(directory, follow_symlinks=False)
            inside = os.stat(f"/proc/{measured[2]}/root{wal.journal.RUNTIME_DEST}/ledger",
                             follow_symlinks=False)
            if (not stat.S_ISDIR(host.st_mode) or not stat.S_ISDIR(inside.st_mode)
                    or (host.st_dev, host.st_ino) != (inside.st_dev, inside.st_ino)):
                raise ValueError("measured Xray kernel WAL mount differs from host source")
            deadline()
            return measured, directory

        measured, directory = remeasure()
        roster = preflight._full_signed_roster(fd, original, node, activation, pinned, measured)
        if (roster.profile_sha256 != original["reply"]["revision"]
                or roster.genesis_sha != original["reply"]["policySha256"]):
            raise ValueError("first-Genesis WAL roster differs from signed original")

        def recheck():
            if (pinned != wal._panel_pin()
                    or release != qualification.read_identity(qualification.QUALIFICATION)
                    or identity != preflight.quarantine._enrolled_activation(panel, node)):
                raise ValueError("enrollment or installed release changed during WAL readback")
            return remeasure()

        _check(roster, user, measured, directory, recheck, deadline)
        return None
    finally:
        os.close(lock)
        os.close(fd)
