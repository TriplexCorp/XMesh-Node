#!/usr/bin/env python3
"""Stage-only, strict-XSP/2 WAL charge sender before signed cap replenishment.

Never supplies authority or refunds a reservation. Replays exact contiguous
fsynced byte-intent journal fragments and verifies Nexus-signed receipts.
An ACK lost after SQL COMMIT is retried from the last durable signed receipt.
"""
import base64
import bisect
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

import first_cap_handoff as caps
import genesis_reservation as lease
import journal_integrity as journal
import meter_inventory_audit as registry
import quarantine_policy as quarantine
import renewal_worker
import wal_transport

DOMAIN = b"XMESH_QUOTA_V2_WAL_CHARGE_V1\x00"
BATCH_BYTES = 56 * 1024
MAX_BATCHES_PER_POLL = 8
MAX_WAL_BYTES = 64 << 20
CURSOR_FILE = "wal-charge-scan-cursor.json"
STREAM = re.compile(r"meter-[0-9a-f]{64}\.jsonl\Z")


def _bytes_after_validation(fd, name, expected_digest):
    before = os.stat(name, dir_fd=fd, follow_symlinks=False)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1 or not 0 < before.st_size <= MAX_WAL_BYTES):
        raise ValueError("unsafe local Xray WAL inode")
    handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                     dir_fd=fd)
    try:
        opened = os.fstat(handle)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
                before.st_dev, before.st_ino, before.st_size):
            raise ValueError("WAL inode replaced during open")
        raw = bytearray()
        while len(raw) < before.st_size:
            chunk = os.read(handle, min(65536, before.st_size - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if ((after.st_dev, after.st_ino, after.st_size) !=
                (before.st_dev, before.st_ino, before.st_size)
                or hashlib.sha256(raw).hexdigest() != expected_digest
                or not raw.endswith(b"\n")):
            raise ValueError("live WAL changed while preparing authenticated charge")
        return bytes(raw)
    finally:
        os.close(handle)


def _validate_receipt(receipt, pinned, public_file, request, birth, first, last):
    doc = wal_transport.observed.strict_json(receipt)
    if (not isinstance(doc, dict)
            or set(doc) != {"algorithm", "payload", "signature"}
            or doc["algorithm"] != "Ed25519"
            or receipt != wal_transport.observed.canonical(doc) + b"\n"):
        raise ValueError("noncanonical signed WAL charge acknowledgment")
    wal_transport.verifier.verify_nexus_signature(
        DOMAIN, doc["payload"], doc["signature"], public_file)
    p = doc["payload"]
    if (not isinstance(p, dict)
            or set(p) != {
                "schemaVersion", "kind", "nodeId", "userId", "reservationId",
                "runtimeId", "filename", "firstSequence", "lastSequence",
                "lastDigest", "journalSha256", "streamBytes",
                "conservativeWalBytes", "conservativeCdnWalBytes",
                "canResume", "finalMeterVerified", "refundableBytes"}
            or type(p["schemaVersion"]) is not int or p["schemaVersion"] != 1
            or p["kind"] != "xmesh.quota-v2.wal-intent-charge"
            or p["nodeId"] != request["nodeId"]
            or p["userId"] != request["userId"]
            or p["reservationId"] != request["reservationId"]
            or p["runtimeId"] != birth["runtimeId"]
            or p["filename"] != request["filename"]
            or p["firstSequence"] != first["sequence"]
            or p["lastSequence"] != last["sequence"]
            or p["lastDigest"] != last["digest"]
            or p["journalSha256"] != hashlib.sha256(request["raw"]).hexdigest()
            or p["streamBytes"] != last["nextBytes"]
            or type(p["conservativeWalBytes"]) is not int
            or type(p["conservativeCdnWalBytes"]) is not int
            or p["conservativeWalBytes"] < p["streamBytes"]
            or not 0 <= p["conservativeCdnWalBytes"] <= p["conservativeWalBytes"]
            or p["canResume"] is not False
            or p["finalMeterVerified"] is not False
            or p["refundableBytes"] != 0):
        raise ValueError("signed WAL receipt does not match exact local intent")
    return p


def _durable_cursor(fd, names, filename, user, node, grant, lines, pinned, public_file):
    key = hashlib.sha256(filename.encode("ascii")).hexdigest()
    marker = re.compile(r"wal-charge-" + key + r"-s([1-9][0-9]{0,18})\.json\Z")
    saved = []
    for name in names:
        m = marker.fullmatch(name)
        if m:
            saved.append((int(m.group(1)), name))
    if len(saved) > 8192:
        raise ValueError("unbounded local WAL acknowledgments")
    if not saved:
        return (0, key)
    number, name = max(saved)
    if number > len(lines):
        raise ValueError("WAL shorter than independently signed charge cursor")
    evidence = lease._identity_file(fd, name, 8192)
    if (not isinstance(evidence, dict) or set(evidence) != {
            "nodeId", "userId", "reservationId", "filename", "signedReceipt"}
            or evidence["nodeId"] != node or evidence["userId"] != user
            or evidence["reservationId"] != grant["reservationId"]
            or evidence["filename"] != filename
            or not isinstance(evidence["signedReceipt"], str)):
        raise ValueError("local charge cursor has foreign or corrupt authority")
    raw = wal_transport._b64(evidence["signedReceipt"], 4096)
    doc = wal_transport.observed.strict_json(raw)
    if (not isinstance(doc, dict)
            or set(doc) != {"algorithm", "payload", "signature"}
            or raw != wal_transport.observed.canonical(doc) + b"\n"
            or doc["algorithm"] != "Ed25519"):
        raise ValueError("invalid saved WAL charge signature envelope")
    wal_transport.verifier.verify_nexus_signature(
        DOMAIN, doc["payload"], doc["signature"], public_file)
    p = doc["payload"]
    if (p.get("nodeId") != node or p.get("userId") != user
            or p.get("reservationId") != grant["reservationId"]
            or p.get("filename") != filename
            or p.get("lastSequence") != number
            or p.get("lastDigest") != lines[number-1]["digest"]
            or p.get("streamBytes") != lines[number-1]["nextBytes"]
            or p.get("finalMeterVerified") is not False
            or p.get("refundableBytes") != 0):
        raise ValueError("durable WAL charge cursor is not a matching signed prefix")
    return (number, key)


def _chunks(raw):
    pending = []
    size = 0
    for line in raw.splitlines(keepends=True):
        if not line.endswith(b"\n") or len(line) > 1024:
            raise ValueError("torn or oversized Xray WAL record")
        if pending and size + len(line) > BATCH_BYTES:
            yield b"".join(pending)
            pending, size = [], 0
        pending.append(line)
        size += len(line)
    if pending:
        yield b"".join(pending)


def _durable_request(fd, key, node, user, reservation, filename, remaining):
    """Persist the EXACT charge batch before its possible SQL COMMIT.

    Resizing a batch after a lost response would collide with the immutable
    PostgreSQL first-sequence key. Always replay the original bytes, even if
    the live Xray has appended more fsynced WAL in the meantime.
    """
    if not remaining or not remaining.endswith(b"\n"):
        raise ValueError("no complete charge WAL suffix")
    first = wal_transport.observed.strict_json(remaining.splitlines()[0])
    sequence = first.get("sequence")
    if type(sequence) is not int or sequence <= 0:
        raise ValueError("invalid WAL charge request sequence")
    name = f"wal-charge-request-{key}-s{sequence}.json"
    try:
        saved = lease._identity_file(fd, name, 128 * 1024)
    except FileNotFoundError:
        raw = next(_chunks(remaining))
        saved = {
            "nodeId": node, "userId": user, "reservationId": reservation,
            "filename": filename, "firstSequence": sequence,
            "journal": base64.b64encode(raw).decode("ascii"),
        }
        quarantine._durable_store(fd, saved, name)
    if (not isinstance(saved, dict) or set(saved) != {
            "nodeId", "userId", "reservationId", "filename",
            "firstSequence", "journal"}
            or saved["nodeId"] != node or saved["userId"] != user
            or saved["reservationId"] != reservation
            or saved["filename"] != filename
            or saved["firstSequence"] != sequence):
        raise ValueError("foreign immutable WAL charge retry")
    raw = wal_transport._b64(saved["journal"], BATCH_BYTES)
    if (not remaining.startswith(raw) or not raw.endswith(b"\n")
            or len(raw) > BATCH_BYTES):
        raise ValueError("original WAL charge request differs from current hash chain")
    return raw


def _next_charge_batch(fd, node, streams):
    try:
        cursor = lease._identity_file(fd, CURSOR_FILE, 256)
    except FileNotFoundError:
        previous = ""
    else:
        if (not isinstance(cursor, dict) or set(cursor) != {"nodeId", "lastStream"}
                or type(cursor["nodeId"]) is not int or cursor["nodeId"] != node
                or not isinstance(cursor["lastStream"], str)
                or STREAM.fullmatch(cursor["lastStream"]) is None):
            raise ValueError("foreign or corrupt WAL charging cursor")
        previous = cursor["lastStream"]
    start = bisect.bisect_right(streams, previous) % len(streams)
    selected = (streams[start:] + streams[:start])[:MAX_BATCHES_PER_POLL]
    renewal_worker.store_scan_cursor(fd, CURSOR_FILE,
                                    {"nodeId": node, "lastStream": selected[-1]})
    return selected


def _grant_for_birth(fd, node, user, pinned, birth):
    # Renewals retain the original reservation. Charging uses the proof tied
    # to the birth, not the user's currently installed revision or runtime.
    runtime = birth["runtimeId"]
    try:
        grant = renewal_worker._verified_reply(
            fd, caps.wal_cap_filename(user, runtime), pinned)
    except FileNotFoundError:
        # Earlier installed Agents only persisted their original admission
        # receipt. Never fall back when an existing archived proof is corrupt.
        grant = renewal_worker._verified_reply(
            fd, f"genesis-positive-cap-u{user}.json", pinned)
    if (grant["kind"] != "xmesh.quota-v2.xray-cap-admission"
            or grant["nodeId"] != node or grant["userId"] != user
            or grant["runtimeId"] != runtime
            or not any(a["email"] == birth["email"] for a in grant["aliasScopes"])):
        raise ValueError("WAL witness refers to a foreign signed Xray permit")
    return grant


def _charge_stream(fd, state_fd, state_names, node, pinned, public, filename, birth, digest, user, allowance):
    grant = _grant_for_birth(state_fd, node, user, pinned, birth)
    raw = _bytes_after_validation(fd, filename, digest)
    lines = [wal_transport.observed.strict_json(line)
             for line in raw.splitlines()]
    if (not lines or len(lines) > 2**20 or
            any(type(row.get("sequence")) is not int or
                row["sequence"] != i + 1 for i, row in enumerate(lines))):
        raise ValueError("Xray WAL sequence is not contiguous")
    position, key = _durable_cursor(
        state_fd, state_names, filename, user, node, grant,
        lines, pinned, public)
    if position == len(lines):
        return 0
    all_lines = raw.splitlines(keepends=True)
    submitted = 0
    while position < len(lines) and submitted < allowance:
        remaining = b"".join(all_lines[position:])
        batch = _durable_request(
            state_fd, key, node, user, grant["reservationId"],
            filename, remaining)
        first = wal_transport.observed.strict_json(batch.splitlines()[0])
        last = wal_transport.observed.strict_json(batch.splitlines()[-1])
        request = {
            "operation": "charge", "nodeId": node,
            "reservationId": grant["reservationId"],
            "filename": filename,
            "journal": base64.b64encode(batch).decode("ascii"),
        }
        with tempfile.TemporaryDirectory(prefix="xmesh-charge-xsp-") as tmp:
            reply = wal_transport.observed.strict_json(
                wal_transport._post(Path(tmp), request))
        if not isinstance(reply, dict) or set(reply) != {"receipt"}:
            raise ValueError("Nexus returned no signed WAL charge receipt")
        receipt = wal_transport._b64(reply["receipt"], 4096)
        _validate_receipt(
            receipt, pinned, public,
            {"nodeId": node, "userId": user,
             "reservationId": grant["reservationId"],
             "filename": filename, "raw": batch},
            birth, first, last)
        evidence = {
            "nodeId": node, "userId": user,
            "reservationId": grant["reservationId"],
            "filename": filename, "signedReceipt": reply["receipt"],
        }
        quarantine._durable_store(
            state_fd, evidence,
            f"wal-charge-{key}-s{last['sequence']}.json")
        position = last["sequence"]
        submitted += 1
    return submitted


def run(panel, node, state="/var/lib/xmesh-xray-sync", failed_users=None):
    if (os.geteuid() != 0 or
            os.environ.get("XMESH_QUOTA_V2_AUTO_RENEW_STAGING") != "1" or
            os.environ.get("XMESH_QUOTA_V2_INSTALLED_CAP_DELIVERY") != "1"
            or not isinstance(panel, str) or not panel.startswith("https://")
            or type(node) is not int or node <= 0):
        raise ValueError("WAL charging requires an explicit staged root Agent")
    # The off-host birth index precedes spending authorization. Keep its
    # existing independently verified signed XSP/2 checkpoint mechanism.
    wal_transport.run("charge-sync", panel, node)
    docker, local = wal_transport._bound_journal()
    journal._verify_mount(docker, local)
    fd = journal._validate_directory(local)
    try:
        state_fd, lock = quarantine._locked_private_state(state)
    except BaseException:
        os.close(fd)
        raise
    submitted = 0
    try:
        names = os.listdir(fd)
        streams = sorted(name for name in names
                         if STREAM.fullmatch(name))
        entries, verified = registry.verify_meter_inventory(
            fd, streams, journal._read_meter_wal, journal._canonical_go)
        if not entries:
            return 0
        pinned = wal_transport._panel_pin()
        state_names = os.listdir(state_fd)
        with tempfile.TemporaryDirectory(prefix="xmesh-charge-key-") as tmp:
            public = Path(tmp) / "panel.pem"
            wal_transport._write_public(pinned, public)
            selected = _next_charge_batch(state_fd, node, sorted(entries))
            per_stream, extra = divmod(MAX_BATCHES_PER_POLL, len(selected))
            for offset, filename in enumerate(selected):
                birth = entries[filename]
                match = registry.EMAIL.fullmatch(birth["email"])
                if match is None:
                    raise ValueError("WAL email is outside signed Node user scope")
                user = int(match.group(1))
                try:
                    submitted += _charge_stream(
                        fd, state_fd, state_names, node, pinned, public, filename,
                        birth, verified[filename][1], user, per_stream + (offset < extra))
                except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
                    # A per-stream authority or ACK failure must not stall
                    # other streams. The verified inventory itself remains
                    # mandatory before we process any of them.
                    if failed_users is not None:
                        failed_users.add(user)
                    print(f"Quota V2 user {user} WAL stream refused: "
                          f"{type(error).__name__}", flush=True)
    finally:
        os.close(lock)
        os.close(state_fd)
        os.close(fd)
    return submitted
