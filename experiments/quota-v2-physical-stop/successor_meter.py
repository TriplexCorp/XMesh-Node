#!/usr/bin/env python3
"""NON-SPENDING isolated successor Xray meter observation (staging only).

Requires: independently pinned Nexus zero-spend preparation, fully closed
OLD Xray with independently checked WAL + final signed Nexus charge receipts,
and a NEW process in an independently measured private Docker/WAL namespace.

This does NOT allocate, sign, install or activate a positive cap, and cannot
refund, reset, or move an old byte. It is not remote hardware attestation.
"""
import hashlib
import os
from pathlib import Path
import stat
import time

import cap_install
import calendar_fence
import genesis_reservation as lease
import quarantine_policy as quarantine
import renewal_worker
import wal_transport

EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SUCCESSOR = "xmesh-successor-quarantine"


def _name(user, predecessor):
    return f"calendar-meter-u{user}-{predecessor}.json"


def _verify_fresh_container_env(docker):
    """Bind Xray's ACTUAL observed journal and strict-cap startup to the
    independently inspected Docker WAL mount. A clean, unused Docker bind
    is not proof if Xray secretly writes its bytes somewhere else.
    """
    import journal_integrity
    config = docker.get("Config") if isinstance(docker, dict) else None
    env = config.get("Env") if isinstance(config, dict) else None
    if not isinstance(env, list) or not all(isinstance(x, str) for x in env):
        raise ValueError("untrusted successor Xray process environment")
    required = {
        "GITHUB_ACTIONS": "true",
        "XMESH_EXPERIMENTAL_DRAIN": "1",
        "XMESH_EXPERIMENTAL_OBSERVED_DIR": journal_integrity.JOURNAL_DEST,
    }
    for name, value in required.items():
        found = [entry.split("=", 1)[1] for entry in env
                 if entry.startswith(name + "=")]
        if found != [value]:
            raise ValueError("successor Xray observed WAL environment differs from Docker bind")
    bindings = [entry.split("=", 1)[1] for entry in env
                if entry.startswith("XMESH_EXPERIMENTAL_SIGNED_CAP_BINDING=")]
    if len(bindings) != 1 or not os.path.isabs(bindings[0]):
        raise ValueError("new Xray must start with one absolute signed-cap binding")


def _clean_mount(old_dir, candidate_dir):
    """Require a distinct root-owned, *empty* WAL namespace at both checks."""
    old = os.open(old_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    candidate = os.open(candidate_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        a, b = os.fstat(old), os.fstat(candidate)
        if (not stat.S_ISDIR(a.st_mode) or not stat.S_ISDIR(b.st_mode)
                or a.st_uid != os.geteuid() or b.st_uid != os.geteuid()
                or stat.S_IMODE(a.st_mode) != 0o700
                or stat.S_IMODE(b.st_mode) != 0o700
                or (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)):
            raise ValueError("successor WAL root is foreign or shared with predecessor")
        names = os.listdir(candidate)
        if any(name != "xray-instance.lock" for name in names):
            raise ValueError("successor WAL is not a fresh empty meter namespace")
        # Xray must already hold its own private, source-pinned instance lock.
        # We do not assume this by just seeing a lock-shaped filename; the
        # independent PID and Unix-peer measurements check the live process.
        if "xray-instance.lock" not in names:
            raise ValueError("successor has no live Xray journal instance")
        lock = os.stat("xray-instance.lock", dir_fd=candidate, follow_symlinks=False)
        if (not stat.S_ISREG(lock.st_mode) or lock.st_uid != os.geteuid()
                or stat.S_IMODE(lock.st_mode) != 0o600 or lock.st_nlink != 1):
            raise ValueError("successor Xray runtime lock was replaced or linked")
    finally:
        os.close(candidate)
        os.close(old)


def _checked_marker(record, old, digest, measured, prep):
    required = {
        "nodeId", "userId", "predecessorId", "successorSha256",
        "candidateMeterEpoch", "candidateReservationId",
        "freshRuntimeId", "freshContainerId", "freshStartedAt",
        "freshHostPid", "freshExecutableSha256", "freshConfigSha256",
        "freshWalInventorySha256", "zeroInitialRawCounters",
        "isolatedNewWalRoot", "authorizedBytes", "canSpend", "canStart",
        "canResume", "finalMeterVerified", "refundableBytes",
    }
    expected = {
        "nodeId": old["nodeId"], "userId": old["userId"],
        "predecessorId": old["reservationId"],
        "successorSha256": digest,
        "candidateMeterEpoch": prep["meterEpoch"],
        "candidateReservationId": prep["reservationId"],
        "freshRuntimeId": measured[3], "freshContainerId": measured[0],
        "freshStartedAt": measured[1], "freshHostPid": measured[2],
        "freshWalInventorySha256": EMPTY_SHA,
        "zeroInitialRawCounters": True, "isolatedNewWalRoot": True,
        "authorizedBytes": 0, "canSpend": False, "canStart": False,
        "canResume": False, "finalMeterVerified": False,
        "refundableBytes": 0,
    }
    if (not isinstance(record, dict) or set(record) != required or
            any(type(record[k]) is not type(value) or record[k] != value
                for k, value in expected.items()) or
            not isinstance(record["freshExecutableSha256"], str) or
            not isinstance(record["freshConfigSha256"], str) or
            not all(len(record[k]) == 64 and
                    all(c in "0123456789abcdef" for c in record[k])
                    for k in ("freshExecutableSha256", "freshConfigSha256"))):
        raise ValueError("fresh meter marker changed its nonauthorizing signed scope")
    return record


def observe_successor_meter(node, user, state, socket_path, executable_pin, config_pin):
    """Capture the original signed scope and verify a separately pristine PID."""
    if (os.geteuid() != 0 or type(node) is not int or node <= 0
            or type(user) is not int or user <= 0
            or not isinstance(executable_pin, str)
            or not isinstance(config_pin, str)
            or any(calendar_fence.caps.HEX64.fullmatch(pin) is None
                   for pin in (executable_pin, config_pin))):
        raise ValueError("successor proof requires root and pinned fresh Xray files")
    fd, lock = quarantine._locked_private_state(state)
    try:
        names = os.listdir(fd)
        pinned = wal_transport._panel_pin()
        old = renewal_worker.latest_signed_cap(fd, names, node, user, pinned)
        now = time.time_ns() // 1_000_000
        if now < old["validUntilMs"]:
            raise ValueError("predecessor is not expired")
        prep_name = renewal_worker._successor_filename(user, old)
        reply = lease._identity_file(fd, prep_name, 16384)
        prep = renewal_worker._verify_successor_reply(
            reply, old, node, user, renewal_worker._successor_nonce(old),
            pinned, now)
        digest = hashlib.sha256(wal_transport.observed.canonical(reply)).hexdigest()
        old_closed_name = calendar_fence._fence_name(user, old["reservationId"])
        closed = lease._identity_file(fd, old_closed_name, 32768)
        calendar_fence._checked_saved(closed, old, digest, old["runtimeId"])
        # A local marker is strictly nonauthorizing and only identifies an
        # immutable original close, with off-host birth+charge confirmations.
        if (closed["oldWalChargeConfirmation"][
                "allOldStreamTailsNexusAcknowledged"] is not True):
            raise ValueError("old Xray WAL is not fully acknowledged")
        previous, old_root = wal_transport._bound_journal()
        fresh, fresh_root = wal_transport._bound_journal(SUCCESSOR)
        _verify_fresh_container_env(fresh)
        measured = wal_transport._measure_quarantined_runtime(
            (executable_pin, config_pin), container_name=SUCCESSOR)
        original = wal_transport._measure_quarantined_runtime()
        if (measured[0] == original[0] or measured[2] == original[2]
                or measured[3] == original[3] or measured[3] == old["runtimeId"]
                or measured[0] != fresh.get("Id")
                or measured[2] != fresh.get("State", {}).get("Pid")
                or measured[0] == previous.get("Id")):
            raise ValueError("new Xray is the predecessor or an untrusted PID")
        _clean_mount(old_root, fresh_root)
        if not 0 < len(old["aliasScopes"]) <= 16:
            raise ValueError("successor signed alias roster is missing")
        scope = {
            "schemaVersion": 1, "nodeId": node, "userId": user,
            "nonce": renewal_worker._successor_nonce(old),
            "meterEpoch": prep["meterEpoch"],
            "reservationId": prep["reservationId"],
            "aliases": old["aliasScopes"],
        }
        observation = cap_install.observe_zero_meter_in_xray(
            socket_path, measured[2], measured[3], scope)
        _clean_mount(old_root, fresh_root)
        if wal_transport._measure_quarantined_runtime(
                (executable_pin, config_pin), container_name=SUCCESSOR) != measured:
            raise ValueError("fresh Xray changed during zero-counter proof")
        marker = {
            "nodeId": node, "userId": user,
            "predecessorId": old["reservationId"], "successorSha256": digest,
            "candidateMeterEpoch": prep["meterEpoch"],
            "candidateReservationId": prep["reservationId"],
            "freshRuntimeId": measured[3], "freshContainerId": measured[0],
            "freshStartedAt": measured[1], "freshHostPid": measured[2],
            "freshExecutableSha256": executable_pin,
            "freshConfigSha256": config_pin,
            "freshWalInventorySha256": observation["inventorySha256"],
            "zeroInitialRawCounters": observation["zeroInitialRawCounters"],
            "isolatedNewWalRoot": observation["isolatedNewWalRoot"],
            "authorizedBytes": 0, "canSpend": False, "canStart": False,
            "canResume": False, "finalMeterVerified": False,
            "refundableBytes": 0,
        }
        _checked_marker(marker, old, digest, measured, prep)
        name = _name(user, old["reservationId"])
        if name in names:
            saved = lease._identity_file(fd, name, 16384)
            _checked_marker(saved, old, digest, measured, prep)
            if saved != marker:
                raise ValueError("recorded fresh Xray proof conflicts with new measurement")
            return False
        quarantine._durable_store(fd, marker, name)
        return True
    finally:
        os.close(lock)
        os.close(fd)
