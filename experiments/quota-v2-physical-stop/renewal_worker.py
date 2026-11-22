#!/usr/bin/env python3
"""Opt-in Agent poll for a measured, quarantined Genesis runtime.

This staging worker starts after signed quarantine. The metered runtime
and its network isolation are managed separately. All authority comes from signed Nexus XSP/2 replies.
Persistent per-revision challenges ensure lost responses retry the exact SQL
transaction instead of silently creating a second issuance.
"""
import argparse
import bisect
import hashlib
import os
import re
import secrets
import subprocess
import tempfile
import time

import first_cap_handoff as caps
import genesis_reservation as lease
import quarantine_policy as quarantine
import wal_transport

STAGING_ENV = "XMESH_QUOTA_V2_AUTO_RENEW_STAGING"
STATE = "/var/lib/xmesh-xray-sync"
SOCKET = "/var/lib/xmesh-measured-lab/wal/drain.sock"
BASE = re.compile(r"genesis-positive-cap-u([1-9][0-9]{0,18})\.json\Z")
RENEW = re.compile(r"genesis-renewal-u([1-9][0-9]{0,18})-r([1-9][0-9]{0,18})\.json\Z")
MAX_USERS = 2048
MAX_PER_POLL = 16
CURSOR_FILE = "genesis-renewal-scan-cursor.json"
ADMISSION_CURSOR_FILE = "genesis-admission-scan-cursor.json"
PIN_KEYS = ("nodeId", "userId", "activationReceiptSha256", "runtimeId",
            "policySha256", "accountEpoch", "meterEpoch", "reservationId",
            "aliasScopes", "validUntilMs")


def _verified_reply(fd, name, pinned):
    document = lease._identity_file(fd, name, 16384)
    if not isinstance(document, dict) or set(document) != {
            "status", "nodeId", "userId", "signedEnvelope"}:
        raise ValueError("unrecognized root-owned signed-cap receipt")
    encoded = document["signedEnvelope"]
    if not isinstance(encoded, str):
        raise ValueError("nontext durable signed-cap receipt")
    with tempfile.TemporaryDirectory(prefix="xmesh-autorenewevidence-") as temp:
        public = os.path.join(temp, "pinned.pem")
        wal_transport._write_public(pinned, public)
        payload = caps._verify_cap_envelope(encoded.encode(), pinned, public)
    if document["nodeId"] != payload["nodeId"] or document["userId"] != payload["userId"]:
        raise ValueError("durable signed-cap receipt changed its owner")
    if document["status"] not in ("committed_first_cap", "committed_renewal"):
        raise ValueError("durable signed-cap receipt has invalid status")
    return payload


def latest_signed_cap(fd, names, node, user, pinned):
    base = _verified_reply(fd, f"genesis-positive-cap-u{user}.json", pinned)
    if (base["kind"] != "xmesh.quota-v2.xray-cap-admission"
            or base["nodeId"] != node or base["userId"] != user
            or type(base["reservationRevision"]) is not int
            or base["reservationRevision"] <= 0):
        raise ValueError("missing signed installed first-cap identity")
    original = base
    revisions = {}
    for name in names:
        match = RENEW.fullmatch(name)
        if match is not None and int(match.group(1)) == user:
            revision = int(match.group(2))
            if revision in revisions:
                raise ValueError("conflicting durable renewal filenames")
            revisions[revision] = name
    if len(revisions) > 2048:
        raise ValueError("excessive durable renewal evidence")
    for rev in sorted(revisions):
        current = _verified_reply(fd, revisions[rev], pinned)
        if (current["kind"] != "xmesh.quota-v2.xray-cap-renewal"
                or current["reservationRevision"] != rev
                or rev != original["reservationRevision"] + 1
                or any(current[field] != base[field] for field in PIN_KEYS)
                or current["sharedCeilingBytes"] < original["sharedCeilingBytes"]
                or current["nodeCeilingBytes"] < original["nodeCeilingBytes"]
                or current["cdnCeilingBytes"] < original["cdnCeilingBytes"]
                or current["issuedAtMs"] < original["issuedAtMs"]):
            raise ValueError("durable signed renewal chain changed authority")
        original = current
    return original


def _candidate(fd, names, node, user, pinned, now):
    original = latest_signed_cap(fd, names, node, user, pinned)
    if not original["issuedAtMs"] <= now < original["validUntilMs"]:
        return None
    revision = original["reservationRevision"]
    name = f"genesis-renewal-request-u{user}-r{revision}.json"
    if name in names:
        request = lease._identity_file(fd, name, 4096)
        if (not isinstance(request, dict)
                or set(request) != {"nodeId", "userId", "previousRevision", "requestChallenge"}
                or request["nodeId"] != node or request["userId"] != user
                or request["previousRevision"] != revision
                or not isinstance(request["requestChallenge"], str)
                or caps.HEX64.fullmatch(request["requestChallenge"]) is None):
            raise ValueError("previous renewal request nonce is corrupt")
        challenge = request["requestChallenge"]
    else:
        challenge = secrets.token_hex(32)
    return (user, revision, challenge)



def _durable_scan_cursor(state_fd, node, last_user, filename=CURSOR_FILE):
    """Advance a scheduling-only cursor; no quota entitlement lives here.

    Atomic replacement and a parent fsync survive a service restart without
    silently resetting the work queue to its first 16 users. The same root
    lock protecting signed evidence also serializes competing worker ticks.
    """
    if (type(node) is not int or node <= 0 or
            type(last_user) is not int or last_user <= 0):
        raise ValueError("invalid quota renewal scan cursor")
    store_scan_cursor(state_fd, filename, {"nodeId": node, "lastUserId": last_user})


def store_scan_cursor(state_fd, filename, cursor):
    raw = wal_transport.observed.canonical(cursor)
    temporary = ".genesis-renewal-scan-" + secrets.token_hex(16)
    output = os.open(temporary,
                     os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                     os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=state_fd)
    try:
        with os.fdopen(output, "wb", closefd=True) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, filename,
                   src_dir_fd=state_fd, dst_dir_fd=state_fd)
        os.fsync(state_fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=state_fd)
        except FileNotFoundError:
            pass


def _next_scan_batch(state_fd, users, node, filename=CURSOR_FILE):
    """Round-robin by persisted user ID, not by unreliable wall-clock slots.

    A 20-second timer with a 16-user batch must advance by 16 users, not
    move the window by one. User IDs remain ordered when users are created
    or removed. A stale/malformed root-owned cursor fails closed.
    """
    if not users or users != sorted(set(users)):
        raise ValueError("invalid ordered quota renewal work queue")
    try:
        saved = lease._identity_file(state_fd, filename, 256)
    except FileNotFoundError:
        last_user = 0
    else:
        if (not isinstance(saved, dict) or set(saved) != {"nodeId", "lastUserId"}
                or type(saved["nodeId"]) is not int or saved["nodeId"] != node
                or type(saved["lastUserId"]) is not int
                or saved["lastUserId"] <= 0):
            raise ValueError("quota renewal scan cursor is corrupt or foreign")
        last_user = saved["lastUserId"]
    start = bisect.bisect_right(users, last_user) % len(users)
    batch = (users[start:] + users[:start])[:MAX_PER_POLL]
    _durable_scan_cursor(state_fd, node, batch[-1], filename)
    return batch


def pending_renewals(state, node, pinned, now=None):
    """Read only immutable signed state under the synchronizer's root lock."""
    instant = time.time_ns() // 1_000_000 if now is None else now
    fd, lock = quarantine._locked_private_state(state)
    try:
        names = os.listdir(fd)
        users = set()
        for name in names:
            match = BASE.fullmatch(name)
            if match is not None:
                users.add(int(match.group(1)))
        if len(users) > MAX_USERS:
            raise ValueError("too many first-cap users for bounded renewal polling")
        selected = sorted(users)
        if not selected:
            return []
        # Durable round-robin: wall-clock slots can repeat or skip whenever
        # a systemd run exceeds 20 seconds; neither case may starve users.
        selected = _next_scan_batch(fd, selected, node)
        jobs = []
        for user in selected:
            try:
                item = _candidate(fd, names, node, user, pinned, instant)
            except (ValueError, OSError, KeyError, TypeError) as error:
                # A damaged signed receipt belongs to THIS user. Its cap
                # remains closed, but it must not prevent other users in the
                # same bounded batch from reaching their verified renewals.
                # Never print signed payloads, paths or credentials.
                print(f"Quota V2 user {user} renewal evidence refused: "
                      f"{type(error).__name__}", flush=True)
                continue
            if item is not None:
                jobs.append(item)
        return jobs
    finally:
        os.close(lock)
        os.close(fd)


def first_cap_challenge(genesis_challenge, user):
    # The immutable Genesis challenge survives a lost Nexus or Unix response.
    message = f"XMESH_QUOTA_V2_FIRST_CAP_V1\0{genesis_challenge}\0{user}".encode("ascii")
    return hashlib.sha256(message).hexdigest()


def activate_initial_cap(panel, node, state, socket_path):
    fd, lock = quarantine._locked_private_state(state)
    try:
        original = lease._identity_file(
            fd, "genesis-quarantine-envelope.json", quarantine.MAX_REPLY + 4096)
        users = original["reply"]["policy"]["users"]
        if not isinstance(users, list) or len(users) > MAX_USERS:
            raise ValueError("invalid admission queue size")
        ids = [entry.get("userId") for entry in users if isinstance(entry, dict)]
        if (len(ids) != len(users)
                or any(type(user) is not int or not 0 < user < 2**63 for user in ids)
                or len(set(ids)) != len(ids)):
            raise ValueError("invalid or duplicate quarantine user identity")
        names = set(os.listdir(fd))
        pending = sorted(user for user in ids
                         if f"genesis-positive-cap-u{user}.json" not in names)
        # Only setup within the signed Genesis window. Expiry of this
        # first-admission proof cannot stall already installed renewals.
        if not pending or time.time_ns() // 1_000_000 >= original["prepared"]["payload"]["validUntilMs"]:
            return 0
        batch = _next_scan_batch(fd, pending, node, ADMISSION_CURSOR_FILE)
    finally:
        os.close(lock)
        os.close(fd)
    installed = 0
    for user in batch:
        try:
            installed += _activate_user(panel, node, user, state, socket_path)
        except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
            print(f"Quota V2 user {user} initial admission refused: "
                  f"{type(error).__name__}", flush=True)
    return installed


def _activate_user(panel, node, user, state, socket_path):
    fd, lock = quarantine._locked_private_state(state)
    try:
        names = set(os.listdir(fd))
        if f"genesis-positive-cap-u{user}.json" in names:
            return False
        pinned = wal_transport._panel_pin()
        active = quarantine._enrolled_activation(panel, node)
        original = lease._staged_original(
            fd, node, user, pinned, active["activationReceiptSha256"])
        executable, _ = lease._original_measurement_pins(
            fd, original, node, active["activationReceiptSha256"])
        challenge = first_cap_challenge(original["prepared"]["payload"]["challenge"], user)
        prepared_name = f"genesis-reservation-prepared-u{user}.json"
        confirmed_name = f"genesis-reservation-confirmed-u{user}.json"
        needs_prepare = prepared_name not in names
        needs_confirm = confirmed_name not in names
        if not needs_confirm and needs_prepare:
            raise ValueError("confirmed reservation is missing its prepared identity")
        if not needs_prepare:
            prepared = lease.verify_lease_response(
                wal_transport.observed.canonical(lease._identity_file(fd, prepared_name, lease.MAX_REPLY)),
                node, user, "prepare", original, pinned, active["activationReceiptSha256"])
            if not needs_confirm:
                lease.verify_lease_response(
                    wal_transport.observed.canonical(lease._identity_file(fd, confirmed_name, lease.MAX_REPLY)),
                    node, user, "confirm", original, pinned, active["activationReceiptSha256"],
                    previous=prepared)
    finally:
        os.close(lock)
        os.close(fd)
    if needs_prepare:
        lease.run(panel, node, user, state, "prepare")
    if needs_confirm:
        lease.run(panel, node, user, state, "confirm")
    caps.fetch_and_install_rehearsal(
        panel, node, user, state, socket_path, executable, challenge)
    return True


def run(panel, node, state=STATE, socket_path=SOCKET):
    if (os.geteuid() != 0 or os.environ.get(STAGING_ENV) != "1"
            or os.environ.get("XMESH_QUOTA_V2_INSTALLED_CAP_DELIVERY") != "1"
            or not isinstance(panel, str) or not panel.startswith("https://")
            or type(node) is not int or node <= 0):
        raise ValueError("automatic renewal is permitted only in explicit root staging")
    # Reconcile fsynced debt before doing any admission work. An expired or
    # malformed Genesis candidate must not stall charging for existing users.
    # The charge worker verifies the remote head before processing streams.
    import charge_worker
    failed_users = set()
    charge_worker.run(panel, node, state, failed_users)
    installed = activate_initial_cap(panel, node, state, socket_path)
    pinned = wal_transport._panel_pin()
    jobs = pending_renewals(state, node, pinned)
    if not jobs:
        return installed
    fd, lock = quarantine._locked_private_state(state)
    try:
        intent = lease._identity_file(fd, quarantine.INTENT_FILE, 4096)
        if (not isinstance(intent, dict) or intent.get("nodeId") != node
                or not isinstance(intent.get("executableSha256"), str)
                or caps.HEX64.fullmatch(intent["executableSha256"]) is None):
            raise ValueError("missing root-pinned original Xray executable")
        executable = intent["executableSha256"]
    finally:
        os.close(lock)
        os.close(fd)
    for user, revision, challenge in jobs:
        if user in failed_users:
            continue
        try:
            caps.fetch_and_install_renewal(
                panel, node, user, state, socket_path,
                executable, challenge, revision)
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            # A 409 while half of the reservation remains is expected.
            # The immutable nonce persists, so a retry cannot change the
            # SQL request identity. Never continue with a guessed permit.
            print(f"Quota V2 renewal denied for user {user}: {type(exc).__name__}",
                  flush=True)
        else:
            installed += 1
    return installed


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel", required=True)
    parser.add_argument("--node-id", required=True, type=int)
    parser.add_argument("--state", default=STATE)
    parser.add_argument("--socket", default=SOCKET)
    args = parser.parse_args()
    try:
        count = run(args.panel, args.node_id, args.state, args.socket)
        print(f"Quota V2 staged automatic renewals installed: {count}")
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Quota V2 automatic renewal refused: {error}\n")
