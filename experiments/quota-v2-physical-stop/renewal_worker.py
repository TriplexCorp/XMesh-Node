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
import uuid

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
    if document["status"] == "committed_calendar_successor":
        if (payload["kind"] != "xmesh.quota-v2.xray-cap-admission"
                or name != caps.wal_cap_filename(payload["userId"], payload["runtimeId"])):
            raise ValueError("successor cap must be archived for its exact WAL runtime")
    elif document["status"] not in ("committed_first_cap", "committed_renewal"):
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
    # On a service restart the already installed, durable first-generation
    # signed cap may still be current while its per-user ingress symlink is
    # missing. Repair only a MISSING route, never overwrite another runtime,
    # and never resurrect an already fenced calendar predecessor.
    if (os.environ.get("XMESH_QUOTA_V2_INGRESS_STAGING") == "1"
            and now < original["validUntilMs"]):
        import calendar_fence
        if calendar_fence._fence_name(user, original["reservationId"]) not in names:
            try:
                os.readlink(f"ingress-u{user}", dir_fd=fd)
            except FileNotFoundError:
                return user, -3, original["nonce"]
    if now >= original["validUntilMs"]:
        successor_name = _successor_filename(user, original)
        if successor_name in names:
            # Existing zero-spend preparation is NOT a completed transition.
            # Keep scheduling until the measured Xray has durably fenced its
            # old user and returned a nonfinal WAL checkpoint.
            saved = lease._identity_file(fd, successor_name, 16384)
            prepared = _verify_successor_reply(
                saved, original, node, user, _successor_nonce(original),
                pinned, now)
            import calendar_fence
            name = calendar_fence._fence_name(user, original["reservationId"])
            if name in names:
                observed = lease._identity_file(fd, name, 32768)
                digest = hashlib.sha256(wal_transport.observed.canonical(saved)).hexdigest()
                calendar_fence._checked_saved(
                    observed, original, digest, original["runtimeId"])
                # Optional SECOND, zero-spend stage. It never resumes
                # ingress. Only source-pinned isolated successor Xray may
                # respond, and it must have an empty private WAL namespace.
                if os.environ.get("XMESH_QUOTA_V2_FRESH_METER_STAGING") == "1":
                    import successor_meter
                    zero_name = successor_meter._name(user, original["reservationId"])
                    if zero_name not in names:
                        return user, -1, _successor_nonce(original)
                    # Never treat a filename as proof that a separately
                    # measured Xray supplied a valid zero-spend receipt.
                    evidence = lease._identity_file(fd, zero_name, 16384)
                    measured = (evidence.get("freshContainerId"),
                                evidence.get("freshStartedAt"),
                                evidence.get("freshHostPid"),
                                evidence.get("freshRuntimeId"))
                    successor_meter._checked_marker(
                        evidence, original, digest, measured, prepared)
                    if os.environ.get("XMESH_QUOTA_V2_AUTO_SUCCESSOR_POSITIVE") == "1":
                        import successor_positive
                        positive_name = successor_positive._filename(
                            user, original["reservationId"])
                        if positive_name not in names:
                            return user, -2, successor_positive._challenge(
                                original["reservationId"], measured[3])
                        successor_positive._verified_saved_receipt(
                            lease._identity_file(fd, positive_name, 32768),
                            original, prepared, evidence, node, user, pinned)
                        if os.environ.get("XMESH_QUOTA_V2_INGRESS_STAGING") == "1":
                            import vless_ingress
                            try:
                                published = os.readlink(f"ingress-u{user}", dir_fd=fd)
                            except FileNotFoundError:
                                published = None
                            if published != vless_ingress.target(measured[2], measured[3]):
                                return user, -2, successor_positive._challenge(
                                    original["reservationId"], measured[3])
                return None
        return user, 0, _successor_nonce(original)
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


def _restore_initial_ingress(panel, node, user, state):
    """Crash-reconcile only the SAME previously installed signed Xray cap.

    Never creates a lease, retries positive issuance, reuses an expired cap,
    or changes an existing route. A recorded calendar fence is irreversible.
    """
    if os.environ.get("XMESH_QUOTA_V2_INGRESS_STAGING") != "1":
        return False
    import calendar_fence
    import vless_ingress
    fd, lock = quarantine._locked_private_state(state)
    try:
        names = os.listdir(fd)
        if f"genesis-positive-cap-u{user}.json" not in names:
            return False
        pinned = wal_transport._panel_pin()
        grant = latest_signed_cap(fd, names, node, user, pinned)
        if (time.time_ns() // 1_000_000 >= grant["validUntilMs"]
                or calendar_fence._fence_name(user, grant["reservationId"]) in names):
            return False
        activation = quarantine._enrolled_activation(panel, node)
        original = lease._identity_file(
            fd, "genesis-quarantine-envelope.json", quarantine.MAX_REPLY + 4096)
        if (not isinstance(original, dict)
                or set(original) != {"prepared", "reply"}
                or grant["activationReceiptSha256"] !=
                    activation["activationReceiptSha256"]
                or grant["runtimeId"] !=
                    original["prepared"]["payload"]["candidateRuntimeId"]):
            raise ValueError("historical signed first-generation ingress changed identity")
        config_pin = calendar_fence._original_signed_scope(
            fd, grant, node, pinned)
        pins = lease._original_measurement_pins(
            fd, original, node, activation["activationReceiptSha256"])
        if config_pin != pins[1]:
            raise ValueError("stored first-generation ingress config differs from pinned Xray")
        measured = wal_transport._measure_quarantined_runtime(pins)
        if measured[3] != grant["runtimeId"]:
            raise ValueError("first-generation ingress Xray restarted without fresh authorization")
        link = f"ingress-u{user}"
        try:
            existing = os.readlink(link, dir_fd=fd)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            if existing != vless_ingress.target(measured[2], measured[3]):
                raise ValueError("foreign ingress route cannot be healed by original cap")
            return False
        # After the signed policy, installed receipt, active deadline and
        # independently measured kernel PID all agree, publish only the
        # original existing cap's missing user link.
        vless_ingress.publish(fd, grant, measured)
        return True
    finally:
        os.close(lock)
        os.close(fd)


def first_cap_challenge(genesis_challenge, user):
    # The immutable Genesis challenge survives a lost Nexus or Unix response.
    message = f"XMESH_QUOTA_V2_FIRST_CAP_V1\0{genesis_challenge}\0{user}".encode("ascii")
    return hashlib.sha256(message).hexdigest()


def _successor_filename(user, previous):
    predecessor = uuid.UUID(previous["reservationId"])
    return f"calendar-successor-u{user}-{predecessor}.json"


def _successor_nonce(previous):
    raw = f"XMESH_QUOTA_V2_CALENDAR_SUCCESSOR_REQUEST_V1\0{uuid.UUID(previous['reservationId'])}"
    return hashlib.sha256(raw.encode("ascii")).hexdigest()


def _verify_successor_reply(response, old, node, user, challenge, pinned, now):
    """Authenticate durable zero-authority successor evidence on EVERY retry.

    This is only a preparation receipt, never a replacement Xray permit.
    A corrupt or expired local marker must not silently suppress further
    admission processing or be mistaken for successfully installed capacity.
    """
    if (not isinstance(response, dict)
            or set(response) != {"status", "nodeId", "userId", "signedEnvelope"}
            or response["status"] != "prepared_calendar_successor"
            or type(response["nodeId"]) is not int or response["nodeId"] != node
            or type(response["userId"]) is not int or response["userId"] != user
            or not isinstance(response["signedEnvelope"], str)
            or not 0 < len(response["signedEnvelope"]) <= 8192):
        raise ValueError("unexpected successor response")
    raw = response["signedEnvelope"].encode("utf-8")
    envelope = wal_transport.observed.strict_json(raw)
    if (raw != wal_transport.observed.canonical(envelope)
            or not isinstance(envelope, dict)):
        raise ValueError("noncanonical successor signature envelope")
    with tempfile.TemporaryDirectory(prefix="xmesh-successor-") as tmp:
        public = os.path.join(tmp, "pinned.pem")
        wal_transport._write_public(pinned, public)
        caps._signed(envelope, b"XMESH_QUOTA_V2_CALENDAR_SUCCESSOR_V1\x00", pinned, public)
    payload = envelope["payload"]
    expected = {
        "schemaVersion": 1, "kind": "xmesh.quota-v2.calendar-successor-prepared",
        "nodeId": node, "userId": user, "nonce": challenge,
        "activationReceiptSha256": old["activationReceiptSha256"],
        "policySha256": old["policySha256"],
        "predecessorRuntimeId": old["runtimeId"],
        "predecessorId": old["reservationId"],
        "accountEpoch": old["accountEpoch"],
        "authorizedBytes": 0, "canSpend": False,
        "canStart": False, "canResume": False,
        "finalMeterVerified": False, "refundableBytes": 0,
    }
    if (not isinstance(payload, dict)
            or set(payload) != set(expected) | {
                "meterEpoch", "reservationId", "issuedAtMs", "validUntilMs"}):
        raise ValueError("successor changes predecessor scope or authority")
    for key, value in expected.items():
        if type(payload.get(key)) is not type(value) or payload[key] != value:
            raise ValueError("successor changes predecessor scope or authority")
    for key in ("meterEpoch", "reservationId"):
        value = payload[key]
        if (not isinstance(value, str) or lease.UUID.fullmatch(value) is None
                or str(uuid.UUID(value)) != value or value == old[key]):
            raise ValueError("successor lacks a distinct valid meter identity")
    if payload["meterEpoch"] == payload["reservationId"]:
        raise ValueError("successor reuses its meter epoch as a reservation")
    if (type(now) is not int or now <= 0
            or type(payload["issuedAtMs"]) is not int
            or type(payload["validUntilMs"]) is not int
            or not old["validUntilMs"] <= payload["issuedAtMs"] <= now
            or payload["validUntilMs"] <= payload["issuedAtMs"]
            or payload["validUntilMs"] - payload["issuedAtMs"] > 120_000):
        # This is a signed ZERO-SPEND planning receipt, not an install
        # deadline for a positive cap. Its exact immutable bytes must
        # remain replayable after an XSP response is lost for >120 seconds.
        # A future positive permit MUST have a separately fresh deadline.

        raise ValueError("successor preparation expired or has invalid clock")
    return payload


def _prepare_successor(panel, state, node, user, challenge, *, predecessor=None):
    fd, lock = quarantine._locked_private_state(state)
    try:
        names = os.listdir(fd)
        pinned = wal_transport._panel_pin()
        old = latest_signed_cap(fd, names, node, user, pinned)
        if predecessor is not None:
            import successor_positive
            old = successor_positive.verified_chain(fd, names, node, user, pinned)[-1][0]
            if old != predecessor:
                raise ValueError("calendar preparation targets an obsolete predecessor")
        now = time.time_ns() // 1_000_000
        name = _successor_filename(user, old)
        if now < old["validUntilMs"] or challenge != _successor_nonce(old):
            return
        if name in names:
            saved = lease._identity_file(fd, name, 16384)
            _verify_successor_reply(saved, old, node, user, challenge, pinned, now)
            return
        active = quarantine._enrolled_activation(panel, node)
        activation = active["activationReceiptSha256"]
        if old["activationReceiptSha256"] != activation:
            raise ValueError("successor is outside the enrolled Node")
        response = wal_transport.observed.strict_json(quarantine._post_quarantined_desired({
            "nodeId": node, "userId": user, "requestChallenge": challenge,
            "calendarSuccessor": {"predecessorId": old["reservationId"]},
        }, state, quarantine.CAP_DELIVERY_PATH))
        _verify_successor_reply(response, old, node, user, challenge, pinned,
                                time.time_ns() // 1_000_000)
        quarantine._durable_store(fd, response, name)
    finally:
        os.close(lock)
        os.close(fd)


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


def _run_generation(panel, node, user, state, socket_path, failed_users, genesis_wal_ok):
    import calendar_fence
    import charge_worker
    import successor_meter
    import successor_positive
    import vless_ingress

    fd, lock = quarantine._locked_private_state(state)
    try:
        names = os.listdir(fd)
        pinned = wal_transport._panel_pin()
        chain = successor_positive.verified_chain(fd, names, node, user, pinned)
        old, measured = chain[-1]
        intent = lease._identity_file(fd, quarantine.INTENT_FILE, 4096)
        executable = intent["executableSha256"]
        config = calendar_fence._original_signed_scope(fd, old, node, pinned)
        if intent["nodeId"] != node or intent["configSha256"] != config:
            raise ValueError("calendar generation policy pins changed")
        repair = False
        if measured is not None:
            try:
                route = os.readlink(f"ingress-u{user}", dir_fd=fd)
            except FileNotFoundError:
                route = None
            repair = route != vless_ingress.target(*measured[2:])
        position = len(chain) - (2 if repair else 1)
        if repair:
            old = chain[position][0]
        container = ("xmesh-managed-xray" if position == 0 else
                     successor_meter.container_for(user, chain[position - 1][0]["reservationId"]))
        candidate = successor_meter.container_for(user, old["reservationId"])
        now = time.time_ns() // 1_000_000
        ready = calendar_fence._fence_name(user, old["reservationId"]) in names
        proved = successor_meter._name(user, old["reservationId"]) in names
    finally:
        os.close(lock)
        os.close(fd)
    if position == 0 and not genesis_wal_ok:
        return False
    live = wal_transport._measure_quarantined_runtime((executable, config), container)
    if live[3] != old["runtimeId"]:
        raise ValueError("measured predecessor no longer matches the signed chain")
    if repair:
        return successor_positive.install_successor(
            panel, node, user, state, successor_meter.control_socket(candidate), executable, config,
            predecessor=old, old_container=container, candidate_container=candidate)
    if position:
        charge_worker.run(panel, node, state, failed_users, container_name=container)
    if user in failed_users:
        return False
    if now < old["validUntilMs"]:
        if position:
            return False
        # Retain first-generation signed refill and initial route recovery.
        fd, lock = quarantine._locked_private_state(state)
        try:
            job = _candidate(fd, os.listdir(fd), node, user, pinned, now)
        finally:
            os.close(lock)
            os.close(fd)
        if job is None:
            return False
        _, revision, challenge = job
        if revision == -3:
            return _restore_initial_ingress(panel, node, user, state)
        if revision > 0:
            caps.fetch_and_install_renewal(
                panel, node, user, state, socket_path, executable, challenge, revision)
            return True
        return False
    if not ready:
        _prepare_successor(panel, state, node, user, _successor_nonce(old), predecessor=old)
        predecessor_socket = successor_meter.control_socket(container) if position else socket_path
        calendar_fence.fence_successor(
            panel, node, user, state, predecessor_socket, executable,
            predecessor=old, container=container)
        return False
    if not proved:
        successor_meter.start_generation(state, node, user, old, container, executable, config)
        successor_meter.observe_successor_meter(
            node, user, state, successor_meter.control_socket(candidate), executable, config,
            predecessor=old, old_container=container, candidate_container=candidate)
        return False
    return successor_positive.install_successor(
        panel, node, user, state, successor_meter.control_socket(candidate), executable, config,
        predecessor=old, old_container=container, candidate_container=candidate)


def _poll_generations(panel, node, state, socket_path, failed_users, genesis_wal_ok):
    import vless_ingress
    if (os.environ.get("XMESH_QUOTA_V2_INGRESS_STAGING") != "1"
            or not vless_ingress._staging_permitted()):
        raise ValueError("automatic calendar generations require signed staging ingress")
    fd, lock = quarantine._locked_private_state(state)
    try:
        users = sorted(int(match.group(1)) for name in os.listdir(fd)
                       if (match := BASE.fullmatch(name)))
        if len(users) > MAX_USERS:
            raise ValueError("too many users for calendar generation polling")
        selected = _next_scan_batch(fd, users, node) if users else []
    finally:
        os.close(lock)
        os.close(fd)
    installed = 0
    for user in selected:
        try:
            installed += int(_run_generation(panel, node, user, state, socket_path,
                                            failed_users, genesis_wal_ok))
        except (ValueError, OSError, TypeError, KeyError, subprocess.SubprocessError) as exc:
            print(f"Quota V2 calendar transition refused for user {user}: {type(exc).__name__}", flush=True)
    return installed


def run(panel, node, state=STATE, socket_path=SOCKET,
        fresh_socket=None, fresh_executable=None, fresh_config=None):
    if (os.geteuid() != 0 or os.environ.get(STAGING_ENV) != "1"
            or os.environ.get("XMESH_QUOTA_V2_INSTALLED_CAP_DELIVERY") != "1"
            or not isinstance(panel, str) or not panel.startswith("https://")
            or type(node) is not int or node <= 0):
        raise ValueError("automatic renewal is permitted only in explicit root staging")
    # Reconcile fsynced debt before doing any admission work. An expired or
    # malformed Genesis candidate must not stall charging for existing users.
    # The charge worker verifies the remote head before processing streams.
    import charge_worker
    import vless_ingress
    failed_users = set()
    if os.environ.get("XMESH_QUOTA_V2_MANAGED_GENERATIONS_STAGING") == "1":
        genesis_wal_ok = True
        try:
            charge_worker.run(panel, node, state, failed_users)
        except (ValueError, OSError, subprocess.SubprocessError) as exc:
            print(f"Quota V2 Genesis WAL ledger unavailable: {type(exc).__name__}", flush=True)
            # Never rotate a Genesis user when its WAL check failed.
            genesis_wal_ok = False
        # Removing the operator staging marker must stop NEW signed grants
        # without stopping conservative reconciliation of already spent WAL.
        if not vless_ingress._staging_permitted():
            print("Quota V2 new admissions paused; staging marker unavailable", flush=True)
            return 0
        installed = activate_initial_cap(panel, node, state, socket_path)
        return installed + _poll_generations(
            panel, node, state, socket_path, failed_users, genesis_wal_ok)
    charge_worker.run(panel, node, state, failed_users)
    # In opt-in staging, keep the successor journal separate and submit
    # only its own signed birth/charge intents against its runtime checkpoint.
    if (os.environ.get("XMESH_QUOTA_V2_AUTO_SUCCESSOR_POSITIVE") == "1"
            and os.environ.get("XMESH_QUOTA_V2_FRESH_METER_STAGING") == "1"):
        try:
            charge_worker.run(
                panel, node, state, failed_users,
                container_name="xmesh-successor-quarantine")
        except (ValueError, OSError, subprocess.SubprocessError) as error:
            print(f"Quota V2 successor WAL ledger not independently anchored: "
                  f"{type(error).__name__}", flush=True)
    if not vless_ingress._staging_permitted():
        print("Quota V2 new admissions paused; staging marker unavailable", flush=True)
        return 0
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
        # A discovered successor socket/pin belongs only to this iteration.
        # Never retain another user's auto-discovered runtime across jobs.
        user_fresh_socket = fresh_socket
        user_fresh_executable = fresh_executable
        user_fresh_config = fresh_config
        try:
            if revision == -3:
                installed += int(_restore_initial_ingress(panel, node, user, state))
                continue
            if (revision in (-1, -2) and user_fresh_socket is None
                    and os.environ.get("XMESH_QUOTA_V2_INGRESS_STAGING") == "1"
                    and os.environ.get("XMESH_QUOTA_V2_FRESH_METER_STAGING") == "1"):
                from successor_meter import SUCCESSOR
                mount, ledger = wal_transport._bound_journal(SUCCESSOR)
                if not any(m.get("Destination") == wal_transport.journal.RUNTIME_DEST
                           for m in mount["Mounts"]):
                    raise ValueError("private successor control socket requires a measured runtime mount")
                user_fresh_socket = os.path.join(os.path.dirname(ledger), "drain.sock")
                user_fresh_executable = executable
                user_fresh_config = intent["configSha256"]
            if revision == -2:
                if os.environ.get("XMESH_QUOTA_V2_FRESH_METER_STAGING") != "1" or not (
                        user_fresh_socket and user_fresh_executable and user_fresh_config):
                    raise ValueError("positive successor requires a separately pinned fresh Xray")
                import successor_positive
                successor_positive.install_successor(
                    panel, node, user, state, user_fresh_socket,
                    user_fresh_executable, user_fresh_config)
                continue
            if revision == -1:
                if not (user_fresh_socket and user_fresh_executable and user_fresh_config):
                    raise ValueError("fresh Xray staging requires independent Unix socket and two SHA-256 pins")
                import successor_meter
                successor_meter.observe_successor_meter(
                    node, user, state, user_fresh_socket, user_fresh_executable, user_fresh_config)
                continue
            if revision == 0:
                _prepare_successor(panel, state, node, user, challenge)
                # Closing the old process's WAL is a separate, irreversible
                # stage. This NEVER installs the candidate successor as a
                # spending cap. A lost IPC response retries its exact durable
                # fence, not a guessed new reservation or counter reset.
                import calendar_fence
                calendar_fence.fence_successor(
                    panel, node, user, state, socket_path, executable)
                continue
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
    parser.add_argument("--successor-socket", default=None)
    parser.add_argument("--successor-executable-sha256", default=None)
    parser.add_argument("--successor-config-sha256", default=None)
    args = parser.parse_args()
    try:
        count = run(args.panel, args.node_id, args.state, args.socket,
                    args.successor_socket, args.successor_executable_sha256,
                    args.successor_config_sha256)
        print(f"Quota V2 staged automatic renewals installed: {count}")
    except (ValueError, OSError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"Quota V2 automatic renewal refused: {error}\n")
