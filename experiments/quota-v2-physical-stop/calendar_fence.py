#!/usr/bin/env python3
"""Stage-only irreversible fence of the PREDECESSOR epoch in an installed Xray.

A Nexus-signed zero-byte calendar-successor PREPARATION is not a grant.
This worker uses it only to deny the old user's sessions, preserve the
predecessor WAL and obtain a nonfinal Xray checkpoint through the original
same-PID Unix socket. It never creates, funds, installs or resumes a cap.

Every invocation uses the Agent's already enrolled, pinned signer and exact
original signed inbound roster. A stale/foreign process or lost response
fails closed; a repeat uses the same stable fence scope and Xray durable
denial. No response here is proof of terminal metering or a quota refund.
"""
import hashlib
import os
import time
import uuid

import cap_install
import first_cap_handoff as caps
import genesis_reservation as lease
import journal_integrity
import quarantine_policy as quarantine
import renewal_worker
import wal_transport

FENCE_NAMESPACE = uuid.UUID("becd936f-23a2-5a5a-92eb-c277f259f70a")


def _fence_name(user, predecessor):
    return f"calendar-fence-u{user}-{uuid.UUID(predecessor)}.json"


def _fence_scope(old, predecessor):
    aliases = old["aliasScopes"]
    if not isinstance(aliases, list) or not aliases:
        raise ValueError("calendar fence has no signed inbound alias")
    primary = aliases[0]["email"]
    if not isinstance(primary, str) or not primary.startswith(
            f"xmesh-u{old['userId']}--"):
        raise ValueError("foreign first alias in signed calendar fence")
    request_id = str(uuid.uuid5(FENCE_NAMESPACE, predecessor))
    # This field is a deterministic durable *stop scope* in the disposable
    # Xray checkpoint schema, not proof of an administrative revocation.
    return {
        "email": primary, "nodeId": old["nodeId"], "userId": old["userId"],
        "epoch": old["accountEpoch"], "meterEpoch": old["meterEpoch"],
        "reservationId": predecessor,
        "revision": old["reservationRevision"], "revocationId": request_id,
    }


def _original_signed_scope(fd, old, node, pinned):
    stored = lease._identity_file(
        fd, "genesis-quarantine-envelope.json", quarantine.MAX_REPLY + 4096)
    if (not isinstance(stored, dict) or set(stored) != {"prepared", "reply"}
            or not isinstance(stored["reply"], dict)):
        raise ValueError("missing original signed quarantine policy")
    original = stored["reply"]
    policy = original.get("policy")
    config = original.get("config")
    if (not isinstance(policy, dict) or not isinstance(config, dict)
            or original.get("nodeId") != node
            or original.get("policyPublicKey") != pinned
            or original.get("policySha256") != old["policySha256"]
            or original.get("revision") != policy.get("configSha256")
            or hashlib.sha256(wal_transport.observed.canonical(policy)).hexdigest()
                != old["policySha256"]
            or hashlib.sha256(wal_transport.observed.canonical(config)).hexdigest()
                != original["revision"]):
        raise ValueError("calendar fence original policy/profile hashes changed")
    # Validate original signature without pretending that the 120-second
    # GENESIS policy is still a fresh right to install a positive permit.
    quarantine._guard().check_signature(policy, original["policySignature"], pinned)
    aliases = caps._authorized_aliases(old, policy, config)
    if aliases != old["aliasScopes"]:
        raise ValueError("calendar fence aliases changed from signed policy")
    return original["revision"]


def _independent_journal_digest(old_checkpoint, measured):
    """Re-read actual fsynced Xray WAL and birth registry from Docker bind.

    The observed HTTP response is only an untrusted, nonfinal account
    snapshot; a same-PID peer is not an accounting proof by itself.
    The existing independent root-owned Docker/mount verifier checks
    EVERY WAL birth against raw file contents, a matching immutable
    fence/checkpoint record, and the exact old process identity.
    """
    if (not isinstance(measured, tuple) or len(measured) != 4
            or type(measured[2]) is not int or measured[2] <= 0):
        raise ValueError("untrusted measured Xray identity for calendar WAL audit")
    docker, journal_dir = wal_transport._bound_journal()
    state = docker.get("State") if isinstance(docker, dict) else None
    if (not isinstance(state, dict)
            or docker.get("Id") != measured[0]
            or state.get("StartedAt") != measured[1]
            or state.get("Running") is not True
            or state.get("Pid") != measured[2]):
        raise ValueError("calendar WAL journal belongs to a different Xray process")
    try:
        digest = journal_integrity.verify_poststop_journal(
            old_checkpoint, journal_dir, docker)
    except (KeyError, TypeError, IndexError, UnicodeError) as exc:
        # A malformed checkpoint or journal from one stopped user must
        # never escape the bounded per-user fail-closed scheduler and
        # prevent other signed users from reaching their own safe window.
        raise ValueError("malformed old-Xray calendar WAL evidence") from exc
    if (not isinstance(digest, str)
            or caps.HEX64.fullmatch(digest) is None):
        raise ValueError("invalid independently audited calendar WAL digest")
    return digest


def _offhost_birth_registry_proof(panel, node, checkpoint):
    """Require the existing Nexus-signed off-host WAL registry readback.

    `charge-sync` verifies the Ed25519 Node witness, immutable full-byte
    Nexus storage and independently queried latest signed remote head.
    A same-node digest alone cannot detect previously deleted WAL births.
    This is a NONAUTHORITATIVE forensic prefix, not a signed user cap.
    """
    result = wal_transport.run("charge-sync", panel, node)
    if result is None:
        # A first-ever completely idle Xray has no birth registry to send.
        # A missing remote registry is NEVER sufficient for a user whose
        # actual old checkpoint contains any byte-bearing WAL.
        if (type(checkpoint.get("uplinkBytes")) is not int
                or type(checkpoint.get("downlinkBytes")) is not int
                or checkpoint["uplinkBytes"] != 0
                or checkpoint["downlinkBytes"] != 0):
            raise ValueError("old Xray has bytes but no committed off-host WAL index")
        return {
            "offhostBirthIndexVerified": False,
            "firstRemoteSnapshotWasOnlyBootstrap": False,
            "preBootstrapHistoryCompletenessVerified": False,
            "allXrayWritersCompletedVerified": False,
            "finalMeterVerified": False,
            "refundableBytes": 0,
            "canResume": False,
        }
    if (not isinstance(result, dict)
            or set(result) != {
                "nexusOffhostSignatureVerified",
                "offhostFullBirthIndexHeadMatched",
                "nodeLocalIndexExtendsNexusHead",
                "firstRemoteSnapshotWasOnlyBootstrap",
                "preBootstrapHistoryCompletenessVerified",
                "allXrayWritersCompletedVerified",
                "canResume", "carryforwardApplied",
                "finalMeterVerified", "refundableBytes"}
            or result["nexusOffhostSignatureVerified"] is not True
            or result["offhostFullBirthIndexHeadMatched"] is not True
            or result["nodeLocalIndexExtendsNexusHead"] is not True
            or type(result["firstRemoteSnapshotWasOnlyBootstrap"]) is not bool
            or result["preBootstrapHistoryCompletenessVerified"] is not False
            or result["allXrayWritersCompletedVerified"] is not False
            or result["canResume"] is not False
            or result["carryforwardApplied"] is not False
            or result["finalMeterVerified"] is not False
            or type(result["refundableBytes"]) is not int
            or result["refundableBytes"] != 0):
        raise ValueError("Nexus did not independently confirm a nonspending WAL birth head")
    return {
        "offhostBirthIndexVerified": True,
        "firstRemoteSnapshotWasOnlyBootstrap": result[
            "firstRemoteSnapshotWasOnlyBootstrap"],
        "preBootstrapHistoryCompletenessVerified": False,
        "allXrayWritersCompletedVerified": False,
        "finalMeterVerified": False,
        "refundableBytes": 0,
        "canResume": False,
    }


def _checked_saved(record, old, successor, runtime):
    if (not isinstance(record, dict)
            or set(record) != {
                "nodeId", "userId", "predecessorId", "runtimeId",
                "successorSha256", "scope", "observedFence",
                "independentJournalSha256", "offhostBirthRegistry"}
            or record["nodeId"] != old["nodeId"]
            or record["userId"] != old["userId"]
            or record["predecessorId"] != old["reservationId"]
            or record["runtimeId"] != runtime
            or record["successorSha256"] != successor
            or record["scope"] != _fence_scope(old, old["reservationId"])
            or not isinstance(record["independentJournalSha256"], str)
            or caps.HEX64.fullmatch(record["independentJournalSha256"]) is None):
        raise ValueError("calendar fence record does not match original signed scope")
    remote = record["offhostBirthRegistry"]
    expected_remote = {
        "offhostBirthIndexVerified", "firstRemoteSnapshotWasOnlyBootstrap",
        "preBootstrapHistoryCompletenessVerified",
        "allXrayWritersCompletedVerified", "finalMeterVerified",
        "refundableBytes", "canResume",
    }
    if (not isinstance(remote, dict) or set(remote) != expected_remote
            or type(remote["offhostBirthIndexVerified"]) is not bool
            or type(remote["firstRemoteSnapshotWasOnlyBootstrap"]) is not bool
            or remote["preBootstrapHistoryCompletenessVerified"] is not False
            or remote["allXrayWritersCompletedVerified"] is not False
            or remote["finalMeterVerified"] is not False
            or type(remote["refundableBytes"]) is not int
            or remote["refundableBytes"] != 0
            or remote["canResume"] is not False
            or (remote["offhostBirthIndexVerified"] is False
                and remote["firstRemoteSnapshotWasOnlyBootstrap"] is True)):
        raise ValueError("calendar fence has no valid nonauthorizing off-host WAL proof")
    observed = record["observedFence"]
    scope = record["scope"]
    checkpoint = observed.get("observedCheckpoint") if isinstance(observed, dict) else None
    if (not isinstance(observed, dict)
            or observed.get("email") != scope["email"]
            or observed.get("fenced") is not True
            or observed.get("drained") is not True
            or type(observed.get("active")) is not int or observed["active"] != 0
            or observed.get("finalMeterVerified") is not False
            or observed.get("refundable") is not False
            or not isinstance(checkpoint, dict)
            or checkpoint.get("runtimeId") != runtime
            or checkpoint.get("schemaVersion") != 3
            or checkpoint.get("finalMeterVerified") is not False
            or type(checkpoint.get("refundableBytes")) is not int
            or checkpoint["refundableBytes"] != 0
            or checkpoint.get("drained") is not True
            or any(checkpoint.get(key) != value for key, value in scope.items())):
        raise ValueError("calendar fence is missing Xray's nonfinal durable checkpoint")
    if (remote["offhostBirthIndexVerified"] is False
            and (type(checkpoint.get("uplinkBytes")) is not int
                 or type(checkpoint.get("downlinkBytes")) is not int
                 or checkpoint["uplinkBytes"] != 0
                 or checkpoint["downlinkBytes"] != 0)):
        raise ValueError("calendar fence has spent bytes without independently witnessed remote WAL")
    # The source-pinned Xray already validates the complete signed alias
    # roster. Revalidate the IPC/stored response independently so a partial
    # observation is never mistaken for the old metered account. This
    # observational total is NONFINAL and cannot authorize a quota refund.
    aliases = old.get("aliasScopes")
    rows = checkpoint.get("inboundMeters")
    if (not isinstance(aliases, list) or not 1 <= len(aliases) <= 16
            or not isinstance(rows, list) or len(rows) != len(aliases)):
        raise ValueError("calendar fence lost a signed MAIN/CDN meter alias")
    total_up = total_down = 0
    previous = ""
    for signed, row in zip(aliases, rows):
        if (not isinstance(signed, dict) or set(signed) != {"email", "class"}
                or signed["class"] not in ("main", "cdn")
                or not isinstance(row, dict)
                or set(row) != {"email", "uplinkBytes", "downlinkBytes"}
                or not isinstance(signed["email"], str)
                or not isinstance(row.get("email"), str)
                or row["email"] != signed["email"]
                or row["email"] <= previous
                or not row["email"].startswith(f"xmesh-u{old['userId']}--")
                or any(type(row.get(key)) is not int or
                       not 0 <= row[key] <= (1 << 63) - 1
                       for key in ("uplinkBytes", "downlinkBytes"))):
            raise ValueError("calendar fence inbound meter scope changed")
        total_up += row["uplinkBytes"]
        total_down += row["downlinkBytes"]
        previous = row["email"]
    if (total_up + total_down > (1 << 63) - 1
            or type(checkpoint.get("uplinkBytes")) is not int
            or type(checkpoint.get("downlinkBytes")) is not int
            or checkpoint["uplinkBytes"] != total_up
            or checkpoint["downlinkBytes"] != total_down):
        raise ValueError("calendar fence meter totals differ from signed roster")
    return record


def fence_successor(panel, node, user, state, socket_path, executable_pin):
    """Fence the old user's aliases; do NOT allocate or install a new cap."""
    if (os.geteuid() != 0 or not isinstance(panel, str)
            or not panel.startswith("https://")
            or type(node) is not int or node <= 0
            or type(user) is not int or user <= 0
            or not isinstance(executable_pin, str)
            or caps.HEX64.fullmatch(executable_pin) is None):
        raise ValueError("calendar fencing requires root and original staged executable")
    fd, lock = quarantine._locked_private_state(state)
    try:
        names = os.listdir(fd)
        pinned = wal_transport._panel_pin()
        old = renewal_worker.latest_signed_cap(fd, names, node, user, pinned)
        now = time.time_ns() // 1_000_000
        if now < old["validUntilMs"]:
            raise ValueError("predecessor cap is not expired")
        suffix = renewal_worker._successor_filename(user, old)
        response = lease._identity_file(fd, suffix, 16384)
        renewal_worker._verify_successor_reply(
            response, old, node, user, renewal_worker._successor_nonce(old),
            pinned, now)
        exact = wal_transport.observed.canonical(response)
        digest = hashlib.sha256(exact).hexdigest()
        name = _fence_name(user, old["reservationId"])
        if name in names:
            saved = lease._identity_file(fd, name, 32768)
            # Only a historical reference. This is NOT proof of completed
            # remote settlement or permission to start another runtime.
            _checked_saved(saved, old, digest, old["runtimeId"])
            return False
        config_pin = _original_signed_scope(fd, old, node, pinned)
        enrolled = quarantine._enrolled_activation(panel, node)
        if enrolled.get("activationReceiptSha256") != old["activationReceiptSha256"]:
            raise ValueError("calendar fence enrolled Node activation changed")
        pins = (executable_pin, config_pin)
        observed_before = wal_transport._measure_quarantined_runtime(pins)
        if observed_before[3] != old["runtimeId"]:
            raise ValueError("calendar fence must target the old measured Xray PID")
        scope = _fence_scope(old, old["reservationId"])
        if (observed_before != wal_transport._measure_quarantined_runtime(pins)
                or enrolled != quarantine._enrolled_activation(panel, node)):
            raise ValueError("calendar fence process or activation changed")
        snapshot = cap_install.fence_calendar_in_xray(
            socket_path, observed_before[2], observed_before[3], scope)
        if observed_before != wal_transport._measure_quarantined_runtime(pins):
            raise ValueError("calendar fence runtime changed after IPC")
        record = {
            "nodeId": node, "userId": user,
            "predecessorId": old["reservationId"],
            "runtimeId": old["runtimeId"],
            "successorSha256": digest, "scope": scope,
            "observedFence": snapshot,
        }
        checkpoint = (snapshot.get("observedCheckpoint")
                      if isinstance(snapshot, dict) else None)
        if not isinstance(checkpoint, dict):
            raise ValueError("old Xray did not return an auditable calendar WAL checkpoint")
        journal_digest = _independent_journal_digest(
            checkpoint, observed_before)
        if observed_before != wal_transport._measure_quarantined_runtime(pins):
            raise ValueError("Xray process changed during independent WAL audit")
        remote = _offhost_birth_registry_proof(panel, node, checkpoint)
        # Source Xray may have advanced during the remote checkpoint. Only
        # the unchanged ORIGINAL old user's fsynced WAL can become a
        # committed nonfinal local calendar marker.
        if _independent_journal_digest(checkpoint, observed_before) != journal_digest:
            raise ValueError("old Xray WAL changed during remote registry publication")
        if (observed_before != wal_transport._measure_quarantined_runtime(pins)
                or enrolled != quarantine._enrolled_activation(panel, node)):
            raise ValueError("Xray process or Node activation changed after remote WAL proof")
        record["independentJournalSha256"] = journal_digest
        record["offhostBirthRegistry"] = remote
        _checked_saved(record, old, digest, old["runtimeId"])
        quarantine._durable_store(fd, record, name)
        return True
    finally:
        os.close(lock)
        os.close(fd)
