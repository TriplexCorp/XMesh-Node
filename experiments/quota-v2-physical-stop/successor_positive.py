#!/usr/bin/env python3
"""Staged FULL successor positive XSP/2 -> measured NEW Xray Unix handoff.

The signed old-period WAL debt is never dropped, recycled or refunded. No
old PID, alias or reservation can be relabeled into the new meter. This
path requires explicit opt-in, a fully closed old epoch, Nexus-signed
zero-spend preparation and a SEPARATE source-pinned fresh Xray zero proof.
"""
import hashlib
import os
import tempfile
import time
import uuid

import cap_install
import calendar_fence
import first_cap_handoff as caps
import genesis_reservation as lease
import quarantine_policy as quarantine
import renewal_worker
import successor_meter
import wal_transport
import vless_ingress

GENESIS_DOMAIN = b"XMESH_XRAY_GENESIS_PREPARED_V1\x00"


def _filename(user, old_reservation):
    return f"calendar-positive-u{user}-{old_reservation}.json"


def _challenge(predecessor, runtime):
    message = (b"XMESH_QUOTA_V2_CALENDAR_POSITIVE_REQUEST_V1\x00" +
               predecessor.encode("ascii") + b"\x00" + runtime.encode("ascii"))
    return hashlib.sha256(message).hexdigest()


def _verify_positive_reply(reply, old, prepared, marker, node, user, pinned, now):
    """Two separately verified Nexus signatures, exact immutable payloads."""
    if (not isinstance(reply, dict) or set(reply) != {
            "status", "nodeId", "userId", "signedEnvelope",
            "freshGenesisEnvelope"}
            or reply["status"] != "committed_calendar_successor"
            or type(reply["nodeId"]) is not int or reply["nodeId"] != node
            or type(reply["userId"]) is not int or reply["userId"] != user
            or not isinstance(reply["signedEnvelope"], str)
            or not isinstance(reply["freshGenesisEnvelope"], str)
            or not 100 < len(reply["signedEnvelope"]) <= 8192
            or not 100 < len(reply["freshGenesisEnvelope"]) <= 4096):
        raise ValueError("unexpected positive successor XSP/2 reply")
    grant_raw = reply["signedEnvelope"].encode("utf-8")
    genesis_raw = reply["freshGenesisEnvelope"].encode("utf-8")
    grant = wal_transport.observed.strict_json(grant_raw)
    genesis = wal_transport.observed.strict_json(genesis_raw)
    if (grant_raw != wal_transport.observed.canonical(grant) + b"\n"
            or genesis_raw != wal_transport.observed.canonical(genesis)):
        raise ValueError("positive successor signatures are not exact canonical bytes")
    with tempfile.TemporaryDirectory(prefix="xmesh-successor-positive-") as tmp:
        pub = os.path.join(tmp, "pinned-nexus.pem")
        wal_transport._write_public(pinned, pub)
        caps._signed(grant, caps.DOMAIN, pinned, pub)
        caps._signed(genesis, GENESIS_DOMAIN, pinned, pub)
    p = grant.get("payload")
    g = genesis.get("payload")
    challenge = _challenge(old["reservationId"], marker["freshRuntimeId"])
    if (not isinstance(p, dict) or set(p) != caps.CAP_KEYS
            or not isinstance(g, dict) or set(g) != {
                "schemaVersion", "kind", "nodeId", "activationReceiptSha256",
                "candidateRuntimeId", "challenge", "preparedAtMs",
                "validUntilMs", "authorizedBytes", "canStart", "canResume"}):
        raise ValueError("unexpected signed successor or fresh-genesis contract")
    expected = {
        "schemaVersion": 1, "kind": "xmesh.quota-v2.xray-cap-admission",
        "nodeId": node, "userId": user,
        "activationReceiptSha256": old["activationReceiptSha256"],
        "runtimeId": marker["freshRuntimeId"],
        "policySha256": old["policySha256"],
        "accountEpoch": old["accountEpoch"],
        "meterEpoch": prepared["meterEpoch"],
        "reservationId": prepared["reservationId"],
        "reservationRevision": 1, "nonce": challenge,
        "inventoryTailDigest": caps.ZERO_HEAD,
        "witnessedWalBytes": 0, "witnessedCdnBytes": 0,
        "aliasScopes": old["aliasScopes"],
        "canSpend": True, "canStart": False, "canResume": False,
        "finalMeterVerified": False, "refundableBytes": 0,
    }
    if any(type(p.get(k)) is not type(v) or p[k] != v
           for k, v in expected.items()):
        raise ValueError("positive successor changes original Node, policy or fresh meter")
    if (not caps._int(p.get("sharedCeilingBytes"), 1, caps.MAX_CAP)
            or not caps._int(p.get("nodeCeilingBytes"),
                             p["sharedCeilingBytes"], caps.MAX_CAP)
            or not caps._int(p.get("cdnCeilingBytes"), 0,
                             p["sharedCeilingBytes"])
            or not caps._int(p.get("issuedAtMs"), 1, now)
            or not caps._int(p.get("installBeforeMs"), now + 1)
            or p["installBeforeMs"] > p["issuedAtMs"] + 120_000
            or not caps._int(p.get("validUntilMs"),
                             p["installBeforeMs"] + 1,
                             p["issuedAtMs"] + 86_400_000)):
        raise ValueError("successor cap has expired or overfunded positive window")
    expected_genesis = {
        "schemaVersion": 1, "kind": "xmesh.xray.genesis-prepared",
        "nodeId": node, "activationReceiptSha256": old["activationReceiptSha256"],
        "candidateRuntimeId": marker["freshRuntimeId"], "challenge": challenge,
        "preparedAtMs": p["issuedAtMs"],
        "validUntilMs": p["issuedAtMs"] + 120_000,
        "authorizedBytes": 0, "canStart": False, "canResume": False,
    }
    if (any(type(g.get(k)) is not type(v) or g[k] != v
            for k, v in expected_genesis.items())
            or p["installBeforeMs"] > g["validUntilMs"]):
        raise ValueError("fresh Xray genesis is not paired with positive successor")
    if not any(alias["class"] == "cdn" for alias in p["aliasScopes"]):
        if p["cdnCeilingBytes"] != 0:
            raise ValueError("unattributed CDN allowance")
    return grant_raw, genesis_raw, {
        "userId": user, "policySha256": old["policySha256"],
        "accountEpoch": old["accountEpoch"],
        "meterEpoch": prepared["meterEpoch"],
        "reservationId": prepared["reservationId"],
        "revision": 1, "nonce": challenge, "aliases": old["aliasScopes"],
    }


def _verified_saved_receipt(saved, old, prepared, fresh, node, user, pinned):
    """Validate an immutable historical installation even after cap expiry.

    A past signed installation is NOT a new permission to spend or to
    re-admit traffic in a later process. Current admission still needs
    live Xray and current cap checks.
    """
    if (not isinstance(saved, dict) or set(saved) != {
            "nodeId", "userId", "predecessorId", "freshRuntimeId",
            "grantSha256", "xrayReceipt", "response"}
            or saved.get("nodeId") != node or saved.get("userId") != user
            or saved.get("predecessorId") != old["reservationId"]
            or saved.get("freshRuntimeId") != fresh["freshRuntimeId"]):
        raise ValueError("saved successor installation is outside signed epoch")
    response = saved["response"]
    if not isinstance(response, dict):
        raise ValueError("saved successor installation response is corrupt")
    raw = response.get("signedEnvelope")
    if not isinstance(raw, str):
        raise ValueError("missing saved positive successor grant")
    envelope = wal_transport.observed.strict_json(raw.encode("utf-8"))
    payload = envelope.get("payload") if isinstance(envelope, dict) else None
    if (not isinstance(payload, dict)
            or not caps._int(payload.get("issuedAtMs"), 1)):
        raise ValueError("invalid historical signed cap clock")
    grant, genesis, scope = _verify_positive_reply(
        response, old, prepared, fresh, node, user, pinned,
        payload["issuedAtMs"] + 1)
    digest = hashlib.sha256(grant).hexdigest()
    if (saved["grantSha256"] != digest
            or saved["xrayReceipt"] != {
                "runtimeId": fresh["freshRuntimeId"],
                "grantSha256": digest}):
        raise ValueError("unmatched original Xray cap-installation receipt")
    return saved


def _read_evidence(fd, node, user, pinned):
    names = os.listdir(fd)
    old = renewal_worker.latest_signed_cap(fd, names, node, user, pinned)
    now = time.time_ns() // 1_000_000
    if now < old["validUntilMs"]:
        raise ValueError("old Xray quota period has not expired")
    response = lease._identity_file(
        fd, renewal_worker._successor_filename(user, old), 16384)
    prepared = renewal_worker._verify_successor_reply(
        response, old, node, user, renewal_worker._successor_nonce(old),
        pinned, now)
    digest = hashlib.sha256(wal_transport.observed.canonical(response)).hexdigest()
    closed = lease._identity_file(
        fd, calendar_fence._fence_name(user, old["reservationId"]), 32768)
    calendar_fence._checked_saved(closed, old, digest, old["runtimeId"])
    if (closed["oldWalChargeConfirmation"]["allOldStreamTailsNexusAcknowledged"]
            is not True):
        raise ValueError("old WAL charge tails are not all committed in Nexus")
    fresh = lease._identity_file(
        fd, successor_meter._name(user, old["reservationId"]), 16384)
    measured = (
        fresh.get("freshContainerId"), fresh.get("freshStartedAt"),
        fresh.get("freshHostPid"), fresh.get("freshRuntimeId"))
    successor_meter._checked_marker(fresh, old, digest, measured, prepared)
    if not fresh["zeroInitialRawCounters"] or not fresh["isolatedNewWalRoot"]:
        raise ValueError("new Xray lacks a pristine zero meter")
    return old, prepared, closed, fresh, digest, measured


def install_successor(panel, node, user, state, socket_path, executable_pin, config_pin):
    """Send one deterministic positive request, install ONLY in new Xray."""
    if (os.geteuid() != 0 or not isinstance(panel, str)
            or not panel.startswith("https://") or type(node) is not int
            or node <= 0 or type(user) is not int or user <= 0
            or not all(isinstance(v, str) and caps.HEX64.fullmatch(v)
                       for v in (executable_pin, config_pin))):
        raise ValueError("successor admission requires root and pinned isolated Xray")

    # First root-locked phase: identify the signed predecessor and EXACT
    # fresh process/zero-counter proof. No network I/O while holding flock.
    fd, lock = quarantine._locked_private_state(state)
    try:
        pinned = wal_transport._panel_pin()
        old, prepared, closed, fresh, digest, measured = _read_evidence(
            fd, node, user, pinned)
        if fresh["freshExecutableSha256"] != executable_pin or \
                fresh["freshConfigSha256"] != config_pin:
            raise ValueError("new executable/config pins differ from immutable marker")
        name = _filename(user, old["reservationId"])
        if name in os.listdir(fd):
            saved = lease._identity_file(fd, name, 32768)
            _verified_saved_receipt(saved, old, prepared, fresh, node, user, pinned)
            if os.environ.get("XMESH_QUOTA_V2_INGRESS_STAGING") == "1":
                before = wal_transport._measure_quarantined_runtime((executable_pin, config_pin))
                after = wal_transport._measure_quarantined_runtime(
                    (executable_pin, config_pin), container_name=successor_meter.SUCCESSOR)
                if before[3] != old["runtimeId"] or after != measured:
                    raise ValueError("saved ingress route targets a replaced Xray")
                grant = wal_transport.observed.strict_json(saved["response"]["signedEnvelope"].encode())
                vless_ingress.publish(fd, grant["payload"], after, vless_ingress.target(before[2], before[3]))
            return False
        pending_name = f"calendar-delivery-u{user}-{old['reservationId']}.json"
        response = (lease._identity_file(fd, pending_name, 32768)
                    if pending_name in os.listdir(fd) else None)
        challenge = _challenge(old["reservationId"], measured[3])
        activation = quarantine._enrolled_activation(panel, node)
        if old["activationReceiptSha256"] != activation["activationReceiptSha256"]:
            raise ValueError("enrolled Node changed since old WAL was signed")
        original_config_sha = calendar_fence._original_signed_scope(
            fd, old, node, pinned)
        # The new Xray may use the same policy roster, but its own mounted
        # config hash must be independently pinned for this exact PID.
        if original_config_sha != config_pin:
            raise ValueError("successor Xray does not use signed original config")
        original = wal_transport._measure_quarantined_runtime()
        candidate = wal_transport._measure_quarantined_runtime(
            (executable_pin, config_pin), container_name=successor_meter.SUCCESSOR)
        if candidate != measured or original[3] != old["runtimeId"]:
            raise ValueError("positive request no longer targets the signed clean process")
        _, old_root = wal_transport._bound_journal()
        _, new_root = wal_transport._bound_journal(successor_meter.SUCCESSOR)
        successor_meter._clean_mount(old_root, new_root, candidate[3])
    finally:
        os.close(lock)
        os.close(fd)

    body = {
        "nodeId": node, "userId": user, "requestChallenge": challenge,
        "calendarSuccessorPositive": {
            "predecessorId": old["reservationId"],
            "freshRuntimeId": fresh["freshRuntimeId"],
            "freshContainerId": fresh["freshContainerId"],
            "freshStartedAt": fresh["freshStartedAt"],
            "freshHostPid": fresh["freshHostPid"],
            "freshExecutableSha256": fresh["freshExecutableSha256"],
            "freshConfigSha256": fresh["freshConfigSha256"],
            "freshWalInventorySha256": fresh["freshWalInventorySha256"],
            "zeroInitialRawCounters": True, "isolatedNewWalRoot": True,
            "oldWalChargeHeadsSha256":
                closed["oldWalChargeConfirmation"]["chargeHeadsSha256"],
        },
    }
    # The transport's authenticated XSP/2 request can take time. The
    # previous WAL remains forever on its original reservation. A lost
    # response retries this SAME challenge and exact outbox.
    if response is None:
        response = wal_transport.observed.strict_json(
            quarantine._post_quarantined_desired(
                body, state, quarantine.CAP_DELIVERY_PATH))
    grant, genesis, scope = _verify_positive_reply(
        response, old, prepared, fresh, node, user, pinned,
        time.time_ns() // 1_000_000)

    # Second root-locked phase: repeat EVERY critical identity/policy
    # check, then use the measured new Xray peer and fsync its receipt.
    fd, lock = quarantine._locked_private_state(state)
    try:
        again = _read_evidence(fd, node, user, pinned)
        if again != (old, prepared, closed, fresh, digest, measured):
            raise ValueError("old WAL or successor changed during positive XSP request")
        active = quarantine._enrolled_activation(panel, node)
        if active != activation or wal_transport._panel_pin() != pinned:
            raise ValueError("Node identity changed while positive cap was committed")
        candidate = wal_transport._measure_quarantined_runtime(
            (executable_pin, config_pin), container_name=successor_meter.SUCCESSOR)
        if candidate != measured:
            raise ValueError("new Xray PID changed during signed-positive request")
        _, old_root = wal_transport._bound_journal()
        _, new_root = wal_transport._bound_journal(successor_meter.SUCCESSOR)
        successor_meter._clean_mount(old_root, new_root, candidate[3])
        # Persist the exact verified pair before IPC. A crash here can retry
        # on this measured process without asking Nexus for another reserve.
        quarantine._durable_store(fd, response, pending_name)
        if name in os.listdir(fd):
            saved = lease._identity_file(fd, name, 32768)
            _verified_saved_receipt(saved, old, prepared, fresh, node, user, pinned)
            if saved["response"] != response:
                raise ValueError("concurrent successor delivery differs from committed grant")
            if os.environ.get("XMESH_QUOTA_V2_INGRESS_STAGING") == "1":
                original_now = wal_transport._measure_quarantined_runtime()
                if original_now[3] != old["runtimeId"]:
                    raise ValueError("predecessor changed before replaying ingress route")
                verified_grant = wal_transport.observed.strict_json(
                    saved["response"]["signedEnvelope"].encode())
                vless_ingress.publish(fd, verified_grant["payload"], candidate,
                                      vless_ingress.target(original_now[2], original_now[3]))
            return False
        # A crash immediately after IPC can leave byte WAL before the
        # installation receipt exists. Attribute it to this exact signed
        # reservation without depending on which epoch the scheduler sees.
        quarantine._durable_store(
            fd, {k: response[k] for k in ("status", "nodeId", "userId", "signedEnvelope")},
            caps.wal_cap_filename(user, candidate[3]))
        receipt = cap_install.install_in_xray(
            socket_path, candidate[2], candidate[3], genesis, grant, scope)
        if wal_transport._measure_quarantined_runtime(
                (executable_pin, config_pin),
                container_name=successor_meter.SUCCESSOR) != measured:
            raise ValueError("new Xray changed during positive cap installation")
        record = {
            "nodeId": node, "userId": user,
            "predecessorId": old["reservationId"],
            "freshRuntimeId": measured[3],
            "grantSha256": hashlib.sha256(grant).hexdigest(),
            "xrayReceipt": receipt, "response": response,
        }
        quarantine._durable_store(fd, record, _filename(user,old["reservationId"]))
        if os.environ.get("XMESH_QUOTA_V2_INGRESS_STAGING") == "1":
            original_now = wal_transport._measure_quarantined_runtime()
            if original_now[3] != old["runtimeId"]:
                raise ValueError("predecessor changed before publishing ingress route")
            vless_ingress.publish(fd, wal_transport.observed.strict_json(grant)["payload"],
                                  candidate, vless_ingress.target(original_now[2], original_now[3]))
        return True
    finally:
        os.close(lock)
        os.close(fd)
