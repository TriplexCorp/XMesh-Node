#!/usr/bin/env python3
"""Experimental verifier for a first-Genesis Nexus cap before local Xray IPC.

The caller must first authenticate the positive grant through the enrolled
strict-XSP/2 tunnel and independently verify its PostgreSQL reservation and WAL
witness. This module cannot fetch or issue a grant, start Xray, or open ingress.
Its job is to prevent a correctly signed grant for a DIFFERENT policy, user,
Node, runtime or inbound alias from reaching the measured Xray socket.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import tempfile
import time

import cap_install
import genesis_reservation as confirmed_lease

import quarantine_policy as quarantine
import wal_transport

DOMAIN = b"XMESH_QUOTA_V2_XRAY_CAP_ADMISSION_V1\x00"
MAX_BYTES = 8192
MAX_CAP = 67_108_864
ZERO_HEAD = "0" * 64
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
CAP_KEYS = frozenset({
    "schemaVersion", "kind", "nodeId", "userId",
    "activationReceiptSha256", "runtimeId", "policySha256",
    "accountEpoch", "meterEpoch", "reservationId",
    "reservationRevision", "nonce", "inventoryTailDigest",
    "witnessedWalBytes", "witnessedCdnBytes", "sharedCeilingBytes",
    "nodeCeilingBytes", "cdnCeilingBytes", "aliasScopes",
    "issuedAtMs", "installBeforeMs", "validUntilMs",
    "canSpend", "canStart", "canResume", "finalMeterVerified",
    "refundableBytes",
})
UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")


def _int(value, lower=None, upper=None):
    return type(value) is int and (lower is None or value >= lower) and (
        upper is None or value <= upper)


def _signed(envelope, domain, pinned, public_file):
    if (not isinstance(envelope, dict)
            or set(envelope) != {"algorithm", "payload", "signature"}
            or envelope["algorithm"] != "Ed25519"
            or not isinstance(envelope["payload"], dict)
            or not isinstance(envelope["signature"], str)
            or re.fullmatch(r"[0-9a-f]{128}", envelope["signature"]) is None):
        raise ValueError("unexpected Nexus signature envelope")
    wal_transport.verifier.verify_nexus_signature(
        domain, envelope["payload"], envelope["signature"], public_file)


def _authorized_aliases(payload, policy, profile):
    user_id = payload["userId"]
    users = policy.get("users")
    if not isinstance(users, list):
        raise ValueError("no signed user roster")
    owners = [u for u in users if isinstance(u, dict)
              and type(u.get("userId")) is int and u["userId"] == user_id]
    if (len(owners) != 1
            or owners[0].get("onHold") is not True
            or not _int(owners[0].get("offlineBudgetBytes"), 0, 0)
            or not isinstance(owners[0].get("xrayId"), str)):
        raise ValueError("cap user is absent or not quarantined in signed policy")
    uuid = owners[0]["xrayId"]
    aliases = payload["aliasScopes"]
    if not isinstance(aliases, list) or not 1 <= len(aliases) <= 16:
        raise ValueError("missing capped MAIN/CDN inbound aliases")
    inbounds = profile.get("inbounds") if isinstance(profile, dict) else None
    if not isinstance(inbounds, list):
        raise ValueError("signed Xray profile has no inbounds")
    result = []
    previous = ""
    found_cdn = False
    for alias in aliases:
        if not isinstance(alias, dict) or set(alias) != {"email", "class"}:
            raise ValueError("unknown signed inbound alias shape")
        email, cls = alias["email"], alias["class"]
        if not isinstance(email, str) or not isinstance(cls, str):
            raise ValueError("invalid signed inbound alias type")
        prefix = f"xmesh-u{user_id}--"
        if (not email.startswith(prefix) or not previous < email
                or cls not in ("main", "cdn")):
            raise ValueError("foreign, duplicate or unsorted signed alias")
        tag = email[len(prefix):]
        if (not 1 <= len(tag) <= 128
                or re.fullmatch(r"[A-Za-z0-9_-]+", tag) is None):
            raise ValueError("invalid encoded Xray tag")
        matching = [item for item in inbounds
                    if isinstance(item, dict) and item.get("tag") == tag]
        if len(matching) != 1:
            raise ValueError("signed alias has no unique Xray inbound")
        inbound = matching[0]
        settings = inbound.get("settings")
        clients = settings.get("clients") if isinstance(settings, dict) else None
        if (not isinstance(clients, list)
                or sum(isinstance(c, dict) and c.get("email") == email
                       and c.get("id") == uuid for c in clients) != 1):
            raise ValueError("signed alias is not assigned to that policy user")
        # Only the exact MAIN and CDN VLESS classes are covered by this first
        # implementation, never an arbitrary protocol or unmetered inbound.
        if inbound.get("protocol") != "vless" or tag != f"vless-{cls}":
            raise ValueError("alias has unsupported protocol or traffic class")
        result.append({"email": email, "class": cls})
        found_cdn |= cls == "cdn"
        previous = email
    if payload["cdnCeilingBytes"] > 0 and not found_cdn:
        raise ValueError("positive CDN cap without assigned CDN alias")
    return result


def verify_grant(grant_raw, evidence, pinned, runtime, now_ms=None):
    """Return an immutable locally derived scope; NEVER trust caller scope."""
    if (not isinstance(grant_raw, bytes)
            or not 0 < len(grant_raw) <= MAX_BYTES
            or not isinstance(evidence, dict)
            or set(evidence) != {"prepared", "reply"}
            or not isinstance(runtime, str) or HEX64.fullmatch(runtime) is None
            or not isinstance(pinned, str) or HEX64.fullmatch(pinned) is None):
        raise ValueError("invalid signed cap or staging inputs")
    now = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    if not _int(now, 1):
        raise ValueError("invalid monotonic admission clock")
    prepared, reply = evidence["prepared"], evidence["reply"]
    if not isinstance(prepared, dict) or not isinstance(reply, dict):
        raise ValueError("invalid first-Genesis durable evidence")
    node = reply.get("nodeId")
    if not _int(node, 1):
        raise ValueError("invalid trusted Node identity")
    quarantine.validate_response(
        wal_transport.observed.canonical(reply), node, prepared, pinned, now)
    genesis = prepared.get("payload")
    if not isinstance(genesis, dict) or genesis.get("candidateRuntimeId") != runtime:
        raise ValueError("first-Genesis Xray runtime changed")
    if not _int(genesis.get("preparedAtMs"), 1):
        raise ValueError("bad first-Genesis preparation clock")
    envelope = wal_transport.observed.strict_json(grant_raw)
    if (grant_raw != wal_transport.observed.canonical(envelope) + b"\n"
            or not isinstance(envelope, dict)):
        raise ValueError("positive cap is not original canonical signed bytes")
    p = envelope.get("payload")
    if not isinstance(p, dict) or set(p) != CAP_KEYS:
        raise ValueError("positive cap has unknown or missing claims")
    if (not _int(p["schemaVersion"], 1, 1)
            or p["kind"] != "xmesh.quota-v2.xray-cap-admission"
            or not _int(p["nodeId"], node, node)
            or not _int(p["userId"], 1)
            or p["activationReceiptSha256"] != genesis.get("activationReceiptSha256")
            or p["runtimeId"] != runtime
            or p["policySha256"] != reply.get("policySha256")
            or not isinstance(p["nonce"], str) or HEX64.fullmatch(p["nonce"]) is None
            or p["inventoryTailDigest"] != ZERO_HEAD
            or not _int(p["witnessedWalBytes"], 0, 0)
            or not _int(p["witnessedCdnBytes"], 0, 0)
            or not _int(p["reservationRevision"], 1)
            or not all(isinstance(p[k], str) and UUID.fullmatch(p[k])
                       for k in ("accountEpoch", "meterEpoch", "reservationId"))
            or not _int(p["sharedCeilingBytes"], 1, MAX_CAP)
            or not _int(p["nodeCeilingBytes"], p["sharedCeilingBytes"], MAX_CAP)
            or not _int(p["cdnCeilingBytes"], 0, p["sharedCeilingBytes"])
            or not _int(p["issuedAtMs"], 1, now)
            or not _int(p["installBeforeMs"], now + 1)
            or p["installBeforeMs"] > p["issuedAtMs"] + 120_000
            or p["installBeforeMs"] > genesis["validUntilMs"]
            or not _int(p["validUntilMs"], p["installBeforeMs"] + 1)
            or p["validUntilMs"] > p["issuedAtMs"] + 86_400_000
            or p["canSpend"] is not True or p["canStart"] is not False
            or p["canResume"] is not False or p["finalMeterVerified"] is not False
            or not _int(p["refundableBytes"], 0, 0)):
        raise ValueError("cap is not a bounded first-Genesis spending-only grant")
    aliases = _authorized_aliases(p, reply["policy"], reply["config"])
    # Both original zero-authority proof and new positive grant must be
    # verified against the ALREADY PINNED signer, not a reply-supplied key.
    with tempfile.TemporaryDirectory(prefix="xmesh-cap-verify-") as root:
        public_file = os.path.join(root, "pinned-nexus.pem")
        wal_transport._write_public(pinned, public_file)
        _signed(prepared, wal_transport.GENESIS_DOMAIN, pinned, public_file)
        _signed(envelope, DOMAIN, pinned, public_file)
    return {
        "userId": p["userId"], "policySha256": p["policySha256"],
        "accountEpoch": p["accountEpoch"], "meterEpoch": p["meterEpoch"],
        "reservationId": p["reservationId"], "revision": p["reservationRevision"],
        "nonce": p["nonce"], "aliases": aliases,
    }


def install_staged_cap(panel, node_id, state, socket_path, grant_raw, executable_pin):
    """Install into the SAME measured, network-isolated Xray; never start it.

    This is only a reusable experiment entry point for a future authenticated
    XSP/2 issuer. A caller cannot supply identity, policy, scope, or a process
    PID: all are re-derived from the original signed staging evidence and the
    kernel. This function itself does not fetch positive authority from Nexus.
    """
    if (not isinstance(panel, str) or not panel.startswith("https://")
            or not _int(node_id, 1) or os.geteuid() != 0
            or not isinstance(executable_pin, str)
            or HEX64.fullmatch(executable_pin) is None):
        raise ValueError("positive cap needs root and a strict enrolled Node")
    state_fd, lock = quarantine._locked_private_state(state)
    try:
        fd = os.open("genesis-quarantine-envelope.json",
                     os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                     dir_fd=state_fd)
        try:
            st = os.fstat(fd)
            if (not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or
                    st.st_nlink != 1 or st.st_mode & 0o077 or
                    st.st_size <= 0 or st.st_size > quarantine.MAX_REPLY + 4096):
                raise ValueError("unsafe first-Genesis evidence file")
            raw = os.read(fd, quarantine.MAX_REPLY + 4097)
            if len(raw) != st.st_size:
                raise ValueError("first-Genesis evidence changed while read")
        finally:
            os.close(fd)
        evidence = wal_transport.observed.strict_json(raw)
        if not isinstance(evidence, dict) or set(evidence) != {"prepared", "reply"}:
            raise ValueError("invalid original quarantine evidence")
        # Hash the ORIGINAL signed Nexus config, then measure the actual
        # config file through this Linux PID's mount namespace. The Xray
        # executable pin must come from independent verified release state;
        # it must never be learned from the live process or grant reply.
        if not isinstance(evidence["reply"], dict) or not isinstance(
                evidence["reply"].get("config"), dict):
            raise ValueError("no signed Xray profile for an executable/config measurement")
        config_pin = hashlib.sha256(wal_transport.observed.canonical(
            evidence["reply"]["config"])).hexdigest()
        pins = (executable_pin, config_pin)
        before = wal_transport._measure_quarantined_runtime(pins)
        if evidence["reply"].get("nodeId") != node_id:
            raise ValueError("foreign stored quarantine Node identity")
        pinned = wal_transport._panel_pin()
        original = quarantine._enrolled_activation(panel, node_id)
        activation = evidence["prepared"].get("payload", {}).get(
            "activationReceiptSha256")
        if original.get("activationReceiptSha256") != activation:
            raise ValueError("original strict-XSP2 product activation changed")
        scope = verify_grant(grant_raw, evidence, pinned, before[3])
        # A valid Nexus-signed cap alone is NOT enough to bypass the durable
        # installed Agent lease echo. Require this SAME user, epochs, exact
        # reservation and revision from the original signed confirmed stage.
        prepared_document = confirmed_lease._identity_file(
            state_fd,
            f"genesis-reservation-prepared-u{scope['userId']}.json",
            confirmed_lease.MAX_REPLY,
        )
        prepared = confirmed_lease.verify_lease_response(
            wal_transport.observed.canonical(prepared_document),
            node_id, scope["userId"], "prepare", evidence,
            pinned, original["activationReceiptSha256"],
        )
        lease_document = confirmed_lease._identity_file(
            state_fd,
            f"genesis-reservation-confirmed-u{scope['userId']}.json",
            confirmed_lease.MAX_REPLY,
        )
        reply_bytes = wal_transport.observed.canonical(lease_document)
        committed = confirmed_lease.verify_lease_response(
            reply_bytes, node_id, scope["userId"], "confirm", evidence,
            pinned, original["activationReceiptSha256"], previous=prepared,
        )
        reservation = committed["payload"]["reservation"]
        if (reservation["epoch"] != scope["accountEpoch"]
                or reservation["meterEpoch"] != scope["meterEpoch"]
                or reservation["reservationId"] != scope["reservationId"]
                or reservation["revision"] != scope["revision"]):
            raise ValueError("signed cap does not match the original durable confirmed lease")
        grant = wal_transport.observed.strict_json(grant_raw)["payload"]
        if (grant["sharedCeilingBytes"] > reservation["ceilingBytes"]
                or grant["validUntilMs"] > reservation["validUntilMs"]):
            raise ValueError("signed cap exceeds the confirmed SQL lease")
        if (before != wal_transport._measure_quarantined_runtime(pins)
                or original != quarantine._enrolled_activation(panel, node_id)):
            raise ValueError("Xray runtime or enrolled Node changed before install")
        # Socket peer PID, uid, runtime, signed cap, live StatsService, WAL,
        # policy/revision and alias registry are independently checked by Xray.
        genesis = wal_transport.observed.canonical(evidence["prepared"])
        receipt = cap_install.install_in_xray(
            socket_path, before[2], before[3], genesis, grant_raw, scope)
        if before != wal_transport._measure_quarantined_runtime(pins):
            raise ValueError("Xray process changed while installing cap")
        return receipt
    finally:
        os.close(lock)
        os.close(state_fd)


def fetch_and_install_rehearsal(panel, node_id, user_id, state, socket_path,
                                executable_pin, request_challenge):
    """Disposable installed Agent path. No arbitrary positive issuer or start.

    Nexus issues the first signed cap from its existing confirmed SQL lease.
    The runtime measurement is local evidence. Nexus does not treat the
    remote host PID or its report as trusted kernel attestation.
    """
    if (os.environ.get("XMESH_QUOTA_V2_INSTALLED_CAP_DELIVERY") != "1"
            or os.geteuid() != 0 or not _int(node_id,1) or not _int(user_id,1)
            or not isinstance(panel,str) or not panel.startswith("https://")
            or not isinstance(executable_pin,str) or HEX64.fullmatch(executable_pin) is None
            or not isinstance(request_challenge,str) or HEX64.fullmatch(request_challenge) is None):
        raise ValueError("explicit disposable signed-cap rehearsal required")
    state_fd,lock = quarantine._locked_private_state(state)
    try:
        pinned = wal_transport._panel_pin()
        identity = quarantine._enrolled_activation(panel,node_id)
        evidence = confirmed_lease._staged_original(
            state_fd,node_id,user_id,pinned,identity["activationReceiptSha256"])
        config_pin = evidence["reply"]["revision"]
        pins = (executable_pin,config_pin)
        before = wal_transport._measure_quarantined_runtime(pins)
        raw = quarantine._post_quarantined_desired({
            "nodeId":node_id, "userId":user_id, "requestChallenge":request_challenge,
            "measurement":{
                "containerId":before[0], "hostPid":before[2], "runtimeId":before[3],
            },
        },state,quarantine.CAP_DELIVERY_PATH)
        if not isinstance(raw,bytes) or not 0 < len(raw) <= 16384:
            raise ValueError("oversized strict signed cap delivery")
        response = wal_transport.observed.strict_json(raw)
        if (not isinstance(response,dict)
                or set(response)!={"status","nodeId","userId","signedEnvelope"}
                or response["status"]!="committed_first_cap"
                or type(response["nodeId"]) is not int or response["nodeId"]!=node_id
                or type(response["userId"]) is not int or response["userId"]!=user_id
                or not isinstance(response["signedEnvelope"],str)):
            raise ValueError("strict-XSP2 did not return one committed cap")
        grant = response["signedEnvelope"].encode("utf-8")
        scope = verify_grant(grant,evidence,pinned,before[3])
        if (scope["userId"]!=user_id or scope["nonce"]!=request_challenge
                or before != wal_transport._measure_quarantined_runtime(pins)
                or identity != quarantine._enrolled_activation(panel,node_id)):
            raise ValueError("delivered cap or independently measured runtime changed")
        # Preserve the EXACT original cap bytes as a string in this root-only
        # evidence file. This is not permission to start/restart Xray.
        quarantine._durable_store(state_fd,response,
                                  f"genesis-positive-cap-u{user_id}.json")
    finally:
        os.close(lock)
        os.close(state_fd)
    # Reacquire the same flock and independently recheck BOTH signed lease
    # receipts, original policy, pins and live PID and private Unix peer.
    return install_staged_cap(panel,node_id,state,socket_path,grant,executable_pin)


def _verify_cap_envelope(raw, pinned, public_file):
    if not 0 < len(raw) <= MAX_BYTES:
        raise ValueError("oversized spending permit")
    env = wal_transport.observed.strict_json(raw)
    if not isinstance(env, dict) or wal_transport.observed.canonical(env) + b"\n" != raw:
        raise ValueError("noncanonical spending permit")
    _signed(env, DOMAIN, pinned, public_file)
    payload = env["payload"]
    if (set(payload) != CAP_KEYS or not _int(payload["schemaVersion"], 1, 1)
            or payload["canSpend"] is not True or payload["canStart"] is not False
            or payload["canResume"] is not False or payload["finalMeterVerified"] is not False
            or not _int(payload["refundableBytes"], 0, 0)):
        raise ValueError("unexpected permit authority")
    return payload


def verify_renewal(raw, previous, pinned, challenge):
    with tempfile.TemporaryDirectory(prefix="xmesh-renew-verify-") as tmp:
        public_file = os.path.join(tmp, "pinned-nexus.pem")
        wal_transport._write_public(pinned, public_file)
        prior = _verify_cap_envelope(previous, pinned, public_file)
        current = _verify_cap_envelope(raw, pinned, public_file)
    policy_fields = ("nodeId", "userId", "activationReceiptSha256", "runtimeId",
                     "policySha256", "accountEpoch", "meterEpoch", "reservationId", "aliasScopes",
                     "validUntilMs")
    now = time.time_ns() // 1_000_000
    if (prior["kind"] not in ("xmesh.quota-v2.xray-cap-admission",
                              "xmesh.quota-v2.xray-cap-renewal")
            or current["kind"] != "xmesh.quota-v2.xray-cap-renewal"
            or any(current[k] != prior[k] for k in policy_fields)
            or current["reservationRevision"] != prior["reservationRevision"] + 1
            or current["nonce"] != challenge
            or current["nonce"] == prior["nonce"]
            or not prior["issuedAtMs"] <= current["issuedAtMs"] <= now
            or not now < current["installBeforeMs"] < current["validUntilMs"]
            or not isinstance(current["inventoryTailDigest"], str)
            or HEX64.fullmatch(current["inventoryTailDigest"]) is None
            or any(not _int(current[k], prior[k], prior[k] + MAX_CAP) for k in (
                "sharedCeilingBytes", "nodeCeilingBytes", "cdnCeilingBytes"))
            or not _int(current["witnessedWalBytes"], prior["witnessedWalBytes"],
                        prior["sharedCeilingBytes"])
            or not _int(current["witnessedCdnBytes"], prior["witnessedCdnBytes"],
                        min(prior["cdnCeilingBytes"], current["witnessedWalBytes"]))):
        raise ValueError("renewal changes authority or does not advance the live permit")
    return {
        "userId": current["userId"], "policySha256": current["policySha256"],
        "accountEpoch": current["accountEpoch"], "meterEpoch": current["meterEpoch"],
        "reservationId": current["reservationId"], "revision": current["reservationRevision"],
        "nonce": challenge, "aliases": prior["aliasScopes"],
    }


def fetch_and_install_renewal(panel, node_id, user_id, state, socket_path,
                              executable_pin, request_challenge, previous_revision):
    if (os.environ.get("XMESH_QUOTA_V2_INSTALLED_CAP_DELIVERY") != "1"
            or os.geteuid() != 0 or not _int(node_id, 1) or not _int(user_id, 1)
            or not isinstance(panel, str) or not panel.startswith("https://")
            or HEX64.fullmatch(executable_pin) is None
            or HEX64.fullmatch(request_challenge) is None
            or not _int(previous_revision, 1, 2**63 - 2)):
        raise ValueError("renewal requires the enrolled root Agent and measured Xray")
    fd, lock = quarantine._locked_private_state(state)
    try:
        original = confirmed_lease._identity_file(
            fd, "genesis-quarantine-envelope.json", quarantine.MAX_REPLY + 4096)
        genesis = original["prepared"]["payload"]
        staged = original["reply"]
        activation = quarantine._enrolled_activation(panel, node_id)["activationReceiptSha256"]
        if genesis["activationReceiptSha256"] != activation or staged["nodeId"] != node_id:
            raise ValueError("renewal is outside the enrolled Xray scope")
        pins = confirmed_lease._original_measurement_pins(fd, original, node_id, activation)
        if pins[0] != executable_pin:
            raise ValueError("Xray executable pin differs from the original measured release")
        measured = wal_transport._measure_quarantined_runtime(pins)
        if measured[3] != genesis["candidateRuntimeId"]:
            raise ValueError("renewal cannot authorize a replacement Xray")
        pinned = wal_transport._panel_pin()
        target = f"genesis-renewal-u{user_id}-r{previous_revision}.json"
        try:
            saved = confirmed_lease._identity_file(fd, target, 16384)
        except FileNotFoundError:
            saved = confirmed_lease._identity_file(fd, f"genesis-positive-cap-u{user_id}.json", 16384)
        previous = saved["signedEnvelope"].encode()
        with tempfile.TemporaryDirectory(prefix="xmesh-renew-prior-") as tmp:
            public_file = os.path.join(tmp, "pinned-nexus.pem")
            wal_transport._write_public(pinned, public_file)
            prior = _verify_cap_envelope(previous, pinned, public_file)
        if (prior["reservationRevision"] != previous_revision or prior["nodeId"] != node_id
                or prior["userId"] != user_id or prior["runtimeId"] != measured[3]
                or prior["policySha256"] != staged["policySha256"]
                or prior["activationReceiptSha256"] != activation):
            raise ValueError("previous spending permit differs from the original Xray scope")
        # The nonce is durable BEFORE contacting Nexus. If its response is
        # lost after COMMIT, the next Agent poll must retry this exact
        # request and cannot accidentally claim a second revision.
        request_name = f"genesis-renewal-request-u{user_id}-r{previous_revision}.json"
        request_intent = {
            "nodeId": node_id, "userId": user_id,
            "previousRevision": previous_revision,
            "requestChallenge": request_challenge,
        }
        try:
            prior_intent = confirmed_lease._identity_file(fd, request_name, 4096)
        except FileNotFoundError:
            quarantine._durable_store(fd, request_intent, request_name)
        else:
            if prior_intent != request_intent:
                raise ValueError("renewal retry replaced a fsynced request nonce")
        raw = quarantine._post_quarantined_desired({
            "nodeId": node_id, "userId": user_id, "requestChallenge": request_challenge,
            "measurement": {"containerId": measured[0], "hostPid": measured[2],
                            "runtimeId": measured[3]},
            "renewal": {"reservationId": prior["reservationId"],
                        "previousRevision": previous_revision},
        }, state, quarantine.CAP_DELIVERY_PATH)
        if not isinstance(raw, bytes) or not 0 < len(raw) <= 16384:
            raise ValueError("invalid renewal response size")
        response = wal_transport.observed.strict_json(raw)
        if (not isinstance(response, dict)
                or set(response) != {"status", "nodeId", "userId", "signedEnvelope"}
                or response["status"] != "committed_renewal"
                or response["nodeId"] != node_id or response["userId"] != user_id):
            raise ValueError("incorrect committed renewal response")
        permit = response["signedEnvelope"].encode()
        scope = verify_renewal(permit, previous, pinned, request_challenge)
        receipt = cap_install.install_in_xray(socket_path, measured[2], measured[3], b"", permit, scope)
        quarantine._durable_store(fd, response,
            f"genesis-renewal-u{user_id}-r{scope['revision']}.json")
        return receipt
    finally:
        os.close(lock)
        os.close(fd)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Disposable first-Genesis strict signed-cap handoff")
    ap.add_argument("--panel",required=True)
    ap.add_argument("--node-id",required=True,type=int)
    ap.add_argument("--user-id",required=True,type=int)
    ap.add_argument("--state",required=True)
    ap.add_argument("--socket",required=True)
    ap.add_argument("--executable-sha256",required=True)
    ap.add_argument("--request-challenge",required=True)
    ap.add_argument("--previous-revision", type=int)
    args = ap.parse_args()
    try:
        common = (args.panel, args.node_id, args.user_id, args.state, args.socket,
                  args.executable_sha256, args.request_challenge)
        if args.previous_revision is None:
            proof = fetch_and_install_rehearsal(*common)
        else:
            proof = fetch_and_install_renewal(*common, args.previous_revision)
        # No signed envelope, credentials or profile on the console.
        print(json.dumps(proof,sort_keys=True,separators=(",",":")))
    except (OSError, ValueError, TypeError, KeyError) as error:
        ap.exit(1,"Disposable Quota V2 signed-cap handoff denied: "+str(error)+"\n")
