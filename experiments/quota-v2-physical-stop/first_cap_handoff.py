"""Experimental verifier for a first-Genesis Nexus cap before local Xray IPC.

The caller must first authenticate the positive grant through the enrolled
strict-XSP/2 tunnel and independently verify its PostgreSQL reservation and WAL
witness. This module cannot fetch or issue a grant, start Xray, or open ingress.
Its job is to prevent a correctly signed grant for a DIFFERENT policy, user,
Node, runtime or inbound alias from reaching the measured Xray socket.
"""
from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
import time

import cap_install

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


def install_staged_cap(panel, node_id, state, socket_path, grant_raw):
    """Install into the SAME measured, network-isolated Xray; never start it.

    This is only a reusable experiment entry point for a future authenticated
    XSP/2 issuer. A caller cannot supply identity, policy, scope, or a process
    PID: all are re-derived from the original signed staging evidence and the
    kernel. This function itself does not fetch positive authority from Nexus.
    """
    if (not isinstance(panel, str) or not panel.startswith("https://")
            or not _int(node_id, 1) or os.geteuid() != 0):
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
        before = wal_transport._measure_quarantined_runtime()
        if evidence["reply"].get("nodeId") != node_id:
            raise ValueError("foreign stored quarantine Node identity")
        pinned = wal_transport._panel_pin()
        original = quarantine._enrolled_activation(panel, node_id)
        activation = evidence["prepared"].get("payload", {}).get(
            "activationReceiptSha256")
        if original.get("activationReceiptSha256") != activation:
            raise ValueError("original strict-XSP2 product activation changed")
        scope = verify_grant(grant_raw, evidence, pinned, before[3])
        if (before != wal_transport._measure_quarantined_runtime()
                or original != quarantine._enrolled_activation(panel, node_id)):
            raise ValueError("Xray runtime or enrolled Node changed before install")
        # Socket peer PID, uid, runtime, signed cap, live StatsService, WAL,
        # policy/revision and alias registry are independently checked by Xray.
        genesis = wal_transport.observed.canonical(evidence["prepared"])
        receipt = cap_install.install_in_xray(
            socket_path, before[2], before[3], genesis, grant_raw, scope)
        if before != wal_transport._measure_quarantined_runtime():
            raise ValueError("Xray process changed while installing cap")
        return receipt
    finally:
        os.close(lock)
        os.close(state_fd)
