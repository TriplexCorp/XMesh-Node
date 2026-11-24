#!/usr/bin/env python3
"""CI-only signed, NONAUTHORIZING candidate for a process-bound V2 reservation.

This parser deliberately has NO HTTP transport, no installed Node command,
no Xray socket, no policy issuer and no positive user-traffic authority.
Never treat a synthetically signed candidate as a Nexus DB commitment or
an independent measurement of a running Xray process.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "xray-dataplane-fence"))
import sign_observation as observed
import verify_nexus_wal_anchor as nexus

DOMAIN = b"XMESH_QUOTA_V2_RESERVATION_CANDIDATE_V1\x00"
KIND = "xmesh.quota-v2.reservation-candidate"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX128 = re.compile(r"^[0-9a-f]{128}$")
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
MAX_INTEGER = (1 << 63) - 1
MAX_LIFETIME_MS = 120_000
FIELDS = frozenset({
    "schemaVersion", "kind", "nodeId", "activationReceiptSha256",
    "containerId", "runtimeId", "measuredPid", "policySha256",
    "userId", "accountEpoch", "meterEpoch", "reservationId",
    "reservationRevision", "acknowledgedBytes", "observedWalBytes",
    "observedCdnWalBytes", "sharedCeilingBytes", "nodeCeilingBytes",
    "cdnCeilingBytes", "inventorySequence", "inventoryTailDigest",
    "aliasScopes", "issuedAtMs", "validUntilMs",
    "authorizedBytes", "canStart", "canResume", "finalMeterVerified",
    "refundableBytes",
})
BINDINGS = frozenset({
    "nodeId", "activationReceiptSha256", "containerId", "runtimeId",
    "measuredPid", "policySha256", "userId", "accountEpoch", "meterEpoch",
    "reservationId", "aliasScopes", "inventorySequence", "inventoryTailDigest",
})


def valid_aliases(scopes, user_id):
    if not isinstance(scopes, list) or not 1 <= len(scopes) <= 16:
        return False
    seen = set()
    ordered = []
    prefix = f"xmesh-u{user_id}--"
    for row in scopes:
        if not isinstance(row, dict) or set(row) != {"email", "class"}:
            return False
        email = row.get("email")
        kind = row.get("class")
        if not isinstance(email, str) or not email.startswith(prefix):
            return False
        tag = email[len(prefix):]
        if not 1 <= len(tag.encode("utf-8")) <= 128 or any(
                char <= " " or char in "<>\\x7f" for char in tag):
            return False
        if kind not in ("main", "cdn") or email in seen:
            return False
        seen.add(email)
        ordered.append(email)
    return ordered == sorted(ordered)


def exact_counter(value, *, nonzero=False):
    return type(value) is int and (0 < value if nonzero else 0 <= value) and value <= MAX_INTEGER


def contract_digest(document):
    return hashlib.sha256(observed.canonical(document) + b"\n").hexdigest()


def verify_candidate(raw_envelope: bytes, pinned_nexus_key: Path,
                     independent_context: dict, now_ms: int,
                     prior: dict | None = None):
    """Validate a signed evidence candidate only; NEVER return start authority.

    The independent_context must be produced by future trusted Node process,
    signed policy, exact Node identity and WAL verification components; this
    function cannot establish those facts itself. A valid signature alone
    is insufficient for a runtime or quota grant.
    """
    if type(now_ms) is not int or not 0 < now_ms <= MAX_INTEGER:
        raise ValueError("candidate: invalid independent clock")
    if not isinstance(independent_context, dict) or set(independent_context) != BINDINGS:
        raise ValueError("candidate: missing independent process/reservation bindings")
    doc = observed.strict_json(raw_envelope)
    if set(doc) != {"algorithm", "payload", "signature"} or (
            doc.get("algorithm") != "Ed25519" or
            not isinstance(doc.get("signature"), str) or
            not HEX128.fullmatch(doc["signature"]) or
            raw_envelope != observed.canonical(doc) + b"\n"):
        raise ValueError("candidate: invalid canonical signed envelope")
    p = doc["payload"]
    if not isinstance(p, dict) or set(p) != FIELDS or (
            type(p["schemaVersion"]) is not int or
            p["schemaVersion"] != 1 or p["kind"] != KIND):
        raise ValueError("candidate: invalid signed schema")
    for key in ("activationReceiptSha256", "containerId", "runtimeId",
                "policySha256", "inventoryTailDigest"):
        if not isinstance(p[key], str) or not HEX64.fullmatch(p[key]):
            raise ValueError("candidate: malformed signed fingerprint")
    for key in ("accountEpoch", "meterEpoch", "reservationId"):
        if not isinstance(p[key], str) or not UUID.fullmatch(p[key]):
            raise ValueError("candidate: malformed signed reservation identity")
    for key in ("nodeId", "measuredPid", "userId", "reservationRevision",
                "inventorySequence", "issuedAtMs", "validUntilMs"):
        if not exact_counter(p[key], nonzero=True):
            raise ValueError("candidate: invalid signed positive identity or timestamp")
    if p["inventorySequence"] > 4096:
        raise ValueError("candidate: unbounded WAL inventory sequence")
    for key in ("acknowledgedBytes", "observedWalBytes",
                "observedCdnWalBytes", "sharedCeilingBytes",
                "nodeCeilingBytes", "cdnCeilingBytes", "authorizedBytes",
                "refundableBytes"):
        if not exact_counter(p[key]):
            raise ValueError("candidate: invalid signed byte counter")
    if not valid_aliases(p["aliasScopes"], p["userId"]):
        raise ValueError("candidate: untrusted alias/transport scope")
    if p["observedCdnWalBytes"] > p["observedWalBytes"] or (
            p["acknowledgedBytes"] > p["observedWalBytes"]) or (
            p["observedWalBytes"] > p["sharedCeilingBytes"]) or (
            p["observedWalBytes"] > p["nodeCeilingBytes"]) or (
            p["observedCdnWalBytes"] > p["cdnCeilingBytes"]):
        raise ValueError("candidate: signed reservation does not cover durable byte floor")
    if p["observedCdnWalBytes"] and not any(
            row["class"] == "cdn" for row in p["aliasScopes"]):
        raise ValueError("candidate: CDN spend with no authenticated CDN alias")
    if (p["validUntilMs"] <= p["issuedAtMs"] or
            p["validUntilMs"] - p["issuedAtMs"] > MAX_LIFETIME_MS or
            not p["issuedAtMs"] <= now_ms < p["validUntilMs"]):
        raise ValueError("candidate: expired or future signed reservation")
    # Signatures for a candidate can bind an existing reservation but cannot
    # mint a positive local authorization. A new kind/version with explicit
    # verified issuer+runtime proof must be reviewed before enabling traffic.
    if (p["authorizedBytes"] != 0 or p["refundableBytes"] != 0 or
            p["canStart"] is not False or p["canResume"] is not False or
            p["finalMeterVerified"] is not False):
        raise ValueError("candidate: evidence attempted to grant traffic or refunds")
    for key in BINDINGS:
        if p[key] != independent_context[key] or type(p[key]) is not type(
                independent_context[key]):
            raise ValueError("candidate: signed claim conflicts with trusted local binding")
    # Node, runtime and signed lease identities are immutable across retries;
    # a new revision may only advance the confirmed local byte floor.
    if prior is not None:
        if not isinstance(prior, dict) or set(prior) != {
                "bindings", "reservationRevision", "acknowledgedBytes",
                "observedWalBytes", "observedCdnWalBytes", "issuedAtMs",
                "receiptDigest"}:
            raise ValueError("candidate: malformed monotonic durable prior")
        if prior["bindings"] != independent_context or not exact_counter(
                prior["reservationRevision"], nonzero=True) or not exact_counter(
                prior["observedWalBytes"]) or not exact_counter(
                prior["observedCdnWalBytes"]) or not exact_counter(
                prior["acknowledgedBytes"]) or not exact_counter(
                prior["issuedAtMs"], nonzero=True):
            raise ValueError("candidate: prior reservation changed without proven close")
        if (p["reservationRevision"] < prior["reservationRevision"] or
                p["acknowledgedBytes"] < prior["acknowledgedBytes"] or
                p["observedWalBytes"] < prior["observedWalBytes"] or
                p["observedCdnWalBytes"] < prior["observedCdnWalBytes"] or
                p["issuedAtMs"] < prior["issuedAtMs"]):
            raise ValueError("candidate: old reservation or durable byte floor replay")
        if (p["reservationRevision"] == prior["reservationRevision"] and
                contract_digest(doc) != prior["receiptDigest"]):
            raise ValueError("candidate: conflicting signed same-revision receipt")
    nexus.verify_nexus_signature(DOMAIN, p, doc["signature"], pinned_nexus_key)
    return {
        "candidateSignatureVerified": True,
        "boundToExpectedNodeRuntimeReservation": True,
        "nodeId": p["nodeId"],
        "userId": p["userId"],
        "reservationId": p["reservationId"],
        "reservationRevision": p["reservationRevision"],
        "acknowledgedBytes": p["acknowledgedBytes"],
        "issuedAtMs": p["issuedAtMs"],
        "observedWalBytes": p["observedWalBytes"],
        "observedCdnWalBytes": p["observedCdnWalBytes"],
        "receiptDigest": contract_digest(doc),
        "bindings": {key: independent_context[key] for key in BINDINGS},
        "authorizedBytes": 0, "canStart": False, "canResume": False,
        "finalMeterVerified": False, "refundableBytes": 0,
    }
