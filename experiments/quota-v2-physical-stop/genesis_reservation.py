#!/usr/bin/env python3
"""Experimental installed strict-PQ Genesis SQL lease prepare/echo.

Returns only a Nexus-signed identity with zero traffic authority. The
separate, still-missing positive issuer and local Xray cap installation are
required before any user traffic. Do not expose this on normal startup.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time

import quarantine_policy as quarantine
import wal_transport

MAX_REPLY = 8192
MAX_CAP = 64 * 1024 * 1024
UUID = re.compile(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\Z")


def _identity_file(state_fd, filename, max_size):
    fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW |
                 os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=state_fd)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or info.st_nlink != 1 or info.st_mode & 0o077
                or not 0 < info.st_size <= max_size):
            raise ValueError("unsafe original root-private Genesis evidence")
        raw = os.read(fd, max_size + 1)
        if len(raw) != info.st_size:
            raise ValueError("Genesis evidence replaced during read")
        return wal_transport.observed.strict_json(raw)
    finally:
        os.close(fd)


def _staged_original(state_fd, node, user, pinned, activation):
    original = _identity_file(
        state_fd, "genesis-quarantine-envelope.json",
        quarantine.MAX_REPLY + 4096)
    if not isinstance(original, dict) or set(original) != {"prepared", "reply"}:
        raise ValueError("missing immutable signed first-Genesis policy")
    prepared, reply = original["prepared"], original["reply"]
    if not isinstance(prepared, dict) or not isinstance(reply, dict):
        raise ValueError("invalid durable Genesis evidence")
    policy = quarantine.validate_response(
        wal_transport.observed.canonical(reply), node, prepared, pinned)
    payload = prepared["payload"]
    if payload["activationReceiptSha256"] != activation:
        raise ValueError("original strict-PQ Node activation changed")
    # Verify the ORIGINAL Ed25519 Genesis under the SAME root-pinned key.
    if (set(prepared) != {"algorithm", "payload", "signature"}
            or prepared["algorithm"] != "Ed25519"):
        raise ValueError("missing original signed Genesis receipt")
    with tempfile.TemporaryDirectory(prefix="xmesh-lease-proof-") as root:
        public = Path(root) / "nexus.pem"
        wal_transport._write_public(pinned, public)
        wal_transport.verifier.verify_nexus_signature(
            wal_transport.GENESIS_DOMAIN, payload, prepared["signature"], public)
    users = policy["policy"]["users"]
    assigned = [u for u in users if isinstance(u, dict)
                and type(u.get("userId")) is int and u["userId"] == user]
    if (len(assigned) != 1 or assigned[0].get("onHold") is not True
            or type(assigned[0].get("offlineBudgetBytes")) is not int
            or assigned[0]["offlineBudgetBytes"] != 0):
        raise ValueError("requested lease user is not in the original signed quarantine")
    return original


def verify_lease_response(raw, node, user, op, original, pinned, activation,
                          previous=None, now_ms=None):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_REPLY:
        raise ValueError("invalid signed lease reply size")
    envelope = wal_transport.observed.strict_json(raw)
    if not isinstance(envelope, dict) or set(envelope) != {
            "algorithm", "payload", "signature"}:
        raise ValueError("invalid lease reply envelope")
    if envelope["algorithm"] != "Ed25519":
        raise ValueError("lease identity signature algorithm mismatch")
    payload = envelope["payload"]
    if not isinstance(payload, dict) or set(payload) != {
            "schemaVersion", "kind", "status", "nodeId", "userId",
            "activationReceiptSha256", "runtimeId", "genesisChallenge",
            "policySha256", "reservation", "issuedAtMs", "authorizedBytes",
            "canSpend", "canStart", "canResume", "finalMeterVerified",
            "refundableBytes"}:
        raise ValueError("unknown or missing signed zero-spend lease claim")
    genesis = original["prepared"]["payload"]
    policy = original["reply"]
    now = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    if (type(payload["schemaVersion"]) is not int or payload["schemaVersion"] != 1
            or payload["kind"] != "xmesh.quota-v2.genesis-lease-identity"
            or payload["status"] != ("prepared" if op == "prepare" else "confirmed")
            or type(payload["nodeId"]) is not int or payload["nodeId"] != node
            or type(payload["userId"]) is not int or payload["userId"] != user
            or payload["activationReceiptSha256"] != activation
            or payload["runtimeId"] != genesis["candidateRuntimeId"]
            or payload["genesisChallenge"] != genesis["challenge"]
            or payload["policySha256"] != policy["policySha256"]
            or type(payload["issuedAtMs"]) is not int
            or not genesis["preparedAtMs"] <= payload["issuedAtMs"] <= now
            or payload["issuedAtMs"] >= genesis["validUntilMs"]
            or type(payload["authorizedBytes"]) is not int
            or payload["authorizedBytes"] != 0
            or payload["canSpend"] is not False
            or payload["canStart"] is not False
            or payload["canResume"] is not False
            or payload["finalMeterVerified"] is not False
            or type(payload["refundableBytes"]) is not int
            or payload["refundableBytes"] != 0):
        raise ValueError("lease stage tried to grant Xray traffic or changed identity")
    lease = payload["reservation"]
    if not isinstance(lease, dict) or set(lease) != {
            "epoch", "meterEpoch", "reservationId", "revision",
            "acknowledgedBytes", "ceilingBytes", "validUntilMs"}:
        raise ValueError("missing immutable lease identity")
    if (not all(isinstance(lease[k], str) and UUID.fullmatch(lease[k])
                for k in ("epoch", "meterEpoch", "reservationId"))
            or type(lease["revision"]) is not int or lease["revision"] <= 0
            or type(lease["acknowledgedBytes"]) is not int
            or lease["acknowledgedBytes"] != 0
            or type(lease["ceilingBytes"]) is not int
            or not 0 <= lease["ceilingBytes"] <= MAX_CAP
            or type(lease["validUntilMs"]) is not int
            or lease["validUntilMs"] <= now
            or (op == "prepare" and lease["ceilingBytes"] != 0)
            or (op == "confirm" and lease["ceilingBytes"] <= 0)):
        raise ValueError("lease invalid or positive-cap authority not independently proven")
    if previous is not None:
        old = previous["payload"]["reservation"]
        if any(lease[k] != old[k]
               for k in ("epoch", "meterEpoch", "reservationId")):
            raise ValueError("confirmed lease differs from original durable echo")
    # Never trust a public key supplied with this reply; use the original
    # owner-enrolled and root-pinned Nexus Ed25519 signer.
    with tempfile.TemporaryDirectory(prefix="xmesh-lease-verify-") as root:
        public = Path(root) / "nexus.pem"
        wal_transport._write_public(pinned, public)
        wal_transport.verifier.verify_nexus_signature(
            b"", payload, envelope["signature"], public)
    return envelope


def _original_measurement_pins(state_fd, original, node, activation):
    """Recover the pins persisted before the original Genesis network call."""
    intent = _identity_file(state_fd, quarantine.INTENT_FILE, 4096)
    genesis = original["prepared"]["payload"]
    expected = {
        "nodeId":node, "runtimeId":genesis["candidateRuntimeId"],
        "activationReceiptSha256":activation,
        "configSha256":original["reply"]["revision"],
        "challenge":genesis["challenge"],
    }
    if (not isinstance(intent,dict)
            or set(intent)!=set(expected)|{"executableSha256"}
            or any(type(intent[k]) is not type(v) or intent[k]!=v
                   for k,v in expected.items())
            or not quarantine._hex(intent["executableSha256"])
            or not quarantine._hex(intent["configSha256"])):
        raise ValueError("original measured Genesis intent mismatches lease")
    return (intent["executableSha256"],intent["configSha256"])


def run(panel, node, user, state, operation, *, require_pins=True):
    if (os.geteuid() != 0 or not isinstance(panel, str)
            or not panel.startswith("https://") or node <= 0 or user <= 0
            or operation not in ("prepare", "confirm")):
        raise ValueError("lease stage requires a root enrolled strict-PQ Agent")
    state_fd, lock = quarantine._locked_private_state(state)
    try:
        pinned = wal_transport._panel_pin()
        identity = quarantine._enrolled_activation(panel, node)
        activation = identity["activationReceiptSha256"]
        original = _staged_original(state_fd, node, user, pinned, activation)
        genesis = original["prepared"]["payload"]
        pins = _original_measurement_pins(state_fd, original, node, activation) if require_pins else None
        before = wal_transport._measure_quarantined_runtime(pins)
        if before[3] != genesis["candidateRuntimeId"]:
            raise ValueError("measured Xray replaced since original signed Genesis")
        previous = None
        request = {
            "nodeId":node, "userId":user, "operation":operation,
            "policySha256":original["reply"]["policySha256"],
            "runtimeId":before[3], "genesisChallenge":genesis["challenge"],
        }
        if operation == "confirm":
            previous = _identity_file(
                state_fd, f"genesis-reservation-prepared-u{user}.json", MAX_REPLY)
            lease = verify_lease_response(
                wal_transport.observed.canonical(previous), node, user, "prepare",
                original, pinned, activation)
            original_lease = lease["payload"]["reservation"]
            request["echo"] = {k:original_lease[k]
                               for k in ("epoch", "meterEpoch", "reservationId")}
        raw = quarantine._post_quarantined_desired(
            request, state, quarantine.LEASE_PATH)
        result = verify_lease_response(
            raw, node, user, operation, original, pinned, activation,
            previous=previous)
        if (before != wal_transport._measure_quarantined_runtime(pins)
                or identity != quarantine._enrolled_activation(panel, node)):
            raise ValueError("strict Node activation or kernel Xray changed during lease stage")
        # A reserved SQL ceiling is NOT an installed Xray byte-cap.
        # Persist exact signed evidence under the root lock before returning.
        quarantine._durable_store(
            state_fd, result,
            f"genesis-reservation-{('prepared' if operation=='prepare' else 'confirmed')}-u{user}.json")
        return {
            "status":operation,
            "nodeId":node,
            "userId":user,
            "authorizedBytes":0,
            "canStart":False,
            "canResume":False,
        }
    finally:
        os.close(lock)
        os.close(state_fd)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--panel", required=True)
    ap.add_argument("--node-id", required=True, type=int)
    ap.add_argument("--user-id", required=True, type=int)
    ap.add_argument("--state", required=True)
    ap.add_argument("--operation", required=True, choices=("prepare", "confirm"))
    args = ap.parse_args()
    try:
        print(json.dumps(
            run(args.panel, args.node_id, args.user_id, args.state,
                args.operation), sort_keys=True, separators=(",", ":")))
    except (OSError, ValueError, TypeError, KeyError, IndexError) as error:
        ap.exit(1, "Quota V2 first-Genesis SQL lease denied: "+str(error)+"\n")
