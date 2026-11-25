#!/usr/bin/env python3
"""Read-only strict-PQ TLS candidate probe, NEVER positive ingress authority.

Uses only the enrolled root-installed XSP/2 product tunnel. This script
NEVER writes signed-cap state, starts a listener, installs a permit or
returns a positive canServePublic value. An SQL match is NOT a receipt of
installed Xray metering, a WAL proof or a trusted TLS certificate.
"""
import argparse
import json
import os
import re
import sys
import time
import uuid

import public_tls_cap_watch

import genesis_reservation
import quarantine_policy as quarantine
import wal_transport

MAX_REPLY = 1536
MAX_PROBE_NS = 9_000_000_000
CAP_FILE = re.compile(r"genesis-positive-cap-u([1-9][0-9]{0,18})\.json\Z")
SOCKET = "/var/lib/xmesh-first-meter/runtime/drain.sock"
MAX_LIFETIME_MS = 120_000
STATUS = "candidate_only_not_authorized"
KEYS = frozenset({
    "status", "nodeId", "userId", "evidenceMatched", "capRosterSha256",
    "canServePublic", "canStart", "canResume", "canSpend",
    "authorizedBytes", "signedEnvelope", "liveMeterVerified",
    "certificateVerified", "revocationWatchInstalled",
})


def verify_zero_authority(raw, *, node, user, roster_sha256):
    if (not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_REPLY
            or not wal_transport._hex(roster_sha256, 64)):
        raise ValueError("public TLS evidence response size invalid")
    response = wal_transport.observed.strict_json(raw)
    if (not isinstance(response, dict) or set(response) != KEYS
            or response["status"] != STATUS
            or type(response["nodeId"]) is not int or response["nodeId"] != node
            or type(response["userId"]) is not int or response["userId"] != user
            or type(response["evidenceMatched"]) is not bool
            or (response["capRosterSha256"] != roster_sha256
                if response["evidenceMatched"] else
                response["capRosterSha256"] is not None)
            or any(response[key] is not False for key in (
                "canServePublic", "canStart", "canResume", "canSpend",
                "liveMeterVerified", "certificateVerified",
                "revocationWatchInstalled"))
            or type(response["authorizedBytes"]) is not int
            or response["authorizedBytes"] != 0
            or response["signedEnvelope"] is not None):
        raise ValueError("public TLS preflight returned a foreign or positive authority")
    return {
        "status": "checked_without_authority",
        "nodeId": node,
        "userId": user,
        "evidenceMatched": response["evidenceMatched"],
        "capRosterSha256": (roster_sha256 if response["evidenceMatched"] else None),
        "canServePublic": False,
        "canStart": False,
        "canResume": False,
        "authorizedBytes": 0,
    }


def _full_signed_roster(fd, original, node, activation, pinned, measured):
    """Derive all grants from root-private files; never trust caller roster IDs."""
    policy = original["reply"]["policy"]
    users = policy["users"]
    if not isinstance(users, list) or not 1 <= len(users) <= 2048:
        raise ValueError("missing bounded original TLS user roster")
    expected = set()
    user_uuids = {}
    for record in users:
        uid = record.get("userId") if isinstance(record, dict) else None
        if (type(uid) is not int or not 0 < uid <= 2**63-1
                or uid in expected or record.get("onHold") is not True
                or type(record.get("offlineBudgetBytes")) is not int
                or record["offlineBudgetBytes"] != 0):
            raise ValueError("malformed, repeated or unquarantined TLS user")
        # A signed quota bound only to email may not silently retarget a
        # different VLESS credential. The original Genesis policy owns the
        # exact client UUID, independently of the signed cap's userId.
        client_uuid = record.get("xrayId")
        if not isinstance(client_uuid, str):
            raise ValueError("signed Genesis user has no VLESS credential identity")
        try:
            canonical_uuid = str(uuid.UUID(client_uuid))
        except (ValueError, AttributeError) as exc:
            raise ValueError("malformed signed Genesis VLESS UUID") from exc
        if canonical_uuid != client_uuid:
            raise ValueError("noncanonical signed Genesis VLESS UUID")
        user_uuids[uid] = client_uuid
        expected.add(uid)
    names = os.listdir(fd)
    # Unrecognized cap-like filenames can be old generations or attempts to
    # smuggle additional signed users via a noncanonical decimal representation.
    # They must not be silently ignored when proving the ENTIRE active roster.
    if any(
        (name.startswith("genesis-positive-cap-u") and not CAP_FILE.fullmatch(name))
        or (name.startswith("genesis-renewal-u"))
        for name in names
    ):
        raise ValueError("a noncanonical or later signed cap requires fresh TLS admission")
    stored = {}
    for name in names:
        match = CAP_FILE.fullmatch(name)
        if match is None:
            continue
        uid = int(match.group(1))
        if uid not in expected or uid in stored:
            raise ValueError("foreign historical signed TLS-cap file")
        envelope = genesis_reservation._identity_file(fd, name, 16384)
        if (not isinstance(envelope, dict)
                or set(envelope) != {"status", "nodeId", "userId", "signedEnvelope"}
                or envelope["status"] != "committed_first_cap"
                or type(envelope["nodeId"]) is not int or envelope["nodeId"] != node
                or type(envelope["userId"]) is not int or envelope["userId"] != uid
                or not isinstance(envelope["signedEnvelope"], str)):
            raise ValueError("foreign or noncanonical root-owned signed TLS cap")
        raw = envelope["signedEnvelope"].encode("utf-8")
        signed = wal_transport.observed.strict_json(raw)
        if (not isinstance(signed, dict)
                or not isinstance(signed.get("payload"), dict)
                or signed["payload"].get("kind") != "xmesh.quota-v2.xray-cap-admission"):
            raise ValueError("first-Genesis TLS roster contains a later cap generation")
        stored[uid] = raw
    if set(stored) != expected:
        raise ValueError("missing initial cap for one or more signed TLS users")
    profile = original["reply"]["config"]
    if (not isinstance(profile, dict) or
            wal_transport.observed.canonical(profile) is None):
        raise ValueError("missing original Genesis measured VLESS profile")
    roster = public_tls_cap_watch.SignedCapRosterWatch(
        profile=profile, signed_grants=stored, pinned=pinned, node=node,
        activation=activation, genesis_sha=original["reply"]["policySha256"],
        runtime_id=measured[3], trusted_pid=measured[2], socket_path=SOCKET)
    # Reconcile the complete signed Genesis userId -> Xray UUID mapping to
    # every real VLESS MAIN/CDN client compiled from that same signed profile.
    # Matching only the signed cap's user ID and email is insufficient: a
    # swapped UUID would route somebody else's credential through this quota.
    for inbound in profile["inbounds"]:
        for client in inbound["settings"]["clients"]:
            match = public_tls_cap_watch.EMAIL.fullmatch(client["email"])
            if (match is None
                    or client["id"] != user_uuids.get(int(match.group(1)))):
                raise ValueError(
                    "signed Genesis user UUID differs from installed VLESS roster")
    return roster


def probe(panel, node, user, state, required_lifetime_ms=30_000):
    if (os.geteuid() != 0 or not isinstance(panel, str)
            or not panel.startswith("https://")
            or type(node) is not int or node <= 0
            or type(user) is not int or user <= 0
            or type(required_lifetime_ms) is not int
            or not 1_000 <= required_lifetime_ms <= MAX_LIFETIME_MS):
        raise ValueError("strict enrolled root Quota V2 TLS probe required")

    started = time.monotonic_ns()
    state_fd, lock = quarantine._locked_private_state(state)
    try:
        pinned = wal_transport._panel_pin()
        before_activation = quarantine._enrolled_activation(panel, node)
        activation = before_activation["activationReceiptSha256"]
        original = genesis_reservation._staged_original(
            state_fd, node, user, pinned, activation)
        pins = genesis_reservation._original_measurement_pins(
            state_fd, original, node, activation)
        measured_before = wal_transport._measure_quarantined_runtime(pins)
        if measured_before[3] != original["prepared"]["payload"]["candidateRuntimeId"]:
            raise ValueError("original signed meter runtime has changed")
        full_roster = _full_signed_roster(
            state_fd, original, node, activation, pinned, measured_before)
        if full_roster.check() is not None:
            raise ValueError("local Xray roster witness tried to grant TLS authority")
        if (full_roster.profile_sha256 != original["reply"]["revision"]
                or user not in full_roster._grants):
            raise ValueError("local installed Xray TLS roster differs from Genesis")

        request = {
            "nodeId": node,
            "userId": user,
            "activationReceiptSha256": activation,
            "genesisPolicySha256": original["reply"]["policySha256"],
            "runtimeId": measured_before[3],
            "profileRevision": original["reply"]["revision"],
            "capRosterSha256": full_roster.roster_sha256,
            "requiredLifetimeMs": required_lifetime_ms,
        }
        raw = quarantine._post_quarantined_desired(
            request, state, quarantine.TLS_PREFLIGHT_PATH)
        result = verify_zero_authority(
            raw, node=node, user=user, roster_sha256=full_roster.roster_sha256)

        if (before_activation != quarantine._enrolled_activation(panel, node)
                or measured_before != wal_transport._measure_quarantined_runtime(pins)
                or full_roster.check() is not None
                or time.monotonic_ns() - started >= MAX_PROBE_NS):
            raise ValueError("strict-PQ activation, live cap roster or Xray changed during TLS probe")
        # No permit, no durable "eligible" state, no traffic, no state write.
        return result
    finally:
        os.close(lock)
        os.close(state_fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel", required=True)
    parser.add_argument("--node-id", type=int, required=True)
    parser.add_argument("--user-id", type=int, required=True)
    parser.add_argument("--state", required=True)
    parser.add_argument("--required-lifetime-ms", type=int, default=30_000)
    options = parser.parse_args()
    try:
        print(json.dumps(probe(
            options.panel, options.node_id, options.user_id, options.state,
            options.required_lifetime_ms,
        ), separators=(",", ":"), sort_keys=True))
    except (OSError, ValueError, TypeError, KeyError, IndexError) as error:
        parser.exit(1, "Quota V2 public TLS evidence probe denied: " + str(error) + "\n")


if __name__ == "__main__":
    main()
