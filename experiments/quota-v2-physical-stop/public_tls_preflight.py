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
import sys

import genesis_reservation
import quarantine_policy as quarantine
import wal_transport

MAX_REPLY = 1536
MAX_LIFETIME_MS = 120_000
STATUS = "candidate_only_not_authorized"
KEYS = frozenset({
    "status", "nodeId", "userId", "evidenceMatched",
    "canServePublic", "canStart", "canResume", "canSpend",
    "authorizedBytes", "signedEnvelope", "liveMeterVerified",
    "certificateVerified", "revocationWatchInstalled",
})


def verify_zero_authority(raw, *, node, user):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_REPLY:
        raise ValueError("public TLS evidence response size invalid")
    response = wal_transport.observed.strict_json(raw)
    if (not isinstance(response, dict) or set(response) != KEYS
            or response["status"] != STATUS
            or type(response["nodeId"]) is not int or response["nodeId"] != node
            or type(response["userId"]) is not int or response["userId"] != user
            or type(response["evidenceMatched"]) is not bool
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
        "canServePublic": False,
        "canStart": False,
        "canResume": False,
        "authorizedBytes": 0,
    }


def probe(panel, node, user, state, required_lifetime_ms=30_000):
    if (os.geteuid() != 0 or not isinstance(panel, str)
            or not panel.startswith("https://")
            or type(node) is not int or node <= 0
            or type(user) is not int or user <= 0
            or type(required_lifetime_ms) is not int
            or not 1_000 <= required_lifetime_ms <= MAX_LIFETIME_MS):
        raise ValueError("strict enrolled root Quota V2 TLS probe required")

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

        request = {
            "nodeId": node,
            "userId": user,
            "activationReceiptSha256": activation,
            "genesisPolicySha256": original["reply"]["policySha256"],
            "runtimeId": measured_before[3],
            "profileRevision": original["reply"]["revision"],
            "requiredLifetimeMs": required_lifetime_ms,
        }
        raw = quarantine._post_quarantined_desired(
            request, state, quarantine.TLS_PREFLIGHT_PATH)
        result = verify_zero_authority(raw, node=node, user=user)

        if (before_activation != quarantine._enrolled_activation(panel, node)
                or measured_before != wal_transport._measure_quarantined_runtime(pins)):
            raise ValueError("strict-PQ activation or metered Xray changed during TLS probe")
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
