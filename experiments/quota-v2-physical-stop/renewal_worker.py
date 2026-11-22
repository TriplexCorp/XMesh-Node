#!/usr/bin/env python3
"""Opt-in, fail-closed Agent renewal poll for an ALREADY installed Genesis cap.

This staging worker cannot enroll, create the first lease, start Xray or
unlock public ingress. All authority comes from signed Nexus XSP/2 replies.
Persistent per-revision challenges ensure lost responses retry the exact SQL
transaction instead of silently creating a second issuance.
"""
import argparse
import os
import re
import secrets
import tempfile
import time

import first_cap_handoff as caps
import genesis_reservation as lease
import quarantine_policy as quarantine
import wal_transport

STAGING_ENV = "XMESH_QUOTA_V2_AUTO_RENEW_STAGING"
STATE = "/var/lib/xmesh-xray-sync"
SOCKET = "/var/lib/xmesh-measured-lab/wal/drain.sock"
BASE = re.compile(r"genesis-positive-cap-u([1-9][0-9]{0,18})\\.json\\Z")
RENEW = re.compile(r"genesis-renewal-u([1-9][0-9]{0,18})-r([1-9][0-9]{0,18})\\.json\\Z")
MAX_USERS = 2048
MAX_PER_POLL = 16
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


def _candidate(fd, names, node, user, pinned, now):
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
        # Rotate the bounded work queue so an ineligible early user cannot
        # indefinitely starve another user of a needed renewal.
        start = (instant // 20000) % len(selected)
        selected = (selected[start:] + selected[:start])[:MAX_PER_POLL]
        return [item for user in selected
                if (item := _candidate(fd, names, node, user, pinned, instant)) is not None]
    finally:
        os.close(lock)
        os.close(fd)


def run(panel, node, state=STATE, socket_path=SOCKET):
    if (os.geteuid() != 0 or os.environ.get(STAGING_ENV) != "1"
            or os.environ.get("XMESH_QUOTA_V2_INSTALLED_CAP_DELIVERY") != "1"
            or not isinstance(panel, str) or not panel.startswith("https://")
            or type(node) is not int or node <= 0):
        raise ValueError("automatic renewal is permitted only in explicit root staging")
    # Without durable WAL submission the server refuses a new grant. Do not
    # bypass the signed WAL charge floor or pretend local counters are final.
    wal_transport.run("sync", panel, node)
    pinned = wal_transport._panel_pin()
    jobs = pending_renewals(state, node, pinned)
    if not jobs:
        return 0
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
    installed = 0
    for user, revision, challenge in jobs:
        try:
            caps.fetch_and_install_renewal(
                panel, node, user, state, socket_path,
                executable, challenge, revision)
        except (ValueError, OSError) as exc:
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
    except (ValueError, OSError, KeyError, TypeError) as error:
        parser.exit(1, f"Quota V2 automatic renewal refused: {error}\n")
