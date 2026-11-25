"""Read-only Nexus Ed25519 revocation witness for a dormant TLS stop monitor.

NO installed issuer/endpoint, production listener or positive authorization.
The supplied fetch callback is NOT independently trusted: every reply needs
a fresh random challenge and the pinned Nexus Ed25519 signature, matching
the exact TLS policy AND every currently pinned user grant. A future issuer
must atomically recheck real SQL revocation, account/lease epochs, WAL
finality, active strict-PQ Node identity and the current measured runtime.
A signed 'not revoked' response without those issuer invariants is NOT
permission to publish a public port.
"""
import re
import secrets
import time

import quarantine_policy
import wal_transport

MAX_WIRE_BYTES = 4096
MAX_FETCH_NS = 3_000_000_000
MAX_AGE_MS = 2000
MAX_VALIDITY_MS = 8000
MAX_CLOCK_DIVERGENCE_NS = 2_000_000_000
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX128 = re.compile(r"[0-9a-f]{128}\Z")


class SignedTlsRevocationWatch:
    """No positive grant: checks nonce-bound signatures and hard deadlines."""

    def __init__(self, *, fetch, node, activation, genesis_sha, runtime_id,
                 profile_sha256, authority_sha256, roster_sha256, pinned):
        if (not callable(fetch) or type(node) is not int or node <= 0
                or any(not isinstance(v, str) or HEX64.fullmatch(v) is None
                       for v in (activation, genesis_sha, runtime_id,
                                 profile_sha256, authority_sha256,
                                 roster_sha256, pinned))):
            raise ValueError("invalid enrolled revocation witness binding")
        self._fetch = fetch
        self.node = node
        self.activation = activation
        self.genesis_sha = genesis_sha
        self.runtime_id = runtime_id
        self.profile_sha256 = profile_sha256
        self.authority_sha256 = authority_sha256
        self.roster_sha256 = roster_sha256
        self.pinned = pinned
        self._previous_nonce = None
        self._deadline_ns = None
        self._wall_ms = None
        self._mono_ns = None

    def ensure_fresh(self):
        """Fail when the last *verified* reply expired during another probe."""
        now_ms = time.time_ns() // 1_000_000
        mono_ns = time.monotonic_ns()
        if (self._deadline_ns is None or type(now_ms) is not int
                or self._wall_ms is None or self._mono_ns is None
                or now_ms < self._wall_ms or mono_ns < self._mono_ns
                or mono_ns >= self._deadline_ns
                or abs((now_ms-self._wall_ms)*1_000_000
                       - (mono_ns-self._mono_ns))
                > MAX_CLOCK_DIVERGENCE_NS):
            raise ValueError("Nexus revocation witness expired or clock changed")
        return None

    def check(self):
        """Fetch a NEW signed Nexus witness; never return traffic authority."""
        nonce = secrets.token_hex(32)
        if (not isinstance(nonce, str) or HEX64.fullmatch(nonce) is None
                or nonce == self._previous_nonce):
            raise ValueError("replayed or malformed TLS revocation challenge")
        started_ns = time.monotonic_ns()
        raw = self._fetch(nonce)
        now_mono_ns = time.monotonic_ns()
        now_ms = time.time_ns() // 1_000_000
        if (now_mono_ns < started_ns
                or now_mono_ns-started_ns > MAX_FETCH_NS
                or not isinstance(raw, bytes)
                or not 0 < len(raw) <= MAX_WIRE_BYTES):
            raise ValueError("unavailable or late Nexus revocation witness")
        doc = wal_transport.observed.strict_json(raw)
        if (not isinstance(doc, dict)
                or set(doc) != {"algorithm", "payload", "signature"}
                or doc["algorithm"] != "Ed25519"
                or not isinstance(doc["signature"], str)
                or HEX128.fullmatch(doc["signature"]) is None
                or raw != wal_transport.observed.canonical(doc) + b"\n"):
            raise ValueError("untrusted or noncanonical signed revocation envelope")
        payload = doc["payload"]
        expected = {
            "schemaVersion": 1,
            "kind": "xmesh.quota-v2.public-tls-revocation-witness",
            "nodeId": self.node,
            "activationReceiptSha256": self.activation,
            "genesisPolicySha256": self.genesis_sha,
            "runtimeId": self.runtime_id,
            "profileRevision": self.profile_sha256,
            "authoritySha256": self.authority_sha256,
            "capRosterSha256": self.roster_sha256,
            "challenge": nonce,
            "revoked": False,
            "canServePublic": False,
            "canStart": False,
            "canResume": False,
        }
        if (not isinstance(payload, dict)
                or set(payload) != set(expected) | {"issuedAtMs", "validUntilMs"}
                or any(type(payload.get(key)) is not type(value)
                       or payload[key] != value
                       for key, value in expected.items())
                or type(payload["issuedAtMs"]) is not int
                or type(payload["validUntilMs"]) is not int
                or not 0 < payload["issuedAtMs"] <= now_ms
                or now_ms-payload["issuedAtMs"] > MAX_AGE_MS
                or not now_ms < payload["validUntilMs"]
                or not 0 < payload["validUntilMs"]-payload["issuedAtMs"]
                        <= MAX_VALIDITY_MS):
            raise ValueError("expired, revoked, foreign or authorizing TLS witness")
        quarantine_policy._guard().check_signature(
            payload, doc["signature"], self.pinned)
        # Only after the cryptographic proof may the previous fresh nonce,
        # clock anchor and deadline advance. No authorization is returned.
        self._previous_nonce = nonce
        self._wall_ms = now_ms
        self._mono_ns = now_mono_ns
        self._deadline_ns = (now_mono_ns
                            + (payload["validUntilMs"]-now_ms)*1_000_000)
        return None
