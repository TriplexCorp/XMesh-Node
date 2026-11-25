#!/usr/bin/env python3
"""Real OpenSSL Ed25519 signed revocation witnesses, NO listener or issuer."""
import copy
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments/quota-v2-physical-stop"))
import public_tls_revocation_watch as watch
import quarantine_policy

class SignedRevocationWitnessTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xmesh-tls-revoke-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.private = self.root / "signer.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "Ed25519",
             "-out", str(self.private)], check=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.pub = subprocess.check_output(
            ["openssl", "pkey", "-in", str(self.private),
             "-pubout", "-outform", "DER"])[-32:].hex()
        self.args = dict(node=47, activation="a" * 64,
                         genesis_sha="b" * 64, runtime_id="c" * 64,
                         profile_sha256="d" * 64, authority_sha256="e" * 64,
                         roster_sha256="f" * 64, pinned=self.pub)
        self.seen = []
        self.change = {}
        self.guard = quarantine_policy._guard()

    def payload(self, nonce):
        now = time.time_ns() // 1_000_000
        return {
            "schemaVersion": 1,
            "kind": "xmesh.quota-v2.public-tls-revocation-witness",
            "nodeId": 47, "activationReceiptSha256": "a" * 64,
            "genesisPolicySha256": "b" * 64,
            "runtimeId": "c" * 64, "profileRevision": "d" * 64,
            "authoritySha256": "e" * 64, "capRosterSha256": "f" * 64,
            "challenge": nonce, "issuedAtMs": now,
            "validUntilMs": now + 4000,
            "revoked": False, "canServePublic": False,
            "canStart": False, "canResume": False,
        }

    def signed(self, payload):
        canonical = self.root / "unsigned.json"
        signature = self.root / "signature.bin"
        canonical.write_bytes(self.guard.canonical(payload))
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-inkey",
             str(self.private), "-rawin", "-in", str(canonical),
             "-out", str(signature)],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        return self.guard.canonical({
            "algorithm": "Ed25519", "payload": payload,
            "signature": signature.read_bytes().hex(),
        }) + b"\n"

    def fetch(self, nonce):
        self.seen.append(nonce)
        return self.signed(dict(self.payload(nonce), **self.change))

    def observer(self, **changes):
        args = dict(self.args, fetch=self.fetch)
        args.update(changes)
        return watch.SignedTlsRevocationWatch(**args)

    def test_two_independent_fresh_signed_witnesses_have_no_authority(self):
        w = self.observer()
        self.assertIsNone(w.check())
        self.assertIsNone(w.ensure_fresh())
        self.assertIsNone(w.check())
        self.assertIsNone(w.ensure_fresh())
        self.assertEqual(len(self.seen), 2)
        self.assertNotEqual(self.seen[0], self.seen[1])
        self.assertTrue(all(len(n) == 64 for n in self.seen))

    def test_fail_closed_on_signed_revoked_foreign_or_authorizing_witness(self):
        variants = (
            {"revoked": True},
            {"canServePublic": True}, {"canStart": True},
            {"canResume": True},
            {"nodeId": 48},
            {"runtimeId": "0" * 64},
            {"genesisPolicySha256": "0" * 64},
            {"activationReceiptSha256": "0" * 64},
            {"profileRevision": "0" * 64},
            {"authoritySha256": "0" * 64},
            {"capRosterSha256": "0" * 64},
            {"schemaVersion": True},
            {"extra": False},
        )
        for variant in variants:
            with self.subTest(variant=variant):
                self.change = variant
                with self.assertRaises(ValueError):
                    self.observer().check()
        self.change = {}

    def test_issuer_must_prove_fresh_timestamp_and_bounded_lifetime(self):
        now = time.time_ns() // 1_000_000
        variants = (
            {"issuedAtMs": now - 2500},
            {"issuedAtMs": now + 1000},
            {"validUntilMs": now - 1},
            {"validUntilMs": now + 15_000},
            {"validUntilMs": True},
        )
        for variant in variants:
            with self.subTest(variant=variant):
                self.change = variant
                with self.assertRaises(ValueError):
                    self.observer().check()
        self.change = {}

    def test_signature_tampering_unknown_key_and_noncanonical_bytes_denied(self):
        good = self.signed(self.payload("1" * 64))
        raw = good.replace(b'"revoked":false', b'"revoked":true')
        with self.assertRaises(ValueError):
            self.observer(fetch=lambda nonce: raw).check()
        with self.assertRaises(ValueError):
            self.observer(pinned="0" * 64).check()
        with self.assertRaises(ValueError):
            self.observer(fetch=lambda nonce: b" " + good).check()
        with self.assertRaises(ValueError):
            self.observer(fetch=lambda nonce: b"x" * 5000).check()
        with self.assertRaises(ValueError):
            self.observer(fetch=lambda nonce: {"signedEnvelope": good}).check()

    def test_replay_of_old_signed_challenge_denied_on_second_poll(self):
        captured = []
        def replay(nonce):
            if not captured:
                captured.append(self.signed(self.payload(nonce)))
            return captured[0]
        w = self.observer(fetch=replay)
        self.assertIsNone(w.check())
        with self.assertRaises(ValueError):
            w.check()

    def test_missing_response_and_repeated_nonce_denied(self):
        for reply in (None, b"", b"{}", "not bytes"):
            with self.subTest(reply=reply), self.assertRaises(ValueError):
                self.observer(fetch=lambda n: reply).check()
        w = self.observer()
        with mock.patch.object(watch.secrets, "token_hex",
                               return_value="1" * 64):
            self.assertIsNone(w.check())
            with self.assertRaises(ValueError):
                w.check()

    def test_failed_probe_cannot_refresh_last_verified_witness(self):
        w = self.observer()
        with self.assertRaises(ValueError):
            w.ensure_fresh()
        self.assertIsNone(w.check())
        old_nonce = w._previous_nonce
        w._fetch = lambda n: b"{}"
        with self.assertRaises(ValueError):
            w.check()
        self.assertEqual(w._previous_nonce, old_nonce)

    def test_late_response_or_clock_jump_rejected(self):
        w = self.observer(fetch=lambda n: b"{}")
        with mock.patch.object(watch.time, "monotonic_ns",
                               side_effect=[1, 3_000_000_002]):
            with self.assertRaises(ValueError):
                w.check()
        w = self.observer()
        self.assertIsNone(w.check())
        # Simulates clock rollback after a correct signature was verified.
        with mock.patch.object(watch.time, "time_ns",
                               return_value=(w._wall_ms-1)*1_000_000):
            with self.assertRaises(ValueError):
                w.ensure_fresh()
        # Simulate a cap probe holding the watcher until its own monotonic TTL.
        with mock.patch.object(watch.time, "monotonic_ns",
                               return_value=w._deadline_ns):
            with self.assertRaises(ValueError):
                w.ensure_fresh()


if __name__ == "__main__":
    unittest.main()
