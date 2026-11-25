#!/usr/bin/env python3
"""Stop-only signed public TLS lifetime negatives (never open a port)."""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parents[1] / "experiments/quota-v2-physical-stop"
sys.path.insert(0, str(HERE))
import public_tls_frontend as tls
import public_tls_stop_monitor as stop
import quarantine_policy
import wal_transport
from test_quota_v2_public_tls_frontend import profile, bindings


class StopOnlyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xmesh-stop-only-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        secret = self.root / "nexus.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519",
                        "-out", str(secret)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.pinned = subprocess.check_output(
            ["openssl", "pkey", "-in", str(secret),
             "-pubout", "-outform", "DER"])[-32:].hex()
        self.node = 47
        self.activation = "a" * 64
        self.genesis = "b" * 64
        self.runtime = "c" * 64
        self.wall_ns = time.time_ns()
        self.mono_ns = time.monotonic_ns()
        now_ms = self.wall_ns // 1_000_000
        payload = {
            "schemaVersion":1, "kind":"xmesh.quota-v2.public-tls-ingress",
            "nodeId":self.node, "activationReceiptSha256":self.activation,
            "genesisPolicySha256":self.genesis,
            "runtimeId":self.runtime,
            "profileRevision":hashlib.sha256(
                wal_transport.observed.canonical(profile())).hexdigest(),
            "canServePublic":True, "bindings":bindings(),
            "issuedAtMs":now_ms-1000, "validUntilMs":now_ms+60_000,
        }
        guard = quarantine_policy._guard()
        unsigned = self.root / "unsigned.json"
        signature = self.root / "signature.bin"
        unsigned.write_bytes(guard.canonical(payload))
        subprocess.run(["openssl", "pkeyutl", "-sign", "-inkey",
                        str(secret), "-rawin", "-in", str(unsigned),
                        "-out", str(signature)], check=True,
                       stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        self.signed = guard.canonical({
            "algorithm":"Ed25519", "payload":payload,
            "signature":signature.read_bytes().hex(),
        })
        self.child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop_child)
        patch1 = mock.patch.object(stop.time, "time_ns",
                                   side_effect=lambda: self.wall_ns)
        patch2 = mock.patch.object(stop.time, "monotonic_ns",
                                   side_effect=lambda: self.mono_ns)
        patch1.start()
        patch2.start()
        self.addCleanup(patch1.stop)
        self.addCleanup(patch2.stop)
        self.certificate = mock.patch.object(
            stop.public_tls_certificates, "verify_certificate_lineage",
            return_value={"vless-main":"root-owned","vless-cdn":"root-owned"})
        self.certificate.start()
        self.addCleanup(self.certificate.stop)
        self.identity = mock.patch.object(
            stop.wal_transport.runtime_identity, "trusted_runtime_identity",
            return_value=self.runtime)
        self.identity.start()
        self.addCleanup(self.identity.stop)

    def stop_child(self):
        if self.child.poll() is None:
            self.child.kill()
        self.child.wait(timeout=5)

    def monitor(self, **changes):
        params=dict(
            child=self.child, profile=profile(), authority=self.signed,
            node=self.node, activation=self.activation,
            genesis_sha=self.genesis, runtime_id=self.runtime,
            pinned=self.pinned, runtime_pid=1234,
        )
        params.update(changes)
        return stop.StopOnlyTlsMonitor(**params)

    def tick(self, wall_ms=0, monotonic_ms=0):
        self.wall_ns += wall_ms * 1_000_000
        self.mono_ns += monotonic_ms * 1_000_000

    def assert_stopped(self, monitor, **kwargs):
        with self.assertRaises(ValueError):
            monitor.check_stop_only(revoked=False, **kwargs)
        self.assertTrue(monitor.stopped)
        self.assertIsNotNone(self.child.poll())
        with self.assertRaises(ValueError):
            monitor.check_stop_only(revoked=False)

    def test_valid_poll_only_observes_without_granting_or_starting(self):
        monitor = self.monitor()
        self.assertIsNone(monitor.check_stop_only(revoked=False))
        self.tick(wall_ms=500,monotonic_ms=500)
        self.assertIsNone(monitor.check_stop_only(revoked=False))
        self.assertFalse(monitor.stopped)
        self.assertIsNone(self.child.poll())

    def test_signed_expiry_uses_monotonic_even_if_wall_clock_frozen(self):
        monitor = self.monitor()
        self.tick(monotonic_ms=60_100)
        self.assert_stopped(monitor)

    def test_rollback_or_large_clock_jump_kills_owned_child(self):
        monitor = self.monitor()
        self.tick(wall_ms=-1,monotonic_ms=1)
        self.assert_stopped(monitor)

    def test_monitor_missed_deadline_fails_closed_before_authority_expires(self):
        monitor = self.monitor()
        self.tick(wall_ms=10_100,monotonic_ms=10_100)
        self.assert_stopped(monitor)

    def test_revocation_stops_owned_subprocess_and_latches(self):
        monitor = self.monitor()
        with self.assertRaises(ValueError):
            monitor.check_stop_only(revoked=True)
        self.assertTrue(monitor.stopped)
        self.assertIsNotNone(self.child.poll())

    def test_unknown_revocation_state_denied(self):
        monitor = self.monitor()
        with self.assertRaises(ValueError):
            monitor.check_stop_only(revoked=None)
        self.assertIsNotNone(self.child.poll())

    def test_metered_runtime_pid_replacement_denied(self):
        monitor = self.monitor()
        with mock.patch.object(
            stop.wal_transport.runtime_identity, "trusted_runtime_identity",
            return_value="f"*64):
            self.assert_stopped(monitor)

    def test_changed_or_invalid_certificate_denied(self):
        monitor = self.monitor()
        with mock.patch.object(
            stop.public_tls_certificates, "verify_certificate_lineage",
            side_effect=ValueError("bad lineage")):
            self.assert_stopped(monitor)

    def test_replayed_foreign_signature_cannot_initialize_monitor(self):
        for changes in (
            {"runtime_id":"d"*64}, {"activation":"e"*64},
            {"pinned":"f"*64}, {"genesis_sha":"f"*64},
        ):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.monitor(**changes)
        self.assertIsNone(self.child.poll())


if __name__ == "__main__":
    unittest.main()
