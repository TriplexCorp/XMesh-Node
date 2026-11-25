#!/usr/bin/env python3
"""Stop-only signed public TLS lifetime negatives (never open a port)."""
import hashlib
import os
import signal
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
import public_tls_spawn_preflight as prespawn
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
        self.certificate_mock = self.certificate.start()
        self.addCleanup(self.certificate.stop)
        self.identity = mock.patch.object(
            stop.wal_transport.runtime_identity, "trusted_runtime_identity",
            return_value=self.runtime)
        self.identity_mock = self.identity.start()
        self.addCleanup(self.identity.stop)
        # This file tests lifecycle failure and child termination. The
        # separate real-Ed25519 roster suite tests the actual CapWatch source.
        self.cap_watch = mock.Mock(
            spec=stop.public_tls_cap_watch.SignedCapRosterWatch)
        self.cap_watch.profile_sha256 = hashlib.sha256(
            wal_transport.observed.canonical(profile())).hexdigest()
        self.cap_watch.node = self.node
        self.cap_watch.activation = self.activation
        self.cap_watch.runtime_id = self.runtime
        self.cap_watch.genesis_sha = self.genesis
        self.cap_watch.pinned = self.pinned
        self.cap_watch.check.return_value = None
        self.revocation_watch = mock.Mock(
            spec=stop.public_tls_revocation_watch.SignedTlsRevocationWatch)
        self.revocation_watch.node = self.node
        self.revocation_watch.activation = self.activation
        self.revocation_watch.genesis_sha = self.genesis
        self.revocation_watch.runtime_id = self.runtime
        self.revocation_watch.profile_sha256 = self.cap_watch.profile_sha256
        self.revocation_watch.roster_sha256 = "d" * 64
        self.revocation_watch.authority_sha256 = hashlib.sha256(
            self.signed).hexdigest()
        self.revocation_watch.pinned = self.pinned
        self.cap_watch.roster_sha256 = self.revocation_watch.roster_sha256
        self.revocation_watch.check.return_value = None
        self.revocation_watch.ensure_fresh.return_value = None

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
            cap_watch=self.cap_watch, revocation_watch=self.revocation_watch,
        )
        params.update(changes)
        return stop.StopOnlyTlsMonitor(**params)

    def tick(self, wall_ms=0, monotonic_ms=0):
        self.wall_ns += wall_ms * 1_000_000
        self.mono_ns += monotonic_ms * 1_000_000

    def assert_stopped(self, monitor):
        with self.assertRaises(ValueError):
            monitor.check_stop_only()
        self.assertTrue(monitor.stopped)
        self.assertIsNotNone(self.child.poll())
        with self.assertRaises(ValueError):
            monitor.check_stop_only()

    def test_valid_poll_only_observes_without_granting_or_starting(self):
        monitor = self.monitor()
        self.assertIsNone(monitor.check_stop_only())
        self.tick(wall_ms=500,monotonic_ms=500)
        self.assertIsNone(monitor.check_stop_only())
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
        self.revocation_watch.check.side_effect = ValueError("Nexus signed revoked")
        with self.assertRaises(ValueError):
            monitor.check_stop_only()
        self.assertTrue(monitor.stopped)
        self.assertIsNotNone(self.child.poll())

    def test_unknown_revocation_state_denied(self):
        monitor = self.monitor()
        self.revocation_watch.check.side_effect = OSError("panel unavailable")
        with self.assertRaises(ValueError):
            monitor.check_stop_only()
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

    def respawn_child(self):
        # Every rejected startup must have killed its previous owned child.
        self.assertIsNotNone(self.child.poll())
        self.child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def test_replayed_foreign_signature_kills_owned_child_during_startup(self):
        for index, changes in enumerate((
            {"runtime_id":"d"*64}, {"activation":"e"*64},
            {"pinned":"f"*64}, {"genesis_sha":"f"*64},
        )):
            if index:
                self.respawn_child()
            with self.subTest(changes=changes), self.assertRaisesRegex(
                    ValueError, "initial TLS supervision preflight failed"):
                self.monitor(**changes)
            self.assertIsNotNone(self.child.poll())

    def test_unverified_certificate_kills_child_before_first_poll(self):
        with mock.patch.object(
            stop.public_tls_certificates, "verify_certificate_lineage",
            side_effect=ValueError("wrong SAN or expired certificate")):
            with self.assertRaisesRegex(
                    ValueError, "initial TLS supervision preflight failed"):
                self.monitor()
        self.assertIsNotNone(self.child.poll())

    def test_metered_runtime_mismatch_and_probe_error_kill_child_at_startup(self):
        for index, kwargs in enumerate((
            {"return_value": "f" * 64},
            {"side_effect": OSError("procfs unavailable")},
        )):
            if index:
                self.respawn_child()
            with mock.patch.object(
                stop.wal_transport.runtime_identity, "trusted_runtime_identity",
                **kwargs):
                with self.assertRaisesRegex(
                        ValueError, "initial TLS supervision preflight failed"):
                    self.monitor()
            self.assertIsNotNone(self.child.poll())

    def test_missing_or_foreign_watcher_kills_child_before_first_tick(self):
        for index, changes in enumerate((
            {"cap_watch": None},
            {"cap_watch": mock.Mock()},
            {"profile_sha256": "f" * 64},
            {"node": self.node + 1},
            {"runtime_id": "f" * 64},
            {"genesis_sha": "f" * 64},
            {"pinned": "f" * 64},
        )):
            if index:
                self.respawn_child()
            if "cap_watch" in changes:
                altered = changes["cap_watch"]
            else:
                altered = mock.Mock(
                    spec=stop.public_tls_cap_watch.SignedCapRosterWatch)
                for field in ("profile_sha256", "node", "activation",
                              "runtime_id", "genesis_sha", "pinned"):
                    setattr(altered, field, getattr(self.cap_watch, field))
                setattr(altered, next(iter(changes)), next(iter(changes.values())))
            with self.subTest(changes=changes), self.assertRaisesRegex(
                    ValueError, "initial TLS supervision preflight failed"):
                self.monitor(cap_watch=altered)
            self.assertIsNotNone(self.child.poll())

    def test_cap_witness_missing_during_startup_kills_child(self):
        self.cap_watch.check.side_effect = OSError("metered Unix peer unavailable")
        with self.assertRaisesRegex(
                ValueError, "initial TLS supervision preflight failed"):
            self.monitor()
        self.assertIsNotNone(self.child.poll())

    def test_any_cap_witness_loss_during_poll_kills_owned_child(self):
        monitor = self.monitor()
        self.cap_watch.check.side_effect = ValueError("one CDN cap exhausted")
        self.assert_stopped(monitor)
        self.assertGreaterEqual(self.cap_watch.check.call_count, 2)

    def test_cap_watcher_cannot_return_positive_authority(self):
        self.cap_watch.check.return_value = True
        with self.assertRaisesRegex(
                ValueError, "initial TLS supervision preflight failed"):
            self.monitor()
        self.assertIsNotNone(self.child.poll())

    def test_live_cap_watch_is_checked_at_every_tick(self):
        monitor = self.monitor()
        self.tick(wall_ms=300, monotonic_ms=300)
        self.assertIsNone(monitor.check_stop_only())
        self.tick(wall_ms=300, monotonic_ms=300)
        self.assertIsNone(monitor.check_stop_only())
        self.assertEqual(self.cap_watch.check.call_count, 3)

    def test_cap_probe_crossing_monitor_gap_fails_closed_after_return(self):
        monitor = self.monitor()
        def slow_probe():
            self.tick(wall_ms=10_050, monotonic_ms=10_050)
            return None
        self.cap_watch.check.side_effect = slow_probe
        self.assert_stopped(monitor)

    def test_missing_or_foreign_signed_revocation_watcher_kills_child(self):
        for index, bad in enumerate((
            {"revocation_watch": None},
            {"revocation_watch": mock.Mock()},
            {"node": self.node + 1},
            {"activation": "f" * 64},
            {"genesis_sha": "f" * 64},
            {"runtime_id": "f" * 64},
            {"profile_sha256": "f" * 64},
            {"authority_sha256": "f" * 64},
            {"roster_sha256": "f" * 64},
            {"pinned": "f" * 64},
        )):
            if index:
                self.respawn_child()
            if "revocation_watch" in bad:
                watcher = bad["revocation_watch"]
            else:
                watcher = mock.Mock(
                    spec=stop.public_tls_revocation_watch.SignedTlsRevocationWatch)
                for key in ("node", "activation", "genesis_sha",
                            "runtime_id", "profile_sha256", "authority_sha256",
                            "roster_sha256", "pinned"):
                    setattr(watcher, key, getattr(self.revocation_watch, key))
                setattr(watcher, next(iter(bad)), next(iter(bad.values())))
            with self.subTest(change=bad), self.assertRaisesRegex(
                    ValueError, "initial TLS supervision preflight failed"):
                self.monitor(revocation_watch=watcher)
            self.assertIsNotNone(self.child.poll())

    def test_revocation_fetch_fails_at_initial_supervision(self):
        self.revocation_watch.check.side_effect = OSError("Nexus offline")
        with self.assertRaisesRegex(
                ValueError, "initial TLS supervision preflight failed"):
            self.monitor()
        self.assertIsNotNone(self.child.poll())

    def test_revocation_witness_expires_during_cap_probe(self):
        monitor = self.monitor()
        self.revocation_watch.ensure_fresh.side_effect = ValueError("expired")
        self.assert_stopped(monitor)

    def test_revocation_witness_cannot_return_positive_authorization(self):
        self.revocation_watch.check.return_value = True
        with self.assertRaisesRegex(
                ValueError, "initial TLS supervision preflight failed"):
            self.monitor()
        self.assertIsNotNone(self.child.poll())

    def test_revocation_fetch_required_on_every_tick(self):
        monitor = self.monitor()
        for _ in range(2):
            self.tick(wall_ms=300, monotonic_ms=300)
            self.assertIsNone(monitor.check_stop_only())
        self.assertEqual(self.revocation_watch.check.call_count, 3)
        self.assertEqual(self.revocation_watch.ensure_fresh.call_count, 6)

    def test_independent_guardian_is_armed_only_after_signed_checks(self):
        monitor = self.monitor()
        self.assertIsNone(self.child.poll())
        self.assertIsNone(monitor._deadman._guardian.poll())
        self.assertIsNotNone(monitor._deadman._guardian.pid)
        self.assertNotEqual(monitor._deadman._guardian.pid, self.child.pid)
        self.tick(wall_ms=100, monotonic_ms=100)
        self.assertIsNone(monitor.check_stop_only())

    def test_killed_independent_guardian_stops_owned_child_fail_closed(self):
        monitor = self.monitor()
        os.kill(monitor._deadman._guardian.pid, signal.SIGKILL)
        monitor._deadman._guardian.wait(timeout=3)
        self.assert_stopped(monitor)

    def test_invalid_initial_pid_and_expired_policy_kill_child(self):
        with self.assertRaisesRegex(
                ValueError, "initial TLS supervision preflight failed"):
            self.monitor(runtime_pid=0)
        self.assertIsNotNone(self.child.poll())
        self.respawn_child()
        self.tick(wall_ms=60_001, monotonic_ms=60_001)
        with self.assertRaisesRegex(
                ValueError, "initial TLS supervision preflight failed"):
            self.monitor()
        self.assertIsNotNone(self.child.poll())

    def test_signed_authority_expiring_during_initial_probe_kills_child(self):
        def exhaust_policy():
            self.tick(wall_ms=60_001, monotonic_ms=60_001)
            return None
        self.cap_watch.check.side_effect = exhaust_policy
        with self.assertRaisesRegex(
                ValueError, "initial TLS supervision preflight failed"):
            self.monitor()
        self.assertIsNotNone(self.child.poll())
        self.revocation_watch.check.assert_called_once_with()
        self.revocation_watch.ensure_fresh.assert_called_once_with()

    def test_startup_probe_over_deadman_gap_must_not_send_heartbeat(self):
        def slow_probe():
            self.tick(wall_ms=10_050, monotonic_ms=10_050)
            return None
        self.cap_watch.check.side_effect = slow_probe
        with self.assertRaisesRegex(
                ValueError, "initial TLS supervision preflight failed"):
            self.monitor()
        self.assertIsNotNone(self.child.poll())

    def test_clock_rollback_during_initial_revocation_probe_kills_child(self):
        def rewind_wall():
            self.tick(wall_ms=-1, monotonic_ms=1)
            return None
        self.revocation_watch.check.side_effect = rewind_wall
        with self.assertRaisesRegex(
                ValueError, "initial TLS supervision preflight failed"):
            self.monitor()
        self.assertIsNotNone(self.child.poll())

    def test_initial_preflight_anchor_moves_to_verified_end_of_probes(self):
        def probe():
            self.tick(wall_ms=2500, monotonic_ms=2500)
            return None
        self.cap_watch.check.side_effect = probe
        monitor = self.monitor()
        self.assertFalse(monitor.stopped)
        self.assertEqual(monitor._wall_ms, self.wall_ns // 1_000_000)
        self.assertEqual(monitor._mono_ns, self.mono_ns)
        self.assertIsNone(monitor.check_stop_only())
        self.assertIsNone(self.child.poll())

    def pre_spawn_check(self, **changes):
        params = dict(
            profile=profile(), authority=self.signed,
            node=self.node, activation=self.activation,
            genesis_sha=self.genesis, runtime_id=self.runtime,
            pinned=self.pinned, runtime_pid=1234,
            cap_watch=self.cap_watch, revocation_watch=self.revocation_watch,
        )
        params.update(changes)
        return prespawn.check_before_spawn(**params)

    def test_pre_spawn_checks_all_live_proofs_without_starting_or_authorizing(self):
        self.assertIsNone(self.pre_spawn_check())
        self.assertIsNone(self.child.poll())
        self.assertEqual(self.identity_mock.call_count, 2)
        self.identity_mock.assert_has_calls([mock.call(1234), mock.call(1234)])
        self.certificate_mock.assert_called_once()
        self.cap_watch.check.assert_called_once_with()
        self.revocation_watch.check.assert_called_once_with()
        self.revocation_watch.ensure_fresh.assert_called_once_with()

    def test_pre_spawn_rejects_missing_or_foreign_signed_roster(self):
        for bad in (
            {"runtime_pid": 0},
            {"genesis_sha": "f" * 64},
            {"activation": "f" * 64},
            {"pinned": "f" * 64},
            {"cap_watch": None},
            {"revocation_watch": None},
            {"authority": self.signed.replace(b"Ed25519", b"Ed25719")},
        ):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.pre_spawn_check(**bad)
        self.assertIsNone(self.child.poll())

    def test_pre_spawn_never_turns_witness_return_values_into_permission(self):
        self.cap_watch.check.return_value = True
        with self.assertRaisesRegex(ValueError, "cap watcher cannot issue"):
            self.pre_spawn_check()
        self.cap_watch.check.return_value = None
        self.revocation_watch.check.return_value = True
        with self.assertRaisesRegex(ValueError, "revocation watcher cannot issue"):
            self.pre_spawn_check()
        self.revocation_watch.check.return_value = None
        self.revocation_watch.ensure_fresh.return_value = True
        with self.assertRaisesRegex(ValueError, "revocation witness"):
            self.pre_spawn_check()
        self.assertIsNone(self.child.poll())

    def test_pre_spawn_expiry_during_cap_probe_denied(self):
        def delayed_cap():
            self.tick(wall_ms=60_001, monotonic_ms=60_001)
            return None
        self.cap_watch.check.side_effect = delayed_cap
        with self.assertRaisesRegex(ValueError, "pre-spawn proofs expired"):
            self.pre_spawn_check()

    def test_pre_spawn_stalled_probe_and_clock_rollback_denied(self):
        def stalled_cap():
            self.tick(wall_ms=8001, monotonic_ms=8001)
            return None
        self.cap_watch.check.side_effect = stalled_cap
        with self.assertRaisesRegex(ValueError, "pre-spawn proofs expired"):
            self.pre_spawn_check()
        self.cap_watch.check.side_effect = None
        self.wall_ns, self.mono_ns = time.time_ns(), time.monotonic_ns()
        def rollback():
            self.tick(wall_ms=-5, monotonic_ms=5)
            return None
        self.revocation_watch.check.side_effect = rollback
        with self.assertRaisesRegex(ValueError, "pre-spawn proofs expired"):
            self.pre_spawn_check()

    def test_pre_spawn_rechecks_meter_after_slow_witnesses(self):
        self.identity_mock.side_effect = [self.runtime, "f" * 64]
        with self.assertRaisesRegex(ValueError, "changed during TLS pre-spawn"):
            self.pre_spawn_check()
        self.assertEqual(self.identity_mock.call_count, 2)
        self.assertIsNone(self.child.poll())

    def test_startup_rechecks_meter_after_signed_revocation(self):
        # Signed checks can succeed just as the metered PID is replaced.
        self.identity_mock.side_effect = [self.runtime, "f" * 64]
        with self.assertRaisesRegex(
                ValueError, "initial TLS supervision preflight failed"):
            self.monitor()
        self.assertEqual(self.identity_mock.call_count, 2)
        self.assertIsNotNone(self.child.poll())

    def test_poll_rechecks_meter_after_cap_and_revocation(self):
        monitor = self.monitor()
        self.identity_mock.side_effect = [self.runtime, "f" * 64]
        self.assert_stopped(monitor)
        self.assertEqual(self.identity_mock.call_count, 4)

    def test_slow_final_runtime_probe_cannot_refresh_expired_deadman(self):
        monitor = self.monitor()
        calls = 0
        def runtime_after_delay(_pid):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.tick(wall_ms=10_050, monotonic_ms=10_050)
            return self.runtime
        self.identity_mock.side_effect = runtime_after_delay
        self.assert_stopped(monitor)
        self.assertEqual(calls, 2)

    def test_startup_ack_crossing_signed_expiry_kills_child(self):
        def slow_ack():
            self.tick(wall_ms=60_001, monotonic_ms=60_001)
            return None
        with mock.patch.object(
                stop.public_tls_deadman.StopOnlyDeadman, "pulse",
                side_effect=slow_ack):
            with self.assertRaisesRegex(
                    ValueError, "initial TLS supervision preflight failed"):
                self.monitor()
        self.assertIsNotNone(self.child.poll())

    def test_periodic_ack_crossing_watchdog_gap_stops_child(self):
        monitor = self.monitor()
        def slow_ack():
            self.tick(wall_ms=10_050, monotonic_ms=10_050)
            return None
        with mock.patch.object(monitor._deadman, "pulse", side_effect=slow_ack):
            self.assert_stopped(monitor)

    def test_periodic_ack_must_not_outlive_signed_revocation_witness(self):
        monitor = self.monitor()
        self.revocation_watch.ensure_fresh.side_effect = [
            None, ValueError("Nexus witness expired during ACK")]
        self.assert_stopped(monitor)

    def test_post_ack_verified_clock_becomes_next_monitor_anchor(self):
        monitor = self.monitor()
        def bounded_ack():
            self.tick(wall_ms=100, monotonic_ms=100)
            return None
        with mock.patch.object(monitor._deadman, "pulse",
                               side_effect=bounded_ack):
            self.assertIsNone(monitor.check_stop_only())
        self.assertEqual(monitor._wall_ms, self.wall_ns // 1_000_000)
        self.assertEqual(monitor._mono_ns, self.mono_ns)
        self.assertFalse(monitor.stopped)
        self.assertIsNone(self.child.poll())

    def test_good_startup_checks_certificate_and_meter_before_first_poll(self):
        monitor = self.monitor()
        self.assertFalse(monitor.stopped)
        self.assertIsNone(self.child.poll())
        self.assertEqual(self.identity_mock.call_count, 2)
        self.assertEqual(self.certificate_mock.call_count, 1)
        self.cap_watch.check.assert_called_once_with()
        self.revocation_watch.check.assert_called_once_with()
        self.assertEqual(self.revocation_watch.ensure_fresh.call_count, 2)


if __name__ == "__main__":
    unittest.main()
