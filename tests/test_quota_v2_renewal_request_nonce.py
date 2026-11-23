#!/usr/bin/env python3
"""Durable idempotency for Agent renewals after a lost SQL COMMIT response."""
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments/quota-v2-physical-stop"))
import first_cap_handoff as cap
import genesis_reservation as lease
import quarantine_policy as quarantine
import renewal_worker
import calendar_fence
import vless_ingress


class DurableRenewalNonce(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("root-owned fsynced intent requires privileged test runner")
        self.temp = tempfile.TemporaryDirectory(prefix="xmesh-quota-renew-nonce-")
        self.addCleanup(self.temp.cleanup)
        self.state = self.temp.name
        os.chmod(self.state, 0o700)

    def locked(self):
        return quarantine._locked_private_state(self.state)

    def test_recover_only_missing_live_signed_original_ingress(self):
        user, node = 123, 7
        now = time.time_ns() // 1_000_000
        runtime = "a" * 64
        activation = "f" * 64
        config_pin = "c" * 64
        grant = {
            "kind": "xmesh.quota-v2.xray-cap-admission",
            "nodeId": node, "userId": user,
            "runtimeId": runtime,
            "activationReceiptSha256": activation,
            "policySha256": "b" * 64,
            "reservationId": "11111111-1111-4111-8111-111111111111",
            "nonce": "d" * 64, "issuedAtMs": now - 1000,
            "validUntilMs": now + 60000,
        }
        original = {"prepared": {"payload": {
            "candidateRuntimeId": runtime,
        }}, "reply": {"revision": config_pin}}
        measured = ("e" * 64, "2026-11-22T00:00:00Z", os.getpid(), runtime)
        Path(self.state, f"genesis-positive-cap-u{user}.json").touch()
        env = {"XMESH_QUOTA_V2_INGRESS_STAGING": "1"}
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(renewal_worker, "latest_signed_cap", return_value=grant), \
                mock.patch.object(renewal_worker.wal_transport, "_panel_pin", return_value="f"*64), \
                mock.patch.object(renewal_worker.quarantine, "_enrolled_activation",
                                  return_value={"activationReceiptSha256": activation}), \
                mock.patch.object(renewal_worker.lease, "_identity_file", return_value=original), \
                mock.patch.object(renewal_worker.calendar_fence if hasattr(
                    renewal_worker, "calendar_fence") else calendar_fence,
                    "_original_signed_scope", return_value=config_pin), \
                mock.patch.object(renewal_worker.lease, "_original_measurement_pins",
                                  return_value=("e"*64, config_pin)), \
                mock.patch.object(renewal_worker.wal_transport,
                                  "_measure_quarantined_runtime", return_value=measured), \
                mock.patch.object(vless_ingress, "publish") as publish:
            fd, lock = self.locked()
            try:
                item = renewal_worker._candidate(
                    fd, os.listdir(fd), node, user, "f"*64, now)
                self.assertEqual(item, (user, -3, grant["nonce"]))
            finally:
                os.close(lock)
                os.close(fd)
            self.assertTrue(renewal_worker._restore_initial_ingress(
                "https://staging.example.invalid", node, user, self.state))
            publish.assert_called_once()
            self.assertEqual(publish.call_args.args[1:3],
                             (grant, measured))
            link = Path(self.state, f"ingress-u{user}")
            link.symlink_to(vless_ingress.target(measured[2], measured[3]))
            self.assertFalse(renewal_worker._restore_initial_ingress(
                "https://staging.example.invalid", node, user, self.state))
            publish.assert_called_once()
            link.unlink()
            link.symlink_to(vless_ingress.target(measured[2], "b"*64))
            with self.assertRaisesRegex(ValueError, "foreign ingress"):
                renewal_worker._restore_initial_ingress(
                    "https://staging.example.invalid", node, user, self.state)
            link.unlink()
            Path(self.state, calendar_fence._fence_name(
                user, grant["reservationId"])).touch()
            self.assertFalse(renewal_worker._restore_initial_ingress(
                "https://staging.example.invalid", node, user, self.state))
            publish.assert_called_once()
            Path(self.state, calendar_fence._fence_name(
                user, grant["reservationId"])).unlink()
            grant["validUntilMs"] = now - 1
            self.assertFalse(renewal_worker._restore_initial_ingress(
                "https://staging.example.invalid", node, user, self.state))
            publish.assert_called_once()

    def test_successor_auto_discovery_does_not_reuse_prior_user_socket(self):
        # Two successor jobs in one tick must independently inspect the
        # successor runtime. Never carry a socket discovered for user 101
        # into user 102 merely because the previous job succeeded.
        import charge_worker
        from successor_meter import SUCCESSOR
        jobs = [(101, -1, "a" * 64), (102, -1, "b" * 64)]
        intent = {"nodeId": 7, "executableSha256": "a" * 64,
                  "configSha256": "b" * 64}
        observed = []

        def bound_journal(container_name):
            self.assertEqual(container_name, SUCCESSOR)
            index = len(observed)
            return ({"Mounts": [{"Destination":
                     renewal_worker.wal_transport.journal.RUNTIME_DEST}]},
                    f"/private/successor-{index}/ledger")

        def observe(node, user, state, socket, executable, config):
            observed.append((user, socket, executable, config))

        env = {"XMESH_QUOTA_V2_AUTO_RENEW_STAGING": "1",
               "XMESH_QUOTA_V2_INSTALLED_CAP_DELIVERY": "1",
               "XMESH_QUOTA_V2_AUTO_SUCCESSOR_POSITIVE": "0",
               "XMESH_QUOTA_V2_FRESH_METER_STAGING": "1",
               "XMESH_QUOTA_V2_INGRESS_STAGING": "1"}
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(charge_worker, "run"), \
                mock.patch.object(renewal_worker, "activate_initial_cap", return_value=0), \
                mock.patch.object(vless_ingress, "_staging_permitted", return_value=True), \
                mock.patch.object(renewal_worker, "pending_renewals", return_value=jobs), \
                mock.patch.object(renewal_worker.wal_transport, "_panel_pin", return_value="a"*64), \
                mock.patch.object(renewal_worker.lease, "_identity_file", return_value=intent), \
                mock.patch.object(renewal_worker.wal_transport, "_bound_journal",
                                  side_effect=bound_journal) as bound, \
                mock.patch("successor_meter.observe_successor_meter",
                           side_effect=observe):
            # Staging observation does not count as a newly installed cap.
            self.assertEqual(renewal_worker.run(
                "https://staging.example.invalid", 7, self.state), 0)
        self.assertEqual(bound.call_count, 2)
        self.assertEqual([row[:2] for row in observed], [
            (101, "/private/successor-0/drain.sock"),
            (102, "/private/successor-1/drain.sock")])

    def test_missing_staging_marker_pauses_new_caps_but_preserves_wal_accounting(self):
        # A revoked or absent root-only staging marker must stop all new
        # positive permits. Already-committed WAL debit must still reach
        # Nexus, even when the operator has suspended new admissions.
        import charge_worker
        env = {
            "XMESH_QUOTA_V2_AUTO_RENEW_STAGING": "1",
            "XMESH_QUOTA_V2_INSTALLED_CAP_DELIVERY": "1",
            "XMESH_QUOTA_V2_INGRESS_STAGING": "1",
            "XMESH_QUOTA_V2_AUTO_SUCCESSOR_POSITIVE": "0",
        }
        for managed in ("0", "1"):
            with self.subTest(managed=managed), \
                    mock.patch.dict(os.environ, dict(
                        env, XMESH_QUOTA_V2_MANAGED_GENERATIONS_STAGING=managed)), \
                    mock.patch.object(vless_ingress, "_staging_permitted",
                                      return_value=False), \
                    mock.patch.object(charge_worker, "run") as charge, \
                    mock.patch.object(renewal_worker, "activate_initial_cap") as activate, \
                    mock.patch.object(renewal_worker, "pending_renewals") as renew, \
                    mock.patch.object(renewal_worker, "_poll_generations") as rotate:
                self.assertEqual(renewal_worker.run(
                    "https://staging.example.invalid", 7, self.state), 0)
                charge.assert_called_once()
                activate.assert_not_called()
                renew.assert_not_called()
                rotate.assert_not_called()

    def test_managed_wal_failure_blocks_initial_caps_even_with_valid_staging(self):
        # A root-owned marker is not sufficient when WAL debit integrity
        # is unknown. Preserve old charges; never mint a fresh positive cap.
        import charge_worker
        env = {
            "XMESH_QUOTA_V2_AUTO_RENEW_STAGING": "1",
            "XMESH_QUOTA_V2_INSTALLED_CAP_DELIVERY": "1",
            "XMESH_QUOTA_V2_INGRESS_STAGING": "1",
            "XMESH_QUOTA_V2_MANAGED_GENERATIONS_STAGING": "1",
        }
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(vless_ingress, "_staging_permitted",
                                  return_value=True) as marker, \
                mock.patch.object(charge_worker, "run",
                                  side_effect=ValueError("unverified WAL")) as charge, \
                mock.patch.object(renewal_worker, "activate_initial_cap") as activate, \
                mock.patch.object(renewal_worker, "_poll_generations") as rotate:
            self.assertEqual(renewal_worker.run(
                "https://staging.example.invalid", 7, self.state), 0)
            charge.assert_called_once()
            marker.assert_not_called()
            activate.assert_not_called()
            rotate.assert_not_called()

    def test_commit_retry_reuses_exact_nonce_and_refuses_competing_nonce(self):
        fd, lock = self.locked()
        try:
            before = "a" * 64
            name = cap._persist_renewal_request(fd, 7, 123, 4, before)
            self.assertEqual(name, "genesis-renewal-request-u123-r4.json")
            self.assertEqual(cap._persist_renewal_request(fd, 7, 123, 4, before), name)
            intent = lease._identity_file(fd, name, 4096)
            self.assertEqual(intent["requestChallenge"], before)
            with self.assertRaisesRegex(ValueError, "fsynced request nonce"):
                cap._persist_renewal_request(fd, 7, 123, 4, "b" * 64)
            self.assertEqual(lease._identity_file(fd, name, 4096), intent)
            next_name = cap._persist_renewal_request(fd, 7, 123, 5, "c" * 64)
            self.assertNotEqual(next_name, name)
        finally:
            os.close(lock)
            os.close(fd)

    def test_wrong_owner_invalid_nonce_or_symlink_refused(self):
        fd, lock = self.locked()
        try:
            for node, user, rev, nonce in (
                (0, 123, 3, "a" * 64),
                (7, 0, 3, "a" * 64),
                (7, 123, 0, "a" * 64),
                (7, 123, 3, "z" * 64),
                (7, 123, 3, "a" * 63),
            ):
                with self.assertRaises(ValueError):
                    cap._persist_renewal_request(fd, node, user, rev, nonce)
            name = "genesis-renewal-request-u123-r4.json"
            os.symlink("nowhere", Path(self.state) / name)
            with self.assertRaises((ValueError, OSError)):
                cap._persist_renewal_request(fd, 7, 123, 4, "a" * 64)
        finally:
            os.close(lock)
            os.close(fd)

    def test_worker_file_discovery_never_matches_trailing_junk(self):
        self.assertIsNotNone(renewal_worker.BASE.fullmatch("genesis-positive-cap-u42.json"))
        self.assertIsNotNone(renewal_worker.RENEW.fullmatch("genesis-renewal-u42-r5.json"))
        for name in ("genesis-positive-cap-u42Xjson", "genesis-positive-cap-u42.json.tmp",
                     "genesis-renewal-u42-r5.json.bad", "genesis-renewal-u42-r5Xjson"):
            self.assertIsNone(renewal_worker.BASE.fullmatch(name))
            self.assertIsNone(renewal_worker.RENEW.fullmatch(name))


    def test_renewal_poll_advances_by_full_batch_and_persists_across_restarts(self):
        # A 20s systemd tick must not shift the 16-user window by ONE
        # position, which makes 116 users take ~34 minutes to be visited.
        for user in range(1, 117):
            (Path(self.state) / f"genesis-positive-cap-u{user}.json").touch()
        visited = []
        with mock.patch.object(
                renewal_worker, "_candidate",
                side_effect=lambda fd, names, node, user, pinned, now:
                    (user, 1, "a" * 64)):
            for tick in range(8):
                # Simulate arbitrarily slow/jittery service restarts: the
                # durable cursor, NOT floor(now/20s), controls fairness.
                jobs = renewal_worker.pending_renewals(
                    self.state, 7, "b" * 64, now=1_000_000 + tick * 97_000)
                self.assertLessEqual(len(jobs), renewal_worker.MAX_PER_POLL)
                visited.extend(user for user, _, _ in jobs)
            self.assertEqual(visited[:16], list(range(1, 17)))
            self.assertEqual(sorted(set(visited)), list(range(1, 117)))
            self.assertEqual(len(visited), 128)
            # A recreated worker starts after the LAST visited user.
            follow_up = renewal_worker.pending_renewals(
                self.state, 7, "b" * 64, now=50_000_000)
            self.assertEqual([u for u, _, _ in follow_up],
                             list(range(13, 29)))
        fd, lock = self.locked()
        try:
            cursor = lease._identity_file(fd, renewal_worker.CURSOR_FILE, 256)
            self.assertEqual(cursor, {"nodeId": 7, "lastUserId": 28})
        finally:
            os.close(lock)
            os.close(fd)

    def test_cursor_survives_user_removal_and_insertion(self):
        for user in (3, 8, 21, 55):
            (Path(self.state) / f"genesis-positive-cap-u{user}.json").touch()
        with mock.patch.object(
                renewal_worker, "_candidate",
                side_effect=lambda fd, names, node, user, pinned, now:
                    (user, 1, "a" * 64)):
            first = renewal_worker.pending_renewals(self.state, 7, "b" * 64, now=1)
            self.assertEqual([item[0] for item in first], [3, 8, 21, 55])
            (Path(self.state) / "genesis-positive-cap-u21.json").unlink()
            (Path(self.state) / "genesis-positive-cap-u33.json").touch()
            second = renewal_worker.pending_renewals(self.state, 7, "b" * 64, now=2)
            self.assertEqual([item[0] for item in second], [3, 8, 33, 55])

    def test_corrupt_foreign_or_symlinked_cursor_refuses_renewal(self):
        (Path(self.state) / "genesis-positive-cap-u9.json").touch()
        with mock.patch.object(
                renewal_worker, "_candidate",
                return_value=(9, 1, "a" * 64)):
            renewal_worker.pending_renewals(self.state, 7, "b" * 64, now=1)
            with self.assertRaisesRegex(ValueError, "foreign"):
                renewal_worker.pending_renewals(self.state, 8, "b" * 64, now=2)
            cursor = Path(self.state) / renewal_worker.CURSOR_FILE
            for raw in ('{"nodeId":7,"lastUserId":true}',
                        '{"nodeId":7,"lastUserId":0}',
                        '{"nodeId":7,"lastUserId":9,"extra":1}',
                        '{"nodeId":7,"lastUserId":'):
                cursor.write_text(raw)
                with self.assertRaises((ValueError, TypeError)):
                    renewal_worker.pending_renewals(
                        self.state, 7, "b" * 64, now=3)
            cursor.unlink()
            cursor.symlink_to("/etc/passwd")
            with self.assertRaises((ValueError, OSError)):
                renewal_worker.pending_renewals(
                    self.state, 7, "b" * 64, now=4)


    def test_one_corrupt_user_does_not_starve_other_signed_renewals(self):
        for user in range(1, 18):
            (Path(self.state) / f"genesis-positive-cap-u{user}.json").touch()

        def candidate(fd, names, node, user, pinned, now):
            if user == 4:
                raise ValueError("signed data corrupted: never disclose payload")
            return (user, 1, "a" * 64)

        with mock.patch.object(renewal_worker, "_candidate", side_effect=candidate):
            with mock.patch("builtins.print") as log:
                jobs = renewal_worker.pending_renewals(
                    self.state, 7, "b" * 64, now=1)
                self.assertEqual([item[0] for item in jobs],
                                 [1, 2, 3] + list(range(5, 17)))
                self.assertEqual(log.call_count, 1)
                self.assertNotIn("never disclose payload", str(log.call_args))
            # The next round visits the previously unvisited user 17,
            # even though user 4's signed original is still invalid.
            second = renewal_worker.pending_renewals(
                self.state, 7, "b" * 64, now=2)
            self.assertEqual(second[0][0], 17)


if __name__ == "__main__":
    unittest.main()
