#!/usr/bin/env python3
"""Durable idempotency for Agent renewals after a lost SQL COMMIT response."""
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments/quota-v2-physical-stop"))
import first_cap_handoff as cap
import genesis_reservation as lease
import quarantine_policy as quarantine
import renewal_worker


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
