#!/usr/bin/env python3
"""Durable idempotency for Agent renewals after a lost SQL COMMIT response."""
import os
from pathlib import Path
import sys
import tempfile
import unittest

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


if __name__ == "__main__":
    unittest.main()
