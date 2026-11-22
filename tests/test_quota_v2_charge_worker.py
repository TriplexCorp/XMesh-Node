#!/usr/bin/env python3
"""Stage-only WAL charge sender: bounded batches, exact bytes, strict ACK scope."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments/quota-v2-physical-stop"))
import charge_worker as worker
import quarantine_policy as quarantine
import wal_transport


def signed(doc):
    return wal_transport.observed.canonical({
        "algorithm": "Ed25519", "payload": doc, "signature": "a" * 128,
    }) + b"\n"


class ChargeWorkerTests(unittest.TestCase):
    def test_batch_boundaries_never_split_durable_wal_lines(self):
        lines = [b'{"sequence":1}\n', b'{"sequence":2}\n',
                 b'{"sequence":3}\n']
        raw = b"".join(lines * 5000)
        parts = list(worker._chunks(raw))
        self.assertGreater(len(parts), 1)
        self.assertEqual(b"".join(parts), raw)
        self.assertTrue(all(len(part) <= worker.BATCH_BYTES for part in parts))
        self.assertTrue(all(part.endswith(b"\n") for part in parts))
        with self.assertRaises(ValueError):
            list(worker._chunks(b'{"sequence":4}'))
        with self.assertRaises(ValueError):
            list(worker._chunks(b"x" * 1025 + b"\n"))

    def test_wal_charge_receipt_cannot_change_authoritative_scope(self):
        raw = b'{"sequence":1}\n'
        birth = {"runtimeId": "d" * 64}
        first = {"sequence": 1}
        last = {"sequence": 1, "digest": "e" * 64, "nextBytes": 17}
        request = {"nodeId": 7, "userId": 42, "reservationId":
                   "00000000-0000-0000-0000-000000000001",
                   "filename": "meter-" + "b"*64 + ".jsonl", "raw": raw}
        payload = {
            "schemaVersion": 1, "kind": "xmesh.quota-v2.wal-intent-charge",
            "nodeId": 7, "userId": 42, "reservationId": request["reservationId"],
            "runtimeId": birth["runtimeId"], "filename": request["filename"],
            "firstSequence": 1, "lastSequence": 1,
            "lastDigest": last["digest"], "journalSha256": hashlib.sha256(raw).hexdigest(),
            "streamBytes": 17, "conservativeWalBytes": 17,
            "conservativeCdnWalBytes": 0,
            "canResume": False, "finalMeterVerified": False, "refundableBytes": 0,
        }
        with mock.patch.object(wal_transport.verifier, "verify_nexus_signature") as verify:
            self.assertEqual(worker._validate_receipt(
                signed(payload), "f"*64, "/dev/null",
                request, birth, first, last), payload)
            self.assertEqual(verify.call_count, 1)
            for key, invalid in (
                ("userId", 999), ("nodeId", 8), ("filename", "meter-evil.jsonl"),
                ("journalSha256", "0"*64), ("lastSequence", 99),
                ("finalMeterVerified", True), ("refundableBytes", 1),
                ("streamBytes", 18), ("conservativeCdnWalBytes", 18),
            ):
                changed = dict(payload, **{key: invalid})
                with self.subTest(key=key), self.assertRaises(ValueError):
                    worker._validate_receipt(
                        signed(changed), "f"*64, "/dev/null",
                        request, birth, first, last)

    def test_private_wal_read_refuses_mismatch_and_symlink(self):
        if os.geteuid() != 0:
            self.skipTest("root-owned WAL inode verification")
        with tempfile.TemporaryDirectory(prefix="xmesh-charge-file-") as root:
            directory = Path(root)
            os.chmod(directory, 0o700)
            name = "meter-" + "c" * 64 + ".jsonl"
            path = directory / name
            raw = b'{"sequence":1}\n'
            path.write_bytes(raw)
            path.chmod(0o600)
            fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                self.assertEqual(worker._bytes_after_validation(
                    fd, name, hashlib.sha256(raw).hexdigest()), raw)
                with self.assertRaises(ValueError):
                    worker._bytes_after_validation(fd, name, "0"*64)
                path.unlink()
                path.symlink_to("/dev/null")
                with self.assertRaises((OSError, ValueError)):
                    worker._bytes_after_validation(
                        fd, name, hashlib.sha256(raw).hexdigest())
            finally:
                os.close(fd)

    def test_immutable_receipt_namespace_disallows_overwrite(self):
        if os.geteuid() != 0:
            self.skipTest("root-owned WAL ACK durability")
        with tempfile.TemporaryDirectory(prefix="xmesh-wal-ack-") as root:
            os.chmod(root, 0o700)
            fd, lock = quarantine._locked_private_state(root)
            try:
                name = "wal-charge-" + "c"*64 + "-s42.json"
                evidence = {"nodeId": 7, "userId": 42, "signedReceipt": "abc"}
                quarantine._durable_store(fd, evidence, name)
                quarantine._durable_store(fd, evidence, name)
                with self.assertRaises(ValueError):
                    quarantine._durable_store(
                        fd, dict(evidence, nodeId=8), name)
                with self.assertRaises(ValueError):
                    quarantine._durable_store(fd, evidence, "wal-charge-evil.json")
            finally:
                os.close(lock)
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
