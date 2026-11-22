#!/usr/bin/env python3
"""Stage-only WAL charge sender: bounded batches, exact bytes, strict ACK scope."""
import hashlib
import os
from pathlib import Path
import subprocess
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
    def test_wal_queue_reaches_every_stream_across_reopened_state(self):
        streams = [f"meter-{i:064x}.jsonl" for i in range(1, 1001)]
        with tempfile.TemporaryDirectory() as tmp:
            def poll():
                fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    return worker._next_charge_batch(fd, 42, streams)
                finally:
                    os.close(fd)
            assert len(streams) % worker.MAX_BATCHES_PER_POLL == 0
            scanned = []
            for _ in range(len(streams) // worker.MAX_BATCHES_PER_POLL):
                scanned.extend(poll())
            self.assertEqual(scanned, streams)
            self.assertEqual(poll(), streams[:worker.MAX_BATCHES_PER_POLL])

    def test_failed_user_charge_does_not_starve_the_other_stream(self):
        if os.geteuid() != 0:
            self.skipTest("root-owned WAL and Agent state")
        files = [f"meter-{i:064x}.jsonl" for i in range(1, 3)]
        entries = {name: {"email": f"xmesh-u{i}--vless-main"}
                   for i, name in enumerate(files, 1)}
        verified = {name: (None, "a"*64) for name in files}
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            state = root / "state"
            state.mkdir(mode=0o700)
            for name in files:
                (root / name).touch(mode=0o600)
            with (
                mock.patch.dict(os.environ, {
                    "XMESH_QUOTA_V2_AUTO_RENEW_STAGING": "1",
                    "XMESH_QUOTA_V2_INSTALLED_CAP_DELIVERY": "1",
                }),
                mock.patch.object(wal_transport, "run"),
                mock.patch.object(wal_transport, "_bound_journal",
                                  return_value=({}, str(root))),
                mock.patch.object(worker.journal, "_verify_mount"),
                mock.patch.object(worker.registry, "verify_meter_inventory",
                                  return_value=(entries, verified)),
                mock.patch.object(wal_transport, "_panel_pin", return_value="b"*64),
                mock.patch.object(wal_transport, "_write_public"),
                mock.patch.object(worker, "_charge_stream",
                                  side_effect=[subprocess.TimeoutExpired("product", 30), 1]) as charge,
            ):
                refused = set()
                self.assertEqual(worker.run("https://isolated.test", 42, str(state), refused), 1)
                self.assertEqual(refused, {1})
                self.assertEqual([call.args[-2] for call in charge.call_args_list], [1, 2])

    def test_old_wal_reconciles_before_failed_first_admission(self):
        observed = mock.Mock()
        observed.admission.side_effect = ValueError("invalid Genesis candidate")
        with (
            mock.patch.dict(os.environ, {
                "XMESH_QUOTA_V2_AUTO_RENEW_STAGING": "1",
                "XMESH_QUOTA_V2_INSTALLED_CAP_DELIVERY": "1",
            }),
            mock.patch.object(os, "geteuid", return_value=0),
            mock.patch.object(worker, "run", observed.charge),
            mock.patch.object(worker.renewal_worker, "activate_initial_cap", observed.admission),
        ):
            with self.assertRaisesRegex(ValueError, "invalid Genesis candidate"):
                worker.renewal_worker.run("https://isolated.test", 42, "/private/state", "/private/socket")
        self.assertEqual(observed.mock_calls, [
            mock.call.charge("https://isolated.test", 42, "/private/state", set()),
            mock.call.admission("https://isolated.test", 42, "/private/state", "/private/socket"),
        ])

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

    def test_real_nexus_ed25519_wal_charge_receipt(self):
        import subprocess
        with tempfile.TemporaryDirectory(prefix="xmesh-wal-charge-ed25519-") as root:
            key = Path(root) / "signer.pem"
            public = Path(root) / "public.pem"
            message = Path(root) / "domain-message"
            signature = Path(root) / "signature"
            subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519",
                            "-out", str(key)], check=True, capture_output=True)
            subprocess.run(["openssl", "pkey", "-in", str(key), "-pubout",
                            "-out", str(public)], check=True, capture_output=True)
            raw = b'{"sequence":1}\n'
            filename = "meter-" + "b"*64 + ".jsonl"
            reservation = "00000000-0000-0000-0000-000000000001"
            payload = {
                "schemaVersion": 1, "kind": "xmesh.quota-v2.wal-intent-charge",
                "nodeId": 7, "userId": 42, "reservationId": reservation,
                "runtimeId": "d"*64, "filename": filename,
                "firstSequence": 1, "lastSequence": 1, "lastDigest": "e"*64,
                "journalSha256": hashlib.sha256(raw).hexdigest(),
                "streamBytes": 17, "conservativeWalBytes": 17,
                "conservativeCdnWalBytes": 0, "canResume": False,
                "finalMeterVerified": False, "refundableBytes": 0,
            }
            message.write_bytes(worker.DOMAIN + wal_transport.observed.canonical(payload))
            subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin",
                            "-inkey", str(key), "-in", str(message),
                            "-out", str(signature)], check=True, capture_output=True)
            exact = wal_transport.observed.canonical({
                "algorithm": "Ed25519", "payload": payload,
                "signature": signature.read_bytes().hex()}) + b"\n"
            req = {"nodeId": 7, "userId": 42, "reservationId": reservation,
                   "filename": filename, "raw": raw}
            self.assertEqual(worker._validate_receipt(
                exact, "0"*64, public, req, {"runtimeId": "d"*64},
                {"sequence": 1},
                {"sequence": 1, "digest": "e"*64, "nextBytes": 17}), payload)
            altered = dict(payload, conservativeWalBytes=18)
            forged = wal_transport.observed.canonical({
                "algorithm": "Ed25519", "payload": altered,
                "signature": signature.read_bytes().hex()}) + b"\n"
            with self.assertRaises(ValueError):
                worker._validate_receipt(
                    forged, "0"*64, public, req, {"runtimeId": "d"*64},
                    {"sequence": 1},
                    {"sequence": 1, "digest": "e"*64, "nextBytes": 17})

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

    def test_lost_commit_response_replays_original_bytes_after_wal_grows(self):
        if os.geteuid() != 0:
            self.skipTest("root-owned immutable charge request")
        with tempfile.TemporaryDirectory(prefix="xmesh-charge-lost-commit-") as root:
            os.chmod(root, 0o700)
            fd, lock = quarantine._locked_private_state(root)
            try:
                file = "meter-" + "b"*64 + ".jsonl"
                key = hashlib.sha256(file.encode()).hexdigest()
                reservation = "00000000-0000-0000-0000-000000000001"
                original = b'{"sequence":1}\n'
                added = b'{"sequence":2}\n'
                first = worker._durable_request(fd, key, 7, 42, reservation, file, original)
                self.assertEqual(first, original)
                self.assertEqual(worker._durable_request(
                    fd, key, 7, 42, reservation, file, original + added), original)
                with self.assertRaises(ValueError):
                    worker._durable_request(fd, key, 8, 42, reservation, file, original)
                with self.assertRaises(ValueError):
                    worker._durable_request(fd, key, 7, 42,
                        "00000000-0000-0000-0000-000000000002", file, original)
                self.assertEqual(worker._durable_request(
                    fd, key, 7, 42, reservation, file, original + added), original)
            finally:
                os.close(lock)
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
