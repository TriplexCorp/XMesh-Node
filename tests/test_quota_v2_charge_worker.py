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
import successor_positive
import vless_ingress
import wal_transport


def signed(doc):
    return wal_transport.observed.canonical({
        "algorithm": "Ed25519", "payload": doc, "signature": "a" * 128,
    }) + b"\n"


class ChargeWorkerTests(unittest.TestCase):
    def test_wal_charge_refuses_replaced_docker_kernel_or_private_journal(self):
        before = {"Id": "a" * 64,
                  "State": {"Pid": 23456,
                            "StartedAt": "2026-11-24T07:00:00Z"}}
        wal = "/var/lib/xmesh-private-wal"
        name = "xmesh-quota-u42-" + "b" * 32
        runtime = "c" * 64
        with (
            mock.patch.object(wal_transport, "_bound_journal",
                              return_value=(before, wal)) as inspect,
            mock.patch.object(wal_transport.runtime_identity,
                              "trusted_runtime_identity", return_value=runtime) as measure,
        ):
            worker._verify_charging_runtime_unchanged(name, before, wal, runtime)
            inspect.assert_called_once_with(name)
            measure.assert_called_once_with(23456)

        for current, mount in (
            (dict(before, Id="d" * 64), wal),
            (dict(before, State=dict(before["State"], Pid=23457)), wal),
            (dict(before, State=dict(before["State"],
                                    StartedAt="2026-11-24T07:00:01Z")), wal),
            (before, "/var/lib/different-wal"),
            (dict(before, State={"Pid": 23456}), wal),
            (dict(before, State={"Pid": 0,
                                 "StartedAt": before["State"]["StartedAt"]}), wal),
        ):
            with (
                self.subTest(current=current, mount=mount),
                mock.patch.object(wal_transport, "_bound_journal",
                                  return_value=(current, mount)),
                mock.patch.object(wal_transport.runtime_identity,
                                  "trusted_runtime_identity", return_value=runtime),
            ):
                with self.assertRaisesRegex(ValueError, "changed during authenticated WAL charging"):
                    worker._verify_charging_runtime_unchanged(name, before, wal, runtime)

        with (
            mock.patch.object(wal_transport, "_bound_journal",
                              return_value=(before, wal)),
            mock.patch.object(wal_transport.runtime_identity,
                              "trusted_runtime_identity", return_value="e" * 64),
        ):
            with self.assertRaisesRegex(ValueError, "kernel identity changed"):
                worker._verify_charging_runtime_unchanged(name, before, wal, runtime)

        # A shared multiuser Genesis has no per-successor runtime pin,
        # but must still refuse container restart or journal replacement.
        with (
            mock.patch.object(wal_transport, "_bound_journal",
                              return_value=(before, wal)) as inspect,
            mock.patch.object(wal_transport.runtime_identity,
                              "trusted_runtime_identity") as measure,
        ):
            worker._verify_charging_runtime_unchanged(
                "xmesh-managed-xray", before, wal, None)
            inspect.assert_called_once_with()
            measure.assert_not_called()

    def test_isolated_successor_wal_cannot_charge_a_foreign_user(self):
        candidate = "xmesh-quota-u42-" + "a" * 32
        good = {
            "meter-" + "b" * 64 + ".jsonl": {
                "email": "xmesh-u42--vless-main", "runtimeId": "c" * 64,
            },
            "meter-" + "d" * 64 + ".jsonl": {
                "email": "xmesh-u42--vless-cdn", "runtimeId": "c" * 64,
            },
        }
        self.assertIsNone(worker._verify_private_successor_wal_owner(candidate, good))
        for birth in (
            {"email": "xmesh-u43--vless-main", "runtimeId": "c" * 64},
            {"email": "xmesh-u0--vless-main", "runtimeId": "c" * 64},
            {"email": "not-a-signed-email", "runtimeId": "c" * 64},
            {"runtimeId": "c" * 64},
            None,
        ):
            mixed = dict(good, **{"meter-" + "e" * 64 + ".jsonl": birth})
            with self.subTest(birth=birth), self.assertRaisesRegex(
                    ValueError, "foreign|malformed|another user's byte intents"):
                worker._verify_private_successor_wal_owner(candidate, mixed)
        # The original shared Genesis Xray is intentionally multiuser.
        self.assertIsNone(worker._verify_private_successor_wal_owner(
            "xmesh-managed-xray", {
                "meter-" + "e" * 64 + ".jsonl": {
                    "email": "xmesh-u43--vless-main", "runtimeId": "c" * 64,
                },
            }))

    def test_historical_wal_selects_its_runtime_and_rejects_corrupt_evidence(self):
        old, current = "a" * 64, "b" * 64
        email = "xmesh-u42--vless-main"
        legacy = "genesis-positive-cap-u42.json"
        archive = f"wal-cap-u42-{old}.json"
        cap = {"kind": "xmesh.quota-v2.xray-cap-admission", "nodeId": 7,
               "userId": 42, "runtimeId": old, "reservationId": "old",
               "aliasScopes": [{"email": email, "class": "main"}]}
        birth = {"runtimeId": old, "email": email}
        newer = dict(cap, runtimeId=current, reservationId="next")
        for archived, fallback, accepted in (
            (cap, newer, True),
            (FileNotFoundError(), cap, True),
            (FileNotFoundError(), newer, False),
            (ValueError("corrupt archive"), cap, False),
            (dict(cap, nodeId=8), cap, False),
        ):
            fixtures = {archive: archived, legacy: fallback}

            def verify(fd, name, pin):
                result = fixtures[name]
                if isinstance(result, Exception):
                    raise result
                return result

            with (mock.patch.object(worker.renewal_worker, "_verified_reply",
                                    side_effect=verify) as verify_reply,
                  mock.patch.object(successor_positive, "_read_evidence",
                                    side_effect=ValueError("no saved successor evidence"))):
                if accepted:
                    self.assertEqual(worker._grant_for_birth(3, 7, 42, "c" * 64, birth), cap)
                else:
                    with self.assertRaises(ValueError):
                        worker._grant_for_birth(3, 7, 42, "c" * 64, birth)
                if not isinstance(archived, FileNotFoundError):
                    verify_reply.assert_called_once_with(3, archive, "c" * 64)

    def test_successor_receipt_is_only_accepted_under_its_runtime_archive(self):
        runtime = "a" * 64
        archive = f"wal-cap-u42-{runtime}.json"
        grant = {"kind": "xmesh.quota-v2.xray-cap-admission", "nodeId": 7,
                 "userId": 42, "runtimeId": runtime}
        receipt = {"status": "committed_calendar_successor", "nodeId": 7,
                   "userId": 42, "signedEnvelope": "fixture"}
        verify = worker.renewal_worker
        with (mock.patch.object(verify.lease, "_identity_file", return_value=receipt),
              mock.patch.object(wal_transport, "_write_public"),
              mock.patch.object(worker.caps, "_verify_cap_envelope", return_value=grant)):
            self.assertEqual(verify._verified_reply(3, archive, "pin"), grant)
            with self.assertRaisesRegex(ValueError, "exact WAL runtime"):
                verify._verified_reply(3, "genesis-positive-cap-u42.json", "pin")

    def test_generation_chain_selects_second_successor_and_refuses_forks(self):
        def grant(i):
            return {"reservationId": f"reserve-{i}", "meterEpoch": f"meter-{i}",
                    "runtimeId": f"runtime-{i}"}

        user = 42
        original, second, third = map(grant, (1, 2, 3))
        first_name = successor_positive._filename(user, original["reservationId"])
        second_name = successor_positive._filename(user, second["reservationId"])
        foreign_name = successor_positive._filename(43, original["reservationId"])

        def saved(_, name, __):
            result = second if name == first_name else third
            return {"response": {"signedEnvelope": wal_transport.observed.canonical(
                {"payload": result}).decode()}}

        with (mock.patch.object(worker.renewal_worker, "latest_signed_cap", return_value=original),
              mock.patch.object(successor_positive, "_read_evidence",
                                return_value=(None, None, None, None, None, ("measurement",))) as read,
              mock.patch.object(successor_positive, "_verified_saved_receipt") as verify,
              mock.patch.object(successor_positive.lease, "_identity_file", side_effect=saved)):
            chain = successor_positive.verified_chain(
                3, [second_name, foreign_name, first_name], 7, user, "pin")
            self.assertEqual([cap for cap, _ in chain], [original, second, third])
            self.assertEqual([call.kwargs["old"] for call in read.call_args_list],
                             [original, second])
            self.assertEqual(verify.call_count, 2)
            with self.assertRaisesRegex(ValueError, "disconnected"):
                successor_positive.verified_chain(3, [second_name], 7, user, "pin")
            with self.assertRaisesRegex(ValueError, "disconnected"):
                successor_positive.verified_chain(
                    3, [first_name, second_name, successor_positive._filename(user, "fork")],
                    7, user, "pin")
            third["runtimeId"] = original["runtimeId"]
            with self.assertRaisesRegex(ValueError, "reused"):
                successor_positive.verified_chain(3, [first_name, second_name], 7, user, "pin")

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

    def test_alternating_runtime_polls_preserve_both_positions(self):
        batch = worker.MAX_BATCHES_PER_POLL
        ledgers = {
            None: [f"meter-{i:064x}.jsonl" for i in range(batch * 2)],
            "a" * 64: [f"meter-{i:064x}.jsonl" for i in range(batch * 2, batch * 4)],
        }
        with tempfile.TemporaryDirectory() as tmp:
            for start in (0, batch, 0):
                for runtime, streams in ledgers.items():
                    fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        self.assertEqual(
                            worker._next_charge_batch(fd, 42, streams, runtime_id=runtime),
                            streams[start:start + batch],
                        )
                    finally:
                        os.close(fd)

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
                                  return_value=({"Id": "a" * 64,
                                      "State": {"Pid": os.getpid(),
                                                "StartedAt": "2026-11-24T07:00:00Z"}}, str(root))),
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
            tempfile.TemporaryDirectory() as directory,
            mock.patch.dict(os.environ, {
                "XMESH_QUOTA_V2_AUTO_RENEW_STAGING": "1",
                "XMESH_QUOTA_V2_INSTALLED_CAP_DELIVERY": "1",
            }),
            mock.patch.object(os, "geteuid", return_value=0),
            mock.patch.object(worker, "run", observed.charge),
            mock.patch.object(worker.renewal_worker, "activate_initial_cap", observed.admission),
        ):
            marker = Path(directory) / "staging"
            marker.touch(mode=0o600)
            with (
                mock.patch.object(vless_ingress, "STAGING_MARKER", str(marker)),
                self.assertRaisesRegex(ValueError, "invalid Genesis candidate"),
            ):
                worker.renewal_worker.run("https://isolated.test", 42, "/private/state", "/private/socket")
        self.assertEqual(observed.mock_calls, [
            mock.call.charge("https://isolated.test", 42, "/private/state", set()),
            mock.call.admission("https://isolated.test", 42, "/private/state", "/private/socket",
                                blocked_users=set()),
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
