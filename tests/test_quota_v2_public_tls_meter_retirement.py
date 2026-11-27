#!/usr/bin/env python3
"""Real Linux child/pidfd/flock and Ed25519; Docker/IPC are test fixtures.

The installed native TLS and actual Xray fence must be qualified separately.
No positive issuer, terminal byte claim or service is exercised here.
"""
from contextlib import ExitStack
import fcntl
import json
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
import public_tls_meter_retirement as retirement
import public_tls_cap_watch as cap_watch
import public_tls_wal_watch as watch
import test_quota_v2_first_cap_handoff as cap_fixture
import test_quota_v2_public_tls_wal_watch as watch_fixture
import quota_v2_meter_wal_fixture as wal_fixture

LOCK_CHILD = """
import fcntl,os,sys,time
fd=os.open(sys.argv[1],os.O_CREAT|os.O_EXCL|os.O_RDWR,0o600)
fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
print("locked",flush=True)
time.sleep(120)
"""


class RetirementTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        temp = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="xmesh-retirement-"))
        self.directory = Path(temp)
        self.child = subprocess.Popen(
            [sys.executable, "-c", LOCK_CHILD, str(self.directory / watch.INSTANCE_LOCK)],
            stdout=subprocess.PIPE, text=True)
        self.stack.callback(self.stop_child)
        self.assertEqual(self.child.stdout.readline().strip(), "locked")
        self.runtime = retirement.wal.runtime_identity.trusted_runtime_identity(self.child.pid)
        self.source = cap_fixture.FirstCapHandoffTests(
            "test_original_nexus_signer_and_real_assigned_vless_scope")
        self.source.setUp()
        self.stack.callback(self.source.doCleanups)
        source = self.source
        raw = source.signed_grant(dict(source.claims, runtimeId=self.runtime))
        self.roster = cap_watch.SignedCapRosterWatch(
            profile=source.reply["config"], signed_grants={100: raw}, pinned=source.pub,
            node=source.node, activation=source.fixture.activation,
            genesis_sha=source.reply["policySha256"], runtime_id=self.runtime,
            trusted_pid=self.child.pid, socket_path="/var/lib/xmesh-first-meter/runtime/drain.sock")
        cap = self.directory / "positive-cap-u100.json"
        cap.write_bytes(raw)
        cap.chmod(0o600)
        self.measured = ("a"*64, "2026-11-26T19:30:01.012345678Z", self.child.pid, self.runtime)
        self.running = True
        self.cid = self.measured[0]
        self.restart = "no"
        self.checkpoint_rows = [
            {"email": "xmesh-u100--vless-cdn", "uplinkBytes": 7, "downlinkBytes": 0},
            {"email": "xmesh-u100--vless-main", "uplinkBytes": 42, "downlinkBytes": 2},
        ]
        self.counters = (51, 7)
        wal_fixture.write_test_meter_intents(
            {"runtimeId": self.runtime, "inboundMeters": self.checkpoint_rows}, self.directory)
        self.stack.enter_context(mock.patch.object(retirement, "DIRECTORY", self.directory))
        self.stack.enter_context(mock.patch.object(retirement, "_require_disposable"))
        self.stack.enter_context(mock.patch.object(retirement, "_same_mount"))
        self.stack.enter_context(mock.patch.object(retirement.wal, "_bound_journal",
                                                  side_effect=lambda: (self.docker(), str(self.directory))))
        self.stack.enter_context(mock.patch.object(watch.cap_install, "observe_installed_cap_in_xray",
                                                  side_effect=self.local))
        self.fetch = self.stack.enter_context(mock.patch.object(watch, "_fetch", side_effect=self.reply))
        self.fence = self.stack.enter_context(mock.patch.object(watch.cap_install, "fence_calendar_in_xray",
                                                               side_effect=self.publish_fence))

    def stop_child(self):
        if self.child.poll() is None:
            self.child.kill()
            self.child.wait(timeout=5)
        self.child.stdout.close()
        self.running = False

    def docker(self):
        return {
            "Id": self.cid, "Name": "/xmesh-managed-xray",
            "State": {"Running": self.running, "Restarting": False,
                      "Pid": self.child.pid if self.running else 0,
                      "StartedAt": self.measured[1]},
            "HostConfig": {"RestartPolicy": {"Name": self.restart}, "NetworkMode": "none"},
            "Mounts": [{"Type": "bind", "Source": str(self.directory),
                        "Destination": retirement.journal.JOURNAL_DEST, "RW": True}],
        }

    def snapshot(self):
        return watch._snapshot(self.directory, self.roster, lambda: None)

    def reply(self, request):
        return watch_fixture.PublicTlsWalWatchTests.reply(self, request, self.snapshot())

    def local(self, *args):
        return watch_fixture.PublicTlsWalWatchTests.local(self, *args)

    def publish_fence(self, path, pid, runtime, scope):
        self.assertEqual((path, pid, runtime),
                         (self.roster._socket, self.child.pid, self.runtime))
        self.assertEqual(scope, retirement._scope(self.roster, 100))
        cp = dict(scope, schemaVersion=3, runtimeId=runtime, uplinkBytes=49, downlinkBytes=2,
                  inboundMeters=self.checkpoint_rows, drained=True,
                  finalMeterVerified=False, refundableBytes=0)
        j = retirement.journal
        stem = hashlib.sha256(b"xmesh-u100").hexdigest()
        records = (
            ("fence-" + stem + ".json", dict({k: cp[k] for k in j.FIELDS}, schemaVersion=1)),
            ("observed-" + stem + ".json", {k: cp[k] for k in j.CHECKPOINT}),
        )
        for name, record in records:
            fd = os.open(self.directory / name, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(j._canonical_go(record))
                handle.flush()
                os.fsync(handle.fileno())
        directory_fd = j._validate_directory(self.directory)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return {"observedCheckpoint": cp}

    def capture(self):
        return self.stack.enter_context(retirement.FirstGenesisRetirement(
            self.roster, 100, self.measured, lambda: (self.measured, str(self.directory))))

    def fenced(self):
        proof = self.capture()
        proof.fence_all()
        return proof

    def test_real_original_exit_with_same_flocked_ledger_and_signed_heads(self):
        original = self.snapshot()
        proof = self.fenced()
        with self.assertRaisesRegex(ValueError, "pidfd has not exited"):
            proof.verify_exited()
        self.stop_child()
        result = proof.verify_exited()
        self.assertEqual(result["committedChargeHeadsSha256"], original["chargeHeadsSha256"])
        self.assertEqual(result["inventorySha256"], original["sha256"])
        self.assertEqual(result["runtimeId"], self.runtime)
        self.assertEqual(set(result["durableUserDenials"]), {"100"})
        self.assertTrue(result["originalMeterPidfdExited"])
        self.assertTrue(result["lifetimeLockReleased"])
        self.assertFalse(result["finalMeterVerified"])
        self.assertFalse(result["settlementEligible"])
        self.assertFalse(result["canResume"])
        self.assertEqual(result["refundableBytes"], 0)
        self.assertEqual(proof.verify_exited(), result)

    def test_false_Docker_stopped_metadata_cannot_replace_real_pidfd(self):
        proof = self.fenced()
        self.running = False
        with self.assertRaisesRegex(ValueError, "pidfd has not exited"):
            proof.verify_exited()

    def test_restart_or_replacement_after_real_original_exit_rejected(self):
        proof = self.fenced()
        self.stop_child()
        for cid, restart, running in (("b"*64, "no", False),
                                      (self.measured[0], "always", False),
                                      (self.measured[0], "no", True)):
            self.cid, self.restart, self.running = cid, restart, running
            with self.subTest(cid=cid, restart=restart, running=running), self.assertRaisesRegex(ValueError, "incarnation"):
                proof.verify_exited()

    def test_lifetime_lock_replacement_after_original_exit_rejected(self):
        proof = self.fenced()
        self.stop_child()
        lock = self.directory / watch.INSTANCE_LOCK
        lock.rename(self.directory / "old-lock")
        lock.touch(mode=0o600)
        with self.assertRaisesRegex(ValueError, "lock inode changed"):
            proof.verify_exited()

    def test_foreign_writer_lock_after_original_exit_rejected_against_real_flock(self):
        proof = self.fenced()
        self.stop_child()
        with (self.directory / watch.INSTANCE_LOCK).open("rb") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, "lock still held"):
                proof.verify_exited()

    def test_changed_committed_wal_after_exit_never_settles(self):
        proof = self.fenced()
        self.stop_child()
        with next(self.directory.glob("meter-*.jsonl")).open("ab") as wal:
            wal.write(b"x")
        with self.assertRaisesRegex(ValueError, "committed original WAL bytes changed"):
            proof.verify_exited()

    @staticmethod
    def replace_identical(path):
        raw = path.read_bytes()
        replacement = path.with_name(".replacement")
        replacement.write_bytes(raw)
        replacement.chmod(0o600)
        replacement.replace(path)

    def test_same_bytes_different_inode_before_fence_denies(self):
        proof = self.capture()
        self.replace_identical(next(self.directory.glob("meter-*.jsonl")))
        with self.assertRaisesRegex(ValueError, "changed before fencing"):
            proof.fence_all()
        self.fence.assert_not_called()

    def test_identical_wal_replacement_after_exit_denies(self):
        proof = self.fenced()
        self.stop_child()
        self.replace_identical(next(self.directory.glob("meter-*.jsonl")))
        with self.assertRaisesRegex(ValueError, "WAL inode changed"):
            proof.verify_exited()

    def test_identical_durable_fence_replacement_after_exit_denies(self):
        proof = self.fenced()
        self.stop_child()
        self.replace_identical(next(self.directory.glob("fence-*.json")))
        with self.assertRaisesRegex(ValueError, "changed across process exit"):
            proof.verify_exited()

    def test_original_lock_retained_across_verification_and_publication(self):
        proof = self.fenced()
        self.stop_child()
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(
            prefix="xmesh-retire-record-")))
        with mock.patch.object(retirement, "RECORD_DIRECTORY", root):
            payload = proof.publish_exited()
            record = root / ("retired-" + self.runtime + ".json")
            wire = record.read_bytes()
            doc = json.loads(wire)
            self.assertEqual(doc["observation"], payload)
            self.assertEqual(hashlib.sha256(doc["nexusResponse"].encode()).hexdigest(),
                             payload["signedWalReadbackSha256"])
            self.assertEqual(doc["nexusResponse"].encode(), proof._witness_raw)
            for flag in ("deliveredBytesVerified", "nodeSignatureVerified", "canStart",
                         "canServePublic", "canResume", "settlementEligible", "finalMeterVerified"):
                self.assertIs(payload[flag], False)
            self.assertEqual(payload["refundableBytes"], 0)
            self.assertEqual(record.stat().st_mode & 0o777, 0o600)
            self.assertEqual(record.stat().st_nlink, 1)
            inode = record.stat().st_ino
            self.assertEqual(proof.publish_exited(), payload)
            self.assertEqual(record.stat().st_ino, inode)
            self.assertEqual(record.read_bytes(), wire)
            with (self.directory / watch.INSTANCE_LOCK).open("rb") as foreign:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(foreign, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with self.assertRaisesRegex(ValueError, "conflicting immutable"):
                retirement._publish_record(root, self.runtime, b"other", lambda: None)
        proof.close()
        with (self.directory / watch.INSTANCE_LOCK).open("rb") as foreign:
            fcntl.flock(foreign, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_pending_record_denies_recovery_without_original_observation(self):
        root = Path(self.stack.enter_context(tempfile.TemporaryDirectory(
            prefix="xmesh-retire-abort-")))

        def abort():
            raise ValueError("ledger changed before publication")

        with self.assertRaisesRegex(ValueError, "ledger changed"):
            retirement._publish_record(root, self.runtime, b"nonfinal", abort)
        names = list(root.iterdir())
        self.assertEqual(len(names), 1)
        self.assertTrue(names[0].name.startswith(".retirement-pending-"))
        with self.assertRaisesRegex(ValueError, "interrupted retirement publication"):
            retirement._publish_record(root, self.runtime, b"nonfinal", lambda: None)

    def test_missing_deny_or_unknown_journal_after_exit_is_not_proof(self):
        proof = self.fenced()
        self.stop_child()
        deny = next(self.directory.glob("fence-*.json"))
        deny.unlink()
        with self.assertRaisesRegex(ValueError, "missing, additional"):
            proof.verify_exited()

    def test_signed_stale_tails_are_rejected_before_any_deny(self):
        self.fetch.side_effect = lambda request: watch_fixture.PublicTlsWalWatchTests.reply(
            self, request, self.snapshot(), {"committedChargeHeadsSha256": "e"*64})
        with self.assertRaisesRegex(ValueError, "signed Nexus WAL history does not match"):
            self.capture()
        self.fence.assert_not_called()

    def test_missing_alias_in_fence_is_not_complete_deny(self):
        original = self.publish_fence
        def wrong(*args):
            result = original(*args)
            result["observedCheckpoint"]["inboundMeters"] = self.checkpoint_rows[:1]
            return result
        self.fence.side_effect = wrong
        proof = self.capture()
        with self.assertRaisesRegex(ValueError, "durable denial differs"):
            proof.fence_all()
        self.stop_child()
        with self.assertRaisesRegex(ValueError, "pidfd has not exited after durable"):
            proof.verify_exited()

    def test_exited_before_fencing_cannot_create_historical_proof(self):
        proof = self.capture()
        self.stop_child()
        with self.assertRaisesRegex(ValueError, "exited before"):
            proof.fence_all()
        self.fence.assert_not_called()
        with self.assertRaises(ValueError):
            proof.verify_exited()

    def test_hosted_guard_default_refuses_retirement(self):
        # Call the real function captured before other tests patch it.
        with mock.patch.dict(os.environ, {}, clear=True), self.assertRaisesRegex(ValueError, "hosted disposable"):
            REAL_GUARD()


REAL_GUARD = retirement._require_disposable

if __name__ == "__main__":
    unittest.main()
