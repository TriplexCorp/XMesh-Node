#!/usr/bin/env python3
"""CI-only linked nonfinal Xray receipt / exact old PID stop regressions.

The fixture signs fake byte counters ONLY to test the cryptographic chain;
it never claims to create valid committed-policy bytes or final refunds.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments/quota-v2-physical-stop"))
import attestor
import stop_chain
import journal_integrity
import sign_observation as observed
import runtime_identity

NODE_ID = 9


class StopChainTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="xmesh-stop-chain-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.observed = self.root / "observed"
        self.stopped = self.root / "stopped"
        self.xray = self.root / "xray-meter-journal"
        self.observed.mkdir(mode=0o700)
        self.stopped.mkdir(mode=0o700)
        self.xray.mkdir(mode=0o700)
        self.key = self.root / "node.key"
        self.pub = self.root / "node.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519",
                        "-out", str(self.key)], check=True, capture_output=True)
        os.chmod(self.key, 0o600)
        subprocess.run(["openssl", "pkey", "-in", str(self.key),
                        "-pubout", "-out", str(self.pub)],
                       check=True, capture_output=True)
        self.child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(25)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop_child)
        self.before = self.docker(True)
        self.after = self.docker(False)
        self.cp = {
            "schemaVersion": 3,
            "nodeId": NODE_ID, "userId": 101,
            "email": "xmesh-u101--vless-main",
            "epoch": "11111111-1111-4111-8111-111111111111",
            "meterEpoch": "22222222-2222-4222-8222-222222222222",
            "reservationId": "33333333-3333-4333-8333-333333333333",
            "revision": 3,
            "revocationId": "44444444-4444-4444-8444-444444444444",
            "runtimeId": runtime_identity.trusted_runtime_identity(
                self.child.pid),
            "uplinkBytes": 7, "downlinkBytes": 13,
            "inboundMeters": [
                {"email": "xmesh-u101--vless-main",
                 "uplinkBytes": 7, "downlinkBytes": 13}],
            "drained": True, "finalMeterVerified": False,
            "refundableBytes": 0,
        }
        self.marker_helper = ROOT / "deploy/xmesh-quota-revocation-marker.py"
        subprocess.run(
            [sys.executable, str(self.marker_helper), "arm", str(self.root)],
            check=True, capture_output=True)
        self.original = self.publish_synthetic_receipt(self.cp)
        self.publish_xray_journal()

    def publish_xray_journal(self):
        self.stem = hashlib.sha256(b"xmesh-u101").hexdigest()
        fence = {k:self.cp[k] for k in journal_integrity.FIELDS}
        fence["schemaVersion"] = 1
        checkpoint = {k:self.cp[k] for k in journal_integrity.CHECKPOINT}
        for prefix,record in (("fence-",fence),("observed-",checkpoint)):
            filename = self.xray / (prefix + self.stem + ".json")
            filename.write_bytes(journal_integrity._canonical_go(record))
            filename.chmod(0o600)

    def docker(self, running):
        return {
            "Id": "a" * 64, "Name": "/xmesh-managed-xray",
            "State": {
                "Running": running,
                "Pid": self.child.pid if running else 0,
                "StartedAt": "2026-11-18T14:10:00Z"},
            "HostConfig": {"RestartPolicy": {
                "Name": "unless-stopped" if running else "no"}},
            "Mounts": [{
                "Type": "bind", "Source": str(self.xray),
                "Destination": journal_integrity.JOURNAL_DEST, "RW": True,
            }],
        }

    def stop_child(self):
        if self.child.poll() is None:
            self.child.terminate()
            self.child.wait(timeout=5)

    def publish_synthetic_receipt(self, cp, floor=True):
        # CI fixture with fake byte rows, NOT genuine signed-policy validation.
        payload = {
            "schemaVersion": 2,
            "kind": observed.KIND, "nodeId": NODE_ID,
            "checkpoint": cp,
            "checkpointSha256": hashlib.sha256(
                observed.canonical(cp)).hexdigest(),
            "boundToCommittedPolicy": True,
            "completeSignedInboundScopeObserved": True,
            "liveRuntimeIndependentlyVerified": True,
            "monotonicLedgerFloorVerified": floor,
            "durableAbsoluteFloorBytes": 20 if floor else 0,
            "finalMeterVerified": False, "settlementEligible": False,
            "refundableBytes": 0,
        }
        envelope = {
            "algorithm": "Ed25519", "payload": payload,
            "signature": observed.sign_bytes(
                self.key, observed.DOMAIN + observed.canonical(payload))}
        raw = observed.canonical(envelope) + b"\n"
        if not (self.observed / observed.receipt_name(cp)).exists():
            dfd = observed.private_directory(self.observed)
            try:
                observed.append_only(dfd, observed.receipt_name(cp), raw)
            finally:
                os.close(dfd)
        return raw

    def bound(self):
        with patch.object(attestor, "inspect_managed",
                          side_effect=[self.before, self.before]):
            probe = attestor.begin_old_xray_probe()
        try:
            with patch.object(attestor, "inspect_managed",
                              return_value=self.before):
                bound = stop_chain.prepare_old_process_stop(
                    probe, self.cp, self.observed, NODE_ID, self.pub, self.xray)
            return probe, bound
        except BaseException:
            probe.close()
            raise

    def complete(self, bound, **overrides):
        # The pidfd comes from an actual now-exited subprocess, while Docker
        # identity is deliberately mocked to exercise adversarial races.
        with patch.object(attestor, "inspect_managed",
                          side_effect=overrides.get(
                              "inspections", [self.after] * 4)):
            return stop_chain.complete_old_process_stop(
                bound, self.root, self.marker_helper,
                self.observed, self.stopped, self.key, self.pub)

    def test_same_pid_stop_chain_is_signed_nonfinal_and_idempotent(self):
        probe, bound = self.bound()
        with probe:
            self.stop_child()
            receipt = self.complete(bound)
            reread = self.complete(bound)
        self.assertEqual(receipt, reread)
        slot = self.stopped / (
            "stop-" + observed.receipt_name(self.cp))
        self.assertEqual(
            slot.read_bytes(), observed.canonical(receipt) + b"\n")
        self.assertEqual(slot.stat().st_mode & 0o777, 0o600)
        accepted = stop_chain.verify_stop_chain(
            receipt, self.original, NODE_ID, self.pub)
        self.assertEqual(accepted["oldContainerId"], "a" * 64)
        self.assertEqual(accepted["oldRuntimeId"], self.cp["runtimeId"])
        self.assertEqual(accepted["observationSha256"],
                         hashlib.sha256(self.original).hexdigest())
        self.assertTrue(accepted["oldPidfdExited"])
        self.assertFalse(accepted["finalMeterVerified"])
        self.assertFalse(accepted["settlementEligible"])
        self.assertEqual(accepted["refundableBytes"], 0)

    def test_still_live_pidfd_cannot_sign_stop(self):
        probe, bound = self.bound()
        with probe:
            with self.assertRaisesRegex(ValueError, "still running"):
                self.complete(bound)
        self.assertEqual(list(self.stopped.iterdir()), [])

    def test_different_docker_runtime_at_prepare_refused(self):
        with patch.object(attestor, "inspect_managed",
                          side_effect=[self.before, self.before]):
            probe = attestor.begin_old_xray_probe()
        with probe:
            other = copy.deepcopy(self.before)
            other["Id"] = "b" * 64
            with patch.object(attestor, "inspect_managed",
                              return_value=other):
                with self.assertRaisesRegex(ValueError, "changed"):
                    stop_chain.prepare_old_process_stop(
                        probe, self.cp, self.observed, NODE_ID, self.pub, self.xray)

    def test_missing_floor_and_wrong_node_key_refuse_prepare(self):
        probe, bound = self.bound()
        with probe:
            with self.assertRaises(ValueError):
                with patch.object(attestor, "inspect_managed",
                                  return_value=self.before):
                    stop_chain.prepare_old_process_stop(
                        probe, self.cp, self.observed, 10, self.pub, self.xray)
        self.assertEqual(list(self.stopped.iterdir()), [])

    def test_direct_pid_fixture_with_no_signed_durable_floor_refused(self):
        original = observed.strict_json(self.original)
        original["payload"]["monotonicLedgerFloorVerified"] = False
        original["payload"]["durableAbsoluteFloorBytes"] = 0
        original["signature"] = observed.sign_bytes(
            self.key, observed.DOMAIN + observed.canonical(original["payload"]))
        bad_bytes = observed.canonical(original) + b"\n"
        path = self.observed / observed.receipt_name(self.cp)
        path.write_bytes(bad_bytes)
        probe = None
        with patch.object(attestor, "inspect_managed",
                          side_effect=[self.before, self.before]):
            probe = attestor.begin_old_xray_probe()
        with probe, patch.object(attestor, "inspect_managed",
                                 return_value=self.before):
            with self.assertRaisesRegex(ValueError, "incomplete signed"):
                stop_chain.prepare_old_process_stop(
                    probe, self.cp, self.observed, NODE_ID, self.pub, self.xray)

    def test_observation_tamper_before_stop_publication_refused(self):
        probe, bound = self.bound()
        with probe:
            self.stop_child()
            path = self.observed / observed.receipt_name(self.cp)
            path.write_bytes(b'{"corrupt":true}\n')
            with self.assertRaises(ValueError):
                self.complete(bound)
        self.assertEqual(list(self.stopped.iterdir()), [])

    def test_swapped_or_restarted_docker_after_stop_refused(self):
        probe, bound = self.bound()
        with probe:
            self.stop_child()
            for name in ("different-container", "restarted"):
                with self.subTest(name=name):
                    wrong = copy.deepcopy(self.after)
                    if name == "different-container":
                        wrong["Id"] = "b" * 64
                    else:
                        wrong["State"]["Running"] = True
                        wrong["State"]["Pid"] = 999999
                    with self.assertRaises(ValueError):
                        self.complete(bound, inspections=[wrong] * 3)
            self.assertEqual(list(self.stopped.iterdir()), [])

    def test_marker_disappears_before_chain_publication(self):
        probe, bound = self.bound()
        with probe:
            self.stop_child()
            (self.root / "quota-revocation-deny-pending").unlink()
            with self.assertRaises(ValueError):
                self.complete(bound)
        self.assertEqual(list(self.stopped.iterdir()), [])

    def test_receipt_signature_and_refund_tamper_rejected(self):
        probe, bound = self.bound()
        with probe:
            self.stop_child()
            receipt = self.complete(bound)
        for corrupt in (
            lambda e: e["payload"].update(refundableBytes=1),
            lambda e: e["payload"].update(finalMeterVerified=True),
            lambda e: e["payload"].update(settlementEligible=True),
            lambda e: e["payload"].update(oldContainerId="b"*64),
            lambda e: e["payload"].update(observationSha256="f"*64),
            lambda e: e.update(signature="0"*128),
        ):
            forged = copy.deepcopy(receipt)
            corrupt(forged)
            with self.assertRaises(ValueError):
                stop_chain.verify_stop_chain(
                    forged, self.original, NODE_ID, self.pub)
        self.assertEqual(len(list(self.stopped.iterdir())), 1)

    def test_node_durable_slot_rejects_conflicting_replay(self):
        probe, bound = self.bound()
        with probe:
            self.stop_child()
            self.complete(bound)
            slot = self.stopped / (
                "stop-" + observed.receipt_name(self.cp))
            original = slot.read_bytes()
            slot.write_bytes(original[:-2] + b"xx")
            with self.assertRaisesRegex(ValueError, "conflicting"):
                self.complete(bound)
        self.assertNotEqual(slot.read_bytes(), original)


    def test_pre_stop_missing_xray_fence_or_observation_fails_closed(self):
        for name in ("fence-", "observed-"):
            with self.subTest(name=name):
                target = self.xray / (name + self.stem + ".json")
                original = target.read_bytes()
                target.unlink()
                try:
                    with self.assertRaises((ValueError, FileNotFoundError)):
                        self.bound()
                    self.assertEqual(list(self.stopped.iterdir()), [])
                finally:
                    target.write_bytes(original)
                    target.chmod(0o600)

    def test_pre_stop_unbound_docker_mount_cannot_claim_meter(self):
        with patch.object(attestor, "inspect_managed",
                          side_effect=[self.before,self.before]):
            probe=attestor.begin_old_xray_probe()
        with probe:
            wrong=copy.deepcopy(self.before)
            wrong["Mounts"][0]["Source"]=str(self.stopped)
            with patch.object(attestor,"inspect_managed",return_value=wrong):
                with self.assertRaisesRegex(ValueError,"bind actual managed Xray journal"):
                    stop_chain.prepare_old_process_stop(
                        probe,self.cp,self.observed,NODE_ID,self.pub,self.xray)
        self.assertEqual(list(self.stopped.iterdir()),[])

    def test_late_raw_counter_taint_after_snapshot_blocks_signed_stop(self):
        probe,bound=self.bound()
        with probe:
            self.stop_child()
            # The raw StatsService Add/Set audit writes this name before
            # changing any byte. A genuine old-PID exit does not erase it.
            marker=self.xray/("taint-"+self.stem+".json")
            marker.write_bytes(b'{"schemaVersion":1}\n')
            marker.chmod(0o600)
            with self.assertRaisesRegex(ValueError,"post-stop taint"):
                self.complete(bound)
        self.assertEqual(list(self.stopped.iterdir()),[])

    def test_old_xray_observed_bytes_change_after_prepare_refused(self):
        probe,bound=self.bound()
        with probe:
            self.stop_child()
            path=self.xray/("observed-"+self.stem+".json")
            obj=json.loads(path.read_bytes())
            obj["uplinkBytes"]+=1
            path.write_bytes(journal_integrity._canonical_go(obj))
            with self.assertRaises(ValueError):
                self.complete(bound)
        self.assertEqual(list(self.stopped.iterdir()),[])

    def test_crash_interrupted_pending_taint_blocks_signed_stop(self):
        probe,bound=self.bound()
        with probe:
            self.stop_child()
            path=self.xray/".taint-pending-deadbeef"
            path.write_bytes(b"possibly fsynced but unpublished")
            with self.assertRaisesRegex(ValueError,"uncertain or uncommitted"):
                self.complete(bound)
        self.assertEqual(list(self.stopped.iterdir()),[])

    def test_wrong_journal_mount_after_pid_exit_is_rejected(self):
        probe,bound=self.bound()
        with probe:
            self.stop_child()
            substituted=copy.deepcopy(self.after)
            substituted["Mounts"][0]["Source"]=str(self.stopped)
            with self.assertRaisesRegex(ValueError,"bind actual managed Xray journal"):
                self.complete(bound,inspections=[
                    self.after,self.after,substituted,self.after])
        self.assertEqual(list(self.stopped.iterdir()),[])

    def test_poststop_journal_permissions_and_symlinks_are_rejected(self):
        probe,bound=self.bound()
        with probe:
            self.stop_child()
            original=self.xray.stat().st_mode & 0o777
            self.xray.chmod(0o755)
            try:
                with self.assertRaisesRegex(ValueError,"not private"):
                    self.complete(bound)
            finally:
                self.xray.chmod(original)
        self.assertEqual(list(self.stopped.iterdir()),[])

if __name__ == "__main__":
    unittest.main()
