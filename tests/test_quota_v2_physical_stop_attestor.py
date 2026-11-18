#!/usr/bin/env python3
"""CI-only old Xray PID death, Docker replacement and durable deny regressions."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "quota_stop_attestor", ROOT / "experiments/quota-v2-physical-stop/attestor.py")
attestor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(attestor)
HELPER = ROOT / "deploy/xmesh-quota-revocation-marker.py"


def docker_state(pid, running=True, restart="unless-stopped"):
    return {
        "Id": "a" * 64, "Name": "/xmesh-managed-xray",
        "State": {
            "Running": running, "Pid": pid if running else 0,
            "StartedAt": "2026-11-18T13:00:00Z",
        },
        "HostConfig": {"RestartPolicy": {"Name": restart}},
    }


class PhysicalStopProofTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(25)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop_child)
        self.before = docker_state(self.child.pid)

    def stop_child(self):
        if self.child.poll() is None:
            self.child.terminate()
            self.child.wait(timeout=5)

    def begin(self):
        with patch.object(attestor, "inspect_managed",
                          side_effect=[self.before, self.before]):
            return attestor.begin_old_xray_probe()

    def verify(self, probe, after=None, marker_ok=True):
        if after is None:
            after = docker_state(self.child.pid, False, "no")
        with patch.object(attestor, "inspect_managed",
                          side_effect=[after, after]), patch.object(
                attestor, "marker_armed",
                side_effect=None if marker_ok else ValueError("not armed")):
            return attestor.verify_old_xray_physically_stopped(
                probe, self.root, HELPER)

    def test_live_process_cannot_be_reported_stopped(self):
        with self.begin() as probe:
            with self.assertRaisesRegex(ValueError, "still running"):
                self.verify(probe)
        self.assertIsNone(probe.pidfd)

    def test_actual_old_pidfd_exit_and_durable_deny_is_nonfinal(self):
        with self.begin() as probe:
            old_pid = self.child.pid
            self.stop_child()
            record = self.verify(probe)
        self.assertEqual(probe.old_pid, old_pid)
        self.assertTrue(record["oldPidfdExited"])
        self.assertTrue(record["restartDisabled"])
        self.assertTrue(record["durableDenyArmed"])
        self.assertFalse(record["finalMeterVerified"])
        self.assertFalse(record["settlementEligible"])
        self.assertEqual(record["refundableBytes"], 0)

    def test_restart_policy_or_wrong_container_rejected_after_pid_exit(self):
        with self.begin() as probe:
            self.stop_child()
            variants = (
                docker_state(self.child.pid, False, "unless-stopped"),
                dict(docker_state(self.child.pid, False, "no"), Id="b"*64),
                docker_state(self.child.pid, True, "no"),
            )
            for altered in variants:
                with self.subTest(state=altered):
                    with self.assertRaises(ValueError):
                        self.verify(probe, altered)

    def test_durable_marker_loss_never_promotes_stop(self):
        with self.begin() as probe:
            self.stop_child()
            with self.assertRaisesRegex(ValueError, "not armed"):
                self.verify(probe, marker_ok=False)

    def test_restart_between_final_inspections_rejected(self):
        with self.begin() as probe:
            self.stop_child()
            stopped = docker_state(self.child.pid, False, "no")
            replacement = docker_state(self.child.pid, True, "no")
            with patch.object(attestor, "inspect_managed",
                              side_effect=[stopped, replacement]), patch.object(
                    attestor, "marker_armed", return_value=None):
                with self.assertRaisesRegex(ValueError, "restarted"):
                    attestor.verify_old_xray_physically_stopped(
                        probe, self.root, HELPER)

    def test_capture_rejects_replaced_or_dead_process(self):
        replaced = dict(self.before, Id="b"*64)
        with patch.object(attestor, "inspect_managed",
                          side_effect=[self.before, replaced]):
            with self.assertRaisesRegex(ValueError, "changed"):
                attestor.begin_old_xray_probe()
        self.stop_child()
        with patch.object(attestor, "inspect_managed",
                          side_effect=[self.before, self.before]):
            with self.assertRaisesRegex(ValueError, "exited"):
                attestor.begin_old_xray_probe()

    def test_real_production_marker_helper_is_required(self):
        with self.assertRaisesRegex(ValueError, "not armed"):
            attestor.marker_armed(self.root, HELPER)
        cmd = [sys.executable, str(HELPER), "arm", str(self.root)]
        subprocess.run(cmd, check=True, capture_output=True)
        attestor.marker_armed(self.root, HELPER)
        marker = self.root / "quota-revocation-deny-pending"
        self.assertEqual(marker.read_bytes(), b"signed-v2-deny\n")
        marker.unlink()
        marker.symlink_to(self.root / "forged-marker")
        with self.assertRaises(ValueError):
            attestor.marker_armed(self.root, HELPER)

    def test_inspector_refuses_fake_docker_state(self):
        variants = [
            dict(self.before, Name="/foreign"),
            dict(self.before, Id="f"),
            dict(self.before, State={}),
            dict(self.before, HostConfig={}),
            dict(self.before, State={"StartedAt": "0001-01-01T00:00:00Z"}),
        ]
        for variant in variants:
            with self.subTest(state=variant):
                result = subprocess.CompletedProcess(
                    ["docker"], 0, json.dumps(variant), "")
                with patch.object(attestor.subprocess, "run",
                                  return_value=result):
                    with self.assertRaises(ValueError):
                        attestor.inspect_managed()


if __name__ == "__main__":
    unittest.main()
