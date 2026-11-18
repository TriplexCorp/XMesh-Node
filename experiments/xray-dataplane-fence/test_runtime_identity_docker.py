#!/usr/bin/env python3
"""CI-only Docker process identity tests: no actual Docker daemon required."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runtime_identity as identity


class ManagedXrayRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.container = {
            "Id": "a" * 64,
            "Name": "/xmesh-managed-xray",
            "State": {
                "Pid": os.getpid(),
                "Running": True,
                "StartedAt": "2026-11-18T12:00:00.000000000Z",
            },
        }
        self.checkpoint = {
            "runtimeId": identity.trusted_runtime_identity(os.getpid()),
        }

    def response(self, data):
        return subprocess.CompletedProcess(
            args=["docker", "inspect"], returncode=0,
            stdout=json.dumps(data), stderr="")

    def test_real_procfs_matches_double_checked_managed_pid(self):
        replies = [self.response(self.container), self.response(self.container)]
        with patch.object(identity.subprocess, "run", side_effect=replies) as docker:
            self.assertTrue(identity.verify_managed_xray_runtime(self.checkpoint))
        self.assertEqual(docker.call_count, 2)
        for call in docker.call_args_list:
            self.assertEqual(call.args[0], [
                "docker", "inspect", "--format", "{{json .}}",
                "xmesh-managed-xray",
            ])
            self.assertTrue(call.kwargs["check"])
            self.assertEqual(call.kwargs["timeout"], 5)

    def test_container_replacement_between_inspects_refused(self):
        changed = copy.deepcopy(self.container)
        changed["Id"] = "b" * 64
        with patch.object(identity.subprocess, "run", side_effect=[
                self.response(self.container), self.response(changed)]):
            with self.assertRaisesRegex(ValueError, "replaced"):
                identity.verify_managed_xray_runtime(self.checkpoint)

    def test_wrong_pid_claim_does_not_supply_docker_identity(self):
        forged = {"runtimeId": "f" * 64}
        with patch.object(identity.subprocess, "run",
                          return_value=self.response(self.container)):
            with self.assertRaisesRegex(ValueError, "not the independently"):
                identity.verify_managed_xray_runtime(forged)

    def test_stopped_replaced_or_invalid_docker_state_refused(self):
        cases = [
            ("wrong-name", lambda d: d.update(Name="/another-container")),
            ("not-running", lambda d: d["State"].update(Running=False)),
            ("boolean-pid", lambda d: d["State"].update(Pid=True)),
            ("missing-pid", lambda d: d["State"].pop("Pid")),
            ("invalid-id", lambda d: d.update(Id="short")),
            ("stale", lambda d: d["State"].update(
                StartedAt="0001-01-01T00:00:00Z")),
            ("negative-pid", lambda d: d["State"].update(Pid=-1)),
        ]
        for name, mutate in cases:
            item = copy.deepcopy(self.container)
            mutate(item)
            with self.subTest(name=name), patch.object(
                    identity.subprocess, "run",
                    return_value=self.response(item)):
                with self.assertRaises(ValueError):
                    identity.verify_managed_xray_runtime(self.checkpoint)

    def test_docker_failure_is_not_equivalent_to_stopped_xray(self):
        for failure in (
            FileNotFoundError("docker absent"),
            subprocess.TimeoutExpired("docker inspect", 5),
            subprocess.CalledProcessError(1, ["docker", "inspect"]),
        ):
            with self.subTest(failure=str(failure)), patch.object(
                    identity.subprocess, "run", side_effect=failure):
                with self.assertRaisesRegex(ValueError, "unavailable"):
                    identity.verify_managed_xray_runtime(self.checkpoint)


if __name__ == "__main__":
    unittest.main()
