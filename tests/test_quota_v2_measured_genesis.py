#!/usr/bin/env python3
"""CI-only zero-authority genesis: kernel runtime measurement, not an arbitrary claim.

This test uses an actual Linux child PID and pidfd but a mocked Docker
inspection. It does NOT prove user ingress closure or a paid reservation.
The future positive-admission code must use real Docker and live VLESS tests.
"""
import copy
from contextlib import ExitStack
from pathlib import Path
import subprocess
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments/quota-v2-physical-stop"))
import wal_transport
import runtime_identity


class MeasuredGenesisTests(unittest.TestCase):
    def setUp(self):
        self.node = 47
        self.cid = "a" * 64
        self.started = "2026-11-21T06:00:00Z"
        self.challenge = "c" * 64
        self.child = subprocess.Popen([sys.executable, "-c",
                                        "import time; time.sleep(15)"],
                                       stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL)
        self.addCleanup(self.stop_child)
        self.runtime = {
            "Id": self.cid, "Name": "/xmesh-managed-xray",
            "State": {"Running": True, "Pid": self.child.pid, "StartedAt": self.started},
            "HostConfig": {"NetworkMode": "none", "RestartPolicy": {"Name": "no"},
                           "PortBindings": {}, "Privileged": False,
                           "CapAdd": None, "CapDrop": ["ALL"], "PidMode": "",
                           "IpcMode": "private", "Devices": None,
                           "ReadonlyRootfs": True,
                           "SecurityOpt": ["no-new-privileges:true"]},
            "Mounts": [
                {"Destination": "/etc/xray/config.json", "Type": "bind"},
                {"Destination": wal_transport.journal.JOURNAL_DEST, "Type": "bind"}],
            "NetworkSettings": {"Networks": {"none": {}}, "Ports": {"443/tcp": None}},
        }

    def stop_child(self):
        if self.child.poll() is None:
            self.child.terminate()
            self.child.wait(timeout=5)

    def overrides(self, runtime=None, inspected=None):
        stack = ExitStack()
        self.addCleanup(stack.close)
        value = copy.deepcopy(self.runtime if runtime is None else runtime)
        stack.enter_context(mock.patch.object(wal_transport, "_bound_journal",
                                              return_value=(value, "/unused/test-wal")))
        reference = (value["Id"], value["State"]["StartedAt"], value["State"]["Pid"])
        stack.enter_context(mock.patch.object(
            runtime_identity, "inspect_managed_xray",
            return_value=reference if inspected is None else inspected))
        stack.enter_context(mock.patch.object(wal_transport.os, "geteuid", return_value=0))
        return stack

    def test_kernel_measured_candidate_is_passed_to_signed_zero_authority_prep(self):
        expected = runtime_identity.trusted_runtime_identity(self.child.pid)
        prepared = {"algorithm": "Ed25519",
                    "payload": {"candidateRuntimeId": expected,
                                "authorizedBytes": 0, "canStart": False,
                                "canResume": False},
                    "signature": "f" * 128}
        self.overrides()
        with mock.patch.object(wal_transport, "prepare_genesis",
                               return_value=prepared) as remote:
            result = wal_transport.prepare_measured_genesis(
                "https://disposable.example", self.node, self.challenge)
        self.assertEqual(result, prepared)
        remote.assert_called_once_with(
            "https://disposable.example", self.node, expected, self.challenge)
        self.assertFalse(result["payload"]["canStart"])
        self.assertFalse(result["payload"]["canResume"])
        self.assertEqual(result["payload"]["authorizedBytes"], 0)

    def test_network_restart_and_publication_settings_must_be_isolated(self):
        invalid = [
            lambda x: x["HostConfig"].update(NetworkMode="bridge"),
            lambda x: x["HostConfig"]["RestartPolicy"].update(Name="always"),
            lambda x: x["HostConfig"].update(PortBindings={"443/tcp": [{"HostPort": "443"}]}),
            lambda x: x["NetworkSettings"].update(Networks={"bridge": {}}),
            lambda x: x["NetworkSettings"]["Ports"].update({"443/tcp": [{"HostPort": "443"}]}),
            lambda x: x["State"].update(Running=False),
            lambda x: x.update(Name="/other-xray"),
        ]
        for change in invalid:
            case = copy.deepcopy(self.runtime)
            change(case)
            with self.subTest(case=case), ExitStack() as stack:
                stack.enter_context(mock.patch.object(wal_transport, "_bound_journal",
                                                      return_value=(case, "/unused")))
                stack.enter_context(mock.patch.object(wal_transport.os, "geteuid",
                                                      return_value=0))
                with mock.patch.object(wal_transport, "prepare_genesis") as sign:
                    with self.assertRaises(ValueError):
                        wal_transport.prepare_measured_genesis(
                            "https://disposable.example", self.node, self.challenge)
                    sign.assert_not_called()

    def test_only_anonymous_upstream_docker_volumes_are_allowed(self):
        candidate = copy.deepcopy(self.runtime)
        for destination, letter in (("/usr/local/etc/xray", "a"),
                                    ("/var/log/xray", "b")):
            candidate["Mounts"].append({
                "Destination": destination, "Type": "volume",
                "Driver": "local", "Name": letter * 64})
        self.overrides(runtime=candidate)
        expected = runtime_identity.trusted_runtime_identity(self.child.pid)
        with mock.patch.object(wal_transport, "prepare_genesis",
                               return_value={"authorizedBytes": 0,
                                             "canStart": False}) as signer:
            wal_transport.prepare_measured_genesis(
                "https://disposable.example", self.node, self.challenge)
            signer.assert_called_once_with(
                "https://disposable.example", self.node, expected, self.challenge)

    def test_privilege_and_host_namespace_escape_is_rejected(self):
        mutations = [
            lambda x: x["HostConfig"].update(Privileged=True),
            lambda x: x["HostConfig"].update(CapAdd=["SYS_ADMIN"]),
            lambda x: x["HostConfig"].update(CapDrop=[]),
            lambda x: x["HostConfig"].update(PidMode="host"),
            lambda x: x["HostConfig"].update(IpcMode="host"),
            lambda x: x["HostConfig"].update(ReadonlyRootfs=False),
            lambda x: x["HostConfig"].update(SecurityOpt=[]),
            lambda x: x["HostConfig"].update(SecurityOpt=["no-new-privileges:false"]),
            lambda x: x["HostConfig"].update(Devices=[{"PathOnHost": "/dev/sda"}]),
            lambda x: x["Mounts"].append({
                "Destination": "/var/run/docker.sock", "Type": "bind"}),
            lambda x: x["Mounts"].append({
                "Destination": "/var/log/xray", "Type": "bind"}),
            lambda x: x["Mounts"].append({
                "Destination": "/var/log/xray", "Type": "volume",
                "Driver": "local", "Name": "user-provided-volume"}),
            lambda x: x["Mounts"].append({
                "Destination": "/var/log/xray", "Type": "volume",
                "Driver": "evil-driver", "Name": "a" * 64}),
        ]
        for mutate in mutations:
            candidate = copy.deepcopy(self.runtime)
            mutate(candidate)
            with self.subTest(candidate=candidate), \
                 mock.patch.object(wal_transport, "_bound_journal",
                                   return_value=(candidate, "/unused")), \
                 mock.patch.object(wal_transport.os, "geteuid",
                                   return_value=0), \
                 mock.patch.object(wal_transport, "prepare_genesis") as remote:
                with self.assertRaisesRegex(ValueError, "hardened isolated"):
                    wal_transport.prepare_measured_genesis(
                        "https://disposable.example", self.node, self.challenge)
                remote.assert_not_called()

    def test_docker_kernel_pid_disagreement_fails_before_external_signature(self):
        self.overrides(inspected=(self.cid, self.started, self.child.pid + 1))
        with mock.patch.object(wal_transport, "prepare_genesis") as sign:
            with self.assertRaisesRegex(ValueError, "independently confirmed"):
                wal_transport.prepare_measured_genesis(
                    "https://disposable.example", self.node, self.challenge)
            sign.assert_not_called()

    def test_replacement_after_nexus_signing_does_not_return_receipt(self):
        first = (self.cid, self.started, self.child.pid, "e" * 64)
        replacement = ("b" * 64, self.started, self.child.pid, "f" * 64)
        with mock.patch.object(wal_transport.os, "geteuid", return_value=0), \
             mock.patch.object(wal_transport, "_measure_quarantined_runtime",
                               side_effect=[first, replacement]), \
             mock.patch.object(wal_transport, "prepare_genesis",
                               return_value={"payload": {"canStart": False}}) as issued:
            with self.assertRaisesRegex(ValueError, "changed during genesis"):
                wal_transport.prepare_measured_genesis(
                    "https://disposable.example", self.node, self.challenge)
            issued.assert_called_once()

    def test_network_attached_during_external_preparation_is_rejected(self):
        first = copy.deepcopy(self.runtime)
        connected = copy.deepcopy(self.runtime)
        connected["NetworkSettings"]["Networks"]["bridge"] = {"IPAddress": "172.18.0.2"}
        with mock.patch.object(wal_transport.os, "geteuid", return_value=0), \
             mock.patch.object(wal_transport, "_bound_journal",
                               side_effect=[(first, "/unused"), (connected, "/unused")]), \
             mock.patch.object(runtime_identity, "inspect_managed_xray",
                               return_value=(self.cid, self.started, self.child.pid)), \
             mock.patch.object(wal_transport, "prepare_genesis",
                               return_value={"payload": {"canStart": False}}) as signed:
            with self.assertRaisesRegex(ValueError, "network-isolated"):
                wal_transport.prepare_measured_genesis(
                    "https://disposable.example", self.node, self.challenge)
            signed.assert_called_once()

    def test_failure_to_obtain_pidfd_prevents_any_genesis_request(self):
        self.overrides()
        with mock.patch.object(runtime_identity.os, "pidfd_open",
                               side_effect=OSError("pidfd unavailable")), \
             mock.patch.object(wal_transport, "prepare_genesis") as sign:
            with self.assertRaises(OSError):
                wal_transport.prepare_measured_genesis(
                    "https://disposable.example", self.node, self.challenge)
            sign.assert_not_called()

    def test_invalid_identity_or_challenge_is_denied_without_inspection(self):
        for node, nonce in ((0, self.challenge), (self.node, "f"),
                            (self.node, "g" * 64)):
            with self.subTest(node=node, nonce=nonce), \
                 mock.patch.object(wal_transport.os, "geteuid", return_value=0), \
                 mock.patch.object(wal_transport, "_measure_quarantined_runtime") as inspect:
                with self.assertRaises(ValueError):
                    wal_transport.prepare_measured_genesis(
                        "https://disposable.example", node, nonce)
                inspect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
