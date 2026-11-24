#!/usr/bin/env python3
"""No-authority successor meter regression. No production Docker/panel writes."""
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments" / "quota-v2-physical-stop"))

import cap_install
import successor_meter


class IsolatedSuccessorMeterTests(unittest.TestCase):
    def setUp(self):
        self.runtime = ("a" * 64, "2026-11-22T00:00:00Z", 18181, "b" * 64)
        self.old = {
            "nodeId": 47, "userId": 101,
            "reservationId": "44444444-4444-4444-8444-444444444444",
        }
        self.prepared = {
            "meterEpoch": "55555555-5555-4555-8555-555555555555",
            "reservationId": "66666666-6666-4666-8666-666666666666",
        }
        self.marker = {
            "nodeId": 47, "userId": 101,
            "predecessorId": self.old["reservationId"],
            "successorSha256": "f" * 64,
            "candidateMeterEpoch": self.prepared["meterEpoch"],
            "candidateReservationId": self.prepared["reservationId"],
            "freshRuntimeId": self.runtime[3],
            "freshContainerId": self.runtime[0],
            "freshStartedAt": self.runtime[1],
            "freshHostPid": self.runtime[2],
            "freshExecutableSha256": "c" * 64,
            "freshConfigSha256": "d" * 64,
            "freshWalInventorySha256": successor_meter.EMPTY_SHA,
            "zeroInitialRawCounters": True, "isolatedNewWalRoot": True,
            "authorizedBytes": 0, "canSpend": False,
            "canStart": False, "canResume": False,
            "finalMeterVerified": False, "refundableBytes": 0,
        }
        self.scope = {
            "schemaVersion": 1, "nodeId": 47, "userId": 101,
            "nonce": "a" * 64, "meterEpoch": self.prepared["meterEpoch"],
            "reservationId": self.prepared["reservationId"],
            "aliases": [
                {"email": "xmesh-u101--vless-cdn", "class": "cdn"},
                {"email": "xmesh-u101--vless-main", "class": "main"},
            ],
        }
        self.receipt = {
            k: self.scope[k] for k in ("schemaVersion", "nodeId", "userId",
                                       "nonce", "meterEpoch", "reservationId")
        }
        self.receipt.update({
            "kind": "xmesh.quota-v2.fresh-meter-observed",
            "aliases": copy.deepcopy(self.scope["aliases"]),
            "runtimeId": self.runtime[3],
            "inventorySha256": successor_meter.EMPTY_SHA,
            "zeroInitialRawCounters": True, "isolatedNewWalRoot": True,
            "authorizedBytes": 0, "canSpend": False, "canStart": False,
            "canResume": False, "finalMeterVerified": False,
            "refundableBytes": 0,
        })

    def test_only_nonspending_preflight_is_accepted(self):
        self.assertEqual(
            successor_meter._checked_marker(
                self.marker, self.old, "f" * 64, self.runtime, self.prepared),
            self.marker)
        self.assertEqual(
            cap_install._verify_fresh_zero_meter_receipt(
                self.receipt, self.scope, self.runtime[3]), self.receipt)
        for key, bad in (
            ("canSpend", True), ("canStart", True),
            ("canResume", True), ("refundableBytes", 1),
            ("authorizedBytes", 1), ("finalMeterVerified", True),
            ("freshRuntimeId", "9" * 64), ("freshHostPid", 0),
            ("candidateMeterEpoch", self.old["reservationId"]),
            ("freshWalInventorySha256", "0" * 64),
            ("zeroInitialRawCounters", False),
            ("freshExecutableSha256", "x" * 64),
            ("isolatedNewWalRoot", False),
        ):
            with self.subTest(key=key):
                changed = copy.deepcopy(self.marker)
                changed[key] = bad
                with self.assertRaises(ValueError):
                    successor_meter._checked_marker(
                        changed, self.old, "f" * 64,
                        self.runtime, self.prepared)
        for key, bad in (
            ("runtimeId", "9" * 64), ("canSpend", True),
            ("canStart", True), ("canResume", True),
            ("zeroInitialRawCounters", False),
            ("authorizedBytes", 1), ("inventorySha256", "f" * 64),
            ("schemaVersion", True), ("nodeId", True),
            ("aliases", [self.scope["aliases"][0]]),
            ("refundableBytes", 1), ("finalMeterVerified", True),
        ):
            with self.subTest(receipt=key):
                changed = copy.deepcopy(self.receipt)
                changed[key] = bad
                with self.assertRaises(ValueError):
                    cap_install._verify_fresh_zero_meter_receipt(
                        changed, self.scope, self.runtime[3])

    def test_fresh_container_environment_is_bound_to_actual_wal_mount(self):
        import journal_integrity
        # sudo strips GITHUB_ACTIONS in Node CI. Model an actual host CI
        # explicitly here, instead of treating Docker's CI claim alone as
        # authorization outside the runner.
        ci_env = mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "true"})
        ci_env.start()
        self.addCleanup(ci_env.stop)
        # The CI label is not authority: even a real runner must have
        # the local root-only staging marker before trusting Docker env.
        import vless_ingress
        marker_guard = mock.patch.object(vless_ingress, "_staging_permitted",
                                         return_value=True)
        marker_check = marker_guard.start()
        self.addCleanup(marker_guard.stop)
        expected = [
            "GITHUB_ACTIONS=true",
            "XMESH_EXPERIMENTAL_DRAIN=1",
            "XMESH_EXPERIMENTAL_OBSERVED_DIR=" + journal_integrity.JOURNAL_DEST,
            "XMESH_EXPERIMENTAL_SIGNED_CAP_BINDING=/run/xmesh/positive-cap-binding.json",
        ]
        container = {"Config": {"Env": list(expected)}}
        self.assertIsNone(successor_meter._verify_fresh_container_env(container))
        marker_check.return_value = False
        with self.assertRaisesRegex(ValueError, "staging marker"):
            successor_meter._verify_fresh_container_env(container)
        marker_check.return_value = True
        for changed in (
            {"Config": {}},
            {"Config": {"Env": None}},
            {"Config": {"Env": [17]}},
            {"Config": {"Env": expected[:-1]}},
            {"Config": {"Env": expected + [expected[0]]}},
            {"Config": {"Env": expected + [expected[-1]]}},
            {"Config": {"Env": [
                "GITHUB_ACTIONS=false", *expected[1:]]}},
            {"Config": {"Env": [
                *expected[:2], "XMESH_EXPERIMENTAL_OBSERVED_DIR=/tmp/wal",
                expected[-1]]}},
            {"Config": {"Env": [
                *expected[:-1], "XMESH_EXPERIMENTAL_SIGNED_CAP_BINDING=relative.json"]}},
        ):
            with self.subTest(config=changed), self.assertRaises(ValueError):
                successor_meter._verify_fresh_container_env(changed)

    def test_outside_ci_requires_real_host_marker_not_docker_claim(self):
        import journal_integrity
        import vless_ingress
        base = [
            "XMESH_EXPERIMENTAL_DRAIN=1",
            "XMESH_EXPERIMENTAL_OBSERVED_DIR=" + journal_integrity.JOURNAL_DEST,
            "XMESH_EXPERIMENTAL_SIGNED_CAP_BINDING=/run/xmesh/positive-cap-binding.json",
        ]
        marker = "/etc/xmesh-quota-v2-staging"
        docker = {
            "Mounts": [{"Source": marker, "Destination": marker,
                        "Type": "bind", "RW": False}],
            "Config": {"Env": base + ["XMESH_QUOTA_V2_STAGING_RUNTIME=1"]},
        }
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}), \
                mock.patch.object(vless_ingress, "_staging_permitted", return_value=False):
            with self.assertRaisesRegex(ValueError, "staging marker"):
                successor_meter._verify_fresh_container_env(docker)
        with mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}), \
                mock.patch.object(vless_ingress, "_staging_permitted", return_value=True):
            self.assertIsNone(successor_meter._verify_fresh_container_env(docker))
            for invalid in (
                    dict(docker, Mounts=[]),
                    dict(docker, Mounts=[dict(docker["Mounts"][0], RW=True)]),
                    dict(docker, Mounts=[dict(docker["Mounts"][0], Source="/tmp/foreign")]),
                    dict(docker, Mounts=docker["Mounts"] * 2)):
                with self.subTest(mount=invalid["Mounts"]), self.assertRaisesRegex(
                        ValueError, "staging marker"):
                    successor_meter._verify_fresh_container_env(invalid)
            with self.assertRaisesRegex(ValueError, "staging marker"):
                successor_meter._verify_fresh_container_env({
                    "Config": {"Env": base + ["GITHUB_ACTIONS=true"]},
                })
            with self.assertRaisesRegex(ValueError, "staging marker"):
                successor_meter._verify_fresh_container_env({
                    "Config": {"Env": base + [
                        "GITHUB_ACTIONS=true", "XMESH_QUOTA_V2_STAGING_RUNTIME=1"]},
                })
            with self.assertRaises(ValueError):
                successor_meter._verify_fresh_container_env({
                    "Config": {"Env": base + [
                        "XMESH_QUOTA_V2_STAGING_RUNTIME=0"]},
                })

    def test_existing_generation_is_measured_not_trusted_by_docker_name(self):
        # An interrupted calendar launch can leave the deterministic Docker
        # name behind. Never mistake that name for a clean live successor.
        with tempfile.TemporaryDirectory() as state:
            name = successor_meter.container_for(
                self.old["userId"], self.old["reservationId"])
            ledger = Path(state) / name / "ledger"
            ledger.mkdir(parents=True, mode=0o700)
            source = "/etc/xray/source-pinned.json"
            old_runtime = ("1" * 64, self.runtime[1], 11111, "2" * 64)
            fresh = self.runtime
            predecessor = dict(self.old, runtimeId=old_runtime[3],
                               activationReceiptSha256="5" * 64)
            pinned = "6" * 64
            binding = ledger.parent / "cap-binding.json"
            original = successor_meter.wal_transport.observed.canonical({
                "nodeId": predecessor["nodeId"],
                "activationReceiptSha256": predecessor["activationReceiptSha256"],
                "policyPublicKey": pinned,
            })
            binding.write_bytes(original)
            binding.chmod(0o600)
            old_inspect = {
                "Image": "sha256:" + "3" * 64,
                "Mounts": [{"Type": "bind", "Destination": "/etc/xray/config.json",
                            "Source": source, "RW": False}],
            }
            current = {
                "Name": "/" + name, "Image": old_inspect["Image"],
                "Mounts": [
                    {"Type": "bind", "Destination": "/etc/xray/config.json",
                     "Source": source, "RW": False},
                    {"Type": "bind", "Destination":
                     successor_meter.wal_transport.journal.RUNTIME_DEST,
                     "Source": str(ledger.parent), "RW": True},
                ],
            }
            def inspect(candidate):
                if candidate == "xmesh-managed-xray":
                    return old_inspect, "/tmp/old-verified-wal"
                if candidate == name:
                    return current, str(ledger)
                raise ValueError("foreign container")

            def measure(pins, candidate):
                if candidate == "xmesh-managed-xray":
                    return old_runtime
                if candidate == name:
                    return fresh
                raise ValueError("foreign process")

            with (mock.patch.object(successor_meter.wal_transport,
                                    "_bound_journal", side_effect=inspect),
                  mock.patch.object(successor_meter.wal_transport,
                                    "_measure_quarantined_runtime", side_effect=measure) as measuring,
                  mock.patch.object(successor_meter, "_verify_fresh_container_env"),
                  mock.patch.object(successor_meter.wal_transport, "_panel_pin",
                                    return_value=pinned),
                  mock.patch.object(successor_meter, "_clean_mount") as clean):
                def check():
                    return successor_meter.verify_reusable_generation(
                        name, state, predecessor, "xmesh-managed-xray",
                        "c" * 64, "d" * 64, pinned)
                self.assertEqual(check(), name)
                self.assertEqual(measuring.call_count, 3)
                clean.assert_called_with("/tmp/old-verified-wal",
                                         str(ledger), fresh[3])
                measuring.reset_mock()
                current["Image"] = "sha256:" + "e" * 64
                with self.assertRaisesRegex(ValueError, "foreign Docker identity"):
                    check()
                current["Image"] = old_inspect["Image"]
                current["Mounts"][1]["Source"] = "/tmp/another-wal"
                with self.assertRaisesRegex(ValueError, "predecessor mounts"):
                    check()
                current["Mounts"][1]["Source"] = str(ledger.parent)
                current["Mounts"][0]["Source"] = "/tmp/other-config"
                with self.assertRaisesRegex(ValueError, "predecessor mounts"):
                    check()
                current["Mounts"][0]["Source"] = source
                binding.write_bytes(b"foreign binding")
                with self.assertRaisesRegex(ValueError, "foreign signed-cap binding"):
                    check()
                binding.write_bytes(original)
                (ledger / "positive-cap-u101.json").write_text("foreign")
                with self.assertRaisesRegex(ValueError, "signed spend or WAL"):
                    check()
                (ledger / "positive-cap-u101.json").unlink()
                (ledger / "meter-old-runtime.jsonl").write_text("not settled")
                with self.assertRaisesRegex(ValueError, "signed spend or WAL"):
                    check()
                (ledger / "meter-old-runtime.jsonl").unlink()
                with mock.patch.object(successor_meter.wal_transport,
                                       "_measure_quarantined_runtime",
                                       side_effect=ValueError("stopped Xray has no live PID")):
                    with self.assertRaisesRegex(ValueError, "no live PID"):
                        check()
                # No code path is allowed to run Docker start/rm on a
                # potentially funded but incompletely recorded successor.
                self.assertEqual(check(), name)

    def test_runtime_bind_keeps_ipc_out_of_wal_and_cannot_hide_old_debt(self):
        import journal_integrity as journal
        with tempfile.TemporaryDirectory() as source:
            ledger = Path(source, "ledger")
            ledger.mkdir(mode=0o700)
            binding = Path(source, "cap-binding.json")
            binding.write_bytes(b"{}")
            binding.chmod(0o600)
            mount = {"Source": source, "Destination": journal.RUNTIME_DEST,
                     "Type": "bind", "RW": True}
            setting = "XMESH_EXPERIMENTAL_OBSERVED_DIR=" + journal.RUNTIME_DEST + "/ledger"
            docker = {"Mounts": [mount], "Config": {"Env": [setting]}}
            self.assertEqual(journal._verify_mount(docker, str(ledger)), mount)
            with self.assertRaises(ValueError):
                journal._verify_mount(docker, source)
            for env in ([], [setting, setting], [setting + "/other"]):
                with self.subTest(env=env), self.assertRaises(ValueError):
                    journal._journal_binding(dict(docker, Config={"Env": env}))
            for dest in (journal.JOURNAL_DEST, journal.RUNTIME_DEST + "/ledger"):
                with self.subTest(dest=dest), self.assertRaises(ValueError):
                    journal._journal_binding(dict(docker, Mounts=[mount, dict(mount, Destination=dest)]))
            legacy = Path(source, "meter-old-runtime.jsonl")
            legacy.write_bytes(b"old debt")
            with self.assertRaisesRegex(ValueError, "historical state"):
                journal._verify_mount(docker, str(ledger))
            self.assertEqual(legacy.read_bytes(), b"old debt")
            legacy.unlink()
            ledger.rmdir()
            with tempfile.TemporaryDirectory() as other:
                ledger.symlink_to(other, target_is_directory=True)
                with self.assertRaisesRegex(ValueError, "symlink"):
                    journal._verify_mount(docker, str(ledger))

    def test_new_wal_root_is_private_distinct_and_empty(self):
        with tempfile.TemporaryDirectory(prefix="xmesh-meter-old-") as old:
            with tempfile.TemporaryDirectory(prefix="xmesh-meter-fresh-") as fresh:
                os.chmod(old, 0o700)
                os.chmod(fresh, 0o700)
                lock = Path(fresh) / "xray-instance.lock"
                lock.write_bytes(b"")
                lock.chmod(0o600)
                successor_meter._clean_mount(old, fresh)
                with self.assertRaisesRegex(ValueError, "shared with predecessor"):
                    successor_meter._clean_mount(fresh, fresh)
                stale = Path(fresh) / "meter-old-runtime.jsonl"
                stale.write_text("past-wal\n")
                with self.assertRaisesRegex(ValueError, "not a fresh"):
                    successor_meter._clean_mount(old, fresh)
                stale.unlink()
                lock.unlink()
                with self.assertRaisesRegex(ValueError, "no live Xray"):
                    successor_meter._clean_mount(old, fresh)
                lock.write_bytes(b"")
                lock.chmod(0o600)
                os.chmod(fresh, 0o755)
                with self.assertRaisesRegex(ValueError, "foreign or shared"):
                    successor_meter._clean_mount(old, fresh)


if __name__ == "__main__":
    unittest.main()
