#!/usr/bin/env python3
"""No-authority successor meter regression. No production Docker/panel writes."""
import copy
import os
from pathlib import Path
import sys
import tempfile
import unittest

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
        expected = [
            "GITHUB_ACTIONS=true",
            "XMESH_EXPERIMENTAL_DRAIN=1",
            "XMESH_EXPERIMENTAL_OBSERVED_DIR=" + journal_integrity.JOURNAL_DEST,
            "XMESH_EXPERIMENTAL_SIGNED_CAP_BINDING=/run/xmesh/positive-cap-binding.json",
        ]
        container = {"Config": {"Env": list(expected)}}
        self.assertIsNone(successor_meter._verify_fresh_container_env(container))
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
