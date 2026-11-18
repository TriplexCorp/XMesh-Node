#!/usr/bin/env python3
"""Quota-v2 must fail CLOSED on unverifiable same-runtime counter resets.

This deliberately latches an untrusted-byte-interval denial. A normal,
newer signed policy revision without a trusted terminal meter cannot erase
the uncertainty and issue more traffic to that same reservation.
"""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "xmesh_v2_meter_discontinuity", ROOT / "deploy/xmesh-policy-guard-base.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

UUID = "550e8400-e29b-41d4-a716-446655440001"


def lease(revision=1, ceiling=100):
    return {"epoch": "11111111-1111-4111-8111-111111111111",
            "meterEpoch": "22222222-2222-4222-8222-222222222222",
            "reservationId": "33333333-3333-4333-8333-333333333333",
            "revision": revision, "acknowledgedBytes": 0,
            "ceilingBytes": ceiling, "validUntilMs": 100_000}


def fixture():
    config = {"inbounds": [{"tag": "MAIN", "protocol": "vless",
                           "settings": {"clients": [{"id": UUID}]}}]}
    user = {"userId": 1, "xrayId": UUID, "expireAtMs": 90_000,
            "panelUsedBytes": 0, "limitBytes": 100,
            "offlineBudgetBytes": None, "quotaReservation": lease()}
    policy = {"version": 2, "nodeId": 1, "issuedAtMs": 1000,
              "validUntilMs": 100_000, "users": [user]}
    return policy, config


def count(up=20, down=0):
    return {("1", "MAIN"): {"uplink": up, "downlink": down}}


class MeterContinuityFailClosedTests(unittest.TestCase):
    def start(self):
        policy, config = fixture()
        effective, ledger, denied = guard.enforce(
            policy, copy.deepcopy(config), {},
            {"1": 20}, "xray-unchanged", False, 1000, count())
        self.assertEqual(denied, {})
        self.assertEqual(len(effective["inbounds"][0]["settings"]["clients"]), 1)
        self.assertEqual(ledger["users"]["1"]["total"], 20)
        self.assertNotIn("quotaMeterContinuityLost", ledger["users"]["1"])
        return policy, config, ledger

    def verify_sticky_denial(self, policy, config, ledger):
        # An online signed revision with a higher ceiling and resumed counter
        # still cannot prove the bytes missing before a raw counter reset.
        preserved = json.loads(json.dumps(ledger))
        policy["users"][0]["quotaReservation"] = lease(revision=2, ceiling=150)
        policy["issuedAtMs"] = 2000
        effective, returned, denied = guard.enforce(
            policy, copy.deepcopy(config), preserved,
            {"1": 100}, preserved["runtimeId"], False, 2000,
            count(up=100))
        self.assertEqual(denied.get(UUID), "quota-meter-continuity-lost")
        self.assertEqual(effective["inbounds"][0]["settings"]["clients"], [])
        self.assertEqual(
            returned["users"]["1"]["quotaMeterContinuityLost"],
            preserved["users"]["1"]["quotaMeterContinuityLost"])
        # Offline re-poll cannot remove the sticky signed-lease failure.
        _, _, denied = guard.enforce(
            policy, copy.deepcopy(config), returned,
            {"1": 100}, returned["runtimeId"], True, 2100, count(up=100))
        self.assertEqual(denied.get(UUID), "quota-meter-continuity-lost")

    def test_same_runtime_user_raw_reset_is_not_a_new_grant(self):
        policy, config, ledger = self.start()
        effective, ledger, denied = guard.enforce(
            policy, copy.deepcopy(config), ledger,
            {"1": 3}, "xray-unchanged", False, 1500, count(up=3))
        self.assertEqual(denied.get(UUID), "quota-meter-continuity-lost")
        self.assertEqual(
            ledger["users"]["1"]["quotaMeterContinuityLost"]["reason"],
            "regressed-xray-user-counter")
        self.assertEqual(effective["inbounds"][0]["settings"]["clients"], [])
        self.verify_sticky_denial(policy, config, ledger)

    def test_inbound_reset_even_if_aggregate_user_counter_advances(self):
        policy, config, ledger = self.start()
        _, ledger, denied = guard.enforce(
            policy, copy.deepcopy(config), ledger,
            {"1": 24}, "xray-unchanged", False, 1500, count(up=4, down=0))
        self.assertEqual(denied.get(UUID), "quota-meter-continuity-lost")
        self.assertEqual(
            ledger["users"]["1"]["quotaMeterContinuityLost"]["reason"],
            "regressed-xray-inbound-counter")
        self.verify_sticky_denial(policy, config, ledger)

    def test_missing_user_counter_after_positive_baseline_denies(self):
        policy, config, ledger = self.start()
        _, ledger, denied = guard.enforce(
            policy, copy.deepcopy(config), ledger,
            {}, "xray-unchanged", False, 1500, {})
        self.assertEqual(denied.get(UUID), "quota-meter-continuity-lost")
        self.assertEqual(
            ledger["users"]["1"]["quotaMeterContinuityLost"]["reason"],
            "missing-xray-user-counter")

    def test_missing_inbound_after_positive_baseline_denies(self):
        policy, config, ledger = self.start()
        _, ledger, denied = guard.enforce(
            policy, copy.deepcopy(config), ledger,
            {"1": 22}, "xray-unchanged", False, 1500, {})
        self.assertEqual(denied.get(UUID), "quota-meter-continuity-lost")
        self.assertEqual(
            ledger["users"]["1"]["quotaMeterContinuityLost"]["reason"],
            "missing-xray-inbound-counter")

    def test_new_docker_runtime_has_untrusted_old_tail(self):
        policy, config, ledger = self.start()
        _, ledger, denied = guard.enforce(
            policy, copy.deepcopy(config), ledger,
            {"1": 2}, "new-xray-runtime", False, 1600, count(up=2))
        self.assertEqual(denied.get(UUID), "quota-meter-continuity-lost")
        self.assertEqual(
            ledger["users"]["1"]["quotaMeterContinuityLost"]["reason"],
            "unverified-xray-runtime-transition")
        self.assertEqual(ledger["users"]["1"]["total"], 22)
        self.verify_sticky_denial(policy, config, ledger)

    def test_first_zero_fresh_xray_sample_does_not_lock_new_reservation(self):
        policy, config = fixture()
        _, ledger, denied = guard.enforce(
            policy, copy.deepcopy(config), {},
            {"1": 0}, "fresh-xray-runtime", False, 1000, count(up=0))
        self.assertEqual(denied, {})
        self.assertNotIn("quotaMeterContinuityLost", ledger["users"]["1"])

    def test_legacy_restart_and_reset_behavior_stays_compatible(self):
        record = {"users": {"1": {"last": 20, "total": 20}},
                  "runtimeId": "legacy-old",
                  "inbounds": {'[1,"MAIN"]': {
                      "lastUp": 20, "lastDown": 0,
                      "totalUp": 20, "totalDown": 0}}}
        reset = guard.integrate_counters(
            record, {"1": 2}, "legacy-old", 1500, count(up=2))
        self.assertNotIn("quotaMeterContinuityLost", reset["users"]["1"])
        updated = guard.integrate_counters(
            reset, {"1": 3}, "legacy-new", 1600, count(up=3))
        self.assertNotIn("quotaMeterContinuityLost", updated["users"]["1"])


if __name__ == "__main__":
    unittest.main()
