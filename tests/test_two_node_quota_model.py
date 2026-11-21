#!/usr/bin/env python3
"""Actual guard decisions with independent node ledgers; no network or signed-envelope validation."""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("quota_guard", ROOT / "deploy/xmesh-policy-guard-base.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
UID = "550e8400-e29b-41d4-a716-446655440001"
CONFIG = {"inbounds":[{"tag":"MAIN","protocol":"vless",
    "settings":{"clients":[{"id":UID}]}}]}


def policy(node, used=0, issued=1000, budget=50):
    return {"nodeId":node,"issuedAtMs":issued,"validUntilMs":100000,
        "users":[{"userId":1,"xrayId":UID,"expireAtMs":90000,
                  "panelUsedBytes":used,"limitBytes":100,"offlineBudgetBytes":budget}]}


def step(p, ledger, total, offline, now, runtime="xray-a"):
    return guard.enforce(p, copy.deepcopy(CONFIG), ledger,
                         None if total is None else {"1":total},
                         runtime, offline, now)


class TwoNodeQuotaTests(unittest.TestCase):
    def test_independent_nodes_cut_off_at_each_original_allowance(self):
        for node in (1,2):
            p = policy(node)
            _, ledger, _ = step(p, {}, 0, False, 1000)
            _, ledger, denied = step(p, ledger, 49, True, 2000)
            self.assertNotIn(UID, denied)
            _, ledger, denied = step(p, ledger, 50, True, 3000)
            self.assertEqual(denied[UID], "quota")

    def test_replay_process_reload_and_runtime_restart_preserve_spending(self):
        p = policy(1)
        _, ledger, _ = step(p, {}, 0, False, 1000)
        _, ledger, _ = step(p, ledger, 30, True, 2000)
        ledger = json.loads(json.dumps(ledger))
        _, ledger, _ = step(p, ledger, 30, True, 3000)
        self.assertEqual(ledger["users"]["1"]["total"], 30)
        _, ledger, denied = step(p, ledger, 19, True, 4000, "xray-b")
        self.assertEqual(ledger["users"]["1"]["total"], 49)
        self.assertNotIn(UID, denied)
        _, ledger, denied = step(p, ledger, 20, True, 5000, "xray-b")
        self.assertEqual(denied[UID], "quota")

    def test_missing_counters_and_expired_policy_fail_closed(self):
        p = policy(1)
        _, ledger, _ = step(p, {}, 0, False, 1000)
        _, _, denied = step(p, copy.deepcopy(ledger), None, True, 2000)
        self.assertEqual(denied[UID], "unverified-traffic-counter")
        _, _, denied = step(p, ledger, 0, True, 100001)
        self.assertEqual(denied[UID], "policy-expired")

    def test_other_node_report_does_not_refill_unacknowledged_local_spending(self):
        a, b = policy(1), policy(2)
        _, la, _ = step(a, {}, 0, False, 1000)
        _, lb, _ = step(b, {}, 0, False, 1000)
        _, la, _ = step(a, la, 40, True, 2000)
        _, lb, _ = step(b, lb, 10, True, 2000)
        # Model: only B's ten bytes reached Nexus; A's forty bytes did not.
        refreshed_a = policy(1, used=10, issued=3000, budget=45)
        _, la, _ = step(refreshed_a, la, 40, False, 3000)
        _, _, denied = step(refreshed_a, la, 50, True, 4000)
        self.assertEqual(denied.get(UID), "quota",
            "Global usage change must not acknowledge another node's unreported local spending")


    def test_counter_increases_and_decreases_from_other_node_never_refill(self):
        base = policy(1, used=0, issued=1000, budget=50)
        _, ledger, _ = step(base, {}, 0, False, 1000)
        _, ledger, _ = step(base, ledger, 48, True, 2000)
        for index, global_used in enumerate((10, 50, 11, 90, 0, 100), 1):
            new = policy(1, used=global_used,
                         issued=2000 + index * 1000, budget=64)
            _, ledger, _ = step(new, ledger, 48, False, 2000 + index * 1000)
            self.assertEqual(ledger["users"]["1"]["anchor"], 0)
            self.assertEqual(ledger["users"]["1"]["budget"], 50)
            self.assertEqual(ledger["users"]["1"]["total"], 48)
        _, _, denied = step(new, ledger, 50, True, 9800)
        self.assertEqual(denied[UID], "quota")

    def test_expiry_extension_recovers_time_only_and_not_local_bytes(self):
        p = policy(1, budget=50)
        _, ledger, _ = step(p, {}, 0, False, 1000)
        _, ledger, denied = step(p, ledger, 10, True, 100001)
        self.assertEqual(denied[UID], "policy-expired")
        renewed = policy(1, used=10, issued=101000, budget=64)
        renewed["validUntilMs"] = 200000
        renewed["users"][0]["expireAtMs"] = 180000
        _, ledger, denied = step(renewed, ledger, 10, False, 101000)
        self.assertNotIn(UID, denied)
        self.assertEqual(ledger["users"]["1"]["anchor"], 0)
        self.assertEqual(ledger["users"]["1"]["budget"], 50)
        _, ledger, denied = step(renewed, ledger, 50, True, 102000)
        self.assertEqual(denied[UID], "quota")

    def test_plan_increase_does_not_duplicate_shared_allowance(self):
        p = policy(1, budget=50)
        _, ledger, _ = step(p, {}, 0, False, 1000)
        _, ledger, denied = step(p, ledger, 50, True, 3000)
        self.assertEqual(denied[UID], "quota")
        upgraded = policy(1, used=50, issued=4000, budget=64)
        upgraded["users"][0]["limitBytes"] = 1000
        _, ledger, denied = step(upgraded, ledger, 50, False, 4000)
        self.assertEqual(denied[UID], "locally-revoked")
        self.assertEqual(ledger["users"]["1"]["budget"], 50)
        self.assertEqual(ledger["users"]["1"]["anchor"], 0)
        _, ledger, denied = step(upgraded, ledger, 51, True, 5000)
        self.assertEqual(denied[UID], "quota")

    def test_renewal_after_quota_exhaustion_cannot_turn_into_expiry_revocation(self):
        p = policy(1, budget=50)
        _, ledger, _ = step(p, {}, 0, False, 1000)
        _, ledger, _ = step(p, ledger, 50, True, 2000)
        _, ledger, denied = step(p, ledger, 50, True, 100001)
        self.assertEqual(ledger["users"]["1"]["revokedReason"], "quota")
        renewed = policy(1, used=100, issued=101000, budget=50)
        renewed["validUntilMs"] = 200000
        renewed["users"][0]["expireAtMs"] = 180000
        _, ledger, denied = step(renewed, ledger, 50, False, 101000)
        self.assertIn(UID, denied)
        self.assertTrue(ledger["users"]["1"]["revoked"])
        self.assertEqual(ledger["users"]["1"]["revokedReason"], "quota")

    def test_no_implicit_finite_to_unlimited_or_unlimited_to_finite_grant(self):
        limited = policy(1, budget=50)
        _, ledger, _ = step(limited, {}, 0, False, 1000)
        now_unlimited = policy(1, used=2, issued=3000, budget=None)
        now_unlimited["users"][0]["limitBytes"] = 0
        _, ledger, _ = step(now_unlimited, ledger, 49, False, 3000)
        self.assertEqual(ledger["users"]["1"]["budget"], 50)
        _, ledger, denied = step(now_unlimited, ledger, 50, True, 4000)
        self.assertEqual(denied[UID], "quota")
        original_unlimited = policy(2, budget=None)
        original_unlimited["users"][0]["limitBytes"] = 0
        _, ledger, _ = step(original_unlimited, {}, 0, False, 1000)
        then_limited = policy(2, used=9, issued=3000, budget=50)
        _, ledger, _ = step(then_limited, ledger, 9, False, 3000)
        self.assertEqual(ledger["users"]["1"]["budget"], 0)
        _, _, denied = step(then_limited, ledger, 9, True, 4000)
        self.assertEqual(denied[UID], "quota")

    def test_signed_decrease_cannot_expand_existing_node_allowance(self):
        p = policy(1, budget=50)
        _, ledger, _ = step(p, {}, 0, False, 1000)
        _, ledger, _ = step(p, ledger, 40, True, 2000)
        changed = policy(1, used=20, issued=3000, budget=45)
        _, ledger, _ = step(changed, ledger, 40, False, 3000)
        self.assertEqual(ledger["users"]["1"]["budget"], 45)
        _, _, denied = step(changed, ledger, 45, True, 4000)
        self.assertEqual(denied[UID], "quota")


if __name__ == "__main__":
    unittest.main()
