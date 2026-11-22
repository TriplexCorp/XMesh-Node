#!/usr/bin/env python3
"""Regression: another Node's acknowledged aggregate usage is not a local receipt.

V1 cannot cryptographically acknowledge a particular Node's unreported
offline bytes. The safe fallback preserves its original durable allowance.
"""
import copy
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location(
    "quota_guard_v1", ROOT / "deploy/xmesh-policy-guard-base.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)
UID = "550e8400-e29b-41d4-a716-446655440001"
CONFIG = {"inbounds": [{"tag": "MAIN", "protocol": "vless",
                         "settings": {"clients": [{"id": UID}]}}]}


def policy(node, used=0, issued=1000, budget=50, validity=100000):
    return {"nodeId": node, "issuedAtMs": issued, "validUntilMs": validity,
            "users": [{"userId": 1, "xrayId": UID, "expireAtMs": 90000,
                       "panelUsedBytes": used, "limitBytes": 100,
                       "offlineBudgetBytes": budget}]}


def step(p, ledger, total, offline, now, runtime="xray-a"):
    return guard.enforce(p, copy.deepcopy(CONFIG), ledger,
                         None if total is None else {"1": total},
                         runtime, offline, now)


class V1PartialAcknowledgementTests(unittest.TestCase):
    def test_other_node_report_does_not_refill_unacknowledged_local_spending(self):
        a, b = policy(1), policy(2)
        _, la, _ = step(a, {}, 0, False, 1000)
        _, lb, _ = step(b, {}, 0, False, 1000)
        _, la, _ = step(a, la, 40, True, 2000)
        _, lb, _ = step(b, lb, 10, True, 2000)
        self.assertEqual(la["users"]["1"]["total"], 40)
        # Only B's 10 bytes arrived in Nexus. A's 40 are still outstanding.
        refreshed = policy(1, used=10, issued=3000, budget=45)
        _, la, _ = step(refreshed, la, 40, False, 3000)
        self.assertEqual(la["users"]["1"]["anchor"], 0)
        self.assertEqual(la["users"]["1"]["panelUsedBytes"], 10)
        self.assertEqual(la["users"]["1"]["budget"], 45)
        _, la, denied = step(refreshed, la, 50, True, 4000)
        self.assertEqual(denied.get(UID), "quota")

    def test_repeated_panel_usage_reports_cannot_rebase_v1_offline_budget(self):
        p = policy(1)
        _, la, _ = step(p, {}, 0, False, 1000)
        _, la, _ = step(p, la, 30, True, 1500)
        for used, issued in ((5, 2000), (20, 3000), (45, 4000)):
            newer = policy(1, used=used, issued=issued)
            _, la, _ = step(newer, la, 30, False, issued)
            self.assertEqual(la["users"]["1"]["anchor"], 0)
        _, _, denied = step(newer, la, 50, True, 5000)
        self.assertEqual(denied.get(UID), "quota")

    def test_policy_expiry_refresh_restores_only_unspent_local_allowance(self):
        p = policy(1, validity=2000)
        _, la, _ = step(p, {}, 0, False, 1000)
        _, la, _ = step(p, la, 40, True, 1500)
        _, la, denied = step(p, la, 40, True, 2100)
        self.assertEqual(denied.get(UID), "policy-expired")
        newer = policy(1, used=10, issued=3000)
        _, la, denied = step(newer, la, 40, False, 3000)
        self.assertNotIn(UID, denied)
        self.assertEqual(la["users"]["1"]["anchor"], 0)
        _, _, denied = step(newer, la, 50, True, 4000)
        self.assertEqual(denied.get(UID), "quota")

    def test_runtime_restart_preserves_absolute_spending(self):
        p = policy(1)
        _, la, _ = step(p, {}, 0, False, 1000)
        _, la, _ = step(p, la, 30, True, 2000)
        la = json.loads(json.dumps(la))
        _, la, _ = step(p, la, 19, True, 3000, runtime="xray-b")
        self.assertEqual(la["users"]["1"]["total"], 49)
        _, _, denied = step(p, la, 20, True, 4000, runtime="xray-b")
        self.assertEqual(denied.get(UID), "quota")

    def test_missing_counter_remains_denied(self):
        p = policy(1)
        _, la, _ = step(p, {}, 0, False, 1000)
        _, _, denied = step(p, la, None, True, 2000)
        self.assertEqual(denied.get(UID), "unverified-traffic-counter")


if __name__ == "__main__":
    unittest.main()
