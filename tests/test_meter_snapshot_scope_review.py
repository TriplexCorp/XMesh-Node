#!/usr/bin/env python3
"""Characterize retained meter history versus published scope; no network/files written."""
import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("meter_scope_review",
    ROOT / "deploy/xmesh-policy-guard-base.py")
meter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(meter)


class SnapshotScopeReview(unittest.TestCase):
    def test_retired_inbound_is_still_published_from_durable_history(self):
        ledger = meter.integrate_counters({}, {"7": 30, "8": 60}, "runtime-a", 1000,
            {("7","ACTIVE"):{"uplink":10,"downlink":20},
             ("8","RETIRED"):{"uplink":20,"downlink":40}})
        # A later Xray observation contains only the still-active account.
        ledger = meter.integrate_counters(ledger, {"7": 45}, "runtime-a", 2000,
            {("7","ACTIVE"):{"uplink":15,"downlink":30}})
        with patch.object(meter, "write_atomic") as write, \
             patch.object(meter.Path, "is_dir", return_value=True), \
             patch.object(meter.grp, "getgrnam", side_effect=KeyError):
            meter.store_metrics_snapshot(ledger, 1, 2000)
        snapshot = json.loads(write.call_args.args[1])
        self.assertEqual({row["userId"] for row in snapshot["userTraffic"]}, {7,8})
        self.assertEqual(ledger["users"]["8"]["total"], 60)
        self.assertEqual(next(row for row in snapshot["userTraffic"]
                              if row["userId"]==7)["uplinkBytes"], 15)
        # Characterization only: this proves retention/publication behavior,
        # not that retaining history is itself wrong or a runtime fix.


if __name__ == "__main__":
    unittest.main()
