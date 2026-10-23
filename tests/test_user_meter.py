#!/usr/bin/env python3
"""Regression: user traffic samples are cumulative, restart-safe and idempotent."""
import importlib.util
import pathlib
import unittest

SOURCE = pathlib.Path(__file__).resolve().parents[1] / "deploy" / "xmesh-policy-guard.py"
SPEC = importlib.util.spec_from_file_location("xmesh_policy_guard", SOURCE)
guard = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(guard)


class MeterTests(unittest.TestCase):
    def test_counter_deltas_restart_and_per_inbound_consistency(self):
        state = {}
        state = guard.integrate_counters(state, {"7": 300}, "docker-a", 1000,
            {("7", "DE_VLESS"): {"uplink": 100, "downlink": 200}})
        self.assertEqual(state["users"]["7"]["total"], 300)
        key = '[7,"DE_VLESS"]'
        self.assertEqual(state["inbounds"][key]["totalUp"], 100)
        self.assertEqual(state["inbounds"][key]["totalDown"], 200)
        # Repeated samples must not count the same bytes twice.
        state = guard.integrate_counters(state, {"7": 300}, "docker-a", 1100,
            {("7", "DE_VLESS"): {"uplink": 100, "downlink": 200}})
        self.assertEqual(state["users"]["7"]["total"], 300)
        self.assertEqual(state["inbounds"][key]["totalUp"], 100)
        # Only newly observed traffic is added.
        state = guard.integrate_counters(state, {"7": 380}, "docker-a", 1200,
            {("7", "DE_VLESS"): {"uplink": 125, "downlink": 255}})
        self.assertEqual(state["users"]["7"]["total"], 380)
        self.assertEqual(state["inbounds"][key]["totalUp"], 125)
        # New Xray runtime resets raw counters but not durable totals.
        state = guard.integrate_counters(state, {"7": 30}, "docker-b", 1300,
            {("7", "DE_VLESS"): {"uplink": 10, "downlink": 20}})
        self.assertEqual(state["users"]["7"]["total"], 410)
        self.assertEqual(state["inbounds"][key]["totalUp"], 135)
        self.assertEqual(state["inbounds"][key]["totalDown"], 275)
        # A reset inside one runtime is treated as a new baseline.
        state = guard.integrate_counters(state, {"7": 8}, "docker-b", 1400,
            {("7", "DE_VLESS"): {"uplink": 4, "downlink": 4}})
        self.assertEqual(state["users"]["7"]["total"], 418)
        self.assertEqual(state["inbounds"][key]["totalUp"], 139)
        self.assertEqual(state["inbounds"][key]["totalDown"], 279)

    def test_no_stats_does_not_create_usage(self):
        state = guard.integrate_counters({}, None, None, 1000, None)
        self.assertEqual(state["users"], {})
        self.assertNotIn("inbounds", state)


if __name__ == "__main__":
    unittest.main()
