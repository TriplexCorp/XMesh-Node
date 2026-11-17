#!/usr/bin/env python3
"""Signed-scope publication regression: never send retired Node metering rows."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("node_meter_scope", ROOT / "deploy/xmesh-policy-guard.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class MeterPublicationScopeTests(unittest.TestCase):
    def publish(self, ledger, scope):
        # No network and no writes to /run; inspect the exact serialized payload.
        with patch.object(guard.base, "write_atomic") as write, \
             patch.object(guard.base.Path, "is_dir", return_value=True), \
             patch.object(guard.base.grp, "getgrnam", side_effect=KeyError):
            guard.store_metrics_snapshot(ledger, 12, 2000, scope)
        return json.loads(write.call_args.args[1])

    def test_retired_inbound_and_other_user_are_not_published(self):
        history = guard.integrate_counters({}, {"7": 150, "8": 20}, "xray-a", 1000, {
            ("7", "CURRENT"): {"uplink": 60, "downlink": 40},
            ("7", "RETIRED"): {"uplink": 30, "downlink": 20},
            ("8", "UNASSIGNED"): {"uplink": 15, "downlink": 5},
        })
        unchanged = copy.deepcopy(history)
        active = self.publish(history, {7: {"CURRENT"}})
        self.assertEqual(active["userInboundTraffic"], [
            {"userId": 7, "inboundTag": "CURRENT", "uplinkBytes": 60, "downlinkBytes": 40},
        ])
        # Keep the historical 50 bytes in user-wide cumulative baselines:
        # removing an inbound must not be misinterpreted as a user reset.
        self.assertEqual(active["userTraffic"], [
            {"userId": 7, "uplinkBytes": 90, "downlinkBytes": 60},
        ])
        self.assertEqual(history, unchanged)
        self.assertEqual(history["users"]["8"]["total"], 20)
        self.assertIn('[7,"RETIRED"]', history["inbounds"])
        self.assertIn('[8,"UNASSIGNED"]', history["inbounds"])

        # Retry/idempotency and later reauthorization never reduce the
        # user-wide baseline or delete/duplicate historical inbound bytes.
        same = self.publish(history, {7: {"CURRENT"}})
        self.assertEqual(same, active)
        restored = self.publish(history, {7: {"CURRENT", "RETIRED"}})
        self.assertEqual(restored["userTraffic"], active["userTraffic"])
        self.assertEqual(len(restored["userInboundTraffic"]), 2)

        updated = guard.integrate_counters(history, {"7": 160}, "xray-a", 3000, {
            ("7", "CURRENT"): {"uplink": 65, "downlink": 45},
        })
        later = self.publish(updated, {7: {"CURRENT"}})
        self.assertEqual(later["userTraffic"][0]["uplinkBytes"], 95)
        self.assertEqual(later["userTraffic"][0]["downlinkBytes"], 65)

    def test_missing_scope_fails_closed_and_pending_policy_never_grants_rights(self):
        with self.assertRaisesRegex(ValueError, "signed telemetry scope"):
            guard.store_metrics_snapshot({}, 12, 1000, None)
        with tempfile.TemporaryDirectory() as directory:
            state = Path(directory)
            (state / "policy-envelope.json.pending").write_text("{}")
            self.assertIsNone(guard.committed_snapshot_scope(state, 12))

    def test_verified_account_mapping_uses_signed_transport_identity(self):
        uid1 = "550e8400-e29b-41d4-a716-446655440001"
        uid2 = "550e8400-e29b-41d4-a716-446655440002"
        # Independent non-UUID transport credentials still map to the
        # signed policy's stable xrayId through xmesh-u<ID>--<tag>.
        doc = {"config": {"inbounds": [
            {"tag": "DE", "protocol": "vless", "settings": {"decryption": "none", "clients": [
                {"id": uid1, "email": "xmesh-u7--DE"},
                {"id": uid2, "email": "xmesh-u8--DE"},
            ]}},
            {"tag": "NO", "protocol": "trojan", "settings": {"users": [
                {"password": "a" * 64, "email": "xmesh-u7--NO"},
            ]}},
        ]}}
        users = [{"userId": 7, "xrayId": uid1}, {"userId": 8, "xrayId": uid2}]
        with patch.object(guard.base, "verify_envelope", return_value={"users": users}) as verify:
            scope = guard.verified_snapshot_scope(doc, Path("/tmp/node-signed-scope-test"), 12)
        verify.assert_called_once()
        self.assertEqual(scope, {7: {"DE", "NO"}, 8: {"DE"}})
        bad_doc = copy.deepcopy(doc)
        bad_doc["config"]["inbounds"][1]["settings"]["users"][0]["email"] = "xmesh-u8--NO"
        with patch.object(guard.base, "verify_envelope", return_value={"users": users}):
            # The new identity is bound to the wrong independent credential
            # according to the supplied test. The full verifier additionally
            # enforces Ed25519 + config digest in production.
            changed = guard.verified_snapshot_scope(bad_doc, Path("/tmp"), 12)
        self.assertEqual(changed, {7: {"DE"}, 8: {"DE", "NO"}})


if __name__ == "__main__":
    unittest.main()
