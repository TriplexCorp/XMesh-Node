#!/usr/bin/env python3
"""Bound the pre-restart telemetry gap without claiming refundable final usage."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("prestop_guard", ROOT / "deploy/xmesh-policy-guard-base.py")
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)


class PreStopCaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name)
        (self.state / "policy-envelope.json.pending").write_text("{}", encoding="utf-8")
        self.journal = self.state / "policy-usage.json"
        self.journal.write_text(json.dumps({
            "runtimeId": "old-xray",
            "users": {"1": {"total": 10, "last": 10}},
        }), encoding="utf-8")
        self.policy = {
            "users": [{
                "userId": 1,
                "quotaRevocation": {
                    "requestId": "44444444-4444-4444-8444-444444444444",
                    "epoch": "11111111-1111-4111-8111-111111111111",
                    "meterEpoch": "22222222-2222-4222-8222-222222222222",
                    "reservationId": "33333333-3333-4333-8333-333333333333",
                },
            }],
        }

    def capture(self, counters, scope=None):
        if scope is None:
            scope = {1: {"MAIN"}}
        with patch.object(guard, "verify_envelope", return_value=self.policy), \
             patch.object(guard, "committed_snapshot_scope", return_value=scope), \
             patch.object(guard, "get_counters", return_value=counters), \
             patch.object(guard, "store_metrics_snapshot") as snapshot:
            captured = guard.sample_before_xray_replace(self.state, 7, now_ms=1234)
            return captured, snapshot

    def test_preserves_old_xray_bytes_before_process_replacement(self):
        captured, snapshot = self.capture(({"1": 15}, "old-xray",
                                           {("1", "MAIN"): {"uplink": 15, "downlink": 0}}))
        self.assertTrue(captured)
        ledger = guard.load_json(self.journal)
        self.assertEqual(ledger["users"]["1"]["total"], 15)
        self.assertEqual(ledger["runtimeId"], "old-xray")
        self.assertNotIn("quotaRevocationApplied", ledger["users"]["1"])
        self.assertNotIn("quotaFinalMeter", ledger["users"]["1"])
        snapshot.assert_called_once()
        self.assertEqual(snapshot.call_args.args[1:3], (7, 1234))
        self.assertEqual(snapshot.call_args.args[3], {1: {"MAIN"}})
        # The new process restarts at zero; the durable old reading survives.
        restarted = guard.integrate_counters(ledger, {"1": 0}, "new-xray", 1235)
        restarted = guard.integrate_counters(restarted, {"1": 6}, "new-xray", 1236)
        self.assertEqual(restarted["users"]["1"]["total"], 21)

    def test_fails_closed_on_missing_stats_without_overwriting_journal(self):
        old_bytes = self.journal.read_bytes()
        with self.assertRaisesRegex(ValueError, "StatsService unavailable"):
            self.capture((None, None, None))
        self.assertEqual(self.journal.read_bytes(), old_bytes)

    def test_out_of_scope_user_and_inbound_cannot_poison_journal(self):
        old_bytes = self.journal.read_bytes()
        with self.assertRaisesRegex(ValueError, "user outside committed"):
            self.capture(({"1": 15, "99": 3}, "old-xray",
                          {("1", "MAIN"): {"uplink": 15, "downlink": 0}}))
        self.assertEqual(self.journal.read_bytes(), old_bytes)
        with self.assertRaisesRegex(ValueError, "inbound outside committed"):
            self.capture(({"1": 15}, "old-xray",
                          {("1", "OTHER"): {"uplink": 15, "downlink": 0}}))
        self.assertEqual(self.journal.read_bytes(), old_bytes)

    def test_fails_closed_without_committed_signed_scope(self):
        old_bytes = self.journal.read_bytes()
        with self.assertRaisesRegex(ValueError, "committed signed scope"):
            self.capture(({"1": 15}, "old-xray", {}), scope={})
        # Empty scope is deliberately rejected for users that require the
        # pre-stop sample; no unauthorised telemetry is published.
        self.assertEqual(self.journal.read_bytes(), old_bytes)

    def test_no_revocation_does_not_query_live_stats(self):
        empty = {"users": [{"userId": 1}]}
        with patch.object(guard, "verify_envelope", return_value=empty), \
             patch.object(guard, "get_counters") as stats:
            self.assertFalse(guard.sample_before_xray_replace(self.state, 7))
        stats.assert_not_called()

    def test_no_signed_pending_policy_fails_closed(self):
        (self.state / "policy-envelope.json.pending").unlink()
        with self.assertRaisesRegex(ValueError, "Missing signed pending policy"):
            guard.sample_before_xray_replace(self.state, 7)

    def test_shell_hook_is_opt_in_and_precedes_process_replacement(self):
        shell = (ROOT / "deploy/xmesh-xray-sync.sh").read_text(encoding="utf-8")
        guard_hook = 'python3 "$POLICY_GUARD" prestop-sample'
        old_process_removal = 'docker rm -f xmesh-managed-xray >/dev/null 2>&1 || true'
        self.assertEqual(shell.count(guard_hook), 1)
        hook_pos = shell.index(guard_hook)
        self.assertIn('XMESH_QUOTA_V2_PRESTOP_SAMPLE:-0', shell[:hook_pos])
        self.assertIn('"$POLICY_ENABLED" == true', shell[:hook_pos])
        self.assertIn('"$OFFLINE_POLICY" == false', shell[:hook_pos])
        self.assertIn('Old Xray revocation meter capture failed; refusing replacement.',
                      shell[hook_pos:hook_pos + 300])
        self.assertLess(hook_pos, shell.index(old_process_removal, hook_pos))
        # No "final meter" or refund response field is emitted by this hook.
        self.assertNotIn("quotaFinalMeter", shell)
        self.assertNotIn("quotaFinalReceipts", shell)


if __name__ == "__main__":
    unittest.main()
