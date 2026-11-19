#!/usr/bin/env python3
"""Bound the pre-restart telemetry gap without claiming refundable final usage."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

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

    def test_missing_user_or_inbound_counters_fail_closed(self):
        before = self.journal.read_bytes()
        with self.assertRaisesRegex(ValueError, "missing revoked user counters"):
            self.capture(({}, "old-xray", {}))
        with self.assertRaisesRegex(ValueError, "missing revoked inbound counters"):
            self.capture(({"1": 0}, "old-xray", {}))
        self.assertEqual(self.journal.read_bytes(), before)

    def test_partial_or_regressed_runtime_counters_fail_closed(self):
        before = self.journal.read_bytes()
        sample = ({"1": 15}, "old-xray",
                  {("1", "MAIN"): {"uplink": 15, "downlink": 0}})
        with self.assertRaisesRegex(ValueError, "runtime does not match"):
            self.capture((sample[0], "new-xray", sample[2]))
        with self.assertRaisesRegex(ValueError, "totals disagree"):
            self.capture(({"1": 16}, "old-xray", sample[2]))
        with self.assertRaisesRegex(ValueError, "user counter regressed"):
            self.capture(({"1": 9}, "old-xray",
                          {("1", "MAIN"): {"uplink": 9, "downlink": 0}}))
        self.assertEqual(self.journal.read_bytes(), before)

    def test_inbound_counter_rollback_fails_closed(self):
        document = json.loads(self.journal.read_text())
        document["inbounds"] = {'[1,"MAIN"]': {
            "lastUp": 25, "lastDown": 1,
            "totalUp": 25, "totalDown": 1,
        }}
        self.journal.write_text(json.dumps(document))
        before = self.journal.read_bytes()
        with self.assertRaisesRegex(ValueError, "inbound counter regressed"):
            self.capture(({"1": 21}, "old-xray",
                          {("1", "MAIN"): {"uplink": 20, "downlink": 1}}))
        self.assertEqual(self.journal.read_bytes(), before)

    def test_missing_secondary_signed_inbound_fails_closed(self):
        before = self.journal.read_bytes()
        with self.assertRaisesRegex(ValueError, "missing revoked inbound counters"):
            self.capture(({"1": 15}, "old-xray",
                          {("1", "MAIN"): {"uplink": 15, "downlink": 0}}),
                         scope={1: {"MAIN", "CDN"}})
        self.assertEqual(self.journal.read_bytes(), before)

    def test_xray_runtime_replacement_during_statsquery_is_rejected(self):
        before = self.journal.read_bytes()
        responses = [
            Mock(stdout="container-A 2026-11-18T00:00:00Z"),
            Mock(stdout='{"stat":[{"name":"user>>>xmesh-u1--MAIN>>>traffic>>>uplink","value":"15"}]}'),
            Mock(stdout="container-B 2026-11-18T00:00:01Z"),
        ]
        with patch.object(guard.subprocess, "run", side_effect=responses) as run:
            counters, runtime_id, inbound = guard.get_counters()
        self.assertIsNone(counters)
        self.assertIsNone(runtime_id)
        self.assertIsNone(inbound)
        self.assertEqual(run.call_count, 3)
        self.assertEqual(self.journal.read_bytes(), before)

    def test_duplicate_or_malformed_xray_stats_fail_closed(self):
        name = "user>>>xmesh-u1--MAIN>>>traffic>>>uplink"
        for rows in (
            [{"name": name, "value": 15}, {"name": name, "value": 16}],
            [{"name": name, "value": "garbage"}],
        ):
            responses = [
                Mock(stdout="container-A 2026-11-18T00:00:00Z"),
                Mock(stdout=json.dumps({"stat": rows})),
                Mock(stdout="container-A 2026-11-18T00:00:00Z"),
            ]
            with self.subTest(rows=rows), patch.object(
                    guard.subprocess, "run", side_effect=responses):
                self.assertEqual(guard.get_counters(), (None, None, None))

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

    def test_revocation_marker_requires_a_valid_signed_policy(self):
        with patch.object(guard, "verify_envelope", return_value=self.policy):
            self.assertTrue(guard.pending_revocation_present(self.state, 7))
        with patch.object(guard, "verify_envelope",
                          side_effect=ValueError("Policy signature verification failed")):
            with self.assertRaisesRegex(ValueError, "signature"):
                guard.pending_revocation_present(self.state, 7)
        self.assertTrue((self.state / "policy-envelope.json.pending").exists())
        (self.state / "policy-envelope.json.pending").unlink()
        with self.assertRaisesRegex(ValueError, "Missing signed pending"):
            guard.pending_revocation_present(self.state, 7)

    def test_failed_signed_revocation_never_restores_old_xray_policy(self):
        shell = (ROOT / "deploy/xmesh-xray-sync.sh").read_text(encoding="utf-8")
        marker = '"$REVOCATION_MARKER"'
        self.assertIn('REVOCATION_MARKER="$STATE/quota-revocation-deny-pending"', shell)
        self.assertIn('PENDING_REVOCATION="$(python3 "$POLICY_GUARD" pending-revocation', shell)
        self.assertIn('REVOCATION_FAIL_CLOSED=true', shell)
        self.assertIn('stop_managed_xray_for_revocation || exit 1', shell)
        self.assertIn('Signed quota revocation pending: cached/offline policy cannot re-enable old Xray.', shell)
        self.assertIn('Signed quota revocation pending but policy guard unavailable', shell)
        self.assertEqual(shell.count('if [[ "$REVOCATION_FAIL_CLOSED" != true && "$OFFLINE_POLICY" != true && -f "$PREVIOUS" ]];then'), 3)
        self.assertEqual(shell.count('python3 "$DENY_HELPER" clear "$STATE"'), 2)
        self.assertIn('if [[ -e "$REVOCATION_MARKER" || -L "$REVOCATION_MARKER" ]];then stop_managed_xray_for_revocation', shell)
        self.assertLess(shell.index('PENDING_REVOCATION="$(python3'), shell.index('# An active signed GeoData manifest'))
        self.assertLess(shell.index('python3 "$DENY_HELPER" arm "$STATE"'), shell.index('docker rm -f xmesh-managed-xray'))
        # Non-revocation deployments retain the existing rollback path.
        self.assertIn('cp "$PREVIOUS" "$ACTIVE"', shell)
        self.assertIn(marker, shell)

    def test_revoked_xray_stop_uses_restart_disable_and_verifies_termination(self):
        shell = (ROOT / "deploy/xmesh-xray-sync.sh").read_text(encoding="utf-8")
        start = shell.index('stop_managed_xray_for_revocation() {')
        end = shell.index('\n}\n', start) + 2
        helper = shell[start:end]
        program = """
set -Eeuo pipefail
""" + helper + """
CALL_LOG="$(mktemp)"
RUNNING=true
docker() {
 case "$1" in
  info) return 0;;
  inspect) if [[ "$2" == "-f" ]]; then echo "$RUNNING"; else return 0; fi;;
  update) [[ "$2" == "--restart=no" ]] || return 1; echo restart-disabled >> "$CALL_LOG";;
  stop) RUNNING=false; echo stopped >> "$CALL_LOG";;
  kill) RUNNING=false; echo killed >> "$CALL_LOG";;
  *) return 1;;
 esac
}
stop_managed_xray_for_revocation
[[ "$RUNNING" == false ]]
cat "$CALL_LOG"
rm -f "$CALL_LOG"
"""
        good = subprocess.run(["bash", "-c", program], capture_output=True,
                              text=True, timeout=5)
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertIn("restart-disabled", good.stdout)
        self.assertIn("stopped", good.stdout)
        broken = subprocess.run(["bash", "-c",
            "set -Eeuo pipefail\n" + helper +
            "\ndocker() { return 1; }\nstop_managed_xray_for_revocation"],
            capture_output=True, text=True, timeout=5)
        self.assertNotEqual(broken.returncode, 0)
        self.assertIn("Docker unavailable", broken.stderr)

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
