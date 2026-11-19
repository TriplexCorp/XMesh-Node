#!/usr/bin/env python3
"""The REAL production Xray synchronizer must deny unverifiable offline quota.

Test the embedded offline lifetime check as code, plus the physical Docker
stop helper with a fake Docker binary. Never involve production containers.
No final Xray meter or refundable byte proof is inferred.
"""
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SHELL = (ROOT / "deploy/xmesh-xray-sync.sh").read_text(encoding="utf-8")
PY_START = '<<\'PYCACHE\'\n'
PY_END = '\nPYCACHE\n'
assert SHELL.count(PY_START) == 1 and SHELL.count(PY_END) == 1
CHECK = SHELL.split(PY_START, 1)[1].split(PY_END, 1)[0]
MATCH_STOP = re.search(
    r"(?ms)^stop_managed_xray_for_revocation\(\) \{\n.*?^\}\n", SHELL)
MATCH_CUTOFF = re.search(
    r"(?ms)^stop_managed_xray_for_invalid_offline_policy\(\) \{\n.*?^\}\n",
    SHELL)
assert MATCH_STOP is not None and MATCH_CUTOFF is not None
STOP = MATCH_STOP.group() + MATCH_CUTOFF.group()


class OfflinePolicyCutoff(unittest.TestCase):
    def status(self, *, expiry, now_floor=0, issued=1000, malformed=False):
        with tempfile.TemporaryDirectory() as td:
            policy, ledger = (Path(td) / p for p in ("policy.json", "ledger.json"))
            envelope = ({"policy": {"issuedAtMs": issued, "validUntilMs": expiry}}
                        if not malformed else {"bad": 1})
            policy.write_text(json.dumps(envelope), encoding="utf-8")
            ledger.write_text(json.dumps({"maxSeenMs": now_floor}), encoding="utf-8")
            result = subprocess.run(
                [sys.executable, "-", str(policy), str(ledger)],
                input=CHECK, text=True, capture_output=True, check=False, timeout=5)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(result.stdout.strip(), {"live", "expired", "invalid"})
            return result.stdout.strip()

    def test_signed_policy_expired_is_cut_off_before_xray_reconcile(self):
        self.assertEqual(self.status(expiry=10_000), "expired")
        self.assertEqual(self.status(expiry=100_000, now_floor=100_000), "expired")

    def test_high_water_from_ledger_prevents_clock_rollback_revival(self):
        # Future on wall clock does NOT erase the previously durable clock.
        self.assertEqual(
            self.status(expiry=1_999_999_999_000,
                        issued=1_999_999_999_000 - 86_400_000,
                        now_floor=2_000_000_000_000),
            "expired")

    def test_malformed_or_invalid_lifetime_denied(self):
        self.assertEqual(self.status(expiry=100_000, malformed=True), "invalid")
        self.assertEqual(self.status(expiry=1000, issued=1000), "invalid")
        self.assertEqual(self.status(expiry=900 * 86400000, issued=1000), "invalid")

    def test_valid_future_cache_may_continue_only_after_signature_guard(self):
        future = 2_000_000_000_000
        self.assertEqual(self.status(expiry=future, issued=future - 86_400_000), "live")
        self.assertIn('python3 "$POLICY_GUARD" offline --state "$STATE"', SHELL)
        # Metadata 'live' is never enough to bypass the verified guard.
        branch = SHELL[
            SHELL.index('CACHED_LIFETIME="$(python3 - '):
            SHELL.index('PENDING_REVOCATION="$(python3 ')]
        self.assertIn('if [[ "$CACHED_LIFETIME" != live ]];then', branch)
        self.assertIn('python3 "$POLICY_GUARD" offline', branch)

    def test_unverifiable_cache_and_failed_guard_stop_physical_xray(self):
        missing = SHELL.index('if [[ ! -s "$STATE/policy-envelope.json" ]];then')
        failed = SHELL.index('python3 "$POLICY_GUARD" offline --state "$STATE"')
        expired = SHELL.index('if [[ "$CACHED_LIFETIME" != live ]];then')
        self.assertIn("stop_managed_xray_for_invalid_offline_policy", SHELL[missing:missing + 270])
        self.assertIn("stop_managed_xray_for_invalid_offline_policy", SHELL[failed:failed + 320])
        self.assertIn("stop_managed_xray_for_invalid_offline_policy", SHELL[expired:expired + 330])
        self.assertNotIn("No valid cached offline policy; leaving existing Xray intact", SHELL)
        self.assertNotIn("No previously issued signed offline policy; existing Xray untouched", SHELL)
        self.assertIn("stop_managed_xray_for_invalid_offline_policy || exit 1", SHELL)

    def test_offline_reconciliation_error_trap_cannot_restore_old_users(self):
        # A VALID cached policy can revoke a user due to quota exhaustion.
        # If a later Docker/TLS/GeoData/router stage fails, preserving or
        # rolling back an old config would re-admit that revoked identity.
        # No online/offline transition may briefly restart an obsolete
        # configured user set before the exit cutoff executes.
        self.assertNotIn('cp "$PREVIOUS" "$ACTIVE"', SHELL)
        self.assertNotIn('&& -f "$PREVIOUS" ]];then', SHELL)
        trap = SHELL.split("trap 'rc=$?;", 1)[1].split("' EXIT", 1)[0]
        self.assertIn(
            'if [[ "$rc" -ne 0 ]];then stop_managed_xray_for_invalid_offline_policy',
            trap,
        )
        self.assertIn('if [[ -e "$REVOCATION_MARKER" || -L "$REVOCATION_MARKER" ]]', trap)


    def test_missing_guard_cannot_leave_old_xray_running_during_panel_failure(self):
        # Execute the REAL production response branch with a fake Docker, not
        # merely a copy of the expected shell logic. No live VPS is involved.
        start = SHELL.index(
            'if [[ "$HTTP_STATUS" != 200 && "$POLICY_ENABLED" != true ]];then')
        end = SHELL.index("# The control agent owns reactivation.", start)
        response_branch = SHELL[start:end]
        self.assertNotIn("existing Xray untouched", response_branch)
        for http_status in ("000", "403", "503"):
            with self.subTest(http_status=http_status):
                with tempfile.TemporaryDirectory() as td:
                    state = Path(td) / "running"
                    restart = Path(td) / "restart"
                    state.write_text("true", encoding="ascii")
                    script = """set -Eeuo pipefail
STATE_FILE="$1"
RESTART_FILE="$2"
HTTP_STATUS="$3"
POLICY_ENABLED=false
OFFLINE_POLICY=true
docker() {
 case "$1" in
  info) return 0;;
  inspect)
   if [[ "$2" == "-f" ]];then cat "$STATE_FILE";else return 0;fi;;
  update)
   [[ "$2" == "--restart=no" ]] || return 1
   printf 'disabled\n' > "$RESTART_FILE";;
  stop|kill) printf 'false\n' > "$STATE_FILE";;
  *) return 1;;
 esac
}
""" + STOP + response_branch
                    result = subprocess.run(
                        ["bash", "-c", script, "_", str(state), str(restart),
                         http_status],
                        text=True, capture_output=True, check=False, timeout=5)
                    self.assertNotEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(state.read_text().strip(), "false")
                    self.assertEqual(restart.read_text().strip(), "disabled")
                    self.assertIn("CRITICAL", result.stderr)


    def test_early_failure_trap_precedes_identity_helper_and_journal_checks(self):
        # The real EXIT trap is registered before sourcing local identity,
        # parsing the durable ledger, verifying deny helper or network work.
        trap_match = re.search(r"(?m)^trap 'rc=\$\?;.*' EXIT$", SHELL)
        self.assertIsNotNone(trap_match)
        trap_line = trap_match.group()
        self.assertLess(SHELL.index(trap_line), SHELL.index("source /etc/xmesh-node-metrics.env"))
        self.assertLess(SHELL.index(trap_line), SHELL.index('[[ -f "$DENY_HELPER"'))
        self.assertLess(SHELL.index(trap_line), SHELL.index('REQUEST="$(python3 -'))
        self.assertLess(SHELL.index(trap_line), SHELL.index('if flock -n -E 75 9;then'))
        self.assertIn('if [[ "$rc" -ne 0 ]];then stop_managed_xray_for_invalid_offline_policy',
                      trap_line)
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "running"
            restarted = Path(td) / "restart"
            state.write_text("true")
            program = """set -Eeuo pipefail
STATE_FILE="$1"; RESTART_FILE="$2"
STATE="$3"; REVOCATION_MARKER="$STATE/missing-marker"
GEO_WORKER="$STATE/missing-geodata"
SIGN_FILE=""; RESP_FILE=""; CONFIG_FILE=""
docker() {
 case "$1" in
  info) return 0;;
  inspect) if [[ "$2" == "-f" ]];then cat "$STATE_FILE";else return 0;fi;;
  update) [[ "$2" == "--restart=no" ]] || return 1
          printf 'disabled\\n' > "$RESTART_FILE";;
  stop|kill) printf 'false\\n' > "$STATE_FILE";;
  *) return 1;;
 esac
}
""" + STOP + trap_line + """
# Simulates missing local identity, corrupt JSON or a failed preflight command.
false
"""
            result = subprocess.run(
                ["bash", "-c", program, "_", str(state), str(restarted), td],
                capture_output=True, text=True, check=False, timeout=5)
            self.assertNotEqual(result.returncode, 0, result.stderr)
            self.assertEqual(state.read_text().strip(), "false")
            self.assertEqual(restarted.read_text().strip(), "disabled")

    def test_guard_missing_even_on_http_200_denies_managed_xray(self):
        # The gate is unconditional after detection of missing/disabled guard,
        # before parsing an allegedly valid HTTP 200 desired config.
        gate = SHELL.index('if [[ "$POLICY_ENABLED" != true ]];then')
        self.assertLess(gate, SHELL.index('printf \'XMESH1\\nPOST'))
        self.assertLess(gate, SHELL.index('if [[ "$HTTP_STATUS" == 202 ]];then'))
        if_fragment = SHELL[gate:SHELL.index('fi\n', gate)+3]
        self.assertIn('exit 1', if_fragment)
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "running"
            state.write_text("true")
            script = """set -Eeuo pipefail
STATE_FILE="$1"
POLICY_ENABLED=false; HTTP_STATUS=200
docker() {
 case "$1" in
  info) return 0;;
  inspect) if [[ "$2" == "-f" ]];then cat "$STATE_FILE";else return 0;fi;;
  update) return 0;;
  stop|kill) printf 'false\\n' > "$STATE_FILE";;
  *) return 1;;
 esac
}
""" + STOP + if_fragment
            # The extracted gate exits nonzero, but it must also invoke
            # physical stop through the startup EXIT trap in production.
            script = script.replace(if_fragment, (
                "trap 'rc=$?; if [[ $rc -ne 0 ]];then "
                "stop_managed_xray_for_invalid_offline_policy;fi' EXIT\n"
                + if_fragment))
            result = subprocess.run(["bash", "-c", script, "_", str(state)],
                                    capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(state.read_text().strip(), "false")

    def test_unexpected_202_body_physically_stops_old_xray(self):
        # Invalid profile-assignment body must never be a keep-alive path.
        start = SHELL.index('if [[ "$HTTP_STATUS" == 202 ]];then')
        end = SHELL.index('# An unrelated 403', start)
        branch = SHELL[start:end]
        trap_line = re.search(r"(?m)^trap 'rc=\$\?;.*' EXIT$", SHELL).group()
        with tempfile.TemporaryDirectory() as td:
            state = Path(td) / "running"
            state.write_text("true")
            response = Path(td) / "response.json"
            response.write_text('{"status":"awaiting_profile","nodeId":999}')
            program = """set -Eeuo pipefail
STATE_FILE="$1"; RESP_FILE="$2"; STATE="$3"
REVOCATION_MARKER="$STATE/missing-marker"
GEO_WORKER="$STATE/missing-geodata"
SIGN_FILE=""; CONFIG_FILE=""
XMESH_NODE_ID=7; HTTP_STATUS=202
docker() {
 case "$1" in
  info) return 0;;
  inspect) if [[ "$2" == "-f" ]];then cat "$STATE_FILE";else return 0;fi;;
  update) return 0;;
  stop|kill) printf 'false\\n' > "$STATE_FILE";;
  *) return 1;;
 esac
}
""" + STOP + trap_line + "\n" + branch
            result = subprocess.run(
                ["bash", "-c", program, "_", str(state), str(response), td],
                capture_output=True, text=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("Unexpected HTTP 202", result.stderr)
            self.assertEqual(state.read_text().strip(), "false")

    def test_forced_stop_marker_also_checks_physical_xray_stop(self):
        branch = SHELL[SHELL.index(
            'if [[ -f /var/lib/xmesh-node-control/forced-stop ]];then'):
            SHELL.index('if [[ -f "$REVOCATION_MARKER" && "$HTTP_STATUS" != 200 ]]')]
        self.assertIn('stop_managed_xray_for_invalid_offline_policy || exit 1', branch)

    def test_no_docker_restart_and_actual_stopped_state(self):
        shell = """set -Eeuo pipefail
RUNNING=true
UPDATES=0
STOPS=0
docker() {
 case "$1" in
  info) return 0;;
  inspect)
   if [[ "$2" == "-f" ]];then echo "$RUNNING";else return 0;fi;;
  update) [[ "$2" == "--restart=no" ]] || return 1; UPDATES=$((UPDATES+1));;
  stop) RUNNING=false; STOPS=$((STOPS+1));;
  kill) RUNNING=false;;
  *) return 1;;
 esac
}
""" + STOP + """
stop_managed_xray_for_invalid_offline_policy
[[ "$RUNNING" == false && "$UPDATES" == 1 && "$STOPS" == 1 ]]
"""
        result = subprocess.run(
            ["bash", "-c", shell], text=True, capture_output=True,
            check=False, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        fail = subprocess.run(
            ["bash", "-c", "set -Eeuo pipefail\n" + STOP
             + "\ndocker() { return 1; }\n"
             + "stop_managed_xray_for_invalid_offline_policy"],
            text=True, capture_output=True, check=False, timeout=5)
        self.assertNotEqual(fail.returncode, 0)
        self.assertIn("operator action required", fail.stderr)


if __name__ == "__main__":
    unittest.main()
