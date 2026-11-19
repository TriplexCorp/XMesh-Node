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
