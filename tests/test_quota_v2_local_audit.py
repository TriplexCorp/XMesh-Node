#!/usr/bin/env python3
"""Local Quota V2 audit must never declare whole fleet or byte refunds safe."""
import importlib.util
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "scripts/quota-v2-local-audit.py"
spec = importlib.util.spec_from_file_location("xmesh_v2_audit", SOURCE)
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def signed(version, budget=64 * 1024 * 1024, expiry=2_000_000_000_000):
    return {"version": version, "validUntilMs": expiry,
            "users": [{"limitBytes": 1_000_000_000, "offlineBudgetBytes": budget}]}


class TestLocalAudit(unittest.TestCase):
    def check(self, policy, *, applied=True, control=True, pq=True,
              services=None):
        if services is None:
            services = {"xray.service": "inactive", "v2ray.service": "inactive"}
        return audit.evaluate(
            policy, applied, control, pq, services, 1_900_000_000_000,
            ("xmesh-node", "xmesh-managed-xray"),
            {unit: True for unit in audit.REQUIRED_TIMERS},
        )

    def test_v1_with_unexpired_budget_blocks(self):
        result = self.check(signed(1))
        self.assertTrue(result["potentialLiveV1OfflineBudget"])
        self.assertIn("committed_v1_signed_policy", result["blockers"])
        self.assertFalse(result["localV2AppliedVerified"])

    def test_even_expired_v1_or_zero_allowance_is_not_v2(self):
        for old in [signed(1, expiry=1_800_000_000_000), signed(1, budget=0)]:
            with self.subTest(old=old):
                result = self.check(old)
                self.assertFalse(result["potentialLiveV1OfflineBudget"])
                self.assertFalse(result["localV2AppliedVerified"])

    def test_local_verified_v2_is_never_fleet_or_final_receipt(self):
        result = self.check(signed(2))
        self.assertTrue(result["localV2AppliedVerified"])
        self.assertEqual(result["blockers"], [])
        self.assertFalse(result["allLegacyCopiesRetiredVerified"])
        self.assertFalse(result["fleetActivationAuthorized"])
        self.assertFalse(result["finalMeterVerified"])
        self.assertEqual(result["refundableBytes"], 0)

    def test_stale_profile_or_unverified_binary_fail_closed(self):
        for kwargs in [{"applied": False}, {"control": False}, {"pq": False}]:
            with self.subTest(kwargs=kwargs):
                self.assertFalse(self.check(signed(2), **kwargs)["localV2AppliedVerified"])

    def test_native_old_xray_or_unknown_state_is_unacceptable(self):
        for state in ("active", "unknown"):
            with self.subTest(state=state):
                result = self.check(signed(2), services={
                    "xray.service": state, "v2ray.service": "inactive"})
                self.assertIn("legacy_or_unverifiable_xray_service", result["blockers"])
                self.assertFalse(result["localV2AppliedVerified"])

    def test_extra_live_docker_container_blocks_local_green(self):
        p = signed(2)
        for running in (
            ("xmesh-managed-xray", "xmesh-node", "old-v1-xray"),
            ("xmesh-managed-xray", "xmesh-node", "unrelated-docker-app"),
        ):
            with self.subTest(running=running):
                r = audit.evaluate(p, True, True, True,
                    {"xray.service": "inactive", "v2ray.service": "inactive"},
                    1_900_000_000_000, running,
                    {unit: True for unit in audit.REQUIRED_TIMERS})
                self.assertFalse(r["localV2AppliedVerified"])
                self.assertIn("unreviewed_parallel_running_docker_container",
                              r["blockers"])

    def test_missing_required_docker_container_or_unavailable_docker(self):
        for containers, blocker in (
            (None, "docker_inventory_unavailable"),
            (("xmesh-node",), "managed_xray_container_not_running"),
            (("xmesh-managed-xray",), "managed_router_container_not_running"),
        ):
            with self.subTest(containers=containers):
                r = audit.evaluate(signed(2), True, True, True,
                    {"xray.service": "inactive", "v2ray.service": "inactive"},
                    1_900_000_000_000, containers,
                    {unit: True for unit in audit.REQUIRED_TIMERS})
                self.assertFalse(r["localV2AppliedVerified"])
                self.assertIn(blocker, r["blockers"])

    def test_quota_timers_must_be_enabled_and_active(self):
        for unit in audit.REQUIRED_TIMERS:
            with self.subTest(unit=unit):
                timers = {name: True for name in audit.REQUIRED_TIMERS}
                timers[unit] = False
                r = audit.evaluate(signed(2), True, True, True,
                    {"xray.service": "inactive", "v2ray.service": "inactive"},
                    1_900_000_000_000,
                    ("xmesh-node", "xmesh-managed-xray"), timers)
                self.assertFalse(r["localV2AppliedVerified"])
                self.assertIn("enforcement_timer_not_enabled_and_active",
                              r["blockers"])
        r = audit.evaluate(signed(2), True, True, True,
            {"xray.service": "inactive", "v2ray.service": "inactive"},
            1_900_000_000_000,
            ("xmesh-node", "xmesh-managed-xray"), None)
        self.assertIn("enforcement_timer_inventory_unavailable", r["blockers"])

    def test_docker_inventory_validates_names_and_rejects_failure(self):
        from unittest.mock import patch
        for body, code in (
            ("xmesh-node\\nxmesh-managed-xray\\n", 0),
            ("xmesh-node\\nxmesh-node\\n", 0),
            ("xmesh-node\\nname/invalid\\n", 0),
            ("", 1),
        ):
            with self.subTest(body=body, code=code):
                response = subprocess.CompletedProcess([], code,
                    stdout=body.replace("\\\\n", "\\n"), stderr="")
                with patch.object(audit, "run", return_value=response):
                    if code != 0 or "invalid" in body or body.count("xmesh-node") > 1:
                        with self.assertRaises(ValueError):
                            audit.inspect_running_docker_names()
                    else:
                        self.assertEqual(
                            audit.inspect_running_docker_names(),
                            frozenset(("xmesh-node", "xmesh-managed-xray")),
                        )

    def test_actual_binary_identities_must_match_installed_manifest(self):
        a = "a" * 64
        b = "b" * 64
        revision = "c" * 40
        manifest = {
            "version": audit.VERSION, "sourceRevision": revision,
            "activationArtifactSha256": a, "productArtifactSha256": b,
            "strictPQCapable": True, "strictPQRequired": True,
            "automaticClassicalFallback": False,
        }
        def identities(revision_override=None):
            return [
                subprocess.CompletedProcess([], 0, stdout=json.dumps({
                    "version": audit.VERSION,
                    "sourceRevision": revision_override or revision,
                    "artifactSha256": h,
                })) for h in (a, b)
            ]
        with patch.object(audit, "read_json", return_value=manifest), (
                patch.object(audit, "digest_file", side_effect=[a, b])), (
                patch.object(audit, "run", side_effect=identities())):
            self.assertTrue(audit.verify_binary_manifest())
        with patch.object(audit, "read_json", return_value=manifest), (
                patch.object(audit, "digest_file", side_effect=[a, "d" * 64])), (
                patch.object(audit, "run", side_effect=identities())):
            self.assertFalse(audit.verify_binary_manifest())
        with patch.object(audit, "read_json", return_value=manifest), (
                patch.object(audit, "digest_file", side_effect=[a, b])), (
                patch.object(audit, "run", side_effect=identities("e" * 40))):
            self.assertFalse(audit.verify_binary_manifest())

    def test_invalid_and_bool_versions_rejected(self):
        for bad in (None, {}, [], {"version": True}, {"version": 3}):
            with self.subTest(bad=bad):
                self.assertIn("signed_policy_missing_or_invalid", self.check(bad)["blockers"])
                self.assertFalse(self.check(bad)["localV2AppliedVerified"])


if __name__ == "__main__":
    unittest.main()
