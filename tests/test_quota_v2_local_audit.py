#!/usr/bin/env python3
"""Local Quota V2 audit must never declare whole fleet or byte refunds safe."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
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
              services=None, workers=True):
        if services is None:
            services = {"xray.service": "inactive", "v2ray.service": "inactive"}
        return audit.evaluate(
            policy, applied, control, pq, services, 1_900_000_000_000,
            (frozenset(("xmesh-node", "xmesh-managed-xray")),
             frozenset(("xmesh-node", "xmesh-managed-xray"))),
            {unit: True for unit in audit.REQUIRED_TIMERS}, workers,
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
                    1_900_000_000_000, (frozenset(running), frozenset(running)),
                    {unit: True for unit in audit.REQUIRED_TIMERS}, True)
                self.assertFalse(r["localV2AppliedVerified"])
                self.assertIn("unreviewed_other_docker_container",
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
                    1_900_000_000_000,
                    (frozenset(containers), frozenset(containers))
                    if containers is not None else None,
                    {unit: True for unit in audit.REQUIRED_TIMERS}, True)
                self.assertFalse(r["localV2AppliedVerified"])
                self.assertIn(blocker, r["blockers"])

    def test_quota_timers_must_be_enabled_and_active(self):
        # User meter is the durable per-user sampler, not interchangeable with
        # aggregate node metrics heartbeat or a healthy running Xray.
        self.assertIn("xmesh-node-user-meter.timer", audit.REQUIRED_TIMERS)
        for unit in audit.REQUIRED_TIMERS:
            with self.subTest(unit=unit):
                timers = {name: True for name in audit.REQUIRED_TIMERS}
                timers[unit] = False
                r = audit.evaluate(signed(2), True, True, True,
                    {"xray.service": "inactive", "v2ray.service": "inactive"},
                    1_900_000_000_000,
                    (frozenset(("xmesh-node", "xmesh-managed-xray")),
                     frozenset(("xmesh-node", "xmesh-managed-xray"))), timers, True)
                self.assertFalse(r["localV2AppliedVerified"])
                self.assertIn("enforcement_timer_not_enabled_and_active",
                              r["blockers"])
        r = audit.evaluate(signed(2), True, True, True,
            {"xray.service": "inactive", "v2ray.service": "inactive"},
            1_900_000_000_000,
            (frozenset(("xmesh-node", "xmesh-managed-xray")),
             frozenset(("xmesh-node", "xmesh-managed-xray"))), None, True)
        self.assertIn("enforcement_timer_inventory_unavailable", r["blockers"])

    def test_docker_inventory_distinguishes_stopped_from_running(self):
        # A stopped managed router must never count as active. Docker ps -a
        # would have listed its name, producing a false-green in older audits.
        all_names = frozenset(("xmesh-node", "xmesh-managed-xray"))
        for running in (
            frozenset(("xmesh-managed-xray",)),
            frozenset(("xmesh-node",)),
            frozenset(),
        ):
            with self.subTest(running=running):
                result = audit.evaluate(
                    signed(2), True, True, True,
                    {"xray.service": "inactive", "v2ray.service": "inactive"},
                    1_900_000_000_000, (all_names, running),
                    {unit: True for unit in audit.REQUIRED_TIMERS}, True)
                self.assertFalse(result["localV2AppliedVerified"])
                self.assertIn(
                    "managed_router_container_not_running"
                    if "xmesh-node" not in running
                    else "managed_xray_container_not_running",
                    result["blockers"])

    def test_extra_stopped_container_is_still_blocked(self):
        result = audit.evaluate(
            signed(2), True, True, True,
            {"xray.service": "inactive", "v2ray.service": "inactive"},
            1_900_000_000_000,
            (frozenset(("xmesh-node", "xmesh-managed-xray", "old-xray")),
             frozenset(("xmesh-node", "xmesh-managed-xray"))),
            {unit: True for unit in audit.REQUIRED_TIMERS}, True)
        self.assertFalse(result["localV2AppliedVerified"])
        self.assertIn("unreviewed_other_docker_container", result["blockers"])

    def test_docker_inventory_validates_states_names_and_rejects_failure(self):
        samples = [
            (["xmesh-node\trunning", "xmesh-managed-xray\trunning"],
             0, True),
            (["xmesh-node\texited", "xmesh-managed-xray\trunning"],
             0, True),
            (["xmesh-node\trunning", "xmesh-node\texited"],
             0, False),
            (["xmesh-node\trunning", "name/invalid\tcreated"],
             0, False),
            (["xmesh-node\tother"], 0, False),
            (["xmesh-node\trunning\tanything"], 0, False),
            (["xmesh-node"], 0, False),
            ([], 1, False),
        ]
        for rows, code, should_pass in samples:
            with self.subTest(rows=rows, code=code):
                response = subprocess.CompletedProcess(
                    [], code, stdout="\n".join(rows) + "\n", stderr="")
                with patch.object(audit, "run", return_value=response):
                    if should_pass:
                        all_names, running = audit.inspect_docker_inventory()
                        self.assertEqual(
                            all_names,
                            frozenset(("xmesh-node", "xmesh-managed-xray")))
                        self.assertEqual(
                            running,
                            frozenset(("xmesh-managed-xray",))
                            if "xmesh-node\texited" in rows else all_names)
                    else:
                        with self.assertRaises(ValueError):
                            audit.inspect_docker_inventory()

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

    def test_installed_worker_integrity_blocks_green_fleet_audit(self):
        result = self.check(signed(2), workers=False)
        self.assertFalse(result["localV2AppliedVerified"])
        self.assertIn("installed_quota_enforcement_worker_unverified",
                      result["blockers"])

    def test_installed_worker_bytes_must_match_pq_pinned_git_checkout(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp) / "node"
            (root / "deploy").mkdir(parents=True)
            (root / ".git").mkdir()
            installed_dir = Path(temp) / "installed"
            installed_dir.mkdir()
            (root / "config.json").write_text("{}")
            workers = {}
            for name in audit.NODE_RUNTIME_WORKERS:
                src = root / "deploy" / name
                dst = installed_dir / name
                src.write_bytes(b"reviewed signed quota worker\n")
                dst.write_bytes(src.read_bytes())
                workers[name] = dst
            revision = "a" * 40
            def command(argv):
                if argv[:2] == ["docker", "inspect"]:
                    return subprocess.CompletedProcess(argv, 0,
                                stdout=str(root / "config.json") + "\n")
                if argv[-2:] == ["rev-parse", "HEAD"]:
                    return subprocess.CompletedProcess(argv, 0,
                                stdout=revision + "\n")
                if argv[-3:] == ["status", "--porcelain", "--untracked-files=no"]:
                    return subprocess.CompletedProcess(argv, 0, stdout="")
                if argv[-3:] == ["remote", "get-url", "origin"]:
                    return subprocess.CompletedProcess(argv, 0,
                        stdout="https://github.com/TriplexCorp/XMesh-Node.git\n")
                raise AssertionError(f"Unexpected audit command: {argv}")
            with patch.object(audit, "read_json",
                    return_value={"sourceRevision": revision}), \
                 patch.object(audit, "NODE_RUNTIME_WORKERS", workers), \
                 patch.object(audit, "owned_regular", side_effect=lambda p: p.is_file()), \
                 patch.object(audit, "run", side_effect=command):
                self.assertTrue(audit.verify_installed_enforcement_workers())
                workers["xmesh-xray-sync.sh"].write_bytes(b"outdated sync code\n")
                self.assertFalse(audit.verify_installed_enforcement_workers())
                workers["xmesh-xray-sync.sh"].write_bytes(
                    (root / "deploy" / "xmesh-xray-sync.sh").read_bytes())
                with patch.object(audit, "read_json",
                        return_value={"sourceRevision": "b" * 40}):
                    self.assertFalse(audit.verify_installed_enforcement_workers())
                self.assertTrue(audit.verify_installed_enforcement_workers())

    def test_invalid_and_bool_versions_rejected(self):
        for bad in (None, {}, [], {"version": True}, {"version": 3}):
            with self.subTest(bad=bad):
                self.assertIn("signed_policy_missing_or_invalid", self.check(bad)["blockers"])
                self.assertFalse(self.check(bad)["localV2AppliedVerified"])


if __name__ == "__main__":
    unittest.main()
