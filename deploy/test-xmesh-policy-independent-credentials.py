#!/usr/bin/env python3
"""Regression coverage for Nexus independent per-protocol credentials."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).parent
SOURCE = ROOT / "test-xmesh-policy-guard.py"
spec = importlib.util.spec_from_file_location("xmesh_guard_tests", SOURCE)
if spec is None or spec.loader is None:
    raise SystemExit("cannot load base policy tests")
base_tests = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base_tests)
base_tests.GUARD = ROOT / "xmesh-policy-guard.py"

DEDICATED = {
    "vmess": "550e8400-e29b-41d4-a716-446655440002",
    "trojan": "11" * 32,
    "hysteria": "22" * 32,
    "masque": "33" * 32,
    "shadowsocks": "44" * 32,
}
KEY = {
    "vmess": "id",
    "trojan": "password",
    "hysteria": "auth",
    "masque": "pass",
    "shadowsocks": "password",
}


class IndependentCredentialTests(base_tests.SignedPolicyTests):
    def _set_dedicated(self, protocol):
        self.configure_protocol(protocol)
        field = "clients" if protocol == "vless" else "users"
        self.config["inbounds"][0]["settings"][field][0][KEY[protocol]] = DEDICATED[protocol]
        self.policy["configSha256"] = hashlib.sha256(base_tests.compact(self.config)).hexdigest()
        self.write_envelope()

    def test_signed_independent_protocol_credentials_are_bound_by_user_email(self):
        for protocol in ("vmess", "trojan", "hysteria", "masque", "shadowsocks"):
            with self.subTest(protocol=protocol):
                self._set_dedicated(protocol)
                self.run_guard("prepare")
                self.run_guard("commit")
                field = "users"
                effective = json.loads(self.output.read_text())["inbounds"][0]
                self.assertEqual(effective["settings"][field][0][KEY[protocol]], DEDICATED[protocol])
                self.stats.write_text('{"1":150}')
                self.run_guard("offline", base_tests.NOW + 10000)
                self.assertEqual(json.loads(self.output.read_text())["inbounds"][0]["settings"][field], [])
                for child in self.state.iterdir():
                    if child.is_file():
                        child.unlink()
                self.stats.write_text('{"1":0}')

    def test_hysteria_dedicated_secret_survives_dual_profile_policy_validation(self):
        self.configure_dual_profile()
        self.config["inbounds"][1]["settings"]["users"][0]["auth"] = DEDICATED["hysteria"]
        self.policy["configSha256"] = hashlib.sha256(base_tests.compact(self.config)).hexdigest()
        self.write_envelope()
        self.run_guard("prepare")
        active = json.loads(self.output.read_text())["inbounds"]
        self.assertEqual(active[1]["settings"]["users"][0]["auth"], DEDICATED["hysteria"])

    def test_duplicate_hysteria_secret_is_rejected_even_with_two_signed_user_ids(self):
        self.configure_dual_profile()
        secret = DEDICATED["hysteria"]
        self.config["inbounds"][1]["settings"]["users"][0]["auth"] = secret
        second_uuid = "550e8400-e29b-41d4-a716-446655440099"
        self.config["inbounds"][0]["settings"]["clients"].append({
            "id": second_uuid, "email": "xmesh-u2--vless-main", "level": 0
        })
        self.config["inbounds"][1]["settings"]["users"].append({
            "auth": secret, "email": "xmesh-u2--hysteria-main", "level": 0
        })
        self.policy["users"].append({
            "userId": 2, "xrayId": second_uuid, "expireAtMs": base_tests.NOW + 86400000,
            "panelUsedBytes": 0, "offlineBudgetBytes": 100
        })
        self.policy["configSha256"] = hashlib.sha256(base_tests.compact(self.config)).hexdigest()
        self.write_envelope()
        result = self.run_guard("prepare", success=False)
        self.assertIn("Duplicate or missing signed proxy credential", result.stderr)


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(IndependentCredentialTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
