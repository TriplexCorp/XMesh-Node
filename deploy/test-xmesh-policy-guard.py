#!/usr/bin/env python3
"""Signed node-policy integration checks without Docker/network dependencies."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))
# The helper uses a hyphenated filename, so invoke its CLI as a subprocess.
GUARD = ROOT / "xmesh-policy-guard.py"
UID = "550e8400-e29b-41d4-a716-446655440001"
NOW = 1_800_000_000_000


def compact(data):
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


class SignedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.key = self.root / "signing-key.pem"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(self.key)],
                       check=True, capture_output=True)
        der = subprocess.check_output(["openssl", "pkey", "-in", str(self.key), "-pubout", "-outform", "DER"])
        self.pub = der[-32:].hex()
        self.config = {"inbounds": [{"listen": "127.0.0.1", "port": 28351,
                                    "protocol": "vless", "settings": {
                                        "decryption": "none", "clients": [{"id": UID, "level": 0}]}}],
                       "outbounds": [{"tag": "direct", "protocol": "freedom"}]}
        self.policy = {"version": 1, "nodeId": 12, "issuedAtMs": NOW,
                       "validUntilMs": NOW + 7 * 86400000,
                       "configSha256": hashlib.sha256(compact(self.config)).hexdigest(),
                       "users": [{"userId": 1, "xrayId": UID, "expireAtMs": NOW + 86400000,
                                  "panelUsedBytes": 0, "offlineBudgetBytes": 100}]}
        # Use valid minuscule test-only budget; production cap is <=64 MiB.
        self.stats = self.root / "stats.json"
        self.stats.write_text('{"1":0}')
        self.envelope = self.root / "response.json"
        self.output = self.root / "effective.json"
        self.state = self.root / "node-state"
        self.write_envelope()

    def write_envelope(self):
        message = self.root / "policy-data"
        signature = self.root / "policy-sig"
        message.write_bytes(compact(self.policy))
        subprocess.run(["openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(self.key),
                        "-in", str(message), "-out", str(signature)],
                       check=True, capture_output=True)
        self.envelope.write_text(json.dumps({
            "nodeId": 12, "port": 28351, "config": self.config,
            "policy": self.policy, "policySignature": signature.read_bytes().hex(),
            "policyPublicKey": self.pub
        }))

    def run_guard(self, action, timestamp=NOW, success=True):
        args = [sys.executable, str(GUARD), action, "--state", str(self.state),
                "--node-id", "12", "--now-ms", str(timestamp)]
        if action != "commit":
            args += ["--output", str(self.output), "--stats-file", str(self.stats)]
        if action == "prepare":
            args += ["--response", str(self.envelope)]
        result = subprocess.run(args, capture_output=True, text=True)
        if success:
            self.assertEqual(result.returncode, 0, result.stderr)
        else:
            self.assertNotEqual(result.returncode, 0)
        return result

    def num_clients(self):
        return len(json.loads(self.output.read_text())["inbounds"][0]["settings"]["clients"])

    def configure_protocol(self, protocol, *, method=None):
        credential = {"vless": "id", "vmess": "id", "trojan": "password",
                      "shadowsocks": "password", "hysteria": "auth",
                      "masque": "pass"}[protocol]
        value = "TEST-SS2022-PSK" if method else UID
        entry = {credential: value, "email": "xmesh-u1--hysteria-main", "level": 0}
        settings = {"version": 2, "users": [entry]}
        if method is not None:
            settings["method"] = method
        if protocol == "vless":
            settings = {"decryption": "none", "clients": [entry]}
        self.config["inbounds"][0]["protocol"] = protocol
        self.config["inbounds"][0]["settings"] = settings
        self.policy["configSha256"] = hashlib.sha256(compact(self.config)).hexdigest()
        self.write_envelope()

    def test_signed_multi_protocol_accounts_and_offline_cutoff(self):
        for protocol in ("vless", "vmess", "trojan", "shadowsocks", "hysteria", "masque"):
            with self.subTest(protocol=protocol):
                self.configure_protocol(protocol)
                self.run_guard("prepare")
                self.run_guard("commit")
                field = "clients" if protocol == "vless" else "users"
                effective = json.loads(self.output.read_text())["inbounds"][0]
                self.assertEqual(len(effective["settings"][field]), 1)
                self.stats.write_text('{"1":150}')
                self.run_guard("offline", NOW + 10000)
                effective = json.loads(self.output.read_text())["inbounds"][0]
                self.assertEqual(effective["settings"][field], [])
                # Reset isolated per-protocol state so each variant is tested
                # with its own first-contact signed policy.
                for child in self.state.iterdir():
                    if child.is_file():
                        child.unlink()
                self.stats.write_text('{"1":0}')

    def configure_dual_profile(self):
        self.config["inbounds"] = [
            {"tag": "vless-main", "listen": "127.0.0.1", "port": 28351,
             "protocol": "vless", "settings": {"decryption": "none",
                "clients": [{"id": UID, "email": "xmesh-u1--vless-main", "level": 0}]},
             "streamSettings": {"network": "xhttp", "security": "tls",
                "tlsSettings": {"alpn": ["h2", "http/1.1"]}}},
            {"tag": "hysteria-main", "listen": "127.0.0.1", "port": 28352,
             "protocol": "hysteria", "settings": {"version": 2,
                "users": [{"auth": UID, "email": "xmesh-u1--hysteria-main", "level": 0}]},
             "streamSettings": {"network": "hysteria", "security": "tls",
                "tlsSettings": {"alpn": ["h3"]}}},
            {"tag": "xmesh_stats_in", "listen": "127.0.0.1", "port": 10085,
             "protocol": "dokodemo-door", "settings": {"address": "127.0.0.1",
                 "port": 10085, "network": "tcp"}}
        ]
        self.config["api"] = {"tag": "xmesh_stats_api", "services": ["StatsService"]}
        self.policy["configSha256"] = hashlib.sha256(compact(self.config)).hexdigest()
        self.write_envelope()

    def test_dual_signed_policy_authorizes_and_revokes_both_transports(self):
        self.configure_dual_profile()
        self.run_guard("prepare")
        active = json.loads(self.output.read_text())["inbounds"]
        self.assertEqual(len(active[0]["settings"]["clients"]), 1)
        self.assertEqual(len(active[1]["settings"]["users"]), 1)
        self.run_guard("commit")
        self.stats.write_text('{"1":150}')
        self.run_guard("offline", NOW + 10000)
        active = json.loads(self.output.read_text())["inbounds"]
        self.assertEqual(active[0]["settings"]["clients"], [])
        self.assertEqual(active[1]["settings"]["users"], [])
        self.assertEqual(active[2]["tag"], "xmesh_stats_in")

    def test_dual_disallows_extra_or_mislabelled_accounts(self):
        self.configure_dual_profile()
        self.config["inbounds"][1]["settings"]["users"].append({
            "auth": "550e8400-e29b-41d4-a716-446655440099",
            "email": "xmesh-u99--hysteria-main"})
        self.policy["configSha256"] = hashlib.sha256(compact(self.config)).hexdigest()
        self.write_envelope()
        self.assertIn("proxy accounts differ", self.run_guard("prepare", success=False).stderr)
        self.configure_dual_profile()
        self.config["inbounds"][1]["settings"]["users"][0]["email"] = "xmesh-u1--vless-main"
        self.policy["configSha256"] = hashlib.sha256(compact(self.config)).hexdigest()
        self.write_envelope()
        self.assertIn("proxy accounts differ", self.run_guard("prepare", success=False).stderr)

    def test_dual_rejects_port_collision_and_competing_quic(self):
        self.configure_dual_profile()
        self.config["inbounds"][1]["port"] = 28351
        self.policy["configSha256"] = hashlib.sha256(compact(self.config)).hexdigest()
        self.write_envelope()
        self.assertIn("listener disagree", self.run_guard("prepare", success=False).stderr)
        self.configure_dual_profile()
        self.config["inbounds"][0]["streamSettings"]["tlsSettings"]["alpn"] = ["h2", "h3"]
        self.policy["configSha256"] = hashlib.sha256(compact(self.config)).hexdigest()
        self.write_envelope()
        self.assertIn("one TCP", self.run_guard("prepare", success=False).stderr)

    def test_attestation_accepts_only_account_removal_for_both_transports(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "xmesh_profile_attest", ROOT / "xmesh-profile-attest.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.configure_dual_profile()
        active = json.loads(json.dumps(self.config))
        active["inbounds"][0]["settings"]["clients"] = []
        active["inbounds"][1]["settings"]["users"] = []
        self.assertTrue(module.is_restricted_copy(self.config, active))
        active["inbounds"][1]["settings"]["users"] = [{"auth": "injected"}]
        self.assertFalse(module.is_restricted_copy(self.config, active))

    def test_signed_hysteria_email_with_s_in_tag(self):
        # Regression: raw regex [^\\\\s] accidentally rejected the letter s.
        self.configure_protocol("hysteria")
        self.config["inbounds"][0]["settings"]["users"][0]["email"] = "xmesh-u1--hysteria-main"
        self.policy["configSha256"] = hashlib.sha256(compact(self.config)).hexdigest()
        self.write_envelope()
        self.run_guard("prepare")
        self.run_guard("commit")
        self.assertEqual(len(json.loads(self.output.read_text())["inbounds"][0]["settings"]["users"]), 1)

    def test_signed_hysteria_rejects_extra_unlisted_user(self):
        self.configure_protocol("hysteria")
        self.config["inbounds"][0]["settings"]["users"].append({
            "auth": "550e8400-e29b-41d4-a716-446655440099",
            "email": "xmesh-u99--hysteria-main"
        })
        self.policy["configSha256"] = hashlib.sha256(compact(self.config)).hexdigest()
        self.write_envelope()
        self.assertIn("proxy accounts differ", self.run_guard("prepare", success=False).stderr)

    def test_hysteria_credentials_cannot_swap_signed_user_id(self):
        self.configure_protocol("hysteria")
        self.config["inbounds"][0]["settings"]["users"][0]["auth"] = "550e8400-e29b-41d4-a716-446655440099"
        self.policy["configSha256"] = hashlib.sha256(compact(self.config)).hexdigest()
        self.write_envelope()
        self.assertIn("proxy accounts differ", self.run_guard("prepare", success=False).stderr)

    def test_shadowsocks_2022_uses_signed_user_mapping(self):
        self.configure_protocol("shadowsocks", method="2022-blake3-aes-128-gcm")
        self.run_guard("prepare")
        self.run_guard("commit")
        self.assertEqual(len(json.loads(self.output.read_text())["inbounds"][0]["settings"]["users"]), 1)
        self.stats.write_text('{"1":150}')
        self.run_guard("offline", NOW + 10000)
        self.assertEqual(json.loads(self.output.read_text())["inbounds"][0]["settings"]["users"], [])

    def test_disconnected_limit_and_sticky_denial(self):
        self.run_guard("prepare")
        self.run_guard("commit")
        self.assertEqual(self.num_clients(), 1)
        self.stats.write_text('{"1":150}')
        self.run_guard("offline", NOW + 10000)
        self.assertEqual(self.num_clients(), 0)
        # Identical policy re-pulled cannot reauthorize a locally denied user.
        self.run_guard("prepare", NOW + 20000)
        self.assertEqual(self.num_clients(), 0)
        # A fresh signed panel accounting increase can issue another offline budget.
        self.policy["issuedAtMs"] = NOW + 25000
        self.policy["panelUsageRevision"] = 2
        self.policy["users"][0]["panelUsedBytes"] = 150
        self.write_envelope()
        self.run_guard("prepare", NOW + 30000)
        self.assertEqual(self.num_clients(), 1)

    def test_expiration_offline_and_policy_key_pin(self):
        self.run_guard("prepare")
        self.run_guard("commit")
        self.run_guard("offline", NOW + 86400001)
        self.assertEqual(self.num_clients(), 0)
        # A newly signed renewal with a later expiration restores this user.
        self.policy["issuedAtMs"] = NOW + 86400002
        self.policy["validUntilMs"] = self.policy["issuedAtMs"] + 7 * 86400000
        self.policy["users"][0]["expireAtMs"] = NOW + 3 * 86400000
        self.write_envelope()
        self.run_guard("prepare", NOW + 86400003)
        self.assertEqual(self.num_clients(), 1)
        # Tampering with a body field breaks the detached policy signature.
        body = json.loads(self.envelope.read_text())
        body["policy"]["users"][0]["expireAtMs"] += 1000000000
        self.envelope.write_text(json.dumps(body))
        self.run_guard("prepare", NOW + 1000, success=False)
        # Pinning cannot be silently bypassed with a new public key.
        self.write_envelope()
        body = json.loads(self.envelope.read_text())
        body["policyPublicKey"] = "a" * 64
        self.envelope.write_text(json.dumps(body))
        self.run_guard("prepare", NOW + 1000, success=False)

    def test_signed_policy_rollback_and_revision_collision(self):
        self.run_guard("prepare")
        self.run_guard("commit")
        self.policy["issuedAtMs"] = NOW + 2000
        self.policy["validUntilMs"] = self.policy["issuedAtMs"] + 7 * 86400000
        self.write_envelope()
        self.run_guard("prepare", NOW + 3000)
        self.run_guard("commit")
        # A valid but older panel signature must not restore stale rights.
        self.policy["issuedAtMs"] = NOW + 1000
        self.policy["validUntilMs"] = self.policy["issuedAtMs"] + 7 * 86400000
        self.write_envelope()
        self.assertIn("rollback", self.run_guard("prepare", NOW + 3000, success=False).stderr)
        # Same revision number with a different valid signature is ambiguous.
        self.policy["issuedAtMs"] = NOW + 2000
        self.policy["validUntilMs"] = self.policy["issuedAtMs"] + 7 * 86400000
        self.policy["users"][0]["expireAtMs"] += 1000
        self.write_envelope()
        self.assertIn("Conflicting", self.run_guard("prepare", NOW + 3000, success=False).stderr)

    def test_offline_requires_committed_signed_snapshot(self):
        self.run_guard("offline", success=False)
        self.run_guard("prepare")
        self.run_guard("offline", success=False)
        self.run_guard("commit")
        self.run_guard("offline")
        self.assertEqual(self.num_clients(), 1)


if __name__ == "__main__":
    unittest.main()
