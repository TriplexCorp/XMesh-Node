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

    def test_offline_requires_committed_signed_snapshot(self):
        self.run_guard("offline", success=False)
        self.run_guard("prepare")
        self.run_guard("offline", success=False)
        self.run_guard("commit")
        self.run_guard("offline")
        self.assertEqual(self.num_clients(), 1)


if __name__ == "__main__":
    unittest.main()
