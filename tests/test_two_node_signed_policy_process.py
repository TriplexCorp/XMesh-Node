#!/usr/bin/env python3
"""Two real CLI guard processes with independently durable Node ledgers.

All signed desired policies use the same disposable Nexus Ed25519 key, and
both Node IDs are independently validated. There is no live Nexus/Postgres
here, so this does NOT prove production policy-issue transaction ordering.
"""
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / "deploy/xmesh-policy-guard.py"
NOW = 1_800_000_000_000
UID = "550e8400-e29b-41d4-a716-446655440001"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode()


class RealSignedNode:
    def __init__(self, root, node_id, key, pub):
        self.node_id = node_id
        self.root = root / f"node-{node_id}"
        self.root.mkdir()
        self.key = key
        self.pub = pub
        self.state = self.root / "state"
        self.response = self.root / "response.json"
        self.effective = self.root / "effective.json"
        self.stats = self.root / "stats.json"
        self.stats.write_text('{"1":0}')
        self.config = {
            "inbounds": [{"listen": "127.0.0.1", "port": 28351,
                          "protocol": "vless", "settings": {
                              "decryption": "none",
                              "clients": [{"id": UID, "level": 0}]}}],
            "outbounds": [{"tag": "direct", "protocol": "freedom"}],
        }
        self.policy = {
            "version": 1, "nodeId": node_id,
            "issuedAtMs": NOW,
            "validUntilMs": NOW + 7 * 86400000,
            "configSha256": hashlib.sha256(canonical(self.config)).hexdigest(),
            "users": [{"userId": 1, "xrayId": UID,
                       "expireAtMs": NOW + 86400000,
                       "panelUsedBytes": 0, "limitBytes": 1000,
                       "offlineBudgetBytes": 100}],
        }

    def sign(self):
        payload = self.root / "policy"
        signature = self.root / "policy.sig"
        payload.write_bytes(canonical(self.policy))
        subprocess.run(
            ["openssl", "pkeyutl", "-sign", "-rawin",
             "-inkey", str(self.key), "-in", str(payload),
             "-out", str(signature)], check=True, capture_output=True)
        self.response.write_text(json.dumps({
            "nodeId": self.node_id, "port": 28351, "config": self.config,
            "policy": self.policy,
            "policySignature": signature.read_bytes().hex(),
            "policyPublicKey": self.pub,
        }))
        return self.response

    def run(self, action, at, total, success=True, alternate=None):
        self.stats.write_text(json.dumps({"1": total}))
        args = [sys.executable, str(GUARD), action, "--state",
                str(self.state), "--node-id", str(self.node_id),
                "--now-ms", str(at)]
        if action != "commit":
            args.extend(["--output", str(self.effective),
                         "--stats-file", str(self.stats)])
        if action == "prepare":
            args.extend(["--response", str(
                self.response if alternate is None else alternate)])
        outcome = subprocess.run(args, capture_output=True, text=True, timeout=15)
        if success:
            if outcome.returncode:
                raise AssertionError(outcome.stderr)
        else:
            if not outcome.returncode:
                raise AssertionError("expected bad node/policy signature denied")
        return outcome

    def clients(self):
        return len(json.loads(self.effective.read_bytes())
                   ["inbounds"][0]["settings"]["clients"])

    def ledger(self):
        return json.loads((self.state / "policy-usage.json").read_bytes())


class SignedTwoNodeV1Tests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="xmesh-v1-two-nodes-")
        self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        key = root / "nexus.key"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519",
                        "-out", str(key)], check=True, capture_output=True)
        public = subprocess.check_output(
            ["openssl", "pkey", "-in", str(key),
             "-pubout", "-outform", "DER"])
        self.a = RealSignedNode(root, 12, key, public[-32:].hex())
        self.b = RealSignedNode(root, 13, key, public[-32:].hex())
        for node in (self.a, self.b):
            node.sign()
            node.run("prepare", NOW, 0)
            self.assertEqual(node.clients(), 1)
            node.run("commit", NOW, 0)

    def test_real_signed_two_node_partial_ack_and_process_restart(self):
        self.a.run("offline", NOW + 1000, 95)
        self.b.run("offline", NOW + 1000, 15)
        # Only B's 15 bytes are globally visible; A has 95 held locally.
        self.a.policy["issuedAtMs"] = NOW + 2000
        self.a.policy["users"][0]["panelUsedBytes"] = 15
        self.a.sign()
        self.a.run("prepare", NOW + 2000, 95)
        self.a.run("commit", NOW + 2000, 95)
        self.assertEqual(self.a.ledger()["users"]["1"]["anchor"], 0)
        self.assertEqual(self.a.ledger()["users"]["1"]["budget"], 100)
        # New OS process reloads root-owned state and must not gain bytes.
        self.a.run("offline", NOW + 3000, 100)
        self.assertEqual(self.a.clients(), 0)
        self.assertEqual(self.a.ledger()["users"]["1"]["revokedReason"], "quota")
        # Server later receives A's report and issues refreshed usage on B.
        self.b.policy["issuedAtMs"] = NOW + 4000
        self.b.policy["users"][0]["panelUsedBytes"] = 110
        self.b.sign()
        self.b.run("prepare", NOW + 4000, 15)
        self.b.run("commit", NOW + 4000, 15)
        self.b.run("offline", NOW + 4500, 99)
        self.assertEqual(self.b.clients(), 1)
        self.b.run("offline", NOW + 5000, 100)
        self.assertEqual(self.b.clients(), 0)
        for node in (self.a, self.b):
            self.assertEqual(node.ledger()["users"]["1"]["budget"], 100)
            self.assertEqual(node.ledger()["users"]["1"]["anchor"], 0)

    def test_signed_policy_global_decrease_and_upgraded_plan_do_not_resurrect(self):
        self.a.run("offline", NOW + 1000, 100)
        self.assertEqual(self.a.clients(), 0)
        for issued, used, limit, budget in (
                (2000, 150, 1000, 100),
                (3000, 0, 1000, 100),
                (4000, 0, 10000, 100),
                (5000, 200, 10000, 200)):
            self.a.policy["issuedAtMs"] = NOW + issued
            self.a.policy["users"][0].update({
                "panelUsedBytes": used, "limitBytes": limit,
                "offlineBudgetBytes": budget})
            # A real signed V1 budget cannot exceed the protocol max,
            # but the fixture uses deliberately tiny values below that cap.
            self.a.sign()
            self.a.run("prepare", NOW + issued, 100)
            self.a.run("commit", NOW + issued, 100)
            self.assertEqual(self.a.clients(), 0)
            self.assertEqual(self.a.ledger()["users"]["1"]["budget"], 100)

    def test_valid_signature_for_other_node_cannot_be_applied_here(self):
        b = self.b.sign()
        self.a.run("prepare", NOW + 1000, 0, success=False, alternate=b)
        # The original accepted policy remains durable and usable offline.
        self.a.run("offline", NOW + 2000, 0)
        self.assertEqual(self.a.clients(), 1)

    def test_signed_lease_only_renews_expiry_without_refilling_original_budget(self):
        self.a.run("offline", NOW + 7 * 86400000, 40)
        self.assertEqual(self.a.clients(), 0)
        self.a.policy["issuedAtMs"] = NOW + 7 * 86400000 + 2000
        self.a.policy["validUntilMs"] = self.a.policy["issuedAtMs"] + 7 * 86400000
        self.a.policy["users"][0]["expireAtMs"] = NOW + 14 * 86400000
        self.a.sign()
        self.a.run("prepare", self.a.policy["issuedAtMs"] + 1, 40)
        self.assertEqual(self.a.clients(), 1)
        self.assertEqual(self.a.ledger()["users"]["1"]["anchor"], 0)
        self.assertEqual(self.a.ledger()["users"]["1"]["budget"], 100)
        self.a.run("commit", self.a.policy["issuedAtMs"] + 1, 40)
        self.a.run("offline", self.a.policy["issuedAtMs"] + 3, 100)
        self.assertEqual(self.a.clients(), 0)


if __name__ == "__main__":
    unittest.main()
