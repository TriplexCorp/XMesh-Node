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

    def test_observed_checkpoint_requires_signed_committed_lease_and_stop(self):
        """The Xray observation is ONLY scope-bound; it cannot refund bytes."""
        import importlib.util
        import copy
        spec = importlib.util.spec_from_file_location("xmesh_signed_observation", GUARD)
        guarded = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guarded)
        self.config["inbounds"][0]["tag"] = "vless-main"
        self.config["inbounds"][0]["settings"]["clients"][0]["email"] = "xmesh-u1--vless-main"
        # A separately authenticated CDN inbound is present in the signed
        # COMMITTED config. It must be represented even if no session used it.
        cdn = copy.deepcopy(self.config["inbounds"][0])
        cdn["tag"] = "vless-cdn"
        cdn["port"] = 28352
        cdn["settings"]["clients"][0]["email"] = "xmesh-u1--vless-cdn"
        self.config["inbounds"].append(cdn)
        self.policy["version"] = 2
        user = self.policy["users"][0]
        user["limitBytes"] = 1000
        lease = {
            "epoch": "11111111-1111-4111-8111-111111111111",
            "meterEpoch": "22222222-2222-4222-8222-222222222222",
            "reservationId": "33333333-3333-4333-8333-333333333333",
            "revision": 1, "acknowledgedBytes": 0, "ceilingBytes": 500,
            "validUntilMs": NOW + 7200000
        }
        user["quotaReservation"] = lease
        self.policy["configSha256"] = hashlib.sha256(compact(self.config)).hexdigest()
        self.write_envelope()
        self.run_guard("prepare")
        self.run_guard("commit")
        revoke = {
            "requestId": "44444444-4444-4444-8444-444444444444",
            "epoch": lease["epoch"], "meterEpoch": lease["meterEpoch"],
            "reservationId": lease["reservationId"]
        }
        self.policy["issuedAtMs"] = NOW + 1000
        user["quotaReservation"]["revision"] = 2
        user["quotaRevocation"] = revoke
        self.write_envelope()
        self.run_guard("prepare", NOW + 1000)
        self.assertEqual(self.num_clients(), 0)
        observation = {
            "schemaVersion": 3, "nodeId": 12, "userId": 1,
            "email": "xmesh-u1--vless-main",
            "epoch": lease["epoch"], "meterEpoch": lease["meterEpoch"],
            "reservationId": lease["reservationId"], "revision": 2,
            "revocationId": revoke["requestId"], "runtimeId": "a" * 64,
            "uplinkBytes": 70, "downlinkBytes": 80,
            "inboundMeters": [
                {"email": "xmesh-u1--vless-cdn",
                 "uplinkBytes": 40, "downlinkBytes": 40},
                {"email": "xmesh-u1--vless-main",
                 "uplinkBytes": 30, "downlinkBytes": 40},
            ],
            "drained": True,
            "finalMeterVerified": False, "refundableBytes": 0
        }
        ledger = json.loads((self.state / "policy-usage.json").read_text())
        with self.assertRaisesRegex(ValueError, "Unassigned or unrevoked"):
            guarded.verify_committed_observed_checkpoint(
                self.state, 12, observation, ledger)
        # Only the reconciler may commit after the denied effective config is applied.
        (self.state / "config.json").write_text(self.output.read_text())
        self.run_guard("commit", NOW + 1000)
        ledger = json.loads((self.state / "policy-usage.json").read_text())
        snapshot = guarded.verify_committed_observed_checkpoint(
            self.state, 12, observation, ledger)
        self.assertTrue(snapshot["scopeBoundToSignedPolicy"])
        self.assertTrue(snapshot["completeSignedInboundScopeObserved"])
        self.assertEqual(snapshot["signedInboundCount"], 2)
        self.assertEqual(snapshot["observedRawBytes"], 150)
        # Omitting even an UNUSED-but-SIGNED CDN inbound must be rejected.
        incomplete = copy.deepcopy(observation)
        incomplete["inboundMeters"] = [incomplete["inboundMeters"][1]]
        with self.assertRaisesRegex(ValueError, "Missing signed inbound"):
            guarded.verify_committed_observed_checkpoint(
                self.state, 12, incomplete, ledger)
        for mutation in ("duplicate", "wrong", "inverted", "unsorted"):
            broken = copy.deepcopy(observation)
            if mutation == "duplicate":
                broken["inboundMeters"][1] = broken["inboundMeters"][0]
            elif mutation == "wrong":
                broken["inboundMeters"][0]["email"] = "xmesh-u2--vless-cdn"
            elif mutation == "inverted":
                broken["inboundMeters"][0]["uplinkBytes"] += 1
            else:
                broken["inboundMeters"].reverse()
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                guarded.verify_committed_observed_checkpoint(
                    self.state, 12, broken, ledger)
        self.assertIs(snapshot["finalMeterVerified"], False)
        self.assertEqual(snapshot["refundableBytes"], 0)
        # Cross the actual verified signed-policy boundary before the
        # experimental Node signing step: no mocked policy approval here.
        signed_spec = importlib.util.spec_from_file_location(
            "xmesh_nonfinal_signer",
            Path(__file__).resolve().parents[1]
            / "experiments/xray-dataplane-fence/sign_observation.py")
        signer = importlib.util.module_from_spec(signed_spec)
        signed_spec.loader.exec_module(signer)
        node_key = self.root / "node-identity-key.pem"
        node_pub = self.root / "node-identity-key.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519",
                        "-out", str(node_key)], check=True, capture_output=True)
        os.chmod(node_key, 0o600)
        subprocess.run(["openssl", "pkey", "-in", str(node_key), "-pubout",
                        "-out", str(node_pub)], check=True, capture_output=True)
        signed_dir = self.root / "signed-nonfinal"
        signed_dir.mkdir(mode=0o700)
        envelope = signer.create_observation(
            self.state, 12, observation, node_key, signed_dir)
        signed = signer.verify_envelope(envelope, 12, node_pub)
        self.assertFalse(signed["finalMeterVerified"])
        self.assertFalse(signed["settlementEligible"])
        self.assertEqual(signed["refundableBytes"], 0)
        self.assertEqual(signer.create_observation(
            self.state, 12, observation, node_key, signed_dir), envelope)
        # Even correctly signed evidence must fail when the policy is forged.
        original_policy_bytes = (self.state / "policy-envelope.json").read_bytes()
        counterfeit = json.loads(original_policy_bytes)
        counterfeit["policy"]["users"][0]["quotaReservation"]["revision"] += 1
        (self.state / "policy-envelope.json").write_text(json.dumps(counterfeit))
        try:
            with self.assertRaises(ValueError):
                signer.create_observation(
                    self.state, 12, observation, node_key, signed_dir)
        finally:
            (self.state / "policy-envelope.json").write_bytes(original_policy_bytes)
        tests = [
            ("nodeId", 13), ("userId", 2), ("revision", 3),
            ("email", "xmesh-u2--vless-main"), ("revocationId", "5" * 8 + "-5555-4555-8555-" + "5" * 12),
            ("epoch", "55555555-5555-4555-8555-555555555555"),
            ("meterEpoch", "66666666-6666-4666-8666-666666666666"),
            ("reservationId", "77777777-7777-4777-8777-777777777777"),
            ("runtimeId", ""), ("schemaVersion", 1),
            ("drained", False), ("finalMeterVerified", True),
            ("refundableBytes", 1), ("uplinkBytes", -1),
        ]
        for key, bad in tests:
            with self.subTest(mutation=key):
                altered = {**observation, key: bad}
                with self.assertRaises(ValueError):
                    guarded.verify_committed_observed_checkpoint(
                        self.state, 12, altered, ledger)
        with self.assertRaises(ValueError):
            guarded.verify_committed_observed_checkpoint(
                self.state, 12, observation, {})
        raw = (self.state / "policy-envelope.json")
        original = raw.read_text()
        forged = json.loads(original)
        forged["policy"]["users"][0]["quotaReservation"]["revision"] = 500
        raw.write_text(json.dumps(forged))
        try:
            with self.assertRaises(ValueError):
                guarded.verify_committed_observed_checkpoint(
                    self.state, 12, observation, ledger)
        finally:
            raw.write_text(original)


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

    def test_signed_committed_meter_scope_rejects_tampering_and_pending_rights(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "xmesh_scope_guard", GUARD)
        guarded = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guarded)
        self.configure_dual_profile()
        # The prepared policy is validly signed but NOT YET committed.
        self.run_guard("prepare")
        self.assertIsNone(guarded.committed_snapshot_scope(self.state, 12))
        self.run_guard("commit")
        self.assertEqual(guarded.committed_snapshot_scope(self.state, 12), {
            1: {"vless-main", "hysteria-main"},
        })
        committed = self.state / "policy-envelope.json"
        saved = committed.read_text()
        tampered = json.loads(saved)
        tampered["policy"]["users"][0]["userId"] = 991
        committed.write_text(json.dumps(tampered))
        with self.assertRaisesRegex(ValueError, "signature"):
            guarded.committed_snapshot_scope(self.state, 12)
        committed.write_text(saved)

    def test_real_signed_reassignment_filters_published_metrics_without_losing_ledger(self):
        import importlib.util
        from unittest.mock import patch
        spec = importlib.util.spec_from_file_location("xmesh_scope_transition", GUARD)
        guarded = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(guarded)
        self.configure_dual_profile()
        second = "550e8400-e29b-41d4-a716-446655440022"
        second_user = {
            "userId": 22, "xrayId": second,
            "expireAtMs": NOW + 86400000,
            "panelUsedBytes": 0, "offlineBudgetBytes": 100,
        }
        second_client = {
            "id": second, "email": "xmesh-u22--vless-main", "level": 0,
        }
        self.policy["users"].append(second_user.copy())
        self.config["inbounds"][0]["settings"]["clients"].append(second_client.copy())
        def resign():
            self.policy["configSha256"] = hashlib.sha256(compact(self.config)).hexdigest()
            self.write_envelope()
        def export(ledger):
            permitted = guarded.committed_snapshot_scope(self.state, 12)
            with patch.object(guarded.base, "write_atomic") as write, \
                 patch.object(guarded.base.Path, "is_dir", return_value=True), \
                 patch.object(guarded.base.grp, "getgrnam", side_effect=KeyError):
                guarded.store_metrics_snapshot(ledger, 12, NOW, permitted)
            return json.loads(write.call_args.args[1])

        resign()
        self.run_guard("prepare")
        self.run_guard("commit")
        ledger = guarded.integrate_counters({}, {"1": 150, "22": 75}, "runtime-a", NOW, {
            ("1", "vless-main"): {"uplink": 60, "downlink": 40},
            ("1", "hysteria-main"): {"uplink": 30, "downlink": 20},
            ("22", "vless-main"): {"uplink": 45, "downlink": 30},
        })
        old_snapshot = export(ledger)
        self.assertEqual({row["userId"] for row in old_snapshot["userTraffic"]}, {1, 22})
        old_ledger_total = ledger["users"]["22"]["total"]

        # Signed updated revision removes user 22 from this node.
        self.policy["issuedAtMs"] = NOW + 100
        self.policy["users"] = [user for user in self.policy["users"] if user["userId"] != 22]
        self.config["inbounds"][0]["settings"]["clients"] = [
            item for item in self.config["inbounds"][0]["settings"]["clients"]
            if item["email"] != "xmesh-u22--vless-main"
        ]
        resign()
        self.run_guard("prepare", NOW + 100)
        # Pending authorization has no effect on the published scope.
        self.assertEqual({row["userId"] for row in export(ledger)["userTraffic"]}, {1, 22})
        self.run_guard("commit")
        filtered = export(ledger)
        self.assertEqual(filtered["userTraffic"], [
            {"userId": 1, "uplinkBytes": 90, "downlinkBytes": 60},
        ])
        self.assertEqual({r["userId"] for r in filtered["userInboundTraffic"]}, {1})
        self.assertEqual(ledger["users"]["22"]["total"], old_ledger_total)

        # An independent, later signed revision restores the assignment.
        self.policy["issuedAtMs"] = NOW + 200
        self.policy["users"].append(second_user.copy())
        self.config["inbounds"][0]["settings"]["clients"].append(second_client.copy())
        resign()
        self.run_guard("prepare", NOW + 200)
        self.run_guard("commit")
        restored = export(ledger)
        self.assertEqual(restored["userTraffic"], old_snapshot["userTraffic"])
        self.assertEqual(len(restored["userInboundTraffic"]), 3)
        self.assertEqual(export(ledger), restored)  # repeated send is idempotent

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

    def test_expiring_lease_never_clears_earlier_exhausted_offline_quota(self):
        self.policy["users"][0]["expireAtMs"] = 0
        self.write_envelope()
        self.run_guard("prepare")
        self.run_guard("commit")
        self.stats.write_text('{"1":150}')
        self.run_guard("offline", NOW + 1000)
        self.assertEqual(self.num_clients(), 0)
        self.run_guard("offline", self.policy["validUntilMs"])
        self.assertEqual(self.num_clients(), 0)
        self.assertEqual(
            json.loads((self.state / "policy-usage.json").read_text())["users"]["1"]["revokedReason"],
            "quota")
        # A newer signed policy without changed entitlement must not refill
        # a quota that was exhausted BEFORE the previous lease expired.
        self.policy["issuedAtMs"] = NOW + 7 * 86400000 + 1000
        self.policy["validUntilMs"] = self.policy["issuedAtMs"] + 7 * 86400000
        self.write_envelope()
        self.run_guard("prepare", self.policy["issuedAtMs"] + 1)
        self.assertEqual(self.num_clients(), 0)

    def test_unlimited_user_policy_expires_offline_then_accepts_new_signed_lease(self):
        # Null offlineBudgetBytes is an unlimited traffic quota, not infinite
        # validity for an already expired signed control-plane policy.
        self.policy["users"][0]["offlineBudgetBytes"] = None
        self.policy["users"][0]["expireAtMs"] = 0
        self.write_envelope()
        self.run_guard("prepare")
        self.run_guard("commit")
        self.run_guard("offline", self.policy["validUntilMs"] - 1)
        self.assertEqual(self.num_clients(), 1)
        self.run_guard("offline", self.policy["validUntilMs"])
        self.assertEqual(self.num_clients(), 0)
        self.run_guard("offline", self.policy["validUntilMs"] + 1)
        self.assertEqual(self.num_clients(), 0)
        # Unlike quota exhaustion, policy expiry must be recoverable once the
        # panel signs a genuinely newer lease without changing user limits.
        self.policy["issuedAtMs"] = NOW + 7 * 86400000 + 1000
        self.policy["validUntilMs"] = self.policy["issuedAtMs"] + 7 * 86400000
        self.write_envelope()
        self.run_guard("prepare", self.policy["issuedAtMs"] + 1)
        self.assertEqual(self.num_clients(), 1)
        self.run_guard("commit")
        self.run_guard("offline", self.policy["issuedAtMs"] + 2)
        self.assertEqual(self.num_clients(), 1)

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
