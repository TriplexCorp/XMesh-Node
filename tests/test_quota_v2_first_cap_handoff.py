#!/usr/bin/env python3
"""Real OpenSSL Ed25519 tests for staged-policy -> signed-cap ownership.

No production panel, release, public listener, or simulated positive issuer.
The signed bytes are test fixtures, never authority to enable Quota V2.
"""
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments" / "quota-v2-physical-stop"))

from test_quota_v2_quarantine_handoff import QuarantinePolicyTests
import first_cap_handoff as cap
import quarantine_policy as quarantine


class FirstCapHandoffTests(unittest.TestCase):
    def setUp(self):
        fixture = QuarantinePolicyTests("test_true_openssl_signer_and_exact_original_quarantine_pass")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.fixture = fixture
        self.guard = fixture.guard
        self.node = fixture.node
        self.now = fixture.now
        self.runtime = fixture.runtime
        self.pub = fixture.pub
        self.xray_id = "11111111-1111-4111-8111-111111111111"
        self.aliases = [
            {"email": "xmesh-u100--vless-cdn", "class": "cdn"},
            {"email": "xmesh-u100--vless-main", "class": "main"},
        ]
        self.prepared = copy.deepcopy(fixture.prepared)
        self.prepared["signature"] = self.sign(
            cap.wal_transport.GENESIS_DOMAIN, self.prepared["payload"])
        self.reply = fixture.signed_doc(users=[{
            "userId": 100, "xrayId": self.xray_id,
            "offlineBudgetBytes": 0, "onHold": True,
        }])
        self.reply["config"]["inbounds"] = [
            {"tag": f"vless-{cls}", "protocol": "vless",
             "listen": "127.0.0.1",
             "settings": {"clients": [{
                 "email": f"xmesh-u100--vless-{cls}", "id": self.xray_id,
             }]}}
            for cls in ("main", "cdn")
        ]
        self.resign_policy()
        self.claims = {
            "schemaVersion": 1, "kind": "xmesh.quota-v2.xray-cap-admission",
            "nodeId": self.node, "userId": 100,
            "activationReceiptSha256": fixture.activation,
            "runtimeId": self.runtime, "policySha256": self.reply["policySha256"],
            "accountEpoch": "22222222-2222-4222-8222-222222222222",
            "meterEpoch": "33333333-3333-4333-8333-333333333333",
            "reservationId": "44444444-4444-4444-8444-444444444444",
            "reservationRevision": 1, "nonce": "d" * 64,
            "inventoryTailDigest": "0" * 64,
            "witnessedWalBytes": 0, "witnessedCdnBytes": 0,
            "sharedCeilingBytes": 1000, "nodeCeilingBytes": 1000,
            "cdnCeilingBytes": 150, "aliasScopes": self.aliases,
            "issuedAtMs": self.now,
            "installBeforeMs": self.now + 30_000,
            "validUntilMs": self.now + 180_000,
            "canSpend": True, "canStart": False, "canResume": False,
            "finalMeterVerified": False, "refundableBytes": 0,
        }

    def sign(self, domain, payload):
        data = self.fixture.root / "cap-message.bin"
        signature = self.fixture.root / "cap-message.sig"
        data.write_bytes(domain + self.guard.canonical(payload))
        subprocess.run([
            "openssl", "pkeyutl", "-sign", "-inkey", str(self.fixture.private),
            "-rawin", "-in", str(data), "-out", str(signature),
        ], check=True, capture_output=True)
        return signature.read_bytes().hex()

    def resign_policy(self):
        digest = hashlib.sha256(
            self.guard.canonical(self.reply["config"])).hexdigest()
        self.reply["revision"] = digest
        self.reply["policy"]["configSha256"] = digest
        self.reply["policySignature"] = self.sign(b"", self.reply["policy"])
        self.reply["policySha256"] = hashlib.sha256(
            self.guard.canonical(self.reply["policy"])).hexdigest()

    def evidence(self):
        return {"prepared": self.prepared, "reply": self.reply}

    def signed_grant(self, claims=None):
        p = self.claims if claims is None else claims
        return self.guard.canonical({
            "algorithm": "Ed25519", "payload": p,
            "signature": self.sign(cap.DOMAIN, p),
        }) + b"\n"

    def test_renewal_scope_and_conservative_floors(self):
        nonce = "a" * 64
        claims = dict(self.claims, kind="xmesh.quota-v2.xray-cap-renewal",
                      nonce=nonce, reservationRevision=2, sharedCeilingBytes=1250,
                      nodeCeilingBytes=1250, cdnCeilingBytes=200,
                      witnessedWalBytes=600, witnessedCdnBytes=100,
                      inventoryTailDigest="b" * 64)
        prior = self.signed_grant()
        scope = cap.verify_renewal(self.signed_grant(claims), prior, self.pub, nonce)
        self.assertEqual(scope["revision"], 2)
        self.assertEqual(scope["aliases"], self.aliases)
        for field, value in (
            ("reservationRevision", 3), ("runtimeId", "f" * 64),
            ("nonce", "b" * 64), ("sharedCeilingBytes", 999),
            ("witnessedWalBytes", 1001), ("witnessedCdnBytes", 151),
            ("validUntilMs", self.claims["validUntilMs"] + 1),
        ):
            with self.subTest(field=field), self.assertRaises(ValueError):
                cap.verify_renewal(self.signed_grant(dict(claims, **{field: value})),
                                   prior, self.pub, nonce)

    def verify(self, claims=None):
        return cap.verify_grant(
            self.signed_grant(claims), self.evidence(),
            self.pub, self.runtime, self.now)

    def test_original_nexus_signer_and_real_assigned_vless_scope(self):
        result = self.verify()
        self.assertEqual(result["userId"], 100)
        self.assertEqual(result["policySha256"], self.reply["policySha256"])
        self.assertEqual(result["aliases"], self.aliases)
        self.assertEqual(result["nonce"], "d" * 64)
        # No canStart or allowance is minted by this verifier.
        self.assertNotIn("canStart", result)
        self.assertNotIn("sharedCeilingBytes", result)

    def test_reject_independently_signed_but_foreign_authority(self):
        changes = {
            "foreign node": ("nodeId", 48),
            "foreign user": ("userId", 101),
            "foreign activation": ("activationReceiptSha256", "8" * 64),
            "foreign runtime": ("runtimeId", "9" * 64),
            "other signed policy": ("policySha256", "a" * 64),
            "old WAL": ("witnessedWalBytes", 1),
            "old CDN": ("witnessedCdnBytes", 1),
            "nonempty WAL head": ("inventoryTailDigest", "b" * 64),
            "free restart": ("canStart", True),
            "free resume": ("canResume", True),
            "implied finality": ("finalMeterVerified", True),
            "refund": ("refundableBytes", 1),
            "over 64MiB": ("sharedCeilingBytes", cap.MAX_CAP + 1),
            "CDN over share": ("cdnCeilingBytes", 1001),
            "unsigned class": ("aliasScopes", [{
                "email": "xmesh-u100--vless-cdn", "class": "main"}]),
            "missing user alias": ("aliasScopes", [{
                "email": "xmesh-u999--vless-main", "class": "main"}]),
            "future issue": ("issuedAtMs", self.now + 10),
            "expired install": ("installBeforeMs", self.now),
            "long install": ("installBeforeMs", self.now + 121_000),
            "invalid UUID": ("reservationId", "111"),
            "bool id": ("nodeId", True),
        }
        for label, (field, value) in changes.items():
            with self.subTest(label=label):
                p = copy.deepcopy(self.claims)
                p[field] = value
                with self.assertRaises(ValueError):
                    self.verify(p)

    def test_reject_correct_signature_with_alias_not_in_signed_config(self):
        self.reply["config"]["inbounds"][1]["settings"]["clients"][0]["id"] = (
            "55555555-5555-4555-8555-555555555555")
        self.resign_policy()
        self.claims["policySha256"] = self.reply["policySha256"]
        with self.assertRaises(ValueError):
            self.verify()

    def test_reject_duplicate_aliases_and_extra_claims(self):
        for aliases in (self.aliases[::-1], [self.aliases[0], self.aliases[0]]):
            p = copy.deepcopy(self.claims)
            p["aliasScopes"] = aliases
            with self.assertRaises(ValueError):
                self.verify(p)
        p = copy.deepcopy(self.claims)
        p["canOpenPublicIngress"] = True
        with self.assertRaises(ValueError):
            self.verify(p)

    def test_reject_spoofed_signatures_and_reformatted_envelope(self):
        valid = self.signed_grant()
        forged = json.loads(valid)
        forged["signature"] = ("0" if forged["signature"][0] != "0" else "1") + forged["signature"][1:]
        with self.assertRaises(ValueError):
            cap.verify_grant(self.guard.canonical(forged) + b"\n",
                             self.evidence(), self.pub, self.runtime, self.now)
        with self.assertRaises(ValueError):
            cap.verify_grant(valid.strip(), self.evidence(),
                             self.pub, self.runtime, self.now)
        # Reject duplicate keys even when the last value equals the original.
        duplicate = valid.replace(b'"algorithm":"Ed25519"',
                                  b'"algorithm":"Ed25519","algorithm":"Ed25519"', 1)
        with self.assertRaises(ValueError):
            cap.verify_grant(duplicate, self.evidence(),
                             self.pub, self.runtime, self.now)

    def test_reject_modified_prepared_genesis_or_expired_quarantine(self):
        saved = self.evidence()
        saved["prepared"] = copy.deepcopy(self.prepared)
        saved["prepared"]["signature"] = "0" * 128
        with self.assertRaises(ValueError):
            cap.verify_grant(self.signed_grant(), saved,
                             self.pub, self.runtime, self.now)
        with self.assertRaises(ValueError):
            cap.verify_grant(self.signed_grant(), self.evidence(),
                             self.pub, self.runtime, self.now + 120_000)


    def confirmed_lease(self, status="confirmed"):
        reserve = {
            "epoch":self.claims["accountEpoch"],
            "meterEpoch":self.claims["meterEpoch"],
            "reservationId":self.claims["reservationId"],
            "revision":self.claims["reservationRevision"],
            "acknowledgedBytes":0,
            "ceilingBytes":self.claims["sharedCeilingBytes"] if status == "confirmed" else 0,
            "validUntilMs":self.now+3_600_000,
        }
        payload = {
            "schemaVersion":1,
            "kind":"xmesh.quota-v2.genesis-lease-identity",
            "status":status,
            "nodeId":self.node,
            "userId":self.claims["userId"],
            "activationReceiptSha256":self.fixture.activation,
            "runtimeId":self.runtime,
            "genesisChallenge":self.prepared["payload"]["challenge"],
            "policySha256":self.reply["policySha256"],
            "reservation":reserve,
            "issuedAtMs":self.now,
            "authorizedBytes":0,"canSpend":False,"canStart":False,
            "canResume":False,"finalMeterVerified":False,"refundableBytes":0,
        }
        return {
            "algorithm":"Ed25519","payload":payload,
            "signature":self.sign(b"",payload),
        }

    def test_private_genesis_evidence_delivers_only_derived_signed_scope(self):
        if __import__("os").geteuid() != 0:
            self.skipTest("private installed Agent evidence requires root")
        state = self.fixture.root / "state"
        state.mkdir(mode=0o700)
        evidence_path = state / "genesis-quarantine-envelope.json"
        evidence_path.write_bytes(self.guard.canonical(self.evidence()))
        evidence_path.chmod(0o600)
        prepared_path = state / "genesis-reservation-prepared-u100.json"
        prepared_path.write_bytes(self.guard.canonical(self.confirmed_lease("prepared")))
        prepared_path.chmod(0o600)
        confirmed_path = state / "genesis-reservation-confirmed-u100.json"
        confirmed_path.write_bytes(self.guard.canonical(self.confirmed_lease()))
        confirmed_path.chmod(0o600)
        observed = ("f" * 64, "2026-11-21T00:00:00Z", 4321, self.runtime)
        product = {
            "nodeId": self.node,
            "activationReceiptSha256": self.fixture.activation,
        }
        grant = self.signed_grant()
        with (
            mock.patch.object(cap.wal_transport, "_panel_pin", return_value=self.pub),
            mock.patch.object(cap.wal_transport, "_measure_quarantined_runtime",
                              return_value=observed),
            mock.patch.object(quarantine, "_enrolled_activation",
                              return_value=product),
            mock.patch.object(cap.cap_install, "install_in_xray",
                              return_value={"runtimeId": self.runtime}) as installed,
        ):
            receipt = cap.install_staged_cap(
                "https://isolated-ci.example", self.node, str(state),
                "/private/measured-xray.sock", grant, "e" * 64)
        self.assertEqual(receipt["runtimeId"], self.runtime)
        installed.assert_called_once()
        sent = installed.call_args.args
        self.assertEqual(sent[1:3], (4321, self.runtime))
        self.assertEqual(sent[3], self.guard.canonical(self.prepared))
        self.assertEqual(sent[4], grant)
        self.assertEqual(sent[5]["aliases"], self.aliases)
        self.assertEqual(sent[5]["reservationId"], self.claims["reservationId"])

    def test_first_issuance_sends_the_measured_runtime_over_the_product_client(self):
        import os

        if os.geteuid() != 0:
            self.skipTest("private installed Agent evidence requires root")
        state = self.fixture.root / "state"
        state.mkdir(mode=0o700)
        grant = self.signed_grant()
        identity = {"nodeId": self.node, "activationReceiptSha256": self.fixture.activation}
        observed = ("f"*64, "2026-11-21T00:00:00Z", 4321, self.runtime)
        response = {"status": "committed_first_cap", "nodeId": self.node,
                    "userId": 100, "signedEnvelope": grant.decode()}
        with (
            mock.patch.dict(os.environ, {"XMESH_QUOTA_V2_INSTALLED_CAP_DELIVERY": "1"}),
            mock.patch.object(cap.wal_transport, "_panel_pin", return_value=self.pub),
            mock.patch.object(cap.wal_transport, "_measure_quarantined_runtime", return_value=observed),
            mock.patch.object(quarantine, "_enrolled_activation", return_value=identity),
            mock.patch.object(cap.confirmed_lease, "_staged_original", return_value=self.evidence()),
            mock.patch.object(quarantine, "_post_quarantined_desired",
                              return_value=self.guard.canonical(response)) as posted,
            mock.patch.object(cap, "install_staged_cap") as install,
        ):
            marker = state / "genesis-positive-cap-u100.json"
            def lose_local_ack(*args):
                self.assertFalse(marker.exists())
                raise OSError("Unix reply lost")
            install.side_effect = lose_local_ack
            args = ("https://isolated-ci.example", self.node, 100, str(state),
                    "/private/measured-xray.sock", "e"*64, self.claims["nonce"])
            with self.assertRaisesRegex(OSError, "reply lost"):
                cap.fetch_and_install_rehearsal(*args)
            self.assertFalse(marker.exists())
            install.side_effect = None
            install.return_value = {"runtimeId": self.runtime}
            cap.fetch_and_install_rehearsal(*args)
            self.assertEqual(posted.call_args_list[0], posted.call_args_list[1])
        posted.assert_called_with({
            "nodeId": self.node, "userId": 100, "requestChallenge": self.claims["nonce"],
            "measurement": {"containerId": "f"*64, "hostPid": 4321, "runtimeId": self.runtime},
        }, str(state), quarantine.CAP_DELIVERY_PATH)
        self.assertEqual(json.loads((state/"genesis-positive-cap-u100.json").read_bytes()), response)

    def test_signed_cap_cannot_skip_the_original_prepared_echo(self):
        if __import__("os").geteuid() != 0:
            self.skipTest("root-private signed prepare evidence requires root")
        state = self.fixture.root / "state"
        state.mkdir(mode=0o700)
        original = state / "genesis-quarantine-envelope.json"
        original.write_bytes(self.guard.canonical(self.evidence()))
        original.chmod(0o600)
        confirmed = state / "genesis-reservation-confirmed-u100.json"
        confirmed.write_bytes(self.guard.canonical(self.confirmed_lease()))
        confirmed.chmod(0o600)
        before = ("f"*64, "2026-11-21T00:00:00Z", 4321, self.runtime)
        activation = {"nodeId":self.node,
                      "activationReceiptSha256":self.fixture.activation}
        with (
            mock.patch.object(cap.wal_transport,"_panel_pin",return_value=self.pub),
            mock.patch.object(cap.wal_transport,"_measure_quarantined_runtime",
                              return_value=before),
            mock.patch.object(quarantine,"_enrolled_activation",
                              return_value=activation),
            mock.patch.object(cap.cap_install,"install_in_xray") as installed,
        ):
            with self.assertRaises((OSError,ValueError)):
                cap.install_staged_cap(
                    "https://isolated-ci.example",self.node,str(state),
                    "/private/measured-xray.sock",self.signed_grant(),"e"*64)
        installed.assert_not_called()

    def test_local_install_rejects_changed_activation_before_socket(self):
        if __import__("os").geteuid() != 0:
            self.skipTest("private installed Agent evidence requires root")
        state = self.fixture.root / "state"
        state.mkdir(mode=0o700)
        evidence_path = state / "genesis-quarantine-envelope.json"
        evidence_path.write_bytes(self.guard.canonical(self.evidence()))
        evidence_path.chmod(0o600)
        observed = ("f" * 64, "2026-11-21T00:00:00Z", 4321, self.runtime)
        product = {
            "nodeId": self.node,
            "activationReceiptSha256": "5" * 64,
        }
        with (
            mock.patch.object(cap.wal_transport, "_panel_pin", return_value=self.pub),
            mock.patch.object(cap.wal_transport, "_measure_quarantined_runtime",
                              return_value=observed),
            mock.patch.object(quarantine, "_enrolled_activation",
                              return_value=product),
            mock.patch.object(cap.cap_install, "install_in_xray") as installed,
        ):
            with self.assertRaises(ValueError):
                cap.install_staged_cap(
                    "https://isolated-ci.example", self.node, str(state),
                    "/private/measured-xray.sock", self.signed_grant(), "e" * 64)
        installed.assert_not_called()


if __name__ == "__main__":
    unittest.main()
