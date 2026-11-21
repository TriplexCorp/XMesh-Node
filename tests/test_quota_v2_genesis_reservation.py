#!/usr/bin/env python3
"""OpenSSL Ed25519 negative tests: strict Genesis SQL lease has ZERO authority."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/"experiments"/"quota-v2-physical-stop"))
from test_quota_v2_quarantine_handoff import QuarantinePolicyTests
import genesis_reservation as lease
import quarantine_policy as qp


class SignedGenesisLeaseTests(unittest.TestCase):
    def setUp(self):
        f = QuarantinePolicyTests(
            "test_true_openssl_signer_and_exact_original_quarantine_pass")
        f.setUp()
        self.addCleanup(f.doCleanups)
        self.f = f
        self.node, self.user = 47, 101
        self.now = f.now
        self.guard = f.guard
        self.origin = {
            "prepared":copy.deepcopy(f.prepared),
            "reply":f.signed_doc(users=[{
                "userId":self.user, "xrayId":"11111111-1111-4111-8111-111111111111",
                "offlineBudgetBytes":0, "onHold":True,
            }]),
        }
        self.origin["prepared"]["signature"] = self.sign(
            qp.wal_transport.GENESIS_DOMAIN,
            self.origin["prepared"]["payload"])
        self.identity = {
            "nodeId":self.node,
            "activationReceiptSha256":f.activation,
        }
        self.reservation = {
            "epoch":"11111111-1111-4111-8111-111111111111",
            "meterEpoch":"22222222-2222-4222-8222-222222222222",
            "reservationId":"33333333-3333-4333-8333-333333333333",
            "revision":1, "acknowledgedBytes":0, "ceilingBytes":0,
            "validUntilMs":self.now+3_600_000,
        }
        self.prepared = self.signed("prepare")

    def sign(self, domain, payload):
        path = self.f.root / "lease-message"
        signature = self.f.root / "lease-signature"
        path.write_bytes(domain+self.guard.canonical(payload))
        subprocess.run(
            ["openssl","pkeyutl","-sign","-inkey",str(self.f.private),
             "-rawin","-in",str(path),"-out",str(signature)],
            check=True, capture_output=True)
        return signature.read_bytes().hex()

    def signed(self, operation, change=None):
        claim = {
            "schemaVersion":1,
            "kind":"xmesh.quota-v2.genesis-lease-identity",
            "status": "prepared" if operation=="prepare" else "confirmed",
            "nodeId":self.node, "userId":self.user,
            "activationReceiptSha256":self.f.activation,
            "runtimeId":self.f.runtime,
            "genesisChallenge":self.f.challenge,
            "policySha256":self.origin["reply"]["policySha256"],
            "issuedAtMs":self.now,
            "reservation":copy.deepcopy(self.reservation),
            "authorizedBytes":0, "canSpend":False,
            "canStart":False, "canResume":False,
            "finalMeterVerified":False, "refundableBytes":0,
        }
        if operation=="confirm":
            claim["reservation"]["ceilingBytes"]=1_048_576
        if change:
            key, value = change
            if key.startswith("reservation."):
                claim["reservation"][key.split(".",1)[1]] = value
            else:
                claim[key] = value
        envelope = {
            "algorithm":"Ed25519","payload":claim,
            "signature":self.sign(b"",claim),
        }
        return self.guard.canonical(envelope)

    def verify(self, raw, operation="prepare", previous=None, now=None):
        return lease.verify_lease_response(
            raw, self.node, self.user, operation,
            self.origin, self.f.pub, self.f.activation,
            previous=previous, now_ms=self.now if now is None else now)

    def test_actual_openssl_positive_prepared_and_confirmed_are_zero_authority(self):
        p = self.verify(self.prepared)
        c = self.verify(self.signed("confirm"), "confirm", previous=p)
        for result in [p, c]:
            self.assertEqual(result["payload"]["authorizedBytes"], 0)
            self.assertIs(result["payload"]["canSpend"], False)
            self.assertIs(result["payload"]["canStart"], False)
            self.assertIs(result["payload"]["canResume"], False)
        self.assertEqual(p["payload"]["reservation"]["ceilingBytes"], 0)
        self.assertEqual(c["payload"]["reservation"]["ceilingBytes"], 1048576)

    def test_signed_foreign_identity_or_permission_is_rejected(self):
        tests = [
            ("status","confirmed"),
            ("nodeId",48),
            ("userId",102),
            ("runtimeId","1"*64),
            ("activationReceiptSha256","2"*64),
            ("genesisChallenge","3"*64),
            ("policySha256","4"*64),
            ("canSpend",True),
            ("canStart",True),
            ("canResume",True),
            ("refundableBytes",1),
            ("authorizedBytes",1),
            ("finalMeterVerified",True),
            ("issuedAtMs",self.now+120000),
            ("reservation.ceilingBytes",1),
            ("reservation.acknowledgedBytes",1),
            ("reservation.reservationId","different"),
            ("reservation.epoch","definitely-invalid"),
            ("reservation.validUntilMs",self.now-1),
        ]
        for name, value in tests:
            with self.subTest(field=name):
                with self.assertRaises(ValueError):
                    self.verify(self.signed("prepare",(name,value)))
        with self.assertRaises(ValueError):
            self.verify(self.signed("confirm"),"confirm",
                        previous={"payload":{"reservation":{
                            **self.reservation,"reservationId":"4"*8+"-4444-4444-8444-444444444444"}}})

    def test_duplicate_or_forged_signed_reply_is_rejected(self):
        raw = self.signed("prepare")
        bad = raw.replace(b'"algorithm":"Ed25519"',
                          b'"algorithm":"Ed25519","algorithm":"Ed25519"',1)
        with self.assertRaises(ValueError):
            self.verify(bad)
        altered = json.loads(raw)
        altered["signature"] = "0"*128
        with self.assertRaises(ValueError):
            self.verify(self.guard.canonical(altered))
        with self.assertRaises(ValueError):
            lease.verify_lease_response(
                raw, self.node, self.user,"prepare",self.origin,
                "5"*64,self.f.activation, now_ms=self.now)

    def test_installed_lease_prepare_and_confirm_only_under_root_lock(self):
        if os.geteuid() != 0:
            self.skipTest("root-only installed Agent evidence")
        state = self.f.root / "state"
        state.mkdir(mode=0o700)
        original = state / "genesis-quarantine-envelope.json"
        original.write_bytes(self.guard.canonical(self.origin))
        original.chmod(0o600)
        actual = ("f"*64,"2026-11-21T00:00:00Z",4321,self.f.runtime)
        with (
            mock.patch.object(qp.wal_transport,"_panel_pin",return_value=self.f.pub),
            mock.patch.object(qp,"_enrolled_activation",return_value=self.identity),
            mock.patch.object(qp.wal_transport,"_measure_quarantined_runtime",
                              return_value=actual),
            mock.patch.object(qp,"_post_quarantined_desired",
                              side_effect=[self.prepared,self.signed("confirm")]) as network,
        ):
            first = lease.run("https://isolated-ci.example",self.node,self.user,
                              str(state),"prepare")
            second = lease.run("https://isolated-ci.example",self.node,self.user,
                               str(state),"confirm")
        self.assertEqual(first["authorizedBytes"],0)
        self.assertEqual(second["authorizedBytes"],0)
        self.assertEqual(network.call_count,2)
        self.assertEqual(network.call_args_list[0].args[1],str(state))
        self.assertEqual(network.call_args_list[0].args[2],qp.LEASE_PATH)
        confirmed_body = network.call_args_list[1].args[0]
        self.assertEqual(confirmed_body["echo"]["reservationId"],
                         self.reservation["reservationId"])
        self.assertTrue((state/f"genesis-reservation-prepared-u{self.user}.json").is_file())
        self.assertTrue((state/f"genesis-reservation-confirmed-u{self.user}.json").is_file())
        with self.assertRaises(ValueError):
            qp._durable_store(os.open(state,os.O_DIRECTORY),
                              {"forged":True},"genesis-reservation-../grant.json")


if __name__ == "__main__":
    unittest.main()
