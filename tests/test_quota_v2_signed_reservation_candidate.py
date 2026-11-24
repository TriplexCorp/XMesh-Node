#!/usr/bin/env python3
"""CI-only synthetic Nexus Ed25519 candidate. Never starts installed Xray."""
import copy
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments/quota-v2-physical-stop"))
sys.path.insert(0, str(ROOT / "experiments/xray-dataplane-fence"))
import signed_reservation_candidate as candidate
import sign_observation as observed

NOW = 1_800_000_000_000
EPOCH = "11111111-1111-4111-8111-111111111111"
METER = "22222222-2222-4222-8222-222222222222"
RESERVATION = "33333333-3333-4333-8333-333333333333"


def fixture():
    return {
        "schemaVersion":1, "kind":candidate.KIND, "nodeId":47,
        "activationReceiptSha256":"a"*64, "containerId":"b"*64,
        "runtimeId":"c"*64, "measuredPid":7621,
        "policySha256":"d"*64, "userId":101,
        "accountEpoch":EPOCH, "meterEpoch":METER,
        "reservationId":RESERVATION, "reservationRevision":1,
        "acknowledgedBytes":10, "observedWalBytes":30,
        "observedCdnWalBytes":12,
        "sharedCeilingBytes":100, "nodeCeilingBytes":70,
        "cdnCeilingBytes":20, "inventorySequence":2,
        "inventoryTailDigest":"e"*64,
        "aliasScopes":[
            {"email":"xmesh-u101--vless-cdn","class":"cdn"},
            {"email":"xmesh-u101--vless-main","class":"main"},
        ],
        "issuedAtMs":NOW, "validUntilMs":NOW+60_000,
        "authorizedBytes":0, "canStart":False, "canResume":False,
        "finalMeterVerified":False, "refundableBytes":0,
    }


class SignedCandidateTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="xmesh-quota-cap-candidate-")
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.key=self.root/"nexus.key"
        self.pub=self.root/"nexus.pub"
        subprocess.run(["openssl","genpkey","-algorithm","Ed25519",
                        "-out",str(self.key)],check=True,capture_output=True)
        subprocess.run(["openssl","pkey","-in",str(self.key),"-pubout",
                        "-out",str(self.pub)],check=True,capture_output=True)
        self.payload=fixture()
        self.context={name:copy.deepcopy(self.payload[name]) for name in candidate.BINDINGS}

    def sign(self,payload=None,key=None):
        body=copy.deepcopy(self.payload if payload is None else payload)
        message=self.root/"payload"
        signature=self.root/"signature"
        message.write_bytes(candidate.DOMAIN+observed.canonical(body))
        subprocess.run(["openssl","pkeyutl","-sign","-rawin","-inkey",
                        str(self.key if key is None else key),
                        "-in",str(message),"-out",str(signature)],
                       check=True,capture_output=True)
        return observed.canonical({
            "algorithm":"Ed25519","payload":body,
            "signature":signature.read_bytes().hex()})+b"\n"

    def verify(self,payload=None,**kwargs):
        return candidate.verify_candidate(
            self.sign(payload),self.pub,copy.deepcopy(self.context),NOW,**kwargs)

    def prior_from(self,receipt):
        return {key:copy.deepcopy(receipt[key]) for key in (
            "bindings","reservationRevision","acknowledgedBytes",
            "observedWalBytes","observedCdnWalBytes","issuedAtMs",
            "receiptDigest")}

    def test_valid_exact_signature_still_has_no_start_authority(self):
        result=self.verify()
        self.assertTrue(result["candidateSignatureVerified"])
        self.assertTrue(result["boundToExpectedNodeRuntimeReservation"])
        self.assertEqual(result["observedWalBytes"],30)
        self.assertEqual(result["observedCdnWalBytes"],12)
        self.assertEqual(result["authorizedBytes"],0)
        self.assertIs(result["canStart"],False)
        self.assertIs(result["canResume"],False)
        self.assertFalse(result["finalMeterVerified"])
        self.assertEqual(result["refundableBytes"],0)

    def test_old_signature_and_foreign_public_key_are_rejected(self):
        signed=self.sign()
        raw=signed.replace(b'"observedWalBytes":30',b'"observedWalBytes":31')
        with self.assertRaisesRegex(ValueError,"foreign key"):
            candidate.verify_candidate(raw,self.pub,self.context,NOW)
        other=self.root/"foreign.pub"
        foreign_key=self.root/"foreign.key"
        subprocess.run(["openssl","genpkey","-algorithm","Ed25519",
                        "-out",str(foreign_key)],check=True,capture_output=True)
        subprocess.run(["openssl","pkey","-in",str(foreign_key),"-pubout",
                        "-out",str(other)],check=True,capture_output=True)
        with self.assertRaisesRegex(ValueError,"foreign key"):
            candidate.verify_candidate(signed,other,self.context,NOW)

    def test_valid_signature_cannot_change_independent_node_runtime_or_lease(self):
        swaps={
            "nodeId":48, "activationReceiptSha256":"f"*64,
            "containerId":"f"*64, "runtimeId":"f"*64, "measuredPid":9999,
            "policySha256":"f"*64, "userId":102,
            "accountEpoch":"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            "meterEpoch":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
            "reservationId":"cccccccc-cccc-4ccc-8ccc-cccccccccccc",
            "inventorySequence":3, "inventoryTailDigest":"f"*64,
            "aliasScopes":[{"email":"xmesh-u101--vless-main","class":"main"}],
        }
        for field,value in swaps.items():
            with self.subTest(field=field):
                payload=fixture()
                payload[field]=value
                with self.assertRaisesRegex(ValueError,"trusted local binding|scope|CDN"):
                    self.verify(payload)

    def test_reject_every_signed_attempt_to_turn_candidate_into_traffic_authority(self):
        for key,value in (
                ("canStart",True),("canResume",True),
                ("authorizedBytes",1),("refundableBytes",1),
                ("finalMeterVerified",True)):
            with self.subTest(key=key):
                p=fixture()
                p[key]=value
                with self.assertRaisesRegex(ValueError,"grant traffic or refunds"):
                    self.verify(p)

    def test_invalid_byte_conservation_is_rejected_even_when_signed(self):
        checks=(
            ("acknowledgedBytes",31),
            ("observedWalBytes",101),
            ("observedCdnWalBytes",21),
            ("sharedCeilingBytes",29),
            ("nodeCeilingBytes",29),
            ("cdnCeilingBytes",11),
            ("observedWalBytes",-1),
            ("sharedCeilingBytes",True),
            ("sharedCeilingBytes",2**63),
        )
        for field,value in checks:
            with self.subTest(field=field,value=value):
                p=fixture()
                p[field]=value
                with self.assertRaisesRegex(ValueError,"byte"):
                    self.verify(p)

    def test_expiry_future_issuance_oversized_lifetime_and_boolean_timestamps_fail(self):
        checks=(
            ("validUntilMs",NOW),
            ("issuedAtMs",NOW+1),
            ("validUntilMs",NOW+120_001),
            ("issuedAtMs",True),
            ("validUntilMs",None),
        )
        for field,value in checks:
            with self.subTest(field=field,value=value):
                p=fixture()
                p[field]=value
                with self.assertRaisesRegex(ValueError,"timestamp|expired"):
                    self.verify(p)
        with self.assertRaisesRegex(ValueError,"expired"):
            candidate.verify_candidate(self.sign(),self.pub,self.context,NOW+60_000)

    def test_alias_reassignment_and_duplicate_inbound_are_rejected(self):
        cases=(
            [{"email":"xmesh-u101--vless-main","class":"main"},
             {"email":"xmesh-u101--vless-main","class":"cdn"}],
            [{"email":"xmesh-u102--vless-cdn","class":"cdn"},
             {"email":"xmesh-u101--vless-main","class":"main"}],
            [{"email":"xmesh-u101--vless-main","class":"main"},
             {"email":"xmesh-u101--vless-cdn","class":"cdn"}],
            [{"email":"xmesh-u101--vless-cdn","class":"main"},
             {"email":"xmesh-u101--vless-main","class":"main"}],
        )
        for alias in cases:
            with self.subTest(aliases=alias):
                p=fixture()
                p["aliasScopes"]=alias
                with self.assertRaisesRegex(ValueError,"scope|binding|CDN"):
                    self.verify(p)

    def test_monotonic_same_lease_replay_and_revision_change(self):
        old=self.verify()
        prior=self.prior_from(old)
        self.assertEqual(self.verify(prior=prior)["receiptDigest"],old["receiptDigest"])
        moved=fixture()
        moved["reservationRevision"]=2
        moved["observedWalBytes"]=35
        moved["observedCdnWalBytes"]=12
        self.assertEqual(self.verify(moved,prior=prior)["reservationRevision"],2)
        for field,value in (("reservationRevision",0),("observedWalBytes",29),
                            ("observedCdnWalBytes",11),
                            ("acknowledgedBytes",9),
                            ("issuedAtMs",NOW-1)):
            p=fixture()
            p["reservationRevision"]=2
            p[field]=value
            with self.subTest(field=field),self.assertRaisesRegex(
                    ValueError,"replay|identity"):
                self.verify(p,prior=prior)
        conflict=fixture()
        conflict["validUntilMs"]=NOW+61_000
        with self.assertRaisesRegex(ValueError,"conflicting"):
            self.verify(conflict,prior=prior)
        altered=copy.deepcopy(prior)
        altered["bindings"]["nodeId"]=48
        with self.assertRaisesRegex(ValueError,"prior reservation changed"):
            self.verify(prior=altered)

    def test_noncanonical_unknown_duplicate_and_invalid_json_refused(self):
        signed=self.sign()
        cases=(
            signed[:-1], # canonical envelope requires newline
            signed.replace(b'"algorithm":"Ed25519"',b'"algorithm":"Ed25519","algorithm":"Ed25519"'),
            signed.replace(b'"schemaVersion":1',b'"schemaVersion":1,"other":0'),
            signed.replace(b'"authorizedBytes":0',b'"authorizedBytes":null'),
            b"{}",
        )
        for raw in cases:
            with self.subTest(raw=raw[:80]),self.assertRaises(ValueError):
                candidate.verify_candidate(raw,self.pub,self.context,NOW)


if __name__=="__main__":
    unittest.main()
