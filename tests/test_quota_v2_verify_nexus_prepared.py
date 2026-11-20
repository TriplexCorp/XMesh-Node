#!/usr/bin/env python3
"""Independent Node verification of Nexus PREPARED-ONLY receipt.

Uses the actual Node signed old-PID fixture with real pidfd exit and old
WAL; a disposable OpenSSL Nexus signer constructs protocol-compatible
receipts, but NO Nexus source is imported and NO Xray gate is modified.
"""
import copy
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"experiments/quota-v2-physical-stop"))
import rollover_prepare
import sign_observation as observed
import stop_chain
import verify_nexus_prepared as nexus
from test_quota_v2_rollover_prepare import ConservativeRolloverProposalTests


class VerifyNexusPreparedReceiptTests(unittest.TestCase):
    def setUp(self):
        self.fi=ConservativeRolloverProposalTests(
            "test_signed_old_pid_evidence_and_byte_wal_yield_non_authorizing_proposal")
        self.fi.setUp()
        self.addCleanup(self.fi.doCleanups)
        self.proposal=self.fi.prepare()
        self.raw=observed.canonical(self.proposal)+b"\n"
        self.scope={key:self.fi.fx.cp[key] for key in stop_chain.SCOPE}
        self.temp=tempfile.TemporaryDirectory(prefix="xmesh-nexus-node-verifier-")
        self.addCleanup(self.temp.cleanup)
        root=Path(self.temp.name)
        self.key=root/"nexus.key"
        self.pub=root/"nexus.pub"
        subprocess.run(["openssl","genpkey","-algorithm","Ed25519",
                        "-out",str(self.key)],check=True,capture_output=True)
        os.chmod(self.key,0o600)
        subprocess.run(["openssl","pkey","-in",str(self.key),
                        "-pubout","-out",str(self.pub)],
                       check=True,capture_output=True)
        self.stage_hash=hashlib.sha256(b"synthetic immutable Nexus stage row").hexdigest()
        src=self.proposal["payload"]
        self.payload={key:self.scope[key] for key in stop_chain.SCOPE}
        self.payload.update({
            "schemaVersion":1,"kind":nexus.KIND,
            "oldRuntimeId":src["oldRuntimeId"],
            "oldContainerId":src["oldContainerId"],
            "oldStartedAt":src["oldStartedAt"],
            "proposalSha256":hashlib.sha256(self.raw).hexdigest(),
            "stopChainSha256":src["stopChainSha256"],
            "xrayJournalSha256":src["xrayJournalSha256"],
            "stagedLedgerRowSha256":self.stage_hash,
            "nodeDurableAbsoluteFloorBytes":src["nodeDurableAbsoluteFloorBytes"],
            "oldRuntimeObservedUplinkBytes":src["oldRuntimeObservedUplinkBytes"],
            "oldRuntimeObservedDownlinkBytes":src["oldRuntimeObservedDownlinkBytes"],
            "nexusRecordedPrepared":True,
            "absoluteCarryforwardVerified":False,
            "rolloverAuthorized":False,
            "resumptionAllowed":False,
            "finalMeterVerified":False,
            "settlementEligible":False,
            "refundableBytes":0,
        })

    def signed(self,payload=None,private_key=None,domain=nexus.DOMAIN):
        content=self.payload if payload is None else payload
        with tempfile.TemporaryDirectory(prefix="xmesh-nexus-signer-") as temp:
            message=Path(temp)/"msg"
            message.write_bytes(domain+observed.canonical(content))
            signature=subprocess.run(
                ["openssl","pkeyutl","-sign","-rawin","-in",str(message),
                 "-inkey",str(self.key if private_key is None else private_key)],
                check=True,capture_output=True).stdout.hex()
        return observed.canonical({
            "algorithm":"Ed25519","payload":content,"signature":signature})+b"\n"

    def verify(self,receipt,**changed):
        return nexus.verify_nexus_prepared_registration(
            receipt,changed.get("nexus_pub",self.pub),
            changed.get("scope",self.scope),
            changed.get("proposal",self.raw),
            changed.get("observed",self.fi.fx.original),
            changed.get("stop",self.fi.stop_raw),
            changed.get("node_pub",self.fi.fx.pub),
            changed.get("wal",self.fi.journal_digest))

    def test_valid_nexus_prepared_receipt_never_authorizes_an_old_runtime(self):
        original=self.signed()
        result=self.verify(original)
        self.assertTrue(result["nodeValidatedNexusPreparedRegistration"])
        self.assertTrue(result["authenticatedOldNodeRollover"])
        self.assertEqual(result["nexusClaimedStagedLedgerRowSha256"],self.stage_hash)
        self.assertFalse(result["nodeIndependentlyReadNexusDatabase"])
        for name in ("carryforwardApplied","canResume","finalMeterVerified",
                     "settlementEligible"):
            self.assertIs(result[name],False)
        self.assertEqual(result["refundableBytes"],0)
        self.assertEqual(self.verify(original),result)

    def test_resigned_false_to_true_authorizations_and_overshoot_rejected(self):
        cases=(
            ("nexusRecordedPrepared",False),
            ("absoluteCarryforwardVerified",True),
            ("rolloverAuthorized",True),
            ("resumptionAllowed",True),
            ("finalMeterVerified",True),
            ("settlementEligible",True),
            ("refundableBytes",1),
            ("rolloverAuthorized",0),
            ("resumptionAllowed",0),
            ("schemaVersion",2),
            ("oldRuntimeObservedUplinkBytes",8),
            ("oldRuntimeObservedDownlinkBytes",14),
            ("nodeDurableAbsoluteFloorBytes",21),
            ("stagedLedgerRowSha256","wrong"),
            ("proposalSha256","b"*64),
            ("stopChainSha256","f"*64),
            ("xrayJournalSha256","a"*64),
            ("oldRuntimeId","a"*64),
            ("oldContainerId","b"*64),
            ("oldStartedAt","2026-11-19T00:00:00Z"),
        )
        for key,value in cases:
            with self.subTest(change=(key,value)):
                payload=copy.deepcopy(self.payload)
                payload[key]=value
                with self.assertRaises(ValueError):
                    self.verify(self.signed(payload))

    def test_all_foreign_reservations_and_aliases_rejected(self):
        for key,value in (
            ("nodeId",10),("userId",102),("revision",4),
            ("epoch","11111111-1111-4111-8111-222222222222"),
            ("meterEpoch","22222222-2222-4222-8222-333333333333"),
            ("reservationId","33333333-3333-4333-8333-555555555555"),
            ("revocationId","44444444-4444-4444-8444-555555555555"),
        ):
            with self.subTest(field=key):
                payload=copy.deepcopy(self.payload)
                payload[key]=value
                with self.assertRaises(ValueError):
                    self.verify(self.signed(payload))
                with self.assertRaises(ValueError):
                    self.verify(self.signed(),scope=dict(self.scope,**{key:value}))

    def test_enrolled_nexus_key_and_ed25519_domain_cannot_be_substituted(self):
        receipt=self.signed()
        other=Path(self.temp.name)/"foreign.key"
        otherpub=Path(self.temp.name)/"foreign.pub"
        subprocess.run(["openssl","genpkey","-algorithm","Ed25519",
                        "-out",str(other)],check=True,capture_output=True)
        subprocess.run(["openssl","pkey","-in",str(other),"-pubout",
                        "-out",str(otherpub)],check=True,capture_output=True)
        for invalid in (
            self.signed(private_key=other),
            self.signed(domain=rollover_prepare.DOMAIN),
            receipt.replace(b'"signature":"',b'"signature":"0',1),
        ):
            with self.assertRaises(ValueError):
                self.verify(invalid)
        with self.assertRaises(ValueError):
            self.verify(receipt,nexus_pub=otherpub)

    def test_original_node_signed_source_old_wal_and_scope_cannot_change(self):
        receipt=self.signed()
        with self.assertRaises(ValueError):
            self.verify(receipt,wal="f"*64)
        with self.assertRaises(ValueError):
            self.verify(receipt,proposal=self.raw[:-1]+b" ")
        with self.assertRaises(ValueError):
            self.verify(receipt,observed=self.fi.fx.original[:-1]+b" ")
        with self.assertRaises(ValueError):
            self.verify(receipt,stop=self.fi.stop_raw[:-1]+b" ")
        forged=copy.deepcopy(self.proposal)
        forged["payload"]["inboundMeters"][0]["uplinkBytes"]+=1
        with self.assertRaises(ValueError):
            self.verify(receipt,proposal=observed.canonical(forged)+b"\n")

    def test_unknown_fields_reordered_json_duplicate_keys_and_noncanonical_denied(self):
        original=self.signed()
        for invalid in (
            original+b"\n",
            original[:-1]+b" ",
            original.replace(b'"algorithm":',
                             b'"algorithm":"Ed25519","algorithm":',1),
            original.replace(b'"schemaVersion":1',b'"schemaVersion":1.0',1),
        ):
            with self.subTest(invalid=invalid[:30]),self.assertRaises(ValueError):
                self.verify(invalid)
        payload=copy.deepcopy(self.payload)
        payload["approvedBytes"]=1
        with self.assertRaises(ValueError):
            self.verify(self.signed(payload))

    def test_nexus_signed_different_staging_hash_is_only_an_untrusted_db_claim(self):
        # A new Nexus-signed digest may be cryptographically valid. The Node
        # has NO independent SQL view and MUST NOT treat that fact as a
        # applied carryforward, user release or verified final byte count.
        payload=copy.deepcopy(self.payload)
        payload["stagedLedgerRowSha256"]=hashlib.sha256(b"second-claim").hexdigest()
        result=self.verify(self.signed(payload))
        self.assertTrue(result["nodeValidatedNexusPreparedRegistration"])
        self.assertFalse(result["nodeIndependentlyReadNexusDatabase"])
        self.assertFalse(result["carryforwardApplied"])
        self.assertFalse(result["canResume"])


if __name__=="__main__":
    unittest.main()
