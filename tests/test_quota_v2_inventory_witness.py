#!/usr/bin/env python3
"""Disposable Node WAL-to-off-host witness and rollback-detection tests.

A running Linux child and real pidfd-style Docker identity fixture produce
synthetic locally fsynced Go-format birth-indexed Xray byte WALs. They do NOT
prove transmitted bytes, process writer completion, remote persistence or
any quota refund eligibility.
"""
import copy
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"experiments/quota-v2-physical-stop"))
import witness_inventory as witness
import journal_integrity as journal
import meter_inventory_audit as registry
import sign_observation as signed
import quota_v2_meter_wal_fixture
from test_quota_v2_stop_chain import StopChainTests


class ExternalInventoryWitnessTests(unittest.TestCase):
    def setUp(self):
        self.fx=StopChainTests("test_unrelated_user_wal_does_not_block_signed_account_stop")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.node=self.fx.cp["nodeId"]
        self.pub=self.fx.pub
        self.docker=self.fx.before
        self.directory=self.fx.xray

    def witness(self):
        return witness.produce_witness(
            self.node,self.docker,str(self.directory),self.fx.key,self.pub)

    def verify(self,receipt,raw,**kwargs):
        return witness.verify_local_against_remote_prefix(
            str(self.directory),kwargs.get("registry",raw),
            kwargs.get("node",self.node),kwargs.get("receipt",receipt),
            kwargs.get("pub",self.pub))

    def test_witness_includes_real_local_full_wal_births_and_strict_nonauthority(self):
        receipt,raw=self.witness()
        p=witness._verify_witness(receipt,raw,self.node,self.pub)
        self.assertEqual(p["inventorySha256"],witness.hashlib.sha256(raw).hexdigest())
        self.assertEqual(p["inventorySequence"],2)
        self.assertEqual(p["indexedWalCount"],2)
        self.assertTrue(p["localBirthsIndependentlyChecked"])
        self.assertFalse(p["nexusPersisted"])
        self.assertFalse(p["canResume"])
        self.assertFalse(p["finalMeterVerified"])
        self.assertEqual(p["refundableBytes"],0)
        proof=self.verify(receipt,raw)
        self.assertTrue(proof["localRegistryExtendsRemotePrefix"])
        self.assertFalse(proof["externalPersistenceIndependentlyVerified"])
        self.assertFalse(proof["canResume"])
        self.assertEqual(self.witness(),(receipt,raw))

    def test_entire_local_index_and_all_wal_files_deleted_still_detected_by_external(self):
        receipt,raw=self.witness()
        index=self.directory/registry.NAME
        index.unlink()
        for path in self.directory.glob("meter-*.jsonl"):
            path.unlink()
        # Directory-only scanner would see no evidence. An EXTERNAL
        # authenticated witness persists outside the reset VPS and refuses
        # this apparent fresh start.
        with self.assertRaisesRegex(ValueError,"rolled back"):
            self.verify(receipt,raw)
        with self.assertRaises(ValueError):
            self.witness()

    def test_exact_birth_prefix_survives_new_runtime_or_other_account_append(self):
        receipt,raw=self.witness()
        next_checkpoint=copy.deepcopy(self.fx.cp)
        next_checkpoint["userId"]=102
        next_checkpoint["email"]="xmesh-u102--vless-cdn"
        next_checkpoint["runtimeId"]="f"*64
        next_checkpoint["inboundMeters"]=[
            {"email":"xmesh-u102--vless-cdn","uplinkBytes":9,"downlinkBytes":11}]
        quota_v2_meter_wal_fixture.write_test_meter_intents(
            next_checkpoint,self.directory)
        newer=self.verify(receipt,raw)
        self.assertTrue(newer["localRegistryExtendsRemotePrefix"])
        # This witness is a real prefix. A later follow-up registry must
        # have an exact additional hash-chain birth step, not new totals
        # substituted under previously witnessed file names.
        other_receipt,new_raw=self.witness()
        self.assertNotEqual(receipt,other_receipt)
        self.assertTrue(new_raw.startswith(raw))
        self.assertEqual(witness._verify_witness(other_receipt,new_raw,
                                                self.node,self.pub)["inventorySequence"],4)

    def test_wrong_trusted_node_and_foreign_public_key_are_denied(self):
        receipt,raw=self.witness()
        with self.assertRaises(ValueError):
            self.verify(receipt,raw,node=42)
        foreign=self.fx.root/"foreign.key"
        foreign_public=self.fx.root/"foreign.pub"
        subprocess.run(["openssl","genpkey","-algorithm","Ed25519",
                        "-out",str(foreign)],check=True,capture_output=True)
        subprocess.run(["openssl","pkey","-in",str(foreign),"-pubout",
                        "-out",str(foreign_public)],check=True,capture_output=True)
        with self.assertRaises(ValueError):
            self.verify(receipt,raw,pub=foreign_public)
        with self.assertRaises(ValueError):
            self.witness() if not receipt else witness._verify_witness(
                receipt,raw,1000,foreign_public)

    def test_changed_signed_sequence_tail_hash_nonfinal_flags_and_canonical_json_denied(self):
        receipt,raw=self.witness()
        envelope=signed.strict_json(receipt)
        for field,value in (
            ("inventorySequence",3),("inventoryTailDigest","f"*64),
            ("inventorySha256","f"*64),("indexedWalCount",0),
            ("canResume",True),("carryforwardApplied",True),
            ("finalMeterVerified",True),("nexusPersisted",True),
            ("refundableBytes",5),("refundableBytes",False),
        ):
            with self.subTest(field=field):
                tampered=copy.deepcopy(envelope)
                tampered["payload"][field]=value
                broken=signed.canonical(tampered)+b"\n"
                with self.assertRaises(ValueError):
                    self.verify(broken,raw)
        for invalid in (receipt+b"\n",receipt[:-1]+b" ",
                        receipt.replace(b'"algorithm":',
                                        b'"algorithm":"Ed25519","algorithm":',1)):
            with self.assertRaises(ValueError):
                self.verify(invalid,raw)

    def test_original_wal_missing_index_corrupt_or_rewritten_after_signing_denies(self):
        receipt,raw=self.witness()
        first=next(self.directory.glob("meter-*.jsonl"))
        first.unlink()
        with self.assertRaises(ValueError):
            self.verify(receipt,raw)
        # Separately, corrupt the *registry* and keep old files.
        self.directory.joinpath(registry.NAME).write_bytes(raw[:-1])
        with self.assertRaises(ValueError):
            self.verify(receipt,raw)

    def test_signature_requires_complete_local_stable_wal_and_docker_mount(self):
        original=self.docker
        foreign=copy.deepcopy(original)
        foreign["Mounts"]=[]
        with self.assertRaises(ValueError):
            witness.produce_witness(self.node,foreign,str(self.directory),
                                    self.fx.key,self.pub)
        self.fx.key.chmod(0o644)
        with self.assertRaises(ValueError):
            self.witness()


if __name__=="__main__":
    unittest.main()
