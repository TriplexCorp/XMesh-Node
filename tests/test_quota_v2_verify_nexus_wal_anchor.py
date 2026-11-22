#!/usr/bin/env python3
"""Node-only independent Nexus signed off-host WAL ACK contract regressions.

A separate test-only OpenSSL Ed25519 Nexus key signs the literal protocol
shape: NO Nexus implementation imported, NO remote DB mocked as authoritative.
The actual Nexus CI uses a real PostgreSQL store before signing receipts.
Here an independently supplied latest-head tuple is required for verification;
signing alone must not allow replay, Xray re-admission or any refund.
"""
import base64
import copy
import gzip
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"experiments/quota-v2-physical-stop"))
import wal_transport
import witness_inventory
import verify_nexus_wal_anchor as verifier
import sign_observation as signed
import quota_v2_meter_wal_fixture as wal_fixture
from test_quota_v2_inventory_witness import ExternalInventoryWitnessTests


class WalIndexEncodingTests(unittest.TestCase):
    def test_compressed_inventory_retains_exact_bytes_and_rejects_invalid_members(self):
        raw = b"".join(
            (signed.canonical({
                "sequence": sequence,
                "email": f"xmesh-u{sequence // 2 + 1}--vless-main",
                "runtimeId": "a" * 64,
                **{field: hashlib.sha256(f"{field}-{sequence}".encode()).hexdigest()
                   for field in ("filename", "firstWalDigest", "previousDigest", "digest")},
            }) + b"\n")
            for sequence in range(1000)
        )
        self.assertGreater(len(raw), wal_transport.WIRE_INDEX_LIMIT)
        bundle = dict(wal_transport._pack_inventory(raw), head="", receipt="", witness="")
        self.assertEqual(bundle["inventoryEncoding"], "gzip")
        self.assertEqual(wal_transport._unpack_bundle(signed.canonical(bundle))[1], raw)
        wire = base64.b64decode(bundle["inventory"], validate=True)
        for bad in (wire + wire, wire[:-1], gzip.compress(b"0" * (wal_transport.INDEX_LIMIT + 1))):
            altered = dict(bundle, inventory=base64.b64encode(bad).decode("ascii"))
            with self.assertRaisesRegex(ValueError, "compressed WAL inventory"):
                wal_transport._unpack_bundle(signed.canonical(altered))
        legacy = dict(wal_transport._pack_inventory(b"existing"), head="", receipt="", witness="")
        self.assertNotIn("inventoryEncoding", legacy)
        self.assertEqual(wal_transport._unpack_bundle(signed.canonical(legacy))[1], b"existing")


class NexusExternalWalAnchorTests(unittest.TestCase):
    def setUp(self):
        self.fi=ExternalInventoryWitnessTests(
            "test_witness_includes_real_local_full_wal_births_and_strict_nonauthority")
        self.fi.setUp()
        self.addCleanup(self.fi.doCleanups)
        self.node=self.fi.node
        self.node_pub=self.fi.pub
        self.source,self.raw=self.fi.witness()
        self.head={
            "sequence":self.raw.count(b"\n"),
            "registrySha256":hashlib.sha256(self.raw).hexdigest(),
        }
        self.tmp=tempfile.TemporaryDirectory(prefix="xmesh-node-external-ack-")
        self.addCleanup(self.tmp.cleanup)
        root=Path(self.tmp.name)
        self.key=root/"nexus.key"
        self.pub=root/"nexus.pub"
        subprocess.run(["openssl","genpkey","-algorithm","Ed25519",
                        "-out",str(self.key)],check=True,capture_output=True)
        self.key.chmod(0o600)
        subprocess.run(["openssl","pkey","-in",str(self.key),"-pubout",
                        "-out",str(self.pub)],check=True,capture_output=True)
        node=witness_inventory._verify_witness(
            self.source,self.raw,self.node,self.node_pub)
        self.payload={
            "schemaVersion":1,"kind":verifier.KIND,"nodeId":self.node,
            "inventorySequence":node["inventorySequence"],
            "inventorySha256":node["inventorySha256"],
            "inventoryTailDigest":node["inventoryTailDigest"],
            "originalNodeWitnessSha256":hashlib.sha256(self.source).hexdigest(),
            "oldContainerId":node["oldContainerId"],
            "oldStartedAt":node["oldStartedAt"],
            "offhostFullIndexCommitted":True,
            "bootstrapOnly":True,
            "canResume":False,
            "carryforwardApplied":False,
            "finalMeterVerified":False,
            "refundableBytes":0,
        }

    def signed(self,p=None,domain=verifier.DOMAIN,key=None):
        p=self.payload if p is None else p
        with tempfile.TemporaryDirectory(prefix="xmesh-test-nexus-sign-") as tmp:
            msg=Path(tmp)/"msg"
            msg.write_bytes(domain+signed.canonical(p))
            signature=subprocess.run(
                ["openssl","pkeyutl","-sign","-rawin","-in",str(msg),
                 "-inkey",str(self.key if key is None else key)],
                capture_output=True,check=True).stdout.hex()
        return signed.canonical({
            "algorithm":"Ed25519","payload":p,"signature":signature})+b"\n"

    def check(self,ack,**kwargs):
        return verifier.verify_nexus_offhost_anchor(
            ack,kwargs.get("source",self.source),
            kwargs.get("registry",self.raw),kwargs.get("node",self.node),
            kwargs.get("node_pub",self.node_pub),
            kwargs.get("nexus_pub",self.pub),
            kwargs.get("head",self.head),
            str(self.fi.directory))

    def test_transport_head_binds_fresh_challenge_receipt_and_local_history(self):
        receipt = self.signed()
        challenge = "1" * 64
        def bundle(domain=wal_transport.HEAD_DOMAIN):
            head = self.signed({
                "schemaVersion": 1, "kind": "xmesh.quota-v2.external-wal-head",
                "nodeId": self.node, "challenge": challenge, **self.head,
                "receiptSha256": hashlib.sha256(receipt).hexdigest(),
            }, domain=domain)
            return signed.canonical({
                name: base64.b64encode(blob).decode("ascii")
                for name, blob in (
                    ("receipt", receipt), ("head", head),
                    ("witness", self.source), ("inventory", self.raw),
                )
            })

        def verify(raw, nonce=challenge, expected=receipt):
            return wal_transport.verify_bundle(
                raw, nonce, self.node, self.node_pub, self.pub, str(self.fi.directory),
                expected_receipt=expected,
            )

        raw = bundle()
        result = verify(raw)
        self.assertTrue(result["offhostFullBirthIndexHeadMatched"])
        self.assertFalse(result["canResume"])
        with self.assertRaisesRegex(ValueError, "fresh WAL head binding"):
            verify(raw, "2" * 64)
        with self.assertRaisesRegex(ValueError, "differs from the current checkpoint"):
            verify(raw, expected=b"other receipt")
        with self.assertRaisesRegex(ValueError, "foreign key"):
            verify(bundle(domain=b"other domain"))
        (self.fi.directory / "xmesh-meter-inventory-v1.jsonl").unlink()
        for meter in self.fi.directory.glob("meter-*.jsonl"):
            meter.unlink()
        with self.assertRaisesRegex(ValueError, "rolled back"):
            verify(raw)

    def test_sync_requires_verified_existing_head_and_skips_unchanged_upload(self):
        def reply(challenge):
            receipt = self.signed()
            head = self.signed({
                "schemaVersion": 1, "kind": "xmesh.quota-v2.external-wal-head",
                "nodeId": self.node, "challenge": challenge, **self.head,
                "receiptSha256": hashlib.sha256(receipt).hexdigest(),
            }, domain=wal_transport.HEAD_DOMAIN)
            return signed.canonical({
                name: base64.b64encode(blob).decode("ascii")
                for name, blob in (
                    ("receipt", receipt), ("head", head),
                    ("witness", self.source), ("inventory", self.raw),
                )
            })

        def call(post):
            return wal_transport.sync_checkpoint(
                "sync", self.node, {}, str(self.fi.directory), self.node_pub, self.pub,
                lambda *_: self.fail("unexpected witness signing"), post,
            )

        def post(body):
            self.assertEqual(body["operation"], "head")
            return reply(body["challenge"])

        proof = call(post)
        self.assertTrue(proof["offhostFullBirthIndexHeadMatched"])
        self.assertFalse(proof["canResume"])

        def unavailable(body):
            self.assertEqual(body["operation"], "head")
            raise OSError("fixture lost connection")

        with self.assertRaisesRegex(OSError, "lost connection"):
            call(unavailable)
        (self.fi.directory / "xmesh-meter-inventory-v1.jsonl").unlink()
        with self.assertRaisesRegex(ValueError, "rolled back"):
            call(post)

    def test_current_signed_nexus_offhost_head_verified_but_non_authorizing(self):
        receipt=self.signed()
        result=self.check(receipt)
        self.assertTrue(result["nexusOffhostSignatureVerified"])
        self.assertTrue(result["offhostFullBirthIndexHeadMatched"])
        self.assertTrue(result["nodeLocalIndexExtendsNexusHead"])
        self.assertTrue(result["firstRemoteSnapshotWasOnlyBootstrap"])
        self.assertFalse(result["preBootstrapHistoryCompletenessVerified"])
        self.assertFalse(result["allXrayWritersCompletedVerified"])
        for flag in ("canResume","carryforwardApplied","finalMeterVerified"):
            self.assertFalse(result[flag])
        self.assertEqual(result["refundableBytes"],0)
        self.assertEqual(self.check(receipt),result)

    def test_replay_old_legitimate_node_nexus_witness_below_latest_offhost_head_denied(self):
        receipt=self.signed()
        cp=copy.deepcopy(self.fi.fx.cp)
        cp["runtimeId"]="f"*64
        cp["userId"]=102
        cp["email"]="xmesh-u102--vless-cdn"
        cp["inboundMeters"]=[{
            "email":"xmesh-u102--vless-cdn","uplinkBytes":6,"downlinkBytes":7}]
        wal_fixture.write_test_meter_intents(cp,self.fi.directory)
        _,new_index=self.fi.witness()
        newer={"sequence":new_index.count(b"\n"),
               "registrySha256":hashlib.sha256(new_index).hexdigest()}
        with self.assertRaisesRegex(ValueError,"stale"):
            self.check(receipt,head=newer)
        with self.assertRaisesRegex(ValueError,"stale"):
            self.check(receipt,head={
                "sequence":self.head["sequence"],
                "registrySha256":"f"*64,
            })

    def test_even_signed_receipt_refuses_total_local_wal_and_birth_registry_deletion(self):
        receipt=self.signed()
        (self.fi.directory/"xmesh-meter-inventory-v1.jsonl").unlink()
        for path in self.fi.directory.glob("meter-*.jsonl"):
            path.unlink()
        with self.assertRaisesRegex(ValueError,"rolled back"):
            self.check(receipt)

    def test_node_and_nexus_pubkeys_are_independently_enrolled_not_payload_selected(self):
        receipt=self.signed()
        wrong=Path(self.tmp.name)/"wrong.key"
        foreign_pub=Path(self.tmp.name)/"wrong.pub"
        subprocess.run(["openssl","genpkey","-algorithm","Ed25519",
                        "-out",str(wrong)],check=True,capture_output=True)
        subprocess.run(["openssl","pkey","-in",str(wrong),"-pubout",
                        "-out",str(foreign_pub)],check=True,capture_output=True)
        with self.assertRaises(ValueError):
            self.check(receipt,nexus_pub=foreign_pub)
        with self.assertRaises(ValueError):
            self.check(receipt,node_pub=foreign_pub)
        with self.assertRaises(ValueError):
            self.check(receipt,node=100)
        with self.assertRaises(ValueError):
            self.check(self.signed(key=wrong))

    def test_nexus_sighash_domain_and_original_source_cannot_be_reused(self):
        receipt=self.signed()
        with self.assertRaises(ValueError):
            self.check(self.signed(domain=witness_inventory.DOMAIN))
        with self.assertRaises(ValueError):
            self.check(receipt,source=self.source[:-1]+b" ")
        with self.assertRaises(ValueError):
            self.check(receipt,registry=self.raw[:-1]+b" ")
        with self.assertRaises(ValueError):
            self.check(receipt,head=None)

    def test_all_signed_false_to_true_or_other_amounts_rejected(self):
        receipt=self.signed()
        for key,value in (
            ("canResume",True),("carryforwardApplied",True),
            ("finalMeterVerified",True),("refundableBytes",1),
            ("refundableBytes",False),("offhostFullIndexCommitted",False),
            ("offhostFullIndexCommitted",0),("bootstrapOnly",0),
            ("nodeId",100),("inventorySequence",3),
            ("inventorySha256","f"*64),
            ("inventoryTailDigest","f"*64),
            ("originalNodeWitnessSha256","f"*64),
            ("oldContainerId","b"*64),
            ("oldStartedAt","2026-11-20T00:00:00Z"),
            ("schemaVersion",2),
        ):
            with self.subTest(key=key,value=value):
                p=copy.deepcopy(self.payload)
                p[key]=value
                with self.assertRaises(ValueError):
                    self.check(self.signed(p))
        for extra in (
            receipt+b"\n",receipt[:-1]+b" ",
            receipt.replace(b'"algorithm":',
                            b'"algorithm":"Ed25519","algorithm":',1),
        ):
            with self.assertRaises(ValueError):
                self.check(extra)

    def test_independently_missing_or_malformed_remote_head_is_not_best_effort(self):
        receipt=self.signed()
        for head in ({},None,{"sequence":0,"registrySha256":"f"*64},
                     {"sequence":True,"registrySha256":self.head["registrySha256"]},
                     {"sequence":1,"registrySha256":"oops"},
                     {"sequence":1,"registrySha256":self.head["registrySha256"],
                      "untrusted":True}):
            with self.subTest(head=head),self.assertRaises(ValueError):
                self.check(receipt,head=head)


if __name__=="__main__":
    unittest.main()
