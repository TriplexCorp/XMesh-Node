#!/usr/bin/env python3
"""Real OpenSSL Ed25519 proof of a zero-authority first-genesis policy.

The positive grant is intentionally absent. All tests use disposable files,
not an installed Agent, Xray, external network or production instance.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"experiments"/"quota-v2-physical-stop"))
import quarantine_policy as qp


class QuarantinePolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory(prefix="xmesh-qd-")
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.private=self.root/"signing.key"
        subprocess.run(["openssl","genpkey","-algorithm","Ed25519",
            "-out",str(self.private)],check=True,stdout=subprocess.DEVNULL)
        public=subprocess.check_output(["openssl","pkey","-in",str(self.private),
            "-pubout","-outform","DER"])
        self.pub=public[-32:].hex()
        self.node=47
        self.now=int(time.time()*1000)
        self.runtime="a"*64
        self.challenge="e"*64
        self.activation="c"*64
        self.prepared={"algorithm":"Ed25519","signature":"f"*128,"payload":{
            "schemaVersion":1,"kind":"xmesh.xray.genesis-prepared",
            "nodeId":self.node,"candidateRuntimeId":self.runtime,
            "challenge":self.challenge,"activationReceiptSha256":self.activation,
            "authorizedBytes":0,"canStart":False,"canResume":False,
            "preparedAtMs":self.now,"validUntilMs":self.now+120000,
        }}
        self.guard=qp._guard()
        self.doc=self.signed_doc()

    def signed_doc(self,users=None):
        config={"inbounds":[{"listen":"127.0.0.1","port":18501,
                             "protocol":"vless","settings":{"clients":[]}}]}
        config_digest=hashlib.sha256(self.guard.canonical(config)).hexdigest()
        policy={
            "version":1,"kind":"xmesh.quota-v2.genesis-quarantine-policy",
            "nodeId":self.node,"configSha256":config_digest,
            "issuedAtMs":self.now,"validUntilMs":self.now+120000,
            "users":users if users is not None else [{
                "userId":100,"offlineBudgetBytes":0,"onHold":True
            }],
            "quotaV2Genesis":{
                "mode":"quarantined","runtimeId":self.runtime,
                "challenge":self.challenge,
                "firstActivationReceiptSha256":self.activation,
                "authorizedBytes":0,"canStart":False,
                "canResume":False,"refundableBytes":0,
            }
        }
        plain=self.root/"canonical.json"
        plain.write_bytes(self.guard.canonical(policy))
        sig=self.root/"policy.sig"
        subprocess.run(["openssl","pkeyutl","-sign","-inkey",str(self.private),
            "-rawin","-in",str(plain),"-out",str(sig)],
            check=True,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        return {
            "status":"quarantined","nodeId":self.node,"profileId":29,
            "listen":"127.0.0.1","port":18501,"revision":config_digest,
            "config":config,"policy":policy,
            "policySignature":sig.read_bytes().hex(),
            "policyPublicKey":self.pub,
            "policySha256":hashlib.sha256(self.guard.canonical(policy)).hexdigest(),
            "publicIngressAllowed":False,"canStart":False,"canResume":False,
            "authorizedBytes":0,
        }

    def encoded(self,doc=None):
        return self.guard.canonical(self.doc if doc is None else doc)

    def verify(self,doc=None):
        return qp.validate_response(self.encoded(doc),self.node,
                                    self.prepared,self.pub,now_ms=self.now)

    def test_true_openssl_signer_and_exact_original_quarantine_pass(self):
        self.assertEqual(self.verify(),self.doc)

    def test_unpinned_key_and_tampered_policy_rejected(self):
        with self.assertRaises(ValueError):
            qp.validate_response(self.encoded(),self.node,
                                 self.prepared,"1"*64,self.now)
        altered=json.loads(self.encoded())
        altered["policy"]["users"][0]["userId"]=999
        with self.assertRaises(ValueError):
            self.verify(altered)

    def test_invalid_expiry_runtime_challenge_or_authority_denied(self):
        variations=[
            ("canStart",True),("authorizedBytes",1),
            ("publicIngressAllowed",True),("status","active"),
        ]
        for field,value in variations:
            with self.subTest(field=field):
                changed=json.loads(self.encoded())
                changed[field]=value
                with self.assertRaises(ValueError):
                    self.verify(changed)
        for kind in ("runtimeId","challenge","firstActivationReceiptSha256"):
            with self.subTest(kind=kind):
                changed=json.loads(self.encoded())
                changed["policy"]["quotaV2Genesis"][kind]="b"*64
                with self.assertRaises(ValueError):
                    self.verify(changed)
        with self.assertRaises(ValueError):
            qp.validate_response(self.encoded(),self.node,
                                self.prepared,self.pub,now_ms=self.now+120001)
        with self.assertRaises(ValueError):
            qp.validate_response(self.encoded(),self.node,
                                self.prepared,self.pub,now_ms=self.now-1)

    def test_signed_positive_allowance_rejected_even_with_valid_signature(self):
        users=[{"userId":100,"offlineBudgetBytes":100,"onHold":True}]
        self.assertTrue(self.doc["policySignature"])
        with self.assertRaises(ValueError):
            self.verify(self.signed_doc(users))
        for budget in (None,-1,67108864):
            with self.subTest(budget=budget):
                with self.assertRaises(ValueError):
                    self.verify(self.signed_doc([{
                        "userId":100,"offlineBudgetBytes":budget,"onHold":True
                    }]))

    def test_unknown_fields_duplicates_wrong_profile_and_oversize_denied(self):
        wrong=json.loads(self.encoded())
        wrong["secretAuthority"]=True
        with self.assertRaises(ValueError):
            self.verify(wrong)
        wrong=json.loads(self.encoded())
        wrong["revision"]="0"*64
        with self.assertRaises(ValueError):
            self.verify(wrong)
        raw=self.encoded()
        doubled=raw[:-1]+b',"authorizedBytes":100}'
        with self.assertRaises(ValueError):
            qp.validate_response(doubled,self.node,self.prepared,self.pub,self.now)
        with self.assertRaises(ValueError):
            qp.validate_response(b"x"*(qp.MAX_REPLY+1),self.node,
                                 self.prepared,self.pub,self.now)

    def test_newly_enrolled_node_pins_policy_signer_by_owner_enrolled_xsp2(self):
        pin=self.root/"policy-public-key"
        identity={"nodeId":self.node,"activationReceiptSha256":self.activation}
        response={
            "status":"quarantine_pin_only","nodeId":self.node,
            "activationReceiptSha256":self.activation,"policyPublicKey":self.pub,
            "authorizedBytes":0,"canStart":False,"canResume":False,
            "refundableBytes":0,
        }
        def read_pin():
            if not pin.exists():
                raise FileNotFoundError("first policy pin not present")
            raw=pin.read_bytes()
            if len(raw)!=65 or not raw.endswith(b"\n"):
                raise ValueError("invalid first policy pin")
            return raw[:-1].decode("ascii")
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        try:
            with mock.patch.object(qp.wal_transport,"POLICY_KEY",str(pin)),\
                 mock.patch.object(qp.wal_transport,"_panel_pin",
                                   side_effect=read_pin),\
                 mock.patch.object(qp,"_enrolled_activation",
                                   return_value=identity) as enrolled,\
                 mock.patch.object(qp,"_post_quarantined_desired",
                                   return_value=self.guard.canonical(response)) as remote:
                self.assertEqual(qp._pinned_policy_before_genesis(
                    "https://panel.example",self.node,str(self.root),fd),self.pub)
                self.assertEqual(qp._pinned_policy_before_genesis(
                    "https://panel.example",self.node,str(self.root),fd),self.pub)
                self.assertEqual(remote.call_count,1)
                self.assertEqual(enrolled.call_count,2)
            self.assertEqual(pin.read_bytes(),(self.pub+"\n").encode())
            self.assertEqual(pin.stat().st_mode&0o777,0o600)
        finally:
            os.close(fd)

    def test_signed_product_pin_mismatch_or_authority_flag_keeps_disk_clean(self):
        pin=self.root/"policy-public-key"
        identity={"nodeId":self.node,"activationReceiptSha256":self.activation}
        response={
            "status":"quarantine_pin_only","nodeId":self.node,
            "activationReceiptSha256":self.activation,"policyPublicKey":self.pub,
            "authorizedBytes":0,"canStart":False,"canResume":False,
            "refundableBytes":0,
        }
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        try:
            for altered in (
                {**response,"authorizedBytes":1},
                {**response,"nodeId":self.node+1},
                {**response,"activationReceiptSha256":"f"*64},
            ):
                with self.subTest(altered=altered),\
                     mock.patch.object(qp.wal_transport,"POLICY_KEY",str(pin)),\
                     mock.patch.object(qp.wal_transport,"_panel_pin",
                            side_effect=FileNotFoundError),\
                     mock.patch.object(qp,"_enrolled_activation",
                            return_value=identity),\
                     mock.patch.object(qp,"_post_quarantined_desired",
                            return_value=self.guard.canonical(altered)):
                    with self.assertRaises(ValueError):
                        qp._pinned_policy_before_genesis(
                            "https://panel.example",self.node,str(self.root),fd)
                    self.assertFalse(pin.exists())
        finally:
            os.close(fd)

    def test_shared_xray_reconciler_flock_excludes_concurrent_genesis(self):
        fd,lock=qp._locked_private_state(str(self.root))
        try:
            with self.assertRaises(BlockingIOError):
                qp._locked_private_state(str(self.root))
            assert (self.root/"lock").stat().st_mode & 0o777 == 0o600
        finally:
            os.close(lock)
            os.close(fd)
        # Closing the same installed lock lets a different serialized
        # reconciler proceed. This stage never overrides the normal lock.
        other_fd,other_lock=qp._locked_private_state(str(self.root))
        os.close(other_lock)
        os.close(other_fd)
        link=self.root.parent/"xmesh-symlink-should-not-be-state"
        if link.exists():
            link.unlink()
        link.symlink_to(self.root, target_is_directory=True)
        self.addCleanup(lambda: link.unlink(missing_ok=True))
        with self.assertRaises(ValueError):
            qp._locked_private_state(str(link))

    def test_private_durable_evidence_idempotency_and_tamper_denial(self):
        fd=os.open(self.root,os.O_RDONLY|os.O_DIRECTORY)
        try:
            data={"prepared":self.prepared,"reply":self.doc}
            qp._durable_store(fd,data)
            qp._durable_store(fd,data)
            target=self.root/"genesis-quarantine-envelope.json"
            self.assertEqual(target.stat().st_mode&0o777,0o600)
            self.assertEqual(json.loads(target.read_bytes()),data)
            with self.assertRaises(ValueError):
                qp._durable_store(fd,{"prepared":self.prepared,"reply":{"user":1}})
        finally:
            os.close(fd)

    def test_installed_product_handoff_uses_measured_pid_and_does_not_install_cap(self):
        before=("f"*64,"2026-11-21T00:00:00Z",987,self.runtime)
        def state_handles(_):
            return os.open(self.root,os.O_RDONLY|os.O_DIRECTORY),os.open(os.devnull,os.O_RDONLY)
        with mock.patch.object(qp,"_locked_private_state",side_effect=state_handles),\
             mock.patch.object(qp,"_pinned_policy_before_genesis",return_value=self.pub),\
             mock.patch.object(qp.wal_transport,"_measure_quarantined_runtime",
                               side_effect=[before,before]) as measured,\
             mock.patch.object(qp.wal_transport,"prepare_measured_genesis",
                               return_value=self.prepared) as prepared,\
             mock.patch.object(qp,"_post_quarantined_desired",
                               return_value=self.encoded()) as tunnel:
            with mock.patch.object(qp.secrets,"token_hex",return_value=self.challenge):
                result=qp.request_quarantine("https://panel.example",self.node,str(self.root))
        self.assertEqual(result["authorizedBytes"],0)
        self.assertEqual(result["status"],"quarantined")
        self.assertEqual(measured.call_count,2)
        prepared.assert_called_once_with("https://panel.example",self.node,self.challenge)
        sent=tunnel.call_args.args[0]
        self.assertEqual(sent["quotaGenesisRuntimeId"],self.runtime)
        self.assertEqual(sent["quotaGenesisChallenge"],self.challenge)
        self.assertEqual(sent["quotaProtocolVersion"],2)
        self.assertEqual(sent["quotaGenesisQuarantine"],True)
        self.assertTrue((self.root/"genesis-quarantine-envelope.json").is_file())

    def test_runtime_replaced_after_strict_tunnel_keeps_disk_clean(self):
        initial=("f"*64,"start",987,self.runtime)
        replaced=("a"*64,"start",988,self.runtime)
        def state_handles(_):
            return os.open(self.root,os.O_RDONLY|os.O_DIRECTORY),os.open(os.devnull,os.O_RDONLY)
        with mock.patch.object(qp,"_locked_private_state",side_effect=state_handles),\
             mock.patch.object(qp,"_pinned_policy_before_genesis",return_value=self.pub),\
             mock.patch.object(qp.wal_transport,"_measure_quarantined_runtime",
                               side_effect=[initial,replaced]),\
             mock.patch.object(qp.wal_transport,"prepare_measured_genesis",
                               return_value=self.prepared),\
             mock.patch.object(qp,"_post_quarantined_desired",
                               return_value=self.encoded()),\
             mock.patch.object(qp.secrets,"token_hex",return_value=self.challenge):
            with self.assertRaisesRegex(ValueError,"changed"):
                qp.request_quarantine("https://panel.example",self.node,str(self.root))
        self.assertFalse((self.root/"genesis-quarantine-envelope.json").exists())


if __name__=="__main__":
    unittest.main()
