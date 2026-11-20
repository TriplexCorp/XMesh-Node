#!/usr/bin/env python3
"""Adversarial, disposable conservative cross-runtime rollover proposal tests.

Only signed evidence and fake byte fixtures are used; no VPS, Nexus
acceptance, production Xray patch, or real refund action exists.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"experiments/quota-v2-physical-stop"))
import attestor
import journal_integrity
import rollover_prepare as rollover
import stop_chain
import sign_observation as observed
from test_quota_v2_stop_chain import StopChainTests
import quota_v2_meter_wal_fixture


class ConservativeRolloverProposalTests(unittest.TestCase):
    def setUp(self):
        # Full source chain with real pidfd, signed Node observed checkpoint,
        # *actually exited* process, independent stopped Docker fixture,
        # fsynced WAL files and signed physical stop. No standalone claims.
        self.fx=StopChainTests("test_same_pid_stop_chain_is_signed_nonfinal_and_idempotent")
        self.fx.setUp()
        self.addCleanup(self.fx.doCleanups)
        self.proposals=self.fx.root/"rollover-proposals"
        self.proposals.mkdir(mode=0o700)
        probe,bound=self.fx.bound()
        with probe:
            self.fx.stop_child()
            self.stop=self.fx.complete(bound)
        self.stop_raw=observed.canonical(self.stop)+b"\n"
        self.journal_digest=journal_integrity.verify_poststop_journal(
            self.fx.cp,self.fx.xray,self.fx.after)

    def prepare(self,**kwargs):
        with patch.object(attestor,"inspect_managed",
                          side_effect=kwargs.get("docker",[self.fx.after,self.fx.after])):
            return rollover.create_rollover_proposal(
                kwargs.get("checkpoint",self.fx.cp),
                self.fx.observed,self.fx.stopped,self.fx.xray,9,
                kwargs.get("key",self.fx.key),self.fx.pub,self.proposals)

    def verify(self,envelope,original=None,stop=None,journal_digest=None,pub=None):
        return rollover.verify_rollover_proposal(
            envelope,self.fx.original if original is None else original,
            self.stop_raw if stop is None else stop,
            9,self.fx.pub if pub is None else pub,
            self.journal_digest if journal_digest is None else journal_digest)

    def test_signed_old_pid_evidence_and_byte_wal_yield_non_authorizing_proposal(self):
        self.assertEqual(self.stop["payload"]["schemaVersion"],2)
        self.assertEqual(self.stop["payload"]["xrayJournalSha256"],self.journal_digest)
        envelope=self.prepare()
        p=self.verify(envelope)
        self.assertEqual(p["nodeId"],9)
        self.assertEqual(p["userId"],101)
        self.assertEqual(p["oldRuntimeId"],self.fx.cp["runtimeId"])
        self.assertEqual(p["oldContainerId"],self.fx.after["Id"])
        self.assertEqual(p["oldRuntimeObservedUplinkBytes"],7)
        self.assertEqual(p["oldRuntimeObservedDownlinkBytes"],13)
        self.assertEqual(p["nodeDurableAbsoluteFloorBytes"],20)
        self.assertEqual(p["inboundMeters"],self.fx.cp["inboundMeters"])
        self.assertEqual(p["observationSha256"],
                         hashlib.sha256(self.fx.original).hexdigest())
        self.assertEqual(p["stopChainSha256"],
                         hashlib.sha256(self.stop_raw).hexdigest())
        self.assertEqual(p["xrayJournalSha256"],self.journal_digest)
        for name in rollover.FLAGS:
            self.assertIs(p[name],False,name)
        self.assertEqual(p["refundableBytes"],0)
        output=self.proposals/rollover.proposal_name(self.fx.cp)
        raw=output.read_bytes()
        before=output.stat().st_ino
        self.assertEqual(raw,observed.canonical(envelope)+b"\n")
        self.assertEqual(output.stat().st_mode&0o777,0o600)
        self.assertEqual(self.prepare(),envelope)
        self.assertEqual(output.read_bytes(),raw)
        self.assertEqual(output.stat().st_ino,before)

    def test_no_signature_key_no_old_stop_no_live_journal_never_publish(self):
        for case in ("wrong-key","missing-stop","wrong-node","restarted","changed-pid",
                     "invalid-restart-policy","mount-changed"):
            with self.subTest(case=case):
                old_key=self.fx.key
                old_stop=self.fx.stopped/("stop-"+observed.receipt_name(self.fx.cp))
                original_stop=old_stop.read_bytes()
                docker=[copy.deepcopy(self.fx.after)]*2
                key=old_key
                if case=="wrong-key":
                    key=self.fx.root/"unknown-privkey"
                elif case=="missing-stop":
                    old_stop.unlink()
                elif case=="wrong-node":
                    docker[0]["Id"]="b"*64
                elif case=="restarted":
                    docker[0]["State"]["Running"]=True
                    docker[0]["State"]["Pid"]=141
                elif case=="changed-pid":
                    docker[0]["State"]["Pid"]=141
                elif case=="invalid-restart-policy":
                    docker[0]["HostConfig"]["RestartPolicy"]["Name"]="always"
                elif case=="mount-changed":
                    docker[0]["Mounts"][0]["Source"]=str(self.proposals)
                try:
                    with self.assertRaises((ValueError,FileNotFoundError)):
                        self.prepare(key=key,docker=docker)
                finally:
                    if case=="missing-stop":
                        old_stop.write_bytes(original_stop)
                        old_stop.chmod(0o600)
                self.assertEqual(list(self.proposals.iterdir()),[])

    def test_adversarial_signature_scope_and_finality_tamper_never_verifies(self):
        evidence=self.prepare()
        for case in ("signature","amount","journal","stop","identity","refund",
                     "approve","nexus","final","settlement","revision","schema",
                     "cross-node","duplicate-extra"):
            with self.subTest(case=case):
                forged=copy.deepcopy(evidence)
                p=forged["payload"]
                if case=="signature":
                    forged["signature"]="0"*128
                elif case=="amount":
                    p["inboundMeters"][0]["downlinkBytes"]+=1
                elif case=="journal":
                    p["xrayJournalSha256"]="0"*64
                elif case=="stop":
                    p["stopChainSha256"]="f"*64
                elif case=="identity":
                    p["oldRuntimeId"]="f"*64
                elif case=="refund":
                    p["refundableBytes"]=7
                elif case=="approve":
                    p["rolloverAuthorized"]=True
                elif case=="nexus":
                    p["nexusAcknowledged"]=True
                elif case=="final":
                    p["finalMeterVerified"]=True
                elif case=="settlement":
                    p["settlementEligible"]=True
                elif case=="revision":
                    p["revision"]+=1
                elif case=="schema":
                    p["schemaVersion"]=2
                elif case=="cross-node":
                    p["nodeId"]=11
                else:
                    p["unsupportedAcknowledgmentToken"]="fake"
                with self.assertRaises(ValueError):
                    self.verify(forged)
        self.assertEqual(len(list(self.proposals.iterdir())),1)

    def test_stale_old_stop_chain_or_original_observation_refused(self):
        evidence=self.prepare()
        with self.assertRaises(ValueError):
            self.verify(evidence,stop=self.stop_raw[:-1]+b" ")
        with self.assertRaises(ValueError):
            self.verify(evidence,original=self.fx.original[:-1]+b" ")
        with self.assertRaises(ValueError):
            self.verify(evidence,journal_digest="0"*64)
        impostor=copy.deepcopy(self.stop)
        impostor["payload"]["xrayJournalSha256"]="f"*64
        impostor["signature"]=observed.sign_bytes(
            self.fx.key,stop_chain.DOMAIN+observed.canonical(impostor["payload"]))
        with self.assertRaises(ValueError):
            self.verify(evidence,stop=observed.canonical(impostor)+b"\n")
        self.assertEqual(len(list(self.proposals.iterdir())),1)

    def test_modified_actual_old_xray_journal_or_second_old_runtime_refused(self):
        path=self.fx.xray/("meter-"+hashlib.sha256(
            (self.fx.cp["runtimeId"]+"\x00"+self.fx.cp["email"]+"\x00uplink"
             ).encode()).hexdigest()+".jsonl")
        old=path.read_bytes()
        try:
            record=json.loads(old)
            record["nextBytes"]=9
            record["digest"]=""
            record["digest"]=hashlib.sha256(
                journal_integrity._canonical_go(record)).hexdigest()
            path.write_bytes(journal_integrity._canonical_go(record))
            with self.assertRaisesRegex(ValueError,"meter|WAL|byte"):
                self.prepare()
            # Even a correctly chained history for ANOTHER old incarnation
            # is not an authorized carryforward for the stopped lease.
            path.write_bytes(old)
            extra=copy.deepcopy(self.fx.cp)
            extra["runtimeId"]="e"*64
            extra["inboundMeters"]=[
                {"email":"xmesh-u101--vless-cdn","uplinkBytes":8,"downlinkBytes":0}]
            existing=set(self.fx.xray.iterdir())
            quota_v2_meter_wal_fixture.write_test_meter_intents(extra,self.fx.xray)
            created=set(self.fx.xray.iterdir())-existing
            try:
                with self.assertRaisesRegex(ValueError,"historic|runtime"):
                    self.prepare()
            finally:
                for name in created:
                    name.unlink()
        finally:
            path.write_bytes(old)
        self.assertEqual(list(self.proposals.iterdir()),[])

    def test_signing_race_replaced_docker_or_late_wal_denies_publication(self):
        for case in ("docker","late-wal"):
            with self.subTest(case=case):
                extra=copy.deepcopy(self.fx.after)
                extra["Id"]="c"*64
                after=[self.fx.after,extra] if case=="docker" else [
                    self.fx.after,self.fx.after]
                original=rollover.observed.sign_bytes
                path=self.fx.xray/("meter-"+hashlib.sha256(
                    (self.fx.cp["runtimeId"]+"\x00"+self.fx.cp["email"]+"\x00uplink"
                     ).encode()).hexdigest()+".jsonl")
                raw=path.read_bytes()
                def after_sign(key,message):
                    signature=original(key,message)
                    if case=="late-wal":
                        record=json.loads(raw)
                        record["nextBytes"]=10
                        record["digest"]=""
                        record["digest"]=hashlib.sha256(
                            journal_integrity._canonical_go(record)).hexdigest()
                        path.write_bytes(journal_integrity._canonical_go(record))
                    return signature
                try:
                    with patch.object(rollover.observed,"sign_bytes",side_effect=after_sign):
                        with self.assertRaisesRegex(ValueError,"replaced|changed|differs|meter"):
                            self.prepare(docker=after)
                finally:
                    path.write_bytes(raw)
                self.assertEqual(list(self.proposals.iterdir()),[])

    def test_hardlink_slot_prevents_conflicting_same_reservation_signatures(self):
        signed=self.prepare()
        name=rollover.proposal_name(self.fx.cp)
        alternate=copy.deepcopy(signed)
        alternate["payload"]["revision"]+=1
        alternate["signature"]=observed.sign_bytes(
            self.fx.key,rollover.DOMAIN+observed.canonical(alternate["payload"]))
        fd=observed.private_directory(self.proposals)
        try:
            with self.assertRaisesRegex(ValueError,"conflicting"):
                observed.append_only(fd,name,observed.canonical(alternate)+b"\n")
        finally:
            os.close(fd)
        self.assertEqual(self.verify(signed)["rolloverAuthorized"],False)

    def test_floor_not_added_to_raw_and_false_type_not_coercible(self):
        original=observed.strict_json(self.fx.original)
        original["payload"]["durableAbsoluteFloorBytes"]=125
        p=rollover._build_payload(
            self.fx.cp,original,self.stop["payload"],self.fx.original,
            self.stop_raw,self.journal_digest)
        self.assertEqual(p["nodeDurableAbsoluteFloorBytes"],125)
        self.assertEqual(p["oldRuntimeObservedUplinkBytes"]+
                         p["oldRuntimeObservedDownlinkBytes"],20)
        self.assertNotIn("candidateAbsoluteFloorBytes",p)
        evidence=self.prepare()
        bad=copy.deepcopy(evidence)
        bad["payload"]["absoluteCarryforwardVerified"]=0  # 0==False in Python
        with self.assertRaises(ValueError):
            self.verify(bad)
        self.assertEqual(evidence["payload"]["refundableBytes"],0)


if __name__=="__main__":
    unittest.main()
