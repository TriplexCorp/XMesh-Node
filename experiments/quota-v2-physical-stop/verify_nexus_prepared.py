#!/usr/bin/env python3
"""CI-only Node verifier: Nexus registered my old-Xray PREPARE, NOT its bytes.

Nexus's PREPARED-only receipt is a signed claim about a SQL row: Node does
not independently read Nexus PostgreSQL. No class/function here can clear
historicRuntimeDebtUnresolved, re-open admission, send an allowance, or issue
a final/refundable meter. This deliberately does NOT implement carryforward.

Do not import any XMesh-Nexus code to check Nexus's Ed25519 signature. The
enrolled public key MUST be provided by a separate trusted channel, never
embedded in an incoming receipt, URL, JSON or Node-provided key id.
"""
import hashlib
from pathlib import Path
import subprocess
import tempfile

import rollover_prepare as node_prepare
import stop_chain
import sign_observation as observed

DOMAIN=b"XMESH_QUOTA_V2_NONFINAL_PREPARE_RECORDED_V1\x00"
KIND="xmesh.quota-v2.nonfinal-prepare-recorded"
SCOPE=stop_chain.SCOPE
FLAGS=("absoluteCarryforwardVerified","rolloverAuthorized",
       "resumptionAllowed","finalMeterVerified","settlementEligible")
FIELDS=(*SCOPE,"schemaVersion","kind","oldRuntimeId","oldContainerId",
    "oldStartedAt","proposalSha256","stopChainSha256","xrayJournalSha256",
    "stagedLedgerRowSha256","nodeDurableAbsoluteFloorBytes",
    "oldRuntimeObservedUplinkBytes","oldRuntimeObservedDownlinkBytes",
    "nexusRecordedPrepared",*FLAGS,"refundableBytes")


def _verified_structure(payload):
    if not isinstance(payload,dict) or set(payload)!=set(FIELDS):
        raise ValueError("Nexus PREPARED receipt has unknown or missing fields")
    for name in ("nodeId","userId","revision"):
        if type(payload[name]) is not int or payload[name]<=0:
            raise ValueError("Nexus receipt invalid scoped integer")
    for name in ("epoch","meterEpoch","reservationId","revocationId"):
        if (not isinstance(payload[name],str) or
                stop_chain.observed.UUID.fullmatch(payload[name]) is None):
            raise ValueError("Nexus receipt invalid scoped UUID")
    if (type(payload["schemaVersion"]) is not int or payload["schemaVersion"]!=1 or
            payload["kind"]!=KIND or
            payload["nexusRecordedPrepared"] is not True or
            any(type(payload[name]) is not bool or payload[name] is not False
                for name in FLAGS) or
            type(payload["refundableBytes"]) is not int or
            payload["refundableBytes"]!=0):
        raise ValueError("Nexus PREPARED receipt incorrectly authorizes rollover")
    for name in ("oldRuntimeId","oldContainerId","proposalSha256",
                 "stopChainSha256","xrayJournalSha256","stagedLedgerRowSha256"):
        if (not isinstance(payload[name],str) or
                node_prepare.HEX64.fullmatch(payload[name]) is None):
            raise ValueError("Nexus receipt missing immutable proof fingerprint")
    if (not isinstance(payload["oldStartedAt"],str) or
            not 15<=len(payload["oldStartedAt"])<=64 or
            "T" not in payload["oldStartedAt"]):
        raise ValueError("Nexus receipt old container start is not trusted")
    for name in ("nodeDurableAbsoluteFloorBytes",
                 "oldRuntimeObservedUplinkBytes",
                 "oldRuntimeObservedDownlinkBytes"):
        if (type(payload[name]) is not int or
                not 0<=payload[name]<=node_prepare.MAX_ACCOUNT_BYTES):
            raise ValueError("Nexus receipt amount not a valid conservative meter")
    if (payload["oldRuntimeObservedUplinkBytes"]+
            payload["oldRuntimeObservedDownlinkBytes"]>
            node_prepare.MAX_ACCOUNT_BYTES):
        raise ValueError("Nexus receipt conservative meter overflow")
    return payload


def verify_nexus_prepared_registration(raw_receipt, trusted_nexus_pubkey,
                                        expected_scope, raw_node_prepare,
                                        raw_observation, raw_stop,
                                        trusted_node_pubkey,
                                        independently_rechecked_old_wal_sha):
    """Verify Nexus signature and exact original Node proofs, never unfreeze.

    Caller supplies the trusted current lease/revocation scope, trusted
    Nexus+Node public keys, previously persisted original signed source
    bytes, and the locally rehashed old Xray journal SHA. None may be
    extracted from the remote receipt. The staging row digest remains a
    *signed Nexus assertion*, not a Node-side independent database read.
    """
    if (not isinstance(raw_receipt,bytes) or
            not isinstance(raw_node_prepare,bytes) or
            not isinstance(expected_scope,dict) or
            set(expected_scope)!=set(SCOPE) or
            not isinstance(independently_rechecked_old_wal_sha,str) or
            node_prepare.HEX64.fullmatch(independently_rechecked_old_wal_sha) is None):
        raise ValueError("untrusted Nexus registration inputs")
    raw_node=observed.strict_json(raw_node_prepare)
    if raw_node_prepare!=observed.canonical(raw_node)+b"\n":
        raise ValueError("uncanonical original Node proposal")
    original=node_prepare.verify_rollover_proposal(
        raw_node,raw_observation,raw_stop,
        expected_scope["nodeId"],trusted_node_pubkey,
        independently_rechecked_old_wal_sha)
    if any(original[key]!=expected_scope[key] or
           type(original[key]) is not type(expected_scope[key]) for key in SCOPE):
        raise ValueError("original Node proposal not for current signed reservation")

    # Raw Nexus receipt follows independently reviewed, stable v1 contract.
    receipt=observed.strict_json(raw_receipt)
    if raw_receipt!=observed.canonical(receipt)+b"\n":
        raise ValueError("noncanonical Nexus receipt")
    if (set(receipt)!={"algorithm","payload","signature"} or
            receipt["algorithm"]!="Ed25519" or
            not isinstance(receipt["signature"],str) or
            node_prepare.HEX128.fullmatch(receipt["signature"]) is None):
        raise ValueError("Nexus receipt invalid signed envelope")
    p=_verified_structure(receipt["payload"])
    if (any(p[key]!=expected_scope[key] or
            type(p[key]) is not type(expected_scope[key])
            for key in SCOPE) or
            p["proposalSha256"]!=hashlib.sha256(raw_node_prepare).hexdigest() or
            any(p[receipt_field]!=original[node_field] or
                type(p[receipt_field]) is not type(original[node_field])
                for receipt_field,node_field in (
                  ("oldRuntimeId","oldRuntimeId"),
                  ("oldContainerId","oldContainerId"),
                  ("oldStartedAt","oldStartedAt"),
                  ("stopChainSha256","stopChainSha256"),
                  ("xrayJournalSha256","xrayJournalSha256"),
                  ("nodeDurableAbsoluteFloorBytes","nodeDurableAbsoluteFloorBytes"),
                  ("oldRuntimeObservedUplinkBytes","oldRuntimeObservedUplinkBytes"),
                  ("oldRuntimeObservedDownlinkBytes","oldRuntimeObservedDownlinkBytes")))):
        raise ValueError("Nexus PREPARED receipt mismatches old Node runtime, WAL or lease")
    with tempfile.TemporaryDirectory(prefix="xmesh-node-nexus-prepared-") as tmp:
        message=Path(tmp)/"message"
        sig=Path(tmp)/"signature"
        message.write_bytes(DOMAIN+observed.canonical(p))
        sig.write_bytes(bytes.fromhex(receipt["signature"]))
        proc=subprocess.run(
            ["openssl","pkeyutl","-verify","-rawin","-in",str(message),
             "-pubin","-inkey",str(trusted_nexus_pubkey),
             "-sigfile",str(sig)],
            capture_output=True,timeout=10,check=False)
        if proc.returncode:
            raise ValueError("independently enrolled Nexus prepared-receipt key mismatch")
    # Unlike a future acknowledged/applied carryforward, a signed PREPARED
    # receipt never updates persistent byte totals nor clears old-Xray debt.
    return {
        "nodeValidatedNexusPreparedRegistration":True,
        "authenticatedOldNodeRollover":True,
        "nexusClaimedStagedLedgerRowSha256":p["stagedLedgerRowSha256"],
        "nodeIndependentlyReadNexusDatabase":False,
        "carryforwardApplied":False,
        "canResume":False,
        "finalMeterVerified":False,
        "settlementEligible":False,
        "refundableBytes":0,
    }
