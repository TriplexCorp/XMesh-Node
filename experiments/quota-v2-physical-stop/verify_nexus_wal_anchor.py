#!/usr/bin/env python3
"""Independent Node verifier of Nexus's signed off-host WAL index COMMIT.

Nexus #546 separately authenticates Node's complete first-birth chain and
atomically stores the raw index outside the Xray host. Node must not confuse
an arbitrary signed remote receipt with the *LATEST* independently fetched
Nexus record. Require an out-of-band authoritative current head digest and
sequence; refuse any stale, conflicting or unsigned reply and any local
history rollback behind that full prefix.

No production HTTP fetch, no installed Xray gate, no quota credit/refund.
Even a perfect off-host receipt does NOT prove pre-bootstrap history,
all detached Xray writers or complete transmitted byte counts.
"""
import hashlib
from pathlib import Path
import subprocess
import tempfile

import sign_observation as observed
import witness_inventory as node

DOMAIN=b"XMESH_QUOTA_V2_REMOTE_WAL_BIRTH_STORED_V1\x00"
KIND="xmesh.quota-v2.external-wal-birth-stored"
FIELDS=("schemaVersion","kind","nodeId","inventorySequence",
        "inventorySha256","inventoryTailDigest",
        "originalNodeWitnessSha256","oldContainerId","oldStartedAt",
        "offhostFullIndexCommitted","bootstrapOnly","canResume",
        "carryforwardApplied","finalMeterVerified","refundableBytes")


def verify_nexus_offhost_anchor(
        raw_nexus_ack, original_node_witness, original_remote_registry,
        independently_enrolled_node_id, independently_enrolled_node_pubkey,
        independently_enrolled_nexus_pubkey, trusted_current_remote_head,
        independent_local_xray_journal):
    """Verify Nexus commit signature, current remote head and local prefix.

    trusted_current_remote_head must come from an authenticated query to
    Nexus's LATEST immutable SQL row, NOT from the signed receipt itself
    or untrusted transport headers. Return nonauthorizing forensic proof.
    """
    if (not isinstance(raw_nexus_ack,bytes) or
            not isinstance(trusted_current_remote_head,dict) or
            set(trusted_current_remote_head)!={"sequence","registrySha256"}):
        raise ValueError("fresh independent Nexus WAL inventory head is required")
    seq=trusted_current_remote_head["sequence"]
    sha=trusted_current_remote_head["registrySha256"]
    if (type(seq) is not int or not 1<=seq<=4096 or
            not isinstance(sha,str) or node.HEX64.fullmatch(sha) is None):
        raise ValueError("invalid independently fetched Nexus history head")
    signed_node=node._verify_witness(
        original_node_witness,original_remote_registry,
        independently_enrolled_node_id,independently_enrolled_node_pubkey)
    doc=observed.strict_json(raw_nexus_ack)
    if (raw_nexus_ack!=observed.canonical(doc)+b"\n" or
            set(doc)!={"algorithm","payload","signature"} or
            doc["algorithm"]!="Ed25519" or
            not isinstance(doc["signature"],str) or
            observed.HEX128.fullmatch(doc["signature"]) is None):
        raise ValueError("noncanonical or unsigned Nexus offhost witness")
    p=doc["payload"]
    if not isinstance(p,dict) or set(p)!=set(FIELDS):
        raise ValueError("unknown Node-gate flags in remote anchor receipt")
    if (type(p["schemaVersion"]) is not int or
            p["schemaVersion"]!=1 or p["kind"]!=KIND or
            type(p["nodeId"]) is not int or
            p["nodeId"]!=independently_enrolled_node_id or
            type(p["inventorySequence"]) is not int or
            p["inventorySequence"]!=signed_node["inventorySequence"] or
            type(p["bootstrapOnly"]) is not bool or
            p["offhostFullIndexCommitted"] is not True or
            p["canResume"] is not False or
            p["carryforwardApplied"] is not False or
            p["finalMeterVerified"] is not False or
            type(p["refundableBytes"]) is not int or
            p["refundableBytes"]!=0):
        raise ValueError("Nexus offhost witness must never authorize old Xray debt release")
    original_fields={
        "inventorySha256":signed_node["inventorySha256"],
        "inventoryTailDigest":signed_node["inventoryTailDigest"],
        "originalNodeWitnessSha256":hashlib.sha256(original_node_witness).hexdigest(),
        "oldContainerId":signed_node["oldContainerId"],
        "oldStartedAt":signed_node["oldStartedAt"],
    }
    if any(p[name]!=value or type(p[name]) is not type(value)
           for name,value in original_fields.items()):
        raise ValueError("Nexus offhost receipt binds another old Xray file set")
    if p["inventorySequence"]!=seq or p["inventorySha256"]!=sha:
        raise ValueError("stale Nexus anchor replay behind independently fetched latest head")
    with tempfile.TemporaryDirectory(prefix="xmesh-node-verify-nexus-birth-") as tmp:
        message=Path(tmp)/"msg"
        signature=Path(tmp)/"sig"
        message.write_bytes(DOMAIN+observed.canonical(p))
        signature.write_bytes(bytes.fromhex(doc["signature"]))
        try:
            verified=subprocess.run(
                ["openssl","pkeyutl","-verify","-rawin","-in",str(message),
                 "-pubin","-inkey",str(independently_enrolled_nexus_pubkey),
                 "-sigfile",str(signature)],
                check=False,capture_output=True,timeout=10)
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise ValueError("trusted Nexus public-key verifier unavailable") from exc
        if verified.returncode:
            raise ValueError("Nexus external WAL witness signed by foreign key")
    # Only an independent Nexus-signed and separately head-checked prefix
    # is acceptable at Node restart. An entirely wiped local index, even
    # with no surviving meter-*.jsonl files, must fail here.
    local=node.verify_local_against_remote_prefix(
        independent_local_xray_journal,original_remote_registry,
        independently_enrolled_node_id,original_node_witness,
        independently_enrolled_node_pubkey)
    if local["localRegistryExtendsRemotePrefix"] is not True:
        raise ValueError("local Xray WAL birth inventory not a full offhost extension")
    return {
        "nexusOffhostSignatureVerified":True,
        "offhostFullBirthIndexHeadMatched":True,
        "nodeLocalIndexExtendsNexusHead":True,
        "firstRemoteSnapshotWasOnlyBootstrap":p["bootstrapOnly"],
        "preBootstrapHistoryCompletenessVerified":False,
        "allXrayWritersCompletedVerified":False,
        "canResume":False,
        "carryforwardApplied":False,
        "finalMeterVerified":False,
        "refundableBytes":0,
    }
