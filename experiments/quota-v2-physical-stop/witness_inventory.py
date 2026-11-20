#!/usr/bin/env python3
"""CI-only Node signed off-host witness of exact fsynced old-Xray WAL births.

Requires independently inspected Docker bind + private live Xray registry and
EVERY birth-indexed main/CDN WAL. Produce raw registry bytes PLUS a separately
Ed25519-signed, domain-separated SHA256/sequence/identity. Intended to send
to a future *independent* Nexus append-only witness store, never to Xray.

No production sender, no assumption that signing means Nexus persisted it,
no durable remote ACK, no applied carryforward or refund. A local signature
cannot detect an attacker who deletes every old WAL AND the local registry:
only a retained, externally verified off-host witness can do that.
"""
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

# The cryptographic signer is injected separately from this stop-chain
# experiment. Keep direct-script and independently imported audit modes
# deterministic rather than depending on the test's import order.
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE.parent/"xray-dataplane-fence"))

import journal_integrity as journal
import meter_inventory_audit as registry
import sign_observation as observed

DOMAIN=b"XMESH_QUOTA_V2_OFFHOST_WAL_BIRTH_WITNESS_V1\x00"
KIND="xmesh.quota-v2.offhost-wal-birth-witness"
MAX_REGISTRY=4 << 20
MAX_WITNESS=4096
HEX64=re.compile(r"[0-9a-f]{64}\Z")
FIELDS=("schemaVersion","kind","nodeId","oldContainerId","oldStartedAt",
        "inventorySequence","inventorySha256","inventoryTailDigest",
        "indexedWalCount","localBirthsIndependentlyChecked",
        "nexusPersisted","carryforwardApplied","canResume",
        "finalMeterVerified","refundableBytes")


def _check(payload):
    if not isinstance(payload,dict) or set(payload)!=set(FIELDS):
        raise ValueError("untrusted Xray inventory witness shape")
    if (type(payload["schemaVersion"]) is not int or
            payload["schemaVersion"]!=1 or payload["kind"]!=KIND or
            type(payload["nodeId"]) is not int or payload["nodeId"]<=0 or
            type(payload["inventorySequence"]) is not int or
            not 1<=payload["inventorySequence"]<=registry.MAX_ENTRIES or
            type(payload["indexedWalCount"]) is not int or
            payload["indexedWalCount"]!=payload["inventorySequence"] or
            payload["localBirthsIndependentlyChecked"] is not True or
            payload["nexusPersisted"] is not False or
            payload["carryforwardApplied"] is not False or
            payload["canResume"] is not False or
            payload["finalMeterVerified"] is not False or
            type(payload["refundableBytes"]) is not int or
            payload["refundableBytes"]!=0):
        raise ValueError("offhost birth witness must remain strictly NONFINAL")
    for key in ("oldContainerId","inventorySha256","inventoryTailDigest"):
        value=payload[key]
        if not isinstance(value,str) or HEX64.fullmatch(value) is None:
            raise ValueError("invalid WAL registry witness fingerprint")
    ts=payload["oldStartedAt"]
    if not isinstance(ts,str) or not 15<=len(ts)<=64 or "T" not in ts:
        raise ValueError("untrusted Xray Docker start timestamp")
    return payload


def _verify_witness(raw, registry_bytes, node_id, public_key):
    if (not isinstance(raw,bytes) or not 0<len(raw)<=MAX_WITNESS or
            not isinstance(registry_bytes,bytes) or
            not 0<len(registry_bytes)<=MAX_REGISTRY or
            not registry_bytes.endswith(b"\n")):
        raise ValueError("missing immutable Xray registry and witness")
    env=observed.strict_json(raw)
    if raw!=observed.canonical(env)+b"\n" or set(env)!={"algorithm","payload","signature"}:
        raise ValueError("noncanonical signed Xray inventory witness")
    if env["algorithm"]!="Ed25519" or not isinstance(env["signature"],str) or (
            observed.HEX128.fullmatch(env["signature"]) is None):
        raise ValueError("unsigned Xray registry witness")
    p=_check(env["payload"])
    if p["nodeId"]!=node_id or type(node_id) is not int or node_id<=0 or (
            p["inventorySha256"]!=hashlib.sha256(registry_bytes).hexdigest()):
        raise ValueError("witness signed for foreign Node or lost local registry")
    # Each line ends in newline. This is a FULL prefix commitment, not a
    # subset of whichever files happen to still be present after a crash.
    if p["inventorySequence"]!=registry_bytes.count(b"\n"):
        raise ValueError("signed birth count differs from actual old WAL index")
    # A remote receipt MUST also preserve the exact last gapless
    # registry hash, not merely quote a signed standalone byte digest.
    try:
        last=observed.strict_json(registry_bytes[:-1].split(b"\n")[-1])
    except (ValueError,UnicodeDecodeError) as exc:
        raise ValueError("noncanonical remote birth-tail JSON") from exc
    if last.get("digest")!=p["inventoryTailDigest"] or (
            last.get("sequence")!=p["inventorySequence"] or
            type(last.get("sequence")) is not int):
        raise ValueError("remote Xray witness birth-tail does not match signed prefix")
    with tempfile.TemporaryDirectory(prefix="xmesh-node-birth-verify-") as root:
        message=Path(root)/"message"
        signature=Path(root)/"signature"
        message.write_bytes(DOMAIN+observed.canonical(p))
        signature.write_bytes(bytes.fromhex(env["signature"]))
        try:
            verified=subprocess.run([
                "openssl","pkeyutl","-verify","-rawin","-in",str(message),
                "-pubin","-inkey",str(public_key),"-sigfile",str(signature)],
                capture_output=True,check=False,timeout=10)
        except (OSError,subprocess.TimeoutExpired) as exc:
            raise ValueError("Node witness Ed25519 verifier unavailable") from exc
        if verified.returncode:
            raise ValueError("Node offhost WAL witness signature mismatch")
    return p


def produce_witness(node_id, trusted_docker, root_private_wal_directory,
                    trusted_node_signing_key, independently_enrolled_node_pubkey,
                    *, sign=observed.sign_bytes):
    """Return (canonical_signed_witness, independently audited exact index).

    Caller must obtain the Docker inspect source outside untrusted JSON,
    verify Node identity and ship BOTH artifacts to Nexus. No user-facing
    authorization occurs here, even if Nexus later stores the pair.
    """
    if type(node_id) is not int or node_id<=0 or not isinstance(trusted_docker,dict):
        raise ValueError("missing authenticated Node or Docker runtime")
    container=trusted_docker.get("Id")
    started=(trusted_docker.get("State") or {}).get("StartedAt")
    if (not isinstance(container,str) or HEX64.fullmatch(container) is None or
            not isinstance(started,str)):
        raise ValueError("untrusted Xray container identity for Node witness")
    dfd=journal._validate_directory(root_private_wal_directory)
    try:
        journal._verify_mount(trusted_docker,str(root_private_wal_directory))
        names=sorted(n for n in os.listdir(dfd) if n.startswith("meter-"))
        indexed,validated=registry.verify_meter_inventory(
            dfd,names,journal._read_meter_wal,journal._canonical_go)
        raw=registry._read_inventory(dfd)
        if raw is None or not indexed or len(indexed)!=len(validated):
            raise ValueError("no independently auditable born Xray WALs")
        if len(raw)>MAX_REGISTRY:
            raise ValueError("unbounded Node offhost witness registry")
        # Recheck after all potentially expensive WAL reads to refuse
        # concurrent append/replace before creating an immutable signature.
        if registry._read_inventory(dfd)!=raw:
            raise ValueError("Xray birth registry changed while witnessing")
        sequence=len(indexed)
        tail=next(reversed(indexed.values()))["digest"]
        p={
            "schemaVersion":1,"kind":KIND,
            "nodeId":node_id,"oldContainerId":container,
            "oldStartedAt":started,"inventorySequence":sequence,
            "inventorySha256":hashlib.sha256(raw).hexdigest(),
            "inventoryTailDigest":tail,"indexedWalCount":sequence,
            "localBirthsIndependentlyChecked":True,
            "nexusPersisted":False,"carryforwardApplied":False,
            "canResume":False,"finalMeterVerified":False,"refundableBytes":0,
        }
        _check(p)
        envelope={
            "algorithm":"Ed25519","payload":p,
            "signature":sign(
                trusted_node_signing_key,DOMAIN+observed.canonical(p))}
        signed=observed.canonical(envelope)+b"\n"
        _verify_witness(signed,raw,node_id,independently_enrolled_node_pubkey)
        if registry._read_inventory(dfd)!=raw:
            raise ValueError("Xray WAL birth index changed after signing")
        return signed,raw
    finally:
        os.close(dfd)


def verify_local_against_remote_prefix(trusted_root_wal_directory,
                                       independent_remote_registry_bytes,
                                       trusted_node_id, signed_remote_witness,
                                       externally_enrolled_node_public_key):
    """CI-only Node recovery check against an external, separately saved pair.

    Must run BEFORE re-admitting any new-Xray user. This checks that the
    entire currently live index extends the exact external prefix; if every
    local WAL is deleted, remote prefix still exists and recovery is DENIED.
    It does NOT establish remote persistence by itself: inputs must come
    from Nexus's authenticated, immutable off-host store.
    """
    remote=_verify_witness(signed_remote_witness,independent_remote_registry_bytes,
                           trusted_node_id,externally_enrolled_node_public_key)
    dfd=journal._validate_directory(trusted_root_wal_directory)
    try:
        current=registry._read_inventory(dfd)
        if current is None or not current.startswith(independent_remote_registry_bytes):
            raise ValueError("Xray local WAL history rolled back behind offhost witness")
        names=sorted(n for n in os.listdir(dfd) if n.startswith("meter-"))
        checked,_=registry.verify_meter_inventory(
            dfd,names,journal._read_meter_wal,journal._canonical_go)
        if len(checked)<remote["inventorySequence"]:
            raise ValueError("old Xray inventory shorter than external witness")
        if registry._read_inventory(dfd)!=current:
            raise ValueError("Xray inventory raced remote proof inspection")
    finally:
        os.close(dfd)
    return {
        "remoteWitnessSignatureVerified":True,
        "localRegistryExtendsRemotePrefix":True,
        "externalPersistenceIndependentlyVerified":False,
        "canResume":False,
        "finalMeterVerified":False,
        "refundableBytes":0,
    }
