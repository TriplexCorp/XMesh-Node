#!/usr/bin/env python3
"""Deterministic cross-language fixture; keys are public test seeds ONLY."""
from hashlib import sha256
import json
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def canonical(value):
    # Identical bytes to the Python retirement archive writer.
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"), allow_nan=False).encode("utf-8")


def digest(raw):
    return sha256(raw).hexdigest()


def public(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw,
                                         serialization.PublicFormat.Raw)


def make_vector():
    # NOT product or enrollment keys. Reproducible public test fixtures.
    node = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    nexus = Ed25519PrivateKey.from_private_bytes(bytes(range(32, 64)))
    runtime = "b"*64
    activation = "a"*64
    container = "c"*64
    started = "2026-11-27T04:00:00.123456789Z"
    inventory, heads = "d"*64, "e"*64
    scope = dict(nodeId=42, activationReceiptSha256=activation)
    p = dict(scope, schemaVersion=2, kind="xmesh.quota-v2.public-tls-wal-head",
             userId=100, runtimeId=runtime, containerId=container, startedAt=started,
             hostPid=731, genesisPolicySha256="f"*64, profileRevision="1"*64,
             capRosterSha256="2"*64, challenge="3"*64, issuedAtMs=11000,
             validUntilMs=18000, historyState="committed_birth_index",
             inventorySequence=2, inventorySha256=inventory, inventoryTailDigest="4"*64,
             committedChargeStreamCount=2, committedChargeHeadsSha256=heads,
             preBootstrapHistoryCompletenessVerified=False, liveMeterVerified=False,
             finalMeterVerified=False, canServePublic=False, canSpend=False,
             canStart=False, canResume=False, authorizedBytes=0, refundableBytes=0)
    nexus_message = b"XMESH_QUOTA_V2_PUBLIC_TLS_WAL_HEAD_V2\x00" + canonical(p)
    envelope = canonical(dict(algorithm="Ed25519", payload=p,
                              signature=nexus.sign(nexus_message).hex())) + b"\n"
    response = canonical({"signedEnvelope": envelope.decode()})
    observation = dict(schemaVersion=1, kind="xmesh.quota-v2.nonfinal-first-meter-retirement",
                       nodeId=42, runtimeId=runtime, containerId=container, startedAt=started,
                       signedWalReadbackSha256=digest(response), inventorySha256=inventory,
                       committedChargeHeadsSha256=heads, retiredLedgerSha256="5"*64,
                       durableUserDenials={"100": "6"*64, "101": "7"*64},
                       originalMeterPidfdExited=True, lifetimeLockReleased=True,
                       finalMeterVerified=False, settlementEligible=False, canResume=False,
                       refundableBytes=0, deliveredBytesVerified=False,
                       nodeSignatureVerified=False, canServePublic=False, canStart=False)
    archive = canonical(dict(observation=observation, nexusResponse=response.decode())) + b"\n"
    assert len(archive) <= 8192
    node_public, nexus_public = public(node), public(nexus)
    claim = dict(scope, schemaVersion=1,
                 kind="xmesh.quota-v2.historical-retirement-archive-possession",
                 nodePublicKey=node_public.hex(), nexusPublicKey=nexus_public.hex(),
                 runtimeId=runtime, archiveSha256=digest(archive),
                 signedWalReadbackSha256=digest(response), nexusIssuedAtMs=11000,
                 nexusValidUntilMs=18000, archivePossessionOnly=True,
                 localObservationsVerified=False, liveMeterVerified=False,
                 deliveredBytesVerified=False, finalMeterVerified=False,
                 settlementEligible=False, canServePublic=False, canSpend=False,
                 canStart=False, canResume=False, authorizedBytes=0, refundableBytes=0)
    message = b"XMESH_QUOTA_V2_HISTORICAL_RETIREMENT_ARCHIVE_POSSESSION_V1\x00" + canonical(claim)
    signature = node.sign(message)
    # Independently verify before materializing only public fixture bytes.
    node.public_key().verify(signature, message)
    nexus.public_key().verify(bytes.fromhex(json.loads(envelope)["signature"]), nexus_message)
    return dict(scope, nodePublicKey=node_public.hex(), nexusPublicKey=nexus_public.hex(),
                archive=archive.decode(), messageHex=message.hex(), signature=signature.hex())


if __name__ == "__main__":
    Path(__file__).with_name("python_ed25519_vector.json").write_bytes(
        canonical(make_vector()) + b"\n")
