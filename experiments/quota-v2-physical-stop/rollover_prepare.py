#!/usr/bin/env python3
"""CI-only *prepare*, never apply, a signed conservative Xray runtime rollover.

A new Xray process must not reuse zeroed StatsService counters when the old
process has fsynced user byte intents. This module produces an independently
verifiable proposal bound to all THREE source objects: a signed Node observed
checkpoint, a signed physical old-PID stop, and the exact old process's
root-private, independently Docker-mounted byte WAL.

This is NOT a Nexus ack, a credit transaction, an admission token, a
kernel-verified final byte meter, or an instruction to unfreeze the account.
No production runtime imports or calls this module.
"""
import hashlib
import hmac
import os
from pathlib import Path
import re
import subprocess
import tempfile

import attestor
import journal_integrity
import sign_observation as observed
import stop_chain

DOMAIN = b"XMESH_QUOTA_V2_CONSERVATIVE_ROLLOVER_PREPARE_V1\x00"
KIND = "xmesh.quota-v2.conservative-rollover-prepare"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX128 = re.compile(r"[0-9a-f]{128}\Z")
SLOT_SCOPE = ("nodeId", "userId", "epoch", "meterEpoch", "reservationId")
MAX_ACCOUNT_BYTES = 2**63-1
FLAGS = ("absoluteCarryforwardVerified", "nexusAcknowledged",
         "rolloverAuthorized", "finalMeterVerified", "settlementEligible")


def proposal_name(cp):
    if not isinstance(cp,dict):
        raise ValueError("invalid Xray rollover reservation")
    scope = {key:cp[key] for key in SLOT_SCOPE}
    # The same signed reservation cannot issue independent proposals by
    # changing PID, revision, URL, revocation ID or inbound alias.
    return "rollover-prepare-" + hashlib.sha256(
        observed.canonical(scope)).hexdigest() + ".json"


def read_published(directory,name):
    dfd=observed.private_directory(directory)
    try:
        raw=observed.read_private_record(dfd,name)
    finally:
        os.close(dfd)
    if raw != observed.canonical(observed.strict_json(raw)) + b"\n":
        raise ValueError("noncanonical immutable signed rollover source")
    return raw


def _verify_stopped_docker(docker, cp, stopped):
    if not isinstance(docker,dict) or docker.get("Name")!="/xmesh-managed-xray":
        raise ValueError("independent managed Docker Xray inspection required")
    state=docker.get("State")
    host=docker.get("HostConfig")
    policy=host.get("RestartPolicy") if isinstance(host,dict) else None
    if (not isinstance(state,dict) or
            docker.get("Id")!=stopped["oldContainerId"] or
            state.get("StartedAt")!=stopped["oldStartedAt"] or
            state.get("Running") is not False or
            type(state.get("Pid")) is not int or state["Pid"]!=0 or
            not isinstance(policy,dict) or policy.get("Name")!="no" or
            cp["runtimeId"]!=stopped["oldRuntimeId"] or
            stopped["oldPidfdExited"] is not True or
            stopped["managedContainerStopped"] is not True or
            stopped["restartDisabled"] is not True or
            stopped["durableDenyArmed"] is not True):
        raise ValueError("old Xray runtime not proven physically stopped")
    return True


def _build_payload(checkpoint, original_envelope, stop_payload, raw_observed,
                   raw_stop, journal_hash):
    signed_observed=original_envelope["payload"]
    seen=checkpoint["inboundMeters"]
    total_up=checkpoint["uplinkBytes"]
    total_down=checkpoint["downlinkBytes"]
    original_floor=signed_observed["durableAbsoluteFloorBytes"]
    if (type(original_floor) is not int or original_floor<0 or
            original_floor>MAX_ACCOUNT_BYTES or
            type(total_up) is not int or type(total_down) is not int or
            total_up<0 or total_down<0 or total_up+total_down>MAX_ACCOUNT_BYTES or
            not isinstance(seen,list) or len(seen)==0 or len(seen)>16):
        raise ValueError("untrusted node floor or Xray cumulative byte amounts")
    if not hmac.compare_digest(journal_hash,stop_payload["xrayJournalSha256"]):
        raise ValueError("physical Xray stop proof does not bind this exact byte WAL")
    # Exactly these alias/direction totals were observed and fsynced by the
    # old process. Node cumulative floor may ALREADY include those bytes:
    # NEVER add them together, double-charge, or declare a rollover balance.
    rows=[]
    prior=""
    for row in seen:
        if (not isinstance(row,dict) or
                set(row)!={"email","uplinkBytes","downlinkBytes"} or
                not isinstance(row["email"],str) or
                not row["email"].startswith("xmesh-u"+str(checkpoint["userId"])+"--") or
                row["email"]<=prior):
            raise ValueError("old process alias roster is ambiguous")
        prior=row["email"]
        for name in ("uplinkBytes","downlinkBytes"):
            if type(row[name]) is not int or not 0<=row[name]<=MAX_ACCOUNT_BYTES:
                raise ValueError("old Xray meter amount not a safe integer")
        rows.append(dict(row))
    if (sum(r["uplinkBytes"] for r in rows)!=total_up or
            sum(r["downlinkBytes"] for r in rows)!=total_down):
        raise ValueError("Xray WAL account total differs from exact inbound roster")
    payload={key: checkpoint[key] for key in stop_chain.SCOPE}
    payload.update({
        "schemaVersion":1, "kind":KIND,
        "oldRuntimeId":stop_payload["oldRuntimeId"],
        "oldContainerId":stop_payload["oldContainerId"],
        "oldStartedAt":stop_payload["oldStartedAt"],
        "observationSha256":hashlib.sha256(raw_observed).hexdigest(),
        "stopChainSha256":hashlib.sha256(raw_stop).hexdigest(),
        "xrayJournalSha256":journal_hash,
        "nodeDurableAbsoluteFloorBytes":original_floor,
        "oldRuntimeObservedUplinkBytes":total_up,
        "oldRuntimeObservedDownlinkBytes":total_down,
        "inboundMeters":rows,
        # Explicitly require a future, separately signed and durable
        # Nexus acknowledgment that is NOT implemented in this proposal.
        "absoluteCarryforwardVerified":False,
        "nexusAcknowledged":False,
        "rolloverAuthorized":False,
        "finalMeterVerified":False,
        "settlementEligible":False,
        "refundableBytes":0,
    })
    return payload


def verify_rollover_proposal(envelope, raw_observed, raw_stop,
                             trusted_node_id, trusted_node_public_key,
                             trusted_journal_sha256):
    """Independent verifier must supply the *re-read* old-Xray WAL digest.

    The trusted Node key and digest are caller-provided, not extracted from
    untrusted signed payload. No output authorizes admission or settlement.
    """
    if (not isinstance(trusted_journal_sha256,str) or
            HEX64.fullmatch(trusted_journal_sha256) is None):
        raise ValueError("independent old-Xray WAL fingerprint missing")
    if not isinstance(raw_observed,(bytes,bytearray)) or not isinstance(raw_stop,(bytes,bytearray)):
        raise ValueError("original immutable signed sources are mandatory")
    if (not isinstance(envelope,dict) or
            set(envelope)!={"algorithm","payload","signature"} or
            envelope["algorithm"]!="Ed25519" or
            not isinstance(envelope["signature"],str) or
            HEX128.fullmatch(envelope["signature"]) is None):
        raise ValueError("invalid Xray rollover proposal envelope")
    original=observed.strict_json(raw_observed)
    stop=observed.strict_json(raw_stop)
    if (raw_observed!=observed.canonical(original)+b"\n" or
            raw_stop!=observed.canonical(stop)+b"\n"):
        raise ValueError("changed canonical source evidence")
    signed_observation=observed.verify_envelope(original,trusted_node_id,
                                                 trusted_node_public_key)
    if (signed_observation.get("monotonicLedgerFloorVerified") is not True or
            signed_observation.get("completeSignedInboundScopeObserved") is not True or
            signed_observation.get("liveRuntimeIndependentlyVerified") is not True or
            signed_observation.get("finalMeterVerified") is not False or
            signed_observation.get("settlementEligible") is not False or
            signed_observation.get("refundableBytes") != 0):
        raise ValueError("old observation lacks independently verified Node floor")
    signed_stop=stop_chain.verify_stop_chain(stop,raw_observed,trusted_node_id,
                                              trusted_node_public_key)
    if (signed_stop.get("xrayJournalSha256")!=trusted_journal_sha256 or
            not all(signed_stop.get(k) is True for k in stop_chain.FLAGS)):
        raise ValueError("old process stop not bound to trusted byte WAL")
    checkpoint=signed_observation["checkpoint"]
    expected=_build_payload(checkpoint,original,signed_stop,raw_observed,
                            raw_stop,trusted_journal_sha256)
    p=envelope["payload"]
    if not isinstance(p,dict) or set(p)!=set(expected) or p!=expected or (
            any(type(p[k]) is not bool or p[k] is not False for k in FLAGS) or
            type(p["refundableBytes"]) is not int or p["refundableBytes"]!=0 or
            type(p["schemaVersion"]) is not int or p["schemaVersion"]!=1):
        raise ValueError("invalid or prematurely approved conservative rollover payload")
    with tempfile.TemporaryDirectory(prefix="xmesh-rollover-verify-") as tmp:
        msg=Path(tmp)/"message"
        sig=Path(tmp)/"signature"
        msg.write_bytes(DOMAIN+observed.canonical(p))
        sig.write_bytes(bytes.fromhex(envelope["signature"]))
        result=subprocess.run(
            ["openssl","pkeyutl","-verify","-rawin","-in",str(msg),
             "-pubin","-inkey",str(trusted_node_public_key),
             "-sigfile",str(sig)],
            capture_output=True,timeout=10,check=False)
        if result.returncode:
            raise ValueError("Node Ed25519 conservative rollover signature invalid")
    return p


def create_rollover_proposal(checkpoint, observed_directory, stop_directory,
                             trusted_xray_journal, node_id,
                             node_private_key, trusted_public_key,
                             proposal_directory):
    """Prepare one immutable nonauthorizing account proposal, never apply it.

    Requires the managed old Docker container to still be independently
    inspectable in stopped/no-restart state. An unobserved SIGKILL, stale
    previous-runtime WAL or changed directory mount must fail closed.
    """
    if not isinstance(checkpoint,dict) or type(node_id) is not int or node_id<=0:
        raise ValueError("invalid Node or old-process scope")
    original_name=observed.receipt_name(checkpoint)
    raw_observed=read_published(observed_directory,original_name)
    raw_stop=read_published(stop_directory,"stop-"+original_name)
    stop=stop_chain.verify_stop_chain(
        observed.strict_json(raw_stop),raw_observed,node_id,trusted_public_key)
    docker_before=attestor.inspect_managed()
    _verify_stopped_docker(docker_before,checkpoint,stop)
    digest=journal_integrity.verify_poststop_journal(
        checkpoint,trusted_xray_journal,docker_before)
    if not hmac.compare_digest(digest,stop["xrayJournalSha256"]):
        raise ValueError("old Xray WAL changed after signed physical stop")
    original=observed.strict_json(raw_observed)
    payload=_build_payload(checkpoint,original,stop,raw_observed,raw_stop,digest)
    signature=observed.sign_bytes(node_private_key,DOMAIN+observed.canonical(payload))
    envelope={"algorithm":"Ed25519","payload":payload,"signature":signature}
    verify_rollover_proposal(envelope,raw_observed,raw_stop,node_id,
                             trusted_public_key,digest)
    docker_after=attestor.inspect_managed()
    if docker_before!=docker_after:
        raise ValueError("Xray container was replaced while preparing rollover")
    _verify_stopped_docker(docker_after,checkpoint,stop)
    checked=journal_integrity.verify_poststop_journal(
        checkpoint,trusted_xray_journal,docker_after)
    if not hmac.compare_digest(checked,digest):
        raise ValueError("old-Xray metered WAL changed during rollover signing")
    if (read_published(observed_directory,original_name)!=raw_observed or
            read_published(stop_directory,"stop-"+original_name)!=raw_stop):
        raise ValueError("signed rollover sources changed before publication")
    raw=observed.canonical(envelope)+b"\n"
    if len(raw)>observed.MAX_RECORD:
        raise ValueError("Xray rollover proposal exceeds immutable record limit")
    dfd=observed.private_directory(proposal_directory)
    try:
        observed.append_only(dfd,proposal_name(checkpoint),raw)
    finally:
        os.close(dfd)
    return envelope
