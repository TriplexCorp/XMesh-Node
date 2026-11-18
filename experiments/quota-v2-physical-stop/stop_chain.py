#!/usr/bin/env python3
"""CI-only signed chain: immutable NONFINAL Xray observation -> old PID exit.

This joins two independently checked facts about ONE managed Xray incarnation:
an already fsynced, Node-signed observation verified against the live PID, and
the later physical exit of that exact pinned PID under a durable deny marker.
Neither observation is a trustworthy final byte counter: asynchronous
writers, prior runtimes, and kernel queues remain unproven. Never refund.
"""
import hashlib
import hmac
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "xray-dataplane-fence"))
import sign_observation as observed
import runtime_identity
import attestor

DOMAIN = b"XMESH_QUOTA_V2_NONFINAL_STOP_CHAIN_V1\x00"
KIND = "xmesh.quota-v2.nonfinal-stop-chain"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX128 = re.compile(r"[0-9a-f]{128}\Z")
SCOPE = ("nodeId", "userId", "epoch", "meterEpoch",
         "reservationId", "revision", "revocationId")
FLAGS = ("oldPidfdExited", "managedContainerStopped",
         "restartDisabled", "durableDenyArmed")


def _read_original(directory, checkpoint):
    name = observed.receipt_name(checkpoint)
    dfd = observed.private_directory(directory)
    try:
        raw = observed.read_private_record(dfd, name)
    finally:
        os.close(dfd)
    envelope = observed.strict_json(raw)
    # Never silently accept a different persisted checkpoint under a matching
    # filename. The original receipt has already been cryptographically signed.
    if not isinstance(envelope.get("payload"), dict) or (
            envelope["payload"].get("checkpoint") != checkpoint):
        raise ValueError("persisted observed checkpoint mismatches requested lease")
    return raw, envelope


class BoundOldProcess:
    def __init__(self, probe, checkpoint, raw_hash, original_name, node_id):
        self.probe = probe
        self.checkpoint = checkpoint
        self.raw_hash = raw_hash
        self.original_name = original_name
        self.node_id = node_id


def prepare_old_process_stop(probe, checkpoint, observed_directory,
                             trusted_node_id, trusted_public_key):
    """Bind the recorded pre-stop bytes to the exact still-running pidfd.

    Requires a Node-signed, independently committed-policy-checked observation
    that *already* attested the same durable Node meter floor. Direct-PID test
    fixtures (without floor proof) MUST NOT be promoted to stop-chain input.
    """
    if not isinstance(probe, attestor.OldXrayProbe) or probe.pidfd is None:
        raise ValueError("trusted old-process pidfd missing")
    if not isinstance(checkpoint, dict) or (
            type(trusted_node_id) is not int or trusted_node_id <= 0):
        raise ValueError("invalid bound Node or observed checkpoint")
    raw, envelope = _read_original(observed_directory, checkpoint)
    signed = observed.verify_envelope(
        envelope, trusted_node_id, trusted_public_key)
    if (signed.get("monotonicLedgerFloorVerified") is not True or
            signed.get("liveRuntimeIndependentlyVerified") is not True or
            signed.get("completeSignedInboundScopeObserved") is not True or
            signed.get("finalMeterVerified") is not False or
            signed.get("settlementEligible") is not False or
            signed.get("refundableBytes") != 0):
        raise ValueError("incomplete signed nonfinal Xray observation")
    if signed["checkpoint"] != checkpoint:
        raise ValueError("signed checkpoint replaced in observation")
    runtime_identity.verify_live_runtime(checkpoint, probe.old_pid)
    docker = attestor.inspect_managed()
    if (attestor.identity(docker) != probe.docker_identity or
            docker["State"].get("Running") is not True or
            docker["State"].get("Pid") != probe.old_pid):
        raise ValueError("Xray changed between signed observation and old PID probe")
    return BoundOldProcess(
        probe, checkpoint.copy(), hashlib.sha256(raw).hexdigest(),
        observed.receipt_name(checkpoint), trusted_node_id)


def _payload(bound, stop):
    p = {field: bound.checkpoint[field] for field in SCOPE}
    p.update({
        "schemaVersion": 1, "kind": KIND,
        "observationSha256": bound.raw_hash,
        "checkpointSha256": hashlib.sha256(
            observed.canonical(bound.checkpoint)).hexdigest(),
        "oldRuntimeId": bound.checkpoint["runtimeId"],
        "oldContainerId": stop["oldContainerId"],
        "oldStartedAt": stop["oldStartedAt"],
        "oldPidfdExited": stop["oldPidfdExited"],
        "managedContainerStopped": stop["managedContainerStopped"],
        "restartDisabled": stop["restartDisabled"],
        "durableDenyArmed": stop["durableDenyArmed"],
        "finalMeterVerified": False,
        "settlementEligible": False,
        "refundableBytes": 0,
    })
    return p


def _verify_shape(p, original):
    if not isinstance(p, dict) or set(p) != set(SCOPE) | {
            "schemaVersion", "kind", "observationSha256",
            "checkpointSha256", "oldRuntimeId", "oldContainerId",
            "oldStartedAt", "oldPidfdExited", "managedContainerStopped",
            "restartDisabled", "durableDenyArmed", "finalMeterVerified",
            "settlementEligible", "refundableBytes"}:
        raise ValueError("unknown or missing signed stop-chain fields")
    cp = original["payload"]["checkpoint"]
    if (type(p["schemaVersion"]) is not int or p["schemaVersion"] != 1 or
            p["kind"] != KIND or
            p["finalMeterVerified"] is not False or
            p["settlementEligible"] is not False or
            type(p["refundableBytes"]) is not int or p["refundableBytes"] != 0 or
            any(p[name] is not True for name in FLAGS) or
            any(p[name] != cp[name] or type(p[name]) is not type(cp[name])
                for name in SCOPE) or
            p["oldRuntimeId"] != cp["runtimeId"] or
            not isinstance(p["oldRuntimeId"], str) or
            HEX64.fullmatch(p["oldRuntimeId"]) is None or
            not isinstance(p["oldContainerId"], str) or
            HEX64.fullmatch(p["oldContainerId"]) is None or
            not isinstance(p["oldStartedAt"], str) or
            "T" not in p["oldStartedAt"] or
            p["oldStartedAt"].startswith("0001-01-01") or
            p["checkpointSha256"] != hashlib.sha256(
                observed.canonical(cp)).hexdigest()):
        raise ValueError("stop-chain scope, runtime or nonrefundability invalid")


def verify_stop_chain(envelope, original_record, trusted_node_id,
                      trusted_public_key):
    """Offline signature verification. NEVER establishes terminality."""
    if not isinstance(envelope, dict) or set(envelope) != {
            "payload", "signature", "algorithm"} or (
            envelope["algorithm"] != "Ed25519" or
            not isinstance(envelope["signature"], str) or
            HEX128.fullmatch(envelope["signature"]) is None):
        raise ValueError("invalid stop-chain envelope")
    if not isinstance(original_record, (bytes, bytearray)):
        raise ValueError("missing immutable original receipt bytes")
    original = observed.strict_json(original_record)
    observed.verify_envelope(original, trusted_node_id, trusted_public_key)
    if original["payload"]["monotonicLedgerFloorVerified"] is not True:
        raise ValueError("stop-chain cannot reference test-only unverified meter")
    p = envelope["payload"]
    _verify_shape(p, original)
    if (p["nodeId"] != trusted_node_id or
            p["observationSha256"] != hashlib.sha256(original_record).hexdigest()):
        raise ValueError("stop-chain references a different signed observation")
    if not isinstance(p["observationSha256"], str) or (
            HEX64.fullmatch(p["observationSha256"]) is None):
        raise ValueError("invalid original observation digest")
    with tempfile.TemporaryDirectory(prefix="xmesh-stopchain-verify-") as tmp:
        msg = Path(tmp) / "message"
        sig = Path(tmp) / "sig"
        msg.write_bytes(DOMAIN + observed.canonical(p))
        sig.write_bytes(bytes.fromhex(envelope["signature"]))
        result = subprocess.run(
            ["openssl", "pkeyutl", "-verify", "-rawin",
             "-in", str(msg), "-pubin", "-inkey",
             str(trusted_public_key), "-sigfile", str(sig)],
            capture_output=True, check=False, timeout=10)
        if result.returncode != 0:
            raise ValueError("Node Ed25519 stop-chain signature invalid")
    return p


def complete_old_process_stop(bound, state_dir, marker_helper,
                              observed_directory, stop_ledger,
                              node_private_key, trusted_public_key):
    """Commit a signed NONFINAL historical stop event, never a byte refund."""
    if not isinstance(bound, BoundOldProcess):
        raise ValueError("old-process checkpoint binding missing")
    # Do not trust a post-stop marker without proving the SAME old pidfd exit.
    stop = attestor.verify_old_xray_physically_stopped(
        bound.probe, state_dir, marker_helper)
    if any(stop.get(name) is not True for name in FLAGS) or (
            stop.get("finalMeterVerified") is not False or
            stop.get("settlementEligible") is not False or
            stop.get("refundableBytes") != 0 or
            (stop.get("oldContainerId"), stop.get("oldStartedAt")) !=
            bound.probe.docker_identity):
        raise ValueError("physical stop was not verified for original Xray")
    raw, original = _read_original(observed_directory, bound.checkpoint)
    if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), bound.raw_hash):
        raise ValueError("original signed observation changed during stop")
    observed.verify_envelope(original, bound.node_id, trusted_public_key)
    payload = _payload(bound, stop)
    _verify_shape(payload, original)
    signature = observed.sign_bytes(
        node_private_key, DOMAIN + observed.canonical(payload))
    envelope = {
        "algorithm": "Ed25519", "payload": payload, "signature": signature}
    verify_stop_chain(envelope, raw, bound.node_id, trusted_public_key)
    # Recheck the managed process and deny marker after signing, before any
    # durable stop-chain publication. Historical exit is not a promise that
    # Docker will remain stopped forever, but a concurrent restart may not
    # be recorded as a valid completed stop transaction.
    current = attestor.inspect_managed()
    if (attestor.identity(current) != bound.probe.docker_identity or
            current["State"].get("Running") is not False or
            current["State"].get("Pid") != 0 or
            current["HostConfig"]["RestartPolicy"].get("Name") != "no"):
        raise ValueError("Xray restarted while signing the stop chain")
    attestor.marker_armed(state_dir, marker_helper)
    evidence = observed.canonical(envelope) + b"\n"
    if len(evidence) > observed.MAX_RECORD:
        raise ValueError("stop-chain evidence too large")
    dfd = observed.private_directory(stop_ledger)
    try:
        # The per-reservation slot prevents divergent replays / double use.
        slot = "stop-" + observed.receipt_name(bound.checkpoint)
        observed.append_only(dfd, slot, evidence)
    finally:
        os.close(dfd)
    return envelope
