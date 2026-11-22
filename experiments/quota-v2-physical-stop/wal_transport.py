#!/usr/bin/env python3
"""Exchange nonauthorizing WAL history over the enrolled XSP/2 product tunnel."""
import argparse
import base64
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import sys
import tempfile
import time
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "xray-dataplane-fence"))

import journal_integrity as journal
import meter_inventory_audit as registry
import runtime_identity
import sign_observation as observed
import verify_nexus_wal_anchor as verifier
import witness_inventory as producer

PRODUCT = "/usr/local/bin/xmesh-agent-xspv2-product"
PATH = "/api/v1/node/quota-v2/wal"
HEAD_DOMAIN = b"XMESH_QUOTA_V2_REMOTE_WAL_HEAD_V1\x00"
GENESIS_DOMAIN = b"XMESH_XRAY_GENESIS_PREPARED_V1\x00"
WIRE_INDEX_LIMIT = 384 * 1024
INDEX_LIMIT = 4 * 1024 * 1024
RESPONSE_LIMIT = 544 * 1024
POLICY_KEY = "/var/lib/xmesh-xray-sync/policy-public-key"


def _hex(value, size):
    return isinstance(value, str) and re.fullmatch(rf"[0-9a-f]{{{size}}}", value) is not None


def _b64(value, limit):
    if not isinstance(value, str) or not value or len(value) > ((limit + 2) // 3) * 4:
        raise ValueError("invalid WAL transport record size")
    raw = base64.b64decode(value, validate=True)
    if len(raw) > limit or base64.b64encode(raw).decode("ascii") != value:
        raise ValueError("noncanonical WAL transport bytes")
    return raw


def _unpack_bundle(raw):
    doc = observed.strict_json(raw, limit=RESPONSE_LIMIT)
    fields = {"head", "receipt", "witness", "inventory"}
    if not isinstance(doc, dict) or set(doc) not in (fields, fields | {"inventoryEncoding"}):
        raise ValueError("invalid WAL transport response")
    wire = _b64(doc["inventory"], WIRE_INDEX_LIMIT)
    if "inventoryEncoding" not in doc:
        return doc, wire
    if doc["inventoryEncoding"] != "gzip":
        raise ValueError("unsupported WAL inventory encoding")
    try:
        decoder = zlib.decompressobj(wbits=31)
        index = decoder.decompress(wire, INDEX_LIMIT + 1)
    except zlib.error as error:
        raise ValueError("invalid compressed WAL inventory") from error
    if (not WIRE_INDEX_LIMIT < len(index) <= INDEX_LIMIT or not decoder.eof
            or decoder.unused_data or decoder.unconsumed_tail):
        raise ValueError("invalid compressed WAL inventory bounds")
    return doc, index


def _pack_inventory(index):
    if not 0 < len(index) <= INDEX_LIMIT:
        raise ValueError("full WAL index exceeds the uncompressed limit")
    if len(index) <= WIRE_INDEX_LIMIT:
        return {"inventory": base64.b64encode(index).decode("ascii")}
    wire = gzip.compress(index, compresslevel=6, mtime=0)
    if len(wire) > WIRE_INDEX_LIMIT:
        raise ValueError("full WAL index exceeds the XSP/2 transfer cap")
    return {"inventory": base64.b64encode(wire).decode("ascii"), "inventoryEncoding": "gzip"}


def verify_bundle(raw, challenge, node, node_public, panel_public, local, expected_receipt=None):
    doc, index = _unpack_bundle(raw)
    return _verify_bundle(doc, index, challenge, node, node_public, panel_public, local,
                          expected_receipt)


def _verify_bundle(doc, index, challenge, node, node_public, panel_public, local, expected_receipt):
    head_raw = _b64(doc["head"], 4096)
    receipt = _b64(doc["receipt"], 4096)
    if expected_receipt is not None and receipt != expected_receipt:
        raise ValueError("stored WAL receipt differs from the current checkpoint")
    witness = _b64(doc["witness"], 4096)
    envelope = observed.strict_json(head_raw)
    if (not isinstance(envelope, dict) or set(envelope) != {"algorithm", "payload", "signature"}
            or head_raw != observed.canonical(envelope) + b"\n"
            or envelope["algorithm"] != "Ed25519" or not _hex(envelope["signature"], 128)):
        raise ValueError("invalid signed current WAL head")
    payload = envelope["payload"]
    if (not isinstance(payload, dict) or set(payload) != {
            "schemaVersion", "kind", "nodeId", "challenge", "sequence", "registrySha256", "receiptSha256"}
            or type(payload["schemaVersion"]) is not int or payload["schemaVersion"] != 1
            or payload["kind"] != "xmesh.quota-v2.external-wal-head"
            or type(payload["nodeId"]) is not int or payload["nodeId"] != node
            or not _hex(challenge, 64) or payload["challenge"] != challenge
            or payload["registrySha256"] != hashlib.sha256(index).hexdigest()
            or payload["receiptSha256"] != hashlib.sha256(receipt).hexdigest()):
        raise ValueError("fresh WAL head binding mismatch")
    verifier.verify_nexus_signature(HEAD_DOMAIN, payload, envelope["signature"], panel_public)
    head = {name: payload[name] for name in ("sequence", "registrySha256")}
    return verifier.verify_nexus_offhost_anchor(
        receipt, witness, index, node, node_public, panel_public, head, local)


class MissingCheckpoint(ValueError):
    """Authenticated Nexus reports that this Node has no WAL anchor yet."""


def _post(root, request):
    body, output, status = (root / name for name in ("request.json", "reply.json", "status"))
    body.write_bytes(observed.canonical(request))
    subprocess.run([
        PRODUCT, "request", "--path", PATH, "--body-file", str(body),
        "--output-file", str(output), "--status-file", str(status),
    ], check=True, timeout=30)
    code = status.read_text(encoding="ascii").strip()
    with output.open("rb") as reply:
        raw = reply.read(RESPONSE_LIMIT + 1)
    if len(raw) > RESPONSE_LIMIT:
        raise ValueError("oversized WAL transport response")
    if code == "404" and request["operation"] == "head":
        if observed.strict_json(raw) == {"error": "No committed WAL checkpoint."}:
            raise MissingCheckpoint("Nexus has no committed WAL checkpoint")
    if code != "200":
        raise ValueError("Nexus did not confirm WAL operation")
    return raw


def _write_public(raw_hex, path):
    if not _hex(raw_hex, 64):
        raise ValueError("invalid pinned Ed25519 public key")
    der = bytes.fromhex("302a300506032b6570032100" + raw_hex)
    subprocess.run([
        "openssl", "pkey", "-pubin", "-inform", "DER", "-pubout", "-out", str(path),
    ], input=der, capture_output=True, check=True, timeout=10)


def _panel_pin():
    fd = os.open(POLICY_KEY, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or
                info.st_mode & 0o077 or info.st_size != 65):
            raise ValueError("untrusted pinned Nexus policy key")
        return os.read(fd, 66).decode("ascii").removesuffix("\n")
    finally:
        os.close(fd)


def _bound_journal(container_name="xmesh-managed-xray"):
    if container_name not in ("xmesh-managed-xray", "xmesh-successor-quarantine"):
        raise ValueError("unknown measured Xray candidate")
    raw = subprocess.check_output([
        "docker", "inspect", "--type", "container", "--format", "{{json .}}",
        container_name,
    ], timeout=15)
    if not 0 < len(raw) <= 128 * 1024:
        raise ValueError("managed Xray inspection unavailable")
    runtime = json.loads(raw, object_pairs_hook=observed.unique_pairs)
    if not isinstance(runtime, dict):
        raise ValueError("managed Xray inspection must be one container object")
    mounts = runtime.get("Mounts")
    if not isinstance(mounts, list):
        raise ValueError("managed Xray mount information unavailable")
    mounts = [m for m in mounts if isinstance(m, dict) and m.get("Destination") == journal.JOURNAL_DEST]
    if len(mounts) != 1 or not isinstance(mounts[0].get("Source"), str):
        raise ValueError("managed Xray has no configured private WAL bind")
    source = mounts[0]["Source"]
    journal._verify_mount(runtime, source)
    return runtime, source


def prepare_genesis(panel, node_id, candidate, challenge):
    """Verify a zero-authority preparation using the installed product and pin."""
    if os.geteuid() != 0 or type(node_id) is not int or node_id <= 0:
        raise ValueError("Xray genesis requires an installed root-owned node")
    if not _hex(candidate, 64) or not _hex(challenge, 64) or candidate == challenge:
        raise ValueError("invalid Xray genesis candidate or challenge")
    os.umask(0o077)
    evidence = [PRODUCT, "wal-evidence", "--panel", panel, "--node-id", str(node_id)]
    with tempfile.TemporaryDirectory(prefix="xmesh-genesis-") as temp:
        root = Path(temp)
        public = root / "nexus.pem"
        _write_public(_panel_pin(), public)
        identity = observed.strict_json(subprocess.check_output(evidence, timeout=20))
        activation = identity["activationReceiptSha256"]
        if identity["nodeId"] != node_id or not _hex(activation, 64):
            raise ValueError("invalid enrolled identity for Xray genesis")
        raw = _post(root, {"operation": "prepare_genesis", "nodeId": node_id,
                           "candidateRuntimeId": candidate, "challenge": challenge})
        if len(raw) > 4096:
            raise ValueError("oversized Xray genesis receipt")
        envelope = observed.strict_json(raw)
        if (not isinstance(envelope, dict) or set(envelope) != {"algorithm", "payload", "signature"}
                or envelope["algorithm"] != "Ed25519" or not _hex(envelope["signature"], 128)):
            raise ValueError("invalid Xray genesis envelope")
        payload = envelope["payload"]
        expected = {
            "schemaVersion": 1, "kind": "xmesh.xray.genesis-prepared",
            "nodeId": node_id, "activationReceiptSha256": activation,
            "candidateRuntimeId": candidate, "challenge": challenge,
            "authorizedBytes": 0, "canStart": False, "canResume": False,
        }
        if (not isinstance(payload, dict) or
                set(payload) != set(expected) | {"preparedAtMs", "validUntilMs"} or
                any(type(payload[k]) is not type(value) or payload[k] != value
                    for k, value in expected.items())):
            raise ValueError("Xray genesis binding or authority mismatch")
        issued, expires = payload["preparedAtMs"], payload["validUntilMs"]
        now = time.time_ns() // 1_000_000
        if (type(issued) is not int or type(expires) is not int or
                not 0 < issued <= now < expires or expires - issued != 120_000):
            raise ValueError("Xray genesis receipt is stale or not yet valid")
        verifier.verify_nexus_signature(GENESIS_DOMAIN, payload, envelope["signature"], public)
        if observed.strict_json(subprocess.check_output(evidence, timeout=20)) != identity:
            raise ValueError("enrolled identity changed while verifying Xray genesis")
        return envelope


def _measure_quarantined_runtime(pins=None, container_name="xmesh-managed-xray"):
    """Measure an actual kernel PID in an isolated Docker candidate; NO authority.

    A caller-provided candidate digest is never proof of an Xray process.
    This observation is only for zero-authority preparation. It does not
    prove final WAL bytes or grant a lease.
    """
    inspect, _ = (_bound_journal() if
                  container_name == "xmesh-managed-xray" else
                  _bound_journal(container_name))
    host = inspect.get("HostConfig")
    state = inspect.get("State")
    network = inspect.get("NetworkSettings")
    if (inspect.get("Name") != "/" + container_name or
            not isinstance(host, dict) or not isinstance(state, dict) or
            not isinstance(network, dict) or state.get("Running") is not True or
            host.get("NetworkMode") != "none" or
            not isinstance(host.get("RestartPolicy"), dict) or
            host["RestartPolicy"].get("Name") != "no" or
            host.get("PortBindings") not in (None, {}) or
            not isinstance(network.get("Networks"), dict) or
            set(network["Networks"]) - {"none"} or
            not isinstance(network.get("Ports"), dict) or
            any(v is not None for v in network["Ports"].values())):
        raise ValueError("measured Xray genesis requires a network-isolated nonrestarting candidate")
    mounts = inspect.get("Mounts")
    # Xray's upstream image declares two ANONYMOUS Docker volumes. Accept
    # only those exact destinations as local-driver generated volumes, never
    # a bind mount or an arbitrary named host path (e.g. Docker socket).
    mounts_by_dest = {
        m.get("Destination"): m for m in mounts
    } if isinstance(mounts, list) and all(isinstance(m, dict) for m in mounts) else {}
    required_mounts = {journal.JOURNAL_DEST, "/etc/xray/config.json"}
    image_volumes = {"/usr/local/etc/xray", "/var/log/xray"}
    mounts_safe = (
        isinstance(mounts, list) and 2 <= len(mounts) <= 4 and
        len(mounts_by_dest) == len(mounts) and
        required_mounts <= mounts_by_dest.keys() and
        set(mounts_by_dest) <= required_mounts | image_volumes and
        all(mounts_by_dest[dest].get("Type") == "bind"
            for dest in required_mounts) and
        all(mounts_by_dest[dest].get("Type") == "volume" and
            mounts_by_dest[dest].get("Driver") == "local" and
            _hex(mounts_by_dest[dest].get("Name"), 64)
            for dest in mounts_by_dest.keys() & image_volumes)
    )
    privileged = host.get("Privileged")
    cap_add = host.get("CapAdd")
    cap_drop = host.get("CapDrop")
    pid_mode = host.get("PidMode")
    ipc_mode = host.get("IpcMode")
    devices = host.get("Devices")
    security = host.get("SecurityOpt")
    if (privileged is not False or
            cap_add not in (None, []) or
            not isinstance(cap_drop, list) or
            "ALL" not in cap_drop or
            pid_mode not in ("", "private") or
            ipc_mode not in ("", "private") or
            devices not in (None, []) or
            host.get("ReadonlyRootfs") is not True or
            not isinstance(security, list) or
            not any(option in ("no-new-privileges", "no-new-privileges:true")
                    for option in security if isinstance(option, str)) or
            not mounts_safe):
        # A privileged Docker container, host PID/IPC namespace, added Linux
        # capabilities or Docker socket mount could escape "network none".
        raise ValueError("measured Xray genesis requires a hardened isolated container")
    pid = state.get("Pid")
    started = state.get("StartedAt")
    cid = inspect.get("Id")
    if (type(pid) is not int or pid <= 0 or
            not _hex(cid, 64) or
            not isinstance(started, str) or "T" not in started or
            (runtime_identity.inspect_managed_xray() if
             container_name == "xmesh-managed-xray" else
             runtime_identity.inspect_managed_xray(container_name))
                != (cid, started, pid)):
        raise ValueError("managed genesis process identity is not independently confirmed")
    identity = runtime_identity.trusted_runtime_identity(pid)
    if pins is not None:
        if mounts_by_dest["/etc/xray/config.json"].get("RW") is not False:
            raise ValueError("pinned Xray configuration requires a read-only bind")
        runtime_identity.verify_quarantined_files(pid, *pins)
        current = (runtime_identity.inspect_managed_xray() if
                   container_name == "xmesh-managed-xray" else
                   runtime_identity.inspect_managed_xray(container_name))
        if (runtime_identity.trusted_runtime_identity(pid) != identity or
                current != (cid, started, pid)):
            raise ValueError("managed Xray changed during executable or configuration verification")
    return (cid, started, pid, identity)


def prepare_measured_genesis(panel, node_id, challenge, pins=None):
    """Bind a zero-authority Nexus receipt to an independently measured PID.

    Never connect the container network or admit user traffic here.
    A future positive admission requires separate reservation-bound evidence.
    """
    if os.geteuid() != 0 or type(node_id) is not int or node_id <= 0:
        raise ValueError("measured Xray genesis requires the installed root agent")
    if not _hex(challenge, 64):
        raise ValueError("measured Xray genesis requires a fresh 256-bit challenge")
    if pins is not None and not all(_hex(value, 64) for value in pins):
        raise ValueError("independent executable and configuration SHA-256 pins are both required")
    measure = _measure_quarantined_runtime
    before = measure() if pins is None else measure(pins)
    receipt = prepare_genesis(panel, node_id, before[3], challenge)
    after = measure() if pins is None else measure(pins)
    if after != before:
        raise ValueError("Xray runtime or isolated Docker network changed during genesis")
    return receipt


def run(action, panel, node_id):
    if os.geteuid() != 0:
        raise ValueError("WAL evidence requires the installed root-owned agent")
    os.umask(0o077)
    runtime, local = _bound_journal()
    with tempfile.TemporaryDirectory(prefix="xmesh-wal-transport-") as temp:
        root = Path(temp)
        evidence = [PRODUCT, "wal-evidence", "--panel", panel, "--node-id", str(node_id)]
        identity = observed.strict_json(subprocess.check_output(evidence, timeout=20))
        if identity.get("nodeId") != node_id:
            raise ValueError("unexpected WAL product identity")
        node_pub, panel_pub = root / "node.pem", root / "nexus.pem"
        _write_public(identity["publicKey"], node_pub)
        _write_public(_panel_pin(), panel_pub)

        def product_sign(_, message):
            payload = root / "witness.json"
            payload.write_bytes(message.removeprefix(producer.DOMAIN))
            reply = observed.strict_json(subprocess.check_output(
                evidence + ["--payload-file", str(payload)], timeout=20))
            if (reply.get("nodeId") != node_id or reply.get("publicKey") != identity["publicKey"]
                    or not _hex(reply.get("signature"), 128)):
                raise ValueError("active product key changed while signing")
            return reply["signature"]

        return sync_checkpoint(action, node_id, runtime, local, node_pub, panel_pub,
                               product_sign, lambda request: _post(root, request))


def sync_checkpoint(action, node_id, runtime, local, node_pub, panel_pub, sign, post):
    def current(expected_receipt=None):
        challenge = secrets.token_hex(32)
        response = post({"operation": "head", "nodeId": node_id, "challenge": challenge})
        doc, index = _unpack_bundle(response)
        proof = _verify_bundle(doc, index, challenge, node_id, node_pub, panel_pub, local,
                               expected_receipt)
        return proof, index

    prior = b""
    if action in {"head", "sync", "charge-sync"}:
        try:
            proof, prior = current()
        except MissingCheckpoint:
            # Only the charge worker can publish its first birth index, and
            # the normal Nexus store and signed readback still verify it.
            if action != "charge-sync":
                raise
            fd = journal._validate_directory(local)
            try:
                if registry._read_inventory(fd) is None:
                    if any(name.startswith("meter-") for name in os.listdir(fd)):
                        raise ValueError("unindexed local Xray WAL")
                    return None
            finally:
                os.close(fd)
        else:
            if action == "head":
                return proof
            fd = journal._validate_directory(local)
            try:
                local_index = registry._read_inventory(fd)
            finally:
                os.close(fd)
            if local_index == prior:
                return proof
            if local_index is None or not local_index.startswith(prior):
                raise ValueError("local WAL index changed after remote verification")

    witness, inventory = producer.produce_witness(
        node_id, runtime, local, None, node_pub, sign=sign)
    if prior and (len(inventory) <= len(prior) or not inventory.startswith(prior)):
        raise ValueError("local WAL snapshot no longer extends the verified remote head")
    stored = observed.strict_json(post({
        "operation": "store", "nodeId": node_id,
        "witness": base64.b64encode(witness).decode("ascii"),
        **_pack_inventory(inventory),
    }))
    if not isinstance(stored, dict) or set(stored) != {"receipt"}:
        raise ValueError("invalid WAL store acknowledgment")
    proof, _ = current(_b64(stored["receipt"], 4096))
    return proof


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("head", "store", "sync", "prepare-genesis", "prepare-measured-genesis"))
    parser.add_argument("--panel", required=True)
    parser.add_argument("--node-id", required=True, type=int)
    parser.add_argument("--candidate-runtime")
    parser.add_argument("--challenge")
    parser.add_argument("--executable-sha256")
    parser.add_argument("--config-sha256")
    args = parser.parse_args()
    try:
        pins = (args.executable_sha256, args.config_sha256)
        if any(value is not None for value in pins) and args.operation != "prepare-measured-genesis":
            parser.error("runtime pins require measured genesis")
        if args.operation == "prepare-genesis":
            result = prepare_genesis(args.panel, args.node_id, args.candidate_runtime, args.challenge)
        elif args.operation == "prepare-measured-genesis":
            if args.candidate_runtime is not None:
                parser.error("measured genesis derives the candidate from the kernel, not the caller")
            result = prepare_measured_genesis(args.panel, args.node_id, args.challenge,
                                              pins if any(value is not None for value in pins) else None)
        else:
            if args.candidate_runtime is not None or args.challenge is not None:
                parser.error("candidate runtime and challenge are only used for genesis preparation")
            result = run(args.operation, args.panel, args.node_id)
        print(json.dumps(result, sort_keys=True))
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        parser.exit(1, f"WAL verification failed: {error}\n")
