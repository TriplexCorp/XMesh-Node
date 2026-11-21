#!/usr/bin/env python3
"""Strict-PQ first-Genesis policy handoff; ZERO spending authority.

Only an opt-in, isolated, first-ever Xray candidate can use this helper.
No active Xray config is applied and no VLESS ingress is enabled. The
positive Nexus XSP/2 signed-cap issuer and process-bound installer are
separate, still-unimplemented requirements.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess
import tempfile
import time

import wal_transport

PRODUCT = "/usr/local/bin/xmesh-agent-xspv2-product"
PATH = "/api/v1/node/desired-config"
PIN_PATH = "/api/v1/node/quota-v2/policy-pin"
MAX_REPLY = 262144
_HEX64 = re.compile(r"^[0-9a-f]{64}$")

GUARD_CANDIDATES = (
    Path(__file__).resolve().parents[2] / "deploy" / "xmesh-policy-guard-base.py",
    Path("/usr/local/libexec/xmesh-policy-guard-base.py"),
)


def _guard():
    entry = next((p for p in GUARD_CANDIDATES if p.is_file()), None)
    if entry is None:
        raise ValueError("installed policy signature verifier unavailable")
    spec = importlib.util.spec_from_file_location("xmesh_quarantine_policy_guard", entry)
    if spec is None or spec.loader is None:
        raise ValueError("policy verifier cannot be imported")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _hex(value):
    return isinstance(value, str) and _HEX64.fullmatch(value) is not None


def validate_response(raw, node_id, prepared, pinned, now_ms=None):
    """Validate one original, Ed25519-signed, explicit no-spend response.

    Strict JSON rejects repeated keys and unexpected authority tokens. No
    caller-provided public key or claimed Xray PID is trusted.
    """
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_REPLY:
        raise ValueError("oversized quarantine reply")
    guard = _guard()
    doc = wal_transport.observed.strict_json(raw)
    expected_fields = {
        "status","nodeId","profileId","listen","port","revision","config",
        "policy","policySignature","policyPublicKey","policySha256",
        "publicIngressAllowed","canStart","canResume","authorizedBytes",
    }
    if not isinstance(doc, dict) or set(doc) != expected_fields:
        raise ValueError("unrecognized quarantine response shape")
    if (doc["status"] != "quarantined"
        or type(doc["nodeId"]) is not int or doc["nodeId"] != node_id
        or doc["listen"] != "127.0.0.1"
        or doc["publicIngressAllowed"] is not False
        or doc["canStart"] is not False
        or doc["canResume"] is not False
        or type(doc["authorizedBytes"]) is not int or doc["authorizedBytes"] != 0
        or doc["policyPublicKey"] != pinned or not _hex(pinned)):
        raise ValueError("quarantine cannot authorize public ingress")
    policy = doc["policy"]
    payload = prepared["payload"]
    expected_genesis = {
        "mode": "quarantined",
        "runtimeId": payload["candidateRuntimeId"],
        "challenge": payload["challenge"],
        "firstActivationReceiptSha256": payload["activationReceiptSha256"],
        "authorizedBytes": 0, "canStart": False, "canResume": False,
        "refundableBytes": 0,
    }
    if (not isinstance(policy, dict)
        or policy.get("version") != 1
        or policy.get("kind") != "xmesh.quota-v2.genesis-quarantine-policy"
        or policy.get("nodeId") != node_id
        or policy.get("quotaV2Genesis") != expected_genesis
        or type(policy.get("issuedAtMs")) is not int
        or policy["issuedAtMs"] != payload["preparedAtMs"]
        or type(policy.get("validUntilMs")) is not int
        or policy["validUntilMs"] != payload["validUntilMs"]
        or not isinstance(policy.get("users"), list)
        or any(not isinstance(u,dict) or type(u.get("offlineBudgetBytes")) is not int
               or u["offlineBudgetBytes"] != 0 or u.get("onHold") is not True
               for u in policy["users"])):
        raise ValueError("signed policy deviates from zero-spend Genesis")
    now = time.time_ns() // 1_000_000 if now_ms is None else now_ms
    if type(now) is not int or now < policy["issuedAtMs"] or now >= policy["validUntilMs"]:
        raise ValueError("quarantine expired or clock rolled backward")
    if (not isinstance(doc["config"], dict)
        or not _hex(doc["revision"])
        or policy.get("configSha256") != doc["revision"]
        or hashlib.sha256(guard.canonical(doc["config"])).hexdigest() != doc["revision"]
        or not _hex(doc["policySha256"])
        or hashlib.sha256(guard.canonical(policy)).hexdigest() != doc["policySha256"]):
        raise ValueError("policy or profile hash does not match signed original")
    # Only the pre-pinned, root-owned Nexus public key is accepted.
    guard.check_signature(policy, doc["policySignature"], pinned)
    return doc


def _locked_private_state(directory):
    if os.geteuid() != 0:
        raise ValueError("quarantine handoff requires root-owned installed Agent")
    path = Path(directory)
    if not path.is_absolute() or path.is_symlink():
        raise ValueError("quarantine directory must be an absolute private path")
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
        or info.st_mode & 0o077):
        raise ValueError("quarantine state directory must be root-owned 0700")
    fd = os.open(path, os.O_DIRECTORY | os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        lock = os.open("genesis-quarantine.lock",
            os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600,
            dir_fd=fd)
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o077:
            raise ValueError("unsafe quarantine lock")
        fcntl.flock(lock, fcntl.LOCK_EX)
        return fd,lock
    except Exception:
        os.close(fd)
        raise


def _durable_store(state_fd, data):
    target="genesis-quarantine-envelope.json"
    raw=json.dumps(data,sort_keys=True,separators=(",",":"),
                   ensure_ascii=False,allow_nan=False).encode("utf-8")
    if not 0 < len(raw) <= MAX_REPLY + 4096:
        raise ValueError("oversized staging evidence")
    try:
        old=os.open(target,os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=state_fd)
    except FileNotFoundError:
        old=None
    if old is not None:
        try:
            st=os.fstat(old)
            if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode&0o077:
                raise ValueError("unsafe existing quarantine evidence")
            existing=os.read(old,MAX_REPLY+4097)
            if existing!=raw:
                raise ValueError("conflicting Genesis quarantine: cannot overwrite")
            return
        finally:
            os.close(old)
    # O_EXCL prevents temporary path races; private parent, no symlinks.
    tmp=".genesis-quarantine-"+secrets.token_hex(12)
    output=os.open(tmp,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,
                   0o600,dir_fd=state_fd)
    try:
        with os.fdopen(output,"wb",closefd=True) as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.rename(tmp,target,src_dir_fd=state_fd,dst_dir_fd=state_fd)
        os.fsync(state_fd)
    finally:
        try:os.unlink(tmp,dir_fd=state_fd)
        except FileNotFoundError:pass


def _post_quarantined_desired(request, state, path=PATH):
    """The installed product client owns strict-PQ transport and enrollment.

    No curl, raw HTTP, Ed25519 legacy fallback, insecure TLS or alternate host
    is reachable from this operation.
    """
    if path not in (PATH,PIN_PATH):
        raise ValueError("unregistered XSP/2 product operation")
    with tempfile.TemporaryDirectory(prefix="xmesh-quarantine-",dir=state) as root:
        root=Path(root)
        body,reply,status=(root/n for n in ("request.json","response.json","status.txt"))
        body.write_bytes(wal_transport.observed.canonical(request))
        subprocess.run([PRODUCT,"request","--path",path,
            "--body-file",str(body),"--output-file",str(reply),
            "--status-file",str(status)],timeout=30,check=True)
        if status.read_text(encoding="ascii").strip()!="200":
            raise ValueError("Nexus did not accept strict quarantined desired policy")
        with reply.open("rb") as stream:
            return stream.read(MAX_REPLY+1)


def _enrolled_activation(panel,node):
    # This installed product client checks strict TLS, original signed
    # enrollment, pin/key epoch and exact Node ID; no raw network fetch.
    raw=subprocess.check_output([
        PRODUCT,"wal-evidence","--panel",panel,"--node-id",str(node),
    ],timeout=20)
    if len(raw)>4096:
        raise ValueError("oversized strict product activation evidence")
    identity=wal_transport.observed.strict_json(raw)
    if (not isinstance(identity,dict)
        or type(identity.get("nodeId")) is not int or identity["nodeId"]!=node
        or not _hex(identity.get("activationReceiptSha256"))):
        raise ValueError("no independently authenticated strict product activation")
    return identity


def _pinned_policy_before_genesis(panel,node,state,state_fd):
    """Bootstrap the policy signer BEFORE ordinary desired-config can run.

    The bootstrap is trusted ONLY because the root-installed owner-enrolled
    product verifies the hybrid TLS/XSP2 response. Never TOFU via plain
    HTTPS, an unauthenticated JSON header, a fresh policyPublicKey in a
    normal desired-config reply, or a caller-supplied key.
    """
    pin=Path(wal_transport.POLICY_KEY)
    if not pin.is_absolute() or pin.parent.resolve()!=Path(state).resolve():
        raise ValueError("policy signing key must be bound to the existing root-only state")
    try:
        return wal_transport._panel_pin()
    except FileNotFoundError:
        pass
    original=_enrolled_activation(panel,node)
    raw=_post_quarantined_desired({
        "node_id":node,"operation":"discover_policy_signer",
    },state,PIN_PATH)
    if not isinstance(raw,bytes) or not 0<len(raw)<=4096:
        raise ValueError("oversized strict-PQ policy signer identity")
    result=wal_transport.observed.strict_json(raw)
    if (not isinstance(result,dict)
        or set(result)!={"status","nodeId","activationReceiptSha256",
                          "policyPublicKey","authorizedBytes","canStart",
                          "canResume","refundableBytes"}
        or result["status"]!="quarantine_pin_only"
        or type(result["nodeId"]) is not int or result["nodeId"]!=node
        or result["activationReceiptSha256"]!=original["activationReceiptSha256"]
        or not _hex(result["policyPublicKey"])
        or type(result["authorizedBytes"]) is not int or result["authorizedBytes"]!=0
        or result["canStart"] is not False or result["canResume"] is not False
        or type(result["refundableBytes"]) is not int or result["refundableBytes"]!=0):
        raise ValueError("Nexus key discovery is not an authenticated zero-authority reply")
    if _enrolled_activation(panel,node)!=original:
        raise ValueError("enrolled product identity changed during signer bootstrap")
    key=result["policyPublicKey"]
    # Only create the ABSENT original pin, never rewrite one. If another
    # root process already pinned it concurrently, it must be identical.
    try:
        fd=os.open(pin.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|
            os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=state_fd)
    except FileExistsError:
        if wal_transport._panel_pin()!=key:
            raise ValueError("conflicting original Nexus signing identity")
        return key
    with os.fdopen(fd,"wb") as stream:
        stream.write((key+"\\n").encode("ascii"))
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(state_fd)
    if wal_transport._panel_pin()!=key:
        raise ValueError("durable Nexus signing key pin verification failed")
    return key


def request_quarantine(panel,node_id,state):
    """Separate opt-in root-Agent operation. Never launches or activates Xray."""
    if not isinstance(panel,str) or not panel.startswith("https://") or node_id<=0:
        raise ValueError("invalid strict product Node origin")
    state_fd,lock=_locked_private_state(state)
    try:
        pinned=_pinned_policy_before_genesis(panel,node_id,state,state_fd)
        challenge=secrets.token_hex(32)
        # The EXACT Linux PID/Docker isolation is measured both before and
        # after the real XSP/2 Genesis preparation.
        before=wal_transport._measure_quarantined_runtime()
        prepared=wal_transport.prepare_measured_genesis(panel,node_id,challenge)
        if not isinstance(prepared,dict) or not isinstance(prepared.get("payload"),dict):
            raise ValueError("untrusted preparatory Genesis receipt")
        payload=prepared["payload"]
        if (payload.get("challenge") != challenge
            or payload.get("candidateRuntimeId") != before[3]
            or payload.get("nodeId") != node_id):
            raise ValueError("measured Xray mismatches signed Genesis")
        request={
            "node_id":node_id,"quotaProtocolVersion":2,
            "quotaGenesisQuarantine":True,
            "quotaGenesisRuntimeId":payload["candidateRuntimeId"],
            "quotaGenesisChallenge":challenge,
        }
        raw=_post_quarantined_desired(request,state)
        doc=validate_response(raw,node_id,prepared,pinned)
        after=wal_transport._measure_quarantined_runtime()
        if before!=after:
            raise ValueError("kernel Xray PID, configuration or isolation changed")
        # This is evidence only: no Docker command, no activation, no cap install.
        _durable_store(state_fd,{"prepared":prepared,"reply":doc})
        return {"status":"quarantined","nodeId":node_id,
                "policySha256":doc["policySha256"],
                "authorizedBytes":0,"canStart":False}
    finally:
        os.close(lock)
        os.close(state_fd)


if __name__=="__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel",required=True)
    parser.add_argument("--node-id",type=int,required=True)
    parser.add_argument("--state",required=True)
    args=parser.parse_args()
    try:
        # NEVER output config, secrets, signed envelope or activation token.
        print(json.dumps(request_quarantine(args.panel,args.node_id,args.state),
                         sort_keys=True,separators=(",",":")))
    except (OSError,ValueError,TypeError,KeyError,subprocess.SubprocessError) as error:
        parser.exit(1,"Quota-V2 Genesis quarantine denied: "+str(error)+"\n")
