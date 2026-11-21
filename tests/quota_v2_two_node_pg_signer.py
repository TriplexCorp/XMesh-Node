#!/usr/bin/env python3
"""DISPOSABLE only: real Nexus quota SQL -> Ed25519 -> real Xray Go unit binary.

This is NOT the actual XSP/2 endpoint, Node binary identity service or
production Nexus private signing key. The signer and independent-genesis
context are test substitutes. They deliberately live in an isolated CI job
and never install to production. The actual PostgreSQL allocator, immutable
preflight, canonical signature and instrumented Xray WAL are exercised.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import tempfile
import time
import uuid

import psycopg

DOMAIN=b"XMESH_QUOTA_V2_XRAY_CAP_ADMISSION_V1\x00"
EPOCH="11111111-1111-4111-8111-111111111111"
METER={47:"22222222-2222-4222-8222-222222222247",
       48:"22222222-2222-4222-8222-222222222248"}
RID={47:"33333333-3333-4333-8333-333333333347",
     48:"33333333-3333-4333-8333-333333333348"}
USER=101
ZERO="0"*64

def require_disposable():
    if (os.getenv("XMESH_AUDIT_DISPOSABLE")!="1" or
            os.getenv("GITHUB_ACTIONS")!="true" or
            os.getenv("RUNNER_ENVIRONMENT")!="github-hosted" or
            "quota_test" not in os.environ.get("QUOTA_TEST_DSN","")):
        raise SystemExit("only disposable GitHub-hosted PostgreSQL test is permitted")
    return os.environ["QUOTA_TEST_DSN"]

def sign(payload):
    canonical=json.dumps(payload,sort_keys=True,separators=(",",":"),
                         ensure_ascii=False,allow_nan=False).encode()
    with tempfile.TemporaryDirectory(prefix="xmesh-sql-signer-") as temp:
        root=Path(temp)
        key=root/"test-only-ed25519.pem"
        message=root/"message"
        sig=root/"signature"
        subprocess.run(["openssl","genpkey","-algorithm","Ed25519",
                        "-out",str(key)],check=True,capture_output=True)
        message.write_bytes(DOMAIN+canonical)
        subprocess.run(["openssl","pkeyutl","-sign","-rawin","-inkey",str(key),
                        "-in",str(message),"-out",str(sig)],check=True,capture_output=True)
        pub=subprocess.check_output(
            ["openssl","pkey","-in",str(key),"-pubout","-outform","DER"])
        assert len(pub)==44 and len(sig.read_bytes())==64
        envelope={"algorithm":"Ed25519","payload":payload,
                  "signature":sig.read_bytes().hex()}
        signed=json.dumps(envelope,sort_keys=True,separators=(",",":"),
                          ensure_ascii=False,allow_nan=False)+"\n"
        return pub[-32:].hex(),signed

def init_db(dsn,nexus):
    migrations=[
        "0125_quota_v2_reservations.sql",
        "0126_quota_v2_revocation_requests.sql",
        "0127_quota_v2_revocation_freeze.sql",
        "0128_quota_v2_conservative_burn.sql",
        "0137_quota_v2_xray_genesis.sql",
        "0138_quota_v2_runtime_preflight_ledger.sql",
    ]
    with psycopg.connect(dsn) as conn:
        # Only prerequisites, not a stubbed quota allocator. All actual
        # reserve/burn/preflight logic comes from the real Nexus migrations.
        conn.execute("""CREATE TABLE node_xsp_product_nodes (
            node_id BIGINT PRIMARY KEY, state TEXT NOT NULL, receipt_sha256 BYTEA)""")
        for name in migrations:
            conn.execute((nexus/"backend"/"migrations"/name).read_text())
        conn.execute(
            "INSERT INTO quota_v2_accounts(user_id,epoch,limit_bytes) "
            "VALUES(%s,%s,100)",(USER,EPOCH))
    print("PASS: real Nexus reservation and runtime-preflight SQL loaded",flush=True)

def issue(dsn,node,runtime,policy_sha):
    if node not in (47,48) or len(runtime)!=64 or len(policy_sha)!=64 or any(
            c not in "0123456789abcdef" for c in runtime+policy_sha):
        raise ValueError("invalid disposable Node process measurement")
    activation=("c" if node==47 else "d")*64
    target=70 if node==47 else 50
    with psycopg.connect(dsn) as conn:
        conn.execute("SET LOCAL synchronous_commit TO on")
        # Same account row lock, same PostgreSQL reserve function as actual
        # Nexus policy issuance. With Node 47 first, Node 48 can only hold 30.
        lease=conn.execute(
            "SELECT revision,ceiling_bytes,acknowledged_bytes "
            "FROM quota_v2_reserve(%s,%s,%s,%s,%s,%s,0,"
            "NOW()+INTERVAL '1 hour')",
            (USER,EPOCH,node,METER[node],RID[node],target)).fetchone()
        revision,ceiling,ack=lease
        if ceiling<1 or ceiling>target or ack!=0:
            raise ValueError("real SQL allocator issued invalid fresh grant")
        # CI-only replacement for separately authenticated Agent echo. It
        # MUST NOT be copied to a live Nexus handler.
        conn.execute(
            "UPDATE quota_v2_reservations SET node_confirmed=TRUE "
            "WHERE user_id=%s AND epoch=%s AND node_id=%s",
            (USER,EPOCH,node))
        conn.execute(
            "INSERT INTO quota_v2_xray_genesis("
            "node_id,first_activation_sha256,runtime_id,challenge,"
            "prepared_ms,receipt_signature) VALUES("
            "%s,%s,%s,%s,(EXTRACT(EPOCH FROM clock_timestamp())*1000)::bigint,%s)",
            (node,activation,runtime,"e"*64,"0"*128))
        nonce=secrets.token_hex(32)
        p=conn.execute(
            "SELECT account_limit_bytes,account_floor_bytes,"
            "all_node_held_bytes,lease_ceiling_bytes,lease_acknowledged_bytes "
            "FROM quota_v2_record_runtime_admission_preflight("
            "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (USER,EPOCH,node,METER[node],RID[node],revision,nonce,
             runtime,"f"*64,os.getpid(),policy_sha,activation,0)).fetchone()
        if p[0]!=100 or p[1]!=0 or p[2]>100 or p[3]!=ceiling or p[4]!=0:
            raise ValueError("SQL preflight did not match serial allocation")
        c=conn.execute("SELECT COUNT(*) FROM quota_v2_runtime_admission_preflights "
                       "WHERE node_id=%s AND user_id=%s",
                       (node,USER)).fetchone()[0]
        if c!=1:
            raise ValueError("signed grant snapshot was not recorded exactly once")
        until=conn.execute(
            "SELECT (EXTRACT(EPOCH FROM valid_until)*1000)::bigint "
            "FROM quota_v2_reservations WHERE user_id=%s AND node_id=%s",
            (USER,node)).fetchone()[0]
        # COMMIT, including fsync, BEFORE issuing a signed grant.
    now=int(time.time()*1000)
    policy={
        "schemaVersion":1,"kind":"xmesh.quota-v2.xray-cap-admission",
        "nodeId":node,"userId":USER,"activationReceiptSha256":activation,
        "runtimeId":runtime,"policySha256":policy_sha,
        "accountEpoch":EPOCH,"meterEpoch":METER[node],
        "reservationId":RID[node],"reservationRevision":revision,
        "nonce":nonce,"inventoryTailDigest":ZERO,
        "witnessedWalBytes":0,"witnessedCdnBytes":0,
        "sharedCeilingBytes":ceiling,"nodeCeilingBytes":ceiling,
        "cdnCeilingBytes":min(20,ceiling),
        "aliasScopes":[
            {"email":"xmesh-u101--vless-cdn","class":"cdn"},
            {"email":"xmesh-u101--vless-main","class":"main"}],
        "issuedAtMs":now-1000,"installBeforeMs":now+60000,
        "validUntilMs":min(until,now+3600000),
        "canSpend":True,"canStart":False,"canResume":False,
        "finalMeterVerified":False,"refundableBytes":0,
    }
    pub,envelope=sign(policy)
    print(json.dumps({
        "nodeId":node,"ceiling":ceiling,"signedEnvelope":envelope,
        "publicKeyHex":pub,"phase":"sql-committed-signed-disposable",
    },separators=(",",":")),flush=True)

def assert_complete(dsn,root):
    reports=[]
    for node in (47,48):
        path=root/f"node-{node}.json"
        reports.append(json.loads(path.read_text()))
    with psycopg.connect(dsn) as conn:
        rows=conn.execute(
            "SELECT node_id,ceiling_bytes,acknowledged_bytes "
            "FROM quota_v2_reservations WHERE user_id=%s ORDER BY node_id",
            (USER,)).fetchall()
        preflights=conn.execute(
            "SELECT node_id,authorized_bytes,can_start,can_resume,"
            "final_meter_verified,refundable_bytes "
            "FROM quota_v2_runtime_admission_preflights "
            "WHERE user_id=%s ORDER BY node_id",(USER,)).fetchall()
        account=conn.execute(
            "SELECT settled_bytes,observed_floor_bytes,limit_bytes "
            "FROM quota_v2_accounts WHERE user_id=%s AND epoch=%s",
            (USER,EPOCH)).fetchone()
    if len(rows)!=2 or [row[0] for row in rows]!=[47,48]:
        raise AssertionError("lost a Node's independent reservation")
    if sum(row[1] for row in rows)!=100 or any(row[2] for row in rows):
        raise AssertionError("global capacity was overissued or falsely settled")
    if [row[1] for row in rows]!=[70,30]:
        raise AssertionError("two Node grants did not serialize as 70+30")
    if len(preflights)!=2 or any(x[1:]!=(0,False,False,False,0) for x in preflights):
        raise AssertionError("snapshot incorrectly became traffic authority")
    if account!=(0,0,100):
        raise AssertionError("in-memory Xray spend was mistaken for server settlement")
    for report,row in zip(reports,rows):
        if (report.get("nodeId"),report.get("grantBytes"),report.get("walBytes"),
            report.get("rawBytes"))!=(row[0],row[1],row[1],row[1]):
            raise AssertionError("instrumented Xray StatsService/WAL diverged from real SQL grant")
        if not isinstance(report.get("runtimeId"),str) or len(report["runtimeId"])!=64:
            raise AssertionError("missing process-bound Xray identity")
    if reports[0]["runtimeId"]==reports[1]["runtimeId"]:
        raise AssertionError("both isolated Xray tests reused one PID identity")
    print("PASS: two measured Xray processes consumed exactly 70+30 bytes "
          "from one serialized PostgreSQL 100-byte budget, with NO refunds/settlement",
          flush=True)

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("action",choices=("init","issue","assert"))
    parser.add_argument("--nexus-source",type=Path)
    parser.add_argument("--node",type=int)
    parser.add_argument("--runtime")
    parser.add_argument("--policy-sha")
    parser.add_argument("--reports",type=Path)
    args=parser.parse_args()
    dsn=require_disposable()
    if args.action=="init":
        if args.nexus_source is None:
            raise ValueError("pinned Nexus SQL checkout required")
        init_db(dsn,args.nexus_source)
    elif args.action=="issue":
        issue(dsn,args.node,args.runtime,args.policy_sha)
    else:
        assert_complete(dsn,args.reports)

if __name__=="__main__":
    main()
