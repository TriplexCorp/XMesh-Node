#!/usr/bin/env python3
"""DISPOSABLE only: real Nexus quota SQL -> Ed25519 -> real Xray Go unit binary.

This is NOT the actual XSP/2 endpoint, Node binary identity service or
production Nexus private signing key. The CI key and independent-genesis
context are test substitutes. They deliberately live in an isolated CI job
and never install to production. The actual PostgreSQL allocator, immutable
preflight, canonical signature and instrumented Xray WAL are exercised.
"""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import uuid

import psycopg

DOMAIN=b"XMESH_QUOTA_V2_XRAY_CAP_ADMISSION_V1\x00"
EPOCH="11111111-1111-4111-8111-111111111111"
METER={47:"22222222-2222-4222-8222-222222222247",
       48:"22222222-2222-4222-8222-222222222248"}
RID={47:"33333333-3333-4333-8333-333333333347",
     48:"33333333-3333-4333-8333-333333333348"}
USER=101

def require_disposable():
    if (os.getenv("XMESH_AUDIT_DISPOSABLE")!="1" or
            os.getenv("GITHUB_ACTIONS")!="true" or
            os.getenv("RUNNER_ENVIRONMENT")!="github-hosted" or
            "quota_test" not in os.environ.get("QUOTA_TEST_DSN","")):
        raise SystemExit("only disposable GitHub-hosted PostgreSQL test is permitted")
    return os.environ["QUOTA_TEST_DSN"]

def init_db(dsn,nexus):
    migrations=[
        "0125_quota_v2_reservations.sql",
        "0126_quota_v2_revocation_requests.sql",
        "0127_quota_v2_revocation_freeze.sql",
        "0128_quota_v2_conservative_burn.sql",
        "0137_quota_v2_xray_genesis.sql",
        "0138_quota_v2_runtime_preflight_ledger.sql",
        "0139_quota_v2_signed_first_cap_outbox.sql",
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
            "VALUES(%s,%s,1000)",(USER,EPOCH))
        for node in (47,48):
            activation=("c" if node==47 else "d")*64
            conn.execute(
                "INSERT INTO node_xsp_product_nodes(node_id,state,receipt_sha256) "
                "VALUES(%s,'active',decode(%s,'hex'))",(node,activation))
    print("PASS: real Nexus reservation and runtime-preflight SQL loaded",flush=True)

def issue(dsn,node,runtime,policy_sha,xray_pid):
    if node not in (47,48) or not isinstance(xray_pid,int) or xray_pid<=0 or len(runtime)!=64 or len(policy_sha)!=64 or any(
            c not in "0123456789abcdef" for c in runtime+policy_sha):
        raise ValueError("invalid disposable Node process measurement")
    activation=("c" if node==47 else "d")*64
    target=700 if node==47 else 500
    with psycopg.connect(dsn) as conn:
        conn.execute("SET LOCAL synchronous_commit TO on")
        # Same account row lock, same PostgreSQL reserve function as actual
        # Nexus policy issuance. With Node 47 first, Node 48 can only hold 300.
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
             runtime,"f"*64,xray_pid,policy_sha,activation,0)).fetchone()
        if p[0]!=1000 or p[1]!=0 or p[2]>1000 or p[3]!=ceiling or p[4]!=0:
            raise ValueError("SQL preflight did not match serial allocation")
        c=conn.execute("SELECT COUNT(*) FROM quota_v2_runtime_admission_preflights "
                       "WHERE node_id=%s AND user_id=%s",
                       (node,USER)).fetchone()[0]
        if c!=1:
            raise ValueError("signed grant snapshot was not recorded exactly once")
        # COMMIT synchronously BEFORE the actual Nexus signer reads the
        # immutable preflight in a NEW database transaction.
    binary=os.environ.get("XMESH_CI_NEXUS_SIGNER","")
    if not binary or not Path(binary).is_file():
        raise ValueError("actual Nexus PolicySigner binary missing from disposable CI")
    result=subprocess.run(
        [binary,str(node),nonce,str(xray_pid),policy_sha],
        capture_output=True,text=True,check=True,timeout=15)
    signed=json.loads(result.stdout)
    if (signed.get("nodeId")!=node or signed.get("ceiling")!=ceiling or
            signed.get("phase")!="sql-committed-nexus-policy-signer-disposable" or
            not isinstance(signed.get("publicKeyHex"),str) or
            len(signed["publicKeyHex"])!=64 or
            not isinstance(signed.get("signedEnvelope"),str) or
            not signed["signedEnvelope"].endswith("\n")):
        raise ValueError("real Nexus Rust policy signer returned invalid scope")
    with psycopg.connect(dsn) as conn:
        row=conn.execute(
            "SELECT signed_envelope,signer_public_key,grant_bytes,"
            "can_start,can_resume,refundable_bytes "
            "FROM quota_v2_signed_first_cap_outbox "
            "WHERE node_id=%s AND request_challenge=%s",
            (node,nonce)).fetchone()
        if (row is None or row[0]!=signed["signedEnvelope"].encode("utf-8")
                or row[1]!=signed["publicKeyHex"] or row[2]!=ceiling
                or row[3:]!=(False,False,0)):
            raise AssertionError("first positive grant is not durably and "
                                 "exactly recorded in PostgreSQL")
    again=subprocess.run(
        [binary,str(node),nonce,str(xray_pid),policy_sha],
        capture_output=True,text=True,check=True,timeout=15)
    retried=json.loads(again.stdout)
    if retried!=signed:
        raise AssertionError("lost-response retry changed Ed25519 grant bytes "
                             "or silently renewed the same reserved capacity")
    print(json.dumps(signed,separators=(",",":")),flush=True)

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
        outbox=conn.execute(
            "SELECT node_id,grant_bytes,can_start,can_resume,refundable_bytes "
            "FROM quota_v2_signed_first_cap_outbox "
            "WHERE user_id=%s ORDER BY node_id",(USER,)).fetchall()
    if len(rows)!=2 or [row[0] for row in rows]!=[47,48]:
        raise AssertionError("lost a Node's independent reservation")
    if sum(row[1] for row in rows)!=1000 or any(row[2] for row in rows):
        raise AssertionError("global capacity was overissued or falsely settled")
    if [row[1] for row in rows]!=[700,300]:
        raise AssertionError("two Node grants did not serialize as 700+300")
    if len(preflights)!=2 or any(x[1:]!=(0,False,False,False,0) for x in preflights):
        raise AssertionError("snapshot incorrectly became traffic authority")
    if account!=(0,0,1000):
        raise AssertionError("in-memory Xray spend was mistaken for server settlement")
    if len(outbox)!=2 or [x[0:2] for x in outbox]!=[(47,700),(48,300)] or any(
            x[2:]!=(False,False,0) for x in outbox):
        raise AssertionError("Nexus signed outbox reissued, refunded or started Xray")
    for report,row in zip(reports,rows):
        if (report.get("nodeId"),report.get("grantBytes"),report.get("walBytes"),
            report.get("rawBytes"))!=(row[0],row[1],row[1],row[1]):
            raise AssertionError("instrumented Xray StatsService/WAL diverged from real SQL grant")
        if not isinstance(report.get("runtimeId"),str) or len(report["runtimeId"])!=64:
            raise AssertionError("missing process-bound Xray identity")
    if reports[0]["runtimeId"]==reports[1]["runtimeId"]:
        raise AssertionError("both isolated Xray tests reused one PID identity")
    print("PASS: two measured Xray processes consumed exactly 700+300 bytes "
          "from one serialized PostgreSQL 1000-byte budget, with NO refunds/settlement",
          flush=True)

def replay_after_database_restart(dsn,persist_root):
    binary=os.environ.get("XMESH_CI_NEXUS_SIGNER","")
    if not binary or not Path(binary).is_file():
        raise AssertionError("missing actual Nexus Rust issuer on SQL crash replay")
    for node in (47,48):
        with psycopg.connect(dsn) as c:
            row=c.execute(
                "SELECT request_challenge,reported_pid,reported_policy_sha256 "
                "FROM quota_v2_runtime_admission_preflights "
                "WHERE user_id=%s AND node_id=%s",
                (USER,node)).fetchone()
            original=c.execute(
                "SELECT signed_envelope,signer_public_key,grant_bytes "
                "FROM quota_v2_signed_first_cap_outbox "
                "WHERE user_id=%s AND node_id=%s",
                (USER,node)).fetchone()
        if row is None or original is None:
            raise AssertionError("original signed reservation vanished on SQL restart")
        nonce,pid,policy=row
        command=[binary,str(node),nonce,str(pid),policy]
        result=subprocess.run(command,capture_output=True,text=True,
                              check=False,timeout=15)
        if result.returncode!=0:
            raise AssertionError("native Nexus signed outbox replay refused "
                                 "after PostgreSQL restart: "+
                                 result.stderr[-2500:]+result.stdout[-500:])
        resumed=json.loads(result.stdout)
        prior=(persist_root/f"node-{node}"/"positive-cap-u101.json").read_bytes()
        if (resumed.get("signedEnvelope","").encode()!=original[0]
                or prior!=original[0]
                or resumed.get("publicKeyHex")!=original[1]
                or resumed.get("ceiling")!=original[2]):
            raise AssertionError("PostgreSQL restart or lost signed reply "
                                 "renewed bytes, identity or lease expiry")
        print(f"PASS: Node {node} signer returned identical original Ed25519 "
              "bytes after PostgreSQL container restart",flush=True)

    # A stolen/replaced local signer key must NOT sign an alternate
    # first-genesis cap for the same outstanding SQL lease. Use only
    # disposable CI raw-key bytes and immediately restore the exact key.
    private=Path(os.environ["XMESH_CI_CAP_POLICY_KEY"])
    original_key=private.read_bytes()
    if len(original_key)!=32:
        raise AssertionError("unsafe test signing key format")
    with psycopg.connect(dsn) as c:
        nonce,pid,policy=c.execute(
            "SELECT request_challenge,reported_pid,reported_policy_sha256 "
            "FROM quota_v2_runtime_admission_preflights "
            "WHERE user_id=%s AND node_id=47",(USER,)).fetchone()
    try:
        private.write_bytes(secrets.token_bytes(32))
        attempted=subprocess.run(
            [binary,"47",nonce,str(pid),policy],
            capture_output=True,text=True,timeout=15)
        if attempted.returncode==0:
            raise AssertionError("new policy key replaced original signed "
                                 "lease identity after SQL restart")
    finally:
        private.write_bytes(original_key)
    with psycopg.connect(dsn) as c:
        saved=c.execute(
            "SELECT signed_envelope FROM quota_v2_signed_first_cap_outbox "
            "WHERE user_id=%s AND node_id=47",(USER,)).fetchone()[0]
    assert saved==(persist_root/"node-47"/"positive-cap-u101.json").read_bytes()
    print("PASS: signer rotation refused, original signed grant and WAL intact",flush=True)


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("action",choices=("init","issue","assert","replay"))
    parser.add_argument("--nexus-source",type=Path)
    parser.add_argument("--node",type=int)
    parser.add_argument("--runtime")
    parser.add_argument("--policy-sha")
    parser.add_argument("--xray-pid",type=int)
    parser.add_argument("--reports",type=Path)
    parser.add_argument("--persist",type=Path)
    args=parser.parse_args()
    dsn=require_disposable()
    if args.action=="init":
        if args.nexus_source is None:
            raise ValueError("pinned Nexus SQL checkout required")
        init_db(dsn,args.nexus_source)
    elif args.action=="issue":
        issue(dsn,args.node,args.runtime,args.policy_sha,args.xray_pid)
    elif args.action=="replay":
        if args.persist is None:
            raise ValueError("persisted first-process WAL directory required")
        replay_after_database_restart(dsn,args.persist)
    else:
        assert_complete(dsn,args.reports)

if __name__=="__main__":
    main()
