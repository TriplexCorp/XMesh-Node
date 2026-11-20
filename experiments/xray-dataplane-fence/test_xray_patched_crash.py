#!/usr/bin/env python3
"""Real pinned-Xray SIGKILL and durable-deny restart acceptance (CI only).

This tests that a committed revocation DENIAL outlives SIGKILL even if the
observed counter was never fsynced. It does NOT prove final byte accounting.
"""
import hashlib
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_quota_v2_xray_user_inbound_drain import (
    EchoHandler, EchoServer, reserve_port, connect_socks, echo_bytes, probe_echo,
)
from test_xray_patched_fence import (
    command, await_socket, request_fence, wait_counter, EMAIL_A, EMAIL_A_USER_KEY, EMAIL_B,
    test_lease_scope,
)


def wait_replaced_socket(path, process):
    deadline=time.monotonic()+15
    while time.monotonic()<deadline:
        if process.poll() is not None:
            raise AssertionError("Xray failed to restore durable fence")
        # A freshly bound Unix socket may reuse the deleted endpoint's
        # inode immediately. A successful connection after the old PID was
        # confirmed dead is the reliable live-listener check, not inode != old.
        if path.exists():
            try:
                with socket.socket(socket.AF_UNIX) as probe:
                    probe.settimeout(.5)
                    probe.connect(str(path))
                return
            except OSError:
                pass
        time.sleep(.1)
    raise AssertionError("SIGKILL-stale local control socket was not safely replaced")


def retry_socks_echo(port,target,expect_allowed,seconds=10):
    deadline=time.monotonic()+seconds
    error=None
    while time.monotonic()<deadline:
        conn=None
        try:
            conn=connect_socks(port,target,"127.0.0.1")
            result=probe_echo(conn)
            if result==expect_allowed:
                return
            error=AssertionError(f"Expected allowed={expect_allowed}, got={result}")
        except (AssertionError,OSError,TimeoutError) as exc:
            error=exc
            if not expect_allowed:
                # Network denial may also manifest as an immediate socket error.
                return
        finally:
            if conn is not None:
                conn.close()
        time.sleep(.2)
    raise AssertionError(f"Unexpected SOCKS connectivity: {error}")


def run(xray):
    assert os.environ.get("GITHUB_ACTIONS")=="true"
    assert os.environ.get("XMESH_DISPOSABLE_XRAY_PATCH_EXPERIMENT")=="1"
    with tempfile.TemporaryDirectory(prefix="xmesh-v2-sigkill-fence-") as tmp:
        root=Path(tmp)
        assert root.stat().st_mode & 0o077 == 0
        control=root/"drain.sock"
        email_hash=hashlib.sha256(EMAIL_A_USER_KEY.encode()).hexdigest()
        marker=root/f"fence-{email_hash}.json"
        observed=root/f"observed-{email_hash}.json"
        revocation=str(uuid.uuid4())
        echo=EchoServer(("127.0.0.1",0),EchoHandler)
        threading.Thread(target=echo.serve_forever,daemon=True).start()
        echo_port=echo.server_address[1]
        vless_port,api_port,socks_a,socks_b,socks_c=(reserve_port() for _ in range(5))
        uuid_a,uuid_b,uuid_c=(str(uuid.uuid4()) for _ in range(3))
        email_c="xmesh-u103--vless-spare"
        server_cfg={
            "log":{"loglevel":"warning"},
            "api":{"tag":"xmesh_stats_api","services":["StatsService"]},
            "stats":{},
            "policy":{"levels":{"0":{"statsUserUplink":True,"statsUserDownlink":True}}},
            "inbounds":[
                {"tag":"vless-share","listen":"127.0.0.1","port":vless_port,
                 "protocol":"vless","settings":{"decryption":"none","clients":[
                     {"id":uuid_a,"email":EMAIL_A,"level":0},
                     {"id":uuid_b,"email":EMAIL_B,"level":0},
                     {"id":uuid_c,"email":email_c,"level":0},
                 ]},"streamSettings":{"network":"tcp","security":"none"}},
                {"tag":"xmesh_stats_in","listen":"127.0.0.1","port":api_port,
                 "protocol":"dokodemo-door","settings":{
                    "address":"127.0.0.1","port":api_port,"network":"tcp"}}
            ],
            "outbounds":[{"tag":"direct","protocol":"freedom","settings":{
                "finalRules":[{"action":"allow","network":"tcp",
                               "ip":["127.0.0.1/32"],"port":str(echo_port)}]}}],
            "routing":{"rules":[{"type":"field","inboundTag":["xmesh_stats_in"],
                                 "outboundTag":"xmesh_stats_api"}]},
        }
        def outbound(name,identity):
            return {"tag":name,"protocol":"vless","settings":{"vnext":[
                {"address":"127.0.0.1","port":vless_port,"users":[
                    {"id":identity,"encryption":"none"}]}]},
                "streamSettings":{"network":"tcp","security":"none"}}
        client_cfg={
            "log":{"loglevel":"warning"},
            "inbounds":[
                {"tag":"socks-a","listen":"127.0.0.1","port":socks_a,
                 "protocol":"socks","settings":{"auth":"noauth","udp":False}},
                {"tag":"socks-b","listen":"127.0.0.1","port":socks_b,
                 "protocol":"socks","settings":{"auth":"noauth","udp":False}},
                {"tag":"socks-c","listen":"127.0.0.1","port":socks_c,
                 "protocol":"socks","settings":{"auth":"noauth","udp":False}},
            ],
            "outbounds":[outbound("user-a",uuid_a),outbound("user-b",uuid_b),
                         outbound("user-c",uuid_c)],
            "routing":{"rules":[
                {"type":"field","inboundTag":["socks-b"],"outboundTag":"user-b"},
                {"type":"field","inboundTag":["socks-c"],"outboundTag":"user-c"}]},
        }
        server_json,client_json=root/"server.json",root/"client.json"
        server_json.write_text(json.dumps(server_cfg))
        client_json.write_text(json.dumps(client_cfg))
        for p in (server_json,client_json):
            command(xray,"run","-test","-config",str(p))
        log_server=(root/"server.log").open("w+")
        log_client=(root/"client.log").open("w+")
        server=server2=server3=server4=server5=server_noncanonical=client=None
        a=b=None
        try:
            server_env=os.environ.copy()
            server_env.update({
                "GITHUB_ACTIONS":"true",
                "XMESH_EXPERIMENTAL_DRAIN":"1",
                "XMESH_EXPERIMENTAL_DRAIN_SOCKET":str(control),
                "XMESH_EXPERIMENTAL_OBSERVED_DIR":str(root),
                "XMESH_EXPERIMENTAL_CRASH_AFTER_DRAIN":"1",
            })
            client_env=os.environ.copy()
            client_env.pop("XMESH_EXPERIMENTAL_DRAIN",None)
            server=subprocess.Popen([xray,"run","-config",str(server_json)],
                                    stdout=log_server,stderr=subprocess.STDOUT,env=server_env)
            await_socket(control,server)
            client=subprocess.Popen([xray,"run","-config",str(client_json)],
                                    stdout=log_client,stderr=subprocess.STDOUT,env=client_env)
            a=connect_socks(socks_a,echo_port,"127.0.0.1")
            b=connect_socks(socks_b,echo_port,"127.0.0.1")
            echo_bytes(a,8192)
            echo_bytes(b,8192)
            assert wait_counter(xray,api_port,EMAIL_A)>0
            assert wait_counter(xray,api_port,EMAIL_B)>0

            try:
                request_fence(control,EMAIL_A,revocation)
                raise AssertionError("Crash injection unexpectedly returned a receipt")
            except (AssertionError,OSError,ValueError) as exc:
                # The process MUST actually die from SIGKILL, not an unrelated
                # timeout or a successful premature response.
                if "unexpectedly returned a receipt" in str(exc):
                    raise
            returncode=server.wait(timeout=10)
            assert returncode == -signal.SIGKILL, f"Expected SIGKILL, got {returncode}"
            assert marker.exists() and marker.stat().st_mode & 0o077 == 0
            exact_committed_marker=marker.read_bytes()
            persisted=json.loads(exact_committed_marker)
            assert persisted["schemaVersion"]==1
            for key,value in test_lease_scope(EMAIL_A,revocation).items():
                assert persisted[key]==value,(key,persisted)
            assert not observed.exists(),"SIGKILL after fence unexpectedly produced observed meter"

            # A and B both spent bytes in this old runtime. A carries the
            # durable revocation while B carries unresolved conservative
            # pretransmit WAL only. Neither may resume with a zeroed meter.
            # The fresh account C is still admitted; this is a scoped denial,
            # not an outage of every Xray user.
            server_env.pop("XMESH_EXPERIMENTAL_CRASH_AFTER_DRAIN")
            server2=subprocess.Popen([xray,"run","-config",str(server_json)],
                                     stdout=log_server,stderr=subprocess.STDOUT,env=server_env)
            wait_replaced_socket(control,server2)
            retry_socks_echo(socks_a,echo_port,False)
            # B was never revoked, but it transmitted bytes in the OLD
            # incarnation. Its reset StatsService is not a valid rollover.
            # Both A and B remain denied until Node has an externally
            # verified conservative carryforward. Untouched C still works.
            retry_socks_echo(socks_b,echo_port,False)
            retry_socks_echo(socks_c,echo_port,True)
            refusal=request_fence(control,EMAIL_A,revocation,expected_status=409)
            assert b"checkpoint" in refusal,refusal
            other=request_fence(control,EMAIL_A,str(uuid.uuid4()),expected_status=409)
            assert b"durable fence" in other,other
            assert json.loads(marker.read_text())==persisted
            assert not observed.exists(),"Restart issued an observed meter without old Xray counters"

            # Corruption/symlink changes to a previously committed marker may
            # not silently cause a new Xray process to reauthorize A.
            second_inode=control.stat().st_ino
            server2.terminate()
            server2.wait(timeout=5)
            assert control.exists() and control.stat().st_ino==second_inode
            marker.write_text("tampered")
            server3=subprocess.Popen([xray,"run","-config",str(server_json)],
                                     stdout=log_server,stderr=subprocess.STDOUT,env=server_env)
            assert server3.wait(timeout=10)!=0,"Xray started despite corrupted durable fence"
            assert not observed.exists()

            # Power loss AFTER fsync(.fence-pending-*) but BEFORE link(final)
            # leaves no complete durable deny. It MUST NOT silently restart.
            # The engine's canonical fsynced bytes must survive exactly:
            # a Python json.dumps rewrite is valid JSON but NOT equivalent
            # to the original immutable on-disk representation.
            noncanonical=json.dumps(persisted).encode()
            assert noncanonical!=exact_committed_marker
            marker.write_bytes(noncanonical)
            server_noncanonical=subprocess.Popen(
                [xray,"run","-config",str(server_json)],
                stdout=log_server,stderr=subprocess.STDOUT,env=server_env)
            assert server_noncanonical.wait(timeout=10)!=0, (
                "Xray accepted noncanonical JSON as a durable revocation")
            assert marker.read_bytes()==noncanonical
            assert not observed.exists()
            # Restore the EXACT bytes previously written and fsynced by
            # the real patched Xray for post-link crash reconciliation.
            marker.write_bytes(exact_committed_marker)
            assert marker.read_bytes()==exact_committed_marker
            pending=root/".fence-pending-simulated-sigkill"
            os.link(marker,pending)
            marker.unlink()
            server4=subprocess.Popen([xray,"run","-config",str(server_json)],
                                     stdout=log_server,stderr=subprocess.STDOUT,env=server_env)
            assert server4.wait(timeout=10)!=0, (
                "Xray admitted users despite an uncommitted pending revocation")
            assert pending.exists() and not marker.exists(), (
                "Recovery silently discarded an uncommitted pending revocation")

            # Simulate publication of that *same* fsynced inode. Recovery must
            # directory-fsync, remove the crash-leftover temp and restore deny.
            os.link(pending,marker)
            server5=subprocess.Popen([xray,"run","-config",str(server_json)],
                                     stdout=log_server,stderr=subprocess.STDOUT,env=server_env)
            wait_replaced_socket(control,server5)
            assert not pending.exists(), "Recovered linked pending file was not reconciled"
            retry_socks_echo(socks_a,echo_port,False)
            # B was never revoked, but it transmitted bytes in the OLD
            # incarnation. Its reset StatsService is not a valid rollover.
            # Both A and B remain denied until Node has an externally
            # verified conservative carryforward. Untouched C still works.
            retry_socks_echo(socks_b,echo_port,False)
            retry_socks_echo(socks_c,echo_port,True)
            assert json.loads(marker.read_text())==persisted
            assert not observed.exists()
            report={
                "test":"sigkill-after-durable-fence-before-meter",
                "committedScopeSurvivedSigkill":True,
                "staleUnixSocketRecovered":True,
                "revokedUserDeniedOnRestart":True,
                "unreconciledUnrevokedUserDeniedOnRestart":True,
                "newUnspentUserAliveOnRestart":True,
                "noMeterOrRefundAfterCrash":True,
                "tamperedDenialPreventsStartup":True,
                "noncanonicalDenialPreventsStartup":True,
                "unpublishedPendingFencePreventsStartup":True,
                "postLinkCrashReconcilesWithoutAdmission":True,
                "finalMeterVerified":False,
                "refundableBytes":0,
            }
            print("EXPERIMENTAL PATCHED XRAY CRASH "+json.dumps(report,sort_keys=True),
                  flush=True)
        except BaseException:
            for stream in (log_server,log_client):
                stream.flush()
                stream.seek(0)
                print("XRAY CRASH TEST DIAGNOSTIC:\n"+stream.read()[-14000:],flush=True)
            raise
        finally:
            for conn in (a,b):
                if conn is not None:
                    conn.close()
            for proc in (server,server2,server3,server4,server5,server_noncanonical,client):
                if proc is not None and proc.poll() is None:
                    proc.terminate()
                    try:proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
            log_server.close()
            log_client.close()
            echo.shutdown()
            echo.server_close()


if __name__=="__main__":
    if len(sys.argv)!=2:
        raise SystemExit("usage: test_xray_patched_crash.py <patched-xray-binary>")
    run(str(Path(sys.argv[1]).resolve()))
