#!/usr/bin/env python3
"""Real-process CI acceptance of a DISPOSABLE PATCHED Xray, no refund proof.

Two users share a real VLESS inbound. A root-private Unix control socket
fences one authenticated user, closes existing transport sessions, and leaves
the other user's streams running. This is experimental traffic cessation,
NOT a durable final byte accounting/cryptographic receipt.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from test_quota_v2_xray_user_inbound_drain import (  # noqa: E402
    EchoHandler, EchoServer, reserve_port, connect_socks, echo_bytes,
    probe_echo,
)

EMAIL_A = "xmesh-u101--vless-share"
EMAIL_A_CDN = "xmesh-u101--vless-cdn"
EMAIL_A_UNSAFE = "xmesh-u101--vless-unsafe"
EMAIL_A_USER_KEY = "xmesh-u101"
EMAIL_B = "xmesh-u102--vless-share"
# Run a real patched-Xray process per transport. Production remains untouched.
TRANSPORTS = ("tcp", "ws", "xhttp", "xhttp-stream-up",
              "xhttp-stream-one", "mux-tcp")


def make_stream_settings(transport):
    # MUX is an application-level multiplexing layer over VLESS/TCP.
    wire_transport = "tcp" if transport == "mux-tcp" else transport
    settings = {"network": wire_transport, "security": "none"}
    if transport == "ws":
        settings["wsSettings"] = {"path": "/xmesh-ci-ws"}
    elif transport in ("xhttp", "xhttp-stream-up", "xhttp-stream-one"):
        # Exercise each upstream XHTTP upload mode in an independent real
        # process. The mode is not just a label: the Xray dialer opens
        # different HTTP request/response lifetimes for these variants.
        mode = {
            "xhttp": "packet-up",
            "xhttp-stream-up": "stream-up",
            "xhttp-stream-one": "stream-one",
        }[transport]
        settings["network"] = "xhttp"
        settings["xhttpSettings"] = {
            "path": "/xmesh-ci-xhttp/", "mode": mode,
        }
    elif transport not in ("tcp", "mux-tcp"):
        raise AssertionError(f"Unsupported test transport: {transport}")
    return settings


def command(*argv, check=True):
    return subprocess.run(argv, capture_output=True, text=True,
                          timeout=15, check=check)


def query_counter(xray, port, email):
    result = command(xray, "api", "statsquery", f"--server=127.0.0.1:{port}",
                     "-pattern", f"user>>>{email}")
    stats = json.loads(result.stdout)["stat"]
    values = {}
    for item in stats:
        for suffix in ("uplink", "downlink"):
            if item["name"] == f"user>>>{email}>>>traffic>>>{suffix}":
                values[suffix] = int(item["value"])
    assert len(values) == 2, (email, stats)
    return sum(values.values())


def wait_counter(xray, port, email, minimum=1):
    deadline = time.monotonic() + 12
    last_error = None
    while time.monotonic() < deadline:
        try:
            value = query_counter(xray, port, email)
            if value >= minimum:
                return value
        except (OSError, AssertionError, ValueError, KeyError,
                subprocess.CalledProcessError) as exc:
            last_error = repr(exc)
        time.sleep(.2)
    raw = command(xray,"api","statsquery",f"--server=127.0.0.1:{port}",
                  "-pattern","user>>>",check=False)
    raise AssertionError(
        f"Xray counter for {email} never advanced beyond {minimum}; "
        f"last_error={last_error}; status={raw.returncode}; "
        f"stdout={raw.stdout[-1500:]!r}; stderr={raw.stderr[-1500:]!r}"
    )


# Fake scope is supplied only by the disposable test fixture.
# It is NOT authenticated signed Node lease evidence.
def test_lease_scope(email, revocation_id, *, node_id=201, user_id=101,
                     revision=7):
    return {"email": email, "nodeId": node_id, "userId": user_id,
            "epoch": "11111111-1111-4111-8111-111111111111",
            "meterEpoch": "22222222-2222-4222-8222-222222222222",
            "reservationId": "33333333-3333-4333-8333-333333333333",
            "revision": revision, "revocationId": revocation_id}


def request_fence(path, email, revocation_id, expected_status=200, *,
                  scope_override=None):
    scope = test_lease_scope(email, revocation_id)
    if scope_override:
        scope.update(scope_override)
    message = json.dumps(scope).encode()
    request = (
        b"POST /v1/fence HTTP/1.1\r\nHost: localhost\r\n"
        b"Connection: close\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {len(message)}\r\n\r\n".encode() + message
    )
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(9)
        sock.connect(str(path))
        sock.sendall(request)
        response = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    headers, body = bytes(response).split(b"\r\n\r\n",1)
    assert f" {expected_status} ".encode() in headers.splitlines()[0], response[-2000:]
    return json.loads(body) if expected_status == 200 else body


def await_socket(path, process):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise AssertionError(f"Patched Xray exited before Unix control socket: {process.returncode}")
        time.sleep(.1)
    raise AssertionError("Patched Xray did not start private Unix control socket")


def run(xray, transport):
    assert transport in TRANSPORTS
    assert os.getenv("GITHUB_ACTIONS") == "true"
    assert os.getenv("XMESH_DISPOSABLE_XRAY_PATCH_EXPERIMENT") == "1"
    assert Path(xray).is_file()
    with tempfile.TemporaryDirectory(prefix=f"xmesh-v2-{transport}-") as tmp:
        root = Path(tmp)
        assert root.stat().st_mode & 0o077 == 0
        socket_file = root / "drain.sock"
        revocation_id = str(uuid.uuid4())
        journal_file = root / ("observed-" +
                               hashlib.sha256(EMAIL_A_USER_KEY.encode()).hexdigest() + ".json")
        echo = EchoServer(("127.0.0.1",0),EchoHandler)
        threading.Thread(target=echo.serve_forever,daemon=True).start()
        api_port, vless_port, cdn_port, unsafe_port, socks_a, socks_cdn, socks_unsafe, socks_b, socks_blank = (
            reserve_port(),reserve_port(),reserve_port(),reserve_port(),
            reserve_port(),reserve_port(),reserve_port(),reserve_port(),reserve_port()
        )
        identity_a, identity_b, identity_blank = (
            str(uuid.uuid4()),str(uuid.uuid4()),str(uuid.uuid4())
        )
        server_config = {
            "log":{"loglevel":"warning"},
            "api":{"tag":"xmesh_stats_api","services":["StatsService"]},
            "stats":{},
            "policy":{"levels":{"0":{"statsUserUplink":True,
                                       "statsUserDownlink":True,
                                       "statsUserOnline":True}}},
            "inbounds":[
                {"tag":"vless-share","listen":"127.0.0.1","port":vless_port,
                 "protocol":"vless",
                 "settings":{"decryption":"none","clients":[
                     {"id":identity_a,"email":EMAIL_A,"level":0},
                     {"id":identity_b,"email":EMAIL_B,"level":0},
                     {"id":identity_blank,"level":0}]},
                 "streamSettings":make_stream_settings(transport)},
                # A second billable inbound carries the SAME authenticated
                # identity. Both old streams must be stopped by one revocation.
                {"tag":"vless-cdn","listen":"127.0.0.1","port":cdn_port,
                 "protocol":"vless",
                 "settings":{"decryption":"none","clients":[
                     {"id":identity_a,"email":EMAIL_A_CDN,"level":0}]},
                 "streamSettings":{"network":"tcp","security":"none"}},
                # This third live Xray listener is intentionally absent
                # from the declared billable allowlist; it must reject A.
                {"tag":"vless-unsafe","listen":"127.0.0.1","port":unsafe_port,
                 "protocol":"vless",
                 "settings":{"decryption":"none","clients":[
                     {"id":identity_a,"email":EMAIL_A_UNSAFE,"level":0}]},
                 "streamSettings":{"network":"tcp","security":"none"}},
                {"tag":"xmesh_stats_in","listen":"127.0.0.1","port":api_port,
                 "protocol":"dokodemo-door","settings":{
                     "address":"127.0.0.1","port":api_port,"network":"tcp"}},
            ],
            "outbounds":[{"tag":"direct","protocol":"freedom","settings":{
                "finalRules":[{"action":"allow","network":"tcp",
                    "ip":["127.0.0.1/32"],
                    "port":str(echo.server_address[1])}]
            }}],
            "routing":{"rules":[{"type":"field","inboundTag":["xmesh_stats_in"],
                                  "outboundTag":"xmesh_stats_api"}]}
        }
        def outbound(tag, identity, *, cdn=False, unsafe=False):
            destination = unsafe_port if unsafe else (cdn_port if cdn else vless_port)
            config = {"tag":tag,"protocol":"vless","settings":{"vnext":[{
                "address":"127.0.0.1","port":destination,
                "users":[{"id":identity,"encryption":"none"}]}]},
                "streamSettings":make_stream_settings("tcp" if (cdn or unsafe) else transport)}
            # Exercise two simultaneous logical streams A on one physical MUX
            # transport, while user B uses a separate physical connection.
            if transport == "mux-tcp" and tag == "user-a":
                config["mux"] = {"enabled": True, "concurrency": 8}
            return config
        client_config={
            "log":{"loglevel":"warning"},
            "inbounds":[
                {"tag":"socks-a","listen":"127.0.0.1","port":socks_a,
                 "protocol":"socks","settings":{"auth":"noauth","udp":False}},
                {"tag":"socks-cdn","listen":"127.0.0.1","port":socks_cdn,
                 "protocol":"socks","settings":{"auth":"noauth","udp":False}},
                {"tag":"socks-unsafe","listen":"127.0.0.1","port":socks_unsafe,
                 "protocol":"socks","settings":{"auth":"noauth","udp":False}},
                {"tag":"socks-b","listen":"127.0.0.1","port":socks_b,
                 "protocol":"socks","settings":{"auth":"noauth","udp":False}},
                {"tag":"socks-blank","listen":"127.0.0.1","port":socks_blank,
                 "protocol":"socks","settings":{"auth":"noauth","udp":False}}
            ],
            "outbounds":[outbound("user-a",identity_a),
                         outbound("user-a-cdn",identity_a,cdn=True),
                         outbound("user-unsafe",identity_a,unsafe=True),
                         outbound("user-b",identity_b),
                         outbound("user-blank",identity_blank)],
            "routing":{"rules":[{"type":"field","inboundTag":["socks-cdn"],
                                  "outboundTag":"user-a-cdn"},
                                {"type":"field","inboundTag":["socks-unsafe"],
                                  "outboundTag":"user-unsafe"},
                                {"type":"field","inboundTag":["socks-b"],
                                  "outboundTag":"user-b"},
                                {"type":"field","inboundTag":["socks-blank"],
                                 "outboundTag":"user-blank"}]}
        }
        server_json=root/"server.json"
        client_json=root/"client.json"
        server_json.write_text(json.dumps(server_config),encoding="utf-8")
        client_json.write_text(json.dumps(client_config),encoding="utf-8")
        for config in (server_json,client_json):
            command(xray,"run","-test","-config",str(config))
        log_a=(root/"server.log").open("w+")
        log_b=(root/"client.log").open("w+")
        server=None
        client=None
        a=None
        a2=None
        cdn=None
        b=None
        try:
            env=os.environ.copy()
            env.update({
                "GITHUB_ACTIONS":"true",
                "XMESH_EXPERIMENTAL_DRAIN":"1",
                "XMESH_EXPERIMENTAL_SCOPED_INBOUNDS":"vless-share,vless-cdn",
                "XMESH_EXPERIMENTAL_DRAIN_SOCKET":str(socket_file),
                "XMESH_EXPERIMENTAL_OBSERVED_DIR":str(root),
            })
            server=subprocess.Popen([xray,"run","-config",str(server_json)],
                                    stdout=log_a,stderr=subprocess.STDOUT,env=env)
            await_socket(socket_file,server)
            assert socket_file.stat().st_mode & 0o077 == 0
            client_env=os.environ.copy()
            client_env.pop("XMESH_EXPERIMENTAL_DRAIN",None)
            client=subprocess.Popen([xray,"run","-config",str(client_json)],
                                    stdout=log_b,stderr=subprocess.STDOUT,env=client_env)
            a=connect_socks(socks_a,echo.server_address[1],"127.0.0.1")
            cdn=connect_socks(socks_cdn,echo.server_address[1],"127.0.0.1")
            b=connect_socks(socks_b,echo.server_address[1],"127.0.0.1")
            echo_bytes(a,8192)
            echo_bytes(cdn,8192)
            before_cdn = wait_counter(xray, api_port, EMAIL_A_CDN)
            assert before_cdn > 0, "CDN per-inbound email was not billed"
            # The private StatsService remains available alongside both
            # metered inbounds and the deliberately unlisted third listener.
            before_unlisted = wait_counter(xray, api_port, EMAIL_A)
            assert before_unlisted > 0
            # An omitted user-bearing inbound is a hard admission failure,
            # even BEFORE the user's actual signed revocation is delivered.
            try:
                untracked = connect_socks(socks_unsafe, echo.server_address[1], "127.0.0.1")
            except (OSError, AssertionError):
                pass
            else:
                try:
                    assert not probe_echo(untracked), "Untracked inbound served unmetered traffic"
                finally:
                    untracked.close()
            if transport == "mux-tcp":
                # Both A streams coexist before revocation. Reusing the
                # parent's session ID would reject the second registration.
                a2=connect_socks(socks_a,echo.server_address[1],"127.0.0.1")
                echo_bytes(a2,8192)
                assert probe_echo(a),"First MUX child was evicted by second"
                assert probe_echo(a2),"Second MUX child did not persist"
            echo_bytes(b,8192)
            before_a=wait_counter(xray,api_port,EMAIL_A)
            before_b=wait_counter(xray,api_port,EMAIL_B)
            assert before_a>0 and before_b>0
            proof=request_fence(socket_file,EMAIL_A,revocation_id)
            assert proof["fenced"] and proof["drained"] and proof["active"]==0,proof
            assert not proof["finalMeterVerified"] and not proof["refundable"],proof
            observation=proof["observedCheckpoint"]
            assert observation["email"] == EMAIL_A
            assert observation["revocationId"] == revocation_id
            for k, v in test_lease_scope(EMAIL_A,revocation_id).items():
                assert observation[k] == v, (k,observation)
            assert len(observation["runtimeId"]) == 64
            assert observation["schemaVersion"] == 2
            assert observation["drained"] and not observation["finalMeterVerified"]
            assert observation["refundableBytes"] == 0
            assert (observation["uplinkBytes"] + observation["downlinkBytes"]) >= before_a
            assert journal_file.is_file(), "No durable experimental Xray journal"
            assert journal_file.stat().st_mode & 0o077 == 0
            observed_disk=json.loads(journal_file.read_text())
            assert observed_disk==observation,(observed_disk,observation)
            assert not probe_echo(a),"Old VLESS-A socket survived fenced process-close"
            assert not probe_echo(cdn),"Old CDN inbound stream survived user fence"
            if a2 is not None:
                assert not probe_echo(a2),"Second MUX child survived user fence"
            denied=connect_socks(socks_a,echo.server_address[1],"127.0.0.1")
            try:
                assert not probe_echo(denied),"Fenced user opened new authenticated stream"
            finally:
                denied.close()
            denied_cdn=connect_socks(socks_cdn,echo.server_address[1],"127.0.0.1")
            try:
                assert not probe_echo(denied_cdn), "Revoked user reopened secondary CDN inbound"
            finally:
                denied_cdn.close()
            # The disposable billable VLESS inbound must reject an
            # authenticated user lacking a stable accounting identity.
            # The independent management API inbound must remain usable.
            unnamed=connect_socks(socks_blank,echo.server_address[1],"127.0.0.1")
            try:
                assert not probe_echo(unnamed),"Blank VLESS email bypassed per-user gate"
            finally:
                unnamed.close()
            assert probe_echo(b),"Fence for user A killed user B on shared inbound"
            fresh_b=connect_socks(socks_b,echo.server_address[1],"127.0.0.1")
            try:
                assert probe_echo(fresh_b),"Unrelated user B lost new admission"
            finally:
                fresh_b.close()
            after_a=wait_counter(xray,api_port,EMAIL_A,before_a)
            after_cdn=wait_counter(xray,api_port,EMAIL_A_CDN,before_cdn)
            assert after_cdn >= before_cdn
            after_b=wait_counter(xray,api_port,EMAIL_B,before_b+1)
            repeat=request_fence(socket_file,EMAIL_A,revocation_id)
            assert repeat["fenced"] and repeat["drained"] and repeat["active"]==0
            assert repeat["observedCheckpoint"]==observation
            assert not repeat["refundable"] and not repeat["finalMeterVerified"]
            conflicting=request_fence(socket_file,EMAIL_A,str(uuid.uuid4()),
                                      expected_status=409)
            assert b"durable fence" in conflicting,conflicting
            for wrong in ({"nodeId": 999}, {"userId": 777},
                          {"epoch": "44444444-4444-4444-8444-444444444444"},
                          {"meterEpoch": "55555555-5555-4555-8555-555555555555"},
                          {"reservationId": "66666666-6666-4666-8666-666666666666"},
                          {"revision": 8}):
                mismatch = request_fence(socket_file,EMAIL_A,revocation_id,
                                         expected_status=409,scope_override=wrong)
                assert b"durable fence" in mismatch, (wrong,mismatch)
            assert json.loads(journal_file.read_text())==observation
            assert server.poll() is None,"Xray server exited during selective fence"
            # Data remains after shutting down the Xray process: this
            # verifies persistence, not a terminal-byte correctness barrier.
            server.terminate()
            server.wait(timeout=5)
            assert json.loads(journal_file.read_text())==observation
            report={
                "patchedXray":"a4a3dff5b20c2faae567b742c172c7b95e75c083",
                "testedTransport":transport,
                "simultaneousMuxChildrenStopped":transport == "mux-tcp",
                "userAFenced":True,"existingUserAStreamEnded":True,
                "newUserAStreamsRejected":True,
                "secondaryCDNInboundRevoked":True,
                "distinctSignedInboundEmailsShareUserFence":True,
                "observedSnapshotStillNonfinalAndDoesNotAggregateCDN":True,
                "unlistedBillableInboundDenied":True,
                "blankVlessEmailRejected":True,
                "existingUserBStreamSurvived":True,"newUserBStreamsAccepted":True,
                "statsServiceStillAvailable":True,
                "userABeforeFenceBytes":before_a,"userAAfterFenceBytes":after_a,
                "userBAfterFenceBytes":after_b,
                "observedJournalFsynced":True,
                "observedJournalSurvivedProcessExit":True,
                "observedRuntimeIdBound":True,
                "observedRevocationIdBound":True,
                "finalMeterVerified":False,"refundableBytes":0,
            }
            print("EXPERIMENTAL PATCHED XRAY FENCE "+json.dumps(report,sort_keys=True),
                  flush=True)
        except Exception:
            for file in (log_a,log_b):
                file.flush()
                file.seek(0)
                print("PATCHED XRAY DIAGNOSTIC:\n"+file.read()[-12000:],
                      flush=True)
            raise
        finally:
            for conn in (a,a2,cdn,b):
                if conn is not None:
                    conn.close()
            for proc in (client,server):
                if proc is not None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=4)
            log_a.close()
            log_b.close()
            echo.shutdown()
            echo.server_close()


if __name__=="__main__":
    if len(sys.argv)!=2:
        raise SystemExit("usage: test_xray_patched_fence.py <patched-xray-binary>")
    binary=str(Path(sys.argv[1]).resolve())
    for transport in TRANSPORTS:
        print(f"START PATCHED XRAY TRANSPORT: {transport}", flush=True)
        run(binary, transport)
