#!/usr/bin/env python3
"""Real-process CI acceptance of a DISPOSABLE PATCHED Xray, no refund proof.

Two users share a real VLESS inbound. A root-private Unix control socket
fences one authenticated user, closes existing transport sessions, and leaves
the other user's streams running. This is experimental traffic cessation,
NOT a durable final byte accounting/cryptographic receipt.
"""
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

EMAIL_A = "xmesh-experiment-a"
EMAIL_B = "xmesh-experiment-b"


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


def request_fence(path, email):
    message = json.dumps({"email":email}).encode()
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
    assert b" 200 " in headers.splitlines()[0], response[-2000:]
    return json.loads(body)


def await_socket(path, process):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise AssertionError(f"Patched Xray exited before Unix control socket: {process.returncode}")
        time.sleep(.1)
    raise AssertionError("Patched Xray did not start private Unix control socket")


def run(xray):
    assert os.getenv("GITHUB_ACTIONS") == "true"
    assert os.getenv("XMESH_DISPOSABLE_XRAY_PATCH_EXPERIMENT") == "1"
    assert Path(xray).is_file()
    with tempfile.TemporaryDirectory(prefix="xmesh-v2-patched-xray-") as tmp:
        root = Path(tmp)
        assert root.stat().st_mode & 0o077 == 0
        socket_file = root / "drain.sock"
        echo = EchoServer(("127.0.0.1",0),EchoHandler)
        threading.Thread(target=echo.serve_forever,daemon=True).start()
        api_port, vless_port, socks_a, socks_b, socks_blank = (
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
        def outbound(tag, identity):
            return {"tag":tag,"protocol":"vless","settings":{"vnext":[{
                "address":"127.0.0.1","port":vless_port,
                "users":[{"id":identity,"encryption":"none"}]}]},
                "streamSettings":{"network":"tcp","security":"none"}}
        client_config={
            "log":{"loglevel":"warning"},
            "inbounds":[
                {"tag":"socks-a","listen":"127.0.0.1","port":socks_a,
                 "protocol":"socks","settings":{"auth":"noauth","udp":False}},
                {"tag":"socks-b","listen":"127.0.0.1","port":socks_b,
                 "protocol":"socks","settings":{"auth":"noauth","udp":False}},
                {"tag":"socks-blank","listen":"127.0.0.1","port":socks_blank,
                 "protocol":"socks","settings":{"auth":"noauth","udp":False}}
            ],
            "outbounds":[outbound("user-a",identity_a),outbound("user-b",identity_b),
                         outbound("user-blank",identity_blank)],
            "routing":{"rules":[{"type":"field","inboundTag":["socks-b"],
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
        b=None
        try:
            env=os.environ.copy()
            env.update({
                "GITHUB_ACTIONS":"true",
                "XMESH_EXPERIMENTAL_DRAIN":"1",
                "XMESH_EXPERIMENTAL_DRAIN_SOCKET":str(socket_file),
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
            b=connect_socks(socks_b,echo.server_address[1],"127.0.0.1")
            echo_bytes(a,8192)
            echo_bytes(b,8192)
            before_a=wait_counter(xray,api_port,EMAIL_A)
            before_b=wait_counter(xray,api_port,EMAIL_B)
            assert before_a>0 and before_b>0
            proof=request_fence(socket_file,EMAIL_A)
            assert proof["fenced"] and proof["drained"] and proof["active"]==0,proof
            assert not proof["finalMeterVerified"] and not proof["refundable"],proof
            assert not probe_echo(a),"Old VLESS-A socket survived fenced process-close"
            denied=connect_socks(socks_a,echo.server_address[1],"127.0.0.1")
            try:
                assert not probe_echo(denied),"Fenced user opened new authenticated stream"
            finally:
                denied.close()
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
            after_b=wait_counter(xray,api_port,EMAIL_B,before_b+1)
            repeat=request_fence(socket_file,EMAIL_A)
            assert repeat["fenced"] and repeat["drained"] and repeat["active"]==0
            assert not repeat["refundable"] and not repeat["finalMeterVerified"]
            assert server.poll() is None,"Xray server exited during selective fence"
            report={
                "patchedXray":"a4a3dff5b20c2faae567b742c172c7b95e75c083",
                "userAFenced":True,"existingUserAStreamEnded":True,
                "newUserAStreamsRejected":True,
                "blankVlessEmailRejected":True,
                "existingUserBStreamSurvived":True,"newUserBStreamsAccepted":True,
                "statsServiceStillAvailable":True,
                "userABeforeFenceBytes":before_a,"userAAfterFenceBytes":after_a,
                "userBAfterFenceBytes":after_b,
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
            for conn in (a,b):
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
    run(str(Path(sys.argv[1]).resolve()))
