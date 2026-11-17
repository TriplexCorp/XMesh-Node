#!/usr/bin/env python3
"""Disposable real-Xray experiment: per-user revoke vs inbound removal.

Experiments with live VLESS sessions and HandlerService rmu/rmi. No signed
final-use proof or refundable terminal meter is emitted.
All traffic stays on 127.0.0.1; finalRules allowlists exactly the test port.
"""
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import tempfile
import threading
import time
import uuid

IMAGE = "ghcr.io/xtls/xray-core:26.10.31"
SERVER = "xmesh-final-meter-server"
CLIENT = "xmesh-final-meter-client"
EMAIL = "xmesh-u4242"


def docker(*args, check=True):
    return subprocess.run(("docker", *args), check=check, capture_output=True,
                          text=True, timeout=35)


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(65536)
            if not data:
                return
            self.request.sendall(data)


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def reserve_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def recv_exact(sock, n):
    result = bytearray()
    while len(result) < n:
        chunk = sock.recv(n-len(result))
        if not chunk:
            raise AssertionError("Xray SOCKS5 tunnel closed early")
        result += chunk
    return bytes(result)


def connect_socks(port, target, target_host):
    deadline = time.monotonic()+18
    while True:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=3)
            sock.settimeout(5)
            sock.sendall(b"\x05\x01\x00")
            assert recv_exact(sock, 2) == b"\x05\x00"
            sock.sendall(b"\x05\x01\x00\x01" +
                         socket.inet_aton(target_host) + struct.pack(">H", target))
            header = recv_exact(sock, 4)
            assert header[:2] == b"\x05\x00", f"SOCKS5 refused route: {header!r}"
            addr_len = {1: 4, 4: 16}.get(header[3])
            if addr_len is None:
                assert header[3] == 3
                addr_len = recv_exact(sock, 1)[0]
            recv_exact(sock, addr_len+2)
            return sock
        except (OSError, AssertionError):
            if time.monotonic() > deadline:
                raise
            time.sleep(.25)


def stats_query(api_port):
    cmd = docker("exec", SERVER, "xray", "api", "statsquery",
                 f"--server=127.0.0.1:{api_port}", "-pattern", f"user>>>{EMAIL}")
    doc = json.loads(cmd.stdout)
    assert isinstance(doc.get("stat"), list), doc
    found = {}
    for row in doc["stat"]:
        name = row["name"]
        if name in (f"user>>>{EMAIL}>>>traffic>>>uplink",
                    f"user>>>{EMAIL}>>>traffic>>>downlink"):
            found[name.rsplit(">>>",1)[1]] = int(row["value"])
    assert all(k in found for k in ("uplink","downlink")), found
    return sum(found.values())


def await_counter(api_port, minimum):
    deadline = time.monotonic()+10
    while time.monotonic() < deadline:
        try:
            value = stats_query(api_port)
            if value >= minimum:
                return value
        except (subprocess.CalledProcessError, AssertionError, ValueError, KeyError):
            pass
        time.sleep(.25)
    raise AssertionError(f"Xray StatsService did not advance beyond {minimum}")


def echo_bytes(sock, size):
    payload = os.urandom(size)
    sock.sendall(payload)
    assert recv_exact(sock, len(payload)) == payload, "Corrupted VLESS echo"


def probe_echo(sock, size=4096):
    """Observe an established stream without claiming proof of finality."""
    if sock is None:
        return False
    try:
        sock.settimeout(3)
        echo_bytes(sock, size)
        return True
    except (OSError, AssertionError):
        return False


def run():
    assert os.getenv("GITHUB_ACTIONS") == "true"
    assert os.getenv("XMESH_DISPOSABLE_XRAY_DRAIN_EXPERIMENT") == "1"
    for name in (SERVER,CLIENT):
        assert docker("inspect", name, check=False).returncode != 0, (
            f"Refusing to touch existing container: {name}"
        )
    # Xray Freedom 26.x blocks private destinations unless explicit
    # finalRules allowlists them. The exception below is TCP + EXACT port
    # + 127.0.0.1/32 in this disposable fixture, never production config.
    host_ip = "127.0.0.1"
    echo = EchoServer((host_ip,0),EchoHandler)
    threading.Thread(target=echo.serve_forever,daemon=True).start()
    api_port, vless_port, socks_port = reserve_port(),reserve_port(),reserve_port()
    user = str(uuid.uuid4())
    server_config = {
        "log":{"loglevel":"debug"},
        "api":{"tag":"xmesh_stats_api","services":["StatsService","HandlerService"]},
        "stats":{},  # Enables counter registration in Xray's stats manager
        "policy":{"levels":{"0":{"statsUserUplink":True,"statsUserDownlink":True,
                                   "statsUserOnline":True}}},
        "inbounds":[
            {"tag":"vless-meter-fixture","listen":"127.0.0.1","port":vless_port,
             "protocol":"vless","settings":{"decryption":"none",
               "clients":[{"id":user,"email":EMAIL,"level":0}]},
             "streamSettings":{"network":"tcp","security":"none"}},
            {"tag":"xmesh_stats_in","listen":"127.0.0.1","port":api_port,
             "protocol":"dokodemo-door","settings":{"address":"127.0.0.1",
                                                        "port":api_port,"network":"tcp"}},
        ],
        "outbounds":[{"tag":"direct","protocol":"freedom","settings":{
            "finalRules":[{"action":"allow","network":"tcp",
                "ip":["127.0.0.1/32"],"port":str(echo.server_address[1])}]
        }}],
        "routing":{"rules":[{"type":"field","inboundTag":["xmesh_stats_in"],
                              "outboundTag":"xmesh_stats_api"}]},
    }
    client_config = {
        "log":{"loglevel":"debug"},
        "inbounds":[{"tag":"socks5","listen":"127.0.0.1","port":socks_port,
                     "protocol":"socks","settings":{"auth":"noauth","udp":False}}],
        "outbounds":[{"protocol":"vless","settings":{"vnext":[{
            "address":"127.0.0.1","port":vless_port,
            "users":[{"id":user,"encryption":"none"}]}]},
            "streamSettings":{"network":"tcp","security":"none"}}],
    }
    started=[]
    sock=None
    try:
        with tempfile.TemporaryDirectory(prefix="xmesh-v2-meter-fixture-") as tmp:
            files=[]
            for name,content in ((SERVER,server_config),(CLIENT,client_config)):
                file = Path(tmp) / (name+".json")
                file.write_text(json.dumps(content),encoding="utf-8")
                os.chmod(file,0o644)  # Test config contains only ephemeral random UUID
                files.append(file)
                docker("run","--rm","--network","host",
                       "-v",f"{file}:/etc/xray/config.json:ro",
                       IMAGE,"run","-test","-config","/etc/xray/config.json")
            for name,file in zip((SERVER,CLIENT),files):
                docker("run","-d","--name",name,"--network","host",
                       "--restart","no","--read-only",
                       "--security-opt","no-new-privileges","--cap-drop","ALL",
                       "-v",f"{file}:/etc/xray/config.json:ro",
                       IMAGE,"run","-config","/etc/xray/config.json")
                started.append(name)
            sock=connect_socks(socks_port,echo.server_address[1],host_ip)
            echo_bytes(sock,8192)
            first=await_counter(api_port,1)
            echo_bytes(sock,32768)
            later=await_counter(api_port,first+1)
            assert later>first,(first,later)

            # Exact user-management command for this VLESS inbound, issued
            # against the still-running official Xray HandlerService.
            removed=docker("exec",SERVER,"xray","api","rmu",
                           f"--server=127.0.0.1:{api_port}",
                           "-tag=vless-meter-fixture",EMAIL)
            assert b"Removed 1 user(s) in total." in removed.stdout, removed.stdout
            existing_after_rmu=probe_echo(sock)
            # A SOCKS5 handshake alone does NOT authenticate VLESS; send
            # echo traffic to check if the new VLESS credential was accepted.
            new_sock=connect_socks(socks_port,echo.server_address[1],host_ip)
            try:
                new_sock.settimeout(3)
                new_authorized=probe_echo(new_sock)
            finally:
                new_sock.close()
            assert not new_authorized,"rmu accepted a NEW VLESS authenticated stream"
            after_rmu=stats_query(api_port)
            assert after_rmu>=later,(later,after_rmu)

            # Remove only the application inbound while keeping Xray's
            # management API and in-memory StatsService alive.
            removed_inbound=docker("exec",SERVER,"xray","api","rmi",
                                   f"--server=127.0.0.1:{api_port}",
                                   "vless-meter-fixture")
            assert b"removing:" in removed_inbound.stdout,removed_inbound.stdout
            api_still_alive=docker("exec",SERVER,"xray","api","lsi",
                                   f"--server=127.0.0.1:{api_port}",
                                   "--isOnlyTags=true")
            assert b"vless-meter-fixture" not in api_still_alive.stdout,api_still_alive.stdout
            existing_after_rmi=probe_echo(sock) if existing_after_rmu else False
            after_rmi=stats_query(api_port)
            assert after_rmi>=after_rmu,(after_rmu,after_rmi)
            listener_closed=False
            try:
                with socket.create_connection(("127.0.0.1",vless_port),timeout=2):
                    listener_closed=False
            except OSError:
                listener_closed=True
            assert listener_closed,"HandlerService rmi left the VLESS listener available"

            docker("stop","--time","2",SERVER)
            assert docker("inspect","-f","{{.State.Running}}",SERVER).stdout.strip()=="false"
            lost=docker("exec",SERVER,"xray","api","statsquery",
                        f"--server=127.0.0.1:{api_port}","-pattern",f"user>>>{EMAIL}",
                        check=False)
            assert lost.returncode != 0,"StatsService survived Xray process termination"
            report={
                "initialSampleBytes":first,
                "laterSampleBytes":later,
                "bytesAfterFirstSample":later-first,
                "rmuDeniedNewUserSession":not new_authorized,
                "existingSessionSurvivedRmu":existing_after_rmu,
                "sampleAfterRmuBytes":after_rmu,
                "rmiRemovedInbound":listener_closed,
                "existingSessionSurvivedRmi":existing_after_rmi,
                "statsServiceAccessibleAfterRmi":True,
                "sampleAfterRmiBytes":after_rmi,
                "statsServiceAccessibleAfterProcessStop":False,
                "finalMeterVerified":False,
                "refundableBytes":0,
            }
            print("REAL XRAY DRAIN EXPERIMENT "+json.dumps(report,sort_keys=True),flush=True)
    except Exception:
        # Capture fixture diagnostics before ephemeral containers are removed.
        for name in started:
            log = docker("logs","--tail","60",name,check=False)
            print("DISPOSABLE XRAY "+name+" OUTPUT:\n"+(log.stdout+log.stderr)[-10000:],flush=True)
        raise
    finally:
        if sock is not None:
            sock.close()
        for name in reversed(started):
            docker("rm","-f",name,check=False)
        echo.shutdown()
        echo.server_close()


if __name__=="__main__":
    run()
