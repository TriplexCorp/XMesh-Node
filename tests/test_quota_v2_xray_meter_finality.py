#!/usr/bin/env python3
"""Disposable real-Xray experiment: a live statsquery is NOT terminal evidence.

No signed final-use proof is emitted and no quota refund is ever attempted.
All traffic stays on localhost inside an isolated GitHub Actions worker.
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


def connect_socks(port, target):
    deadline = time.monotonic()+18
    while True:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=3)
            sock.settimeout(5)
            sock.sendall(b"\x05\x01\x00")
            assert recv_exact(sock, 2) == b"\x05\x00"
            sock.sendall(b"\x05\x01\x00\x01" +
                         socket.inet_aton("127.0.0.1") + struct.pack(">H", target))
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


def run():
    assert os.getenv("GITHUB_ACTIONS") == "true"
    assert os.getenv("XMESH_DISPOSABLE_XRAY_METER_EXPERIMENT") == "1"
    for name in (SERVER,CLIENT):
        assert docker("inspect", name, check=False).returncode != 0, (
            f"Refusing to touch existing container: {name}"
        )
    echo = EchoServer(("127.0.0.1",0),EchoHandler)
    threading.Thread(target=echo.serve_forever,daemon=True).start()
    api_port, vless_port, socks_port = reserve_port(),reserve_port(),reserve_port()
    user = str(uuid.uuid4())
    server_config = {
        "log":{"loglevel":"warning"},
        "api":{"tag":"xmesh_stats_api","services":["StatsService"]},
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
        "outbounds":[{"tag":"direct","protocol":"freedom"}],
        "routing":{"rules":[{"type":"field","inboundTag":["xmesh_stats_in"],
                              "outboundTag":"xmesh_stats_api"}]},
    }
    client_config = {
        "log":{"loglevel":"warning"},
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
            sock=connect_socks(socks_port,echo.server_address[1])
            echo_bytes(sock,8192)
            first=await_counter(api_port,1)
            echo_bytes(sock,32768)
            second=await_counter(api_port,first+1)
            assert second>first,(first,second)
            # Old ongoing session is still authenticated and can transfer after
            # a legitimate "last-known" statsquery. Thus the sample is NOT
            # the final number, even though it came from authentic Xray.
            docker("stop","--time","2",SERVER)
            assert docker("inspect","-f","{{.State.Running}}",SERVER).stdout.strip()=="false"
            lost=docker("exec",SERVER,"xray","api","statsquery",
                        f"--server=127.0.0.1:{api_port}","-pattern",f"user>>>{EMAIL}",
                        check=False)
            assert lost.returncode != 0, "StatsService unexpectedly remained alive after Xray exit"
            report={"firstSampleBytes":first,"laterSampleBytes":second,
                    "additionalBytesAfterSample":second-first,
                    "postStopStatsServiceAvailable":False,
                    "finalMeterVerified":False,"refundableBytes":0}
            print("REAL XRAY NONTERMINAL COUNTER EVIDENCE "+json.dumps(report,sort_keys=True),flush=True)
    finally:
        if sock is not None:
            sock.close()
        for name in reversed(started):
            docker("rm","-f",name,check=False)
        echo.shutdown()
        echo.server_close()


if __name__=="__main__":
    run()
