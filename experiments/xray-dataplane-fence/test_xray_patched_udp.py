#!/usr/bin/env python3
"""Disposable real-Xray VLESS UDP/XUDP fence acceptance.

Tests SOCKS5 UDP ASSOCIATE -> actual VLESS UDP -> loopback UDP echo, with
two distinct authenticated users. This is traffic cessation only, and MUST
NOT be used as terminal byte evidence or trigger a refundable quota.
"""
import hashlib
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_quota_v2_xray_user_inbound_drain import recv_exact, reserve_port  # noqa: E402
from test_xray_patched_fence import (  # noqa: E402
    command, await_socket, request_fence, wait_counter, query_counter, EMAIL_A, EMAIL_B,
)


class UDPReply(socketserver.BaseRequestHandler):
    def handle(self):
        payload, listener = self.request
        listener.sendto(payload, self.client_address)


class UDPEcho(socketserver.ThreadingUDPServer):
    allow_reuse_address = True
    daemon_threads = True


def socks_udp_associate(port):
    """Hold SOCKS5's TCP control connection open for its UDP relay lifetime."""
    deadline = time.monotonic() + 15
    while True:
        try:
            control = socket.create_connection(("127.0.0.1", port), timeout=2)
            control.settimeout(5)
            control.sendall(b"\x05\x01\x00")
            assert recv_exact(control, 2) == b"\x05\x00"
            datagrams = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            datagrams.bind(("127.0.0.1", 0))
            datagrams.settimeout(3)
            local_port = datagrams.getsockname()[1]
            control.sendall(b"\x05\x03\x00\x01" +
                            socket.inet_aton("127.0.0.1") +
                            struct.pack(">H", local_port))
            head = recv_exact(control, 4)
            assert head[:3] == b"\x05\x00\x00", f"UDP ASSOCIATE denied: {head!r}"
            atyp = head[3]
            if atyp == 1:
                host = socket.inet_ntoa(recv_exact(control, 4))
            elif atyp == 3:
                n = recv_exact(control, 1)[0]
                host = recv_exact(control, n).decode("ascii")
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, recv_exact(control, 16))
            else:
                raise AssertionError(f"Unsupported relay address type: {atyp}")
            relay_port = struct.unpack(">H", recv_exact(control, 2))[0]
            if host in ("0.0.0.0", "::"):
                host = "127.0.0.1"
            return control, datagrams, (host, relay_port)
        except (OSError, AssertionError):
            if time.monotonic() > deadline:
                raise
            time.sleep(.2)


def exchange_udp(association, echo_port, expect_reply, tag):
    control, datagrams, relay = association
    del control
    token = os.urandom(1232)
    payload = b"\x00\x00\x00\x01" + socket.inet_aton("127.0.0.1") + \
              struct.pack(">H", echo_port) + token
    datagrams.sendto(payload, relay)
    datagrams.settimeout(3 if expect_reply else 1.2)
    try:
        received, _ = datagrams.recvfrom(65536)
    except socket.timeout:
        if expect_reply:
            raise AssertionError(f"{tag}: real UDP echo did not return")
        return False
    assert received[:3] == b"\x00\x00\x00", (tag, received[:8])
    if received[3] == 1:
        header_length = 10
    elif received[3] == 3:
        header_length = 7 + received[4]
    elif received[3] == 4:
        header_length = 22
    else:
        raise AssertionError(f"{tag}: unexpected SOCKS5 UDP address type")
    response = received[header_length:]
    if expect_reply:
        assert response == token, f"{tag}: corrupted routed UDP payload"
        return True
    raise AssertionError(f"{tag}: revoked user received UDP after fence")


def inspect_fence_replay(path, email, revocation_id):
    """Return status and raw bytes. Late UDP/XUDP traffic must yield 409."""
    payload = json.dumps({"email": email, "revocationId": revocation_id}).encode()
    request = (b"POST /v1/fence HTTP/1.1\r\nHost: localhost\r\n"
               b"Connection: close\r\nContent-Type: application/json\r\n"
               + f"Content-Length: {len(payload)}\r\n\r\n".encode() + payload)
    with socket.socket(socket.AF_UNIX) as control:
        control.settimeout(9)
        control.connect(str(path))
        control.sendall(request)
        response = bytearray()
        while True:
            chunk = control.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
    headers, body = bytes(response).split(b"\r\n\r\n", 1)
    status = int(headers.split(b"\r\n", 1)[0].split()[1])
    assert status in (200, 409), response[-2000:]
    return status, body


def run(xray, xudp):
    assert os.getenv("GITHUB_ACTIONS") == "true"
    assert os.getenv("XMESH_DISPOSABLE_XRAY_PATCH_EXPERIMENT") == "1"
    mode = "xudp" if xudp else "udp"
    with tempfile.TemporaryDirectory(prefix=f"xmesh-v2-{mode}-") as tmp:
        root = Path(tmp)
        assert root.stat().st_mode & 0o077 == 0
        control_socket = root / "drain.sock"
        revocation_id = str(uuid.uuid4())
        checkpoint = root / ("observed-" + hashlib.sha256(EMAIL_A.encode()).hexdigest() + ".json")
        echo = UDPEcho(("127.0.0.1", 0), UDPReply)
        threading.Thread(target=echo.serve_forever, daemon=True).start()
        echo_port = echo.server_address[1]
        vless_port, api_port, socks_a, socks_b = (reserve_port() for _ in range(4))
        identity_a, identity_b = str(uuid.uuid4()), str(uuid.uuid4())
        server_config = {
            "log": {"loglevel": "warning"},
            "api": {"tag": "xmesh_stats_api", "services": ["StatsService"]},
            "stats": {},
            "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
            "inbounds": [
                {"tag": "vless-share", "listen": "127.0.0.1", "port": vless_port,
                 "protocol": "vless", "settings": {"decryption": "none", "clients": [
                     {"id": identity_a, "email": EMAIL_A, "level": 0},
                     {"id": identity_b, "email": EMAIL_B, "level": 0}]},
                 "streamSettings": {"network": "tcp", "security": "none"}},
                {"tag": "xmesh_stats_in", "listen": "127.0.0.1", "port": api_port,
                 "protocol": "dokodemo-door", "settings": {
                     "address": "127.0.0.1", "port": api_port, "network": "tcp"}}
            ],
            "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {
                "finalRules": [{"action": "allow", "network": "udp",
                                "ip": ["127.0.0.1/32"], "port": str(echo_port)}]}}],
            "routing": {"rules": [{"type": "field", "inboundTag": ["xmesh_stats_in"],
                                  "outboundTag": "xmesh_stats_api"}]}
        }
        def outbound(tag, identity):
            cfg = {"tag": tag, "protocol": "vless", "settings": {
                "vnext": [{"address": "127.0.0.1", "port": vless_port,
                           "users": [{"id": identity, "encryption": "none"}]}]},
                   "streamSettings": {"network": "tcp", "security": "none"}}
            if xudp and tag == "user-a":
                # Xray uses the XUDP multiplexer only when this is positive.
                cfg["mux"] = {"enabled": True, "concurrency": 8,
                              "xudpConcurrency": 8}
            return cfg
        client_config = {
            "log": {"loglevel": "warning"},
            "inbounds": [
                {"tag": "socks-a", "listen": "127.0.0.1", "port": socks_a,
                 "protocol": "socks", "settings": {"auth": "noauth", "udp": True}},
                {"tag": "socks-b", "listen": "127.0.0.1", "port": socks_b,
                 "protocol": "socks", "settings": {"auth": "noauth", "udp": True}},
            ],
            "outbounds": [outbound("user-a", identity_a), outbound("user-b", identity_b)],
            "routing": {"rules": [{"type": "field", "inboundTag": ["socks-b"],
                                  "outboundTag": "user-b"}]}
        }
        server_path, client_path = root / "server.json", root / "client.json"
        server_path.write_text(json.dumps(server_config))
        client_path.write_text(json.dumps(client_config))
        for config in (server_path, client_path):
            command(xray, "run", "-test", "-config", str(config))

        server_log = (root / "server.log").open("w+")
        client_log = (root / "client.log").open("w+")
        server = client = None
        associations = []
        try:
            env = os.environ.copy()
            env.update({"GITHUB_ACTIONS": "true",
                        "XMESH_EXPERIMENTAL_DRAIN": "1",
                        "XMESH_EXPERIMENTAL_DRAIN_SOCKET": str(control_socket),
                        "XMESH_EXPERIMENTAL_OBSERVED_DIR": str(root)})
            server = subprocess.Popen([xray, "run", "-config", str(server_path)],
                                      stdout=server_log, stderr=subprocess.STDOUT, env=env)
            await_socket(control_socket, server)
            client_env = os.environ.copy()
            client_env.pop("XMESH_EXPERIMENTAL_DRAIN", None)
            client = subprocess.Popen([xray, "run", "-config", str(client_path)],
                                      stdout=client_log, stderr=subprocess.STDOUT, env=client_env)
            a = socks_udp_associate(socks_a)
            b = socks_udp_associate(socks_b)
            associations.extend((a,b))
            assert exchange_udp(a, echo_port, True, f"{mode}-A-1")
            assert exchange_udp(b, echo_port, True, f"{mode}-B-1")
            assert exchange_udp(a, echo_port, True, f"{mode}-A-2")
            before_a = wait_counter(xray, api_port, EMAIL_A)
            before_b = wait_counter(xray, api_port, EMAIL_B)
            proof = request_fence(control_socket, EMAIL_A, revocation_id)
            assert proof["fenced"] and proof["drained"] and proof["active"] == 0, proof
            assert not proof["finalMeterVerified"] and not proof["refundable"], proof
            observation = proof["observedCheckpoint"]
            assert observation["refundableBytes"] == 0
            assert observation["revocationId"] == revocation_id
            assert observation["uplinkBytes"] + observation["downlinkBytes"] >= before_a
            assert checkpoint.is_file()
            assert json.loads(checkpoint.read_text()) == observation
            snapshot_total = observation["uplinkBytes"] + observation["downlinkBytes"]
            immediately_after_fence = query_counter(xray, api_port, EMAIL_A)
            exchange_udp(a, echo_port, False, f"{mode}-A-existing")
            after_old_association = query_counter(xray, api_port, EMAIL_A)
            fresh_a = socks_udp_associate(socks_a)
            associations.append(fresh_a)
            exchange_udp(fresh_a, echo_port, False, f"{mode}-A-new")
            after_new_association = query_counter(xray, api_port, EMAIL_A)
            print("UDP METER LIFECYCLE DIAGNOSTIC "+json.dumps({
                "transport": mode,
                "fsyncedSnapshot": snapshot_total,
                "immediatelyAfterFence": immediately_after_fence,
                "afterRejectedOldAssociation": after_old_association,
                "afterRejectedNewAssociation": after_new_association,
            },sort_keys=True),flush=True)
            assert exchange_udp(b, echo_port, True, f"{mode}-B-continues")
            fresh_b = socks_udp_associate(socks_b)
            associations.append(fresh_b)
            assert exchange_udp(fresh_b, echo_port, True, f"{mode}-B-new")
            after_a = wait_counter(xray, api_port, EMAIL_A, before_a)
            after_b = wait_counter(xray, api_port, EMAIL_B, before_b + 1)
            # Asynchronous UDP writes may arrive after the first fsync.
            # Once the sampled meter grows, the old proof MUST reject replay
            # and NEVER authorize a refund or overwrite its old contents.
            status, body = inspect_fence_replay(control_socket, EMAIL_A, revocation_id)
            if status == 200:
                repeat = json.loads(body)
                assert repeat["observedCheckpoint"] == observation
                assert not repeat["finalMeterVerified"] and not repeat["refundable"]
            else:
                assert b"existing checkpoint mismatch or late counter update" in body
            late_total = query_counter(xray, api_port, EMAIL_A)
            original_total = observation["uplinkBytes"] + observation["downlinkBytes"]
            # No data may enter either stats wrapper after admission is
            # closed. The prior real UDP/XUDP test observed +1232 bytes in
            # this exact phase; preserve that as a hard regression.
            assert late_total == original_total, (
                f"{mode}: post-fence user meter changed by "
                f"{late_total-original_total} bytes")
            assert status == 200, (mode, status, body)
            assert json.loads(checkpoint.read_text()) == observation
            assert server.poll() is None
            server.terminate()
            server.wait(timeout=5)
            assert json.loads(checkpoint.read_text()) == observation
            report = {"testedTransport": mode, "userAUDPRevoked": True,
                      "userBUDPContinues": True, "newUserAUDPRejected": True,
                      "newUserBUDPAllowed": True, "journalFsynced": True,
                      "replayStatus": status,
                      "lateMeterGrowth": late_total - original_total,
                      "userABeforeFenceBytes": before_a,
                      "userAAfterFenceBytes": after_a,
                      "userBAfterFenceBytes": after_b,
                      "finalMeterVerified": False, "refundableBytes": 0}
            print("EXPERIMENTAL PATCHED XRAY UDP "+json.dumps(report, sort_keys=True), flush=True)
        except Exception:
            for stream in (server_log, client_log):
                stream.flush()
                stream.seek(0)
                print(f"UDP {mode} Xray diagnostics:\n"+stream.read()[-14000:], flush=True)
            raise
        finally:
            for tcp, udp, _ in associations:
                tcp.close()
                udp.close()
            for proc in (client, server):
                if proc is not None and proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
            server_log.close()
            client_log.close()
            echo.shutdown()
            echo.server_close()


if __name__ == "__main__":
    assert len(sys.argv) == 2
    binary = str(Path(sys.argv[1]).resolve())
    for xudp in (False, True):
        print(f"START REAL VLESS UDP TEST: {'xudp' if xudp else 'udp'}", flush=True)
        run(binary, xudp)
