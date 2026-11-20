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
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
from runtime_identity import verify_live_runtime
from test_quota_v2_xray_user_inbound_drain import (  # noqa: E402
    EchoHandler, EchoServer, reserve_port, connect_socks as raw_connect_socks, echo_bytes,
    probe_echo,
)

EMAIL_A = "xmesh-u101--vless-share"
EMAIL_A_CDN = "xmesh-u101--vless-cdn"
EMAIL_A_UNSAFE = "xmesh-u101--vless-unsafe"
EMAIL_A_USER_KEY = "xmesh-u101"
EMAIL_B = "xmesh-u102--vless-share"
# Run a real patched-Xray process per transport. Production remains untouched.
TRANSPORTS = ("tcp", "ws", "xhttp", "xhttp-stream-up",
              "xhttp-stream-one", "mux-tcp", "tls-vision")


def make_stream_settings(transport):
    # MUX is an application-level multiplexing layer over VLESS/TCP.
    wire_transport = "tcp" if transport in ("mux-tcp","tls-vision") else transport
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
    elif transport not in ("tcp", "mux-tcp", "tls-vision"):
        raise AssertionError(f"Unsupported test transport: {transport}")
    return settings


def command(*argv, check=True):
    return subprocess.run(argv, capture_output=True, text=True,
                          timeout=15, check=check)


def query_direction_counters(xray, port, email):
    """Read BOTH real Xray StatsService directions, never guess from a sum."""
    result = command(xray, "api", "statsquery", f"--server=127.0.0.1:{port}",
                     "-pattern", f"user>>>{email}")
    stats = json.loads(result.stdout)["stat"]
    values = {}
    for item in stats:
        for suffix in ("uplink", "downlink"):
            if item["name"] == f"user>>>{email}>>>traffic>>>{suffix}":
                assert suffix not in values, (email, stats)
                value = item["value"]
                assert type(value) in (str, int) and str(value).isdecimal()
                values[suffix] = int(value)
    assert set(values) == {"uplink", "downlink"}, (email, stats)
    return values


def query_counter(xray, port, email):
    return sum(query_direction_counters(xray, port, email).values())


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


def send_raw_fence_json(path, payload, expected_status=400):
    """Send intentionally ambiguous JSON across the real root-only Xray socket."""
    request=(
        b"POST /v1/fence HTTP/1.1\r\nHost: localhost\r\n"
        b"Connection: close\r\nContent-Type: application/json\r\n"
        + f"Content-Length: {len(payload)}\r\n\r\n".encode() + payload
    )
    with socket.socket(socket.AF_UNIX) as sock:
        sock.settimeout(9)
        sock.connect(str(path))
        sock.sendall(request)
        result=bytearray()
        while True:
            data=sock.recv(4096)
            if not data:
                break
            result.extend(data)
    response=bytes(result)
    assert f" {expected_status} ".encode() in response.splitlines()[0], response
    assert b"invalid scoped request" in response, response
    return response


def await_socket(path, process):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline:
        if path.exists():
            return
        if process.poll() is not None:
            raise AssertionError(f"Patched Xray exited before Unix control socket: {process.returncode}")
        time.sleep(.1)
    raise AssertionError("Patched Xray did not start private Unix control socket")


class TLSEchoServer(EchoServer):
    """A genuine inner TLS destination, needed to exercise XTLS Vision.

    A plaintext echo cannot trigger the Vision transition toward direct
    TCP splice. We do real TLS1.3 app-data through the SOCKS -> VLESS
    Vision/TLS -> freedom chain instead of claiming a synthetic stream was
    splice-eligible.
    """
    def __init__(self, address, handler, context):
        self.tls_context = context
        super().__init__(address, handler)

    def get_request(self):
        conn, address = super().get_request()
        try:
            return self.tls_context.wrap_socket(conn, server_side=True),address
        except BaseException:
            conn.close()
            raise


def run(xray, transport, *, denied_direction=None):
    assert transport in TRANSPORTS
    assert denied_direction in (None, "uplink", "downlink")
    assert os.getenv("GITHUB_ACTIONS") == "true"
    assert os.getenv("XMESH_DISPOSABLE_XRAY_PATCH_EXPERIMENT") == "1"
    assert Path(xray).is_file()
    vision = transport == "tls-vision"
    with tempfile.TemporaryDirectory(prefix=f"xmesh-v2-{transport}-") as tmp:
        root = Path(tmp)
        assert root.stat().st_mode & 0o077 == 0
        socket_file = root / "drain.sock"
        revocation_id = str(uuid.uuid4())
        journal_file = root / ("observed-" +
                               hashlib.sha256(EMAIL_A_USER_KEY.encode()).hexdigest() + ".json")
        if vision:
            cert, key = root/"vision-tls.crt", root/"vision-tls.key"
            command("openssl","req","-x509","-nodes","-newkey","rsa:2048",
                    "-days","1","-keyout",str(key),"-out",str(cert),
                    "-subj","/CN=localhost","-addext","subjectAltName=DNS:localhost")
            key.chmod(0o600)
            server_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            server_tls.minimum_version = ssl.TLSVersion.TLSv1_3
            server_tls.load_cert_chain(str(cert),str(key))
            echo = TLSEchoServer(("127.0.0.1",0),EchoHandler,server_tls)
            client_tls = ssl.create_default_context()
            client_tls.check_hostname = False  # disposable local fixture
            client_tls.verify_mode = ssl.CERT_NONE
            client_tls.minimum_version = ssl.TLSVersion.TLSv1_3
        else:
            echo = EchoServer(("127.0.0.1",0),EchoHandler)
        threading.Thread(target=echo.serve_forever,daemon=True).start()

        def connect_socks(*args):
            connected = raw_connect_socks(*args)
            if not vision:
                return connected
            try:
                return client_tls.wrap_socket(connected,server_hostname="localhost")
            except BaseException:
                connected.close()
                raise

        def assert_rejected(port, reason):
            # A revoked real Vision route can fail during the INNER TLS
            # handshake instead of delivering a SOCKS-accepted plaintext
            # socket. Either is denial; a successful echo is not.
            try:
                denied=connect_socks(port,echo.server_address[1],"127.0.0.1")
            except OSError:
                return
            try:
                assert not probe_echo(denied),reason
            finally:
                denied.close()

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
        if vision:
            # Only the primary VLESS inbound is Vision/TLS. The secondary
            # CDN inbound remains ordinary VLESS TCP to verify canonical
            # per-user revocation spans both metering paths.
            server_config["inbounds"][0]["streamSettings"] = {
                "network":"tcp","security":"tls",
                "tlsSettings":{
                    "minVersion":"1.3",
                    "certificates":[{
                        "certificateFile":str(cert),
                        "keyFile":str(key),
                    }],
                },
            }
            for registered in server_config["inbounds"][0]["settings"]["clients"][:2]:
                registered["flow"]="xtls-rprx-vision"

        def outbound(tag, identity, *, cdn=False, unsafe=False):
            destination = unsafe_port if unsafe else (cdn_port if cdn else vless_port)
            config = {"tag":tag,"protocol":"vless","settings":{"vnext":[{
                "address":"127.0.0.1","port":destination,
                "users":[{"id":identity,"encryption":"none"}]}]},
                "streamSettings":make_stream_settings("tcp" if (cdn or unsafe) else transport)}
            if vision and not (cdn or unsafe):
                config["streamSettings"] = {
                    "network":"tcp","security":"tls",
                    "tlsSettings":{"serverName":"localhost","allowInsecure":True,
                                   "minVersion":"1.3"},
                }
                if tag in ("user-a","user-b"):
                    config["settings"]["vnext"][0]["users"][0]["flow"] = "xtls-rprx-vision"
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
        if denied_direction is not None:
            # Real VLESS user A has one mandatory stats direction disabled.
            # B stays correctly metered on a distinct Xray policy level.
            # Neither A nor A's CDN alias may transmit uncharged bytes.
            server_config["policy"]["levels"]["1"] = dict(
                server_config["policy"]["levels"]["0"])
            server_config["policy"]["levels"]["0"][
                "statsUser" + denied_direction.capitalize()] = False
            server_config["inbounds"][0]["settings"]["clients"][1]["level"] = 1
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
            if denied_direction is not None:
                # Exercise BOTH dispatch paths on the real patched binary:
                # main VLESS and secondary CDN VLESS. A completed SOCKS
                # handshake alone is insufficient; reject echoed payload.
                for socks_port in (socks_a, socks_cdn):
                    try:
                        denied = connect_socks(
                            socks_port, echo.server_address[1], "127.0.0.1")
                    except (OSError, AssertionError):
                        pass
                    else:
                        try:
                            assert not probe_echo(denied), (
                                "Unmetered authenticated VLESS traffic escaped "
                                "the admission gate: " + denied_direction)
                        finally:
                            denied.close()
                # Policy mismatch for A must not deny independently metered B.
                b = connect_socks(socks_b, echo.server_address[1], "127.0.0.1")
                echo_bytes(b, 2048)
                assert wait_counter(xray, api_port, EMAIL_B) > 0
                print("EXPERIMENTAL XRAY METER COVERAGE " + json.dumps({
                    "deniedDirection": denied_direction,
                    "unmeteredMainDenied": True,
                    "unmeteredCDNDenied": True,
                    "independentMeteredUserAllowed": True,
                    "finalMeterVerified": False, "refundableBytes": 0,
                }, sort_keys=True), flush=True)
                return
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
            # A JSON parser that accepts duplicate keys could fence real
            # user A under a forged user B reservation. Invalid requests
            # must NOT create an on-disk fence, stop either live stream,
            # or record any pretend final-meter observations.
            canonical_request=json.dumps(test_lease_scope(
                EMAIL_A,revocation_id),separators=(",",":")).encode()
            assert b'"userId":101' in canonical_request
            assert b'"email":"xmesh-u101--vless-share"' in canonical_request
            invalid_requests=(
                canonical_request.replace(
                    b'"userId":101',b'"userId":102,"userId":101',1),
                canonical_request.replace(
                    b'"email":"xmesh-u101--vless-share"',
                    b'"email":"xmesh-u102--vless-share","email":"xmesh-u101--vless-share"',1),
                canonical_request.replace(b'"userId":101',b'"userId":102',1),
                canonical_request + b'{}',
                canonical_request.replace(b'"revision":7',
                                          b'"revision":7,"finalMeterVerified":true',1),
            )
            pre_fence_path=root/("fence-"+
                hashlib.sha256(EMAIL_A_USER_KEY.encode()).hexdigest()+".json")
            for forged in invalid_requests:
                assert forged!=canonical_request,"invalid request fixture was unchanged"
                send_raw_fence_json(socket_file,forged)
                assert not pre_fence_path.exists(), "bad JSON committed durable stop"
                assert not journal_file.exists(), "bad JSON committed observed meter"
                assert probe_echo(a) and probe_echo(b), (
                    "invalid lease scope stopped an active authenticated stream")
            proof=request_fence(socket_file,EMAIL_A,revocation_id)
            assert proof["fenced"] and proof["drained"] and proof["active"]==0,proof
            assert not proof["finalMeterVerified"] and not proof["refundable"],proof
            if vision:
                # Must have reached an authenticated, TCP-splice-PREPARABLE
                # raw-copy path. This diagnostic does NOT claim kernel
                # splice occurred or that all Xray background writers ended.
                assert proof["bufferedSpliceCandidates"] > 0, (
                    "Vision/TLS fixture did not exercise the raw-splice candidate path",
                    proof)
            observation=proof["observedCheckpoint"]
            assert verify_live_runtime(observation, server.pid), (
                "Observed Xray runtime is not independently tied to the live host PID")
            try:
                verify_live_runtime(observation, client.pid)
            except ValueError:
                pass
            else:
                raise AssertionError("Client PID substituted for measured server PID")
            assert observation["email"] == EMAIL_A
            assert observation["revocationId"] == revocation_id
            for k, v in test_lease_scope(EMAIL_A,revocation_id).items():
                assert observation[k] == v, (k,observation)
            assert len(observation["runtimeId"]) == 64
            assert observation["schemaVersion"] == 3
            assert observation["drained"] and not observation["finalMeterVerified"]
            assert observation["refundableBytes"] == 0
            assert [m["email"] for m in observation["inboundMeters"]] == sorted(
                [EMAIL_A, EMAIL_A_CDN]), observation
            assert (observation["uplinkBytes"] + observation["downlinkBytes"]) >= before_a + before_cdn, (
                "Observed checkpoint silently omitted the independently billed CDN email", observation,
                before_a, before_cdn
            )
            assert journal_file.is_file(), "No durable experimental Xray journal"
            assert journal_file.stat().st_mode & 0o077 == 0
            observed_disk=json.loads(journal_file.read_text())
            assert observed_disk==observation,(observed_disk,observation)
            assert not probe_echo(a),"Old VLESS-A socket survived fenced process-close"
            assert not probe_echo(cdn),"Old CDN inbound stream survived user fence"
            if a2 is not None:
                assert not probe_echo(a2),"Second MUX child survived user fence"
            assert_rejected(socks_a,"Fenced user opened new authenticated stream")
            assert_rejected(socks_cdn,"Revoked user reopened secondary CDN inbound")
            # The disposable billable VLESS inbound must reject an
            # authenticated user lacking a stable accounting identity.
            # The independent management API inbound must remain usable.
            assert_rejected(socks_blank,"Blank VLESS email bypassed per-user gate")
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
            # A completed tracked read/write drain should NOT permit a late
            # counter update on EITHER signed main/CDN inbound when other
            # users continue transferring on the same shared Xray process.
            # This checks a finite observation window, NOT terminality:
            # uninstrumented background writers and a future restart remain
            # outside the proof. Production refunds MUST stay prohibited.
            expected_meter = {
                row["email"]: {
                    "uplink": row["uplinkBytes"],
                    "downlink": row["downlinkBytes"],
                }
                for row in observation["inboundMeters"]
            }
            assert set(expected_meter) == {EMAIL_A, EMAIL_A_CDN}, expected_meter
            for sample_index in range(3):
                # The control plane and unrelated billable user B remain live.
                # B sends new real echo traffic across each sample.
                echo_bytes(b, 2048)
                for email in sorted(expected_meter):
                    actual = query_direction_counters(xray, api_port, email)
                    assert actual == expected_meter[email], (
                        "Real Xray metered bytes changed AFTER completed fence drain",
                        transport, sample_index, email, expected_meter[email],
                        actual, observation,
                    )
                time.sleep(0.07)
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
                status=400 if "userId" in wrong else 409
                mismatch = request_fence(socket_file,EMAIL_A,revocation_id,
                                         expected_status=status,scope_override=wrong)
                expected=b"invalid scoped request" if status==400 else b"durable fence"
                assert expected in mismatch, (wrong,mismatch)
            assert json.loads(journal_file.read_text())==observation
            assert server.poll() is None,"Xray server exited during selective fence"
            # The real upstream StatsService --reset endpoint calls Counter.Set.
            # Its direct user-byte mutation bypasses dispatcher read/write
            # wrappers, and MUST first fsync a durable discontinuity marker.
            taint_file=root/("taint-"+hashlib.sha256(EMAIL_A_USER_KEY.encode()).hexdigest()+".json")
            assert not taint_file.exists()
            raw_name=f"user>>>{EMAIL_A}>>>traffic>>>uplink"
            reset=command(xray,"api","stats",f"--server=127.0.0.1:{api_port}",
                          "-name",raw_name,"-reset")
            reset_value=json.loads(reset.stdout)["stat"]
            assert reset_value["name"]==raw_name and int(reset_value["value"])>0, reset_value
            assert taint_file.is_file() and taint_file.stat().st_mode&0o077==0
            taint_disk=taint_file.read_bytes()
            taint=json.loads(taint_disk)
            assert taint=={"schemaVersion":1,"canonicalUser":EMAIL_A_USER_KEY},taint
            # A second reset (Set(0) on already zero) must not remove evidence.
            command(xray,"api","stats",f"--server=127.0.0.1:{api_port}",
                    "-name",raw_name,"-reset")
            assert taint_file.read_bytes()==taint_disk
            poisoned=request_fence(socket_file,EMAIL_A,revocation_id,
                                   expected_status=409)
            assert b"unsafe Xray StatsService counter mutation or reset" in poisoned,poisoned
            assert json.loads(journal_file.read_text())==observation
            # User B has a different accounting identity, and remains served.
            assert probe_echo(b),"Raw StatsService reset for A blocked unrelated user B"

            # Data remains after shutting down the Xray process: this
            # verifies persistence, not a terminal-byte correctness barrier.
            server.terminate()
            server.wait(timeout=5)
            assert json.loads(journal_file.read_text())==observation
            assert taint_file.read_bytes()==taint_disk
            if transport=="tcp":
                # A truly new Linux Xray PID + StatsService starts from the
                # old *signed-config test fixture*, without any user-A bytes.
                # Recovery must restore root-private taint before admission;
                # otherwise the identical old checkpoint might look valid.
                server=subprocess.Popen([xray,"run","-config",str(server_json)],
                                        stdout=log_a,stderr=subprocess.STDOUT,env=env)
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    if server.poll() is not None:
                        raise AssertionError("Xray refused a valid post-taint restart")
                    try:
                        with socket.socket(socket.AF_UNIX) as probe:
                            probe.settimeout(.5)
                            probe.connect(str(socket_file))
                        break
                    except OSError:
                        time.sleep(.1)
                else:
                    raise AssertionError("Xray did not restore its private listener")
                assert taint_file.read_bytes()==taint_disk
                post_restart=request_fence(socket_file,EMAIL_A,revocation_id,
                                           expected_status=409)
                assert b"unsafe Xray StatsService counter mutation or reset" in post_restart,post_restart
                old_a=connect_socks(socks_a,echo.server_address[1],"127.0.0.1")
                try:
                    assert not probe_echo(old_a),"Reboot reopened revoked A despite taint"
                finally:
                    old_a.close()
                # B must still authenticate and send data after the real
                # Xray process restart.
                deadline=time.monotonic()+12
                b_recovered=False
                while time.monotonic()<deadline and not b_recovered:
                    fresh_b=None
                    try:
                        fresh_b=connect_socks(socks_b,echo.server_address[1],"127.0.0.1")
                        b_recovered=probe_echo(fresh_b)
                    except (OSError,AssertionError,TimeoutError):
                        pass
                    finally:
                        if fresh_b is not None:
                            fresh_b.close()
                    if not b_recovered:
                        time.sleep(.2)
                assert b_recovered,"Reboot blocked unrelated user B"
                # Real Reset_=true on B runs BEFORE B is fenced. Stable
                # after-fence reads alone cannot recover the erased bytes.
                # Verify this second account is tainted without affecting A.
                b_name=f"user>>>{EMAIL_B}>>>traffic>>>uplink"
                b_prior=command(xray,"api","stats",
                                f"--server=127.0.0.1:{api_port}",
                                "-name",b_name,"-reset")
                b_stat=json.loads(b_prior.stdout)["stat"]
                assert b_stat["name"]==b_name and int(b_stat["value"])>0,b_stat
                b_key="xmesh-u102"
                b_taint=root/("taint-"+hashlib.sha256(b_key.encode()).hexdigest()+".json")
                assert b_taint.is_file() and b_taint.stat().st_mode&0o077==0
                b_taint_disk=b_taint.read_bytes()
                assert json.loads(b_taint_disk)=={
                    "schemaVersion":1,"canonicalUser":b_key},b_taint_disk
                # The pre-restart B stream is already closed; use a NEW
                # real SOCKS/VLESS session to prove B is still admitted here.
                b_pre_fence=connect_socks(socks_b,echo.server_address[1],"127.0.0.1")
                try:
                    assert probe_echo(b_pre_fence),"B was denied before its requested fence"
                finally:
                    b_pre_fence.close()
                b_revoke=str(uuid.uuid4())
                b_refusal=request_fence(socket_file,EMAIL_B,b_revoke,
                                        expected_status=409,
                                        scope_override={"userId":102})
                assert b"unsafe Xray StatsService counter mutation or reset" in b_refusal,b_refusal
                b_observed=root/("observed-"+hashlib.sha256(b_key.encode()).hexdigest()+".json")
                assert not b_observed.exists(),"B received a forged post-reset observed meter"
                assert taint_file.read_bytes()==taint_disk
                server.terminate()
                server.wait(timeout=5)
                assert taint_file.read_bytes()==taint_disk
                assert b_taint.read_bytes()==b_taint_disk
                # A second real Linux Xray incarnation must restore BOTH
                # independent fenced users and B's pre-fence taint.
                server=subprocess.Popen([xray,"run","-config",str(server_json)],
                                        stdout=log_a,stderr=subprocess.STDOUT,env=env)
                deadline=time.monotonic()+15
                while time.monotonic()<deadline:
                    if server.poll() is not None:
                        raise AssertionError("Xray lost crash-safe pre-fence B taint")
                    try:
                        with socket.socket(socket.AF_UNIX) as probe:
                            probe.settimeout(.5)
                            probe.connect(str(socket_file))
                        break
                    except OSError:
                        time.sleep(.1)
                else:
                    raise AssertionError("Xray did not restore both users' durable fences")
                b_restart=request_fence(socket_file,EMAIL_B,b_revoke,
                                        expected_status=409,
                                        scope_override={"userId":102})
                assert b"unsafe Xray StatsService counter mutation or reset" in b_restart,b_restart
                assert b_taint.read_bytes()==b_taint_disk
                server.terminate()
                server.wait(timeout=5)
            report={
                "patchedXray":"a4a3dff5b20c2faae567b742c172c7b95e75c083",
                "testedTransport":transport,
                "simultaneousMuxChildrenStopped":transport == "mux-tcp",
                "userAFenced":True,"existingUserAStreamEnded":True,
                "newUserAStreamsRejected":True,
                "secondaryCDNInboundRevoked":True,
                "distinctSignedInboundEmailsShareUserFence":True,
                "observedSnapshotAggregatesSeenMainAndCDNEmails":True,
                "observedSnapshotStillNonfinalAndNotCompleteSignedScope":True,
                "unlistedBillableInboundDenied":True,
                "blankVlessEmailRejected":True,
                "existingUserBStreamSurvived":True,"newUserBStreamsAccepted":True,
                "statsServiceStillAvailable":True,
                "userABeforeFenceBytes":before_a,"userAAfterFenceBytes":after_a,
                "userBAfterFenceBytes":after_b,
                "boundedPostDrainMainCDNBytesStable":True,
                "realStatsServiceResetDurablyTainted":True,
                "realStatsServiceResetReplayDenied":True,
                "realStatsServiceTaintSurvivedExit":True,
                "realXrayRestartRestoresTaint":transport=="tcp",
                "realPreFenceStatsResetAndRestartFailClosed":transport=="tcp",
                "boundedStabilityStillNotTerminalMeter":True,
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
    # Mandatory directions are checked against real Xray policy, not only
    # against test-only Go booleans. Keep this isolated and cheap (TCP only).
    for direction in ("uplink", "downlink"):
        print(f"START PATCHED XRAY DISABLED {direction.upper()} STATS", flush=True)
        run(binary, "tcp", denied_direction=direction)
