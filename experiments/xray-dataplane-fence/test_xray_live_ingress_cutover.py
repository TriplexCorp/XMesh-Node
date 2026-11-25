#!/usr/bin/env python3
"""Disposable REAL VLESS ingress A->new meter while B stays connected.

Two separately measured, signed-cap patched Xray servers use private Unix
VLESS listeners. An independent persistent frontend authenticates the UUID
and routes it to its owner's private, peer-verified metering process.
This is not yet a Nexus-scheduled calendar transition or production PASS.
"""
from contextlib import ExitStack
import hashlib
import json
import os
import pwd
import signal
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from unittest import mock

from test_xray_live_signed_cap import canonical, sign
from test_xray_patched_fence import await_socket, query_direction_counters
from test_quota_v2_xray_user_inbound_drain import (
    EchoHandler, EchoServer, connect_socks, echo_bytes, probe_echo, reserve_port
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "quota-v2-physical-stop"))
from cap_install import install_in_xray, observe_zero_meter_in_xray, fence_calendar_in_xray
from runtime_identity import trusted_runtime_identity
import vless_ingress
import public_tls_frontend

USER_A, USER_B, NODE = 83001, 83002, 4719
UUID_A = "11111111-1111-4111-8111-111111111111"
UUID_B = "22222222-2222-4222-8222-222222222222"
ACTIVATION = "7" * 64
CLASSES = ("cdn", "main")


def aliases(user):
    return [{"email": f"xmesh-u{user}--vless-{cls}", "class": cls}
            for cls in CLASSES]


def server_profile(target, ports, api_port):
    return {
        "log": {"loglevel": "warning"},
        "api": {"tag": "xmesh_stats_api",
                "listen": f"127.0.0.1:{api_port}",
                "services": ["StatsService"]},
        "stats": {},
        "policy": {"levels": {"0": {"statsUserUplink": True,
                                     "statsUserDownlink": True}}},
        "inbounds": [
            {"tag": f"vless-{cls}", "listen": "127.0.0.1",
             "port": ports[cls], "protocol": "vless",
             "settings": {"decryption": "none", "clients": [
                 {"id": UUID_A, "email": f"xmesh-u{USER_A}--vless-{cls}",
                  "level": 0},
                 {"id": UUID_B, "email": f"xmesh-u{USER_B}--vless-{cls}",
                  "level": 0},
             ]}}
            for cls in CLASSES
        ],
        "outbounds": [{
            "tag": "direct", "protocol": "freedom",
            "settings": {"finalRules": [{
                "action": "allow", "network": "tcp", "ip": ["127.0.0.1/32"],
                "port": str(target),
            }]},
        }],
    }


def client_profile(ports, socks):
    inbound, outbound, rules = [], [], []
    for user, uuid_value in ((USER_A, UUID_A), (USER_B, UUID_B)):
        for cls in CLASSES:
            tag = f"{user}-{cls}"
            inbound.append({
                "tag": tag, "listen": "127.0.0.1", "port": socks[tag],
                "protocol": "socks", "settings": {"auth": "noauth"},
            })
            outbound.append({
                "tag": tag, "protocol": "vless", "settings": {
                    "vnext": [{
                        "address": "127.0.0.1", "port": ports[cls],
                        "users": [{"id": uuid_value, "encryption": "none"}],
                    }],
                },
            })
            rules.append({
                "type": "field", "inboundTag": [tag], "outboundTag": tag,
            })
    return {"log": {"loglevel": "warning"}, "inbounds": inbound,
            "outbounds": outbound, "routing": {"rules": rules}}


def signed_pair(root, key, runtime, policy, user, epoch, meter, reservation):
    issued = time.time_ns() // 1_000_000
    nonce = os.urandom(32).hex()
    genesis = sign(root, key, b"XMESH_XRAY_GENESIS_PREPARED_V1\0", {
        "schemaVersion": 1, "kind": "xmesh.xray.genesis-prepared",
        "nodeId": NODE, "activationReceiptSha256": ACTIVATION,
        "candidateRuntimeId": runtime, "challenge": nonce,
        "preparedAtMs": issued, "validUntilMs": issued + 120_000,
        "authorizedBytes": 0, "canStart": False, "canResume": False,
    })
    claims = {
        "schemaVersion": 1, "kind": "xmesh.quota-v2.xray-cap-admission",
        "nodeId": NODE, "userId": user,
        "activationReceiptSha256": ACTIVATION,
        "runtimeId": runtime, "policySha256": policy,
        "accountEpoch": epoch, "meterEpoch": meter,
        "reservationId": reservation, "reservationRevision": 1,
        "nonce": nonce, "aliasScopes": aliases(user),
        "inventoryTailDigest": "0" * 64,
        "witnessedWalBytes": 0, "witnessedCdnBytes": 0,
        "sharedCeilingBytes": 8 * 1024 * 1024,
        "nodeCeilingBytes": 8 * 1024 * 1024,
        "cdnCeilingBytes": 2 * 1024 * 1024,
        "issuedAtMs": issued,
        "installBeforeMs": issued + 90_000,
        "validUntilMs": issued + 180_000,
        "canSpend": True, "canStart": False, "canResume": False,
        "finalMeterVerified": False, "refundableBytes": 0,
    }
    grant = sign(root, key, b"XMESH_QUOTA_V2_XRAY_CAP_ADMISSION_V1\0",
                 claims) + b"\n"
    scope = {
        "userId": user, "policySha256": policy, "accountEpoch": epoch,
        "meterEpoch": meter, "reservationId": reservation,
        "revision": 1, "nonce": nonce, "aliases": aliases(user),
    }
    return genesis, grant, scope, claims


def wait_port(port, process):
    for _ in range(120):
        if process.poll() is not None:
            raise AssertionError(f"frontend/client Xray exited: {process.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=.2):
                return
        except OSError:
            time.sleep(.1)
    raise AssertionError(f"VLESS frontend port {port} did not open")


def _namespaced_xray_pid(wrapper, binary):
    """Identify the metered Xray, not the sudo/ip-netns/runuser wrapper."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if wrapper.poll() is not None:
            raise AssertionError("isolated Xray wrapper exited")
        stack = [wrapper.pid]
        while stack:
            pid = stack.pop()
            try:
                with open(f"/proc/{pid}/task/{pid}/children", encoding="ascii") as f:
                    stack.extend(int(child) for child in f.read().split())
                if pid != wrapper.pid and os.path.samefile(f"/proc/{pid}/exe", binary):
                    return pid
            except (OSError, ValueError):
                continue
        time.sleep(.05)
    raise AssertionError("isolated Xray PID could not be independently identified")


def _namespace_echo(netns, user, echo_port, root, processes):
    """The new Xray must reach a DIFFERENT netns-local echo process."""
    source = (
        "import socketserver,sys\n"
        "class Handler(socketserver.BaseRequestHandler):\n"
        " def handle(self):\n"
        "  while True:\n"
        "   data=self.request.recv(65536)\n"
        "   if not data: return\n"
        "   self.request.sendall(data)\n"
        "class Server(socketserver.ThreadingTCPServer):\n"
        " allow_reuse_address=True\n"
        " daemon_threads=True\n"
        "Server(('127.0.0.1',int(sys.argv[1])),Handler).serve_forever()\n"
    )
    with (root/"namespace-echo.log").open("ab") as log:
        proc = subprocess.Popen(
            ["sudo", "ip", "netns", "exec", netns, "runuser", "-u",
             user, "--", "python3", "-u", "-c", source, str(echo_port)],
            stdout=log, stderr=subprocess.STDOUT)
    processes.append(proc)
    for _ in range(100):
        if proc.poll() is not None:
            raise AssertionError("isolated echo exited")
        probe = subprocess.run(
            ["sudo", "ip", "netns", "exec", netns, "python3", "-c",
             "import socket,sys; socket.create_connection(('127.0.0.1',int(sys.argv[1])),0.25).close()",
             str(echo_port)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if probe.returncode == 0:
            return
        time.sleep(.1)
    raise AssertionError("isolated echo unavailable")


def run(binary, root, echo_port, processes, netns=None, *, public_tls=False):
    ports = {cls: reserve_port() for cls in CLASSES}
    socks = {f"{u}-{c}": reserve_port() for u in (USER_A, USER_B) for c in CLASSES}
    profile = server_profile(echo_port, ports, reserve_port())
    client_config = client_profile(ports, socks)
    if public_tls:
        # The one-off fixture pins its self-signed local test certificates.
        # These hostnames MUST NEVER be installed: production validates exact
        # Certbot lineages and the certificate chain independently.
        for outbound in client_config["outbounds"]:
            cls = outbound["tag"].rsplit("-", 1)[-1]
            outbound["streamSettings"] = {
                "network": "tcp", "security": "tls",
                "tlsSettings": {"serverName": f"{cls}.quota-test.example.com"},
            }
    else:
        frontend = vless_ingress.frontend(profile)
        frontend["log"] = {"loglevel": "warning"}
        (root/"frontend.json").write_bytes(canonical(frontend))
    (root/"client.json").write_bytes(canonical(client_config))
    policy_sha = hashlib.sha256(canonical(profile)).hexdigest()
    key = root/"nexus-key.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519",
                    "-out", str(key)], check=True)
    pub = subprocess.check_output(["openssl", "pkey", "-in", str(key),
                                   "-pubout", "-outform", "DER"])
    assert len(pub)==44
    binding = root/"binding.json"
    binding.write_bytes(canonical({
        "nodeId": NODE, "activationReceiptSha256": ACTIVATION,
        "policyPublicKey": pub[-32:].hex(),
    }))
    binding.chmod(0o600)
    ingress_state = root/"ingress-state"
    ingress_state.mkdir(mode=0o700)
    backend = {}
    for generation in (1, 2, 3):
        ledger = root/f"ledger-{generation}"
        ledger.mkdir(mode=0o700)
        private = json.loads(json.dumps(profile))
        private["api"]["listen"] = f"127.0.0.1:{reserve_port()}"
        if generation != 1:
            for inbound in private["inbounds"]:
                inbound.pop("port")
                inbound["listen"] = str(root/f"unbound-{generation}-{inbound['tag']}.sock")
        (root/f"backend-{generation}.json").write_bytes(canonical(private))
        backend[generation] = {
            "ledger": ledger, "socket": root/f"control-{generation}.sock",
            "api": int(private["api"]["listen"].rsplit(":",1)[-1]),
            "env": dict(os.environ,
                GITHUB_ACTIONS="true",
                XMESH_EXPERIMENTAL_DRAIN="1",
                XMESH_QUOTA_PRIVATE_VLESS="1",
                XMESH_EXPERIMENTAL_SCOPED_INBOUNDS="vless-cdn,vless-main",
                XMESH_EXPERIMENTAL_SIGNED_CAP_BINDING=str(binding),
                XMESH_EXPERIMENTAL_OBSERVED_DIR=str(ledger),
                XMESH_EXPERIMENTAL_DRAIN_SOCKET=str(root/f"control-{generation}.sock")),
        }

    def launch(name, env):
        command = [binary, "run", "-config", str(root/f"{name}.json")]
        if netns and name == "backend-2":
            user = pwd.getpwuid(os.getuid()).pw_name
            arguments = [f"{key}={value}" for key, value in env.items()
                         if key == "GITHUB_ACTIONS" or key.startswith("XMESH_")]
            command = ["sudo", "ip", "netns", "exec", netns, "runuser",
                       "-u", user, "--", "/usr/bin/env", *arguments, *command]
        with (root/f"{name}.log").open("ab") as log:
            proc = subprocess.Popen(
                command, env=env, stdout=log, stderr=subprocess.STDOUT)
        processes.append(proc)
        return proc

    active = {}
    first = launch("backend-1", backend[1]["env"])
    await_socket(backend[1]["socket"], first)
    active[1] = (first.pid, trusted_runtime_identity(first.pid))
    if public_tls:
        # Bind a REAL disposable Ed25519 signature to the measured running
        # Xray process and original raw VLESS profile. Public listeners are
        # confined to loopback in this CI-only TLS transport rehearsal.
        issued = time.time_ns() // 1_000_000
        bindings = [
            {"tag": f"vless-{cls}", "port": ports[cls],
             "domain": f"{cls}.quota-test.example.com"}
            for cls in CLASSES
        ]
        payload = {
            "schemaVersion": 1, "kind": "xmesh.quota-v2.public-tls-ingress",
            "nodeId": NODE, "activationReceiptSha256": ACTIVATION,
            "genesisPolicySha256": "e" * 64,
            "runtimeId": active[1][1], "profileRevision": policy_sha,
            "issuedAtMs": issued, "validUntilMs": issued + 120_000,
            "canServePublic": True, "bindings": bindings,
        }
        signed = sign(root, key, b"", payload)
        frontend = public_tls_frontend.compile_signed_public_tls(
            profile, signed, node=NODE, activation=ACTIVATION,
            genesis_sha="e" * 64, runtime_id=active[1][1],
            pinned=pub[-32:].hex(), now_ms=issued)
        for inbound in frontend["inbounds"]:
            name = inbound["tag"]
            domain = next(x["domain"] for x in bindings if x["tag"] == name)
            cert = root / f"{name}-cert.pem"
            secret = root / f"{name}-key.pem"
            subprocess.run([
                "openssl", "req", "-x509", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:prime256v1",
                "-nodes", "-days", "1", "-out", str(cert),
                "-keyout", str(secret), "-subj", f"/CN={domain}",
                "-addext", f"subjectAltName=DNS:{domain}",
            ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
            # Test-only transport substitution: NEVER a signed certificate
            # admission. The independent root-owned lineage gate must run
            # before any production socket is created.
            inbound["listen"] = "127.0.0.1"
            record = inbound["streamSettings"]["tlsSettings"]["certificates"][0]
            record["certificateFile"] = str(cert)
            record["keyFile"] = str(secret)
            # Xray v26.10.31 removed allowInsecure. Trust only the exact
            # ephemeral leaf certificate issued for this disposable local
            # test; no global certificate verification bypass is permitted.
            cert_der = subprocess.check_output([
                "openssl", "x509", "-in", str(cert), "-outform", "DER",
            ], timeout=15)
            fingerprint = hashlib.sha256(cert_der).hexdigest()
            for outbound in client_config["outbounds"]:
                if outbound["tag"].rsplit("-", 1)[-1] == name.removeprefix("vless-"):
                    outbound["streamSettings"]["tlsSettings"][
                        "pinnedPeerCertSha256"] = fingerprint
        assert all(
            len(out["streamSettings"]["tlsSettings"].get("pinnedPeerCertSha256", "")) == 64
            for out in client_config["outbounds"]
        ), "TLS client must pin the ephemeral certificate for each signed alias"
        (root / "client.json").write_bytes(canonical(client_config))
        frontend["log"] = {"loglevel": "warning"}
        (root / "frontend.json").write_bytes(canonical(frontend))
    # No byte budget can pass merely because a private inbound was started.
    for cls in CLASSES:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(.5)
            assert probe.connect_ex(("127.0.0.1", ports[cls])) != 0, (
                "private Xray left the original TCP listener open")
        assert Path(f"/proc/{first.pid}/root/dev/shm/xmesh-{active[1][1]}/vless-{cls}").exists()
    front = launch("frontend", dict(os.environ,
                                   GITHUB_ACTIONS="true",
                                   XMESH_QUOTA_INGRESS_STATE=str(ingress_state)))
    client = launch("client", os.environ)
    wait_port(ports["main"], front)
    wait_port(socks[f"{USER_A}-main"], client)

    def connect(user, cls):
        return connect_socks(socks[f"{user}-{cls}"], echo_port, "127.0.0.1")

    with connect(USER_A, "main") as denied:
        assert not probe_echo(denied, 1), "unsigned A traffic bypassed frontend"
    with connect(USER_B, "main") as denied:
        assert not probe_echo(denied, 1), "unsigned B traffic bypassed frontend"

    epoch = str(uuid.uuid4())
    old_meter, old_reservation = str(uuid.uuid4()), str(uuid.uuid4())
    b_meter, b_reservation = str(uuid.uuid4()), str(uuid.uuid4())

    def install(generation, user, meter, reservation):
        # Only the measured, already-started runtime is valid here. Resolving
        # future process locals eagerly would fail before successor startup.
        pid, runtime = active[generation]
        genesis, grant, scope, claims = signed_pair(
            root, key, runtime, policy_sha, user, epoch, meter, reservation)
        install_in_xray(
            str(backend[generation]["socket"]), pid, runtime, genesis, grant, scope)
        return claims

    a_old = install(1, USER_A, old_meter, old_reservation)
    b_old = install(1, USER_B, b_meter, b_reservation)
    # An installed permit is still unreachable until Agent publishes a
    # peer-verified per-user route in the root-only state directory.
    with connect(USER_A, "main") as denied:
        assert not probe_echo(denied, 1), "positive cap bypassed route publication"

    fd = os.open(ingress_state, os.O_RDONLY|os.O_DIRECTORY)
    try:
        with mock.patch.dict(os.environ, {
            "XMESH_QUOTA_V2_INGRESS_STAGING": "1",
        }):
            vless_ingress.publish(
                fd, a_old, ("a"*64, "unused", active[1][0], active[1][1]))
            vless_ingress.publish(
                fd, b_old, ("a"*64, "unused", active[1][0], active[1][1]))
    finally:
        os.close(fd)
    with ExitStack() as active_sockets:
        b = active_sockets.enter_context(connect(USER_B, "main"))
        a = active_sockets.enter_context(connect(USER_A, "main"))
        echo_bytes(b, 16384)
        echo_bytes(a, 16384)
        echo_bytes(b, 16384)
        assert query_direction_counters(binary, backend[1]["api"],
                                        f"xmesh-u{USER_B}--vless-main") == {
            "uplink": 32768, "downlink": 32768,
        }
        if public_tls:
            # Actual TLS-encrypted VLESS has been decoded by the isolated
            # frontend, crossed a per-user private Unix socket, and charged
            # by the signed measured Xray. No unsigned direct route exists.
            assert query_direction_counters(
                binary, backend[1]["api"], f"xmesh-u{USER_A}--vless-main") == {
                    "uplink": 16384, "downlink": 16384,
                }
            assert all(
                x["streamSettings"]["security"] == "tls"
                for x in frontend["inbounds"]
            )
            print("PASS: real CI-only VLESS+TLS -> private signed metered Xray; "
                  "two users accounted, unsigned clients denied. "
                  "NOT a production certificate/expiry or public-network proof.")
            return

        # A clean second Xray can run concurrently; its per-user WAL and
        # private authenticated inbound cannot touch B's in-flight stream.
        if netns:
            _namespace_echo(netns, pwd.getpwuid(os.getuid()).pw_name,
                            echo_port, root, processes)
        second = launch("backend-2", backend[2]["env"])
        await_socket(backend[2]["socket"], second)
        second_pid = (_namespaced_xray_pid(second, binary) if netns
                      else second.pid)
        active[2] = (second_pid, trusted_runtime_identity(second_pid))
        if netns:
            assert os.stat(f"/proc/{second_pid}/ns/net").st_ino != (
                os.stat(f"/proc/{first.pid}/ns/net").st_ino), (
                    "successor shares the original public frontend network namespace")
        for cls in CLASSES:
            assert not (root/f"unbound-2-vless-{cls}.sock").exists()

        fence_scope = {
            "email": aliases(USER_A)[0]["email"],
            "nodeId": NODE, "userId": USER_A, "epoch": epoch,
            "meterEpoch": old_meter, "reservationId": old_reservation,
            "revision": 1,
            "revocationId": str(uuid.uuid5(
                uuid.UUID("becd936f-23a2-5a5a-92eb-c277f259f70a"),
                old_reservation)),
        }
        fence = fence_calendar_in_xray(
            str(backend[1]["socket"]), first.pid,
            active[1][1], fence_scope)
        assert fence["fenced"] is True and fence["drained"] is True
        # The signed byte-WAL files are runtime-hashed names. Capture
        # all old user meter bytes via the inventory's authenticated aliases.
        inventory = backend[1]["ledger"]/"xmesh-meter-inventory-v1.jsonl"
        a_names = {
            json.loads(line)["filename"]
            for line in inventory.read_bytes().splitlines()
            if json.loads(line)["email"].startswith(f"xmesh-u{USER_A}--")
        }
        a_old_wal = {name:(backend[1]["ledger"]/name).read_bytes()
                     for name in a_names}
        assert len(a_old_wal)==2
        # B must still be able to send bytes on its ORIGINAL TCP stream
        # while A's epoch is retired and its new metering process starts.
        echo_bytes(b, 16384)
        a_new = install(2, USER_A, str(uuid.uuid4()), str(uuid.uuid4()))
        fd = os.open(ingress_state, os.O_RDONLY|os.O_DIRECTORY)
        try:
            with __import__("unittest").mock.patch.dict(os.environ, {
                "XMESH_QUOTA_V2_INGRESS_STAGING":"1",
            }):
                vless_ingress.publish(
                    fd, a_new,
                    ("b"*64, "unused", active[2][0], active[2][1]),
                    vless_ingress.target(active[1][0],active[1][1]))
        finally:
            os.close(fd)
        with connect(USER_A,"main") as new_a:
            echo_bytes(new_a, 16384)
        echo_bytes(b, 16384)
        assert {name:(backend[1]["ledger"]/name).read_bytes()
                for name in a_names} == a_old_wal, (
                    "old A WAL changed after epoch fence")
        new_inventory = backend[2]["ledger"]/"xmesh-meter-inventory-v1.jsonl"
        new_a_names = {
            json.loads(line)["filename"]
            for line in new_inventory.read_bytes().splitlines()
        }
        assert len(new_a_names)==2 and new_a_names.isdisjoint(a_names)
        for name in new_a_names:
            last = json.loads((backend[2]["ledger"]/name).read_bytes().splitlines()[-1])
            assert last["nextBytes"]==16384 and last["runtimeId"]==active[2][1]
        assert query_direction_counters(binary, backend[1]["api"],
                                        f"xmesh-u{USER_B}--vless-main") == {
            "uplink": 65536, "downlink": 65536,
        }
        # Calendar 2 -> 3: a THIRD independently metered Xray is admitted.
        # The original B stream must survive both of A's transitions.
        third = launch("backend-3", backend[3]["env"])
        await_socket(backend[3]["socket"], third)
        active[3] = (third.pid, trusted_runtime_identity(third.pid))
        for cls in CLASSES:
            assert not (root/f"unbound-3-vless-{cls}.sock").exists()
        second_scope = {
            "email": aliases(USER_A)[0]["email"],
            "nodeId": NODE, "userId": USER_A, "epoch": epoch,
            "meterEpoch": a_new["meterEpoch"],
            "reservationId": a_new["reservationId"],
            "revision": 1,
            "revocationId": str(uuid.uuid5(
                uuid.UUID("becd936f-23a2-5a5a-92eb-c277f259f70a"),
                a_new["reservationId"])),
        }
        second_fence = fence_calendar_in_xray(
            str(backend[2]["socket"]), active[2][0],
            active[2][1], second_scope)
        assert second_fence["fenced"] is True and second_fence["drained"] is True
        second_wal = {name:(backend[2]["ledger"]/name).read_bytes()
                      for name in new_a_names}
        a_third = install(3, USER_A, str(uuid.uuid4()), str(uuid.uuid4()))
        fd = os.open(ingress_state, os.O_RDONLY|os.O_DIRECTORY)
        try:
            with mock.patch.dict(os.environ, {
                "XMESH_QUOTA_V2_INGRESS_STAGING":"1",
            }):
                vless_ingress.publish(
                    fd, a_third,
                    ("c"*64, "unused", active[3][0], active[3][1]),
                    vless_ingress.target(active[2][0],active[2][1]))
        finally:
            os.close(fd)
        with connect(USER_A, "main") as third_a:
            echo_bytes(third_a, 16384)
        echo_bytes(b, 16384)
        assert {name:(backend[2]["ledger"]/name).read_bytes()
                for name in new_a_names} == second_wal, (
                    "second calendar WAL changed after its fence")
        third_inventory = backend[3]["ledger"]/"xmesh-meter-inventory-v1.jsonl"
        third_names = {
            json.loads(line)["filename"]
            for line in third_inventory.read_bytes().splitlines()
        }
        assert len(third_names)==2 and third_names.isdisjoint(new_a_names|a_names)
        for name in third_names:
            last = json.loads((backend[3]["ledger"]/name).read_bytes().splitlines()[-1])
            assert last["nextBytes"]==16384 and last["runtimeId"]==active[3][1]
        assert query_direction_counters(binary, backend[1]["api"],
                                        f"xmesh-u{USER_B}--vless-main") == {
            "uplink": 81920, "downlink": 81920,
        }
        # Lost publication ACK: replaying the same signed runtime/route
        # must NOT create a second lease, replace the symlink or reopen old
        # WAL. A conflicting predecessor cannot steal an existing route.
        link = f"ingress-u{USER_A}"
        fd = os.open(ingress_state, os.O_RDONLY | os.O_DIRECTORY)
        try:
            before = os.stat(link, dir_fd=fd, follow_symlinks=False)
            with mock.patch.dict(os.environ, {
                "XMESH_QUOTA_V2_INGRESS_STAGING": "1",
            }):
                vless_ingress.publish(
                    fd, a_third,
                    ("c"*64, "unused", active[3][0], active[3][1]))
                try:
                    vless_ingress.publish(
                        fd, a_new,
                        ("b"*64, "unused", active[2][0], active[2][1]))
                except ValueError:
                    pass
                else:
                    raise AssertionError("old signed epoch reclaimed new ingress")
            after = os.stat(link, dir_fd=fd, follow_symlinks=False)
            assert (before.st_dev,before.st_ino)==(after.st_dev,after.st_ino)
        finally:
            os.close(fd)
        assert first.poll() is None and second.poll() is None and third.poll() is None and front.poll() is None
        # Terminating only A's new metering runtime must fail closed for A,
        # while B's original stream continues under its first reservation.
        third.kill()
        assert third.wait(timeout=10)==-9
        with connect(USER_A,"main") as denied:
            assert not probe_echo(denied,1), "dead signed Xray granted A extra traffic"
        echo_bytes(b, 16384)
        assert query_direction_counters(binary, backend[1]["api"],
                                        f"xmesh-u{USER_B}--vless-main") == {
            "uplink":98304, "downlink":98304,
        }
        print("PASS: two-user real VLESS A calendar 1->2->3, B live stream intact; "
              "stale-generation hijack denied, third runtime SIGKILL fails closed; "
              f"successor in separate network namespace={bool(netns)}")


def main():
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("XMESH_DISPOSABLE_XRAY_PATCH_EXPERIMENT") == "1"
    if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != "--tls"):
        raise SystemExit("usage: test_xray_live_ingress_cutover.py PINNED_XRAY_BINARY [--tls]")
    public_tls = len(sys.argv) == 3
    if public_tls and os.environ.get("XMESH_QUOTA_V2_TLS_DISPOSABLE") != "1":
        raise SystemExit("TLS test requires explicitly disposable CI context")
    with tempfile.TemporaryDirectory(prefix="xmesh-live-ingress-") as tmp, EchoServer(("127.0.0.1",0), EchoHandler) as echo:
        root = Path(tmp)
        thread = threading.Thread(target=echo.serve_forever, daemon=True)
        thread.start()
        processes = []
        netns = None
        try:
            if os.environ.get("XMESH_QUOTA_V2_CROSS_NETNS") == "1":
                netns = "xmesh-qv2-" + uuid.uuid4().hex[:12]
                subprocess.run(["sudo", "ip", "netns", "add", netns], check=True)
                subprocess.run(["sudo", "ip", "-n", netns, "link",
                                "set", "lo", "up"], check=True)
            run(sys.argv[1], root, echo.server_address[1], processes, netns,
                public_tls=public_tls)
        except BaseException:
            for log in root.glob("*.log"):
                print(f"{log.name}:\\n{log.read_text(errors='replace')[-6000:]}",
                      file=sys.stderr)
            raise
        finally:
            for proc in reversed(processes):
                if proc.poll() is None:
                    proc.kill()
                proc.wait(timeout=10)
            if netns:
                # The uid-dropped Xray may survive its sudo wrapper.
                # Only this unique disposable namespace is ever cleaned.
                remaining = subprocess.run(
                    ["sudo", "ip", "netns", "pids", netns],
                    capture_output=True, text=True)
                for pid in remaining.stdout.split():
                    subprocess.run(["sudo", "kill", "-KILL", pid], check=False)
                subprocess.run(["sudo", "ip", "netns", "del", netns], check=True)
            echo.shutdown()


if __name__ == "__main__":
    main()
