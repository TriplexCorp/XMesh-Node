#!/usr/bin/env python3
"""Real loopback VLESS acceptance of the local cap handoff.

The signer here is disposable and serves only this IPC/dataplane regression.
The production Nexus/XSP/2 issuance path is outside this test.
"""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
import hashlib
import json
import os
import resource
import socket
import struct
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import uuid

from test_xray_patched_fence import await_socket, query_direction_counters
from test_quota_v2_xray_user_inbound_drain import (
    EchoHandler, EchoServer, connect_socks, echo_bytes, probe_echo, reserve_port,
)

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "quota-v2-physical-stop"))
from cap_install import fence_calendar_in_xray, install_in_xray
from first_cap_handoff import verify_grant
from runtime_identity import trusted_runtime_identity

MIB = 1024 * 1024


def canonical(doc):
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign(root, key, domain, payload):
    msg = root / "unsigned"
    msg.write_bytes(domain + canonical(payload))
    sig = subprocess.check_output([
        "openssl", "pkeyutl", "-sign", "-inkey", str(key), "-rawin", "-in", str(msg),
    ])
    return canonical({"algorithm": "Ed25519", "payload": payload, "signature": sig.hex()})


def configs(root, destination, user):
    names = ("cdn", "main")
    alias = {name: f"xmesh-u{user}--vless-{name}" for name in names}
    server_ports = {name: reserve_port() for name in names}
    client_ports = {name: reserve_port() for name in names}
    api_port = reserve_port()
    client_id = str(uuid.uuid4())
    server = {
        "log": {"loglevel": "warning"},
        "api": {"tag": "xmesh_stats_api", "listen": f"127.0.0.1:{api_port}", "services": ["StatsService"]},
        "stats": {},
        "policy": {"levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}}},
        "inbounds": [
            {"tag": f"vless-{name}", "listen": "127.0.0.1", "port": server_ports[name],
             "protocol": "vless", "settings": {"decryption": "none",
                 "clients": [{"id": client_id, "email": alias[name], "level": 0}]}}
            for name in names
        ],
        "outbounds": [{"tag": "direct", "protocol": "freedom", "settings": {"finalRules": [
            {"action": "allow", "network": "tcp", "ip": ["127.0.0.1/32"], "port": str(destination)},
        ]}}],
    }
    client = {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {"tag": f"socks-{name}", "listen": "127.0.0.1", "port": client_ports[name],
             "protocol": "socks", "settings": {"auth": "noauth"}}
            for name in names
        ],
        "outbounds": [
            {"tag": f"vless-{name}", "protocol": "vless", "settings": {"vnext": [
                {"address": "127.0.0.1", "port": server_ports[name],
                 "users": [{"id": client_id, "encryption": "none"}]}]}}
            for name in names
        ],
        "routing": {"rules": [
            {"type": "field", "inboundTag": [f"socks-{name}"], "outboundTag": f"vless-{name}"}
            for name in names
        ]},
    }
    for name, config in (("server", server), ("client", client)):
        (root / f"{name}.json").write_bytes(canonical(config))
    return alias, client_ports, api_port


def reject(sock_path, pid, runtime, genesis, grant, scope):
    try:
        install_in_xray(sock_path, pid, runtime, genesis, grant, scope)
    except ValueError as exc:
        assert "HTTP 409" in str(exc), str(exc)
    else:
        raise AssertionError("Xray installed an unauthorized or repeated grant")


def run(xray, root, target, processes, scenario):
    node, user = 4719, 8317
    digest = lambda: os.urandom(32).hex()
    activation = digest()
    key = root / "policy.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", key], check=True)
    public = subprocess.check_output(["openssl", "pkey", "-in", key, "-pubout", "-outform", "DER"])
    assert len(public) == 44
    binding = root / "binding.json"
    binding.write_bytes(canonical({"nodeId": node, "activationReceiptSha256": activation,
                                   "policyPublicKey": public[-32:].hex()}))
    binding.chmod(0o600)
    alias, ports, api_port = configs(root, target, user)
    sock_path = root / "control.sock"
    env = dict(os.environ, XMESH_EXPERIMENTAL_DRAIN="1",
               XMESH_EXPERIMENTAL_SIGNED_CAP_BINDING=str(binding),
               XMESH_EXPERIMENTAL_SCOPED_INBOUNDS="vless-cdn,vless-main",
               XMESH_EXPERIMENTAL_OBSERVED_DIR=str(root),
               XMESH_EXPERIMENTAL_DRAIN_SOCKET=str(sock_path))
    def launch(role, launch_env):
        with (root / f"{role}.log").open("a") as log:
            proc = subprocess.Popen(
                [xray, "run", "-config", str(root / f"{role}.json")],
                env=launch_env, stdout=log, stderr=subprocess.STDOUT,
            )
            processes.append(proc)
            return proc

    server = launch("server", env)
    client = launch("client", os.environ)
    await_socket(sock_path, server)
    runtime = trusted_runtime_identity(server.pid)

    def open_stream(name):
        return connect_socks(ports[name], target, "127.0.0.1")

    with open_stream("main") as sock:
        assert not probe_echo(sock), "VLESS passed before signed cap installation"

    now = time.time_ns() // 1_000_000
    genesis = sign(root, key, b"XMESH_XRAY_GENESIS_PREPARED_V1\0", {
        "schemaVersion": 1, "kind": "xmesh.xray.genesis-prepared", "nodeId": node,
        "activationReceiptSha256": activation, "candidateRuntimeId": runtime, "challenge": digest(),
        "preparedAtMs": now, "validUntilMs": now + 120_000,
        "authorizedBytes": 0, "canStart": False, "canResume": False,
    })
    # Build a real, independently Ed25519-signed quarantine policy for the
    # EXACT Xray config/client which is serving the loopback VLESS streams.
    # This is still a disposable fixture signer, NOT an enrolled Nexus issuer.
    profile = json.loads((root / "server.json").read_bytes())
    profile_sha = hashlib.sha256(canonical(profile)).hexdigest()
    genesis_doc = json.loads(genesis)
    g = genesis_doc["payload"]
    first_policy = {
        "version": 1, "kind": "xmesh.quota-v2.genesis-quarantine-policy",
        "nodeId": node, "configSha256": profile_sha,
        "issuedAtMs": now, "validUntilMs": now + 120_000,
        "users": [{
            "userId": user, "xrayId": profile["inbounds"][0]["settings"]["clients"][0]["id"],
            "offlineBudgetBytes": 0, "onHold": True,
        }],
        "quotaV2Genesis": {
            "mode": "quarantined", "runtimeId": runtime,
            "challenge": g["challenge"],
            "firstActivationReceiptSha256": activation,
            "authorizedBytes": 0, "canStart": False, "canResume": False,
            "refundableBytes": 0,
        },
    }
    policy = hashlib.sha256(canonical(first_policy)).hexdigest()
    response = {
        "status": "quarantined", "nodeId": node, "profileId": 29,
        "listen": "127.0.0.1", "port": profile["inbounds"][0]["port"],
        "revision": profile_sha, "config": profile, "policy": first_policy,
        "policySignature": json.loads(sign(root, key, b"", first_policy))["signature"],
        "policyPublicKey": public[-32:].hex(), "policySha256": policy,
        "publicIngressAllowed": False, "canStart": False, "canResume": False,
        "authorizedBytes": 0,
    }
    staged = {"prepared": genesis_doc, "reply": response}
    scope = {"userId": user, "policySha256": policy, "accountEpoch": str(uuid.uuid4()),
             "meterEpoch": str(uuid.uuid4()), "reservationId": str(uuid.uuid4()), "revision": 1,
             "nonce": digest(), "aliases": [{"email": alias[n], "class": n} for n in ("cdn", "main")]}
    claims = {
        "schemaVersion": 1, "kind": "xmesh.quota-v2.xray-cap-admission",
        "nodeId": node, "userId": user, "activationReceiptSha256": activation,
        "runtimeId": runtime, "policySha256": policy,
        "accountEpoch": scope["accountEpoch"], "meterEpoch": scope["meterEpoch"],
        "reservationId": scope["reservationId"], "reservationRevision": scope["revision"],
        "nonce": scope["nonce"], "aliasScopes": scope["aliases"], "inventoryTailDigest": "0" * 64,
        "witnessedWalBytes": 0, "witnessedCdnBytes": 0,
        "sharedCeilingBytes": 8 * MIB, "nodeCeilingBytes": 8 * MIB, "cdnCeilingBytes": 2 * MIB,
        "issuedAtMs": now,
        "installBeforeMs": now + (5_000 if scenario == "expiry" else 90_000),
        "validUntilMs": now + (8_000 if scenario == "expiry" else 180_000),
        "canSpend": True, "canStart": False, "canResume": False, "finalMeterVerified": False,
        "refundableBytes": 0,
    }
    def grant_for(fields):
        return sign(root, key, b"XMESH_QUOTA_V2_XRAY_CAP_ADMISSION_V1\0", fields) + b"\n"

    grant = grant_for(claims)
    # Unlike the older test, the scope handed to the live process is NOT a
    # self-declared fixture: it must be re-derived from the genuine signed
    # quarantine profile, original Genesis and Ed25519 cap envelope.
    derived_scope = verify_grant(grant, staged, public[-32:].hex(), runtime, now)
    assert derived_scope == scope, "signed policy did not independently bind the live VLESS clients"
    scope = derived_scope
    reject(sock_path, server.pid, runtime, genesis, grant_for(dict(claims, nodeId=node + 1)), scope)
    reject(sock_path, server.pid, runtime, genesis, grant_for(dict(claims, runtimeId=digest())), scope)
    forged = json.loads(grant)
    sig = forged["signature"]
    forged["signature"] = ("0" if sig[0] != "0" else "1") + sig[1:]
    reject(sock_path, server.pid, runtime, genesis, canonical(forged) + b"\n", scope)
    install_in_xray(sock_path, server.pid, runtime, genesis, grant, scope)
    assert (root / f"positive-cap-u{user}.json").read_bytes() == grant

    if scenario == "calendar-fence":
        # Genuine loopback VLESS from MAIN and CDN exists under ONE signed
        # reservation before the old-process barrier. The local agent will
        # only reach this IPC after verifying Nexus's ZERO-SPEND successor.
        with open_stream("main") as main, open_stream("cdn") as cdn:
            echo_bytes(main, 16384)
            echo_bytes(cdn, 16384)
            old = {p.name: p.read_bytes() for p in root.glob("meter-*.jsonl")}
            assert len(old) == 4
            old_scope = {
                "email": alias["cdn"], "nodeId": node, "userId": user,
                "epoch": scope["accountEpoch"],
                "meterEpoch": scope["meterEpoch"],
                "reservationId": scope["reservationId"],
                "revision": scope["revision"],
                "revocationId": str(uuid.uuid5(
                    uuid.UUID("becd936f-23a2-5a5a-92eb-c277f259f70a"),
                    scope["reservationId"])),
            }
            fence = fence_calendar_in_xray(
                sock_path, server.pid, runtime, old_scope)
            assert fence["drained"] is True and fence["fenced"] is True
            assert fence["finalMeterVerified"] is False and fence["refundable"] is False
            checkpoint = fence["observedCheckpoint"]
            assert checkpoint["runtimeId"] == runtime
            assert checkpoint["reservationId"] == scope["reservationId"]
            assert checkpoint["finalMeterVerified"] is False
            assert checkpoint["refundableBytes"] == 0
            assert {(row["email"], row["uplinkBytes"], row["downlinkBytes"])
                    for row in checkpoint["inboundMeters"]} == {
                        (alias["cdn"], 16384, 16384),
                        (alias["main"], 16384, 16384),
                    }
            assert not probe_echo(main, 1), "MAIN old epoch survived irreversible fence"
            assert not probe_echo(cdn, 1), "CDN old epoch survived irreversible fence"
        assert fence_calendar_in_xray(
            sock_path, server.pid, runtime, old_scope) == fence
        assert {p.name: p.read_bytes() for p in root.glob("meter-*.jsonl")} == old
        for kind in ("main", "cdn"):
            with open_stream(kind) as conn:
                assert not probe_echo(conn, 1), "new connection reopened an old signed epoch"
        reject(sock_path, server.pid, runtime, genesis, grant, scope)
        assert server.poll() is None and client.poll() is None
        print("PASS: real mixed MAIN/CDN VLESS old epoch fenced on measured PID; WAL unchanged; 0 refund/resume authority")
        return

    if scenario == "expiry":
        with open_stream("main") as sock:
            echo_bytes(sock, 16384)
            assert time.time_ns() // 1_000_000 < claims["validUntilMs"]
            wal = {p.name: p.read_bytes() for p in root.glob("meter-*.jsonl")}
            assert len(wal) == 2
            assert all(json.loads(raw.splitlines()[-1])["nextBytes"] == 16384 for raw in wal.values())
            remaining = claims["validUntilMs"] - time.time_ns() // 1_000_000
            sock.settimeout(max(0, remaining) / 1000 + 4)
            try:
                assert sock.recv(1) == b"", "expired idle VLESS stream did not close"
            except ConnectionResetError:
                pass
            assert time.time_ns() // 1_000_000 >= claims["validUntilMs"]
        reject(sock_path, server.pid, runtime, genesis, grant, scope)
        with open_stream("main") as sock:
            assert not probe_echo(sock, 1), "new VLESS stream reused an expired grant"
        assert {p.name: p.read_bytes() for p in root.glob("meter-*.jsonl")} == wal
        assert server.poll() is None and client.poll() is None
        print("PASS: live idle VLESS closed at signed expiry, preserved fsynced WAL and refused replay")
        return

    if scenario == "restart":
        with open_stream("main") as sock:
            echo_bytes(sock, 16384)
            stats = query_direction_counters(xray, api_port, alias["main"])
            assert stats == dict(uplink=16384, downlink=16384), stats
            server.kill()
            assert server.wait(timeout=10) == -9
            assert not probe_echo(sock, 1), "stopped Xray still served its existing stream"
        old_wal = {path.name: path.read_bytes() for path in root.glob("meter-*.jsonl")}
        assert len(old_wal) == 2
        assert all(json.loads(raw.splitlines()[-1])["nextBytes"] == 16384 for raw in old_wal.values())
        replacement = launch("server", env)
        wait_for_peer(sock_path, replacement)
        new_runtime = trusted_runtime_identity(replacement.pid)
        assert new_runtime != runtime
        reject(sock_path, replacement.pid, new_runtime, genesis, grant, scope)
        with open_stream("main") as sock:
            assert not probe_echo(sock, 1), "replacement served with unresolved old WAL"
        assert {path.name: path.read_bytes() for path in root.glob("meter-*.jsonl")} == old_wal
        print("PASS: SIGKILL after 32768 accounted bytes preserved the WAL and denied reuse by new Xray")
        return

    if scenario == "load":
        echoed = 0
        payload_size = 1024
        for count in (100, 500):
            with ExitStack() as active:
                sockets = []
                for _ in range(count):
                    conn = active.enter_context(open_stream("main"))
                    echo_bytes(conn, payload_size)
                    sockets.append(conn)
                # Every connection has already delivered bytes and remains
                # open until the concurrent second transfer completes.
                with ThreadPoolExecutor(max_workers=24) as traffic:
                    list(traffic.map(lambda conn: echo_bytes(conn, payload_size), sockets))
                echoed += count * payload_size * 2
                assert query_direction_counters(xray, api_port, alias["main"]) == {
                    "uplink": echoed, "downlink": echoed,
                }
                for direction in ("uplink", "downlink"):
                    identity = f"{runtime}\0{alias['main']}\0{direction}".encode()
                    path = root / f"meter-{hashlib.sha256(identity).hexdigest()}.jsonl"
                    assert json.loads(path.read_bytes().splitlines()[-1])["nextBytes"] == echoed
                print(f"PASS: {count} simultaneous VLESS streams confirmed by fsynced Xray WAL", flush=True)
        assert server.poll() is None and client.poll() is None
        return

    def renew(main_echoed, ceiling, revision, *, cdn_ceiling=2 * MIB,
              witnessed_wal=None, witnessed_cdn=None):
        index = (root / "xmesh-meter-inventory-v1.jsonl").read_bytes()
        tail = json.loads(index.splitlines()[-1])["digest"]
        timestamp = time.time_ns() // 1_000_000
        next_scope = dict(scope, nonce=digest(), revision=revision)
        renewed = grant_for(dict(
            claims, kind="xmesh.quota-v2.xray-cap-renewal",
            nonce=next_scope["nonce"], reservationRevision=revision,
            inventoryTailDigest=tail,
            witnessedWalBytes=(2 * (main_echoed + MIB) if witnessed_wal is None else witnessed_wal),
            witnessedCdnBytes=(2 * MIB if witnessed_cdn is None else witnessed_cdn),
            sharedCeilingBytes=ceiling, nodeCeilingBytes=ceiling, cdnCeilingBytes=cdn_ceiling,
            issuedAtMs=timestamp, installBeforeMs=timestamp + 90_000,
            validUntilMs=timestamp + 180_000,
        ))
        receipt = install_in_xray(sock_path, server.pid, runtime, b"", renewed, next_scope)
        assert install_in_xray(sock_path, server.pid, runtime, b"", renewed, next_scope) == receipt
        assert (root / f"positive-cap-u{user}-r{revision}.json").read_bytes() == renewed
        return renewed, next_scope

    older_renewal = None
    for name, echoed in (("cdn", MIB), ("main", 5 * MIB)):
        with open_stream(name) as sock:
            for sent in range(0, echoed, 16384):
                if name == "main" and sent == MIB:
                    older_renewal = renew(sent, 10 * MIB, 2)
                if name == "main" and sent == 3 * MIB:
                    renew(sent, 12 * MIB, 3)
                    reject(sock_path, server.pid, runtime, b"", *older_renewal)
                echo_bytes(sock, 16384)
            assert not probe_echo(sock, 1), f"{name} delivered bytes past its limit"
        direction = query_direction_counters(xray, api_port, alias[name])
        assert direction == dict(uplink=echoed, downlink=echoed), direction
        for way in ("uplink", "downlink"):
            meter_identity = f"{runtime}\0{alias[name]}\0{way}".encode()
            wal = root / f"meter-{hashlib.sha256(meter_identity).hexdigest()}.jsonl"
            assert json.loads(wal.read_bytes().splitlines()[-1])["nextBytes"] == echoed
    # The original 2MiB CDN grant is exhausted. A THIRD Ed25519-signed
    # revision, backed by a separately tested PostgreSQL top-up, explicitly
    # grants only 2MiB more CDN traffic. This must not reset previous WAL
    # or allow unlimited transfer simply because MAIN has refreshed.
    renew(5 * MIB, 16 * MIB, 4, cdn_ceiling=4 * MIB)
    with open_stream("cdn") as sock:
        for _ in range(0, MIB, 16384):
            echo_bytes(sock, 16384)
        assert not probe_echo(sock, 1), "independent CDN replenishment exceeded its signed 4MiB total"
    updated = query_direction_counters(xray, api_port, alias["cdn"])
    assert updated == dict(uplink=2 * MIB, downlink=2 * MIB), updated
    for direction in ("uplink", "downlink"):
        identity = f"{runtime}\0{alias['cdn']}\0{direction}".encode()
        wal = root / f"meter-{hashlib.sha256(identity).hexdigest()}.jsonl"
        assert json.loads(wal.read_bytes().splitlines()[-1])["nextBytes"] == 2 * MIB

    # The shared MAIN allowance still has 2 MiB free. One independent
    # signed CDN-only revision is installed with the SAME shared ceiling.
    # The extra CDN bytes are finite and accumulate on the original WAL.
    renew(5 * MIB, 16 * MIB, 5, cdn_ceiling=6 * MIB,
          witnessed_wal=14 * MIB, witnessed_cdn=4 * MIB)
    with open_stream("cdn") as sock:
        for _ in range(0, MIB, 16384):
            echo_bytes(sock, 16384)
        assert not probe_echo(sock, 1), "CDN-only revision exceeded 6 MiB class ceiling"
    updated = query_direction_counters(xray, api_port, alias["cdn"])
    assert updated == dict(uplink=3 * MIB, downlink=3 * MIB), updated
    for direction in ("uplink", "downlink"):
        identity = f"{runtime}\0{alias['cdn']}\0{direction}".encode()
        wal = root / f"meter-{hashlib.sha256(identity).hexdigest()}.jsonl"
        assert json.loads(wal.read_bytes().splitlines()[-1])["nextBytes"] == 3 * MIB

    for name in ("main", "cdn"):
        with open_stream(name) as sock:
            assert not probe_echo(sock, 1), "new VLESS stream obtained extra budget"
    reject(sock_path, server.pid, runtime, genesis, grant, scope)
    assert server.poll() is None and client.poll() is None, "quota exhaustion killed Xray"
    print("PASS: live mixed VLESS accepted independent CDN-only signed revision with unchanged 16MiB shared ceiling and 6MiB CDN, all WAL exact")


def wait_for_peer(path, process):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline and process.poll() is None:
        try:
            with socket.socket(socket.AF_UNIX) as probe:
                probe.settimeout(1)
                probe.connect(str(path))
                raw = probe.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                if struct.unpack("3i", raw)[0] == process.pid:
                    return
        except OSError:
            pass
        time.sleep(0.1)
    raise AssertionError("replacement Xray did not expose its measured control socket")


def scenario(event):
    with tempfile.TemporaryDirectory(prefix="xmesh-cap-") as tmp, EchoServer(("127.0.0.1", 0), EchoHandler) as echo:
        root = Path(tmp)
        threading.Thread(target=echo.serve_forever, daemon=True).start()
        processes = []
        try:
            run(sys.argv[1], root, echo.server_address[1], processes, event)
        except BaseException as exc:
            if isinstance(exc, subprocess.CalledProcessError):
                print(f"command stderr: {exc.stderr}", file=sys.stderr)
            for log in root.glob("*.log"):
                print(f"{log.name}:\n{log.read_text()[-3000:]}", file=sys.stderr)
            raise
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=10)
            echo.shutdown()


if __name__ == "__main__":
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("XMESH_DISPOSABLE_XRAY_PATCH_EXPERIMENT") == "1"
    scenario("renewal")
    scenario("restart")
    scenario("expiry")
    scenario("calendar-fence")
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft != resource.RLIM_INFINITY and soft < 4096:
        assert hard == resource.RLIM_INFINITY or hard >= 4096
        resource.setrlimit(resource.RLIMIT_NOFILE, (4096, hard))
    scenario("load")
