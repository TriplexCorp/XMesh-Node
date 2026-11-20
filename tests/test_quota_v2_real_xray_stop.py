#!/usr/bin/env python3
"""Real Xray process-stop canary for signed quota-v2 revocation, NOT final-meter evidence.

Runs only inside an opt-in disposable GitHub Actions worker. It uses the exact
production stop helper extracted from xmesh-xray-sync.sh; never touches an
already existing managed container. This tests physical revocation safety, not
statistical finality or refundable bytes.
"""
import contextlib
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "ghcr.io/xtls/xray-core:26.10.31"
NAME = "xmesh-managed-xray"

# Keep the exact SAME OldXrayProbe class across the physical-stop and
# signed-stop-chain modules; importing a second copy would break this binding.
sys.path.insert(0, str(ROOT / "experiments/quota-v2-physical-stop"))
import attestor
import stop_chain
import journal_integrity
import sign_observation as observed
import runtime_identity


def cmd(*argv, check=True):
    return subprocess.run(argv, check=check, capture_output=True, text=True, timeout=55)


def docker(*argv, check=True):
    return cmd("docker", *argv, check=check)


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data = self.request.recv(4096)
            if not data:
                return
            self.request.sendall(data)


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def empty_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_echo(port, timeout=12):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=1)
            sock.settimeout(4)
            sock.sendall(b"xmesh-quota-v2-live-stop")
            if sock.recv(128) == b"xmesh-quota-v2-live-stop":
                return sock
            sock.close()
        except (OSError, AssertionError):
            time.sleep(0.2)
    raise AssertionError("Managed real Xray did not pass live TCP echo before revocation")


def stop_helper():
    source = (ROOT / "deploy/xmesh-xray-sync.sh").read_text(encoding="utf-8")
    found = re.search(
        r"(?ms)^stop_managed_xray_for_revocation\(\) \{\n.*?^\}\n", source
    )
    assert found, "Production signed-revocation stop function missing"
    return found.group()


def verify_stopped():
    raw = docker(
        "inspect", "-f",
        "{{.State.Running}} {{.HostConfig.RestartPolicy.Name}}", NAME
    ).stdout.strip()
    assert raw == "false no", f"Revoked Xray still runnable via Docker restart: {raw!r}"


def synthetic_signed_observation_fixture(root, host_pid, xray_journal):
    """Signature-chain canary only: bytes and policy approval are SYNTHETIC.

    This tests the exact live PID/process -> immutable Node Ed25519 receipt ->
    old PID stop transition, NOT Xray StatsService byte accuracy, complete
    committed production policy, or any entitlement to quota refunds.
    """
    observed_dir, stopped_dir = root / "observed", root / "stopped"
    observed_dir.mkdir(mode=0o700)
    stopped_dir.mkdir(mode=0o700)
    key, pub = root / "fixture-node.key", root / "fixture-node.pub"
    cmd("openssl", "genpkey", "-algorithm", "Ed25519",
        "-out", str(key))
    os.chmod(key, 0o600)
    cmd("openssl", "pkey", "-in", str(key), "-pubout",
        "-out", str(pub))
    email = "xmesh-u101--test-quota-v2"
    checkpoint = {
        "schemaVersion": 3,
        "email": email, "nodeId": 9, "userId": 101,
        "epoch": "11111111-1111-4111-8111-111111111111",
        "meterEpoch": "22222222-2222-4222-8222-222222222222",
        "reservationId": "33333333-3333-4333-8333-333333333333",
        "revision": 3,
        "revocationId": "44444444-4444-4444-8444-444444444444",
        "runtimeId": runtime_identity.trusted_runtime_identity(host_pid),
        "uplinkBytes": 0, "downlinkBytes": 0,
        "inboundMeters": [{
            "email": email, "uplinkBytes": 0, "downlinkBytes": 0}],
        "drained": True, "finalMeterVerified": False,
        "refundableBytes": 0,
    }
    signed = {
        "schemaVersion": 2, "kind": observed.KIND, "nodeId": 9,
        "checkpoint": checkpoint,
        "checkpointSha256": hashlib.sha256(
            observed.canonical(checkpoint)).hexdigest(),
        "boundToCommittedPolicy": True,
        "completeSignedInboundScopeObserved": True,
        "liveRuntimeIndependentlyVerified": True,
        "monotonicLedgerFloorVerified": True,
        "durableAbsoluteFloorBytes": 0,
        "finalMeterVerified": False,
        "settlementEligible": False, "refundableBytes": 0,
    }
    envelope = {
        "algorithm": "Ed25519", "payload": signed,
        "signature": observed.sign_bytes(
            key, observed.DOMAIN + observed.canonical(signed))}
    dfd = observed.private_directory(observed_dir)
    try:
        observed.append_only(
            dfd, observed.receipt_name(checkpoint),
            observed.canonical(envelope) + b"\n")
    finally:
        os.close(dfd)
    # This published-Xray canary does NOT instrument StatsService. Write a
    # plainly synthetic Go-format journal to test the mount/verification
    # chain only; the real byte accounting path is tested separately by
    # the pinned patched-Xray CI, and cannot become terminal by this fixture.
    stem=hashlib.sha256(b"xmesh-u101").hexdigest()
    fence={field:checkpoint[field] for field in journal_integrity.FIELDS}
    fence["schemaVersion"]=1
    observed_record={
        field:checkpoint[field] for field in journal_integrity.CHECKPOINT}
    for prefix,record in (("fence-",fence),("observed-",observed_record)):
        target=xray_journal/(prefix+stem+".json")
        target.write_bytes(journal_integrity._canonical_go(record))
        target.chmod(0o600)
    return checkpoint, observed_dir, stopped_dir, key, pub


def run():
    assert os.getenv("GITHUB_ACTIONS") == "true", "Use a disposable GitHub Actions worker"
    assert os.getenv("XMESH_DISPOSABLE_XRAY_CANARY") == "1", "Explicit disposable canary opt-in required"
    docker("info")
    assert docker("inspect", NAME, check=False).returncode != 0, (
        "Refusing to touch a pre-existing managed Xray container"
    )
    helper = stop_helper()
    with tempfile.TemporaryDirectory(prefix="xmesh-v2-real-stop-") as path:
        root = Path(path)
        xray_journal = root / "xray-synthetic-meter-fixture"
        xray_journal.mkdir(mode=0o700)
        echo = EchoServer(("127.0.0.1", 0), Echo)
        thread = threading.Thread(target=echo.serve_forever, daemon=True)
        thread.start()
        port = empty_port()
        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "tag": "test-quota-v2", "listen": "127.0.0.1", "port": port,
                "protocol": "dokodemo-door",
                "settings": {
                    "address": "127.0.0.1", "port": echo.server_address[1],
                    "network": "tcp"
                }
            }],
            "outbounds": [{"protocol": "freedom"}]
        }
        config_file = root / "config.json"
        config_file.write_text(json.dumps(config), encoding="utf-8")
        os.chmod(config_file, 0o644)  # Disposable fixture; contains no credentials
        docker(
            "run", "--rm", "--network", "none",
            "-v", f"{config_file}:/etc/xray/config.json:ro",
            IMAGE, "run", "-test", "-config", "/etc/xray/config.json"
        )
        created = False
        session = None
        stop_probe = None
        signed_chain = None
        try:
            docker(
                "run", "-d", "--name", NAME, "--restart", "unless-stopped",
                "--network", "host", "--user", "0:0", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "-v", f"{config_file}:/etc/xray/config.json:ro",
                "-v", f"{xray_journal}:{journal_integrity.JOURNAL_DEST}:rw",
                IMAGE, "run", "-config", "/etc/xray/config.json"
            )
            created = True
            session = wait_for_echo(port)
            print("PASS: real Xray serves traffic before revocation", flush=True)
            # Exercise the EXACT production marker publication helper:
            # file fsync, exclusive atomic hardlink, parent directory fsync.
            marker = root / "quota-revocation-deny-pending"
            production_marker_helper = ROOT / "deploy/xmesh-quota-revocation-marker.py"
            def durable_marker(operation):
                return cmd(sys.executable, str(production_marker_helper), operation, str(root))
            assert durable_marker("status").stdout.strip() == "clear"
            durable_marker("arm")
            assert marker.stat().st_mode & 0o077 == 0
            assert marker.read_bytes() == b"signed-v2-deny\n"
            marker_inode = marker.stat().st_ino
            assert durable_marker("status").stdout.strip() == "armed"
            stop_probe = attestor.begin_old_xray_probe()
            cp, observed_dir, stopped_dir, test_key, test_pub = (
                synthetic_signed_observation_fixture(root, stop_probe.old_pid, xray_journal))
            signed_chain = stop_chain.prepare_old_process_stop(
                stop_probe, cp, observed_dir, 9, test_pub, xray_journal)
            script = (
                "set -Eeuo pipefail\n" + helper +
                "\nREVOCATION_MARKER=" + str(marker) + "\n" +
                '[[ -f "$REVOCATION_MARKER" ]] && stop_managed_xray_for_revocation\n'
            )
            done = cmd("bash", "-c", script)
            verify_stopped()
            physical_stop = attestor.verify_old_xray_physically_stopped(
                stop_probe, root, production_marker_helper)
            assert physical_stop["oldPidfdExited"] is True
            assert physical_stop["managedContainerStopped"] is True
            assert physical_stop["durableDenyArmed"] is True
            assert physical_stop["restartDisabled"] is True
            assert physical_stop["finalMeterVerified"] is False
            assert physical_stop["settlementEligible"] is False
            assert physical_stop["refundableBytes"] == 0
            linked = stop_chain.complete_old_process_stop(
                signed_chain, root, production_marker_helper,
                observed_dir, stopped_dir, test_key, test_pub)
            linked_again = stop_chain.complete_old_process_stop(
                signed_chain, root, production_marker_helper,
                observed_dir, stopped_dir, test_key, test_pub)
            assert linked == linked_again
            raw_original = (observed_dir / observed.receipt_name(cp)).read_bytes()
            chained = stop_chain.verify_stop_chain(
                linked, raw_original, 9, test_pub)
            assert chained["oldContainerId"] == physical_stop["oldContainerId"]
            assert chained["oldStartedAt"] == physical_stop["oldStartedAt"]
            assert chained["oldRuntimeId"] == cp["runtimeId"]
            assert chained["finalMeterVerified"] is False
            assert chained["settlementEligible"] is False
            assert chained["refundableBytes"] == 0
            print("PASS: synthetic signed observation chained to same stopped Xray PID; NONFINAL", flush=True)
            assert marker.is_file(), "Stop must not clear durable revocation intent"
            print("PASS: real Xray stopped, restart policy disabled, marker retained", flush=True)
            # The old established stream must not continue delivering traffic.
            try:
                session.settimeout(4)
                session.sendall(b"still-alive?")
                received = session.recv(128)
                assert not received, "Existing Xray stream survived physical revocation"
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
                pass
            except socket.timeout as exc:
                raise AssertionError("Revoked Xray left old connection open and stalled") from exc
            # No fresh sessions should connect once Docker reports stopped.
            with contextlib.suppress(OSError):
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    raise AssertionError("Revoked Xray accepted new connection")
            time.sleep(1)
            verify_stopped()
            # A previously committed marker must be re-synced, not replaced,
            # when the same signed revocation is replayed after a restart.
            durable_marker("arm")
            assert marker.stat().st_ino == marker_inode
            assert durable_marker("status").stdout.strip() == "armed"
            # Repeated boot/reconcile should be idempotent, never auto-start.
            cmd("bash", "-c", script)
            verify_stopped()
            print("PASS: old streams terminated, new sessions refused, repeated stop idempotent", flush=True)
            print("NOTE: counters are not terminal; this test never frees reserved quota", flush=True)
        finally:
            if stop_probe is not None:
                stop_probe.close()
            if session is not None:
                session.close()
            if created:
                docker("rm", "-f", NAME, check=False)
            echo.shutdown()
            echo.server_close()


if __name__ == "__main__":
    run()
