#!/usr/bin/env python3
"""Real Xray process-stop canary for signed quota-v2 revocation, NOT final-meter evidence.

Runs only inside an opt-in disposable GitHub Actions worker. It uses the exact
production stop helper extracted from xmesh-xray-sync.sh; never touches an
already existing managed container. This tests physical revocation safety, not
statistical finality or refundable bytes.
"""
import contextlib
import json
import os
from pathlib import Path
import re
import socket
import socketserver
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "ghcr.io/xtls/xray-core:26.10.31"
NAME = "xmesh-managed-xray"


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
        try:
            docker(
                "run", "-d", "--name", NAME, "--restart", "unless-stopped",
                "--network", "host", "--user", "0:0", "--read-only",
                "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "-v", f"{config_file}:/etc/xray/config.json:ro",
                IMAGE, "run", "-config", "/etc/xray/config.json"
            )
            created = True
            session = wait_for_echo(port)
            print("PASS: real Xray serves traffic before revocation", flush=True)
            marker = root / "quota-revocation-deny-pending"
            marker.write_text("signed-v2-deny\n", encoding="ascii")
            os.chmod(marker, 0o600)
            script = (
                "set -Eeuo pipefail\n" + helper +
                "\nREVOCATION_MARKER=" + str(marker) + "\n" +
                '[[ -f "$REVOCATION_MARKER" ]] && stop_managed_xray_for_revocation\n'
            )
            done = cmd("bash", "-c", script)
            verify_stopped()
            assert marker.is_file(), "Stop must not clear durable revocation intent"
            print("PASS: real Xray stopped, restart policy disabled, marker retained", flush=True)
            # The old established stream must not continue delivering traffic.
            try:
                session.settimeout(4)
                session.sendall(b"still-alive?")
                received = session.recv(128)
                assert not received, "Existing Xray stream survived physical revocation"
            except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError, OSError):
                pass
            # No fresh sessions should connect once Docker reports stopped.
            with contextlib.suppress(OSError):
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    raise AssertionError("Revoked Xray accepted new connection")
            time.sleep(1)
            verify_stopped()
            # Repeated boot/reconcile should be idempotent, never auto-start.
            cmd("bash", "-c", script)
            verify_stopped()
            print("PASS: old streams terminated, new sessions refused, repeated stop idempotent", flush=True)
            print("NOTE: counters are not terminal; this test never frees reserved quota", flush=True)
        finally:
            if session is not None:
                session.close()
            if created:
                docker("rm", "-f", NAME, check=False)
            echo.shutdown()
            echo.server_close()


if __name__ == "__main__":
    run()
