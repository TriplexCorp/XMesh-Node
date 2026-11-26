#!/usr/bin/env python3
"""Disposable real-systemd containment qualification, not an ingress launcher.

Only a loopback TLS 1.3 fixture is executed. No Xray executable, enrollment,
production state, policy signing key, cap mutation or public port is used.
The PID1 watchdog is an independent *stop* fallback when both the Python
supervisor and its pidfd guardian fail. Its interval here is independent of
(and shorter than) the artificial fixture deadline. A production supervisor
would have to choose and qualify an interval fitting every actual proof.
"""
import json
import os
from pathlib import Path
import select
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments/quota-v2-physical-stop"))
import public_tls_deadman as deadman

WATCHDOG_US = 2_000_000
LIVE_WINDOW_MS = 7_000
CI_OPT_IN = "XMESH_DISPOSABLE_TLS_SYSTEMD_TEST"
UNIT_PREFIX = "xmesh-tls-containment-ci-"


def require_hosted_ci():
    if (os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get(CI_OPT_IN) != "1"
            or Path("/proc/1/comm").read_text().strip() != "systemd"):
        raise RuntimeError("real TLS containment requires disposable hosted Linux systemd CI")


def run(*args, check=True, timeout=20):
    return subprocess.run(args, check=check, timeout=timeout, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def notify(message):
    path = os.environ.get("NOTIFY_SOCKET")
    if not path:
        raise ValueError("missing actual systemd notification socket")
    if path.startswith("@"):
        path = "\0" + path[1:]
    with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as conn:
        conn.connect(path)
        conn.sendall(message.encode("ascii"))


def listener(cert, key, gate):
    # The inherited pipe is the only startup gate in this *fixture*.
    # The gate read cannot grant anything in a production service.
    if os.read(gate, 2) != b"G":
        raise ValueError("fixture gate denied")
    os.close(gate)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(cert, key)
    with socket.socket(socket.AF_INET) as sock:
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        print(sock.getsockname()[1], flush=True)
        with sock.accept()[0] as conn, ctx.wrap_socket(conn, server_side=True) as tls:
            tls.sendall(b"proof")
            while tls.recv(1):
                tls.sendall(b"proof")


def fixture(root):
    require_hosted_ci()
    # The service cannot be mistaken for a direct Python/staging run.
    if (os.environ.get("WATCHDOG_USEC") != str(WATCHDOG_US)
            or os.environ.get("WATCHDOG_PID", str(os.getpid())) != str(os.getpid())):
        raise ValueError("service watchdog not bound to main fixture PID")
    reader, writer = os.pipe2(os.O_CLOEXEC)
    child = None
    guard = None
    try:
        child = subprocess.Popen(
            [sys.executable, str(Path(__file__).resolve()), "--listener",
             str(root/"cert.pem"), str(root/"key.pem"), str(reader)],
            pass_fds=(reader,), stdout=subprocess.PIPE, text=True,
            env={"PATH": "/usr/bin:/bin", "GITHUB_ACTIONS": "true",
                 "RUNNER_ENVIRONMENT": "github-hosted", CI_OPT_IN: "1"})
        os.close(reader)
        reader = -1
        guard = deadman.StopOnlyDeadman(child=child, timeout_ms=10_000)
        poll = select.poll()
        poll.register(child.stdout.fileno(), select.POLLIN | select.POLLHUP)
        if poll.poll(150):
            raise ValueError("fixture listener opened before guardian")
        # Simulated expiry solely for exercising containment. These numbers
        # are NOT a real authority or even a signed revocation witness.
        ends_mono = time.monotonic_ns()+LIVE_WINDOW_MS*1_000_000
        ends_wall = time.time_ns()//1_000_000+LIVE_WINDOW_MS
        guard.pulse(deadline_ns=ends_mono, wall_deadline_ms=ends_wall)
        os.write(writer, b"G")
        os.close(writer)
        writer = -1
        if not poll.poll(2000):
            raise ValueError("gated loopback listener did not start")
        port = int(child.stdout.readline())
        (root/"ready.json").write_text(json.dumps({
            "main": os.getpid(), "guardian": guard._guardian.pid,
            "listener": child.pid, "port": port,
        }))
        # Watchdog notifications are conditional on a fresh guardian ACK;
        # never use an unrelated timer/thread that continually pings PID1.
        notify("READY=1\nWATCHDOG=1")
        while True:
            time.sleep(.12)
            guard.pulse(deadline_ns=ends_mono, wall_deadline_ms=ends_wall)
            notify("WATCHDOG=1")
    finally:
        if guard is not None:
            guard.close()
        if child is not None:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=2)
            child.stdout.close()
        for fd in (reader, writer):
            if fd >= 0:
                os.close(fd)


class RealSystemdContainmentTests(unittest.TestCase):
    def setUp(self):
        # Fail, do not skip, when this mandatory CI job lacks real PID1.
        require_hosted_ci()
        self.directory = tempfile.TemporaryDirectory(prefix=UNIT_PREFIX)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.unit = UNIT_PREFIX+uuid.uuid4().hex+".service"
        self.addCleanup(self.cleanup_service)
        run("openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt",
            "ec_paramgen_curve:prime256v1", "-nodes", "-days", "1", "-subj",
            "/CN=localhost", "-keyout", str(self.root/"key.pem"),
            "-out", str(self.root/"cert.pem"))
        started = run(
            "systemd-run", "--quiet", "--unit", self.unit,
            "--property=Type=notify", "--property=NotifyAccess=main",
            "--property=WatchdogSec=2s", "--property=WatchdogSignal=SIGKILL",
            "--property=KillMode=control-group", "--property=SendSIGKILL=yes",
            "--property=TimeoutStopSec=1s", "--property=TimeoutStartSec=10s",
            "--property=Restart=no", "--property=NoNewPrivileges=yes",
            "--property=UMask=0077",
            "--setenv=GITHUB_ACTIONS=true", "--setenv=RUNNER_ENVIRONMENT=github-hosted",
            "--setenv="+CI_OPT_IN+"=1",
            sys.executable, str(Path(__file__).resolve()), "--fixture", str(self.root),
            check=False, timeout=15)
        self.assertEqual(started.returncode, 0, started.stderr)
        self.info = json.loads((self.root/"ready.json").read_text())
        self.assertEqual(set(self.info), {"main", "guardian", "listener", "port"})
        props = self.properties("MainPID", "ControlGroup", "KillMode", "WatchdogUSec",
                                "WatchdogSignal", "Restart", "NotifyAccess", "SendSIGKILL")
        self.assertEqual(int(props["MainPID"]), self.info["main"])
        self.assertEqual(props["KillMode"], "control-group")
        self.assertEqual(props["Restart"], "no")
        self.assertEqual(props["NotifyAccess"], "main")
        self.assertEqual(props["SendSIGKILL"], "yes")
        self.assertIn(props["WatchdogSignal"], ("9", "SIGKILL"))
        # systemctl's human duration formatting differs across releases;
        # the fixture independently checked WATCHDOG_USEC=2000000.
        self.assertNotIn(props["WatchdogUSec"], ("0", "infinity", "0us", ""))
        self.group = Path("/sys/fs/cgroup") / props["ControlGroup"].lstrip("/")
        self.assertTrue(props["ControlGroup"].endswith("/"+self.unit))
        self.assertTrue(self.group.is_dir())
        members = {int(x) for x in (self.group/"cgroup.procs").read_text().split()}
        self.pids = {self.info[x] for x in ("main", "guardian", "listener")}
        self.assertEqual(len(self.pids), 3)
        self.assertTrue(self.pids <= members, (self.pids, members))
        # Only signal the exact process IDs bound to this transient service.
        self.pidfds = {}
        for name in ("main", "guardian", "listener"):
            self.pidfds[name] = os.pidfd_open(self.info[name], 0)
            self.addCleanup(os.close, self.pidfds[name])
        client = ssl.create_default_context(cafile=str(self.root/"cert.pem"))
        client.minimum_version = ssl.TLSVersion.TLSv1_3
        self.wire = client.wrap_socket(
            socket.create_connection(("127.0.0.1", self.info["port"]), timeout=2),
            server_hostname="localhost")
        self.addCleanup(self.wire.close)
        self.assertEqual(self.wire.version(), "TLSv1.3")
        self.assertEqual(self.wire.recv(5), b"proof")

    def properties(self, *names):
        args = ["systemctl", "show", self.unit]
        for name in names:
            args.extend(["--property", name])
        return dict(line.split("=", 1) for line in run(*args).stdout.splitlines())

    def cleanup_service(self):
        run("systemctl", "stop", self.unit, check=False, timeout=10)
        run("systemctl", "reset-failed", self.unit, check=False)
        # Never silently leave a live fixture behind, even after an assert.
        if getattr(self, "group", None) is not None and self.group.exists():
            try:
                members = (self.group/"cgroup.procs").read_text().split()
            except FileNotFoundError:
                members = []
            self.assertFalse(members, f"leftover disposable cgroup processes: {members}")

    def send(self, name, sig):
        signal.pidfd_send_signal(self.pidfds[name], sig, None, 0)

    def assert_stopped(self, expected_result=None):
        start = time.monotonic()
        self.wire.settimeout(5)
        try:
            closed = self.wire.recv(5)
        except (ConnectionResetError, ssl.SSLEOFError):
            closed = b""
        self.assertEqual(closed, b"", "existing TLS traffic survived containment")
        with self.assertRaises(OSError):
            socket.create_connection(("127.0.0.1", self.info["port"]), timeout=1)
        until = start+5
        while time.monotonic() < until:
            props = self.properties("ActiveState", "Result")
            if props["ActiveState"] in ("failed", "inactive"):
                break
            time.sleep(.05)
        self.assertIn(props["ActiveState"], ("failed", "inactive"))
        if expected_result is not None:
            self.assertEqual(props["Result"], expected_result)
        for name, fd in self.pidfds.items():
            poll = select.poll()
            poll.register(fd, select.POLLIN | select.POLLHUP)
            self.assertTrue(poll.poll(1000), name+" survived service failure")
        self.assertLess(time.monotonic()-start, 6)

    def test_guardian_sigkill_stops_tls_and_exits_unit(self):
        self.send("guardian", signal.SIGKILL)
        self.assert_stopped()

    def test_both_frozen_require_pid1_watchdog_to_kill_entire_cgroup(self):
        # No Python user-space guardian or supervisor can run after SIGSTOP.
        # A real PID1 watchdog, NOT a cooperative cleanup, must stop traffic.
        self.send("main", signal.SIGSTOP)
        self.send("guardian", signal.SIGSTOP)
        self.assert_stopped(expected_result="watchdog")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--fixture":
        fixture(Path(sys.argv[2]))
    elif len(sys.argv) == 5 and sys.argv[1] == "--listener":
        require_hosted_ci()
        listener(sys.argv[2], sys.argv[3], int(sys.argv[4]))
    else:
        unittest.main()
