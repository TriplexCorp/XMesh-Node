#!/usr/bin/env python3
"""Independent Linux pidfd deadman: real processes, no public listener."""
import os
from pathlib import Path
from unittest import mock
import select
import socket
import ssl
import tempfile
import signal
import subprocess
import sys
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments/quota-v2-physical-stop"))
import public_tls_deadman as deadman


def dead(child):
    try:
        return child.poll() is not None
    except ChildProcessError:
        return True


def proc_gone_or_zombie(pid):
    try:
        stat = Path(f"/proc/{pid}/stat").read_text()
        return stat[stat.rfind(")") + 1:].split()[0] == "Z"
    except (FileNotFoundError, ProcessLookupError):
        # A process may disappear after /proc lookup but before read_text.
        # ESRCH means the pidfd guardian successfully stopped it.
        return True


class LinuxStopOnlyDeadmanTests(unittest.TestCase):
    def setUp(self):
        self.child = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.addCleanup(self.clean_child)
        self.guardian = None

    def clean_child(self):
        if self.guardian is not None:
            self.guardian.close()
        if self.child.poll() is None:
            self.child.kill()
        self.child.wait(timeout=5)

    def pulse(self, lifetime_ms=20_000):
        return self.guardian.pulse(
            deadline_ns=time.monotonic_ns() + lifetime_ms*1_000_000,
            wall_deadline_ms=time.time_ns()//1_000_000 + lifetime_ms)

    def test_disappearing_proc_stat_is_already_stopped(self):
        with mock.patch.object(Path, "read_text",
                               side_effect=ProcessLookupError(3, "No such process")):
            self.assertTrue(proc_gone_or_zombie(12345))

    def test_directly_owned_live_child_can_be_guarded_but_never_authorized(self):
        self.guardian = deadman.StopOnlyDeadman(
            child=self.child, timeout_ms=950)
        self.assertIsNone(self.pulse())
        time.sleep(0.15)
        self.assertIsNone(self.pulse())
        self.assertIsNone(self.child.poll())
        # Stop pulsing: even a frozen Python monitor must not leave TLS open.
        self.assertIsNotNone(self.child.wait(timeout=3))
        self.assertLessEqual(self.guardian._guardian.wait(timeout=2), 1)

    def test_closing_heartbeat_pipe_kills_child_immediately(self):
        self.guardian = deadman.StopOnlyDeadman(
            child=self.child, timeout_ms=5000)
        started = time.monotonic()
        self.guardian.close()
        self.assertIsNotNone(self.child.wait(timeout=3))
        self.assertLess(time.monotonic() - started, 3)

    def test_killed_guardian_causes_next_monitor_pulse_to_kill_child(self):
        self.guardian = deadman.StopOnlyDeadman(
            child=self.child, timeout_ms=5000)
        os.kill(self.guardian._guardian.pid, signal.SIGKILL)
        self.guardian._guardian.wait(timeout=3)
        with self.assertRaisesRegex(ValueError, "owned child killed"):
            self.pulse()
        self.assertIsNotNone(self.child.poll())

    def test_sigstopped_guardian_cannot_fake_live_heartbeat(self):
        self.guardian = deadman.StopOnlyDeadman(
            child=self.child, timeout_ms=5_000)
        self.assertIsNone(self.pulse())
        guardian_pid = self.guardian._guardian.pid
        os.kill(guardian_pid, signal.SIGSTOP)
        try:
            started = time.monotonic()
            with self.assertRaisesRegex(ValueError, "owned child killed"):
                self.pulse()
            self.assertLess(time.monotonic() - started, 2.5)
            self.assertIsNotNone(self.child.poll())
        finally:
            # A frozen guardian cannot reap itself. Release it before the
            # fixture closes the pipes; its pinned TLS child is already dead.
            if self.guardian._guardian.poll() is None:
                os.kill(guardian_pid, signal.SIGCONT)

    def test_each_heartbeat_requires_a_fresh_guardian_ack(self):
        self.guardian = deadman.StopOnlyDeadman(
            child=self.child, timeout_ms=5_000)
        for _ in range(3):
            self.assertIsNone(self.pulse())
        self.assertIsNone(self.child.poll())
        self.assertIsNone(self.guardian._guardian.poll())

    def test_reject_foreign_popen_and_inactive_child(self):
        for invalid in (None, os.getpid(), "not a Popen"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                deadman.StopOnlyDeadman(child=invalid)
        for timeout in (0, 99, 10_001, True, 0.5):
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                deadman.StopOnlyDeadman(child=self.child, timeout_ms=timeout)
        self.child.kill()
        self.child.wait(timeout=3)
        with self.assertRaises(ValueError):
            deadman.StopOnlyDeadman(child=self.child)

    def test_signed_deadline_shorter_than_watchdog_kills_without_another_tick(self):
        self.guardian = deadman.StopOnlyDeadman(child=self.child, timeout_ms=5000)
        start = time.monotonic()
        self.assertIsNone(self.pulse(lifetime_ms=350))
        self.assertIsNone(self.child.poll())
        self.assertEqual(self.child.wait(timeout=2), -signal.SIGKILL)
        self.assertLess(time.monotonic()-start, 2)

    def test_earliest_wall_or_monotonic_deadline_wins(self):
        self.guardian = deadman.StopOnlyDeadman(child=self.child, timeout_ms=5000)
        self.guardian.pulse(deadline_ns=time.monotonic_ns()+4_000_000_000,
                            wall_deadline_ms=time.time_ns()//1_000_000+350)
        self.assertEqual(self.child.wait(timeout=2), -signal.SIGKILL)

    def test_expired_or_malformed_deadline_kills_owned_child(self):
        self.guardian = deadman.StopOnlyDeadman(child=self.child, timeout_ms=5000)
        with self.assertRaisesRegex(ValueError, "owned child killed"):
            self.guardian.pulse(deadline_ns=True, wall_deadline_ms=2**64)
        self.assertEqual(self.child.poll(), -signal.SIGKILL)

    def test_malformed_heartbeat_wire_stops_child(self):
        self.guardian = deadman.StopOnlyDeadman(child=self.child, timeout_ms=5000)
        os.write(self.guardian._writer, b"P")  # former unbounded heartbeat
        self.assertEqual(self.child.wait(timeout=2), -signal.SIGKILL)

    def test_stale_queued_pulse_cannot_resurrect_expired_guardian(self):
        self.guardian = deadman.StopOnlyDeadman(child=self.child, timeout_ms=5000)
        self.pulse(lifetime_ms=350)
        guardian_pid = self.guardian._guardian.pid
        os.kill(guardian_pid, signal.SIGSTOP)
        try:
            time.sleep(.55)
            # Another packet is already queued when the frozen guardian
            # resumes. It must check its OLD deadline before ACKing it.
            os.write(self.guardian._writer, deadman._STOP_FRAME.pack(
                time.monotonic_ns()+4_000_000_000,
                time.time_ns()//1_000_000+4000))
        finally:
            os.kill(guardian_pid, signal.SIGCONT)
        self.assertEqual(self.child.wait(timeout=2), -signal.SIGKILL)

    def test_close_with_frozen_guardian_kills_child_first(self):
        self.guardian = deadman.StopOnlyDeadman(child=self.child, timeout_ms=5000)
        os.kill(self.guardian._guardian.pid, signal.SIGSTOP)
        self.guardian.close()
        self.assertEqual(self.child.poll(), -signal.SIGKILL)

    def test_frozen_owner_loses_real_local_tls_at_signed_deadline(self):
        # Deliberately disposable, loopback only. No Xray, production key,
        # real quota, public binding or bypass of the production issuer.
        root = ROOT / "experiments/quota-v2-physical-stop"
        with tempfile.TemporaryDirectory() as tmp:
            cert, key = str(Path(tmp)/"cert.pem"), str(Path(tmp)/"key.pem")
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec",
                            "-pkeyopt", "ec_paramgen_curve:prime256v1",
                            "-nodes", "-days", "1", "-subj", "/CN=localhost",
                            "-keyout", key, "-out", cert],
                           check=True, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
            listener = """
import os,socket,ssl,sys
# A disposable startup gate: no bind or TLS setup before the owner has
# armed the guardian. This test does not supply a production launch path.
gate=int(sys.argv[3])
if os.read(gate,2)!=b'G':
    sys.exit(2)
os.close(gate)
ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version=ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(sys.argv[1],sys.argv[2])
with socket.socket() as sock:
    sock.bind(('127.0.0.1',0))
    sock.listen()
    print(sock.getsockname()[1],flush=True)
    with sock.accept()[0] as client, ctx.wrap_socket(client,server_side=True) as wire:
        wire.sendall(b'proof')
        while wire.recv(1):
            wire.sendall(b'proof')
"""
            owner_code = f"""
import os,select,subprocess,sys,time
sys.path.insert(0,{str(root)!r})
import public_tls_deadman as deadman
reader,writer=os.pipe2(os.O_CLOEXEC)
child=subprocess.Popen([sys.executable,'-c',{listener!r},{cert!r},{key!r},str(reader)],
                       pass_fds=(reader,),stdout=subprocess.PIPE,text=True)
os.close(reader)
guardian=deadman.StopOnlyDeadman(child=child,timeout_ms=10000)
poller=select.poll()
poller.register(child.stdout.fileno(),select.POLLIN|select.POLLHUP)
if poller.poll(100):
    raise RuntimeError("TLS child opened before gate")
guardian.pulse(deadline_ns=time.monotonic_ns()+2_000_000_000,
               wall_deadline_ms=time.time_ns()//1_000_000+2000)
os.write(writer,b'G')
os.close(writer)
port=child.stdout.readline().strip()
print(child.pid,guardian._guardian.pid,port,flush=True)
time.sleep(30)
"""
            owner = subprocess.Popen([sys.executable, "-c", owner_code],
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     text=True)
            pid = guard_pid = None
            try:
                poll = select.poll()
                poll.register(owner.stdout.fileno(), select.POLLIN | select.POLLHUP)
                self.assertTrue(poll.poll(4000))
                pid, guard_pid, port = map(int, owner.stdout.readline().split())
                ctx = ssl.create_default_context(cafile=cert)
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                with socket.create_connection(("127.0.0.1", port), timeout=2) as conn:
                    with ctx.wrap_socket(conn, server_hostname="localhost") as wire:
                        self.assertEqual(wire.recv(5), b"proof")
                        os.kill(owner.pid, signal.SIGSTOP)
                        wire.settimeout(4)
                        # Existing encrypted connection closes, not just the
                        # listening socket; no supervisor wakeup is required.
                        self.assertEqual(wire.recv(5), b"")
                with self.assertRaises(OSError):
                    socket.create_connection(("127.0.0.1", port), timeout=1)
                until = time.monotonic()+1
                while time.monotonic()<until and not proc_gone_or_zombie(pid):
                    time.sleep(.01)
                self.assertTrue(proc_gone_or_zombie(pid))
            finally:
                if owner.poll() is None:
                    owner.kill()
                owner.wait(timeout=3)
                for proc in (pid, guard_pid):
                    if proc is not None and not proc_gone_or_zombie(proc):
                        try:
                            os.kill(proc, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                owner.stdout.close()
                owner.stderr.close()

    def test_guardian_kills_orphan_on_parent_sigkill(self):
        root = ROOT / "experiments/quota-v2-physical-stop"
        # A separate owner process creates its own sleep child and guard;
        # killing the owner does not allow its orphan to keep serving.
        script = (
            "import subprocess,sys,time\n"
            f"sys.path.insert(0,{str(root)!r})\n"
            "import public_tls_deadman\n"
            "child=subprocess.Popen([sys.executable,'-c',"
            "'import time; time.sleep(30)'],"
            "stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)\n"
            "guardian=public_tls_deadman.StopOnlyDeadman("
            "child=child,timeout_ms=5000)\n"
            "print(child.pid,guardian._guardian.pid,flush=True)\n"
            "time.sleep(30)\n"
        )
        owner = subprocess.Popen(
            [sys.executable, "-c", script],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        pid = None
        try:
            ready = select.poll()
            ready.register(owner.stdout.fileno(), select.POLLIN | select.POLLHUP)
            self.assertTrue(ready.poll(4000), "orphan owner never became ready")
            line = owner.stdout.readline().strip()
            self.assertTrue(line, "orphan owner failed before guardian READY")
            pid, guardian_pid = map(int, line.split())
            os.kill(owner.pid, signal.SIGKILL)
            owner.wait(timeout=3)
            until = time.monotonic() + 3
            while time.monotonic() < until and not proc_gone_or_zombie(pid):
                time.sleep(0.03)
            self.assertTrue(
                proc_gone_or_zombie(pid),
                "orphaned TLS child survived loss of its guardian owner")
        finally:
            if owner.poll() is None:
                owner.kill()
            owner.wait(timeout=3)
            if pid is not None and not proc_gone_or_zombie(pid):
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            if owner.stdout is not None:
                owner.stdout.close()
            if owner.stderr is not None:
                owner.stderr.close()


if __name__ == "__main__":
    unittest.main()
