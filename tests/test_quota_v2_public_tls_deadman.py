#!/usr/bin/env python3
"""Independent Linux pidfd deadman: real processes, no public listener."""
import os
from pathlib import Path
from unittest import mock
import select
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

    def test_disappearing_proc_stat_is_already_stopped(self):
        with mock.patch.object(Path, "read_text",
                               side_effect=ProcessLookupError(3, "No such process")):
            self.assertTrue(proc_gone_or_zombie(12345))

    def test_directly_owned_live_child_can_be_guarded_but_never_authorized(self):
        self.guardian = deadman.StopOnlyDeadman(
            child=self.child, timeout_ms=950)
        self.assertIsNone(self.guardian.pulse())
        time.sleep(0.15)
        self.assertIsNone(self.guardian.pulse())
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
            self.guardian.pulse()
        self.assertIsNotNone(self.child.poll())

    def test_sigstopped_guardian_cannot_fake_live_heartbeat(self):
        self.guardian = deadman.StopOnlyDeadman(
            child=self.child, timeout_ms=5_000)
        self.assertIsNone(self.guardian.pulse())
        guardian_pid = self.guardian._guardian.pid
        os.kill(guardian_pid, signal.SIGSTOP)
        try:
            started = time.monotonic()
            with self.assertRaisesRegex(ValueError, "owned child killed"):
                self.guardian.pulse()
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
            self.assertIsNone(self.guardian.pulse())
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
