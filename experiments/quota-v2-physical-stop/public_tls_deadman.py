#!/usr/bin/env python3
"""Linux-only STOP-ONLY deadman for a future installed Quota V2 TLS supervisor.

A separate child *guardian process* owns a pidfd for an ALREADY-OWNED TLS
subprocess; it can only KILL that subprocess. Its parent must send heartbeats
after completing signed policy, revocation, certificate and metered-Xray checks.
If the parent exits, freezes or its heartbeat pipe closes, the guardian
SIGKILLs that exact pinned pidfd. No caller can use it to start a public port,
install a quota, refresh a lease or grant traffic. The independent guardian
alone is NOT a sufficient production boundary: systemd KillMode=control-group
must also kill public ingress when the guardian itself dies, and a pre-spawn
authorization gate is required. This module is NOT installed or enabled.
"""
import os
from pathlib import Path
import select
import signal
import stat
import subprocess
import sys
import time

MAX_SILENCE_MS = 10_000
MIN_SILENCE_MS = 100
READY_TIMEOUT_MS = 2_000
ACK_TIMEOUT_MS = 1_000  # A silent or SIGSTOPed guardian must fail closed.


def _starttime_and_parent(pid):
    if type(pid) is not int or pid <= 1:
        raise ValueError("invalid child PID")
    data = Path(f"/proc/{pid}/stat").read_text(encoding="ascii", errors="strict")
    # The second (comm) field may contain spaces and parentheses.
    tail = data[data.rfind(")") + 1:].split()
    if len(tail) < 20:
        raise ValueError("malformed kernel process identity")
    return int(tail[19]), int(tail[1])


def _kill_pidfd(pidfd):
    try:
        signal.pidfd_send_signal(pidfd, signal.SIGKILL, None, 0)
    except ProcessLookupError:
        pass


def _serve(child_pid, expected_parent, heartbeat_fd, ready_fd, ack_fd, timeout_ms):
    """Separate guardian process. Never accepts an 'allowed' wire message."""
    pinned_fd = None
    ready = False
    try:
        if (type(timeout_ms) is not int
                or not MIN_SILENCE_MS <= timeout_ms <= MAX_SILENCE_MS
                or os.getppid() != expected_parent
                or any(fd < 3 for fd in (heartbeat_fd, ready_fd, ack_fd))
                or len({heartbeat_fd, ready_fd, ack_fd}) != 3):
            return 2
        before, owner = _starttime_and_parent(child_pid)
        if owner != expected_parent:
            return 2
        pinned_fd = os.pidfd_open(child_pid, 0)
        after, owner = _starttime_and_parent(child_pid)
        if before != after or owner != expected_parent:
            return 2
        # All FDs were passed by our direct parent, not opened by path.
        # The parent must not consider supervision established until READY.
        os.write(ready_fd, b"READY")
        ready = True
        last = time.monotonic_ns()
        deadline_ns = timeout_ms * 1_000_000
        poller = select.poll()
        poller.register(heartbeat_fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        poller.register(pinned_fd, select.POLLIN | select.POLLHUP | select.POLLERR)
        while True:
            now = time.monotonic_ns()
            if os.getppid() != expected_parent or now < last:
                return 1
            if now - last >= deadline_ns:
                return 1
            # Poll at 100ms maximum so lost parents cannot hold public
            # traffic open until the entire signed policy lifetime.
            events = poller.poll(min(100, max(1, (deadline_ns-(now-last))//1_000_000)))
            for fd, _ in events:
                if fd == pinned_fd:  # Already dead: no need to signal.
                    return 0
                if fd == heartbeat_fd:
                    data = os.read(heartbeat_fd, 4096)
                    if not data:
                        return 1
                    if data != b"P":  # No permit channel or free-form wire.
                        return 1
                    last = time.monotonic_ns()
                    # An ACK proves that this independent process is still
                    # consuming heartbeat messages. An unwatched one-way pipe
                    # may accept writes for hours after its reader SIGSTOPs.
                    os.write(ack_fd, b"A")
    except (OSError, ValueError, OverflowError):
        return 1
    finally:
        if pinned_fd is not None:
            # On every timeout/exception/parent loss, pinning prevents
            # recycled-PID collateral kills. Already-exited pidfds are safe.
            try:
                _kill_pidfd(pinned_fd)
            finally:
                os.close(pinned_fd)
        for fd in (heartbeat_fd, ready_fd, ack_fd):
            try:
                os.close(fd)
            except OSError:
                pass


class StopOnlyDeadman:
    """Independent pidfd guardian for a directly owned Popen child.

    This is a stop-only primitive, never a supervisor scheduling service.
    The owner MUST regularly perform a full signed stop-only check and only
    then pulse. An absent or late check therefore expires the deadman.
    """
    def __init__(self, *, child, timeout_ms=MAX_SILENCE_MS):
        if (not isinstance(child, subprocess.Popen)
                or type(timeout_ms) is not int
                or not MIN_SILENCE_MS <= timeout_ms <= MAX_SILENCE_MS
                or child.poll() is not None):
            raise ValueError("independent TLS deadman requires owned live child")
        self.child = child
        self._writer = None
        self._ack_reader = None
        self._guardian = None
        reader, writer = os.pipe2(os.O_CLOEXEC)
        ready_r, ready_w = os.pipe2(os.O_CLOEXEC)
        ack_r, ack_w = os.pipe2(os.O_CLOEXEC)
        try:
            guardian = subprocess.Popen(
                [sys.executable, "-I", os.path.abspath(__file__), "--guardian",
                 str(child.pid), str(os.getpid()), str(reader), str(ready_w),
                 str(ack_w), str(timeout_ms)],
                pass_fds=(reader, ready_w, ack_w),
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL, close_fds=True)
            self._guardian = guardian
            os.close(reader)
            reader = -1
            os.close(ready_w)
            ready_w = -1
            os.close(ack_w)
            ack_w = -1
            poller = select.poll()
            poller.register(ready_r, select.POLLIN | select.POLLHUP | select.POLLERR)
            events = poller.poll(READY_TIMEOUT_MS)
            if not events or os.read(ready_r, 5) != b"READY" or guardian.poll() is not None:
                raise ValueError("independent TLS deadman did not bind child pidfd")
            self._writer = writer
            writer = -1
            self._ack_reader = ack_r
            ack_r = -1
        except Exception:
            self.close()
            if child.poll() is None:
                child.kill()
                child.wait(timeout=2)
            raise
        finally:
            for fd in (reader, writer, ready_r, ready_w, ack_r, ack_w):
                if fd >= 0:
                    os.close(fd)

    def pulse(self):
        try:
            if (self._writer is None or self._ack_reader is None
                    or self._guardian is None or self._guardian.poll() is not None
                    or self.child.poll() is not None):
                raise ValueError("unavailable TLS deadman or already stopped child")
            os.write(self._writer, b"P")
            poller = select.poll()
            poller.register(self._ack_reader, select.POLLIN | select.POLLHUP |
                            select.POLLERR)
            if not poller.poll(ACK_TIMEOUT_MS) or os.read(self._ack_reader, 1) != b"A":
                raise ValueError("independent guardian did not acknowledge heartbeat")
            if self._guardian.poll() is not None or self.child.poll() is not None:
                raise ValueError("deadman or TLS child exited during heartbeat")
        except (OSError, ValueError):
            # A killed/failed guardian is not a reason to keep TLS alive.
            if self.child.poll() is None:
                self.child.kill()
                self.child.wait(timeout=2)
            raise ValueError("TLS guardian heartbeat lost; owned child killed") from None
        return None

    def close(self):
        writer, self._writer = self._writer, None
        reader, self._ack_reader = self._ack_reader, None
        if writer is not None:
            os.close(writer)
        if reader is not None:
            os.close(reader)
        if self._guardian is not None:
            try:
                self._guardian.wait(timeout=2)
            except subprocess.TimeoutExpired:
                # The guardian itself can fail; the caller MUST stop the
                # owned child and systemd must kill the entire cgroup.
                self._guardian.kill()
                self._guardian.wait(timeout=2)

    def __del__(self):
        try:
            self.close()
        except (OSError, ValueError, AttributeError):
            pass


def _cli():
    if len(sys.argv) != 8 or sys.argv[1] != "--guardian":
        return 2
    try:
        return _serve(*map(int, sys.argv[2:]))
    except (TypeError, ValueError):
        return 2


if __name__ == "__main__":
    sys.exit(_cli())
