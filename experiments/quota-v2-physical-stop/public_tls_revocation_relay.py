"""Hosted-only stop-witness transport across the supervisor network boundary.

An anonymous Unix seqpacket pair carries ONLY fresh challenge strings and
raw Nexus replies. The original-network parent owns the existing fixed-scope
enrolled strict-PQ transport. The single-threaded private-network supervisor
still checks every nonce, signature, scope, and deadline independently.

No route, HTTP proxy, listening Unix pathname, signing key or positive
authority is created; never pass a relay descriptor to the native child.
This library is dormant: no product installer or service invokes it.
"""
import os
from pathlib import Path
import re
import select
import socket
import struct
import subprocess
import time

import public_tls_revocation_watch as watch

CREDENTIALS = struct.Struct("3i")
CHALLENGE_BYTES = 64
POLL_TIMEOUT = 0.25
REPLY_TIMEOUT = watch.MAX_FETCH_NS / 1_000_000_000


def require_hosted():
    if (os.geteuid() != 0 or os.getegid() != 0
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("XMESH_DISPOSABLE_BOUND_LISTENER_TEST") != "1"):
        raise ValueError("revocation relay requires disposable hosted root qualification")


def netns(pid):
    return os.readlink(f"/proc/{pid}/ns/net")


def ready(fd):
    poller = select.poll()
    poller.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(0))


def check_socket(endpoint):
    # SO_PASSCRED can kernel-autobind an already connected endpoint to a
    # short abstract address on its first send. It remains a socketpair,
    # not an accepting socket or a pathname another process can connect to.
    def unnamed_or_autobound(address):
        return address == "" or (isinstance(address, bytes)
                                 and re.fullmatch(rb"\x00[0-9a-f]{5}", address) is not None)
    if (endpoint.family != socket.AF_UNIX
            or endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET
            or endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1
            or endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) != 0
            or not unnamed_or_autobound(endpoint.getsockname())
            or not unnamed_or_autobound(endpoint.getpeername())
            or endpoint.get_inheritable()):
        raise ValueError("anonymous credentialed seqpacket endpoint required")


def receive(endpoint, expected_pid, limit):
    """Fail closed on wrong sender, larger packet or ANY ancillary FD."""
    payload, messages, flags, _ = endpoint.recvmsg(
        limit + 1, socket.CMSG_SPACE(CREDENTIALS.size), socket.MSG_CMSG_CLOEXEC)
    creds = []
    unexpected = False
    for level, kind, raw in messages:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            # Kernel may deliver a subset even on MSG_CTRUNC. Dispose every
            # received descriptor; none is a permissible relay input.
            size = struct.calcsize("i")
            for offset in range(0, len(raw) - size + 1, size):
                os.close(struct.unpack_from("i", raw, offset)[0])
            unexpected = True
        elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(raw) == CREDENTIALS.size:
            creds.append(CREDENTIALS.unpack(raw))
        else:
            unexpected = True
    if (unexpected or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
            or creds != [(expected_pid, 0, 0)] or not 0 < len(payload) <= limit):
        raise ValueError("invalid revocation relay credentials or bounded frame")
    return payload


def send(endpoint, payload):
    if endpoint.send(payload) != len(payload):
        raise ValueError("short revocation relay frame")


class HostedEnrolledRevocationRelay:
    """Own original-network endpoint and the directly owned supervisor PID.

    The only network operation is the prebound existing enrolled_fetch
    closure. A request cannot name endpoints, alter scope or carry FDs.
    Caller must own and always reap the supervisor; the relay never starts
    an Xray process or endorses the response it forwards.
    """

    def __init__(self, *, state, user, node, activation, genesis_sha, runtime_id,
                 profile_sha256, authority_sha256, roster_sha256):
        require_hosted()
        self.original_ns = netns("self")
        self.pid = os.getpid()
        self._fetch = watch.enrolled_fetch(
            state=state, user=user, node=node, activation=activation,
            genesis_sha=genesis_sha, runtime_id=runtime_id, profile_sha256=profile_sha256,
            authority_sha256=authority_sha256, roster_sha256=roster_sha256)
        self._parent, self._supervisor = socket.socketpair(
            socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
        self._pidfd = None
        self._child_pid = None
        self._private_ns = None
        self._last = None
        try:
            for endpoint in (self._parent, self._supervisor):
                endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
                check_socket(endpoint)
            self._parent.settimeout(POLL_TIMEOUT)
        except BaseException:
            self.close()
            raise

    @property
    def supervisor_fd(self):
        if self._supervisor is None or self._child_pid is not None:
            raise ValueError("revocation relay supervisor endpoint already transferred")
        check_socket(self._supervisor)
        return self._supervisor.fileno()

    def bind_supervisor(self, child):
        """Call immediately after Popen(unshare --net ..., pass_fds=(fd,))."""
        if (self._parent is None or self._child_pid is not None
                or not isinstance(child, subprocess.Popen) or child.poll() is not None
                or self.pid != os.getpid() or self.original_ns != netns("self")):
            raise ValueError("live owned private supervisor required")
        try:
            raw = Path(f"/proc/{child.pid}/stat").read_text(encoding="ascii")
            if int(raw[raw.rfind(")") + 1:].split()[1]) != self.pid:
                raise ValueError("revocation relay requires directly owned supervisor")
            self._pidfd = os.pidfd_open(child.pid, 0)
            if ready(self._pidfd) or child.poll() is not None:
                raise ValueError("revocation relay supervisor exited")
            self._child_pid = child.pid
            # Parent must not retain the private-side socket description.
            self._supervisor.close()
            self._supervisor = None
        except BaseException:
            self.close()
            raise

    def _ensure(self):
        if (self._parent is None or self._pidfd is None or ready(self._pidfd)
                or os.getpid() != self.pid or netns("self") != self.original_ns):
            raise ValueError("revocation relay parent or supervisor changed")
        check_socket(self._parent)

    def _ensure_private(self):
        current = netns(self._child_pid)
        if current == self.original_ns:
            raise ValueError("revocation relay supervisor is not in a private network")
        if self._private_ns is None:
            self._private_ns = current
        elif self._private_ns != current:
            raise ValueError("revocation relay supervisor changed network")

    def poll(self):
        """Process one fixed-scope challenge, or no work after 250 ms idle.

        Returns True for a response, False for idle. Any transport/protocol
        error permanently closes the relay; no retry of a failed challenge.
        """
        try:
            self._ensure()
            try:
                raw = receive(self._parent, self._child_pid, CHALLENGE_BYTES)
            except socket.timeout:
                return False
            self._ensure()
            self._ensure_private()
            nonce = raw.decode("ascii")
            if watch.HEX64.fullmatch(nonce) is None or nonce == self._last:
                raise ValueError("invalid or repeated revocation relay challenge")
            self._last = nonce
            # No JSON supplied by the supervisor is ever sent to Nexus;
            # the request is built by enrolled_fetch in this original netns.
            reply = self._fetch(nonce)
            if not isinstance(reply, bytes) or not 0 < len(reply) <= watch.MAX_WIRE_BYTES:
                raise ValueError("invalid enrolled revocation relay reply")
            self._ensure()
            self._ensure_private()
            send(self._parent, reply)
            return True
        except BaseException:
            self.close()
            raise

    def close(self):
        for endpoint in (self._parent, self._supervisor):
            if endpoint is not None:
                endpoint.close()
        self._parent = self._supervisor = None
        if self._pidfd is not None:
            os.close(self._pidfd)
            self._pidfd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class PrivateRevocationFetch:
    """Adopt inherited socket only in the directly owned private supervisor.

    The raw reply is NOT a verified witness. Supply this object to the
    existing SignedTlsRevocationWatch, and never transfer its fd to Xray.
    """

    def __init__(self, *, fd, broker_pid, original_ns):
        require_hosted()
        if (type(fd) is not int or fd < 3 or type(broker_pid) is not int
                or broker_pid <= 1 or os.getppid() != broker_pid
                or netns(broker_pid) != original_ns or netns("self") == original_ns):
            raise ValueError("exact original-network parent and private supervisor required")
        self._endpoint = socket.socket(fileno=fd)
        self._pidfd = None
        self._last = None
        self._broker_pid = broker_pid
        self._original_ns = original_ns
        self._private_ns = netns("self")
        try:
            self._endpoint.set_inheritable(False)
            check_socket(self._endpoint)
            if self._endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                         CREDENTIALS.size) != CREDENTIALS.pack(broker_pid, 0, 0):
                raise ValueError("revocation relay pair not created by original parent")
            self._endpoint.settimeout(REPLY_TIMEOUT)
            self._pidfd = os.pidfd_open(broker_pid, 0)
            self._ensure()
        except BaseException:
            self.close()
            raise

    def _ensure(self):
        if (self._endpoint is None or self._pidfd is None or ready(self._pidfd)
                or os.getppid() != self._broker_pid or netns("self") != self._private_ns
                or netns(self._broker_pid) != self._original_ns):
            raise ValueError("revocation relay broker or private supervisor changed")
        check_socket(self._endpoint)

    def __call__(self, nonce):
        try:
            self._ensure()
            if not isinstance(nonce, str) or watch.HEX64.fullmatch(nonce) is None or nonce == self._last:
                raise ValueError("invalid or repeated private revocation challenge")
            self._last = nonce
            deadline = time.monotonic_ns() + watch.MAX_FETCH_NS
            def budget():
                remaining = deadline - time.monotonic_ns()
                if remaining <= 0:
                    raise ValueError("private revocation relay deadline elapsed")
                self._endpoint.settimeout(remaining / 1_000_000_000)
            budget()
            send(self._endpoint, nonce.encode("ascii"))
            budget()
            reply = receive(self._endpoint, self._broker_pid, watch.MAX_WIRE_BYTES)
            self._ensure()
            budget()
            return reply
        except BaseException:
            self.close()
            raise

    def close(self):
        if self._endpoint is not None:
            self._endpoint.close()
            self._endpoint = None
        if self._pidfd is not None:
            os.close(self._pidfd)
            self._pidfd = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
