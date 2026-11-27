#!/usr/bin/env python3
"""Kernel network-fence proof, restricted to explicit disposable CI."""
import ctypes
import errno
import hashlib
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import unittest

from test_quota_v2_public_tls_bound_listener import CAPLESS, MODULES, require_disposable_namespace

import public_tls_network_fence as fence

# No external endpoint. The deliberately inherited extra, unconnected TCP FD
# is a negative fixture for Landlock (seccomp cannot inspect sockaddr memory).
COMMON = r"""
import ctypes, errno, os, socket, sys
sys.path.insert(0, sys.argv[1])
import public_tls_network_fence as fence
def denied(call, expected):
    try:
        call()
    except OSError as exc:
        assert exc.errno in expected, exc
    else:
        raise AssertionError('network operation unexpectedly succeeded')
def socket_refusals():
    for family, kind, protocol in (
        (socket.AF_INET, socket.SOCK_STREAM, 0),
        (socket.AF_INET6, socket.SOCK_STREAM, 0),
        (socket.AF_INET, socket.SOCK_DGRAM, 0),
        (socket.AF_NETLINK, socket.SOCK_RAW, 0),
        (socket.AF_UNIX, socket.SOCK_DGRAM, 0),
        (socket.AF_UNIX, socket.SOCK_SEQPACKET, 0),
    ):
        denied(lambda: socket.socket(family, kind, protocol), {errno.EPERM})
    denied(socket.socketpair, {errno.EPERM})
    lib = fence._native()
    for nr in (46, 47, 299, 307, 425, 426, 427, 438):
        assert lib.syscall(nr, -1, 0, 0, 0, 0, 0) == -1
        assert ctypes.get_errno() == errno.EPERM, (nr, ctypes.get_errno())
"""

LIVE = COMMON + r"""
import hashlib
from pathlib import Path
_, _, digest, listener_fd, negative_fd, destination_port, unix_path = sys.argv
source = Path(fence.__file__)
assert source.stat().st_uid == 0 and source.stat().st_mode & 0o777 == 0o600
assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
listener = socket.socket(fileno=int(listener_fd))
negative = socket.socket(fileno=int(negative_fd))
destination = ('127.0.0.1', int(destination_port))
assert fence.install() is None
socket_refusals()
# Landlock, not the seccomp socket-creation restriction, must prevent use
# of an IPv4 socket already received from another network namespace.
denied(lambda: negative.connect(destination), {errno.EACCES})
negative.close()
print('network_fence_ready', flush=True)
assert sys.stdin.readline().strip() == 'fixture_listen'
listener.listen(1)
print('original_listener_ready', flush=True)
conn, _ = listener.accept()
with conn:
    assert os.read(conn.fileno(), 1) == b'x'
    # Fresh authenticated Unix paths remain possible. The fixture exercises
    # raw connectivity only; namespacepeer provides separate peer identity.
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as meter:
        meter.connect(unix_path)
        assert os.write(meter.fileno(), b'm') == 1
        assert os.read(meter.fileno(), 1) == b'n'
    assert os.write(conn.fileno(), b'y') == 1
    # A malicious child might disconnect an accepted TCP stream via
    # AF_UNSPEC, then reuse its original-network-namespace socket for
    # egress. Require denial of the attempted reconnect too.
    lib = fence._native()
    sockaddr = ctypes.create_string_buffer(16)
    rc = lib.syscall(42, conn.fileno(), ctypes.byref(sockaddr), 16)
    if rc != 0:
        assert ctypes.get_errno() in (errno.EACCES, errno.EAFNOSUPPORT), ctypes.get_errno()
    denied(lambda: conn.connect(destination), {errno.EACCES})
listener.close()
print('exact_inherited_echo_and_no_tcp_egress', flush=True)
"""


class TestFence(unittest.TestCase):
    def test_actual_seccomp_denials_in_disposable_subprocess(self):
        script = COMMON + r"""
lib = fence._native()
assert lib.prctl(38, 1, 0, 0, 0) == 0
fence._install_socket_filter(lib)
socket_refusals()
print('kernel seccomp socket and ancillary refusal')
"""
        subprocess.run([sys.executable, "-I", "-B", "-c", script, str(MODULES)],
                       check=True, timeout=10)

    def test_actual_inherited_stream_io_and_thread_filter(self):
        # Existing connected descriptors remain useful after filtering.
        # This local test is not a substitute for the hosted TCP+Unix test.
        script = COMMON + r"""
import threading
lib = fence._native()
assert lib.prctl(38, 1, 0, 0, 0) == 0
fence._install_socket_filter(lib)
fd = int(sys.argv[2])
assert os.read(fd, 1) == b'x'
assert os.write(fd, b'y') == 1
failures = []
def worker():
    try:
        socket_refusals()
    except BaseException as exc:
        failures.append(exc)
t = threading.Thread(target=worker)
t.start()
t.join()
assert not failures, failures
"""
        parent, inherited = socket.socketpair()
        with parent, inherited:
            parent.settimeout(5)
            child = subprocess.Popen([sys.executable, "-I", "-B", "-c", script,
                                      str(MODULES), str(inherited.fileno())],
                                     pass_fds=(inherited.fileno(),))
            try:
                inherited.close()
                parent.sendall(b"x")
                self.assertEqual(parent.recv(1), b"y")
                self.assertEqual(child.wait(timeout=5), 0)
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait(timeout=5)

    def test_install_rejects_missing_capless_nnp(self):
        script = COMMON + """
try:
    fence.install()
except ValueError as exc:
    assert 'capless' in str(exc)
else:
    raise AssertionError('privileged precondition bypass')
"""
        # The normal test driver is not a capless/no-new-privs child.
        subprocess.run([sys.executable, "-I", "-B", "-c", script, str(MODULES)],
                       check=True, timeout=10)

    def test_native_socket_filter_arch_and_argument_paths(self):
        # Local executor blocks AF_UNIX creation even before our filter;
        # inspect the exact compiled BPF control flow as an independent
        # structural check. Hosted live test must prove the allowed path.
        def evaluate(nr, arch=fence.AUDIT_ARCH_X86_64, *args):
            import struct
            data = struct.pack("<IIQ6Q", nr, arch, 0, *args,
                               *([0] * (6 - len(args))))
            rows = fence._instructions()
            acc = pc = 0
            while pc < len(rows):
                code, yes, no, value = rows[pc]
                pc += 1
                if code == 0x20:
                    acc = struct.unpack_from("<I", data, value)[0]
                elif code == 0x15:
                    pc += yes if acc == value else no
                elif code == 0x45:
                    pc += yes if acc & value else no
                elif code == 0x54:
                    acc &= value
                elif code == 6:
                    return value
                else:
                    raise AssertionError("unexpected BPF opcode")
            raise AssertionError("BPF fallthrough")

        self.assertEqual(evaluate(41, fence.AUDIT_ARCH_X86_64, 1,
                                  socket.SOCK_STREAM | socket.SOCK_CLOEXEC |
                                  socket.SOCK_NONBLOCK, 0), fence.SECCOMP_RET_ALLOW)
        for domain, kind, protocol in ((2, 1, 0), (1, 2, 0), (1, 1, 1),
                                       (1 + 2**32, 1, 0), (1, 1 + 2**32, 0)):
            self.assertEqual(evaluate(41, fence.AUDIT_ARCH_X86_64, domain, kind, protocol),
                             fence.SECCOMP_RET_ERRNO)
        self.assertEqual(evaluate(41 | fence.X32_SYSCALL), fence.SECCOMP_RET_KILL_PROCESS)
        self.assertEqual(evaluate(41, 0x40000003), fence.SECCOMP_RET_KILL_PROCESS)
        for nr in (42, 43, 50, 288, 0, 1):
            self.assertEqual(evaluate(nr), fence.SECCOMP_RET_ALLOW)
        for nr in fence.DENY_SYSCALLS:
            self.assertEqual(evaluate(nr), fence.SECCOMP_RET_ERRNO)

    def test_unsupported_landlock_is_not_a_success(self):
        from unittest.mock import patch
        with patch.object(fence, "_check", return_value=3):
            with self.assertRaisesRegex(ValueError, "ABI 4"):
                fence._install_landlock(fence._native())


def live(original_ns):
    require_disposable_namespace(original_ns)
    with tempfile.TemporaryDirectory(prefix="xmesh-tls-network-") as directory:
        module = Path(directory) / "public_tls_network_fence.py"
        content = (MODULES / module.name).read_bytes()
        module.write_bytes(content)
        module.chmod(0o600)
        digest = hashlib.sha256(content).hexdigest()
        unix_path = str(Path(directory) / "meter.sock")
        with (socket.socket(socket.AF_INET, socket.SOCK_STREAM) as owner,
              socket.socket(socket.AF_INET, socket.SOCK_STREAM) as negative,
              socket.socket(socket.AF_INET, socket.SOCK_STREAM) as egress,
              socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as meter):
            owner.bind(("127.0.0.1", 443))
            egress.bind(("127.0.0.1", 0))
            egress.listen(1)
            egress.setblocking(False)
            meter.bind(unix_path)
            meter.listen(1)
            meter.settimeout(5)
            child = subprocess.Popen(
                ["unshare", "--net", "--pid", "--fork", "--kill-child=SIGKILL", "--mount-proc", *CAPLESS,
                 sys.executable, "-I", "-B", "-c", LIVE, directory, digest,
                 str(owner.fileno()), str(negative.fileno()),
                 str(egress.getsockname()[1]), unix_path],
                pass_fds=(owner.fileno(), negative.fileno()), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                def wait(message):
                    assert select.select([child.stdout], [], [], 10)[0], message
                    assert child.stdout.readline().strip() == message, message

                wait("network_fence_ready")
                negative.close()
                owner.close()
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                    probe.settimeout(2)
                    assert probe.connect_ex(("127.0.0.1", 443)) == errno.ECONNREFUSED
                child.stdin.write("fixture_listen\n")
                child.stdin.flush()
                wait("original_listener_ready")
                with socket.create_connection(("127.0.0.1", 443), timeout=5) as client:
                    client.sendall(b"x")
                    peer, _ = meter.accept()
                    with peer:
                        peer.settimeout(5)
                        assert peer.recv(1) == b"m"
                        peer.sendall(b"n")
                    assert client.recv(1) == b"y"
                wait("exact_inherited_echo_and_no_tcp_egress")
                assert child.wait(timeout=5) == 0
                # An actual destination listener received no connection,
                # including from the deliberately inherited negative FD.
                try:
                    unexpected, _ = egress.accept()
                except BlockingIOError:
                    pass
                else:
                    unexpected.close()
                    raise AssertionError("forbidden TCP egress reached destination")
                print("PASS: Landlock blocks TCP egress on inherited and accepted sockets; "
                      "seccomp denies new non-Unix sockets and FD transfer; actual inherited "
                      "TCP echo and original Unix connection work.")
            finally:
                if child.poll() is None:
                    child.kill()
                _, stderr = child.communicate(timeout=5)
                if stderr:
                    print(stderr, file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--live":
        live(sys.argv[2])
    else:
        unittest.main()
