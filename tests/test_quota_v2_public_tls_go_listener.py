#!/usr/bin/env python3
"""Actual Go inherited listener behind the qualified network fence.

Hosted disposable namespaces only; never starts an installed service or
creates an external listener.
"""
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import time

from test_quota_v2_public_tls_bound_listener import CAPLESS, MODULES, ROOT, require_disposable_namespace

import public_tls_bound_listener as bound
import public_tls_deadman as deadman
import public_tls_listener_readback as readback

FILTER_EXEC = r"""
import hashlib, os, sys
from pathlib import Path
directory, digest, binary = sys.argv[1:]
sys.path.insert(0, directory)
import public_tls_network_fence as fence
source = Path(fence.__file__)
assert source.stat().st_uid == 0 and source.stat().st_mode & 0o777 == 0o600
assert hashlib.sha256(source.read_bytes()).hexdigest() == digest
assert os.getpid() == 1
assert fence.install() is None
os.execve(binary, [binary, '-test.run=^TestActualTransferredGoListener$'], os.environ)
"""


def live(original_ns):
    require_disposable_namespace(original_ns)
    with tempfile.TemporaryDirectory(prefix="xmesh-go-listener-") as directory:
        binary = str(Path(directory) / "listener.test")
        subprocess.run(["go", "test", "-c", "-o", binary,
                        "./experiments/quota-v2-physical-stop/namespacepeer"],
                       cwd=ROOT, env=dict(os.environ, GOPROXY="off", CGO_ENABLED="0",
                                          GOTOOLCHAIN="local"), check=True, timeout=90)
        module = Path(directory) / "public_tls_network_fence.py"
        contents = (MODULES / module.name).read_bytes()
        module.write_bytes(contents)
        module.chmod(0o600)
        digest = hashlib.sha256(contents).hexdigest()
        unix_path = str(Path(directory) / "meter.sock")
        with (socket.socket(socket.AF_INET, socket.SOCK_STREAM) as owner,
              socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as meter):
            owner.bind(("127.0.0.1", 443))
            original_fd = owner.fileno()
            token = bound.capture_bound(owner, "127.0.0.1", 443,
                                        bound.network_namespace_cookie(owner))
            meter.bind(unix_path)
            meter.listen(1)
            meter.settimeout(5)
            assert len(os.listdir("/proc/self/task")) == 1
            original_pidns = os.readlink("/proc/self/ns/pid")
            assert os.readlink("/proc/self/ns/pid_for_children") == original_pidns
            saved = os.open("/proc/self/ns/pid", os.O_RDONLY | os.O_CLOEXEC)
            lib = ctypes.CDLL(None, use_errno=True)

            def check(rc):
                if rc:
                    error = ctypes.get_errno()
                    raise OSError(error, os.strerror(error))

            child = guardian = None
            try:
                check(lib.unshare(0x20000000))
                try:
                    child = subprocess.Popen(
                        ["unshare", "--net", "--mount-proc", *CAPLESS,
                         sys.executable, "-I", "-B", "-c", FILTER_EXEC,
                         directory, digest, binary],
                        pass_fds=(original_fd,), stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                        env=dict(os.environ, XMESH_DISPOSABLE_GO_LISTENER="1",
                                 XMESH_FIXTURE_LISTENER_FD=str(original_fd),
                                 XMESH_FIXTURE_LISTENER_TOKEN=json.dumps(dict(
                                     Address=token.address, Port=token.port,
                                     Device=token.device, Inode=token.inode,
                                     Cookie=token.cookie, NetNSCookie=token.netns_cookie)),
                                 XMESH_FIXTURE_UNIX_PATH=unix_path))
                finally:
                    check(lib.setns(saved, 0x20000000))
                os.close(saved)
                saved = None
                assert os.readlink("/proc/self/ns/pid_for_children") == original_pidns

                def line():
                    assert select.select([child.stdout], [], [], 8)[0], "Go fixture stalled"
                    return child.stdout.readline().strip()

                assert line() == "go_bound_verified"
                readback.verify_child_fd(child, original_fd, token)
                owner.close()
                readback.require_no_copy(os.getpid(), token)
                guardian = deadman.StopOnlyDeadman(child=child, timeout_ms=12_000)
                readback.require_no_copy(guardian._guardian.pid, token)
                readback.verify_listen_state(token, listening=False)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                    probe.settimeout(2)
                    assert probe.connect_ex(("127.0.0.1", 443)) == errno.ECONNREFUSED
                guardian.pulse(deadline_ns=time.monotonic_ns() + 8_000_000_000,
                               wall_deadline_ms=time.time_ns() // 1_000_000 + 8000)
                child.stdin.write("fixture_go_adopt\n")
                child.stdin.flush()
                result = line()
                assert result.startswith("go_listening_fd:"), result
                actual_fd = int(result.split(":", 1)[1])
                assert actual_fd != original_fd
                readback.verify_child_fd(child, actual_fd, token)
                readback.verify_listen_state(token, listening=True)
                readback.require_no_copy(os.getpid(), token)
                readback.require_no_copy(guardian._guardian.pid, token)
                with socket.create_connection(("127.0.0.1", 443), timeout=5) as client:
                    client.sendall(b"fixture")
                    peer, _ = meter.accept()
                    with peer:
                        peer.settimeout(5)
                        received = bytearray()
                        while len(received) < 7:
                            block = peer.recv(7 - len(received))
                            assert block
                            received.extend(block)
                        assert received == b"fixture"
                        peer.sendall(b"echo")
                    reply = bytearray()
                    while len(reply) < 4:
                        block = client.recv(4-len(reply))
                        assert block
                        reply.extend(block)
                    assert reply == b"echo"
                assert line() == "go_echo_complete"
                # No voluntary shutdown or heartbeat. The exact owned Go
                # PID1 must die and physically release its sole listener.
                assert child.wait(timeout=10) == -9
                assert guardian._guardian.wait(timeout=2) == 1
                readback.verify_listen_state(token, listening=False)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                    probe.settimeout(2)
                    assert probe.connect_ex(("127.0.0.1", 443)) == errno.ECONNREFUSED
                print("PASS: actual Go inherited TCP listener and Unix stream under network "
                      "fence; exact inode/cookie survived Go adoption; no duplicate FD, "
                      "original listener physically stopped by independent deadman.")
            finally:
                if saved is not None:
                    os.close(saved)
                if guardian is not None:
                    guardian.close()
                if child is not None:
                    if child.poll() is None:
                        child.kill()
                    stdout, stderr = child.communicate(timeout=5)
                    if stdout or stderr:
                        print(stdout + stderr, file=sys.stderr)


if __name__ == "__main__":
    assert len(sys.argv) == 3 and sys.argv[1] == "--live"
    live(sys.argv[2])
