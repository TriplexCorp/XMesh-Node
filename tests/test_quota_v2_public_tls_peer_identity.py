#!/usr/bin/env python3
"""Real Linux pidfs/peer tests; never opens a public listener."""
from contextlib import contextmanager
import array
import errno
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "experiments/quota-v2-physical-stop"
sys.path.insert(0, str(MODULES))
import public_tls_peer_identity as proof
import public_tls_route_mount as mount


# An actual nested PID and mount namespace with a new procfs. The child
# receives the expected token alone, not the supervisor's pinned pidfd.
INNER = r"""
import errno, os, signal, socket, struct, sys
modules, parent, device, inode, view, inherited, verdict, name = sys.argv[1:]
sys.path.insert(0, modules)
import public_tls_peer_identity as proof
parent, view, inherited = map(int, (parent, view, inherited))
token = proof.PidfdIdentity(int(device), int(inode))
assert os.getpid() == 1 and os.geteuid() == os.getegid() == 0
assert not os.path.exists(f"/proc/{parent}"), "ancestor PID leaked through procfs"
status = dict(line.split(":", 1) for line in open("/proc/self/status") if ":" in line)
assert status["NoNewPrivs"].strip() == "1"
for key in ("CapEff", "CapInh", "CapPrm", "CapBnd", "CapAmb"):
    assert int(status[key].strip(), 16) == 0
assert os.fstatvfs(view).f_flag & (os.ST_RDONLY | os.ST_NOSUID | os.ST_NODEV | os.ST_NOEXEC) == (
    os.ST_RDONLY | os.ST_NOSUID | os.ST_NODEV | os.ST_NOEXEC)
before = set(os.listdir(f"/proc/self/fd/{view}"))
try:
    os.open("forbidden", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=view)
except OSError as exc:
    assert exc.errno == errno.EROFS, exc
else:
    raise AssertionError("child could create a file in detached meter view")

# There must not be an inherited original meter pidfd or any other pidfd.
for name_fd in os.listdir("/proc/self/fd"):
    try:
        assert proof._filesystem_magic(int(name_fd)) != proof.PID_FS_MAGIC
    except OSError as exc:
        assert exc.errno == errno.EBADF

with (socket.socket(fileno=inherited) if inherited >= 0
      else socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)) as conn:
    if inherited < 0:
        conn.connect(f"/proc/self/fd/{view}/{name}")
    pid, uid, gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    assert (pid, uid, gid) == (0, 0, 0), (pid, uid, gid)
    # The kernel does not expose ancestor numeric PID authority. A peer
    # pidfd is only opened transiently by the independent proof.
    if verdict == "accept":
        assert proof.verify_connected_peer(conn, token) is None
        raw_fd = conn.getsockopt(socket.SOL_SOCKET, proof.SO_PEERPIDFD)
        try:
            # Signal number zero is nondestructive; the descendant PID
            # namespace may not signal its ancestor using the peer pidfd.
            try:
                signal.pidfd_send_signal(raw_fd, 0)
            except OSError as exc:
                assert exc.errno in (errno.EINVAL, errno.EPERM, errno.ESRCH), exc
            else:
                raise AssertionError("ancestor pidfd accepted a signal")
        finally:
            os.close(raw_fd)
    else:
        try:
            proof.verify_connected_peer(conn, token)
        except ValueError as exc:
            assert str(exc) == "Unix peer is not the original pidfs meter object", exc
        else:
            raise AssertionError("different same-UID invisible peer accepted")
for name_fd in os.listdir("/proc/self/fd"):
    try:
        assert proof._filesystem_magic(int(name_fd)) != proof.PID_FS_MAGIC
    except OSError as exc:
        assert exc.errno == errno.EBADF
assert before == set(os.listdir(f"/proc/self/fd/{view}"))
print("actual_namespace_peer_" + verdict, flush=True)
"""


class PeerIdentityTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("root kernel fixture required")
        self.own_pidfd = os.pidfd_open(os.getpid())
        self.addCleanup(os.close, self.own_pidfd)
        self.token = proof.capture_original(self.own_pidfd, os.getpid())

    @contextmanager
    def other_peer(self):
        # The second pair is created by the independent process, not by
        # this supervisor before fork. Transfer one connected endpoint via
        # real SCM_RIGHTS so the local executor needs no socket pathname.
        a, b = socket.socketpair()
        script = r"""
import array, socket, sys
control = socket.socket(fileno=int(sys.argv[1]))
one, two = socket.socketpair()
with control, one, two:
    control.sendmsg([b"R"], [(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array("i",[one.fileno()]))])
    control.recv(1)
"""
        proc = subprocess.Popen([sys.executable, "-I", "-B", "-c", script, str(b.fileno())],
                                pass_fds=(b.fileno(),))
        b.close()
        try:
            a.settimeout(5)
            data, controls, flags, _ = a.recvmsg(1, socket.CMSG_SPACE(array.array("i").itemsize),
                                                 socket.MSG_CMSG_CLOEXEC)
            self.assertEqual(data, b"R")
            self.assertFalse(flags & socket.MSG_CTRUNC)
            self.assertEqual(len(controls), 1)
            level, kind, raw = controls[0]
            self.assertEqual((level, kind), (socket.SOL_SOCKET, socket.SCM_RIGHTS))
            fds = array.array("i")
            fds.frombytes(raw[:fds.itemsize])
            self.assertEqual(len(fds), 1)
            with socket.socket(fileno=fds[0]) as peer:
                pidfd = os.pidfd_open(proc.pid)
                try:
                    token = proof.capture_original(pidfd, proc.pid)
                    yield proc, a, peer, pidfd, token
                finally:
                    os.close(pidfd)
        finally:
            a.close()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)

    @contextmanager
    def readonly_directory(self):
        with tempfile.TemporaryDirectory(prefix="xmesh-tls-peer-") as directory:
            fd = os.open(directory, mount.DIR_FLAGS)
            try:
                view, mount_id = mount.readonly_view(fd)
                try:
                    mount.check_view(fd, view, mount_id)
                    yield Path(directory), view
                finally:
                    os.close(view)
            finally:
                os.close(fd)

    def run_inner(self, view, endpoint, verdict, name="-"):
        inherited = -1 if endpoint is None else endpoint.fileno()
        pass_fds = (view,) if endpoint is None else (view, inherited)
        cmd = ["unshare", "--pid", "--fork", "--kill-child=SIGKILL", "--mount-proc",
               "setpriv", "--no-new-privs", "--bounding-set=-all",
               "--inh-caps=-all", "--ambient-caps=-all", sys.executable,
               "-I", "-B", "-c", INNER, str(MODULES), str(os.getpid()),
               str(self.token.device), str(self.token.inode), str(view),
               str(inherited), verdict, name]
        run = subprocess.run(cmd, pass_fds=pass_fds, capture_output=True, text=True, timeout=15)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        self.assertEqual(run.stdout.strip(), "actual_namespace_peer_" + verdict)

    def test_same_exact_kernel_peer(self):
        a, b = socket.socketpair()
        with a, b:
            self.assertIsNone(proof.verify_connected_peer(a, self.token))
            self.assertEqual(proof.capture_original(self.own_pidfd, os.getpid()), self.token)

    def test_different_live_root_peer_not_equivalent(self):
        with self.other_peer() as (proc, _, peer, pidfd, foreign):
            self.assertNotEqual(foreign, self.token)
            self.assertIsNone(proof.verify_connected_peer(peer, foreign))
            with self.assertRaisesRegex(ValueError, "not the original pidfs"):
                proof.verify_connected_peer(peer, self.token)
            with self.assertRaisesRegex(ValueError, "not the measured"):
                proof.capture_original(pidfd, os.getpid())

    def test_exited_root_peer_rejected_even_with_original_pinned_pidfd(self):
        with self.other_peer() as (proc, control, peer, pidfd, token):
            self.assertIsNone(proof.verify_connected_peer(peer, token))
            control.sendall(b"X")
            self.assertEqual(proc.wait(timeout=5), 0)
            with self.assertRaises((ValueError, OSError)):
                proof.verify_connected_peer(peer, token)
            with self.assertRaisesRegex(ValueError, "no longer live"):
                proof.capture_original(pidfd, proc.pid)

    def test_regular_file_and_inheritable_pidfd_rejected(self):
        with tempfile.TemporaryFile() as ordinary:
            with self.assertRaisesRegex(ValueError, "distinct kernel pidfs"):
                proof.capture_original(ordinary.fileno(), os.getpid())
        leaked = os.dup(self.own_pidfd)
        try:
            os.set_inheritable(leaked, True)
            with self.assertRaisesRegex(ValueError, "CLOEXEC"):
                proof.capture_original(leaked, os.getpid())
        finally:
            os.close(leaked)
        for invalid in ((0, 1), (1, 0), (True, 42), (1, 2**64)):
            with self.assertRaises(ValueError):
                proof.PidfdIdentity(*invalid)

    def test_nested_capless_pid_namespace_accepts_original_and_refuses_foreign(self):
        a, b = socket.socketpair()
        with a, b, self.readonly_directory() as (directory, view):
            self.run_inner(view, a, "accept")
            with self.other_peer() as (_, _, peer, _, _):
                self.run_inner(view, peer, "reject")
            self.assertEqual(list(directory.iterdir()), [])

    def test_actual_new_unix_connect_via_detached_mount_in_private_pid_namespace(self):
        # Real path socket is mandatory on hosted CI. The local executor
        # can prohibit creation of socket(AF_UNIX), while still permitting
        # socketpair/SCM_RIGHTS; only that exact local limitation may skip.
        try:
            server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        except PermissionError:
            if os.environ.get("GITHUB_ACTIONS") == "true":
                raise
            self.skipTest("local executor forbids creating actual pathname Unix socket")
        with server, self.readonly_directory() as (directory, view):
            correct = directory / "vless-main"
            wrong = directory / "vless-cdn"
            server.bind(str(correct))
            correct.chmod(0o600)
            server.listen(2)
            self.run_inner(view, None, "accept", "vless-main")
            server.settimeout(5)
            conn, _ = server.accept()
            with conn:
                self.assertEqual(conn.recv(1), b"")

            # Another real root process presents a same-UID socket in the
            # exact same readonly directory. It MUST fail peer identity.
            script = r"""
import os,socket,sys
with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as listener:
    listener.bind(sys.argv[1]); os.chmod(sys.argv[1],0o600); listener.listen(1)
    print("ready",flush=True)
    conn,_=listener.accept()
    with conn:
        assert conn.recv(1)==b""
"""
            child = subprocess.Popen([sys.executable, "-I", "-B", "-c", script, str(wrong)],
                                     stdout=subprocess.PIPE, text=True)
            try:
                import select
                self.assertTrue(select.select([child.stdout], [], [], 5)[0])
                self.assertEqual(child.stdout.readline(), "ready\n")
                self.run_inner(view, None, "reject", "vless-cdn")
                self.assertEqual(child.wait(timeout=5), 0)
            finally:
                if child.poll() is None:
                    child.kill()
                child.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main()
