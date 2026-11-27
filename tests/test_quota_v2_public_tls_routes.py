#!/usr/bin/env python3
"""Real kernel private route/peer checks; disposable, no public listener."""
import errno
import fcntl
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments/quota-v2-physical-stop"))
import public_tls_routes as routes
import public_tls_namespace_route as namespace_route
import public_tls_cap_watch as caps
import test_quota_v2_first_cap_handoff as fixture


class RouteFixture(unittest.TestCase):
    real_sockets = True

    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("production route ownership requires root")
        temp = tempfile.TemporaryDirectory(prefix="xmesh-tls-routes-")
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        self.source = root / "enrolled"
        self.root = root / "capsules"
        self.source.mkdir(mode=0o700)
        self.root.mkdir(mode=0o700)
        for key, value in (("ROOT", self.root), ("ENROLLED_STATE", self.source)):
            patch = mock.patch.object(routes, key, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.fd = os.open(self.source, routes.DIR_FLAGS)
        self.addCleanup(os.close, self.fd)
        # Real independent process, kernel PID, executable inode, start
        # ticks, namespace, sockets and peer credentials. It is a test
        # socket owner, never a real meter or a traffic-authorizing Xray.
        child_code = """
import os, select, socket, sys, time
from pathlib import Path
print('identity-ready', flush=True)
path = Path(sys.stdin.readline().strip())
path.mkdir(mode=0o700)
sockets = []
try:
    if sys.argv[1] == 'real':
        for tag in ('vless-cdn', 'vless-main'):
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.bind(str(path / tag))
            (path / tag).chmod(0o600)
            sock.listen(10)
            sockets.append(sock)
    print('ready', flush=True)
    while True:
        if sockets:
            for sock in select.select(sockets, [], [], 0.1)[0]:
                conn, _ = sock.accept()
                conn.close()
        else:
            time.sleep(0.1)
finally:
    for sock in sockets:
        sock.close()
"""
        # The real installed Docker meter has no added capabilities. Keep
        # the test peer root-owned but capless as well, and take identity
        # only after setpriv has exec'd the final Python executable.
        self.child = subprocess.Popen([
            "setpriv", "--no-new-privs", "--bounding-set=-all",
            "--inh-caps=-all", "--ambient-caps=-all", sys.executable, "-c",
            child_code, "real" if self.real_sockets else "structure",
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.addCleanup(self.stop_child)
        import select
        self.assertTrue(select.select([self.child.stdout], [], [], 5)[0],
                        "kernel fixture did not exec")
        self.assertEqual(self.child.stdout.readline().strip(), "identity-ready")
        self.runtime = routes.wal.runtime_identity.trusted_runtime_identity(self.child.pid)
        self.meter = Path("/dev/shm/xmesh-" + self.runtime)
        # No pre-existing directory may be removed by this disposable test.
        self.assertFalse(self.meter.exists())
        self.addCleanup(shutil.rmtree, self.meter, True)
        self.child.stdin.write(str(self.meter) + "\n")
        self.child.stdin.flush()
        self.assertTrue(select.select([self.child.stdout], [], [], 5)[0],
                        "kernel Unix fixture did not become ready")
        ready = self.child.stdout.readline().strip()
        if not ready:
            self.child.wait(timeout=5)
            self.fail("kernel Unix fixture exited: " + self.child.stderr.read())
        self.assertEqual(ready, "ready")
        self.target = routes.vless_ingress.target(self.child.pid, self.runtime)
        (self.source / "ingress-u100").symlink_to(self.target)
        signer = fixture.FirstCapHandoffTests("test_original_nexus_signer_and_real_assigned_vless_scope")
        signer.setUp()
        self.addCleanup(signer.doCleanups)
        self.signer = signer
        raw = signer.signed_grant(dict(signer.claims, runtimeId=self.runtime))
        self.roster = caps.SignedCapRosterWatch(
            profile=signer.reply["config"], signed_grants={100: raw},
            pinned=signer.pub, node=signer.node, activation=signer.fixture.activation,
            genesis_sha=signer.reply["policySha256"], runtime_id=self.runtime,
            trusted_pid=self.child.pid, socket_path="/var/lib/xmesh-first-meter/runtime/drain.sock")

    def stop_child(self):
        if self.child.poll() is None:
            self.child.kill()
        self.child.communicate(timeout=5)


class FirstGenesisRouteStructureTests(RouteFixture):
    # Separate isolated structural tests exercise actual filesystem, pidfd,
    # and descriptor inheritance even when the local executor forbids
    # creation of AF_UNIX sockets. Hosted CI runs the real peers below too.
    real_sockets = False

    def setUp(self):
        super().setUp()

        def measure(capsule, deadline):
            deadline()
            capsule._check_liveness()
            self.assertEqual(routes._dir_identity(os.fstat(capsule._meter_fd)),
                             capsule._meter_id)
            deadline()

        patch = mock.patch.object(routes.FirstGenesisRoutes, "_check_meter", measure)
        patch.start()
        self.addCleanup(patch.stop)

    def test_namespace_manifest_sealed_and_view_exact_with_actual_inode_structure(self):
        # The structural-only test uses socket-typed INODES, not real
        # listening peers. The independent live test below is mandatory.
        for tag in ("vless-main", "vless-cdn"):
            os.mknod(self.meter / tag, stat.S_IFSOCK | 0o600)

        def measure(capsule, deadline):
            deadline()
            capsule._check_liveness()
            for tag in capsule._tags:
                evidence = routes._socket_identity(capsule._meter_fd, tag)
                if capsule._socket_ids.get(tag, evidence) != evidence:
                    raise ValueError("original socket changed")
                capsule._socket_ids[tag] = evidence
            deadline()

        with mock.patch.object(routes.FirstGenesisRoutes, "_check_meter", measure):
            with routes.FirstGenesisRoutes(self.roster, self.fd) as capsule:
                with namespace_route.NamespaceMeterInputs(capsule) as bundle:
                    view, manifest = bundle.child_fds
                    self.assertIsNone(bundle.ensure_current())
                    self.assertNotIn(capsule.directory_fd, bundle.child_fds)
                    self.assertNotIn(capsule._pidfd, bundle.child_fds)
                    data = os.pread(manifest, namespace_route.MAX_MANIFEST_BYTES, 0)
                    value = json.loads(data)
                    self.assertEqual(value["aliases"], ["xmesh-u100--vless-cdn", "xmesh-u100--vless-main"])
                    self.assertEqual(value["runtimeId"], self.runtime)
                    self.assertEqual(value["meterDirectoryFd"], view)
                    self.assertEqual(value["peerInode"], str(bundle._peer.inode))
                    self.assertEqual(value["sockets"], [
                        {"tag": tag, "device": str(capsule._socket_ids[tag][0]),
                         "inode": str(capsule._socket_ids[tag][1])}
                        for tag in sorted(capsule._tags)])
                    self.assertNotIn(b"/proc/", data)
                    self.assertNotIn(b"pidfd", data)
                    self.assertEqual(os.fstat(view).st_ino, os.stat("..", dir_fd=view).st_ino)
                    self.assertEqual(fcntl.fcntl(manifest, fcntl.F_GET_SEALS),
                                     namespace_route.certificates.SEALS)
                    with self.assertRaises(OSError) as failure:
                        os.pwrite(manifest, b"x", 0)
                    self.assertEqual(failure.exception.errno, errno.EPERM)
                    with self.assertRaises(OSError) as failure:
                        os.unlink("vless-main", dir_fd=view)
                    self.assertEqual(failure.exception.errno, errno.EROFS)
                    (self.meter/"foreign").write_text("unexpected")
                    with self.assertRaisesRegex(ValueError, "foreign or changed sockets"):
                        bundle.ensure_current()
                for fd in (view, manifest):
                    with self.assertRaises(OSError):
                        os.fstat(fd)
                (self.meter/"foreign").unlink()
                with namespace_route.NamespaceMeterInputs(capsule) as bundle:
                    view, manifest = bundle.child_fds
                    replacement = namespace_route.certificates._sealed_bytes(
                        "foreign-identical-manifest", os.pread(manifest, 1<<20, 0))
                    try:
                        os.dup2(replacement, manifest, inheritable=False)
                        with self.assertRaisesRegex(ValueError, "manifest changed"):
                            bundle.ensure_current()
                    finally:
                        os.close(replacement)
                with namespace_route.NamespaceMeterInputs(capsule) as bundle:
                    view, _ = bundle.child_fds
                    os.dup2(capsule._meter_fd, view, inheritable=False)
                    with self.assertRaisesRegex(ValueError, "pinned read-only mount"):
                        bundle.ensure_current()

    def test_inherited_fd_pins_original_directory_even_after_path_replacement(self):
        with routes.FirstGenesisRoutes(self.roster, self.fd) as capsule:
            self.assertIsNone(capsule.ensure_current())
            self.assertFalse(os.get_inheritable(capsule.directory_fd))
            path = self.root / capsule._name
            self.assertEqual(os.readlink(path / "ingress-u100"), self.target)
            script = """
import os, stat, sys
root = sys.argv[1]
info = os.lstat(root)
assert stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
assert info.st_uid == os.geteuid()
print(os.readlink(os.path.join(root, 'ingress-u100')))
"""

            def read_child():
                return subprocess.check_output(
                    [sys.executable, "-c", script, capsule.ingress_state],
                    pass_fds=(capsule.directory_fd,), timeout=5).decode().strip()
            self.assertEqual(read_child(), self.target)
            moved = self.root / "renamed-original"
            path.rename(moved)
            path.mkdir(mode=0o700)
            (path / "ingress-u100").symlink_to("/proc/1/root/dev/shm/foreign")
            self.assertEqual(read_child(), self.target)
            with self.assertRaisesRegex(ValueError, "capsule changed"):
                capsule.ensure_current()
            fd = capsule.directory_fd
        # Cleanup MUST never remove the substituted path or its contents.
        self.assertEqual(os.readlink(path / "ingress-u100"), "/proc/1/root/dev/shm/foreign")
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_actual_readonly_mount_and_unprivileged_child_cannot_change_it(self):
        with routes.FirstGenesisRoutes(self.roster, self.fd) as capsule:
            ro = capsule.directory_fd
            writer = capsule._write_fd
            self.assertNotEqual(routes.route_mount.mount_id(ro),
                                routes.route_mount.mount_id(writer))
            self.assertEqual(os.fstat(ro).st_ino, os.fstat(writer).st_ino)
            self.assertTrue(os.fstatvfs(ro).f_flag & os.ST_RDONLY)
            self.assertFalse(os.fstatvfs(writer).f_flag & os.ST_RDONLY)
            with self.assertRaises(OSError) as failure:
                os.unlink("ingress-u100", dir_fd=ro)
            self.assertEqual(failure.exception.errno, errno.EROFS)
            script = r"""
import ctypes, errno, os, sys
sys.path.insert(0, sys.argv[1])
import public_tls_route_mount as m
fd = int(sys.argv[2])
writer = int(sys.argv[3])
root = sys.argv[4]
status = dict(line.split(':',1) for line in open('/proc/self/status') if ':' in line)
assert int(status['CapEff'].strip(),16) == 0
assert int(status['CapBnd'].strip(),16) == 0
assert status['NoNewPrivs'].strip() == '1'
# The actual pass_fds operation exposes no writable parent capsule fd.
try:
    os.fstat(writer)
    raise AssertionError("writable parent directory FD inherited")
except OSError as e:
    assert e.errno == errno.EBADF
assert os.fstatvfs(fd).f_flag & m.VFS_FLAGS == m.VFS_FLAGS
assert os.readlink(root+'/ingress-u100') == sys.argv[5]
for attempt in (lambda: os.unlink('ingress-u100',dir_fd=fd),
                lambda: os.symlink('/foreign',root+'/foreign'),
                lambda: os.mkdir('new',dir_fd=fd)):
    try:
        attempt()
        raise AssertionError("route mount accepted child mutation")
    except OSError as e:
        assert e.errno == errno.EROFS, e
# Root UID alone cannot undo mount attributes after losing CAP_SYS_ADMIN.
attr = m.MountAttr(0,m.MOUNT_ATTR_RDONLY,0,0)
assert m._libc().mount_setattr(fd,b'',m.AT_EMPTY_PATH,ctypes.byref(attr),ctypes.sizeof(attr)) == -1
assert ctypes.get_errno() == errno.EPERM
assert os.readlink(root+'/ingress-u100') == sys.argv[5]
print('read-only child verified')
"""
            # Hosted checkout may sit under /home/runner (0700). A
            # capless UID-0 child cannot traverse it. Copy the exact helper
            # to the fixture's own root-private temporary directory; do not
            # grant DAC override or alter checkout permissions.
            isolated_module = self.root.parent / "public_tls_route_mount.py"
            shutil.copyfile(ROOT / "experiments/quota-v2-physical-stop/public_tls_route_mount.py",
                            isolated_module)
            isolated_module.chmod(0o600)
            output = subprocess.check_output([
                "setpriv", "--no-new-privs", "--bounding-set=-all",
                "--inh-caps=-all", "--ambient-caps=-all", sys.executable,
                "-c", script, str(isolated_module.parent),
                str(ro), str(writer), capsule.ingress_state, self.target,
            ], pass_fds=(ro,), timeout=5)
            self.assertEqual(output.strip(), b"read-only child verified")
            self.assertIsNone(capsule.ensure_current())

    def test_writable_fd_substitution_and_unsupported_mount_fail_closed(self):
        with routes.FirstGenesisRoutes(self.roster, self.fd) as capsule:
            os.dup2(capsule._write_fd, capsule.directory_fd, inheritable=False)
            with self.assertRaisesRegex(ValueError, "pinned read-only mount"):
                capsule.ensure_current()
        self.assertEqual(list(self.root.iterdir()), [])
        with mock.patch.object(routes.route_mount, "readonly_view",
                               side_effect=OSError(errno.ENOSYS, "no detached mount support")):
            with self.assertRaises(OSError):
                routes.FirstGenesisRoutes(self.roster, self.fd)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_mutable_agent_route_retarget_is_detected_without_redirecting_capsule(self):
        with routes.FirstGenesisRoutes(self.roster, self.fd) as capsule:
            link = self.source / "ingress-u100"
            link.unlink()
            link.symlink_to("/proc/1/root/dev/shm/foreign")
            self.assertEqual(os.readlink("ingress-u100", dir_fd=capsule.directory_fd), self.target)
            with self.assertRaisesRegex(ValueError, "changed from signed original"):
                capsule.ensure_current()

    def test_foreign_or_pending_source_routes_never_create_capsule(self):
        for name in ("ingress-u999", ".ingress-pending"):
            extra = self.source / name
            extra.symlink_to(self.target)
            try:
                with self.assertRaisesRegex(ValueError, "incomplete, foreign or pending"):
                    routes.FirstGenesisRoutes(self.roster, self.fd)
                self.assertEqual(list(self.root.iterdir()), [])
            finally:
                extra.unlink()

    def test_expired_grant_and_changed_local_roster_fail_closed(self):
        with routes.FirstGenesisRoutes(self.roster, self.fd) as capsule:
            self.roster._grants[100][1]["revision"] += 1
            with self.assertRaisesRegex(ValueError, "expired or changed"):
                capsule.ensure_current()
        self.roster._grants[100][1]["revision"] -= 1
        with routes.FirstGenesisRoutes(self.roster, self.fd) as capsule:
            with mock.patch.object(routes.time, "time_ns",
                                   return_value=(min(capsule._expires) + 1) * 1_000_000):
                with self.assertRaisesRegex(ValueError, "expired or changed"):
                    capsule.ensure_current()

    def test_clock_rollback_or_monotonic_expiry_cannot_extend_routes(self):
        with routes.FirstGenesisRoutes(self.roster, self.fd) as capsule:
            with mock.patch.object(routes.time, "time_ns",
                                   return_value=(capsule._wall_ms - 1) * 1_000_000):
                with self.assertRaisesRegex(ValueError, "expired or changed clock"):
                    capsule.ensure_current()
            with mock.patch.object(routes.time, "monotonic_ns",
                                   return_value=capsule._mono_ns +
                                   (capsule._expiry_ms - capsule._wall_ms) * 1_000_000):
                with self.assertRaisesRegex(ValueError, "expired or changed clock"):
                    capsule.ensure_current()

    def test_refuses_nonroot_unsafe_roots_and_unrelated_state_fd(self):
        with mock.patch.object(routes.os, "geteuid", return_value=1000):
            with self.assertRaisesRegex(ValueError, "root"):
                routes.FirstGenesisRoutes(self.roster, self.fd)
        self.root.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "unsafe root-private"):
            routes.FirstGenesisRoutes(self.roster, self.fd)
        self.root.chmod(0o700)
        foreign = os.open(self.root, routes.DIR_FLAGS)
        try:
            with self.assertRaisesRegex(ValueError, "source or private route root"):
                routes.FirstGenesisRoutes(self.roster, foreign)
        finally:
            os.close(foreign)


class FirstGenesisRouteKernelPeerTests(RouteFixture):
    """Must run with real Unix listeners in hosted CI; no local fallback."""

    def test_independent_go_child_uses_production_short_path_and_kernel_peer(self):
        # No mock of the production Go filesystem/Unix dial primitives.
        # Hosted CI provides the pinned Go toolchain and genuine AF_UNIX.
        source = self.root.parent / "read-route.go"
        source.write_text("""
package main
import ("fmt"; "net"; "os"; "path/filepath"; "strconv"; "syscall")
func main() {
    root := os.Args[1]
    info, err := os.Lstat(root)
    if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 ||
       info.Sys().(*syscall.Stat_t).Uid != uint32(os.Geteuid()) || !filepath.IsAbs(root) {
        panic("untrusted private VLESS directory")
    }
    link := filepath.Join(root, "ingress-u100")
    target, err := os.Readlink(link)
    if err != nil { panic(err) }
    conn, err := net.Dial("unix", filepath.Join(link, "vless-main"))
    if err != nil { panic(err) }
    defer conn.Close()
    raw, err := conn.(*net.UnixConn).SyscallConn()
    if err != nil { panic(err) }
    var cred *syscall.Ucred
    var peerErr error
    err = raw.Control(func(fd uintptr) {
        cred, peerErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
    })
    after, linkErr := os.Readlink(link)
    pid, _ := strconv.Atoi(os.Args[2])
    if err != nil || peerErr != nil || linkErr != nil || target != after ||
       cred == nil || int(cred.Pid) != pid || cred.Uid != uint32(os.Geteuid()) {
        panic("private VLESS peer changed")
    }
    fmt.Println(target)
}
""")
        binary = self.root.parent / "read-route"
        env = dict(os.environ, GO111MODULE="off", GOPROXY="off",
                   CGO_ENABLED="0", GOTOOLCHAIN="local",
                   GOCACHE=str(self.root.parent / "go-cache"))
        subprocess.run(["go", "build", "-o", str(binary), str(source)],
                       env=env, check=True, timeout=90)
        with routes.FirstGenesisRoutes(self.roster, self.fd) as capsule:
            def read_child():
                return subprocess.check_output(
                    ["setpriv", "--no-new-privs", "--bounding-set=-all",
                     "--inh-caps=-all", "--ambient-caps=-all", str(binary),
                     capsule.ingress_state, str(self.child.pid)],
                    pass_fds=(capsule.directory_fd,), timeout=5).decode().strip()
            self.assertEqual(read_child(), self.target)
            ordinary = self.source / "ingress-u100"
            ordinary.unlink()
            ordinary.symlink_to("/proc/1/root/dev/shm/foreign")
            self.assertEqual(read_child(), self.target)
            with self.assertRaisesRegex(ValueError, "changed from signed original"):
                capsule.ensure_current()

    def test_namespace_view_and_sealed_manifest_authenticate_actual_invisible_peer(self):
        # The child imports only fixture code from root-private temp;
        # no host-proc route, original meter pidfd or writable FD passed.
        helper = self.root.parent / "public_tls_peer_identity.py"
        shutil.copyfile(ROOT / "experiments/quota-v2-physical-stop/public_tls_peer_identity.py", helper)
        helper.chmod(0o600)
        inner = r"""
import errno, fcntl, json, os, socket, stat, struct, sys
sys.path.insert(0, sys.argv[1])
import public_tls_peer_identity as proof
view, manifest, old_pid = map(int, sys.argv[2:5])
verdict = sys.argv[5]
assert os.getpid() == 1 and os.getuid() == os.getgid() == 0
assert not os.path.exists(f"/proc/{old_pid}")
status = dict(line.split(":", 1) for line in open("/proc/self/status") if ":" in line)
assert status["NoNewPrivs"].strip() == "1"
for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
    assert int(status[key].strip(), 16) == 0
flags = os.ST_RDONLY | os.ST_NOSUID | os.ST_NODEV | os.ST_NOEXEC
assert os.fstatvfs(view).f_flag & flags == flags
assert os.fstat(view).st_ino == os.stat("..", dir_fd=view).st_ino
assert fcntl.fcntl(manifest, fcntl.F_GET_SEALS) == 15
value = json.loads(os.pread(manifest, 1<<20, 0))
assert value["meterDirectoryFd"] == view
assert os.fstat(view).st_dev == int(value["meterDirectoryDevice"])
assert os.fstat(view).st_ino == int(value["meterDirectoryInode"])
assert value["aliases"] == ["xmesh-u100--vless-cdn", "xmesh-u100--vless-main"]
token = proof.PidfdIdentity(int(value["peerDevice"]), int(value["peerInode"]))
original = next(item for item in value["sockets"] if item["tag"] == "vless-main")
actual = os.stat("vless-main", dir_fd=view, follow_symlinks=False)
assert ((actual.st_dev, actual.st_ino) ==
        (int(original["device"]), int(original["inode"]))) == (verdict == "accept")
for name in os.listdir("/proc/self/fd"):
    try:
        assert proof._filesystem_magic(int(name)) != proof.PID_FS_MAGIC
    except OSError as exc:
        assert exc.errno == errno.EBADF
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as conn:
    conn.connect(f"/proc/self/fd/{view}/vless-main")
    cred = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    assert cred == (0, 0, 0)
    if verdict == "accept":
        assert proof.verify_connected_peer(conn, token) is None
    else:
        try:
            proof.verify_connected_peer(conn, token)
        except ValueError as exc:
            assert str(exc) == "Unix peer is not the original pidfs meter object"
        else:
            raise AssertionError("foreign same-UID peer accepted")
print("namespace_manifest_" + verdict)
"""
        with routes.FirstGenesisRoutes(self.roster, self.fd) as capsule:
            with namespace_route.NamespaceMeterInputs(capsule) as bundle:
                view, manifest = bundle.child_fds
                def check(verdict):
                    output = subprocess.check_output([
                        "unshare", "--pid", "--fork", "--kill-child=SIGKILL", "--mount-proc",
                        "setpriv", "--no-new-privs", "--bounding-set=-all",
                        "--inh-caps=-all", "--ambient-caps=-all", sys.executable,
                        "-I", "-B", "-c", inner, str(helper.parent), str(view), str(manifest),
                        str(self.child.pid), verdict,
                    ], pass_fds=bundle.child_fds, timeout=8)
                    self.assertEqual(output.strip(), ("namespace_manifest_" + verdict).encode())
                check("accept")
                target = self.meter / "vless-main"
                target.unlink()
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as other:
                    other.bind(str(target))
                    target.chmod(0o600)
                    other.listen(1)
                    check("reject")
                    with self.assertRaisesRegex(ValueError, "socket was replaced"):
                        bundle.ensure_current()

    def test_actual_kernel_peer_and_cleanup(self):
        with routes.FirstGenesisRoutes(self.roster, self.fd) as capsule:
            self.assertIsNone(capsule.ensure_current())
            self.assertEqual(set(capsule._socket_ids), {"vless-cdn", "vless-main"})
            self.assertEqual(os.readlink("ingress-u100", dir_fd=capsule.directory_fd),
                             self.target)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_swapped_unix_peer_cannot_masquerade_as_original_meter(self):
        target = self.meter / "vless-main"
        target.unlink()
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as foreign:
            foreign.bind(str(target))
            target.chmod(0o600)
            foreign.listen(1)
            with self.assertRaisesRegex(ValueError, "different kernel peer"):
                routes.FirstGenesisRoutes(self.roster, self.fd)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_real_meter_exit_and_socket_replacement_are_terminal_for_capsule(self):
        with routes.FirstGenesisRoutes(self.roster, self.fd) as capsule:
            target = self.meter / "vless-main"
            target.unlink()
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as foreign:
                foreign.bind(str(target))
                target.chmod(0o600)
                foreign.listen(1)
                with self.assertRaisesRegex(ValueError, "socket was replaced"):
                    capsule.ensure_current()
            self.child.kill()
            self.child.wait(timeout=5)
            with self.assertRaisesRegex(ValueError, "changed or exited"):
                capsule.ensure_current()



if __name__ == "__main__":
    unittest.main()
