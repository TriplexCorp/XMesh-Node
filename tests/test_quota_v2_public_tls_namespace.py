#!/usr/bin/env python3
"""Real pivot-root fixture, capless isolated child, and kernel topology proof."""
from contextlib import contextmanager
import ctypes
import fcntl
import os
from pathlib import Path
import select
import subprocess
import sys
import time
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "experiments/quota-v2-physical-stop"
sys.path.insert(0, str(MODULES))
import public_tls_namespace as proof
import public_tls_deadman as deadman


FIXTURE = r"""
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#define REQUIRE(x) do { if (!(x)) { perror(#x); return 90; } } while (0)
int main(int argc, char **argv) {
    REQUIRE(argc == 2 && getpid() == 1 && getuid() == 0 && getgid() == 0);
    struct stat a, b;
    REQUIRE(stat("/", &a) == 0 && stat("/proc/1/root", &b) == 0);
    REQUIRE(a.st_dev == b.st_dev && a.st_ino == b.st_ino);
    REQUIRE(access("/etc/shadow", F_OK) == -1 && errno == ENOENT);
    REQUIRE(access("/var/lib/xmesh-xray-sync", F_OK) == -1 && errno == ENOENT);
    int q = open("/qualification.fixture", O_RDONLY);
    REQUIRE(q >= 0);
    char value[8] = {0};
    REQUIRE(read(q, value, sizeof(value)) == 7 && strcmp(value, "fixture") == 0);
    close(q);
    if (strcmp(argv[1], "readonly") == 0) {
        int fd = open("/forbidden", O_CREAT | O_EXCL | O_WRONLY, 0600);
        REQUIRE(fd < 0 && errno == EROFS);
    }
    puts("root_ready"); fflush(stdout);
    REQUIRE(getchar() == 'X');
    return 0;
}
"""

# Only the test starts a disposable root. Not an installed launcher. The
# first process in the new PID namespace pivots and then execs a sealed
# static fixture, directly owned by the disposable single-thread supervisor.
PIVOT_TEST = r"""
import ctypes, os, sys
from pathlib import Path
import select

root, fd, mode = sys.argv[1:]
fd = int(fd)
assert os.getpid() == 1 and os.geteuid() == 0
last_cap = int(Path("/proc/sys/kernel/cap_last_cap").read_text())
lib = ctypes.CDLL(None, use_errno=True)
lib.mount.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_char_p,
                      ctypes.c_ulong, ctypes.c_char_p]
lib.umount2.argtypes = [ctypes.c_char_p, ctypes.c_int]

# Resolve ctypes structure layouts before detaching the host root;
# Python 3.14 lazily imports ctypes._layout on class creation.
class Header(ctypes.Structure):
    _fields_ = [("version", ctypes.c_uint32), ("pid", ctypes.c_int)]
class Caps(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint32) for name in ("effective","permitted","inheritable")]
header, caps = Header(0x20080522, 0), (Caps * 2)()

RDONLY, NOSUID, NODEV, NOEXEC, REMOUNT, REC, PRIVATE = 1, 2, 4, 8, 32, 16384, 1<<18
def check(rc, msg):
    if rc != 0:
        e = ctypes.get_errno()
        raise OSError(e, os.strerror(e), msg)

check(lib.mount(None, b"/", None, REC | PRIVATE, None), "private mount propagation")
check(lib.mount(b"proc", os.fsencode(root + "/proc"), b"proc",
                RDONLY | NOSUID | NODEV | NOEXEC, None), "new readonly procfs")
if mode == "extra":
    check(lib.mount(b"tmpfs", os.fsencode(root + "/extra"), b"tmpfs",
                    RDONLY | NOSUID | NODEV | NOEXEC, b"size=1m"), "foreign extra mount")
os.chdir(root)
# Linux amd64 pivot_root syscall. Old root must be detached, not retained
# outside the chroot with an accessible CWD or directory descriptor.
assert os.uname().machine == "x86_64"
check(lib.syscall(155, b".", b"oldroot"), "pivot_root")
os.chdir("/")
check(lib.umount2(b"/oldroot", 2), "detach old root")
os.rmdir("/oldroot")
if mode != "writable":
    check(lib.mount(None, b"/", None, REMOUNT | RDONLY | NOSUID | NODEV | NOEXEC,
                    None), "readonly root filesystem")
assert set(os.listdir("/")) == {"proc","qualification.fixture","extra"}

# No inherited old-root FDs, no elevated root capabilities. A mapped
# test user namespace may deny setgroups; only existing group 0 is okay.
try:
    os.setgroups([])
except PermissionError:
    assert not set(os.getgroups()) - {0}
for cap in range(last_cap + 1):
    check(lib.prctl(24, cap, 0, 0, 0), "drop capability bounding set")

check(lib.capset(ctypes.byref(header), ctypes.byref(caps)), "clear all capabilities")
check(lib.prctl(38, 1, 0, 0, 0), "no new privileges")
os.set_inheritable(fd, False)
os.execve(fd, ["sealed-root-fixture", "writable" if mode == "writable" else "readonly"], {})
"""


class ActualNamespaceTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("root isolated mount namespace required")
        # Do not create mounts in the surrounding host namespace. Hosted
        # CI explicitly places this entire test in a separate private mntns.
        original = os.environ["XMESH_DISPOSABLE_TLS_ROOT_MOUNT_NS"]
        self.assertRegex(original, r"^mnt:\[\d+\]$")
        self.assertNotEqual(os.readlink("/proc/self/ns/mnt"), original)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            self.assertEqual(os.environ.get("RUNNER_ENVIRONMENT"), "github-hosted")
            self.assertEqual(os.readlink("/proc/1/ns/mnt"), original)
        directory = tempfile.TemporaryDirectory(prefix="xmesh-tls-root-")
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        binary = self.directory / "fixture"
        subprocess.run(["gcc", "-static", "-O2", "-x", "c", "-o", binary, "-"],
                       input=FIXTURE.encode(), check=True, timeout=30)
        executable = os.memfd_create("xmesh-test-pivot-exec",
                                     os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | 0x10)
        self.addCleanup(os.close, executable)
        with open(binary, "rb") as source:
            content = source.read()
        written = 0
        while written < len(content):
            written += os.write(executable, content[written:])
        os.fchmod(executable, 0o755)
        fcntl.fcntl(executable, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW |
                    fcntl.F_SEAL_SEAL | 0x10 | 0x20)
        self.executable = executable

    @contextmanager
    def root_mount(self):
        with tempfile.TemporaryDirectory(dir=self.directory) as directory:
            subprocess.run(["mount", "-t", "tmpfs", "-o",
                            "size=1m,mode=0700,nosuid,nodev,noexec", "tmpfs", directory],
                           check=True, timeout=5)
            try:
                path = Path(directory)
                for name in ("proc", "oldroot", "extra"):
                    (path / name).mkdir(mode=0o700)
                (path / "qualification.fixture").write_bytes(b"fixture")
                (path / "qualification.fixture").chmod(0o600)
                fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
                try:
                    yield path, fd, proof.capture_root(fd)
                finally:
                    os.close(fd)
            finally:
                subprocess.run(["umount", directory], check=True, timeout=5)

    @contextmanager
    def fixture(self, root, mode, *, expect_killed=False):
        # Only a strictly single-thread disposable supervisor may make
        # this temporary change to the namespace of future children.
        # No wrapper fork is allowed: the Popen PID itself is namespace
        # init and directly owned by the existing pidfd deadman.
        self.assertEqual(len(os.listdir("/proc/self/task")), 1)
        original = os.readlink("/proc/self/ns/pid")
        self.assertEqual(os.readlink("/proc/self/ns/pid_for_children"), original)
        saved = os.open("/proc/self/ns/pid", os.O_RDONLY | os.O_CLOEXEC)
        lib = ctypes.CDLL(None, use_errno=True)
        newpid = 0x20000000

        def check(result):
            if result != 0:
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))

        child = None
        try:
            check(lib.unshare(newpid))
            try:
                child = subprocess.Popen(
                    ["unshare", "--mount", "--net", "--ipc", "--uts",
                     "--mount-proc", sys.executable, "-I", "-B", "-c",
                     PIVOT_TEST, str(root), str(self.executable), mode],
                    pass_fds=(self.executable,), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, text=True)
                self.assertNotEqual(os.readlink("/proc/self/ns/pid_for_children"), original)
            finally:
                # Restore before starting any guardian or other process;
                # this does not move the supervisor's active namespace.
                check(lib.setns(saved, newpid))
            self.assertEqual(os.readlink("/proc/self/ns/pid_for_children"), original)
            self.assertEqual(os.readlink("/proc/self/ns/pid"), original)
            self.assertTrue(select.select([child.stdout], [], [], 8)[0], "fixture never ready")
            line = child.stdout.readline()
            if line != "root_ready\n":
                child.wait(timeout=3)
                self.fail(child.stderr.read() + line)
            self.assertEqual(deadman._starttime_and_parent(child.pid)[1], os.getpid())
            self.assertNotEqual(os.readlink(f"/proc/{child.pid}/ns/pid"), original)
            yield child
            if expect_killed:
                self.assertEqual(child.returncode, -9)
            else:
                child.stdin.write("X\n")
                child.stdin.flush()
                self.assertEqual(child.wait(timeout=5), 0)
        finally:
            os.close(saved)
            if child is not None:
                if child.poll() is None:
                    child.kill()
                _, stderr = child.communicate(timeout=5)
                if stderr:
                    print(stderr, file=sys.stderr)

    def test_real_readonly_pivot_and_private_procfs(self):
        with self.root_mount() as (root, descriptor, token), self.fixture(root, "readonly") as child:
            self.assertIsNone(proof.verify(child.pid, descriptor, token))
            self.assertIsNone(proof.verify(child.pid, descriptor, token))
            with self.root_mount() as (_, wrong, wrong_token):
                with self.assertRaisesRegex(ValueError, "exact read-only private tmpfs"):
                    proof.verify(child.pid, wrong, wrong_token)
            self.assertFalse((root / "forbidden").exists())

    def test_real_writable_tmpfs_and_foreign_readonly_attachment_refused(self):
        for mode in ("writable", "extra"):
            with self.subTest(mode=mode), self.root_mount() as (root, descriptor, token):
                with self.fixture(root, mode) as child:
                    with self.assertRaisesRegex(ValueError, "root|mount"):
                        proof.verify(child.pid, descriptor, token)

    def test_direct_owned_namespace_init_is_killed_by_actual_deadman(self):
        with self.root_mount() as (root, descriptor, token):
            with self.fixture(root, "readonly", expect_killed=True) as child:
                guard = deadman.StopOnlyDeadman(child=child, timeout_ms=2000)
                try:
                    self.assertEqual(os.readlink(f"/proc/{guard._guardian.pid}/ns/pid"),
                                     os.readlink("/proc/self/ns/pid"))
                    self.assertIsNone(proof.verify(child.pid, descriptor, token))
                    guard.pulse(deadline_ns=time.monotonic_ns() + 900_000_000,
                                wall_deadline_ms=time.time_ns() // 1_000_000 + 900)
                    # No new heartbeat; actual guardian must kill exact
                    # namespace PID1, not an unshare parent wrapper.
                    self.assertEqual(child.wait(timeout=4), -9)
                    self.assertEqual(guard._guardian.wait(timeout=3), 1)
                finally:
                    guard.close()

    def test_unisolated_process_and_non_tmpfs_root_refused(self):
        with self.root_mount() as (_, descriptor, token):
            proc = subprocess.Popen(["sleep", "30"])
            try:
                with self.assertRaisesRegex(ValueError, "not independently isolated"):
                    proof.verify(proc.pid, descriptor, token)
            finally:
                proc.kill()
                proc.wait(timeout=3)
        fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            with self.assertRaisesRegex(ValueError, "private root-owned tmpfs"):
                proof.capture_root(fd)
        finally:
            os.close(fd)


if __name__ == "__main__":
    unittest.main()
