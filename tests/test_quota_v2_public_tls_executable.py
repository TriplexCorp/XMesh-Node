#!/usr/bin/env python3
"""Real kernel executable seals and post-exec ownership, no listener."""
import errno
import fcntl
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]
                       / "experiments/quota-v2-physical-stop"))
import public_tls_executable as executable


class ExecutableTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0, "root required for executable proof tests")
        tmp = tempfile.TemporaryDirectory(prefix="xmesh-exec-proof-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.installed = self.root / "installed"
        self.meter_binary = self.root / "meter"
        self.qualification = self.root / "qualification"
        self.qualification.mkdir(mode=0o700)
        # Do not copy coreutils: distributions may dispatch the applet
        # by AT_EXECFN rather than argv[0]. Compile a tiny independent
        # non-listening ELF whose behavior is invariant under FD exec.
        subprocess.run(["/usr/bin/cc", "-x", "c", "-O2", "-Wall", "-Werror",
                        "-o", str(self.installed), "-"],
                       input=b"#include <unistd.h>\nint main(void) { for (;;) pause(); }\n",
                       check=True, timeout=15)
        self.installed.chmod(0o755)
        shutil.copyfile(self.installed, self.meter_binary)
        self.meter_binary.chmod(0o755)
        self.digest = hashlib.sha256(self.installed.read_bytes()).hexdigest()
        self.record = self.qualification / "identity"
        self.write_record(self.digest)
        for name, value in (("EXECUTABLE", self.installed),
                            ("QUALIFICATION", self.qualification)):
            patch = mock.patch.object(executable.release, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        self.meter = self.child([str(self.meter_binary)])
        self.runtime = executable.wal_transport.runtime_identity.trusted_runtime_identity(
            self.meter.pid)

    def write_record(self, digest):
        self.record.write_text("".join(
            f"{key}={digest if key == 'artifactSha256' else 'a'*40}\n"
            for key in executable.release.FIELDS))
        self.record.chmod(0o600)

    def child(self, args, **kwargs):
        proc = subprocess.Popen(args, **kwargs)
        self.addCleanup(self.stop, proc)
        return proc

    @staticmethod
    def stop(proc):
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=3)

    def snapshot(self):
        return executable.PinnedTlsExecutable(runtime_pid=self.meter.pid,
                                               runtime_id=self.runtime)

    def test_real_sealed_exec_and_no_mutation(self):
        with self.snapshot() as proof:
            fd = proof.exec_fd
            self.assertIsNone(proof.ensure_binding(runtime_pid=self.meter.pid,
                                                   runtime_id=self.runtime))
            for pid, runtime in ((self.meter.pid+1, self.runtime),
                                 (self.meter.pid, "0"*64)):
                with self.assertRaisesRegex(ValueError, "another original meter"):
                    proof.ensure_binding(runtime_pid=pid, runtime_id=runtime)
            self.assertEqual(fcntl.fcntl(fd, fcntl.F_GET_SEALS), executable.SEALS)
            with self.assertRaises(OSError) as cm:
                os.fchmod(fd, 0o400)
            self.assertEqual(cm.exception.errno, errno.EPERM)
            self.assertEqual(os.fstat(fd).st_mode & 0o777, 0o500)
            writer = os.open(f"/proc/self/fd/{fd}", os.O_RDWR)
            try:
                for action in (lambda: os.pwrite(writer, b"x", 0),
                               lambda: os.ftruncate(writer, 1)):
                    with self.assertRaises(OSError) as cm:
                        action()
                    self.assertEqual(cm.exception.errno, errno.EPERM)
            finally:
                os.close(writer)
            proc = self.child([f"/proc/self/fd/{fd}"], pass_fds=(fd,))
            self.assertIsNone(proof.verify_child(proc))
            wrong = self.child([str(self.installed)])
            with self.assertRaisesRegex(ValueError, "original sealed"):
                proof.verify_child(wrong)
            self.stop(proc)
            with self.assertRaisesRegex(ValueError, "live owned"):
                proof.verify_child(proc)
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_both_installed_and_running_bytes_must_match_release(self):
        self.installed.write_bytes(b"not qualified")
        with self.assertRaisesRegex(ValueError, "installed TLS executable"):
            self.snapshot()
        self.installed.write_bytes(self.meter_binary.read_bytes() + b"changed")
        self.write_record(hashlib.sha256(self.installed.read_bytes()).hexdigest())
        with self.assertRaisesRegex(ValueError, "original meter executable"):
            self.snapshot()

    def test_rotation_or_meter_exit_invalidates_existing_proof(self):
        with self.snapshot() as proof:
            replacement = self.root / "same-bytes"
            shutil.copyfile(self.installed, replacement)
            replacement.chmod(0o755)
            replacement.replace(self.installed)
            with self.assertRaisesRegex(ValueError, "qualification or original"):
                proof.ensure_current()
        with self.snapshot() as proof:
            self.stop(self.meter)
            with self.assertRaisesRegex(ValueError, "changed or exited"):
                proof.ensure_current()

    def test_substituted_fd_and_expired_preparation_are_rejected(self):
        with self.snapshot() as proof:
            fd = proof.exec_fd
            other = os.open(self.installed, os.O_RDONLY | os.O_CLOEXEC)
            try:
                os.dup2(other, fd, inheritable=False)
            finally:
                os.close(other)
            with self.assertRaisesRegex(ValueError, "sealed TLS executable inode"):
                proof.ensure_current()
        with mock.patch.object(executable, "MAX_PREP_NS", 0):
            with self.assertRaisesRegex(ValueError, "watchdog budget"):
                self.snapshot()

    def test_reject_path_symlink_unsafe_mode_and_foreign_runtime(self):
        self.installed.chmod(0o775)
        with self.assertRaisesRegex(ValueError, "unsafe qualified"):
            self.snapshot()
        self.installed.unlink()
        self.installed.symlink_to(self.meter_binary)
        with self.assertRaises(OSError):
            self.snapshot()
        with self.assertRaisesRegex(ValueError, "meter changed"):
            executable.PinnedTlsExecutable(runtime_pid=self.meter.pid, runtime_id="0"*64)


if __name__ == "__main__":
    unittest.main()
