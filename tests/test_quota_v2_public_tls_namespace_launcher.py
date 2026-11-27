#!/usr/bin/env python3
"""Prove the bootstrap executes exactly checked immutable bytes, not a path."""
import fcntl
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

MODULES = Path(__file__).resolve().parents[1]/"experiments/quota-v2-physical-stop"
sys.path.insert(0, str(MODULES))
import public_tls_namespace_launcher as launcher


class BootstrapTests(unittest.TestCase):
    def execute(self, fd, digest):
        return subprocess.run([sys.executable, "-I", "-B", "-c",
            launcher.SOURCE_LOADER + '''
import sys
network = load_sealed_network(int(sys.argv[1]), sys.argv[2])
print(network.PROOF)
''', str(fd), digest], pass_fds=(fd,), capture_output=True,
            text=True, timeout=5)

    def test_sealed_snapshot_survives_path_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/"fence.py"
            original = b'PROOF = "original sealed bytes"\n'
            source.write_bytes(original)
            fd, digest = launcher.snapshot_fence(source)
            try:
                self.assertEqual(digest, hashlib.sha256(original).hexdigest())
                self.assertFalse(os.get_inheritable(fd))
                source.unlink()
                source.write_bytes(b'raise AssertionError("mutable path executed")\n')
                with self.assertRaises(OSError):
                    os.pwrite(fd, b"replacement", 0)
                result = self.execute(fd, digest)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "original sealed bytes")
            finally:
                os.close(fd)

    def test_mismatch_is_rejected_before_executing_source(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)/"fence.py"
            source.write_text('raise AssertionError("unexpected code execution")\n')
            fd, _ = launcher.snapshot_fence(source)
            try:
                result = self.execute(fd, "0"*64)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("source digest mismatch", result.stderr)
                self.assertNotIn("AssertionError: unexpected code execution", result.stderr)
            finally:
                os.close(fd)

    def test_unsealed_matching_bytes_refused(self):
        payload = b'raise AssertionError("unexpected code execution")\n'
        fd = os.memfd_create("mutable", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
        try:
            os.fchmod(fd, 0o600)
            os.write(fd, payload)
            self.assertEqual(fcntl.fcntl(fd, fcntl.F_GET_SEALS), 0)
            result = self.execute(fd, hashlib.sha256(payload).hexdigest())
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("immutable network fence source required", result.stderr)
            self.assertNotIn("AssertionError: unexpected code execution", result.stderr)
        finally:
            os.close(fd)

    def test_real_source_snapshot_and_bootstrap_compile(self):
        fd, digest = launcher.snapshot_fence()
        try:
            local = {}
            exec(launcher.SOURCE_LOADER, local)
            network = local["load_sealed_network"](fd, digest)
            self.assertEqual(network.AUDIT_ARCH_X86_64, 0xC000003E)
            self.assertTrue(callable(network.install))
            compile(launcher.PIVOT_EXEC, "<bootstrap>", "exec")
        finally:
            os.close(fd)

    def test_snapshot_refuses_nonregular_symlink_and_hardlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root/"source"
            source.write_bytes(b"PROOF = 1")
            (root/"symlink").symlink_to(source)
            with self.assertRaises(OSError):
                launcher.snapshot_fence(root/"symlink")
            os.link(source, root/"hardlink")
            with self.assertRaises(ValueError):
                launcher.snapshot_fence(source)
            os.mkfifo(root/"fifo")
            with self.assertRaises(ValueError):
                launcher.snapshot_fence(root/"fifo")

    def test_spawn_refuses_non_hosted_environment_before_touching_inputs(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {"GITHUB_ACTIONS":"false"}), self.assertRaisesRegex(ValueError, "disposable hosted"):
            launcher.spawn_disposable(original_ns="unused", proof_args={})


if __name__ == "__main__":
    unittest.main()
