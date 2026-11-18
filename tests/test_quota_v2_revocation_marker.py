#!/usr/bin/env python3
"""Production quota-v2 revocation marker lifecycle and fault-injection tests."""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/xmesh-quota-revocation-marker.py"
spec = importlib.util.spec_from_file_location("quota_revocation_marker", SCRIPT)
marker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(marker)


class DurableRevocationMarkerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="quota-v2-marker-test-")
        self.addCleanup(self.tmp.cleanup)
        self.state = Path(self.tmp.name) / "state"
        self.state.mkdir(mode=0o700)

    def run_helper(self, op, target=None, good=True):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), op, str(target or self.state)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=5,
        )
        if good and result.returncode:
            self.fail(f"{op} unexpectedly rejected: {result.stderr}")
        if not good and result.returncode == 0:
            self.fail(f"{op} unexpectedly succeeded: {result.stdout}")
        return result

    def test_status_arm_replay_and_durable_clear(self):
        self.assertEqual(self.run_helper("status").stdout.strip(), "clear")
        self.run_helper("arm")
        path = self.state / marker.MARKER
        before = path.stat()
        self.assertEqual(path.read_bytes(), marker.CONTENT)
        self.assertEqual(stat.S_IMODE(before.st_mode), 0o600)
        self.assertEqual(before.st_nlink, 1)
        self.assertEqual(self.run_helper("status").stdout.strip(), "armed")
        self.run_helper("arm")
        self.assertEqual(path.stat().st_ino, before.st_ino,
                         "idempotent retry rewrote the previous deny marker")
        self.assertEqual(list(self.state.glob(".quota-v2-intent-*")), [])
        self.run_helper("clear")
        self.assertFalse(path.exists())
        self.run_helper("clear")
        self.assertEqual(self.run_helper("status").stdout.strip(), "clear")

    def test_untrusted_state_dir_or_marker_fails_closed(self):
        self.state.chmod(0o755)
        self.run_helper("status", good=False)
        self.run_helper("arm", good=False)
        self.state.chmod(0o700)

        self.run_helper("arm")
        path = self.state / marker.MARKER
        path.chmod(0o644)
        for op in ("status", "arm", "clear"):
            self.run_helper(op, good=False)
        path.chmod(0o600)
        path.write_bytes(b"unexpected-contents\n")
        for op in ("status", "arm", "clear"):
            self.run_helper(op, good=False)
        path.unlink()

        victim = self.state / "victim"
        victim.write_bytes(b"keep-unchanged")
        path.symlink_to(victim)
        for op in ("status", "arm", "clear"):
            self.run_helper(op, good=False)
        self.assertEqual(victim.read_bytes(), b"keep-unchanged")
        path.unlink()

        self.run_helper("arm")
        extra = self.state / "hardlinked"
        os.link(path, extra)
        for op in ("status", "arm", "clear"):
            self.run_helper(op, good=False)
        extra.unlink()
        self.run_helper("clear")

        linked_state = Path(self.tmp.name) / "symlink-state"
        linked_state.symlink_to(self.state, target_is_directory=True)
        self.run_helper("status", target=linked_state, good=False)
        self.run_helper("arm", target=linked_state, good=False)

    def test_link_publication_failure_cannot_acknowledge_revocation(self):
        with mock.patch.object(marker.os, "link", side_effect=OSError("disk/link error")):
            with self.assertRaises(OSError):
                marker.operate("arm", self.state)
        self.assertFalse((self.state / marker.MARKER).exists())
        self.assertEqual(list(self.state.glob(".quota-v2-intent-*")), [])

    def test_directory_fsync_failure_is_not_mistaken_for_success(self):
        original_fsync = os.fsync
        def fail_dir_sync(fd):
            if stat.S_ISDIR(os.fstat(fd).st_mode):
                raise OSError("simulated quota directory fsync failure")
            return original_fsync(fd)
        with mock.patch.object(marker.os, "fsync", side_effect=fail_dir_sync):
            with self.assertRaisesRegex(OSError, "directory fsync failure"):
                marker.operate("arm", self.state)
        # A visible unacknowledged link is conservative; a retry MUST fsync
        # the existing directory and not replace the previously linked file.
        path = self.state / marker.MARKER
        self.assertTrue(path.is_file())
        old_inode = path.stat().st_ino
        self.run_helper("arm")
        self.assertEqual(path.stat().st_ino, old_inode)
        self.assertEqual(self.run_helper("status").stdout.strip(), "armed")

    def test_short_or_failed_write_never_creates_denial(self):
        with mock.patch.object(marker.os, "write", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                marker.operate("arm", self.state)
        self.assertFalse((self.state / marker.MARKER).exists())
        self.assertEqual(list(self.state.glob(".quota-v2-intent-*")), [])

    def test_production_script_rejects_old_non_durable_path(self):
        sync = (ROOT / "deploy/xmesh-xray-sync.sh").read_text()
        installer = (ROOT / "deploy/install-v6-strict-operational-agents.sh").read_text()
        self.assertIn('python3 "$DENY_HELPER" arm "$STATE"', sync)
        self.assertIn('python3 "$DENY_HELPER" status "$STATE"', sync)
        self.assertIn('python3 "$DENY_HELPER" clear "$STATE"', sync)
        self.assertNotIn('sync -f "$REVOCATION_MARKER"', sync)
        self.assertNotIn('rm -f "$REVOCATION_MARKER"', sync)
        self.assertIn("xmesh-quota-revocation-marker.py", installer)


if __name__ == "__main__":
    unittest.main(verbosity=2)
