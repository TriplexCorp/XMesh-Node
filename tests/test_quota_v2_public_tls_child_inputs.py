#!/usr/bin/env python3
"""Real procfs, sealed memfds, detached RO mount and direct child; no socket."""
from contextlib import contextmanager
import os
from pathlib import Path
import select
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments/quota-v2-physical-stop"))
import public_tls_child_inputs as proof
import public_tls_certificates as certificates
import public_tls_route_mount as mounts


class ChildInputTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0, "real Linux detached mount proof requires root")
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.source = self.own(os.open(self.work.name, mounts.DIR_FLAGS))
        view, _ = mounts.readonly_view(self.source)
        self.route = self.own(view)
        self.config = self.own(certificates._sealed_bytes("test-config", b'{"test":true}'))
        self.certificate = self.own(certificates._sealed_bytes("test-cert", b"certificate"))
        self.key = self.own(certificates._sealed_bytes("test-key", b"fixture key"))
        self.ca = self.own(certificates._sealed_bytes("test-ca", b"fixture CA"))
        self.alternate = self.own(certificates._sealed_bytes("test-foreign", b"foreign"))
        self.expected = (self.config, self.certificate, self.key, self.route)
        self.forbidden = (self.source, self.ca, self.alternate)
        self.pinned = proof.capture(expected=self.expected, forbidden=self.forbidden,
                                    route_fd=self.route)

    def own(self, fd):
        self.addCleanup(os.close, fd)
        return fd

    @contextmanager
    def child(self, *, pass_fds=None, before="pass"):
        script = (
            "import os,sys\n" + before + "\n"
            "print('ready', flush=True)\n"
            "for line in sys.stdin:\n"
            "    if line.strip()=='close':\n"
            f"        os.close({self.config})\n"
            "    print('done', flush=True)\n"
        )
        proc = subprocess.Popen([
            "setpriv", "--no-new-privs", "--bounding-set=-all",
            "--inh-caps=-all", "--ambient-caps=-all", sys.executable, "-c", script,
        ], pass_fds=(
            self.expected if pass_fds is None else pass_fds),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            self.assertTrue(select.select([proc.stdout], [], [], 5)[0])
            self.assertEqual(proc.stdout.readline(), "ready\n")
            yield proc
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.communicate(timeout=5)

    def check(self, child):
        return proof.verify(child, expected=self.expected,
                            forbidden=self.forbidden, route_fd=self.route,
                            pinned=self.pinned)

    def test_real_exact_inherited_config_key_certificate_and_detached_route(self):
        with self.child() as child:
            self.assertIsNone(self.check(child))
            self.assertIsNone(self.check(child))
            child.stdin.write("close\n")
            child.stdin.flush()
            self.assertTrue(select.select([child.stdout], [], [], 5)[0])
            self.assertEqual(child.stdout.readline(), "done\n")
            with self.assertRaises((ValueError, OSError)):
                self.check(child)

    def test_owner_fd_replacement_after_assembly_is_refused(self):
        with self.child() as child:
            backup = os.dup(self.config)
            try:
                os.dup2(self.alternate, self.config, inheritable=False)
                with self.assertRaisesRegex(ValueError, "owner pinned input"):
                    self.check(child)
            finally:
                os.dup2(backup, self.config, inheritable=False)
                os.close(backup)
            self.assertIsNone(self.check(child))

    def test_alternate_config_same_fd_number_is_refused(self):
        with self.child(pass_fds=(*self.expected, self.alternate),
                        before=f"os.dup2({self.alternate},{self.config}); os.close({self.alternate})") as child:
            with self.assertRaisesRegex(ValueError, "exact pinned"):
                self.check(child)

    def test_same_route_inode_but_writable_mount_is_refused(self):
        with self.child(pass_fds=(*self.expected, self.source),
                        before=f"os.dup2({self.source},{self.route}); os.close({self.source})") as child:
            with self.assertRaisesRegex(ValueError, "exact pinned"):
                self.check(child)

    def test_leaked_supervisor_ca_or_writable_route_fd_is_refused(self):
        for leaked in (self.ca, self.source):
            with self.subTest(leaked=leaked), self.child(pass_fds=(*self.expected, leaked)) as child:
                with self.assertRaisesRegex(ValueError, "extra protected"):
                    self.check(child)

    def test_extra_duplicate_of_protected_fd_is_refused(self):
        with self.child(before=f"os.dup({self.key})") as child:
            with self.assertRaisesRegex(ValueError, "extra protected"):
                self.check(child)


if __name__ == "__main__":
    unittest.main()
