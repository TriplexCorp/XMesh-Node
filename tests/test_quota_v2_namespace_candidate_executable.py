#!/usr/bin/env python3
"""Kernel mixed executable proof. Synthetic manifest/bundle are fixture only.

Actual main-only installation verifies both real Sigstore subjects; this test
never mocks a successful signature verifier or installs to production paths.
"""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT/"experiments/xray-dataplane-fence"),
                str(ROOT/"experiments/quota-v2-physical-stop")]
import namespace_candidate_executable as proof
import namespace_candidate_artifact as artifact
import install_namespace_candidate as installation
import public_tls_executable as executable


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class TwoExecutableTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0)
        tmp = tempfile.TemporaryDirectory(prefix="xmesh-mixed-exec-proof-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.source = self.root/"source"
        self.source.mkdir()
        for rel in ("experiments/xray-dataplane-fence", "experiments/quota-v2-physical-stop/namespacepeer"):
            directory = self.source/rel
            directory.mkdir(parents=True)
            (directory/"fixture").write_text("reviewed fixture\n")
        def git(*args):
            subprocess.run(["git","-C",str(self.source),*args],check=True,timeout=10,
                           stdout=subprocess.DEVNULL)
        git("init","-q")
        git("add",".")
        git("-c","user.name=Fixture","-c","user.email=fixture@example.invalid","commit","-qm","source")
        self.revision = artifact.git(self.source,"HEAD")
        self.store = self.root/"candidate-store"
        self.store.mkdir(mode=0o700)
        self.candidate = self.store/self.revision
        self.candidate.mkdir(mode=0o700)
        self.meter = self.root/"ordinary-meter"
        subprocess.run(["/usr/bin/cc","-x","c","-O2","-Wall","-Werror",
                        "-o",str(self.meter),"-"],
                       input=b"#include <unistd.h>\nint main(void) { for (;;) pause(); }\n",
                       check=True,timeout=15)
        self.meter.chmod(0o755)
        self.frontend = self.candidate/"xray"
        shutil.copyfile(self.meter,self.frontend)
        with self.frontend.open("ab") as f:
            f.write(b"distinct frontend executable identity")
        self.frontend.chmod(0o755)
        self.assertNotEqual(digest(self.meter),digest(self.frontend))
        self.qualification = self.root/"ordinary-qualification"
        self.qualification.mkdir(mode=0o700)
        (self.qualification/"identity").write_text("".join(
            f"{key}={digest(self.meter) if key == 'artifactSha256' else 'a'*40}\n"
            for key in executable.release.FIELDS))
        (self.qualification/"identity").chmod(0o600)
        self.manifest = self.candidate/"candidate-manifest.json"
        self.manifest.write_bytes(artifact.canonical(artifact.contract(
            artifact.expected_source(self.source,self.revision), digest(self.frontend))))
        self.manifest.chmod(0o600)
        self.bundle = self.candidate/"provenance.jsonl"
        self.bundle.write_bytes(b"synthetic fixture only; deliberately not a Sigstore attestation\n")
        self.bundle.chmod(0o600)
        self.pins = dict(manifest_sha256=digest(self.manifest),provenance_sha256=digest(self.bundle))
        for module,name,value in ((installation,"ROOT",self.store),
                                  (executable.release,"EXECUTABLE",self.meter),
                                  (executable.release,"QUALIFICATION",self.qualification)):
            patch = mock.patch.object(module,name,value)
            patch.start()
            self.addCleanup(patch.stop)
        patch = mock.patch.dict(os.environ, {"GITHUB_ACTIONS":"true",
                "RUNNER_ENVIRONMENT":"github-hosted","XMESH_DISPOSABLE_BOUND_LISTENER_TEST":"1"})
        patch.start()
        self.addCleanup(patch.stop)
        self.process = self.child([str(self.meter)])
        self.runtime = executable.wal_transport.runtime_identity.trusted_runtime_identity(self.process.pid)

    def child(self,args,**kwargs):
        p = subprocess.Popen(args,**kwargs)
        def stop():
            if p.poll() is None:
                p.kill()
            p.wait(timeout=5)
        self.addCleanup(stop)
        return p

    def snapshot(self, **kw):
        return proof.PinnedNamespaceCandidateExecutable(runtime_pid=self.process.pid,
                runtime_id=self.runtime,source_root=self.source,revision=self.revision,
                **(self.pins | kw))

    def test_separate_real_meter_and_sealed_frontend(self):
        with self.snapshot() as pinned:
            self.assertIsNone(pinned.ensure_current())
            fd = pinned.exec_fd
            self.assertEqual(hashlib.sha256(os.pread(fd,256<<20,0)).hexdigest(),digest(self.frontend))
            child = self.child([f"/proc/self/fd/{fd}"],pass_fds=(fd,))
            self.assertIsNone(pinned.verify_child(child))
            with self.assertRaisesRegex(ValueError,"original sealed"):
                pinned.verify_child(self.child([str(self.meter)]))
        with self.assertRaisesRegex(ValueError,"original meter executable"):
            self.snapshot(fixture_same_candidate=True)

    def test_independent_manifest_and_provenance_pins(self):
        for pin in self.pins:
            with self.subTest(pin=pin), self.assertRaisesRegex(ValueError,"reviewed pin"):
                self.snapshot(**{pin:"0"*64})
        with self.snapshot() as pinned:
            self.bundle.write_bytes(b"replacement")
            with self.assertRaisesRegex(ValueError,"reviewed pin"):
                pinned.ensure_current()

    def test_replaced_frontend_same_bytes_still_rejected(self):
        with self.snapshot() as pinned:
            new = self.root/"replacement"
            shutil.copyfile(self.frontend,new)
            new.chmod(0o755)
            new.replace(self.frontend)
            with self.assertRaisesRegex(ValueError,"qualification or original"):
                pinned.ensure_current()

    def test_wrong_ordinary_meter_digest_and_negative_gate(self):
        with self.snapshot() as pinned:
            # Restore original bytes via a different inode.
            old = self.root/"old-meter"
            shutil.copyfile(self.meter,old)
            old.chmod(0o755)
            old.replace(self.meter)
            with self.assertRaisesRegex(ValueError,"ordinary installed qualification"):
                pinned.ensure_current()
        with mock.patch.dict(os.environ,{"RUNNER_ENVIRONMENT":"self-hosted"}):
            with self.assertRaisesRegex(ValueError,"disposable hosted"):
                self.snapshot()

    def test_candidate_binary_tamper_and_unsafe_provenance(self):
        self.frontend.write_bytes(self.frontend.read_bytes()+b"tamper")
        with self.assertRaisesRegex(ValueError,"foreign, mutable"):
            self.snapshot()
        self.bundle.chmod(0o644)
        with self.assertRaisesRegex(ValueError,"unsafe installed"):
            self.snapshot()


if __name__ == "__main__":
    unittest.main()
