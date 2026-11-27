#!/usr/bin/env python3
"""Local structural contract and actual immutable publication negatives.

No mocked Sigstore acceptance. Real signature checks and the installed
candidate E2E are in the trusted main-only workflow.
"""
import hashlib
import json
import os
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest

PATH = Path(__file__).resolve().parents[1]/"experiments/xray-dataplane-fence"
sys.path.insert(0, str(PATH))
import namespace_candidate_artifact as artifact
import install_namespace_candidate as installation


class ContractTests(unittest.TestCase):
    def setUp(self):
        self.source = {
            "nodeSourceRevision": "a"*40, "upstreamSourceRevision": artifact.UPSTREAM,
            "nodeSourceTree": "b"*40, "patchSourceTree": "c"*40,
            "namespacePeerTree": "d"*40,
        }
        self.binary = b"\x7fELF" + b"known fixture"
        self.value = artifact.contract(self.source, hashlib.sha256(self.binary).hexdigest())
        self.raw = artifact.canonical(self.value)

    def test_exact_source_and_explicit_non_authority(self):
        self.assertEqual(artifact.validate(self.raw, self.binary, self.source), self.value)
        self.assertIs(self.value["candidateOnly"], True)
        self.assertIs(self.value["productionActivationAuthorized"], False)
        self.assertEqual(self.value["verifiedScenarios"],
                         ["signed-witness-expiry", "signed-revocation"])

    def test_wrong_bytes_source_flag_scenarios_and_schema_rejected(self):
        for key, bad in {
            "schemaVersion": True, "kind": "xmesh.metered-xray-candidate",
            "candidateOnly": False, "productionActivationAuthorized": True,
            "nodeSourceRevision": "0"*40, "nodeSourceTree": "0"*40,
            "patchSourceTree": "0"*40, "namespacePeerTree": "0"*40,
            "upstreamSourceRevision": "0"*40, "independentRebuildMatched": 1,
            "goVersion": "go version go1.2 linux/amd64",
            "buildFlags": ["CGO_ENABLED=1"], "verifiedScenarios": ["signed-revocation"],
            "artifactSha256": "0"*64,
        }.items():
            with self.subTest(key=key):
                with self.assertRaises(ValueError):
                    artifact.validate(artifact.canonical(dict(self.value, **{key: bad})),
                                      self.binary, self.source)
        with self.assertRaises(ValueError):
            artifact.validate(self.raw, self.binary+b"changed", self.source)
        with self.assertRaises(ValueError):
            artifact.validate(self.raw, self.binary, dict(self.source, namespacePeerTree="0"*40))

    def test_duplicate_unknown_reformatted_and_nonelf_refused(self):
        for raw in (self.raw+b" ", b'{"schemaVersion":1,'+self.raw[1:],
                    artifact.canonical(dict(self.value, extra=False)),
                    json.dumps(self.value).encode()):
            with self.assertRaises(ValueError):
                artifact.validate(raw, self.binary, self.source)
        raw = artifact.canonical(artifact.contract(self.source, hashlib.sha256(b"not ELF").hexdigest()))
        with self.assertRaisesRegex(ValueError, "ELF"):
            artifact.validate(raw, b"not ELF", self.source)

    def test_real_git_checkout_tree_pins_and_mutations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            def run(*args):
                return subprocess.check_output(["git", "-C", str(root), *args],
                                               stderr=subprocess.STDOUT)
            run("init", "-q")
            run("config", "user.name", "Fixture")
            run("config", "user.email", "fixture@example.invalid")
            for name in ("experiments/xray-dataplane-fence/patch",
                         "experiments/quota-v2-physical-stop/namespacepeer/peer"):
                path = root/name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("original")
            run("add", ".")
            run("commit", "-qm", "pinned source")
            revision = artifact.git(root, "HEAD")
            source = artifact.expected_source(root, revision)
            for field, path in artifact.TREE_PATHS.items():
                self.assertEqual(source[field], artifact.git(root, path))
            with self.assertRaisesRegex(ValueError, "exact expected source"):
                artifact.expected_source(root, "0"*40)
            extra = root/"new"
            extra.touch()
            with self.assertRaisesRegex(ValueError, "must be clean"):
                artifact.expected_source(root, revision)
            extra.unlink()
            (root/"experiments/xray-dataplane-fence/patch").write_text("changed")
            with self.assertRaisesRegex(ValueError, "must be clean"):
                artifact.expected_source(root, revision)

    def test_bounded_regular_no_symlink_hardlink_or_fifo(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            file = root/"file"
            file.write_bytes(b"abc")
            self.assertEqual(artifact.read_bounded(file, 3), b"abc")
            with self.assertRaises(ValueError):
                artifact.read_bounded(file, 2)
            (root/"symlink").symlink_to(file)
            with self.assertRaises(OSError):
                artifact.read_bounded(root/"symlink", 10)
            os.link(file, root/"hardlink")
            with self.assertRaises(ValueError):
                artifact.read_bounded(file, 10)
            os.mkfifo(root/"fifo")
            with self.assertRaises(ValueError):
                artifact.read_bounded(root/"fifo", 10)
            (root/"empty").touch()
            with self.assertRaises(ValueError):
                artifact.read_bounded(root/"empty", 10)


@unittest.skipUnless(os.geteuid() == 0 and os.getegid() == 0, "root-owned publication fixture")
class PublicationTests(unittest.TestCase):
    @staticmethod
    def stage(root, name, payload=b"same"):
        directory = root/name
        directory.mkdir(mode=0o700)
        for filename, (_, mode) in installation.FILES.items():
            installation.write_exact(directory/filename, payload, mode)
        installation.fsync_dir(directory)
        return directory

    def test_actual_atomic_publication_and_no_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root/"installed"
            first = self.stage(root, "first")
            installation.publish(first, target)
            self.assertFalse(first.exists())
            original = (target/"xray").stat()
            second = self.stage(root, "second")
            installation.publish(second, target)
            self.assertTrue(second.exists())
            self.assertEqual((target/"xray").stat().st_ino, original.st_ino)
            modified = self.stage(root, "modified", b"different")
            with self.assertRaisesRegex(ValueError, "refusing replacement"):
                installation.publish(modified, target)
            self.assertEqual((target/"xray").read_bytes(), b"same")
            self.assertEqual((target/"xray").stat().st_ino, original.st_ino)

    def test_existing_symlink_partial_and_wrong_mode_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stage = self.stage(root, "stage")
            link = root/"link"
            link.symlink_to(stage, target_is_directory=True)
            with self.assertRaises(ValueError):
                installation.publish(stage, link)
            partial = root/"partial"
            partial.mkdir(mode=0o700)
            with self.assertRaisesRegex(ValueError, "incomplete"):
                installation.publish(stage, partial)
            wrong = self.stage(root, "wrong")
            (wrong/"xray").chmod(0o777)
            with self.assertRaisesRegex(ValueError, "refusing replacement"):
                installation.publish(stage, wrong)


if __name__ == "__main__":
    unittest.main()
