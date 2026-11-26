#!/usr/bin/env python3
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]
                       / "experiments" / "quota-v2-physical-stop"))
import qualified_runtime_image as image


class QualifiedImageTests(unittest.TestCase):
    def test_exact_identity_shape_and_digest(self):
        raw = "".join(f"{key}={'a' * (64 if key == 'artifactSha256' else 40)}\n"
                      for key in image.FIELDS).encode()
        self.assertEqual(image.parse_identity(raw)["artifactSha256"], "a" * 64)
        for bad in (raw[:-1], raw + b"other=1\n", raw.replace(b"nexusRevision", b"nodeSourceRevision"),
                    raw.replace(b"artifactSha256=a", b"artifactSha256=g")):
            with self.assertRaises(ValueError):
                image.parse_identity(bad)

    def test_image_metadata_cannot_add_startup_or_volume(self):
        config = {"Entrypoint": ["/xray"], "User": "0:0"}
        image.verify_image_config(config)
        for change in ({"Entrypoint": ["/bin/sh"]}, {"Volumes": {"/xray": {}}},
                       {"Cmd": ["run"]}, {"ExposedPorts": {"443/tcp": {}}},
                       {"Healthcheck": {"Test": ["CMD", "/xray"]}},
                       {"OnBuild": ["RUN unexpected"]}, {"User": "1000"}, {"User": ""},
                       {"User": None}, {"User": "0"}, {"User": "root"}, {"User": False}):
            with self.assertRaisesRegex(ValueError, "field: " + next(iter(change))):
                image.verify_image_config(dict(config, **change))

    def test_absent_user_is_not_an_explicit_numeric_identity(self):
        with self.assertRaisesRegex(ValueError, "field: User"):
            image.verify_image_config({"Entrypoint": ["/xray"]})

    @unittest.skipUnless(os.geteuid() == 0, "installed release files belong to root")
    def test_stage_rejects_changed_bytes_and_links(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "source"
            source.write_bytes(b"qualified executable")
            source.chmod(0o755)
            digest = hashlib.sha256(source.read_bytes()).hexdigest()
            copy = Path(directory) / "copy"
            image.stage_binary(source, copy, digest)
            self.assertEqual(copy.read_bytes(), source.read_bytes())
            self.assertEqual(copy.stat().st_mode & 0o777, 0o755)
            source.write_bytes(b"wrong executable")
            with self.assertRaises(ValueError):
                image.stage_binary(source, Path(directory) / "wrong", digest)
            link = Path(directory) / "link"
            link.symlink_to(source)
            with self.assertRaises(OSError):
                image.stage_binary(link, Path(directory) / "symlink", digest)


if __name__ == "__main__":
    unittest.main()
