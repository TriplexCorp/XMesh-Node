#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("patch_source", Path(__file__).resolve().parents[1] / "deploy/verify-metered-xray-patch-source.py")
source = importlib.util.module_from_spec(spec)
spec.loader.exec_module(source)


class PatchSourceTests(unittest.TestCase):
    def setUp(self):
        self.signed = {"apply-experiment.py": b"100644 blob " + b"a"*40,
                       "base.go.txt": b"100644 blob " + b"b"*40}
        self.extension = dict(self.signed, **{name: b"100644 blob " + b"c"*40 for name in source.EXTRA})

    def check(self, installed=None, signed=None, actual=None, attested=None):
        source.verify_projection(actual or source.REVIEWED_EXTENSION, attested or source.SIGNED_BASE,
                                 self.extension if installed is None else installed,
                                 self.signed if signed is None else signed)

    def test_exact_and_reviewed_extension(self):
        self.check()
        self.check(installed=self.signed, actual=source.SIGNED_BASE)

    def test_no_unreviewed_tree(self):
        for actual, attested in (("1"*40, source.SIGNED_BASE), (source.REVIEWED_EXTENSION, "2"*40)):
            with self.subTest(actual=actual, attested=attested), self.assertRaises(ValueError):
                self.check(actual=actual, attested=attested)

    def test_missing_modified_mode_or_extra_input(self):
        changes = [
            dict(self.extension, **{"base.go.txt": b"100644 blob " + b"d"*40}),
            dict(self.extension, **{"base.go.txt": b"100755 blob " + b"b"*40}),
            {k: v for k, v in self.extension.items() if k != "base.go.txt"},
            {k: v for k, v in self.extension.items() if k != next(iter(source.EXTRA))},
            dict(self.extension, **{"unexpected.py": b"100644 blob " + b"e"*40}),
        ]
        for value in changes:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.check(installed=value)
        with self.assertRaises(ValueError):
            self.check(installed=self.extension, actual=source.SIGNED_BASE)

    def test_reject_unsafe_tree_entry(self):
        good = b"100644 blob " + b"a"*40 + b"\tbase.go.txt\0"
        self.assertEqual(set(source.entries(good)), {"base.go.txt"})
        for value in (good[:-1], good+good, good.replace(b"100644", b"120000"),
                      good.replace(b"base.go.txt", b"sub/evil"), b""):
            with self.subTest(value=value), self.assertRaises(ValueError):
                source.entries(value)


    def test_authenticated_private_toolchain_precedes_patcher(self):
        installer = (Path(__file__).resolve().parents[1] / "deploy/install-metered-xray.sh").read_text()
        downloaded = installer.index('fetch https://go.dev/dl/go1.27.4.linux-amd64.tar.gz')
        verified = installer.index('check_sha "$WORK/go.tar.gz"')
        extracted = installer.index('tar -xzf "$WORK/go.tar.gz"')
        patch = installer.index('python3 -I -B "$WORK/patch-source/experiments/xray-dataplane-fence/apply-experiment.py"')
        build = installer.index('"$WORK/go/bin/go" build')
        self.assertLess(downloaded, verified)
        self.assertLess(verified, extracted)
        self.assertLess(extracted, patch)
        self.assertLess(patch, build)
        self.assertIn('env -i PATH="$WORK/go/bin:/usr/bin:/bin"', installer[extracted:patch])


if __name__ == "__main__":
    unittest.main()
