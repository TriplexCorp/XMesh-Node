#!/usr/bin/env python3
"""Exercise cold-install guards with disposable state, never real /var/lib."""
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
GUARD = ROOT / 'deploy/xmesh-pq-install-guard.sh'


class InstallGuardTests(unittest.TestCase):
    def invoke(self, command, *args):
        return subprocess.run(['bash', '-c', 'set -euo pipefail; source "$1"; shift; ' + command,
                               'guard-test', str(GUARD), *map(str, args)],
                              capture_output=True, text=True).returncode

    def test_all_spending_evidence_and_dangling_links_block_cold_install(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td)
            (state / 'ordinary-meter.json').touch()
            self.assertEqual(self.invoke('xmesh_refuse_quota_cold_install "$1"', state), 0)
            for name in ('genesis-quarantine-envelope.json', 'genesis-reservation-prepared-u7.json',
                         'genesis-reservation-confirmed-u7.json', 'genesis-positive-cap-u7.json',
                         'genesis-renewal-u7-r1.json', 'genesis-renewal-request-u7-r1.json',
                         'calendar-positive-u7-abcd.json', 'wal-cap-u7-abcd.json',
                         'wal-charge-abcd-s1.json', 'wal-charge-request-abcd-s1.json',
                         'ingress-u7', 'xmesh-quota-u7-abcd'):
                with self.subTest(name=name):
                    path = state / name
                    path.symlink_to('missing-target')
                    self.assertEqual(self.invoke('xmesh_refuse_quota_cold_install "$1"', state), 2)
                    path.unlink()
                    path.touch()
                    self.assertEqual(self.invoke('xmesh_refuse_quota_cold_install "$1"', state), 2)
                    path.unlink()
            link = state / 'foreign-state'
            link.symlink_to('missing-state')
            self.assertEqual(self.invoke('xmesh_refuse_quota_cold_install "$1"', link), 2)

    def test_partial_and_complete_enrollment_bindings_are_not_fresh(self):
        with tempfile.TemporaryDirectory() as td:
            state = Path(td)
            self.assertEqual(self.invoke('xmesh_product_binding_exists "$1"', state), 1)
            for name in ('config.json', 'activation-request.json', 'activation-receipt.json', 'active.json'):
                with self.subTest(name=name):
                    path = state / name
                    path.symlink_to('missing-target')
                    self.assertEqual(self.invoke('xmesh_product_binding_exists "$1"', state), 0)
                    path.unlink()
                    path.touch()
                    self.assertEqual(self.invoke('xmesh_product_binding_exists "$1"', state), 0)
                    path.unlink()

    @unittest.skipUnless(os.geteuid() == 0, 'installed artifact must be root-owned')
    def test_only_same_safe_binary_is_allowed_for_bound_product(self):
        with tempfile.TemporaryDirectory() as td:
            binary = Path(td) / 'product'
            binary.write_bytes(b'reviewed installed product')
            binary.chmod(0o755)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            command = 'xmesh_require_unchanged_binary "$1" "$2"'
            self.assertEqual(self.invoke(command, binary, digest), 0)
            self.assertEqual(self.invoke(command, binary, '0' * 64), 2)
            self.assertEqual(self.invoke(command, binary, 'invalid'), 2)
            binary.chmod(0o775)
            self.assertEqual(self.invoke(command, binary, digest), 2)
            binary.chmod(0o755)
            alias = Path(td) / 'alias'
            alias.symlink_to(binary)
            self.assertEqual(self.invoke(command, alias, digest), 2)
            self.assertEqual(self.invoke(command, Path(td) / 'absent', digest), 2)

    def test_bound_artifact_preflight_precedes_destructive_entry_points(self):
        bootstrap = (ROOT / 'bootstrap.sh').read_text()
        standalone = (ROOT / 'install.sh').read_text()
        for source, mutation in ((bootstrap, 'systemctl disable --now "$unit"'),
                                 (standalone, 'docker update --restart=no xmesh-node')):
            binding = source.index('if xmesh_product_binding_exists /var/lib/xmesh-agent/product; then')
            preflight = source.index('bash ', binding)
            self.assertLess(preflight, source.index(mutation))
        for name, digest in (
                ('install-xsp-v2-product-client.sh', '$DIGEST'),
                ('install-xsp-v2-production-agent.sh', '$PRODUCT_DIGEST')):
            source = (ROOT / 'deploy' / name).read_text()
            self.assertLess(source.index('xmesh_refuse_quota_cold_install'),
                            source.index('docker run --rm'))
            self.assertLess(source.index('xmesh_require_unchanged_binary'),
                            source.index('mv -f "$PRODUCT_STAGE"'))


if __name__ == '__main__':
    unittest.main()
