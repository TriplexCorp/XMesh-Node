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
            for name in ('config.json', 'activation-request.json', 'activation-receipt.json',
                         'active.json', 'client-key.pem', 'client.pem', 'server-ca.pem',
                         'panel-pin.json'):
                with self.subTest(name=name):
                    path = state / name
                    path.symlink_to('missing-target')
                    self.assertEqual(self.invoke('xmesh_product_binding_exists "$1"', state), 0)
                    path.unlink()
                    path.touch()
                    self.assertEqual(self.invoke('xmesh_product_binding_exists "$1"', state), 0)
                    path.unlink()

    def test_sigkill_after_keyring_fsync_cannot_consume_new_enrollment(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            state = root / 'product'
            state.mkdir(mode=0o700)
            ring = root / 'xsp-v2' / 'keys'
            ring.mkdir(parents=True, mode=0o700)
            for name in ('node-request.master', 'node-request.vault'):
                with self.subTest(name=name):
                    path = ring / name
                    path.write_bytes(b'original encrypted signing material')
                    self.assertEqual(self.invoke('xmesh_product_binding_exists "$1"', state), 0)
                    path.unlink()
                    path.symlink_to('missing-original')
                    self.assertEqual(self.invoke('xmesh_product_binding_exists "$1"', state), 0)
                    path.unlink()
            (root / 'xsp-v2').rename(root / 'staged-keyring')
            (root / 'xsp-v2').symlink_to(root / 'staged-keyring', target_is_directory=True)
            self.assertEqual(self.invoke('xmesh_product_binding_exists "$1"', state), 0)

    @unittest.skipUnless(os.geteuid() == 0, 'PQ directory must be owned by root')
    def test_unsafe_product_root_and_symlink_state_never_execute_agent(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            state = root / 'product'
            state.mkdir(mode=0o700)
            (state / 'config.json').touch()
            (state / 'activation-request.json').touch()
            invoked = root / 'invoked'
            product = root / 'product-binary'
            product.write_text('#!/bin/sh\ntouch "$XMESH_INVOKED"\nexit 0\n')
            product.chmod(0o700)
            command = 'set -euo pipefail; source "$1"; shift; xmesh_verify_or_resume_enrolled_product "$@"'
            def run(path):
                return subprocess.run(['bash', '-c', command, 'test', str(GUARD),
                                       str(path), str(product), 'https://panel.invalid', '7'],
                                      capture_output=True, text=True, timeout=5,
                                      env={**os.environ, 'XMESH_INVOKED': str(invoked)})
            state.chmod(0o777)
            self.assertEqual(run(state).returncode, 2)
            self.assertFalse(invoked.exists())
            state.chmod(0o700)
            (state / 'activation-receipt.json').symlink_to('foreign')
            self.assertEqual(run(state).returncode, 2)
            self.assertFalse(invoked.exists())
            (state / 'activation-receipt.json').unlink()
            alias = root / 'product-alias'
            alias.symlink_to(state, target_is_directory=True)
            self.assertEqual(run(alias).returncode, 2)
            self.assertFalse(invoked.exists())

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

    def test_lost_activation_is_recovered_without_reenrollment(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            state = root / 'product'
            state.mkdir(mode=0o700)
            (state / 'config.json').write_text('private config')
            original = state / 'activation-request.json'
            original.write_text('original signed request')
            marker, calls = state / 'recovered', state / 'calls'
            product = root / 'product-binary'
            product.write_text('''#!/usr/bin/env bash
echo "$1" >>"$XMESH_MOCK_CALLS"
if [[ "$1" == "verify-active" ]]; then
  [[ -e "$XMESH_MOCK_MARKER" && "$3" == "https://panel.invalid" && "$5" == 7 ]] && exit 0
  exit 1
fi
if [[ "$1" == "resume-activation" ]]; then
  touch "$XMESH_MOCK_MARKER"
  exit 0
fi
exit 77
''')
            product.chmod(0o700)
            command = 'set -euo pipefail; source "$1"; shift; xmesh_verify_or_resume_enrolled_product "$@"'
            def run():
                return subprocess.run(
                    ['bash', '-c', command, 'fixture', str(GUARD),
                     str(state), str(product), 'https://panel.invalid', '7'],
                    env={**os.environ, 'XMESH_MOCK_CALLS': str(calls),
                         'XMESH_MOCK_MARKER': str(marker)},
                    capture_output=True, text=True, timeout=5)
            result = run()
            self.assertEqual((result.returncode, result.stdout.strip()), (0, 'resumed'), result.stderr)
            self.assertEqual(calls.read_text().splitlines(),
                             ['verify-active', 'resume-activation', 'verify-active'])
            self.assertEqual(original.read_text(), 'original signed request')
            calls.unlink()
            result = run()
            self.assertEqual((result.returncode, result.stdout.strip()), (0, 'active'), result.stderr)
            self.assertEqual(calls.read_text().splitlines(), ['verify-active'])
            calls.unlink()
            (state / 'active.json').symlink_to('missing-target')
            marker.unlink()
            self.assertEqual(run().returncode, 2)
            self.assertEqual(calls.read_text().splitlines(), ['verify-active'])
            calls.unlink()
            (state / 'active.json').unlink()
            original.unlink()
            self.assertEqual(run().returncode, 2)
            self.assertEqual(calls.read_text().splitlines(), ['verify-active'])
            calls.unlink()
            (state / 'config.json').unlink()
            result = run()
            self.assertEqual((result.returncode, result.stdout.strip()), (0, 'fresh'), result.stderr)
            self.assertFalse(calls.exists())

    def test_both_installer_entrypoints_recover_before_service_shutdown(self):
        for source, mutation in (
                ((ROOT / 'bootstrap.sh').read_text(), 'systemctl disable --now "$unit"'),
                ((ROOT / 'install.sh').read_text(), 'docker update --restart=no xmesh-node')):
            self.assertLess(source.index('PRODUCT_ACTIVATION_STATE="$(xmesh_verify_or_resume_enrolled_product'),
                            source.index(mutation))
            self.assertIn('[[ "$PRODUCT_ACTIVATION_STATE" == fresh ]]', source)
            self.assertIn('xmesh_product_binding_exists /var/lib/xmesh-agent/product', source)

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
