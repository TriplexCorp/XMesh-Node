#!/usr/bin/env python3
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


hot = load('hot', ROOT / 'deploy' / 'xmesh-hot-user-reconcile.py')
attest = load('attest', ROOT / 'deploy' / 'xmesh-profile-attest.py')


def account(user_id=1, uid='550e8400-e29b-41d4-a716-446655440000'):
    return {'id': uid, 'email': f'xmesh-u{user_id}--main'}


def config(accounts=None):
    if accounts is None:
        accounts = [account()]
    return {
        'log': {'loglevel': 'warning'},
        'api': {'tag': 'xmesh_stats_api', 'services': ['StatsService']},
        'stats': {},
        'inbounds': [
            {
                'tag': 'main', 'listen': '127.0.0.1', 'port': 5000,
                'protocol': 'vless',
                'settings': {'decryption': 'none', 'clients': copy.deepcopy(accounts)},
                'streamSettings': {'network': 'raw'},
            },
            {
                'tag': 'xmesh_stats_in', 'listen': '127.0.0.1', 'port': 10085,
                'protocol': 'dokodemo-door', 'settings': {'address': '127.0.0.1'},
            },
        ],
        'outbounds': [{'tag': 'xmesh_stats_api', 'protocol': 'freedom'}],
    }


class HotUserTests(unittest.TestCase):
    def test_augmentation_is_loopback_only_and_idempotent(self):
        value = config()
        hot.augment_config(value)
        hot.augment_config(value)
        self.assertEqual(value['api']['services'], ['StatsService', 'HandlerService'])
        unsafe = config()
        unsafe['inbounds'][-1]['listen'] = '0.0.0.0'
        with self.assertRaises(ValueError):
            hot.augment_config(unsafe)

    def test_plan_accepts_only_account_changes(self):
        old = config()
        new = config([account(), account(2, '550e8400-e29b-41d4-a716-446655440001')])
        hot.augment_config(old); hot.augment_config(new)
        plan = hot.build_plan(old, new)
        self.assertEqual(plan['remove'], [])
        self.assertEqual([item['email'] for item in plan['add']], ['xmesh-u2--main'])
        structural = copy.deepcopy(new)
        structural['inbounds'][0]['port'] = 5001
        with self.assertRaises(hot.HotUserUnavailable):
            hot.build_plan(old, structural)

    def test_rotation_is_remove_then_add_and_preserves_active_inode(self):
        old = config(); new = config([account(uid='550e8400-e29b-41d4-a716-446655440099')])
        hot.augment_config(old); hot.augment_config(new)
        calls = []
        original = hot._run
        def fake(args, *, payload=None, expected=None):
            calls.append((args, payload, expected))
            if args[:2] == ['docker', 'inspect']:
                return b'true\n'
            return expected or b''
        hot._run = fake
        try:
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'config.json'
                path.write_bytes(hot.canonical(old))
                inode = path.stat().st_ino
                self.assertTrue(hot.hot_reconcile_active(new, path))
                self.assertEqual(path.stat().st_ino, inode)
                self.assertEqual(json.loads(path.read_text()), new)
        finally:
            hot._run = original
        actions = ['rmu' if 'rmu' in c[0] else 'adu' if 'adu' in c[0] else 'test' if '-test' in c[0] else 'inspect' for c in calls]
        self.assertEqual(actions, ['inspect', 'test', 'rmu', 'adu'])
        self.assertEqual(calls[2][2], b'Removed 1 user(s) in total.')
        self.assertEqual(calls[3][2], b'Added 1 user(s) in total.')

    def test_preflight_failure_restores_old_config_before_rpc_fallback(self):
        old = config(); new = config([])
        hot.augment_config(old); hot.augment_config(new)
        calls = []
        original = hot._run
        def fail_test(args, *, payload=None, expected=None):
            calls.append(args)
            if args[:2] == ['docker', 'inspect']:
                return b'true\n'
            if '-test' in args:
                raise hot.HotUserUnavailable('simulated preflight failure')
            raise AssertionError('user RPC must not run after failed preflight')
        hot._run = fail_test
        try:
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'config.json'
                path.write_bytes(hot.canonical(old))
                inode = path.stat().st_ino
                self.assertFalse(hot.hot_reconcile_active(new, path))
                self.assertEqual(path.stat().st_ino, inode)
                self.assertEqual(json.loads(path.read_text()), old)
        finally:
            hot._run = original
        self.assertEqual(len(calls), 2)

    def test_rpc_failure_keeps_disk_state_for_full_redeploy_fallback(self):
        old = config(); new = config([])
        hot.augment_config(old); hot.augment_config(new)
        original = hot._run
        def fail(args, *, payload=None, expected=None):
            if args[:2] == ['docker', 'inspect']:
                return b'true\n'
            if '-test' in args:
                return b''
            raise hot.HotUserUnavailable('simulated rpc failure')
        hot._run = fail
        try:
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / 'config.json'
                path.write_bytes(hot.canonical(old))
                self.assertFalse(hot.hot_reconcile_active(new, path))
                self.assertEqual(json.loads(path.read_text()), old)
        finally:
            hot._run = original

    def test_attestation_allows_only_handler_service_local_augmentation(self):
        signed = config([account(), account(2, '550e8400-e29b-41d4-a716-446655440001')])
        running = copy.deepcopy(signed)
        hot.augment_config(running)
        self.assertTrue(attest.is_restricted_copy(signed, running))

        offline_restricted = copy.deepcopy(running)
        offline_restricted['inbounds'][0]['settings']['clients'].pop()
        self.assertTrue(attest.is_restricted_copy(signed, offline_restricted))

        extra = copy.deepcopy(running)
        extra['api']['services'].append('RoutingService')
        self.assertFalse(attest.is_restricted_copy(signed, extra))

        added = copy.deepcopy(running)
        added['inbounds'][0]['settings']['clients'].append(account(3, '550e8400-e29b-41d4-a716-446655440003'))
        self.assertFalse(attest.is_restricted_copy(signed, added))


if __name__ == '__main__':
    unittest.main()
