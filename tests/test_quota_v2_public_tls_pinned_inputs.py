#!/usr/bin/env python3
"""Actual signed compiler, sealed TLS material and detached route FD bundle."""
import copy
import hashlib
import json
import os
import select
from pathlib import Path
import subprocess
import sys
import time
import unittest
from unittest import mock

from test_quota_v2_public_tls_routes import RouteFixture, routes
from test_quota_v2_public_tls_certificates import CertificateTests, DOMAIN_A, DOMAIN_B
import public_tls_pinned_inputs as pinned
import public_tls_frontend as tls
import wal_transport


class BundleFixture(RouteFixture):
    def setUp(self):
        super().setUp()
        self.certs = CertificateTests("test_two_independent_root_owned_lineages_and_signed_paths")
        self.certs.setUp()
        self.addCleanup(self.certs.doCleanups)
        self.profile = self.signer.reply["config"]
        now = time.time_ns() // 1_000_000
        self.payload = {
            "schemaVersion": 1, "kind": "xmesh.quota-v2.public-tls-ingress",
            "nodeId": self.roster.node, "activationReceiptSha256": self.roster.activation,
            "genesisPolicySha256": self.roster.genesis_sha,
            "runtimeId": self.runtime, "profileRevision": self.roster.profile_sha256,
            "canServePublic": True,
            "bindings": [
                {"tag": "vless-main", "domain": DOMAIN_B, "port": 8443},
                {"tag": "vless-cdn", "domain": DOMAIN_A, "port": 443},
            ], "issuedAtMs": now, "validUntilMs": now + 60_000,
        }
        self.authority = self.sign_authority(self.payload)
        self.binding = dict(node=self.roster.node, activation=self.roster.activation,
                            genesis_sha=self.roster.genesis_sha, runtime_id=self.runtime,
                            pinned=self.roster.pinned)
        self.config = tls.compile_signed_public_tls(self.profile, self.authority, **self.binding)

    def sign_authority(self, payload):
        return wal_transport.observed.canonical({
            "algorithm": "Ed25519", "payload": payload,
            "signature": self.signer.sign(b"", payload),
        })

    def bundle(self, **overrides):
        args = dict(profile=self.profile, authority=self.authority, cap_watch=self.roster,
                    enrolled_fd=self.fd, runtime_pid=self.child.pid, **self.binding)
        args.update(overrides)
        return pinned.PinnedTlsInputs(**args)

    def check(self, inputs, **overrides):
        args = dict(config=self.config, authority=self.authority, cap_watch=self.roster,
                    runtime_pid=self.child.pid)
        args.update(overrides)
        return inputs.ensure_current(**args)

    def assert_independent_child(self, inputs):
        # The independent child receives only the actual sealed materials,
        # config and ro route FD; it never binds any socket.
        child_code = """
import hashlib, json, os, sys
config = json.load(open(sys.argv[1]))
result = {}
for inbound in config['inbounds']:
    pair = inbound['streamSettings']['tlsSettings']['certificates'][0]
    result[inbound['tag']] = [hashlib.sha256(open(pair[x], 'rb').read()).hexdigest()
                              for x in ('certificateFile','keyFile')]
assert os.readlink(sys.argv[2]+'/ingress-u100') == sys.argv[3]
assert os.statvfs(sys.argv[2]).f_flag & os.ST_RDONLY
print(json.dumps(result), flush=True)
sys.stdin.read()
"""
        child = subprocess.Popen([
            "setpriv", "--no-new-privs", "--bounding-set=-all",
            "--inh-caps=-all", "--ambient-caps=-all", sys.executable, "-c",
            child_code, inputs.config_path, inputs.ingress_state, self.target,
        ], pass_fds=inputs.child_fds, stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            self.assertTrue(select.select([child.stdout], [], [], 8)[0],
                            "sealed input child did not become ready")
            actual = json.loads(child.stdout.readline())
            self.assertIsNone(inputs.verify_child(child))
        finally:
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)
        expected = {tag: [hashlib.sha256((self.certs.archive/domain/name).read_bytes()).hexdigest()
                          for name in ("fullchain1.pem", "privkey1.pem")]
                    for tag, domain in (("vless-main", DOMAIN_B), ("vless-cdn", DOMAIN_A))}
        self.assertEqual(actual, expected)
        self.assertEqual(len(inputs.child_fds), 6)
        self.assertNotIn(inputs._routes._write_fd, inputs.child_fds)
        self.assertNotIn(inputs._routes._state_fd, inputs.child_fds)
        self.assertNotIn(inputs._routes._pidfd, inputs.child_fds)
        self.assertNotIn(inputs._certificates._fds[0], inputs.child_fds)


class PinnedInputsStructuralTests(BundleFixture):
    real_sockets = False

    def setUp(self):
        super().setUp()

        def measure(capsule, deadline):
            deadline()
            capsule._check_liveness()
            self.assertEqual(routes._dir_identity(os.fstat(capsule._meter_fd)), capsule._meter_id)
            deadline()

        # Only the locally prohibited AF_UNIX network boundary is mocked.
        patch = mock.patch.object(routes.FirstGenesisRoutes, "_check_meter", measure)
        patch.start()
        self.addCleanup(patch.stop)

    def test_real_signed_sealed_bundle_and_no_writable_route_or_ca_fd_in_child(self):
        with self.bundle() as inputs:
            self.assertIsNone(self.check(inputs))
            self.assert_independent_child(inputs)
            fds = inputs.child_fds
        for fd in fds:
            with self.assertRaises(OSError):
                os.fstat(fd)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_exact_compiled_config_and_authority_cannot_be_substituted(self):
        with self.bundle() as inputs:
            alternate = copy.deepcopy(self.config)
            alternate["inbounds"][0]["port"] += 1
            with self.assertRaisesRegex(ValueError, "exact signed authority"):
                self.check(inputs, config=alternate)
            other = self.sign_authority(dict(self.payload, validUntilMs=self.payload["validUntilMs"]-1))
            with self.assertRaisesRegex(ValueError, "exact signed authority"):
                self.check(inputs, authority=other)
            with self.assertRaisesRegex(ValueError, "exact signed authority"):
                self.check(inputs, runtime_pid=self.child.pid+1)
        with self.assertRaises(ValueError):
            self.bundle(authority=self.authority.replace(b"Ed25519", b"Ed25518"))
        self.assertEqual(list(self.root.iterdir()), [])

    def test_lineage_rotation_or_original_route_loss_invalidates_bundle(self):
        with self.bundle() as inputs:
            link = self.source / "ingress-u100"
            link.unlink()
            link.symlink_to("/proc/1/root/dev/shm/foreign")
            with self.assertRaisesRegex(ValueError, "changed from signed original"):
                self.check(inputs)
            link.unlink()
            link.symlink_to(self.target)
            self.certs.ca_cert.chmod(0o600)
            with self.assertRaisesRegex(ValueError, "system TLS trust changed"):
                self.check(inputs)

    def test_assembly_failure_closes_sealed_files_and_route_view(self):
        original = pinned.public_tls_certificates.freeze_certificate_lineage
        captured = []

        def freeze(config):
            result = original(config)
            captured.extend(result._fds)
            return result

        with mock.patch.object(pinned.public_tls_certificates, "freeze_certificate_lineage",
                               side_effect=freeze), mock.patch.object(
                pinned.public_tls_routes, "FirstGenesisRoutes",
                side_effect=ValueError("route proof unavailable")):
            with self.assertRaisesRegex(ValueError, "route proof unavailable"):
                self.bundle()
        self.assertTrue(captured)
        for fd in captured:
            with self.assertRaises(OSError):
                os.fstat(fd)


class PinnedInputsKernelTests(BundleFixture):
    def test_actual_kernel_peer_and_sealed_tls_inputs_share_one_original_binding(self):
        with self.bundle() as inputs:
            self.assertIsNone(self.check(inputs))
            self.assertEqual(set(inputs._routes._socket_ids), {"vless-main", "vless-cdn"})
            self.assert_independent_child(inputs)
            self.child.kill()
            self.child.wait(timeout=5)
            with self.assertRaisesRegex(ValueError, "changed or exited"):
                self.check(inputs)


if __name__ == "__main__":
    unittest.main()
