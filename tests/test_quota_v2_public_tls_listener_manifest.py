#!/usr/bin/env python3
"""Exact signed compiler + sealed config + actual unlistening TCP inputs."""
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest import mock

from test_quota_v2_public_tls_pinned_inputs import BundleFixture, routes
from test_quota_v2_public_tls_bound_listener import CAPLESS, ROOT
import public_tls_bound_listener as bound
import public_tls_listener_manifest as manifests
import public_tls_certificates as certificates


class ManifestTests(BundleFixture):
    # Structural path keeps actual signed crypto, config and original
    # process/mount/Fd proofs. Only local AF_UNIX socket peer step is mocked.
    real_sockets = False

    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("root and disposable private network namespace required")
        original = os.environ["XMESH_TLS_LISTENER_MANIFEST_HOST_NS"]
        self.assertRegex(original, r"^net:\[\d+\]$")
        self.assertNotEqual(os.readlink("/proc/self/ns/net"), original)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            self.assertEqual(os.environ.get("RUNNER_ENVIRONMENT"), "github-hosted")
            self.assertEqual(os.readlink("/proc/1/ns/net"), original)
        super().setUp()
        if not self.real_sockets:
            def measure(capsule, deadline):
                deadline()
                capsule._check_liveness()
                self.assertEqual(routes._dir_identity(os.fstat(capsule._meter_fd)),
                                 capsule._meter_id)
                deadline()
            patch = mock.patch.object(routes.FirstGenesisRoutes, "_check_meter", measure)
            patch.start()
            self.addCleanup(patch.stop)
        self.sockets = {}
        for row in self.config["inbounds"]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.addCleanup(sock.close)
            sock.bind((row["listen"], row["port"]))
            self.sockets[row["tag"]] = sock
        self.ns = bound.network_namespace_cookie(next(iter(self.sockets.values())))

    def manifest(self, inputs, **overrides):
        args = dict(inputs=inputs, config=self.config, authority=self.authority,
                    cap_watch=self.roster, runtime_pid=self.child.pid,
                    sockets=self.sockets, netns_cookie=self.ns)
        args.update(overrides)
        return manifests.ListenerManifest(**args)

    def test_actual_original_bound_tokens_and_frozen_config(self):
        with self.bundle() as inputs, self.manifest(inputs) as manifest:
            fd, *listeners = manifest.child_fds
            self.assertEqual(set(listeners), {sock.fileno() for sock in self.sockets.values()})
            self.assertEqual(fcntl.fcntl(fd, fcntl.F_GET_SEALS), certificates.SEALS)
            raw = json.loads(os.pread(fd, manifests.MAX_MANIFEST, 0))
            self.assertEqual(raw["configFd"], inputs._certificates.config_fd)
            self.assertEqual(raw["configSha256"], hashlib.sha256(os.pread(
                raw["configFd"], certificates.MAX_CONFIG_BYTES, 0)).hexdigest())
            self.assertEqual(raw["authoritySha256"], hashlib.sha256(self.authority).hexdigest())
            self.assertEqual(raw["runtimeId"], self.runtime)
            self.assertEqual([x["tag"] for x in raw["listeners"]], ["vless-cdn", "vless-main"])
            self.assertNotIn(inputs._routes._pidfd, manifest.child_fds)
            self.assertIsNone(manifest.ensure_current())
            for sock in self.sockets.values():
                sock.close()
            self.assertIsNone(manifest.ensure_manifest())
            with self.assertRaises(ValueError):
                manifest.ensure_current()
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_wrong_scope_endpoint_or_signature_refused(self):
        with self.bundle() as inputs:
            changed = copy.deepcopy(self.config)
            changed["inbounds"][0]["port"] += 1
            for override in (
                {"config": changed},
                {"sockets": {"vless-main": self.sockets["vless-main"]}},
                {"sockets": {"vless-cdn": self.sockets["vless-main"],
                             "vless-main": self.sockets["vless-cdn"]}},
                {"netns_cookie": self.ns ^ 1},
                {"authority": self.authority + b" "},
            ):
                with self.subTest(override=list(override)), self.assertRaises(ValueError):
                    self.manifest(inputs, **override)

    def test_same_content_replacement_is_not_original_manifest(self):
        with self.bundle() as inputs, self.manifest(inputs) as manifest:
            fd = manifest.manifest_fd
            raw = os.pread(fd, manifests.MAX_MANIFEST, 0)
            duplicate = certificates._sealed_bytes("substitute", raw)
            saved = os.dup(fd)
            try:
                os.dup2(duplicate, fd, inheritable=False)
                with self.assertRaisesRegex(ValueError, "original sealed listener manifest"):
                    manifest.ensure_manifest()
                os.dup2(saved, fd, inheritable=False)
                self.assertIsNone(manifest.ensure_current())
            finally:
                os.close(saved)
                os.close(duplicate)


class HostedManifestTests(ManifestTests):
    real_sockets = True

    def test_actual_go_validates_exact_sealed_config_and_manifest(self):
        if os.environ.get("GITHUB_ACTIONS") != "true":
            self.skipTest("requires hosted Go toolchain and actual pathname Unix peers")
        with tempfile.TemporaryDirectory(prefix="xmesh-go-listener-manifest-") as directory:
            binary = str(Path(directory) / "listener.test")
            subprocess.run(["go", "test", "-c", "-o", binary,
                            "./experiments/quota-v2-physical-stop/namespacepeer"],
                           cwd=ROOT, env=dict(os.environ, GOPROXY="off", CGO_ENABLED="0",
                                              GOTOOLCHAIN="local"), check=True, timeout=90)
            with self.bundle() as inputs, self.manifest(inputs) as manifest:
                fd = manifest.manifest_fd
                config = inputs._certificates.config_fd
                raw = os.pread(fd, manifests.MAX_MANIFEST, 0)
                doc = json.loads(raw)
                replacement = certificates._sealed_bytes("same-content-substitute", raw)
                self.addCleanup(os.close, replacement)
                bad = certificates._sealed_bytes("noncanonical-listeners", raw + b" ")
                self.addCleanup(os.close, bad)
                # Exact live FD inheritance; no listening in this suite.
                env = dict(os.environ, XMESH_DISPOSABLE_GO_LISTENER_MANIFEST="1",
                           XMESH_FIXTURE_LISTENER_MANIFEST_FD=str(fd),
                           XMESH_FIXTURE_LISTENER_CONFIG_FD=str(config),
                           XMESH_FIXTURE_LISTENER_REPLACEMENT_FD=str(replacement),
                           XMESH_FIXTURE_BAD_LISTENER_MANIFEST_FD=str(bad),
                           XMESH_FIXTURE_RUNTIME=doc["runtimeId"],
                           XMESH_FIXTURE_ROSTER=doc["rosterSha256"],
                           XMESH_FIXTURE_AUTHORITY=doc["authoritySha256"],
                           XMESH_FIXTURE_CONFIG_SHA=doc["configSha256"])
                output = subprocess.check_output([*CAPLESS, binary,
                    "-test.run=^TestActualSealedListenerManifest$", "-test.v"],
                    env=env, pass_fds=(*manifest.child_fds, config, replacement, bad),
                    timeout=10, stderr=subprocess.STDOUT)
                self.assertIn(b"--- PASS: TestActualSealedListenerManifest", output)
                self.assertIsNone(manifest.ensure_current())


if __name__ == "__main__":
    unittest.main()
