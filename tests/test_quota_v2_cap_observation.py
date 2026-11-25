#!/usr/bin/env python3
"""Strict read-only Agent<->live-Xray cap observation, never a public TLS grant.

The synthetic signed bytes in these transport-only tests do NOT establish
cryptographic issuer identity; the installed caller first runs the existing
Ed25519 first_cap_handoff.verify_grant against its pinned Nexus key.
"""
import copy
import hashlib
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] /
                       "experiments/quota-v2-physical-stop"))
import cap_install as observed
import wal_transport

RUNTIME = "a" * 64
ACTIVATION = "b" * 64
POLICY = "d" * 64
NODE = 47
USER = 101
MAIN = "xmesh-u101--vless-main"
CDN = "xmesh-u101--vless-cdn"


def fixture():
    now = time.time_ns() // 1_000_000
    aliases = [{"email": CDN, "class": "cdn"},
               {"email": MAIN, "class": "main"}]
    p = {
        "schemaVersion": 1, "kind": "xmesh.quota-v2.xray-cap-admission",
        "nodeId": NODE, "userId": USER,
        "activationReceiptSha256": ACTIVATION, "runtimeId": RUNTIME,
        "policySha256": POLICY,
        "accountEpoch": "11111111-1111-4111-8111-111111111111",
        "meterEpoch": "22222222-2222-4222-8222-222222222222",
        "reservationId": "33333333-3333-4333-8333-333333333333",
        "reservationRevision": 3, "nonce": "c" * 64,
        "aliasScopes": aliases,
        "sharedCeilingBytes": 100, "nodeCeilingBytes": 70,
        "cdnCeilingBytes": 20, "validUntilMs": now + 120_000,
        "canSpend": True, "canStart": False, "canResume": False,
        "finalMeterVerified": False, "refundableBytes": 0,
    }
    scope = {
        "userId": USER, "policySha256": POLICY,
        "accountEpoch": p["accountEpoch"], "meterEpoch": p["meterEpoch"],
        "reservationId": p["reservationId"], "revision": 3,
        "nonce": p["nonce"], "aliases": aliases,
    }
    signed = {"algorithm": "Ed25519", "payload": p,
              "signature": "e" * 128}
    raw = wal_transport.observed.canonical(signed) + b"\n"
    return raw, p, scope


def reply(req, p):
    return {
        "schemaVersion": 1, "kind": "xmesh.quota-v2.local-cap-observed",
        "nonce": req["nonce"], "nodeId": NODE, "userId": USER,
        "email": req["email"], "runtimeId": RUNTIME,
        "activationReceiptSha256": ACTIVATION, "policySha256": POLICY,
        "accountEpoch": p["accountEpoch"], "meterEpoch": p["meterEpoch"],
        "reservationId": p["reservationId"],
        "reservationRevision": p["reservationRevision"],
        "grantSha256": req["grantSha256"],
        "validUntilMs": p["validUntilMs"],
        "sharedCeilingBytes": 100, "nodeCeilingBytes": 70,
        "cdnCeilingBytes": 20, "chargedBytes": 15, "chargedCdnBytes": 5,
        "installedLocalCap": True, "canServePublic": False,
        "canStart": False, "canResume": False,
        "finalMeterVerified": False, "refundableBytes": 0,
    }


class LocalCapObservationTests(unittest.TestCase):
    def test_reject_foreign_original_grant_and_alias_before_connect(self):
        raw, p, scope = fixture()
        changes = (
            ("runtime", {"runtime": "f" * 64}),
            ("node", {"node": 48}),
            ("activation", {"activation": "f" * 64}),
            ("email", {"email": "xmesh-u102--vless-main"}),
            ("scope", {"scope": dict(scope, nonce="f" * 64)}),
        )
        for name, change in changes:
            with self.subTest(name=name), self.assertRaises(ValueError):
                values = {
                    "runtime": RUNTIME, "node": NODE,
                    "activation": ACTIVATION, "signed_grant": raw,
                    "scope": scope, "email": MAIN, "nonce": "b" * 64,
                }
                values.update(change)
                observed._observed_cap_request(**values)
        malformed = (
            {"canServePublic": True},
            {"canStart": True},
            {"finalMeterVerified": True},
            {"validUntilMs": 1},
            {"sharedCeilingBytes": 0},
            {"reservationRevision": 4},
        )
        for change in malformed:
            with self.subTest(change=change), self.assertRaises(ValueError):
                bad = copy.deepcopy(p)
                bad.update(change)
                bad_raw = wal_transport.observed.canonical({
                    "algorithm": "Ed25519", "payload": bad,
                    "signature": "e" * 128,
                }) + b"\n"
                observed._observed_cap_request(
                    RUNTIME, NODE, ACTIVATION, bad_raw, scope, MAIN, "b" * 64)

    def test_immutable_observed_scope_and_zero_public_authority(self):
        raw, p, scope = fixture()
        req, checked = observed._observed_cap_request(
            RUNTIME, NODE, ACTIVATION, raw, scope, MAIN, "b" * 64)
        self.assertEqual(req["grantSha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(checked, p)
        baseline = reply(req, p)
        parsed = observed.verify_local_cap_observation(
            json.dumps(baseline).encode(), req, p, NODE, ACTIVATION)
        self.assertIs(parsed["canServePublic"], False)
        self.assertIs(parsed["canStart"], False)
        self.assertIs(parsed["canResume"], False)
        mutations = (
            ("nonce", "a" * 64), ("runtimeId", "f" * 64),
            ("nodeId", 48), ("userId", USER + 1),
            ("email", CDN), ("grantSha256", "f" * 64),
            ("reservationId", "foreign"), ("reservationRevision", 4),
            ("sharedCeilingBytes", 1000), ("chargedBytes", 70),
            ("chargedCdnBytes", 30), ("canServePublic", True),
            ("canStart", True), ("canResume", True),
            ("finalMeterVerified", True), ("refundableBytes", 1),
            ("installedLocalCap", 1), ("schemaVersion", True),
        )
        for key, value in mutations:
            with self.subTest(key=key), self.assertRaises(ValueError):
                bad = dict(baseline, **{key: value})
                observed.verify_local_cap_observation(
                    json.dumps(bad).encode(), req, p, NODE, ACTIVATION)
        with self.assertRaises(ValueError):
            observed.verify_local_cap_observation(
                json.dumps(dict(baseline, undocumentedFlag=True)).encode(),
                req, p, NODE, ACTIVATION)
        cdn_request = dict(req, email=CDN)
        full_cdn = dict(baseline, email=CDN, chargedCdnBytes=20)
        with self.assertRaises(ValueError):
            observed.verify_local_cap_observation(
                json.dumps(full_cdn).encode(), cdn_request, p, NODE, ACTIVATION)

    def test_real_private_unix_http_and_pidfd_proof(self):
        raw, p, scope = fixture()
        with tempfile.TemporaryDirectory(prefix="xmesh-observe-") as tmp:
            root = Path(tmp)
            os.chmod(root, 0o700)
            endpoint = root / "meter.sock"
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(str(endpoint))
                os.chmod(endpoint, 0o600)
                listener.listen(1)
                errors = []
                recorded = []

                def serve():
                    try:
                        with listener.accept()[0] as peer:
                            peer.settimeout(5)
                            data = b""
                            while b"\r\n\r\n" not in data:
                                data += peer.recv(4096)
                            header, body = data.split(b"\r\n\r\n", 1)
                            length = next(
                                int(line.split(b":", 1)[1].strip())
                                for line in header.split(b"\r\n")
                                if line.lower().startswith(b"content-length:"))
                            while len(body) < length:
                                body += peer.recv(4096)
                            request = json.loads(body[:length])
                            recorded.append(request)
                            payload = json.dumps(reply(request, p)).encode()
                            peer.sendall(
                                b"HTTP/1.1 200 OK\r\n"
                                + f"Content-Length: {len(payload)}\r\n".encode()
                                + b"Connection: close\r\n\r\n" + payload)
                    except Exception as exc:
                        errors.append(exc)

                worker = threading.Thread(target=serve, daemon=True)
                worker.start()
                with mock.patch.object(
                    observed.wal_transport.runtime_identity,
                    "trusted_runtime_identity", return_value=RUNTIME
                ) as verify_runtime:
                    result = observed.observe_installed_cap_in_xray(
                        endpoint, os.getpid(), RUNTIME, NODE,
                        ACTIVATION, raw, scope, MAIN)
                    self.assertGreaterEqual(verify_runtime.call_count, 3)
                worker.join(timeout=5)
                self.assertFalse(worker.is_alive(), "private Unix listener hung")
                self.assertEqual(errors, [])
                self.assertEqual(len(recorded), 1)
                self.assertEqual(recorded[0]["email"], MAIN)
                self.assertEqual(recorded[0]["runtimeId"], RUNTIME)
                self.assertEqual(recorded[0]["grantSha256"],
                                 hashlib.sha256(raw).hexdigest())
                self.assertEqual(result["chargedBytes"], 15)
                self.assertIs(result["canServePublic"], False)

    def test_foreign_pid_and_public_socket_path_are_rejected(self):
        raw, _, scope = fixture()
        with tempfile.TemporaryDirectory(prefix="xmesh-observe-") as tmp:
            root = Path(tmp)
            os.chmod(root, 0o777)
            with self.assertRaises((OSError, ValueError)):
                observed.observe_installed_cap_in_xray(
                    root / "missing.sock", os.getpid(), RUNTIME, NODE,
                    ACTIVATION, raw, scope, MAIN)
        with self.assertRaises(ValueError):
            observed.observe_installed_cap_in_xray(
                "relative.sock", os.getpid(), RUNTIME, NODE,
                ACTIVATION, raw, scope, MAIN)


if __name__ == "__main__":
    unittest.main()
