#!/usr/bin/env python3
"""Strict XSP/2 public TLS evidence probe: intentionally zero authority."""
import copy
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parents[1] / "experiments/quota-v2-physical-stop"
sys.path.insert(0, str(HERE))

import public_tls_preflight as probe

NODE = 47
USER = 91
UUID_91 = "00000000-0000-4000-8000-000000000091"
UUID_99 = "00000000-0000-4000-8000-000000000099"


def reply(matched=True):
    return {
        "status": "candidate_only_not_authorized",
        "nodeId": NODE, "userId": USER,
        "evidenceMatched": matched,
        "capRosterSha256": "e"*64 if matched else None,
        "canServePublic": False, "canStart": False, "canResume": False,
        "canSpend": False, "authorizedBytes": 0, "signedEnvelope": None,
        "liveMeterVerified": False, "certificateVerified": False,
        "revocationWatchInstalled": False,
    }


def wire(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


class PublicTlsEvidenceTests(unittest.TestCase):
    def test_positive_sql_match_is_never_ingress_authority(self):
        for match in (True, False):
            evidence = probe.verify_zero_authority(wire(reply(match)), node=NODE, user=USER,
                                                    roster_sha256="e"*64)
            self.assertEqual(evidence["evidenceMatched"], match)
            self.assertEqual(evidence["capRosterSha256"], "e"*64 if match else None)
            self.assertEqual(evidence["authorizedBytes"], 0)
            self.assertIs(evidence["canServePublic"], False)
            self.assertEqual(evidence["status"], "checked_without_authority")

    def test_altered_or_positive_authority_replies_rejected(self):
        base = reply()
        mutations = {
            "status": "committed_public_tls_authority",
            "nodeId": NODE + 1,
            "userId": USER + 1,
            "evidenceMatched": 1,
            "capRosterSha256": "f"*64,
            "canServePublic": True,
            "canStart": True,
            "canResume": True,
            "canSpend": True,
            "authorizedBytes": 1,
            "signedEnvelope": "vless://untrusted",
            "liveMeterVerified": True,
            "certificateVerified": True,
            "revocationWatchInstalled": True,
        }
        for k, v in mutations.items():
            with self.subTest(field=k), self.assertRaises(ValueError):
                modified = copy.deepcopy(base)
                modified[k] = v
                probe.verify_zero_authority(wire(modified), node=NODE, user=USER, roster_sha256="e"*64)
        for k in base:
            with self.subTest(missing=k), self.assertRaises(ValueError):
                altered = copy.deepcopy(base)
                altered.pop(k)
                probe.verify_zero_authority(wire(altered), node=NODE, user=USER, roster_sha256="e"*64)
        base["serverSignerKey"] = "f" * 64
        with self.assertRaises(ValueError):
            probe.verify_zero_authority(wire(base), node=NODE, user=USER, roster_sha256="e"*64)

    def test_noncanonical_duplicate_json_and_oversized_response_denied(self):
        with self.assertRaises(ValueError):
            probe.verify_zero_authority(b'{"status":"candidate_only_not_authorized",'
                                        b'"status":"candidate_only_not_authorized"}',
                                        node=NODE, user=USER, roster_sha256="e"*64)
        with self.assertRaises(ValueError):
            probe.verify_zero_authority(b"x" * (probe.MAX_REPLY + 1), node=NODE, user=USER, roster_sha256="e"*64)

    def test_installed_probe_uses_original_signed_identity_and_never_writes_grants(self):
        with tempfile.TemporaryDirectory(prefix="xmesh-tls-preflight-") as root:
            parent = Path(root)
            state_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            lock_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(lambda: None)
            original = {
                "prepared": {"payload": {"candidateRuntimeId": "c" * 64}},
                "reply": {"policySha256": "b" * 64, "revision": "d" * 64},
            }
            activation = {"nodeId": NODE, "activationReceiptSha256": "a" * 64}
            measured = ("container", "some-other", 1234, "c" * 64)
            expected = {
                "nodeId": NODE, "userId": USER,
                "activationReceiptSha256": "a" * 64,
                "genesisPolicySha256": "b" * 64,
                "runtimeId": "c" * 64,
                "profileRevision": "d" * 64,
                "capRosterSha256": "e" * 64,
                "requiredLifetimeMs": 30_000,
            }
            watcher = mock.Mock()
            watcher.profile_sha256 = "d"*64
            watcher.roster_sha256 = "e"*64
            watcher._grants = {USER: (b"signed", None, ())}
            watcher.check.return_value = None
            with (mock.patch.object(probe, "_full_signed_roster", return_value=watcher),
                  mock.patch.object(probe.os, "geteuid", return_value=0),
                  mock.patch.object(probe.quarantine, "_locked_private_state",
                                    return_value=(state_fd, lock_fd)),
                  mock.patch.object(probe.wal_transport, "_panel_pin",
                                    return_value="f" * 64),
                  mock.patch.object(probe.quarantine, "_enrolled_activation",
                                    return_value=activation),
                  mock.patch.object(probe.genesis_reservation, "_staged_original",
                                    return_value=original),
                  mock.patch.object(probe.genesis_reservation, "_original_measurement_pins",
                                    return_value=("pin1", "pin2")),
                  mock.patch.object(probe.wal_transport, "_measure_quarantined_runtime",
                                    return_value=measured),
                  mock.patch.object(probe.quarantine, "_durable_store") as write,
                  mock.patch.object(probe.quarantine, "_post_quarantined_desired",
                                    return_value=wire(reply(True))) as send):
                result = probe.probe("https://nexus.example.com", NODE, USER, root)
                self.assertEqual(result["status"], "checked_without_authority")
                self.assertIs(result["canServePublic"], False)
                self.assertEqual(result["authorizedBytes"], 0)
                send.assert_called_once_with(
                    expected, root, probe.quarantine.TLS_PREFLIGHT_PATH)
                write.assert_not_called()
            # The monitor cannot retain or mutate any root state grants.
            self.assertEqual(list(parent.iterdir()), [])

    def test_full_roster_derives_only_original_signed_ids_and_root_owned_grants(self):
        original = {
            "reply": {
                "policySha256": "b"*64,
                "config": {"inbounds": [{
                    "tag": "vless-main", "settings": {"clients": [
                        {"id": UUID_99, "email": "xmesh-u99--vless-main"},
                        {"id": UUID_91, "email": "xmesh-u91--vless-main"},
                    ]},
                }]},
                "policy": {"users": [
                    {"userId": 99, "onHold": True, "offlineBudgetBytes": 0,
                     "xrayId": UUID_99},
                    {"userId": USER, "onHold": True, "offlineBudgetBytes": 0,
                     "xrayId": UUID_91},
                ]},
            },
        }
        files = [
            f"genesis-positive-cap-u{USER}.json",
            "genesis-positive-cap-u99.json",
        ]
        def read_receipt(_fd, name, max_size):
            self.assertEqual(max_size, 16384)
            user = int(name.split("-u")[1].split(".")[0])
            cap = wire({"algorithm": "Ed25519",
                        "payload": {"kind": "xmesh.quota-v2.xray-cap-admission"},
                        "signature": "1"*128}).decode()
            return dict(status="committed_first_cap", nodeId=NODE,
                        userId=user, signedEnvelope=cap)
        with (mock.patch.object(probe.os, "listdir", return_value=files),
              mock.patch.object(probe.genesis_reservation, "_identity_file",
                                side_effect=read_receipt),
              mock.patch.object(probe.public_tls_cap_watch,
                                "SignedCapRosterWatch") as witness):
            result = probe._full_signed_roster(
                17, original, NODE, "a"*64, "f"*64,
                ("container", "image", 1234, "c"*64))
        self.assertIs(result, witness.return_value)
        args = witness.call_args.kwargs
        self.assertEqual(set(args["signed_grants"]), {99, USER})
        self.assertEqual(args["signed_grants"][99],
                         wire({"algorithm": "Ed25519",
                               "payload": {"kind": "xmesh.quota-v2.xray-cap-admission"},
                               "signature": "1"*128}))
        self.assertEqual(args["signed_grants"][USER],
                         wire({"algorithm": "Ed25519",
                               "payload": {"kind": "xmesh.quota-v2.xray-cap-admission"},
                               "signature": "1"*128}))
        self.assertEqual(args["trusted_pid"], 1234)
        self.assertEqual(args["socket_path"], probe.SOCKET)

    def test_original_signed_policy_uuid_must_match_each_xray_vless_client(self):
        original = {
            "reply": {
                "policySha256": "b"*64,
                "config": {"inbounds": [
                    {"tag": "vless-main", "settings": {"clients": [
                        {"id": UUID_91, "email": "xmesh-u91--vless-main"},
                    ]}},
                    {"tag": "vless-cdn", "settings": {"clients": [
                        {"id": UUID_91, "email": "xmesh-u91--vless-cdn"},
                    ]}},
                ]},
                "policy": {"users": [
                    {"userId": USER, "onHold": True, "offlineBudgetBytes": 0,
                     "xrayId": UUID_91},
                ]},
            }
        }
        signed = wire({
            "algorithm": "Ed25519",
            "payload": {"kind": "xmesh.quota-v2.xray-cap-admission"},
            "signature": "1"*128,
        }).decode()
        receipt = {"status": "committed_first_cap", "nodeId": NODE,
                   "userId": USER, "signedEnvelope": signed}
        with (mock.patch.object(probe.os, "listdir",
                                return_value=[f"genesis-positive-cap-u{USER}.json"]),
              mock.patch.object(probe.genesis_reservation, "_identity_file",
                                return_value=receipt),
              mock.patch.object(probe.public_tls_cap_watch,
                                "SignedCapRosterWatch") as watcher):
            def check(profile):
                candidate = copy.deepcopy(original)
                candidate["reply"]["config"] = profile
                return probe._full_signed_roster(
                    17, candidate, NODE, "a"*64, "f"*64,
                    ("container", "image", 1234, "c"*64))
            self.assertIs(check(original["reply"]["config"]), watcher.return_value)
            wrong = copy.deepcopy(original["reply"]["config"])
            wrong["inbounds"][1]["settings"]["clients"][0]["id"] = UUID_99
            with self.assertRaisesRegex(ValueError, "signed Genesis user UUID"):
                check(wrong)
            wrong = copy.deepcopy(original["reply"]["config"])
            wrong["inbounds"][0]["settings"]["clients"][0]["email"] = (
                "xmesh-u99--vless-main")
            with self.assertRaisesRegex(ValueError, "signed Genesis user UUID"):
                check(wrong)
            for bad in ("INVALID", UUID_99, UUID_91.upper(), None):
                candidate = copy.deepcopy(original)
                candidate["reply"]["policy"]["users"][0]["xrayId"] = bad
                with self.subTest(xrayId=bad), self.assertRaises(ValueError):
                    probe._full_signed_roster(
                        17, candidate, NODE, "a"*64, "f"*64,
                        ("container", "image", 1234, "c"*64))
        # A signed cap is never permission to open a public listener.
        self.assertFalse(hasattr(probe, "launch_public_listener"))

    def test_missing_foreign_duplicate_or_renewed_root_cap_fails_before_network(self):
        original = {"reply": {
            "policy": {"users": [{"userId": USER, "onHold": True,
                                   "offlineBudgetBytes": 0, "xrayId": UUID_91}]},
            "config": {"inbounds": [{
                "tag": "vless-main", "settings": {"clients": [
                    {"id": UUID_91, "email": "xmesh-u91--vless-main"},
                ]},
            }]}, "policySha256": "b"*64,
        }}
        measured = ("container", "image", 1234, "c"*64)
        variants = [
            [], ["genesis-positive-cap-u92.json"],
            ["genesis-positive-cap-u091.json",
             "genesis-positive-cap-u91.json"],
            ["genesis-renewal-u91-r2.json",
             "genesis-positive-cap-u91.json"],
        ]
        for files in variants:
            with (self.subTest(files=files),
                  mock.patch.object(probe.os, "listdir", return_value=files),
                  mock.patch.object(probe.genesis_reservation,
                                    "_identity_file") as read,
                  mock.patch.object(probe.public_tls_cap_watch,
                                    "SignedCapRosterWatch") as witness,
                  self.assertRaises(ValueError)):
                probe._full_signed_roster(
                    17, original, NODE, "a"*64, "f"*64, measured)
                witness.assert_not_called()
        for user in [
            {"userId": USER, "onHold": False, "offlineBudgetBytes": 0},
            {"userId": USER, "onHold": True, "offlineBudgetBytes": "0"},
            {"userId": True, "onHold": True, "offlineBudgetBytes": 0},
        ]:
            invalid = copy.deepcopy(original)
            invalid["reply"]["policy"]["users"] = [user]
            with (self.subTest(user=user),
                  self.assertRaises(ValueError)):
                probe._full_signed_roster(
                    17, invalid, NODE, "a"*64, "f"*64, measured)

    def test_signed_match_with_changed_local_cap_after_network_is_denied(self):
        with tempfile.TemporaryDirectory(prefix="xmesh-tls-swap-") as state:
            state_fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
            lock_fd = os.open(state, os.O_RDONLY | os.O_DIRECTORY)
            watcher = mock.Mock()
            watcher.profile_sha256 = "d"*64
            watcher.roster_sha256 = "e"*64
            watcher._grants = {USER: (b"signed", None, ())}
            watcher.check.side_effect = [None, ValueError("cap replaced")]
            original = {
                "prepared": {"payload": {"candidateRuntimeId": "c"*64}},
                "reply": {"policySha256": "b"*64, "revision": "d"*64},
            }
            activation = {"activationReceiptSha256": "a"*64}
            with (mock.patch.object(probe, "_full_signed_roster",
                                    return_value=watcher),
                  mock.patch.object(probe.os, "geteuid", return_value=0),
                  mock.patch.object(probe.quarantine, "_locked_private_state",
                                    return_value=(state_fd, lock_fd)),
                  mock.patch.object(probe.wal_transport, "_panel_pin",
                                    return_value="f"*64),
                  mock.patch.object(probe.quarantine, "_enrolled_activation",
                                    return_value=activation),
                  mock.patch.object(probe.genesis_reservation,
                                    "_staged_original", return_value=original),
                  mock.patch.object(probe.genesis_reservation,
                                    "_original_measurement_pins",
                                    return_value=("pin1", "pin2")),
                  mock.patch.object(probe.wal_transport,
                                    "_measure_quarantined_runtime",
                                    return_value=("container", "image", 1234, "c"*64)),
                  mock.patch.object(probe.quarantine,
                                    "_post_quarantined_desired",
                                    return_value=wire(reply(True))) as send,
                  self.assertRaisesRegex(ValueError, "cap replaced")):
                probe.probe("https://nexus.example.com", NODE, USER, state)
            send.assert_called_once()

    def test_unenrolled_or_invalid_request_cannot_tunnel(self):
        for values in (
            ("http://insecure.example", NODE, USER, 30_000),
            ("https://nexus.example.com", 0, USER, 30_000),
            ("https://nexus.example.com", NODE, 0, 30_000),
            ("https://nexus.example.com", NODE, USER, 120_001),
            ("https://nexus.example.com", NODE, USER, True),
        ):
            with self.subTest(request=values), self.assertRaises(ValueError):
                probe.probe(values[0], values[1], values[2],
                            "/nonexistent/private", values[3])


if __name__ == "__main__":
    unittest.main()
