#!/usr/bin/env python3
"""Offline tests: signed observation is authenticated, immutable, and NONFINAL."""
import copy
import importlib.util
import json
from pathlib import Path
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "signed_nonfinal_observation",
    ROOT / "experiments/xray-dataplane-fence/sign_observation.py")
evidence = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(evidence)


def checkpoint(node=7):
    return {
        "schemaVersion": 3, "email": "xmesh-u1--MAIN",
        "nodeId": node, "userId": 1,
        "epoch": "11111111-1111-4111-8111-111111111111",
        "meterEpoch": "22222222-2222-4222-8222-222222222222",
        "reservationId": "33333333-3333-4333-8333-333333333333",
        "revision": 4,
        "revocationId": "44444444-4444-4444-8444-444444444444",
        "runtimeId": "a" * 64, "uplinkBytes": 90, "downlinkBytes": 20,
        "inboundMeters": [{"email": "xmesh-u1--MAIN", "uplinkBytes": 90,
                          "downlinkBytes": 20}],
        "drained": True, "finalMeterVerified": False,
        "refundableBytes": 0,
    }


class SignedNonfinalObservationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.state = self.root / "state"
        self.output = self.root / "observed"
        self.state.mkdir(mode=0o700)
        self.output.mkdir(mode=0o700)
        (self.state / "policy-usage.json").write_text('{"users":{}}')
        self.key = self.root / "node.key"
        self.pub = self.root / "node.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519",
                        "-out", str(self.key)], check=True,
                       capture_output=True)
        os.chmod(self.key, 0o600)
        subprocess.run(["openssl", "pkey", "-in", str(self.key),
                        "-pubout", "-out", str(self.pub)], check=True,
                       capture_output=True)
        self.valid_binding = {
            "scopeBoundToSignedPolicy": True,
            "completeSignedInboundScopeObserved": True,
            "finalMeterVerified": False, "refundableBytes": 0,
        }

    def create(self, cp=None, binding=None):
        if cp is None:
            cp = checkpoint()
        if binding is None:
            binding = self.valid_binding
        with patch.object(evidence.guard, "verify_committed_observed_checkpoint",
                          return_value=binding) as bound:
            result = evidence.create_observation(
                self.state, 7, cp, self.key, self.output)
        bound.assert_called_once()
        return result

    def test_signature_exact_replay_and_immutable_private_file(self):
        cp = checkpoint()
        signed = self.create(cp)
        valid = evidence.verify_envelope(signed, 7, self.pub)
        self.assertEqual(valid["checkpoint"], cp)
        self.assertFalse(valid["finalMeterVerified"])
        self.assertTrue(valid["completeSignedInboundScopeObserved"])
        self.assertFalse(valid["settlementEligible"])
        self.assertEqual(valid["refundableBytes"], 0)
        target = self.output / evidence.receipt_name(cp)
        self.assertTrue(target.is_file())
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        before = target.read_bytes()
        inode = target.stat().st_ino
        self.assertEqual(before, evidence.canonical(signed) + b"\n")
        self.assertEqual(self.create(cp), signed)
        self.assertEqual(target.stat().st_ino, inode)
        self.assertEqual(target.read_bytes(), before)

    def test_conflicting_meter_never_overwrites(self):
        cp = checkpoint()
        self.create(cp)
        target = self.output / evidence.receipt_name(cp)
        before = target.read_bytes()
        newer = dict(cp, downlinkBytes=21)
        with self.assertRaisesRegex(ValueError, "conflicting"):
            self.create(newer)
        self.assertEqual(target.read_bytes(), before)

    def test_changed_revocation_or_revision_cannot_mint_new_reservation_receipt(self):
        cp = checkpoint()
        self.create(cp)
        original_path = self.output / evidence.receipt_name(cp)
        original = original_path.read_bytes()
        for edited in (
            dict(cp, revocationId="55555555-5555-4555-8555-555555555555"),
            dict(cp, revision=cp["revision"] + 1),
        ):
            self.assertEqual(evidence.receipt_name(edited),
                             evidence.receipt_name(cp))
            with self.subTest(edited=edited), self.assertRaisesRegex(
                    ValueError, "conflicting"):
                self.create(edited)
        self.assertEqual(sorted(self.output.iterdir()), [original_path])
        self.assertEqual(original_path.read_bytes(), original)

    def test_unverified_or_refundable_guard_result_cannot_sign(self):
        cp = checkpoint()
        for binding in (
            {"scopeBoundToSignedPolicy": False,
             "finalMeterVerified": False, "refundableBytes": 0},
            {"scopeBoundToSignedPolicy": True,
             "finalMeterVerified": True, "refundableBytes": 0},
            {"scopeBoundToSignedPolicy": True,
             "finalMeterVerified": False, "refundableBytes": 10},
        ):
            with self.subTest(binding=binding), self.assertRaises(ValueError):
                self.create(cp, binding=binding)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_injected_raw_heartbeat_is_not_committed_policy(self):
        with patch.object(evidence.guard, "verify_committed_observed_checkpoint",
                          side_effect=ValueError("Missing committed signed policy")):
            with self.assertRaisesRegex(ValueError, "Missing committed"):
                evidence.create_observation(
                    self.state, 7, checkpoint(), self.key, self.output)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_cross_node_identity_and_signature_tampering(self):
        signed = self.create()
        with self.assertRaisesRegex(ValueError, "refund authority"):
            evidence.verify_envelope(signed, 8, self.pub)
        for changer in (
            lambda s: s["payload"].update(refundableBytes=1),
            lambda s: s["payload"].update(settlementEligible=True),
            lambda s: s["payload"].update(finalMeterVerified=True),
            lambda s: s["payload"]["checkpoint"].update(downlinkBytes=19),
            lambda s: s.update(signature="0"*128),
        ):
            altered = copy.deepcopy(signed)
            changer(altered)
            with self.assertRaises(ValueError):
                evidence.verify_envelope(altered, 7, self.pub)

    def test_signed_envelope_never_accepts_incomplete_inbound_row_data(self):
        good = self.create()
        for mutator in (
            lambda x: x["payload"]["checkpoint"]["inboundMeters"].clear(),
            lambda x: x["payload"]["checkpoint"]["inboundMeters"][0].update(
                uplinkBytes=92),
            lambda x: x["payload"].update(
                completeSignedInboundScopeObserved=False),
            lambda x: x["payload"]["checkpoint"]["inboundMeters"].append(
                copy.deepcopy(x["payload"]["checkpoint"]["inboundMeters"][0])),
        ):
            altered = copy.deepcopy(good)
            mutator(altered)
            with self.subTest(mutator=mutator), self.assertRaises(ValueError):
                evidence.verify_envelope(altered, 7, self.pub)

    def test_guard_must_confirm_complete_signed_scope_before_signing(self):
        partial = {
            "scopeBoundToSignedPolicy": True,
            "completeSignedInboundScopeObserved": False,
            "finalMeterVerified": False, "refundableBytes": 0,
        }
        with self.assertRaisesRegex(ValueError, "safely bound"):
            self.create(binding=partial)
        self.assertEqual(list(self.output.iterdir()), [])

    def test_wrong_node_public_key_cannot_verify(self):
        signed = self.create()
        other_key = self.root / "other.key"
        other_pub = self.root / "other.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519",
                        "-out", str(other_key)], check=True, capture_output=True)
        subprocess.run(["openssl", "pkey", "-in", str(other_key),
                        "-pubout", "-out", str(other_pub)], check=True,
                       capture_output=True)
        with self.assertRaisesRegex(ValueError, "signature mismatch"):
            evidence.verify_envelope(signed, 7, other_pub)

    def test_key_and_ledger_permissions_fail_closed(self):
        cp = checkpoint()
        os.chmod(self.key, 0o644)
        with self.assertRaisesRegex(ValueError, "unsafe Node signing key"):
            self.create(cp)
        os.chmod(self.key, 0o600)
        os.chmod(self.output, 0o755)
        with self.assertRaisesRegex(ValueError, "untrusted observation"):
            self.create(cp)
        os.chmod(self.output, 0o700)
        alias = self.root / "alias.key"
        alias.symlink_to(self.key)
        with self.assertRaises(OSError):
            with patch.object(evidence.guard, "verify_committed_observed_checkpoint",
                              return_value=self.valid_binding):
                evidence.create_observation(
                    self.state, 7, cp, alias, self.output)

    def test_corrupted_or_linked_evidence_does_not_mutate(self):
        cp = checkpoint()
        self.create(cp)
        target = self.output / evidence.receipt_name(cp)
        target.write_bytes(b"garbage")
        with self.assertRaisesRegex(ValueError, "conflicting"):
            self.create(cp)
        self.assertEqual(target.read_bytes(), b"garbage")
        # A hardlink allows another path to mutate the ledger: refuse it.
        alias = self.output / "alias"
        os.link(target, alias)
        with self.assertRaisesRegex(ValueError, "unsafe immutable"):
            self.create(cp)
        self.assertEqual(target.read_bytes(), b"garbage")

    def test_strict_json_rejects_duplicate_fields(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            evidence.strict_json(b'{"signature":"a","signature":"b"}')
        with self.assertRaises(ValueError):
            evidence.strict_json(b'{"value":NaN}')


if __name__ == "__main__":
    unittest.main()
