#!/usr/bin/env python3
"""Literal signed Nexus wire, actual private Go-format WAL, no ingress permit."""
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments/quota-v2-physical-stop"))
import public_tls_wal_watch as watch
import public_tls_cap_watch
import quota_v2_meter_wal_fixture as wal_fixture
import test_quota_v2_first_cap_handoff as cap_fixture


class PublicTlsWalWatchTests(unittest.TestCase):
    def setUp(self):
        self.source = cap_fixture.FirstCapHandoffTests(
            "test_original_nexus_signer_and_real_assigned_vless_scope")
        self.source.setUp()
        self.addCleanup(self.source.doCleanups)
        source = self.source
        raw = source.signed_grant()
        self.roster = public_tls_cap_watch.SignedCapRosterWatch(
            profile=source.reply["config"], signed_grants={100: raw}, pinned=source.pub,
            node=source.node, activation=source.fixture.activation,
            genesis_sha=source.reply["policySha256"], runtime_id=source.runtime,
            trusted_pid=12345, socket_path="/var/lib/xmesh-first-meter/runtime/drain.sock")
        tmp = tempfile.TemporaryDirectory(prefix="xmesh-tls-wal-test-")
        self.addCleanup(tmp.cleanup)
        self.directory = Path(tmp.name)
        cap = self.directory / "positive-cap-u100.json"
        cap.write_bytes(raw)
        cap.chmod(0o600)
        self.measured = ("a"*64, "2026-11-26T19:30:01.012345678Z", 12345, source.runtime)
        self.counters = (0, 0)
        self.requests = []

    def snapshot(self):
        return watch._snapshot(self.directory, self.roster, lambda: None)

    def create_wal(self, runtime=None, alias="xmesh-u100--vless-main"):
        wal_fixture.write_test_meter_intents({
            "runtimeId": runtime or self.roster.runtime_id,
            "inboundMeters": [
                {"email": alias, "uplinkBytes": 42, "downlinkBytes": 2},
                {"email": "xmesh-u100--vless-cdn", "uplinkBytes": 7, "downlinkBytes": 0},
            ],
        }, self.directory)
        self.counters = (51, 7)

    def reply(self, request, snapshot, changes=None, *, domain=watch.DOMAIN):
        # Independent explicit wire contract, not the verifier's expected map.
        scope = request["proof"]["scope"]
        proof = request["proof"]
        now = time.time_ns() // 1_000_000
        p = {
            "schemaVersion": 1, "kind": "xmesh.quota-v2.public-tls-wal-head",
            "nodeId": scope["nodeId"], "userId": scope["userId"],
            "activationReceiptSha256": scope["activationReceiptSha256"],
            "genesisPolicySha256": scope["genesisPolicySha256"],
            "runtimeId": scope["runtimeId"], "profileRevision": scope["profileRevision"],
            "capRosterSha256": scope["capRosterSha256"],
            "challenge": proof["challenge"], "containerId": proof["containerId"],
            "hostPid": proof["hostPid"], "startedAt": proof["startedAt"],
            "issuedAtMs": now, "validUntilMs": now + 7000,
            "historyState": ("committed_birth_index" if snapshot["sequence"]
                             else "empty_remote_history"),
            "inventorySequence": snapshot["sequence"],
            "inventorySha256": snapshot["sha256"],
            "inventoryTailDigest": snapshot["tail"],
            "committedChargeStreamCount": snapshot["sequence"],
            "preBootstrapHistoryCompletenessVerified": False,
            "liveMeterVerified": False, "finalMeterVerified": False,
            "canServePublic": False, "canSpend": False, "canStart": False,
            "canResume": False, "authorizedBytes": 0, "refundableBytes": 0,
        }
        p.update(changes or {})
        return watch.wal.observed.canonical({"signedEnvelope": (
            watch.wal.observed.canonical({
                "algorithm": "Ed25519", "payload": p,
                "signature": self.source.sign(domain, p),
            }) + b"\n").decode()})

    def local(self, _socket, pid, runtime, node, activation, raw, scope, email):
        self.assertEqual((pid, runtime, node, activation),
                         (self.roster._pid, self.roster.runtime_id,
                          self.roster.node, self.roster.activation))
        self.assertEqual(raw, self.roster._grants[100][0])
        self.assertEqual(scope["userId"], 100)
        return {
            "userId": 100, "email": email, "installedLocalCap": True,
            "canServePublic": False, "canStart": False, "canResume": False,
            "finalMeterVerified": False, "refundableBytes": 0,
            "chargedBytes": self.counters[0], "chargedCdnBytes": self.counters[1],
        }

    def check(self, fetch=None, remeasure=None):
        def normal(request):
            self.requests.append(request)
            return self.reply(request, self.snapshot())

        with (mock.patch.object(watch, "_fetch", side_effect=fetch or normal),
              mock.patch.object(public_tls_cap_watch.cap_install,
                                "observe_installed_cap_in_xray", side_effect=self.local)):
            return watch._check(self.roster, 100, self.measured, self.directory,
                                remeasure or (lambda: (self.measured, self.directory)),
                                lambda: None)

    def test_empty_and_real_nonempty_index_have_no_authority(self):
        self.assertEqual(self.snapshot()["sha256"], hashlib.sha256(b"").hexdigest())
        self.assertIsNone(self.check())
        self.assertIsNone(self.check())
        self.assertNotEqual(self.requests[0]["proof"]["challenge"],
                            self.requests[1]["proof"]["challenge"])
        self.create_wal()
        snapshot = self.snapshot()
        self.assertEqual(snapshot["sequence"], 3)
        self.assertEqual(snapshot["totals"], {100: [51, 7]})
        self.assertEqual(snapshot["sha256"], hashlib.sha256(
            (self.directory / watch.wal.registry.NAME).read_bytes()).hexdigest())
        self.assertIsNone(self.check())

    def test_real_signature_is_not_authority_or_a_substitute_for_fresh_scope(self):
        request = watch._request(self.roster, 100, self.measured)
        snapshot = self.snapshot()
        for field, value in (
            ("challenge", "f"*64), ("nodeId", self.roster.node+1),
            ("userId", True), ("hostPid", 12346), ("containerId", "f"*64),
            ("startedAt", "2026-11-26T19:30:02Z"), ("runtimeId", "f"*64),
            ("profileRevision", "f"*64), ("capRosterSha256", "f"*64),
            ("activationReceiptSha256", "f"*64), ("genesisPolicySha256", "f"*64),
            ("canServePublic", True), ("canSpend", True), ("canStart", True),
            ("canResume", True), ("authorizedBytes", 1), ("refundableBytes", 1),
            ("liveMeterVerified", True), ("finalMeterVerified", True),
            ("preBootstrapHistoryCompletenessVerified", True),
            ("historyState", "committed_birth_index"), ("inventorySequence", 1),
            ("inventorySha256", "f"*64), ("inventoryTailDigest", "f"*64),
            ("committedChargeStreamCount", 1), ("committedChargeStreamCount", True),
            ("validUntilMs", 1), ("validUntilMs", time.time_ns()//1_000_000 + 30000),
            ("issuedAtMs", time.time_ns()//1_000_000 - 5000),
        ):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                watch._verify(self.reply(request, snapshot, {field: value}), request,
                              self.roster.pinned, snapshot, time.time_ns()//1_000_000)
        for raw, pin in (
            (self.reply(request, snapshot, domain=b"foreign-domain"), self.roster.pinned),
            (self.reply(request, snapshot), "e"*64),
            (b'{"error":"No committed WAL checkpoint."}', self.roster.pinned),
            (b'{"signedEnvelope":"a","signedEnvelope":"b"}', self.roster.pinned),
        ):
            with self.assertRaises(ValueError):
                watch._verify(raw, request, pin, snapshot, time.time_ns()//1_000_000)

    def test_signed_empty_cannot_hide_nonzero_counters_or_lost_wal(self):
        self.counters = (1, 0)
        with self.assertRaisesRegex(ValueError, "counters differ"):
            self.check()
        empty = self.snapshot()
        self.create_wal()
        with self.assertRaisesRegex(ValueError, "mismatched Nexus WAL"):
            self.check(lambda request: self.reply(request, empty))
        # Deleting one indexed stream, or the entire index, cannot pass.
        index = self.directory / watch.wal.registry.NAME
        raw = index.read_bytes()
        index.unlink()
        with self.assertRaisesRegex(ValueError, "without birth index"):
            self.snapshot()
        index.write_bytes(raw)
        index.chmod(0o600)
        next(self.directory.glob("meter-*.jsonl")).unlink()
        with self.assertRaisesRegex(ValueError, "missing previously"):
            self.snapshot()

    def test_foreign_runtime_and_alias_never_match_original(self):
        self.create_wal(runtime="f"*64)
        with self.assertRaisesRegex(ValueError, "outside original"):
            self.snapshot()
        for path in self.directory.glob("meter-*.jsonl"):
            path.unlink()
        (self.directory / watch.wal.registry.NAME).unlink()
        self.create_wal(alias="xmesh-u999--vless-main")
        with self.assertRaisesRegex(ValueError, "outside original"):
            self.snapshot()

    def test_cap_bytes_and_unexpected_later_ledger_denied(self):
        cap = self.directory / "positive-cap-u100.json"
        original = cap.read_bytes()
        cap.write_bytes(b"x"*len(original))
        with self.assertRaisesRegex(ValueError, "durable cap differs"):
            self.snapshot()
        cap.write_bytes(original)
        later = self.directory / "positive-cap-u100-r2.json"
        later.write_bytes(original)
        with self.assertRaisesRegex(ValueError, "later first-Genesis"):
            self.snapshot()
        later.unlink()
        cap.unlink()
        cap.symlink_to("/dev/null")
        with self.assertRaisesRegex(ValueError, "unsafe"):
            self.snapshot()

    def test_mutation_during_readback_or_changed_pid_denied(self):
        def fetch(request):
            raw = self.reply(request, self.snapshot())
            self.create_wal()
            # Simulate stale (not authoritative) counter samples: local
            # WAL reread still has to detect the intervening birth.
            self.counters = (0, 0)
            return raw
        with self.assertRaisesRegex(ValueError, "changed during readback"):
            self.check(fetch)
        self.counters = (51, 7)
        with self.assertRaisesRegex(ValueError, "changed during readback"):
            self.check(remeasure=lambda: (("b"*64, *self.measured[1:]), self.directory))

    def test_transport_refuses_404_no_fallback(self):
        def run(command, **kwargs):
            self.assertEqual(command[0:4],
                             [watch.wal.PRODUCT, "request", "--path", watch.wal.PATH])
            self.assertEqual(kwargs["timeout"], 2.8)
            Path(command[command.index("--output-file")+1]).write_text(
                '{"error":"No committed WAL checkpoint."}')
            Path(command[command.index("--status-file")+1]).write_text("404")
        with mock.patch.object(watch.subprocess, "run", side_effect=run) as call:
            with self.assertRaisesRegex(ValueError, "did not sign"):
                watch._fetch(watch._request(self.roster, 100, self.measured))
            self.assertEqual(call.call_count, 1)


if __name__ == "__main__":
    unittest.main()
