#!/usr/bin/env python3
"""Real Ed25519 signed roster checks; stop-only; NEVER grants public TLS."""
import copy
from pathlib import Path
import sys
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments/quota-v2-physical-stop"))
sys.path.insert(0, str(ROOT / "tests"))

import public_tls_cap_watch as watch
import test_quota_v2_first_cap_handoff as cap_fixture


class SignedCapRosterWatchTests(unittest.TestCase):
    def setUp(self):
        source = cap_fixture.FirstCapHandoffTests(
            "test_original_nexus_signer_and_real_assigned_vless_scope")
        source.setUp()
        self.addCleanup(source.doCleanups)
        self.source = source
        self.profile = copy.deepcopy(source.reply["config"])
        self.grants = {100: source.signed_grant()}
        self.args = dict(
            profile=self.profile, signed_grants=self.grants,
            pinned=source.pub, node=source.node,
            activation=source.fixture.activation,
            genesis_sha=source.reply["policySha256"],
            runtime_id=source.runtime, trusted_pid=12345,
            socket_path="/var/lib/xmesh-first-meter/runtime/drain.sock",
        )

    def watcher(self, **changes):
        args = dict(self.args)
        args.update(changes)
        return watch.SignedCapRosterWatch(**args)

    def test_real_pinned_ed25519_full_roster_checked_every_time(self):
        observed = []
        def probe(_socket, pid, runtime, node, activation, raw, scope, email):
            observed.append((pid, runtime, node, activation, raw, scope, email))
            return dict(userId=100, email=email, installedLocalCap=True,
                        canServePublic=False, canStart=False, canResume=False)
        with mock.patch.object(
                watch.cap_install, "observe_installed_cap_in_xray",
                side_effect=probe):
            verified = self.watcher()
            self.assertEqual(verified.check(), None)
            self.assertEqual(verified.check(), None)
        self.assertEqual(len(observed), 4)
        self.assertEqual(
            [v[-1] for v in observed],
            self.source.aliases and
            [self.source.aliases[0]["email"], self.source.aliases[1]["email"]] * 2)
        self.assertTrue(all(v[-3] == self.grants[100] for v in observed))
        self.assertTrue(all(v[-2]["userId"] == 100 for v in observed))
        self.assertTrue(all(v[-2]["aliases"] == self.source.aliases for v in observed))

    def test_missing_foreign_or_swapped_users_fail_closed(self):
        cases = (
            {"signed_grants": {}},
            {"signed_grants": {100: self.grants[100], 200: self.grants[100]}},
            {"signed_grants": {200: self.grants[100]}},
            {"runtime_id": "f" * 64},
            {"activation": "f" * 64},
            {"genesis_sha": "f" * 64},
            {"pinned": "f" * 64},
            {"node": self.source.node + 1},
        )
        for candidate in cases:
            with self.subTest(candidate=candidate.keys()), self.assertRaises(ValueError):
                self.watcher(**candidate)

    def test_tampered_signature_and_foreign_signed_cap_denied(self):
        tampered = self.grants[100].replace(b'"canSpend":true', b'"canSpend":false')
        with self.assertRaises(ValueError):
            self.watcher(signed_grants={100: tampered})
        wrong = dict(self.source.claims, userId=101)
        with self.assertRaises(ValueError):
            self.watcher(signed_grants={100: self.source.signed_grant(wrong)})
        wrong = dict(self.source.claims, validUntilMs=self.source.now - 1)
        with self.assertRaises(ValueError):
            self.watcher(signed_grants={100: self.source.signed_grant(wrong)})
        wrong = dict(self.source.claims, aliasScopes=self.source.aliases[:1])
        with self.assertRaises(ValueError):
            self.watcher(signed_grants={100: self.source.signed_grant(wrong)})
        wrong = dict(self.source.claims, runtimeId="f" * 64)
        with self.assertRaises(ValueError):
            self.watcher(signed_grants={100: self.source.signed_grant(wrong)})
        # A REAL signature over another policy is insufficient even when
        # the Node, process, VLESS UUID, aliases and other fields all match.
        wrong = dict(self.source.claims, policySha256="f" * 64)
        with self.assertRaises(ValueError):
            self.watcher(signed_grants={100: self.source.signed_grant(wrong)})

    def test_extra_unmetered_or_duplicate_vless_clients_denied(self):
        extra = copy.deepcopy(self.profile)
        extra["inbounds"][0]["settings"]["clients"].append({
            "id": "22222222-2222-4222-8222-222222222222",
            "email": "xmesh-u101--vless-main"})
        with self.assertRaises(ValueError):
            self.watcher(profile=extra)
        repeated = copy.deepcopy(self.profile)
        repeated["inbounds"][0]["settings"]["clients"].append(
            copy.deepcopy(repeated["inbounds"][0]["settings"]["clients"][0]))
        with self.assertRaises(ValueError):
            self.watcher(profile=repeated)
        different_uuid = copy.deepcopy(self.profile)
        different_uuid["inbounds"][1]["settings"]["clients"][0]["id"] = (
            "22222222-2222-4222-8222-222222222222")
        with self.assertRaises(ValueError):
            self.watcher(profile=different_uuid)
        public = copy.deepcopy(self.profile)
        public["inbounds"][0]["listen"] = "0.0.0.0"
        with self.assertRaises(ValueError):
            self.watcher(profile=public)

    def test_full_roster_probe_must_finish_inside_five_second_watchdog_budget(self):
        watcher = self.watcher()
        recorded = []
        def probe(_socket, _pid, _runtime, _node, _activation,
                  _raw, _scope, email):
            recorded.append(email)
            return dict(userId=100, email=email, installedLocalCap=True,
                        canServePublic=False, canStart=False, canResume=False)
        # The first alias replied, but the overall signed roster is late.
        # Reject rather than letting a healthy alias mask stalled others.
        with (mock.patch.object(
                watch.cap_install, "observe_installed_cap_in_xray",
                side_effect=probe),
              mock.patch.object(watch.time, "monotonic_ns",
                                side_effect=[0, 0, 5_000_000_001])):
            with self.assertRaisesRegex(ValueError, "watchdog deadline"):
                watcher.check()
        self.assertEqual(len(recorded), 1)

    def test_cap_probe_refuses_rolled_back_monotonic_clock(self):
        watcher = self.watcher()
        with (mock.patch.object(
                watch.cap_install, "observe_installed_cap_in_xray") as probe,
              mock.patch.object(watch.time, "monotonic_ns",
                                side_effect=[1000, 900])):
            with self.assertRaisesRegex(ValueError, "watchdog deadline"):
                watcher.check()
            probe.assert_not_called()

    def test_a_single_missing_exhausted_or_authorizing_xray_observation_denies_all(self):
        valid = self.watcher()
        for failure in ("missing", "exhausted", "authority", "foreign", "replaced"):
            called = []
            def probe(_socket, _pid, _runtime, _node, _activation,
                      _raw, _scope, email):
                called.append(email)
                if len(called) == 2:
                    if failure == "missing":
                        raise OSError("private Unix socket disappeared")
                    if failure == "exhausted":
                        raise ValueError("CDN cap consumed")
                    if failure == "replaced":
                        raise ValueError("Xray kernel PID changed")
                    if failure == "authority":
                        return dict(userId=100, email=email,
                                    installedLocalCap=True, canServePublic=True,
                                    canStart=False, canResume=False)
                    return dict(userId=101, email=email, installedLocalCap=True,
                                canServePublic=False, canStart=False,
                                canResume=False)
                return dict(userId=100, email=email, installedLocalCap=True,
                            canServePublic=False, canStart=False, canResume=False)
            with self.subTest(failure=failure), mock.patch.object(
                    watch.cap_install, "observe_installed_cap_in_xray",
                    side_effect=probe):
                with self.assertRaises((ValueError, OSError)):
                    valid.check()
                self.assertEqual(len(called), 2)


if __name__ == "__main__":
    unittest.main()
