#!/usr/bin/env python3
"""No refund: exact runtime+per-inbound Node floor regressions."""
import copy
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from meter_floor import verify_monotonic_meter_floor as verify

DOCKER = ("a" * 64, "2026-11-18T12:00:00Z", 1245)


def sample():
    return {
        "runtimeId": DOCKER[0] + " " + DOCKER[1],
        "users": {"101": {"last": 280, "total": 560}},
        "inbounds": {
            '[101,"vless-main"]': {
                "lastUp": 100, "lastDown": 20,
                "totalUp": 240, "totalDown": 100},
            '[101,"PL/CDN"]': {
                "lastUp": 140, "lastDown": 20,
                "totalUp": 140, "totalDown": 80},
        },
    }, {
        "userId": 101,
        "uplinkBytes": 300, "downlinkBytes": 100,
        "inboundMeters": [
            {"email": "xmesh-u101--PL%2FCDN",
             "uplinkBytes": 170, "downlinkBytes": 50},
            {"email": "xmesh-u101--vless-main",
             "uplinkBytes": 130, "downlinkBytes": 50},
        ],
    }


class MeterFloorTests(unittest.TestCase):
    def test_signed_main_cdn_above_durable_floor_not_final(self):
        ledger, checkpoint = sample()
        proof = verify(ledger, checkpoint, DOCKER)
        self.assertEqual(proof["durableAbsoluteBytes"], 560)
        self.assertEqual(proof["observedRawBytes"], 400)
        self.assertTrue(proof["sameDockerRuntime"])
        self.assertTrue(proof["aboveDurableFloor"])
        self.assertFalse(proof["finalMeterVerified"])
        self.assertEqual(proof["refundableBytes"], 0)

    def test_sticky_discontinuity_refuses_new_signing_even_after_counters_recover(self):
        for reason in ("regressed-xray-user-counter",
                       "missing-xray-inbound-counter",
                       "unverified-xray-runtime-transition"):
            ledger, cp = sample()
            ledger["users"]["101"]["quotaMeterContinuityLost"] = {
                "reason": reason, "runtimeId": ledger["runtimeId"],
                "atMs": 1795050000000,
            }
            with self.subTest(reason=reason), self.assertRaisesRegex(
                    ValueError, "continuity loss"):
                verify(ledger, cp, DOCKER)

    def test_cumulative_inbounds_cannot_outgrow_absolute_user_meter(self):
        ledger, cp = sample()
        # A raw reset of the user's aggregate meter can be hidden behind
        # an apparently healthy raw snapshot. The historic inbound totals
        # are stronger and MUST not be allowed to exceed user absolute.
        ledger["users"]["101"]["total"] = 350
        self.assertGreaterEqual(
            ledger["users"]["101"]["total"],
            ledger["users"]["101"]["last"])
        with self.assertRaisesRegex(ValueError, "inbound cumulative bytes exceed"):
            verify(ledger, cp, DOCKER)

    def test_recent_inbound_delta_must_fit_user_absolute_delta(self):
        ledger, cp = sample()
        # The individual cumulative totals are <= the durable user total,
        # yet after adding newly observed per-inbound raw bytes the
        # account's projected absolute total becomes inconsistent.
        ledger["users"]["101"]["total"] = 540
        with self.assertRaisesRegex(ValueError, "inbound cumulative bytes exceed"):
            verify(ledger, cp, DOCKER)
        # A coherent previous ledger remains nonfinal and signs no refunds.
        ledger["users"]["101"]["total"] = 560
        self.assertFalse(verify(ledger, cp, DOCKER)["finalMeterVerified"])

    def test_cumulative_inbound_overflow_is_nonproof(self):
        ledger, cp = sample()
        ledger["inbounds"]['[101,"vless-main"]']["totalUp"] = 2**63 - 1
        with self.assertRaisesRegex(ValueError, "cumulative signed inbound meter overflow"):
            verify(ledger, cp, DOCKER)

    def test_every_inbound_counter_must_be_monotonic(self):
        for index in (0, 1):
            for column in ("uplinkBytes", "downlinkBytes"):
                ledger, checkpoint = sample()
                tag = "PL/CDN" if index == 0 else "vless-main"
                last = ledger["inbounds"][
                    '[101,"' + tag + '"]']
                checkpoint["inboundMeters"][index][column] = (
                    last["lastUp" if column == "uplinkBytes" else "lastDown"] - 1)
                checkpoint["uplinkBytes"] = sum(
                    x["uplinkBytes"] for x in checkpoint["inboundMeters"])
                checkpoint["downlinkBytes"] = sum(
                    x["downlinkBytes"] for x in checkpoint["inboundMeters"])
                with self.subTest(index=index, direction=column):
                    with self.assertRaisesRegex(ValueError, "regressed"):
                        verify(ledger, checkpoint, DOCKER)

    def test_wrong_runtime_or_container_restart_rejected(self):
        ledger, cp = sample()
        for other in (
            ("b"*64, DOCKER[1], 1245),
            (DOCKER[0], "2026-11-18T12:01:00Z", 1255),
        ):
            with self.subTest(runtime=other), self.assertRaisesRegex(
                    ValueError, "another Xray runtime"):
                verify(ledger, cp, other)

    def test_user_raw_floor_cannot_rollback(self):
        ledger, cp = sample()
        ledger["users"]["101"]["last"] = 401
        with self.assertRaisesRegex(ValueError, "regressed"):
            verify(ledger, cp, DOCKER)

    def test_missing_prior_inbound_and_missing_user_fail_closed(self):
        ledger, cp = sample()
        for mutation in (
            lambda d: d["inbounds"].pop('[101,"PL/CDN"]'),
            lambda d: d["users"].pop("101"),
            lambda d: d.pop("inbounds"),
            lambda d: d.pop("runtimeId"),
        ):
            broken = copy.deepcopy(ledger)
            mutation(broken)
            with self.assertRaises(ValueError):
                verify(broken, cp, DOCKER)

    def test_malformed_bool_nan_negative_and_cumulative_meters(self):
        ledger, cp = sample()
        for updater in (
            lambda d: d["users"]["101"].update(last=True),
            lambda d: d["users"]["101"].update(total=-1),
            lambda d: d["inbounds"]['[101,"vless-main"]'].update(lastUp=True),
            lambda d: d["inbounds"]['[101,"vless-main"]'].update(totalDown=None),
            lambda d: d["inbounds"]['[101,"vless-main"]'].update(totalUp=99),
            lambda d: d["inbounds"]['[101,"vless-main"]'].update(totalDown=19),
            lambda d: d["users"]["101"].update(total=5),
        ):
            broken = copy.deepcopy(ledger)
            updater(broken)
            with self.assertRaises(ValueError):
                verify(broken, cp, DOCKER)

    def test_duplicate_or_wrong_user_inbound_not_accepted(self):
        ledger, cp = sample()
        for replace in ("xmesh-u101--vless-main", "xmesh-u102--PL%2FCDN",
                        "xmesh-u101--%ZZ"):
            changed = copy.deepcopy(cp)
            changed["inboundMeters"][0]["email"] = replace
            with self.assertRaises(ValueError):
                verify(ledger, changed, DOCKER)

    def test_overflow_cannot_mint_evidence(self):
        ledger, cp = sample()
        cp["inboundMeters"][0]["uplinkBytes"] = 2**63 - 1
        with self.assertRaises(ValueError):
            verify(ledger, cp, DOCKER)


if __name__ == "__main__":
    unittest.main()
