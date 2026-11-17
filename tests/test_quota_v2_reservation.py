import copy
import importlib.util
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location("reservation_guard",ROOT/"deploy/xmesh-policy-guard-base.py")
guard=importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

def lease(ceiling=50,ack=0,revision=1):
    return {"epoch":"11111111-1111-4111-8111-111111111111",
            "meterEpoch":"22222222-2222-4222-8222-222222222222",
            "reservationId":"33333333-3333-4333-8333-333333333333",
            "revision":revision,"acknowledgedBytes":ack,"ceilingBytes":ceiling,
            "validUntilMs":10000}

class ReservationGuardTests(unittest.TestCase):
    def test_aggregate_usage_never_refills_local_ceiling(self):
        record={}
        user={"panelUsedBytes":0,"quotaReservation":lease()}
        self.assertIsNone(guard.enforce_quota_reservation(user,record,40,1000))
        user["panelUsedBytes"]=10
        self.assertIsNone(guard.enforce_quota_reservation(user,record,49,2000))
        self.assertEqual(guard.enforce_quota_reservation(user,record,50,2000),"quota")
        self.assertEqual(record["quotaReservation"]["ceilingBytes"],50)

    def test_ack_is_monotonic_and_does_not_allocate_bytes(self):
        record={}
        user={"quotaReservation":lease(50,40)}
        guard.enforce_quota_reservation(user,record,40,1000)
        self.assertEqual(guard.enforce_quota_reservation(user,record,50,2000),"quota")
        user["quotaReservation"]=lease(50,10,2)
        with self.assertRaises(ValueError):
            guard.enforce_quota_reservation(user,record,50,3000)

    def test_only_explicit_signed_ceiling_extension_replenishes(self):
        record={}
        user={"quotaReservation":lease()}
        guard.enforce_quota_reservation(user,record,50,1000)
        user["quotaReservation"]=lease(90,40,2)
        self.assertIsNone(guard.enforce_quota_reservation(user,record,50,2000))
        self.assertIsNone(guard.enforce_quota_reservation(user,record,89,2000))
        self.assertEqual(guard.enforce_quota_reservation(user,record,90,2000),"quota")

    def test_limited_without_offline_budget_enforces_v2_ceiling(self):
        uid = "550e8400-e29b-41d4-a716-446655440001"
        config = {"inbounds":[{"tag":"MAIN","protocol":"vless",
                   "settings":{"clients":[{"id":uid}]}}]}
        user = {"userId":1,"xrayId":uid,"expireAtMs":90000,
                "panelUsedBytes":0,"limitBytes":100,
                "offlineBudgetBytes":None,"quotaReservation":lease()}
        policy = {"version":2,"nodeId":1,"issuedAtMs":1000,
                  "validUntilMs":100000,"users":[user]}
        _, ledger, denied = guard.enforce(policy, copy.deepcopy(config), {},
                                          {"1":49}, "xray-a", False, 1000)
        self.assertNotIn(uid, denied)
        user["panelUsedBytes"] = 10
        policy["issuedAtMs"] = 2000
        _, ledger, denied = guard.enforce(policy, copy.deepcopy(config), ledger,
                                          {"1":50}, "xray-a", False, 2000)
        self.assertEqual(denied.get(uid), "quota")
        _, _, denied = guard.enforce(policy, copy.deepcopy(config), ledger,
                                    None, "xray-a", True, 3000)
        self.assertEqual(denied.get(uid), "unverified-traffic-counter")

    def test_waiting_subscription_can_bootstrap_online_only(self):
        uid = "550e8400-e29b-41d4-a716-446655440001"
        config = {"inbounds":[{"tag":"MAIN","protocol":"vless",
                   "settings":{"clients":[{"id":uid}]}}]}
        user = {"userId":1,"xrayId":uid,"expireAtMs":0,
                "panelUsedBytes":0,"limitBytes":1000000,
                "offlineBudgetBytes":0,"onHold":True,
                "quotaReservation":lease(ceiling=1000)}
        policy = {"version":2,"nodeId":1,"issuedAtMs":1000,
                  "validUntilMs":100000,"users":[user]}
        _, ledger, denied = guard.enforce(
            policy, copy.deepcopy(config), {}, {"1":0}, "xray-a", False, 1000)
        self.assertNotIn(uid, denied, denied)
        _, _, denied = guard.enforce(
            policy, copy.deepcopy(config), ledger, {"1":0}, "xray-a", True, 2000)
        self.assertEqual(denied.get(uid), "subscription-awaiting-first-connection")
        user["onHold"] = False
        policy["issuedAtMs"] = 3000
        _, _, denied = guard.enforce(
            policy, copy.deepcopy(config), ledger, {"1":1}, "xray-a", False, 3000)
        self.assertNotIn(uid, denied, denied)

    def test_v2_unlimited_global_still_enforces_node_offline_limit(self):
        uid = "550e8400-e29b-41d4-a716-446655440001"
        config = {"inbounds":[{"tag":"NODE-LTE","protocol":"vless",
                   "settings":{"clients":[{"id":uid}]}}]}
        user = {"userId":1,"xrayId":uid,"expireAtMs":90000,
                "panelUsedBytes":0,"limitBytes":0,
                "offlineBudgetBytes":5}
        policy = {"version":2,"nodeId":1,"issuedAtMs":1000,
                  "validUntilMs":100000,"users":[user]}
        _, ledger, denied = guard.enforce(
            policy, copy.deepcopy(config), {}, {"1":0}, "xray-a", False, 1000)
        self.assertNotIn(uid, denied)
        _, ledger, denied = guard.enforce(
            policy, copy.deepcopy(config), ledger, {"1":5}, "xray-a", True, 2000)
        self.assertEqual(denied.get(uid), "quota")
        # Another node's aggregate traffic must not renew this node's allowance.
        user["panelUsedBytes"] = 1000
        policy["issuedAtMs"] = 3000
        _, _, denied = guard.enforce(
            policy, copy.deepcopy(config), ledger, {"1":5}, "xray-a", False, 3000)
        # A signed increase in another node's aggregate usage is not grounds
        # to undo this node's prior locally enforced quota cutoff.
        self.assertEqual(denied.get(uid), "locally-revoked")

    def test_signed_ceiling_cannot_be_less_than_acknowledged_usage(self):
        invalid=lease(ceiling=40,ack=41)
        with self.assertRaises(ValueError):
            guard.enforce_quota_reservation({"quotaReservation":invalid},{},41,1000)

    def test_identity_revision_ack_and_lifetime_validation(self):
        for field,value in [("meterEpoch","bad"),("revision",True),
                            ("acknowledgedBytes",100),("ceilingBytes",-1)]:
            with self.subTest(field=field):
                user={"quotaReservation":lease()}
                user["quotaReservation"][field]=value
                with self.assertRaises(ValueError):
                    guard.enforce_quota_reservation(user,{},40,1000)
        self.assertEqual(guard.enforce_quota_reservation(
            {"quotaReservation":lease()}, {}, 0, 10000),"quota-reservation-expired")

if __name__=="__main__":
    unittest.main()
