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
