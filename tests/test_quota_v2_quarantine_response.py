#!/usr/bin/env python3
"""Exercise the REAL desired-config shell quarantine parser without Docker.
An HTTP 200 quarantine document must never be accepted as active config.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT=Path(__file__).resolve().parents[1]/"deploy"/"xmesh-xray-sync.sh"
text=SCRIPT.read_text()
BEGIN="<<'PYQUARANTINE'\n"
END="\nPYQUARANTINE"
if text.count(BEGIN)!=1:
    raise RuntimeError("expected exactly one inline legacy Agent quarantine guard")
source=text.split(BEGIN,1)[1].split(END,1)[0]


class QuarantineDesiredPolicyGuard(unittest.TestCase):
    def probe(self,doc):
        with tempfile.TemporaryDirectory() as folder:
            f=Path(folder)/"desired.json"
            f.write_text(json.dumps(doc))
            return subprocess.run([sys.executable,"-c",source,str(f)],
                                  capture_output=True,check=False).returncode

    def test_explicit_quarantine_status_never_grants_http_200(self):
        self.assertEqual(self.probe({"status":"quarantined","config":{"inbounds":[]}}),0)

    def test_signed_policy_quarantine_is_denied_even_without_status(self):
        doc={"config":{"inbounds":[]},"policy":{
            "quotaV2Genesis":{"mode":"quarantined",
                 "authorizedBytes":0,"canStart":False}
        }}
        self.assertEqual(self.probe(doc),0)

    def test_explicit_false_public_ingress_always_denies(self):
        self.assertEqual(self.probe({"publicIngressAllowed":False,"config":{}}),0)

    def test_normal_desired_config_does_not_trigger_quarantine_guard(self):
        self.assertEqual(self.probe({"nodeId":8,"config":{"inbounds":[]},
                "policy":{"version":1}}),1)

    def test_malformed_body_reaches_normal_fail_closed_validation(self):
        self.assertEqual(self.probe([]),1)

    def test_signed_quarantine_marker_cannot_be_masked_by_normal_status(self):
        self.assertEqual(self.probe({"status":"ready","policy":{
            "quotaV2Genesis":{"mode":"quarantined"}}}),0)


if __name__=="__main__":
    unittest.main()
