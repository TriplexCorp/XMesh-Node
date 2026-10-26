#!/usr/bin/env python3
"""Regression coverage for per-node managed TLS; no network calls are made."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("xmesh_tls", ROOT / "deploy" / "xmesh-tls-provision.py")
tls = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tls)


class ProvisionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.original_state = tls.STATE
        tls.STATE = self.root
        self.addCleanup(setattr, tls, "STATE", self.original_state)

    def run_case(self, policy, config):
        response = self.root / "response.json"
        target = self.root / "config.json"
        response.write_text(json.dumps({"policy": policy}))
        target.write_text(json.dumps(config))
        with mock.patch.object(sys, "argv", ["provision", str(response), str(target)]):
            return tls.main()

    def test_not_opted_in_never_requests_certificate(self):
        with mock.patch.object(tls.subprocess, "run", side_effect=AssertionError("must not run")):
            self.assertEqual(self.run_case({}, {"inbounds": []}), 0)

    def test_rejects_domain_path_mismatch_before_certbot(self):
        domain = "tenant.example.org"
        with mock.patch.object(tls.subprocess, "run", side_effect=AssertionError("must not run")):
            self.assertEqual(self.run_case(
                {"tlsProvision": {"domain": domain, "email": "ops@example.org",
                                  "provider": "letsencrypt-http01"}},
                {"inbounds": [{"streamSettings": {"security": "tls", "tlsSettings":
                    {"certificates": [{"certificateFile": "/etc/letsencrypt/live/other.example.org/fullchain.pem",
                                        "keyFile": "/etc/letsencrypt/live/other.example.org/privkey.pem"}]}}}]}
            ), 1)

    def test_rejects_untrusted_acme_domain(self):
        self.assertEqual(self.run_case(
            {"tlsProvision": {"domain": "../tenant", "email": "ops@example.org",
                              "provider": "letsencrypt-http01"}},
            {"inbounds": []}), 1)

    def test_missing_required_tls_inbound_fails_closed(self):
        self.assertEqual(self.run_case(
            {"tlsProvision": {"domain": "tenant.example.org", "email": "ops@example.org",
                              "provider": "letsencrypt-http01"}},
            {"inbounds": []}), 1)


if __name__ == "__main__":
    unittest.main()
