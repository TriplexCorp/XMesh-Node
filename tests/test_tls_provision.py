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

    def test_deploy_hook_path_matches_operational_installer(self):
        installer = (ROOT / "deploy" / "install-v6-strict-operational-agents.sh").read_text()
        canonical = "/usr/local/libexec/xmesh-tls-renew-hook"
        self.assertEqual(str(tls.DEPLOY_HOOK), canonical)
        self.assertIn(
            'install -o root -g root -m 0700 "$ROOT/deploy/xmesh-tls-renew-hook.sh" '
            + canonical,
            installer,
        )
        self.assertNotIn("/usr/local/sbin/xmesh-tls-renew-hook", (ROOT / "deploy" / "xmesh-tls-provision.py").read_text())

    def test_certbot_mutable_state_stays_inside_reconciler_state_dir(self):
        source = (ROOT / "deploy" / "xmesh-tls-provision.py").read_text()
        installer = (ROOT / "deploy" / "install-v6-strict-operational-agents.sh").read_text()
        self.assertIn('certbot_work = STATE / "certbot-work"', source)
        self.assertIn('certbot_logs = STATE / "certbot-logs"', source)
        self.assertIn('"--work-dir", str(certbot_work), "--logs-dir", str(certbot_logs)', source)
        # Do not widen the systemd sandbox to generic host logging/work paths.
        self.assertNotIn("/var/log/letsencrypt", installer)
        self.assertNotIn("/var/lib/letsencrypt", installer)
        self.assertIn("/var/lib/xmesh-xray-sync", installer)
        self.assertIn("-/etc/letsencrypt", installer)


if __name__ == "__main__":
    unittest.main()
