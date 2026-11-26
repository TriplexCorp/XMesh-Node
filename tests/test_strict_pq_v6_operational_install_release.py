#!/usr/bin/env python3
"""Source-only first-install strict-PQ control-v6.0.36 regression tests."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
CANONICAL = (ROOT / "AGENT_VERSION").read_text(encoding="utf-8").strip()


class FirstInstall(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.bootstrap = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
        cls.installer = (ROOT / "deploy/install-v6-strict-operational-agents.sh").read_text(encoding="utf-8")
        cls.xray = (ROOT / "deploy/xmesh-xray-update.py").read_text(encoding="utf-8")

    def test_fresh_version_and_zero_stale_recovery_gates(self):
        self.assertEqual(CANONICAL, "control-v6.0.36")
        for label, source in (("bootstrap", self.bootstrap),
                              ("installer", self.installer), ("Xray updater", self.xray)):
            with self.subTest(label=label):
                self.assertNotIn("control-v6.0.33", source)
                self.assertNotIn("control-v6.0.34", source)
                self.assertNotIn("control-v6.0.35", source)
                self.assertIn(CANONICAL, source)
        self.assertIn('AGENT_VERSION = "' + CANONICAL + '"', self.xray)

    def test_bootstrap_uses_exact_node_and_nexus_release_revisions(self):
        self.assertIn('NODE_RELEASE_SHA="$(git -C', self.bootstrap)
        self.assertIn('"$NODE_RELEASE_SHA" == "$RELEASE_REF"', self.bootstrap)
        self.assertIn('"$AGENT_VERSION" == ' + CANONICAL, self.bootstrap)
        self.assertIn('XMESH_NEXUS_RELEASE_REF:-', self.bootstrap)
        self.assertIn('xmesh_refuse_quota_cold_install', self.bootstrap)
        self.assertIn('"$AGENT_VERSION" == ' + CANONICAL + ' && ! "$NEXUS_REF"', self.installer)

    def test_recovery_and_release_upgrade_installed_for_current_version(self):
        source = self.installer
        self.assertIn(
            'if [[ "$AGENT_VERSION" == ' + CANONICAL
            + ' ]]; then\ncat > /etc/systemd/system/xmesh-pq-activation-recovery.service',
            source,
        )
        self.assertIn('ExecStart=/usr/local/bin/xmesh-agent-xspv2-product resume-activation', source)
        self.assertIn('systemctl enable xmesh-pq-activation-recovery.service', source)
        self.assertIn('Requires=xmesh-pq-activation-recovery.service', source)
        self.assertIn('xmesh-product-upgrade-coordinator.py --fresh initialize', source)
        self.assertIn('xmesh-product-release-update.timer', source)
        self.assertIn('grep -Fxq "AGENT_VERSION = \\"$AGENT_VERSION\\""', source)

    def test_new_tls_probe_is_installed_only_as_inert_root_command(self):
        source = self.installer
        self.assertIn(
            "quarantine_policy,genesis_reservation,public_tls_preflight,public_tls_cap_watch,public_tls_revocation_watch,first_cap_handoff",
            source,
        )
        self.assertIn(
            'ln -sfn "$WAL_ROOT/quota-v2-physical-stop/public_tls_preflight.py" '
            '/usr/local/sbin/xmesh-quota-public-tls-preflight',
            source,
        )
        self.assertNotIn("ExecStart=/usr/bin/python3 $modules/public_tls", source)
        self.assertNotIn("systemctl enable xmesh-quota-v2-public-tls", source)

    def test_bash_syntax(self):
        subprocess.run(
            ["bash", "-n", str(ROOT / "bootstrap.sh"),
             str(ROOT / "deploy/install-v6-strict-operational-agents.sh")],
            check=True, timeout=12,
        )


if __name__ == "__main__":
    unittest.main()
