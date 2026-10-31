#!/usr/bin/env python3
"""Regression contract: an empty-panel v6 node stays safe while awaiting Xray profile."""
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SYNC = (ROOT / "deploy/xmesh-xray-sync.sh").read_text(encoding="utf-8")
BOOTSTRAP = (ROOT / "bootstrap.sh").read_text(encoding="utf-8")
OPERATIONAL = (ROOT / "deploy/install-v6-strict-operational-agents.sh").read_text(encoding="utf-8")


class PendingEnrollmentTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Exercise the real inlined pending-response parser, not a duplicate.
        match = re.search(
            r'if ! python3 - "\$RESP_FILE" "\$XMESH_NODE_ID" <<\x27PY\x27\n(.*?)\nPY',
            SYNC, re.DOTALL,
        )
        assert match, "Sync worker must validate pending responses"
        cls.parser_source = match.group(1)

    def parse(self, payload, node_id=1):
        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "response.json"
            path.write_text(
                json.dumps(payload) if not isinstance(payload, str) else payload,
                encoding="utf-8",
            )
            return subprocess.run(
                [sys.executable, "-", str(path), str(node_id)],
                input=self.parser_source,
                text=True,
                capture_output=True,
                check=False,
            ).returncode

    def test_matching_pending_response(self):
        self.assertEqual(self.parse({"status": "awaiting_profile", "nodeId": 1}), 0)

    def test_pending_response_rejects_wrong_node(self):
        self.assertNotEqual(self.parse({"status": "awaiting_profile", "nodeId": 2}), 0)

    def test_pending_response_rejects_policy_or_config(self):
        for key in ("policy", "config"):
            with self.subTest(key=key):
                self.assertNotEqual(
                    self.parse({"status": "awaiting_profile", "nodeId": 1, key: {}}), 0
                )

    def test_pending_response_rejects_invalid_types_and_states(self):
        for payload in (
            {"status": "ok", "nodeId": 1},
            {"status": "awaiting_profile", "nodeId": True},
            {"status": "awaiting_profile", "nodeId": "1"},
            {"status": "awaiting_profile", "nodeId": 1.0},
            [],
            "{broken-json",
        ):
            with self.subTest(payload=payload):
                self.assertNotEqual(self.parse(payload), 0)

    def test_sync_does_not_use_unsigned_placeholder_config(self):
        self.assertIn('if [[ "$HTTP_STATUS" == 202 ]]', SYNC)
        self.assertIn("docker inspect xmesh-managed-xray", SYNC)
        self.assertIn("docker update --restart=no xmesh-managed-xray", SYNC)
        self.assertIn('"$STATE/awaiting-profile"', SYNC)
        self.assertIn("No previously issued signed offline policy", SYNC)
        self.assertIn('rm -f "$STATE/awaiting-profile"', SYNC)

    def test_v6_bootstrap_uses_only_product_enrollment(self):
        self.assertNotIn('config={"panel_url":', BOOTSTRAP)
        self.assertNotIn('d.update(panel_url=', BOOTSTRAP)
        self.assertNotIn("install-node-metrics-agent.sh", BOOTSTRAP)
        self.assertNotIn("/api/v1/node/enroll", BOOTSTRAP)
        self.assertIn("install-xsp-v2-product-client.sh", BOOTSTRAP)
        self.assertIn('"$PRODUCT" bootstrap --panel "$PANEL" --node-id "$NODE" --token-file "$TOKEN_FILE"', BOOTSTRAP)
        self.assertIn("install-v6-strict-operational-agents.sh", BOOTSTRAP)

    def test_bootstrap_token_handling_is_secret_safe(self):
        self.assertIn("read -r -s TOKEN < /dev/tty", BOOTSTRAP)
        self.assertIn("chmod 0600 \"$TOKEN_FILE\"", BOOTSTRAP)
        self.assertIn("unset TOKEN", BOOTSTRAP)
        self.assertIn("shred -u \"$TOKEN_FILE\"", BOOTSTRAP)
        self.assertNotIn('echo "$TOKEN"', BOOTSTRAP)
        self.assertNotIn('cat "$TOKEN_FILE"', BOOTSTRAP)

    def test_profile_attestation_installed_before_first_sync(self):
        self.assertIn("xmesh-profile-attest.py", OPERATIONAL)
        self.assertIn('python3 -m py_compile "$ROOT/deploy/$helper"', OPERATIONAL)
        install_at = OPERATIONAL.index('install -o root -g root -m 0700 "$ROOT/deploy/$helper"')
        sync_at = OPERATIONAL.index("systemctl start xmesh-xray-sync.service")
        self.assertLess(install_at, sync_at)
        self.assertNotIn('profileCheck\": \"verified\"', BOOTSTRAP)

    def test_pending_profile_still_leaves_xray_stopped(self):
        # Pending is a valid control-plane state after PQ activation, but it is
        # never permission to fabricate/apply a placeholder Xray config.
        self.assertIn("No previously issued signed offline policy", SYNC)
        self.assertIn("docker stop -t 3 xmesh-managed-xray", SYNC)
        self.assertIn("OnUnitInactiveSec=20s", OPERATIONAL)
        self.assertIn("systemctl start xmesh-xray-sync.service", OPERATIONAL)


if __name__ == "__main__":
    unittest.main()
