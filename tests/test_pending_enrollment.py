#!/usr/bin/env python3
"""Regression contract: connecting an empty-panel node must not require Xray."""
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

    def test_managed_bootstrap_does_not_register_duplicate_router_heartbeat(self):
        self.assertNotIn('config={"panel_url":', BOOTSTRAP)
        self.assertNotIn('d.update(panel_url=', BOOTSTRAP)
        self.assertIn('for legacy in ("panel_url", "node_id", "private_key_file"):', BOOTSTRAP)
        self.assertIn("xmesh-node-control", BOOTSTRAP)

    def test_bootstrap_reports_pending_as_success(self):
        self.assertIn("OnUnitInactiveSec=60s", BOOTSTRAP)
        self.assertIn("No XRAY STUDIO profile assigned yet (normal on a fresh panel)", BOOTSTRAP)
        self.assertIn("if systemctl start xmesh-xray-sync.service; then", BOOTSTRAP)


if __name__ == "__main__":
    unittest.main()
