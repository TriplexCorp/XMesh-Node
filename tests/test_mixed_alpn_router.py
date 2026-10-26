#!/usr/bin/env python3
"""Ensure mixed XHTTP ALPN keeps both public forwarding families."""
import pathlib
import re
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SYNC = (ROOT / "deploy/xmesh-xray-sync.sh").read_text(encoding="utf-8")


class MixedALPNRouterTests(unittest.TestCase):
    def test_shell_syntax(self):
        result = subprocess.run(["bash", "-n", str(ROOT / "deploy/xmesh-xray-sync.sh")],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_mixed_alpn_detection(self):
        self.assertIn('"h3" in alpn', SYNC)
        self.assertIn('print("both" if quic and tcp else "udp" if quic else "tcp")', SYNC)
        self.assertIn('if network in ("tcp", "both"):', SYNC)
        self.assertIn('if network in ("udp", "both"):', SYNC)
        self.assertIn('if [[ "$INBOUND_NETWORK" == udp || "$INBOUND_NETWORK" == both ]]', SYNC)
        self.assertIn('if [[ "$INBOUND_NETWORK" == tcp || "$INBOUND_NETWORK" == both ]]', SYNC)
        self.assertIn('if old_quic:', SYNC)
        self.assertIn('if old_tcp or not old_quic:', SYNC)

    def test_reconciler_keeps_unmanaged_routes_protected(self):
        self.assertIn('action = "unmanaged"', SYNC)
        self.assertIn('if action == "unmanaged"', SYNC)
        self.assertIn('os.replace(tmp, router_path)', SYNC)
        self.assertIn('docker compose up -d --no-deps --force-recreate xmesh-node', SYNC)


if __name__ == "__main__":
    unittest.main()
