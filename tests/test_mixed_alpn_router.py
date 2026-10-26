#!/usr/bin/env python3
"""Ensure XHTTP with mixed ALPN maps TCP and UDP while dual QUIC fails closed."""
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
SYNC = (ROOT / "deploy/xmesh-xray-sync.sh").read_text(encoding="utf-8")
PYTHON = SYNC.split("PORTS=\"$(python3 - \"$CONFIG_FILE\" <<'PYPORTS'\n", 1)[1].split("\nPYPORTS\n", 1)[0]


class MixedALPNRouterTests(unittest.TestCase):
    def run_ports(self, inbounds, ok=True):
        with tempfile.TemporaryDirectory() as td:
            path = pathlib.Path(td) / "config.json"
            path.write_text(json.dumps({"inbounds": inbounds}), encoding="utf-8")
            result = subprocess.run([sys.executable, "-", str(path)],
                                    input=PYTHON, text=True, capture_output=True)
            self.assertEqual(result.returncode == 0, ok, result.stderr)
            return result.stdout.strip()

    def test_shell_syntax(self):
        result = subprocess.run(["bash", "-n", str(ROOT / "deploy/xmesh-xray-sync.sh")],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_mixed_xhttp_alpn_uses_both_transports_on_same_port(self):
        ib = {"tag": "vless", "protocol": "vless", "listen": "127.0.0.1",
              "port": 5000, "streamSettings": {"network": "xhttp", "security": "tls",
                                                "tlsSettings": {"alpn": ["h2", "h3"]}}}
        self.assertEqual(self.run_ports([ib]), "5000 5000")

    def test_tcp_and_hysteria_receive_separate_private_ports(self):
        vless = {"tag": "vless", "protocol": "vless", "listen": "127.0.0.1",
                 "port": 5000, "streamSettings": {"network": "xhttp",
                 "security": "tls", "tlsSettings": {"alpn": ["h2", "http/1.1"]}}}
        hysteria = {"tag": "hysteria", "protocol": "hysteria", "listen": "127.0.0.1",
                    "port": 5001, "streamSettings": {"network": "hysteria",
                    "security": "tls", "tlsSettings": {"alpn": ["h3"]}}}
        stats = {"tag": "xmesh_stats_in", "listen": "127.0.0.1", "port": 10085}
        self.assertEqual(self.run_ports([vless, hysteria, stats]), "5000 5001")
        self.assertEqual(self.run_ports([hysteria | {"port": 5000},
                                         vless | {"port": 5001}, stats]), "5001 5000")
        vless["streamSettings"]["tlsSettings"]["alpn"] = ["h2", "h3"]
        self.run_ports([vless, hysteria, stats], ok=False)

    def test_router_does_not_override_manual_routes(self):
        self.assertIn('action = "unmanaged"', SYNC)
        self.assertIn('if action == "unmanaged"', SYNC)
        self.assertIn('os.replace(tmp, router_path)', SYNC)
        self.assertIn('docker compose up -d --no-deps --force-recreate xmesh-node', SYNC)


if __name__ == "__main__":
    unittest.main()
