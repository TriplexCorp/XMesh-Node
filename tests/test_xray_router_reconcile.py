#!/usr/bin/env python3
"""Regression tests for the router-default migration embedded in xmesh-xray-sync."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "deploy" / "xmesh-xray-sync.sh"
SOURCE = SCRIPT.read_text(encoding="utf-8")
BEGIN = " # BEGIN ROUTER_PORT_RECONCILER\n"
END = "\nPY\n then\n"
assert SOURCE.count(BEGIN) == 1, "router snippet marker changed"
PYTHON = SOURCE.split(BEGIN, 1)[1].split(END, 1)[0].split("<<'PY'\n", 1)[1]


class RouterReconcileTests(unittest.TestCase):
    def check_router(self, old, new=5000, previous=10443, routes=None, marker=None):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            router = directory / "config.json"
            previous_path = directory / "previous.json"
            marker_path = directory / "router-managed-port"
            flag_path = directory / "action"
            router.write_text(json.dumps({
                "default_tcp": old, "routes": routes if routes is not None else [],
                "listen_tcp": ":443", "node_id": 27
            }), encoding="utf-8")
            if previous is not None:
                previous_path.write_text(json.dumps({
                    "inbounds": [{"port": previous}]
                }), encoding="utf-8")
            if marker is not None:
                marker_path.write_text(str(marker), encoding="ascii")
            completed = subprocess.run(
                [sys.executable, "-", str(router), str(new),
                 str(previous_path), str(marker_path), str(flag_path)],
                input=PYTHON, text=True, capture_output=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            after = json.loads(router.read_text(encoding="utf-8"))
            return flag_path.read_text(encoding="ascii"), after

    def test_changed_prior_managed_port_10443_to_5000(self):
        action, result = self.check_router("127.0.0.1:10443")
        self.assertEqual(action, "changed")
        self.assertEqual(result["default_tcp"], "127.0.0.1:5000")
        self.assertEqual(result["listen_tcp"], ":443")
        self.assertEqual(result["node_id"], 27)

    def test_already_aligned(self):
        action, result = self.check_router("127.0.0.1:5000")
        self.assertEqual(action, "aligned")
        self.assertEqual(result["default_tcp"], "127.0.0.1:5000")

    def test_default_bootstrap_port(self):
        action, result = self.check_router("127.0.0.1:9443", previous=None)
        self.assertEqual(action, "changed")
        self.assertEqual(result["default_tcp"], "127.0.0.1:5000")

    def test_legacy_unowned_port_must_not_be_overwritten(self):
        action, result = self.check_router("127.0.0.1:10443", previous=None)
        self.assertEqual(action, "unmanaged")
        self.assertEqual(result["default_tcp"], "127.0.0.1:10443")

    def test_explicit_custom_routes_never_overwritten(self):
        action, result = self.check_router(
            "127.0.0.1:10443", routes=[
                {"sni": "other.example.org", "backend": "127.0.0.1:8443"}
            ]
        )
        self.assertEqual(action, "unmanaged")
        self.assertEqual(result["default_tcp"], "127.0.0.1:10443")
        self.assertEqual(len(result["routes"]), 1)

    def test_recorded_managed_port_may_migrate(self):
        action, result = self.check_router(
            "127.0.0.1:10443", previous=None, marker=10443
        )
        self.assertEqual(action, "changed")
        self.assertEqual(result["default_tcp"], "127.0.0.1:5000")

    def test_unrelated_manual_default_preserved(self):
        action, result = self.check_router(
            "127.0.0.1:12345", previous=10443, marker=10443
        )
        self.assertEqual(action, "unmanaged")
        self.assertEqual(result["default_tcp"], "127.0.0.1:12345")

    def test_shell_integration_contract(self):
        self.assertIn("if ! reconcile_router_default;then", SOURCE)
        self.assertIn("docker compose up -d --no-deps --force-recreate xmesh-node", SOURCE)
        self.assertNotIn("docker compose restart xmesh-node", SOURCE)
        self.assertIn('XMesh desired-config returned HTTP $HTTP_STATUS', SOURCE)
        unchanged = SOURCE.index('echo "Xray configuration unchanged, container healthy, router reconciled."')
        self.assertLess(SOURCE.index("if ! reconcile_router_default;then"), unchanged)


if __name__ == "__main__":
    unittest.main()
