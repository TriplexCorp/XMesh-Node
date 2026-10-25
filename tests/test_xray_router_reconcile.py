#!/usr/bin/env python3
"""Exercise the exact embedded TCP/UDP router reconciler (no Docker needed)."""
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
    def check_router(self, old="127.0.0.1:10443", new=5000,
                     previous=10443, previous_network="tcp", network="tcp",
                     routes=None, marker=None, udp_listener="", udp_backend="",
                     udp_marker=None):
        with tempfile.TemporaryDirectory() as td:
            directory = Path(td)
            router = directory / "config.json"
            previous_path = directory / "previous.json"
            tcp_marker = directory / "router-managed-port"
            udp_marker_path = directory / "router-managed-udp-port"
            flag_path = directory / "action"
            router.write_text(json.dumps({
                "default_tcp": old, "routes": routes if routes is not None else [],
                "listen_tcp": ":443", "listen_udp": udp_listener,
                "udp_backend": udp_backend, "node_id": 27
            }), encoding="utf-8")
            if previous is not None:
                previous_path.write_text(json.dumps({"inbounds": [{
                    "port": previous,
                    "protocol": "hysteria" if previous_network == "udp" else "vless"
                }]}), encoding="utf-8")
            if marker is not None:
                tcp_marker.write_text(str(marker), encoding="ascii")
            if udp_marker is not None:
                udp_marker_path.write_text(str(udp_marker), encoding="ascii")
            completed = subprocess.run(
                [sys.executable, "-", str(router), str(new), network,
                 str(previous_path), str(tcp_marker), str(udp_marker_path),
                 str(flag_path)],
                input=PYTHON, text=True, capture_output=True, check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            after = json.loads(router.read_text(encoding="utf-8"))
            return flag_path.read_text(encoding="ascii"), after

    def test_changed_prior_managed_tcp_port(self):
        action, result = self.check_router()
        self.assertEqual(action, "changed")
        self.assertEqual(result["default_tcp"], "127.0.0.1:5000")
        self.assertEqual(result["listen_udp"], "")

    def test_tcp_already_aligned(self):
        action, result = self.check_router(old="127.0.0.1:5000")
        self.assertEqual(action, "aligned")
        self.assertEqual(result["default_tcp"], "127.0.0.1:5000")

    def test_default_bootstrap_tcp_port(self):
        action, result = self.check_router(old="127.0.0.1:9443", previous=None)
        self.assertEqual(action, "changed")
        self.assertEqual(result["default_tcp"], "127.0.0.1:5000")

    def test_legacy_unowned_tcp_port(self):
        action, result = self.check_router(previous=None)
        self.assertEqual(action, "unmanaged")
        self.assertEqual(result["default_tcp"], "127.0.0.1:10443")

    def test_explicit_custom_tcp_routes(self):
        action, result = self.check_router(routes=[
            {"sni": "other.example.org", "backend": "127.0.0.1:8443"}
        ])
        self.assertEqual(action, "unmanaged")
        self.assertEqual(result["default_tcp"], "127.0.0.1:10443")

    def test_recorded_tcp_port_may_migrate(self):
        action, result = self.check_router(previous=None, marker=10443)
        self.assertEqual(action, "changed")
        self.assertEqual(result["default_tcp"], "127.0.0.1:5000")

    def test_unrelated_manual_tcp_default_preserved(self):
        action, result = self.check_router(old="127.0.0.1:12345", marker=10443)
        self.assertEqual(action, "unmanaged")
        self.assertEqual(result["default_tcp"], "127.0.0.1:12345")

    def test_hysteria_enables_public_udp_without_changing_tcp(self):
        action, result = self.check_router(
            old="127.0.0.1:5000", network="udp", previous_network="udp",
            previous=None)
        self.assertEqual(action, "changed")
        self.assertEqual(result["listen_udp"], ":443")
        self.assertEqual(result["udp_backend"], "127.0.0.1:5000")
        self.assertEqual(result["default_tcp"], "127.0.0.1:5000")

    def test_hysteria_already_aligned(self):
        action, result = self.check_router(
            old="127.0.0.1:5000", network="udp",
            udp_listener=":443", udp_backend="127.0.0.1:5000")
        self.assertEqual(action, "aligned")
        self.assertEqual(result["listen_udp"], ":443")

    def test_hysteria_updates_previous_managed_udp_port(self):
        action, result = self.check_router(
            network="udp", previous_network="udp", previous=10443,
            udp_listener=":443", udp_backend="127.0.0.1:10443")
        self.assertEqual(action, "changed")
        self.assertEqual(result["udp_backend"], "127.0.0.1:5000")

    def test_hysteria_updates_recorded_managed_udp_port(self):
        action, result = self.check_router(
            network="udp", previous=None, udp_marker=9444,
            udp_listener=":443", udp_backend="127.0.0.1:9444")
        self.assertEqual(action, "changed")
        self.assertEqual(result["udp_backend"], "127.0.0.1:5000")

    def test_custom_udp_backend_is_not_overwritten(self):
        action, result = self.check_router(
            network="udp", udp_listener=":443", udp_backend="127.0.0.1:9444")
        self.assertEqual(action, "unmanaged")
        self.assertEqual(result["udp_backend"], "127.0.0.1:9444")

    def test_hysteria_does_not_modify_custom_tcp_rules(self):
        routes = [{"sni": "example.org", "backend": "127.0.0.1:10443"}]
        action, result = self.check_router(network="udp", routes=routes)
        self.assertEqual(action, "changed")
        self.assertEqual(result["routes"], routes)

    def test_shell_integration_contract(self):
        self.assertIn("if ! reconcile_router_default;then", SOURCE)
        self.assertIn("docker compose up -d --no-deps --force-recreate xmesh-node", SOURCE)
        self.assertNotIn("docker compose restart xmesh-node", SOURCE)
        self.assertIn('XMesh desired-config returned HTTP $HTTP_STATUS', SOURCE)
        self.assertIn("router-managed-udp-port", SOURCE)
        self.assertIn('"$INBOUND_NETWORK" == udp', SOURCE)


if __name__ == "__main__":
    unittest.main()
