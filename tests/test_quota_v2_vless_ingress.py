#!/usr/bin/env python3
"""Narrow fail-closed tests for experimental per-user VLESS ingress ownership.

No real traffic authorization occurs here: real Xray + WAL tests must prove
the dataplane separately. These fixtures prevent route publication defects
that previously escaped Node CI entirely.
"""
import copy
import os
from pathlib import Path
import socket
import stat
import subprocess
import struct
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments" / "quota-v2-physical-stop"))
import vless_ingress as ingress

RUNTIME_A = "a" * 64
RUNTIME_B = "b" * 64
USER = 941
NODE = 38
UUID_A = "11111111-1111-4111-8111-111111111111"
ACCOUNT = "22222222-2222-4222-8222-222222222222"
METER = "33333333-3333-4333-8333-333333333333"
RESERVATION = "44444444-4444-4444-8444-444444444444"


def signed_claims(runtime=RUNTIME_A):
    # This is a trusted CALLER fixture, NOT a forged cryptographic signature.
    # publish() is invoked only AFTER the independent Ed25519 cap installer.
    return {
        "schemaVersion": 1, "kind": "xmesh.quota-v2.xray-cap-admission",
        "nodeId": NODE, "userId": USER, "runtimeId": runtime,
        "accountEpoch": ACCOUNT, "meterEpoch": METER,
        "reservationId": RESERVATION,
        "aliasScopes": [
            {"email": f"xmesh-u{USER}--vless-cdn", "class": "cdn"},
            {"email": f"xmesh-u{USER}--vless-main", "class": "main"},
        ],
        "canSpend": True, "canStart": False, "canResume": False,
        "finalMeterVerified": False, "refundableBytes": 0,
        "validUntilMs": time.time_ns() // 1_000_000 + 120_000,
    }


def xray_profile():
    return {"inbounds": [
        {"tag": f"vless-{cls}", "listen": "127.0.0.1", "port": 20000+i,
         "protocol": "vless", "settings": {
             "decryption": "none",
             "clients": [
                 {"id": UUID_A, "email": f"xmesh-u{USER}--vless-{cls}"}
             ]
         }}
        for i, cls in enumerate(("cdn", "main"))
    ]}


class VlessIngressTests(unittest.TestCase):
    def test_frontend_requires_native_authenticated_vless_and_denies_fallback(self):
        out = ingress.frontend(xray_profile())
        self.assertEqual(out["outbounds"][0]["tag"], "deny")
        self.assertEqual(len(out["routing"]["rules"]), 2)
        self.assertEqual(out["routing"]["rules"][0], {
            "type": "field", "inboundTag": ["vless-cdn"],
            "user": [f"xmesh-u{USER}--vless-cdn"],
            "outboundTag": f"xmesh-u{USER}--vless-cdn",
        })
        for outbound in out["outbounds"][1:]:
            self.assertEqual(outbound["settings"]["vnext"][0]["address"],
                             "xmesh-meter.invalid")
        self.assertEqual(out["inbounds"], xray_profile()["inbounds"])

    def test_frontend_refuses_ambiguous_or_unmetered_roster(self):
        good = xray_profile()
        for mutate in [
            lambda p: p["inbounds"].append(copy.deepcopy(p["inbounds"][0])),
            lambda p: p["inbounds"][0].update(tag="unsupported"),
            lambda p: p["inbounds"][0].update(protocol="trojan"),
            lambda p: p["inbounds"][0].update(listen="0.0.0.0"),
            lambda p: p["inbounds"][0]["settings"].update(fallbacks=[{"dest": 80}]),
            lambda p: p["inbounds"][0]["settings"]["clients"][0].update(flow="xtls-rprx-vision"),
            lambda p: p["inbounds"][0]["settings"]["clients"].append(
                copy.deepcopy(p["inbounds"][0]["settings"]["clients"][0])),
            lambda p: p["inbounds"][0]["settings"]["clients"][0].update(
                email=f"xmesh-u{USER+1}--vless-main"),
        ]:
            with self.subTest(mutate=mutate):
                value = copy.deepcopy(good)
                mutate(value)
                with self.assertRaises((ValueError, TypeError, KeyError)):
                    ingress.frontend(value)

    def test_publish_requires_current_scoped_nonresumable_signed_grant(self):
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(
            os.environ, {"XMESH_QUOTA_V2_INGRESS_STAGING": "1"}
        ):
            fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, fd)
            measured = ("c" * 64, "2026-01-01T00:00:00Z", os.getpid(), RUNTIME_A)
            payload = signed_claims()
            for key, value in [
                ("kind", "other"), ("canSpend", False),
                ("canStart", True), ("canResume", True),
                ("finalMeterVerified", True), ("refundableBytes", 2),
                ("validUntilMs", 1), ("runtimeId", RUNTIME_B),
                ("aliasScopes", []), ("aliasScopes", payload["aliasScopes"][:1]*2),
                ("accountEpoch", METER[:-1]+"X"),
            ]:
                with self.subTest(key=key), self.assertRaises(ValueError):
                    ingress.publish(fd, dict(payload, **{key: value}), measured)
            self.assertEqual(os.listdir(folder), [])

    def test_publish_atomic_replay_and_no_foreign_runtime_switch(self):
        if os.name != "posix":
            self.skipTest("Linux process/Unix socket ownership")
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(
            os.environ, {"XMESH_QUOTA_V2_INGRESS_STAGING": "1"}
        ):
            fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, fd)
            measured_a = ("c"*64, "2026-01-01T00:00:00Z", os.getpid(), RUNTIME_A)
            measured_b = ("d"*64, "2026-01-02T00:00:00Z", os.getpid(), RUNTIME_B)
            a, b = str(Path(folder) / "xray-a"), str(Path(folder) / "xray-b")
            Path(a).mkdir(mode=0o700)
            Path(b).mkdir(mode=0o700)
            with (mock.patch.object(ingress, "target", side_effect=[a, b, b, b]),
                  mock.patch.object(ingress.wal_transport.runtime_identity,
                                    "trusted_runtime_identity",
                                    side_effect=lambda pid: RUNTIME_A if pid == measured_a[2] else None),
                  mock.patch.object(ingress.socket, "socket") as conn):
                peer = conn.return_value.__enter__.return_value
                peer.getsockopt.return_value = struct.pack(
                    "3i", os.getpid(), os.geteuid(), os.getegid())
                ingress.publish(fd, signed_claims(), measured_a)
                self.assertEqual(os.readlink(f"ingress-u{USER}", dir_fd=fd), a)
                self.assertEqual(conn.return_value.__enter__.call_count, 2)
                for call in peer.connect.call_args_list:
                    unix_path = call.args[0]
                    self.assertTrue(unix_path.startswith("/proc/self/fd/"))
                    self.assertLess(len(unix_path.encode()), 108)
                # Wrong predecessor route cannot replace an existing signed epoch.
                with self.assertRaisesRegex(ValueError, "predecessor"):
                    ingress.publish(fd, signed_claims(RUNTIME_B), measured_b)
                self.assertEqual(os.readlink(f"ingress-u{USER}", dir_fd=fd), a)
            self.assertEqual(sorted(os.listdir(folder)), sorted([
                f"ingress-u{USER}", "xray-a", "xray-b",
            ]))

    def test_three_calendar_routes_are_atomic_and_replay_safe(self):
        # 1 -> 2 -> 3 uses distinct measured Xray processes and signed
        # reservation epochs. An old receipt cannot roll back the route.
        with tempfile.TemporaryDirectory() as folder, mock.patch.dict(
            os.environ, {"XMESH_QUOTA_V2_INGRESS_STAGING": "1"}
        ):
            fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, fd)
            paths = []
            for index in range(3):
                path = str(Path(folder) / f"calendar-{index+1}")
                Path(path).mkdir(mode=0o700)
                paths.append(path)
            runtimes = ["a" * 64, "b" * 64, "c" * 64]
            pids = [os.getpid() + index for index in range(3)]
            measurements = [
                ("d" * 64, f"2026-11-{20+i:02d}T00:00:00Z",
                 pids[i], runtimes[i]) for i in range(3)
            ]
            claims = []
            for index, runtime in enumerate(runtimes):
                payload = signed_claims(runtime)
                payload["reservationId"] = f"44444444-4444-4444-8444-{index+1:012d}"
                claims.append(payload)
            with (mock.patch.object(ingress, "target",
                                    side_effect=lambda pid, runtime:
                                    paths[runtimes.index(runtime)]),
                  mock.patch.object(ingress.wal_transport.runtime_identity,
                                    "trusted_runtime_identity",
                                    side_effect=lambda pid: runtimes[pids.index(pid)]),
                  mock.patch.object(ingress.socket, "socket") as conn):
                peer = conn.return_value.__enter__.return_value
                peer.getsockopt.side_effect = lambda *_: struct.pack(
                    "3i", current_pid[0], os.geteuid(), os.getegid())
                current_pid = [pids[0]]
                ingress.publish(fd, claims[0], measurements[0])
                self.assertEqual(os.readlink(f"ingress-u{USER}", dir_fd=fd), paths[0])
                for index in (1, 2):
                    current_pid[0] = pids[index]
                    ingress.publish(fd, claims[index], measurements[index],
                                    ingress.target(*measurements[index-1][2:]))
                    self.assertEqual(os.readlink(f"ingress-u{USER}", dir_fd=fd),
                                     paths[index])
                with self.assertRaisesRegex(ValueError, "predecessor"):
                    current_pid[0] = pids[1]
                    ingress.publish(fd, claims[1], measurements[1], paths[0])
                self.assertEqual(os.readlink(f"ingress-u{USER}", dir_fd=fd), paths[2])
                current_pid[0] = pids[2]
                ingress.publish(fd, claims[2], measurements[2], paths[1])
                self.assertEqual(os.readlink(f"ingress-u{USER}", dir_fd=fd), paths[2])

    def test_unix_socket_checks_real_peer_pid_and_permissions(self):
        try:
            first = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        except PermissionError:
            if os.environ.get("XMESH_REQUIRE_REAL_UNIX") == "1":
                raise
            self.skipTest("local executor denies AF_UNIX")
        with (first, socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as second,
              tempfile.TemporaryDirectory() as tmp,
              mock.patch.dict(os.environ, {"XMESH_QUOTA_V2_INGRESS_STAGING": "1"}),
              mock.patch.object(ingress, "target", return_value=tmp)):
            self.assertEqual(stat.S_IMODE(os.stat(tmp).st_mode), 0o700)
            for listener, tag in ((first, "vless-cdn"), (second, "vless-main")):
                path = Path(tmp) / tag
                listener.bind(str(path))
                path.chmod(0o600)
                listener.listen(4)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

            identity = ingress.wal_transport.runtime_identity.trusted_runtime_identity
            fd = os.open(tmp, os.O_RDONLY | os.O_DIRECTORY)
            self.addCleanup(os.close, fd)
            with subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"]) as foreign:
                try:
                    foreign_runtime = identity(foreign.pid)
                    with self.assertRaisesRegex(ValueError, "different owner"):
                        ingress.publish(fd, signed_claims(foreign_runtime),
                                        ("c" * 64, "start", foreign.pid, foreign_runtime))
                    self.assertFalse(Path(tmp, f"ingress-u{USER}").is_symlink())
                finally:
                    foreign.terminate()
            runtime = identity(os.getpid())
            ingress.publish(fd, signed_claims(runtime), ("c" * 64, "start", os.getpid(), runtime))
            self.assertEqual(os.readlink(f"ingress-u{USER}", dir_fd=fd), tmp)

    def test_installed_staging_marker_requires_private_root_file(self):
        if os.geteuid() != 0:
            self.skipTest("staging marker must belong to real root")
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / "xmesh-quota-v2-staging"
            marker.write_text("disposable-staging-only\n")
            marker.chmod(0o600)
            with mock.patch.object(ingress, "STAGING_MARKER", str(marker)), \
                    mock.patch.dict(os.environ, {"GITHUB_ACTIONS": "false"}):
                self.assertTrue(ingress._staging_permitted())
                marker.chmod(0o644)
                self.assertFalse(ingress._staging_permitted())
                marker.chmod(0o600)
                marker.rename(Path(folder) / "saved")
                marker.symlink_to(Path(folder) / "saved")
                self.assertFalse(ingress._staging_permitted())
                marker.unlink()
                os.link(Path(folder) / "saved", marker)
                self.assertFalse(ingress._staging_permitted())

    def test_non_ci_frontend_must_not_spoof_github_runner(self):
        with mock.patch.dict(os.environ, {
                "XMESH_QUOTA_V2_INGRESS_STAGING":"1",
                "GITHUB_ACTIONS":"false"}):
            with self.assertRaisesRegex(ValueError, "production ingress"):
                ingress.serve("https://example.invalid", NODE,
                              "/nonexistent", "/nonexistent/xray")


if __name__ == "__main__":
    unittest.main()
