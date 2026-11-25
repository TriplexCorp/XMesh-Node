#!/usr/bin/env python3
"""No production egress or signed cap is created by these tests."""
import asyncio
import ipaddress
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] /
                       "experiments/quota-v2-physical-stop"))
import metered_tcp_egress as egress


class TargetTests(unittest.TestCase):
    @unittest.skipUnless(os.geteuid() == 0, "root-owned socket")
    def test_installed_egress_socket_requires_exact_private_owner_and_mode(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            root.chmod(0o700)
            path = root / "egress.sock"
            with mock.patch.object(egress, "BRIDGE_DIR", root), \
                 mock.patch.object(egress, "SOCKET", path):
                with self.assertRaises(FileNotFoundError):
                    egress.require_socket()
                with socket.socket(socket.AF_UNIX) as listener:
                    listener.bind(str(path))
                    path.chmod(0o600)
                    egress.require_socket()
                    path.chmod(0o666)
                    with self.assertRaises(ValueError):
                        egress.require_socket()
                    path.chmod(0o600)
                    root.chmod(0o755)
                    with self.assertRaises(ValueError):
                        egress.require_socket()
                    root.chmod(0o700)

    def test_public_destinations_and_dns_are_explicit(self):
        self.assertEqual(egress.parse_target(b"EXAMPLE.COM", 443),
                         ("example.com", 443))
        self.assertEqual(egress.parse_target(b"1.1.1.1", 443),
                         ("1.1.1.1", 443))
        for host in (b"127.0.0.1", b"10.0.0.1", b"169.254.169.254",
                     b"::1", b"fe80::1", b"0.0.0.0", b"localhost",
                     b"internal", b"12345678", b"example..com",
                     b"127.1", b"test.local", b"one\x00two",
                     b"example.com\n", b"a/b", b"8.8.8.8%eth0"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                egress.parse_target(host, 443)
        for port in (0, -1, 65536, True, "443"):
            with self.subTest(port=port), self.assertRaises(ValueError):
                egress.parse_target(b"example.com", port)

    def test_dns_results_cannot_rebind_to_private_address(self):
        async def check():
            with mock.patch.object(asyncio.get_running_loop(), "getaddrinfo",
                    return_value=[(socket.AF_INET, 0, 0, "", ("10.1.1.1", 443)),
                                  (socket.AF_INET, 0, 0, "", ("93.184.215.14", 443))]):
                result = [address async for address in
                          egress.public_tcp_addresses("example.com", 443)]
                self.assertEqual(result, [(socket.AF_INET, "93.184.215.14")])
        asyncio.run(check())


class ProtocolTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addAsyncCleanup(asyncio.to_thread, self.folder.cleanup)
        self.path = str(Path(self.folder.name) / "bridge.sock")
        self.capacity = asyncio.Semaphore(4)
        self.server = await asyncio.start_unix_server(
            lambda r, w: egress.bridge(r, w, self.capacity), path=self.path)
        self.addAsyncCleanup(self.stop_server)

    async def stop_server(self):
        self.server.close()
        await self.server.wait_closed()

    async def request(self, host=b"example.com", port=443, *, magic=b"XME1"):
        reader, writer = await asyncio.open_unix_connection(self.path)
        self.addAsyncCleanup(self.close_writer, writer)
        writer.write(egress.HEADER.pack(magic, len(host), port) + host)
        await writer.drain()
        return reader, writer

    @staticmethod
    async def close_writer(writer):
        writer.close()
        await writer.wait_closed()

    async def test_rejects_unqualified_meter_before_connect(self):
        with mock.patch.object(egress, "require_qualified_peer",
                               side_effect=ValueError("not a meter")):
            reader, _ = await self.request()
            self.assertEqual(await reader.readexactly(1), b"\x01")

    async def test_valid_peer_has_bounded_frame_and_public_dns(self):
        with mock.patch.object(egress, "require_qualified_peer"):
            async def echo(reader, writer):
                try:
                    writer.write(await reader.readexactly(4))
                    await writer.drain()
                finally:
                    writer.close()
            server = await asyncio.start_server(echo, "127.0.0.1", 0)
            self.addAsyncCleanup(self.stop_local_server, server)
            port = server.sockets[0].getsockname()[1]
            # The resolver is injected solely in this unit test. Production
            # public_tcp_addresses categorically denies host-local IPs.
            async def resolve(name, _):
                yield socket.AF_INET, "127.0.0.1"
            with mock.patch.object(egress, "public_tcp_addresses", resolve):
                reader, writer = await self.request(port=port)
                # Host-side postconnect public check correctly refuses even
                # a test resolver that tries to smuggle a loopback endpoint.
                self.assertEqual(await reader.readexactly(1), b"\x01")

    @staticmethod
    async def stop_local_server(server):
        server.close()
        await server.wait_closed()


if __name__ == "__main__":
    unittest.main()
