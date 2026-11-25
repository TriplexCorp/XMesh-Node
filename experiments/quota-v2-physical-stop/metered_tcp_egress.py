#!/usr/bin/env python3
"""Root-only outbound TCP bridge for the qualified, network-isolated Xray.

Wire protocol: XME1, uint16 host length, uint16 port, ASCII destination.
Response: 0 (success), family (4 or 6), 16 IP bytes, uint16 port; 1 (deny).
The host NEVER accepts an arbitrary Docker name, user-controlled socket
or IP from the peer as evidence of an authorized meter.
"""
import argparse
import asyncio
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import socket
import stat
import struct
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import qualified_runtime_image as release
import wal_transport

BRIDGE_DIR = Path("/run/xmesh-quota-egress")
SOCKET = BRIDGE_DIR / "egress.sock"
HEADER = struct.Struct("!4sHH")
PEER = struct.Struct("3i")
DOMAIN = re.compile(r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.?\Z")
MAX_PEERS = 128


def parse_target(raw, port):
    if type(port) is not int or not 1 <= port <= 65535 or not 1 <= len(raw) <= 253:
        raise ValueError("invalid outbound TCP endpoint")
    name = raw.decode("ascii")
    if name != name.strip() or "\x00" in name or "%" in name:
        raise ValueError("invalid outbound endpoint syntax")
    try:
        parsed = ipaddress.ip_address(name)
    except ValueError:
        parsed = None
    if parsed is not None:
        if not parsed.is_global:
            raise ValueError("private, special or local TCP destination denied")
        return str(parsed), port
    if not DOMAIN.fullmatch(name) or name.endswith(".."):
        raise ValueError("invalid outbound hostname")
    # Literal IP address representations must never fall through to a resolver
    # under a different spelling (octal, integer IP, IPv6 zone ID, etc).
    if name.rstrip(".").replace(".", "").isdigit():
        raise ValueError("ambiguous numeric hostname denied")
    return name.lower().rstrip("."), port


async def public_tcp_addresses(name, port):
    loop = asyncio.get_running_loop()
    try:
        ip = ipaddress.ip_address(name)
    except ValueError:
        entries = await asyncio.wait_for(loop.getaddrinfo(
            name, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP), 8)
        resolved = [(family, item[4][0]) for item in entries
                    for family in [item[0]] if family in (socket.AF_INET, socket.AF_INET6)]
    else:
        resolved = [(socket.AF_INET6 if ip.version == 6 else socket.AF_INET, str(ip))]
    unique = set()
    for family, address in resolved:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            continue
        if ip.is_global and (family, str(ip)) not in unique:
            unique.add((family, str(ip)))
            yield family, str(ip)
    if not unique:
        raise ValueError("no eligible public TCP address")


def require_qualified_peer(pid):
    if type(pid) is not int or pid <= 1 or os.geteuid() != 0:
        raise ValueError("untrusted metered Xray peer PID")
    # A Docker name is not identity. Validate live container, PID, start time,
    # read-only qualification, pinned executable/config and namespace at once.
    record = release.read_identity(release.QUALIFICATION)
    config = Path("/var/lib/xmesh-first-meter/config.json")
    fd = os.open(config, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or not 0 < info.st_size <= 2 << 20):
            raise ValueError("untrusted original signed Xray config")
        digest = hashlib.file_digest(source, "sha256").hexdigest()
    # The first generation is named exactly, subsequent generations are
    # restricted to runtime_identity's canonical per-user reservation names.
    candidates = ["xmesh-managed-xray"]
    try:
        import subprocess
        raw = subprocess.check_output(
            ["docker", "ps", "--filter", "name=^/xmesh-quota-u", "--format", "{{.Names}}"],
            timeout=4,
        )
        if len(raw) > 16384:
            raise ValueError("too many metering peers")
        candidates += raw.decode("ascii").splitlines()
    except (OSError, subprocess.SubprocessError, UnicodeDecodeError) as exc:
        raise ValueError("unable to inspect current metering generations") from exc
    for name in candidates:
        if not wal_transport.runtime_identity.managed_container_name(name):
            raise ValueError("untrusted managed container name")
        try:
            cid, started, running_pid, runtime = wal_transport._measure_quarantined_runtime(
                (record["artifactSha256"], digest), container_name=name)
        except (ValueError, OSError, subprocess.SubprocessError):
            continue
        if running_pid == pid and runtime:
            return
    raise ValueError("egress peer is not a live qualified metering process")


async def transfer(reader, writer):
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        if writer.can_write_eof():
            try:
                writer.write_eof()
            except OSError:
                pass


async def bridge(reader, writer, capacity):
    remote_writer = None
    try:
        if capacity.locked():
            raise ValueError("egress connection limit reached")
        async with capacity:
            peer = writer.get_extra_info("socket").getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, PEER.size)
            pid, uid, _ = PEER.unpack(peer)
            if uid != 0:
                raise ValueError("non-root outbound meter denied")
            await asyncio.wait_for(
                asyncio.to_thread(require_qualified_peer, pid), 20)
            magic, size, port = HEADER.unpack(
                await asyncio.wait_for(reader.readexactly(HEADER.size), 5))
            if magic != b"XME1" or not 1 <= size <= 253:
                raise ValueError("invalid metered egress frame")
            name, port = parse_target(
                await asyncio.wait_for(reader.readexactly(size), 5), port)
            errors = []
            async for family, address in public_tcp_addresses(name, port):
                try:
                    remote_reader, remote_writer = await asyncio.wait_for(
                        asyncio.open_connection(address, port, family=family), 8)
                    break
                except (TimeoutError, OSError) as exc:
                    errors.append(type(exc).__name__)
            if remote_writer is None:
                raise ValueError("public TCP dial unavailable")
            peer_address = remote_writer.get_extra_info("peername")
            ip = ipaddress.ip_address(peer_address[0])
            if not ip.is_global:
                raise ValueError("connected socket changed to private endpoint")
            address = ip.packed + (b"\x00" * (16 - len(ip.packed)))
            writer.write(b"\x00" + bytes([ip.version]) + address +
                         struct.pack("!H", peer_address[1]))
            await writer.drain()
            await asyncio.gather(transfer(reader, remote_writer),
                                 transfer(remote_reader, writer))
    except (ValueError, UnicodeError, OSError, EOFError, asyncio.TimeoutError,
            asyncio.IncompleteReadError):
        if remote_writer is None:
            try:
                writer.write(b"\x01")
                await writer.drain()
            except (ConnectionError, OSError):
                pass
    finally:
        if remote_writer is not None:
            remote_writer.close()
            await remote_writer.wait_closed()
        writer.close()
        await writer.wait_closed()


def private_directory(path):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_uid != 0):
        raise ValueError("egress socket parent is not root-only")


async def serve(path=SOCKET):
    if os.geteuid() != 0:
        raise ValueError("egress bridge requires root")
    path = Path(path)
    private_directory(path.parent)
    if path.exists() or path.is_symlink():
        raise ValueError("existing egress socket requires explicit recovery")
    capacity = asyncio.Semaphore(MAX_PEERS)
    server = await asyncio.start_unix_server(
        lambda r, w: bridge(r, w, capacity), path=str(path), backlog=128)
    try:
        os.chmod(path, 0o600)
        info = path.lstat()
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600):
            raise ValueError("untrusted metered egress socket")
        async with server:
            await server.serve_forever()
    finally:
        server.close()
        await server.wait_closed()
        # Never remove a replaced socket path.
        info = path.lstat() if path.exists() else None
        if info and stat.S_ISSOCK(info.st_mode) and info.st_uid == 0:
            path.unlink()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--socket", default=str(SOCKET))
    args = parser.parse_args()
    if args.socket != str(SOCKET):
        raise SystemExit("only the private installed egress socket is permitted")
    asyncio.run(serve())
