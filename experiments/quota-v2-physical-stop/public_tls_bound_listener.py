"""Dormant identity proof for an already-bound, not-yet-listening TCP FD.

A future supervisor may bind a signed privileged port, then give a
capless isolated child exactly that socket. This module only verifies an
existing descriptor. It never binds, listens, accepts, changes sysctls,
grants authority, launches Xray, or installs a service. A positive
authority gate and actual Xray inherited-listener support remain required.
"""
from dataclasses import dataclass
import errno
import ipaddress
import os
import socket
import stat
import struct

# Linux UAPI asm-generic/socket.h and linux/in.h.
SO_COOKIE = 57
SO_NETNS_COOKIE = 71
SO_BINDTODEVICE = 25
IP_FREEBIND = 15
IP_TRANSPARENT = 19


def _positive_u64(value):
    return type(value) is int and 0 < value < 2**64


def _endpoint(address, port):
    if (type(address) is not str or
            str(ipaddress.IPv4Address(address)) != address or
            type(port) is not int or not 1 <= port <= 65535):
        raise ValueError("canonical signed IPv4 TCP endpoint required")
    return address, port


@dataclass(frozen=True)
class BoundListenerIdentity:
    address: str
    port: int
    device: int
    inode: int
    cookie: int
    netns_cookie: int

    def __post_init__(self):
        _endpoint(self.address, self.port)
        if not all(_positive_u64(i) for i in (self.device, self.inode, self.cookie,
                                               self.netns_cookie)):
            raise ValueError("invalid immutable bound TCP socket identity")


def _cookie(sock, option):
    raw = sock.getsockopt(socket.SOL_SOCKET, option, 8)
    result, = struct.unpack("=Q", raw)
    if not _positive_u64(result):
        raise ValueError("missing kernel socket cookie")
    return result


def network_namespace_cookie(sock):
    """Read the kernel network namespace of a real, already-open socket."""
    if not isinstance(sock, socket.socket):
        raise ValueError("kernel socket required")
    return _cookie(sock, SO_NETNS_COOKIE)


def _inspect(sock, *, listening):
    if (os.geteuid() != 0 or type(listening) is not bool
            or not isinstance(sock, socket.socket)):
        raise ValueError("root and actual TCP socket required")
    fd = sock.fileno()
    before = os.fstat(fd)
    def valid_options():
        return (sock.getsockopt(socket.SOL_SOCKET, socket.SO_DOMAIN) == socket.AF_INET
                and sock.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) == socket.SOCK_STREAM
                and sock.getsockopt(socket.SOL_SOCKET, socket.SO_PROTOCOL) == socket.IPPROTO_TCP
                and sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT) == 0
                and sock.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR) == 0
                and not sock.getsockopt(socket.SOL_SOCKET, SO_BINDTODEVICE, 16).rstrip(b"\0")
                and sock.getsockopt(socket.IPPROTO_IP, IP_FREEBIND) == 0
                and sock.getsockopt(socket.IPPROTO_IP, IP_TRANSPARENT) == 0
                and sock.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == int(listening))

    if (not stat.S_ISSOCK(before.st_mode) or not valid_options()):
        raise ValueError("not an exclusive IPv4 TCP socket in the expected listen phase")
    # A connected stream cannot stand in for a bound or listening socket,
    # even when its local address and port happen to match.
    def unconnected():
        try:
            sock.getpeername()
        except OSError as exc:
            if exc.errno != errno.ENOTCONN:
                raise
        else:
            raise ValueError("connected stream is not the original listener")

    unconnected()
    address, port = _endpoint(*sock.getsockname())
    cookie = _cookie(sock, SO_COOKIE)
    netns = network_namespace_cookie(sock)
    after = os.fstat(fd)
    if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or cookie != _cookie(sock, SO_COOKIE)
            or netns != network_namespace_cookie(sock)
            or not valid_options()
            or sock.getsockname() != (address, port)):
        raise ValueError("bound socket changed during kernel proof")
    unconnected()
    return BoundListenerIdentity(address, port, before.st_dev, before.st_ino, cookie, netns)


def capture_bound(sock, address, port, intended_netns_cookie):
    """Pin the supervisor's exclusive bound *unlistening* socket.

    The exact address/port must come from the separately verified signed
    configuration and the expected namespace from an independent kernel
    reference. Keep the owner FD only until exact child inheritance is
    measured; RELEASE the owner copy BEFORE any listen gate. Keeping a
    copy while the child listens would defeat physical listener shutdown
    on independent child death. Use nonduplicating kernel readback after
    transfer; never retain or reopen a live listener in the supervisor.
    """
    endpoint = _endpoint(address, port)
    if not _positive_u64(intended_netns_cookie):
        raise ValueError("missing intended network namespace identity")
    if not isinstance(sock, socket.socket) or os.get_inheritable(sock.fileno()):
        raise ValueError("supervisor bound socket must be private CLOEXEC")
    current = _inspect(sock, listening=False)
    if (endpoint != (current.address, current.port)
            or intended_netns_cookie != current.netns_cookie):
        raise ValueError("bound socket differs from intended signed endpoint or network namespace")
    return current


def verify_bound_socket(sock, expected, *, listening):
    """Check the exact inherited socket before/after a future listen gate."""
    if type(expected) is not BoundListenerIdentity:
        raise ValueError("immutable bound socket token required")
    if _inspect(sock, listening=listening) != expected:
        raise ValueError("bound TCP socket differs from original kernel object")
    return None
