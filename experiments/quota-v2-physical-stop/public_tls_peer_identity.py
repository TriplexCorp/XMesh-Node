"""Dormant kernel peer identity for a future private-PID TLS child.

A PID from SO_PEERCRED is namespace-relative (zero for an ancestor peer
not visible to the child). A pidfs inode is instead a kernel process
object, not a numeric PID. Compare the live SO_PEERPIDFD object with an
immutable token captured by the supervisor while it holds the original
meter pidfd. Do not inherit a supervisor pidfd into the child, accept an
anonymous-inode fallback, trust UID alone, or send application bytes
until this check succeeds.

This module is NOT an ingress dialer, launcher, sandbox, or authority.
The existing Go production-role dialer remains unchanged.
"""
from dataclasses import dataclass
import ctypes
import os
import select
import socket
import struct

# Linux UAPI asm-generic/socket.h and linux/magic.h.
SO_PEERPIDFD = 77
PID_FS_MAGIC = 0x50494446


@dataclass(frozen=True)
class PidfdIdentity:
    device: int
    inode: int

    def __post_init__(self):
        if (type(self.device) is not int or type(self.inode) is not int
                or not 0 < self.device < 2**64 or not 0 < self.inode < 2**64):
            raise ValueError("invalid immutable meter pidfs identity")


def _filesystem_magic(fd):
    # A Linux struct statfs starts with a native long f_type; reserve
    # ample aligned storage for the complete libc structure rather than
    # assuming the remaining ABI layout. Only the magic is inspected.
    storage = (ctypes.c_long * 64)()
    libc = ctypes.CDLL(None, use_errno=True)
    libc.fstatfs.argtypes = [ctypes.c_int, ctypes.c_void_p]
    libc.fstatfs.restype = ctypes.c_int
    if libc.fstatfs(fd, ctypes.byref(storage)) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), "fstatfs meter pidfd")
    return storage[0]


def _still_live(fd):
    poll = select.poll()
    poll.register(fd, select.POLLIN | select.POLLHUP | select.POLLERR | select.POLLNVAL)
    if poll.poll(0):
        raise ValueError("original meter pidfd no longer live")


def _identity(fd):
    if type(fd) is not int or fd < 0 or os.get_inheritable(fd):
        raise ValueError("meter pidfd must be a private CLOEXEC descriptor")
    if _filesystem_magic(fd) != PID_FS_MAGIC:
        # Older kernels expose pidfds as indistinguishable anon_inode
        # objects. Their dev/inode cannot safely authenticate this peer.
        raise ValueError("distinct kernel pidfs meter identity required")
    _still_live(fd)
    before = os.fstat(fd)
    with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as handle:
        values = [line.split(":", 1)[1].strip() for line in handle
                  if line.startswith("Pid:")]
    if len(values) != 1 or not values[0].isdigit():
        raise ValueError("missing live namespace-relative pidfd identity")
    pid = int(values[0])
    after = os.fstat(fd)
    _still_live(fd)
    token = PidfdIdentity(before.st_dev, before.st_ino)
    if token != PidfdIdentity(after.st_dev, after.st_ino):
        raise ValueError("meter pidfd changed during kernel proof")
    return token, pid


def capture_original(pidfd, measured_pid):
    """Capture the actual original meter object in the measuring namespace.

    The supervisor must keep this same original live pidfd pinned until
    stop/reap, never pass it to the child, and bind the token into the
    immutable input bundle. This is a primitive, not that integration.
    """
    if os.geteuid() != 0 or type(measured_pid) is not int or measured_pid <= 1:
        raise ValueError("root and actual measured original meter PID required")
    token, actual = _identity(pidfd)
    if actual != measured_pid:
        raise ValueError("pidfd is not the measured original meter PID")
    return token


def verify_connected_peer(conn, expected):
    """Return None only for the exact live root Unix stream peer.

    The fresh kernel peer pidfd is private, checked, and always closed.
    No other peer PID, UID, FD, stale socket path, caller claim, or
    unsupported kernel is equivalent to the captured pidfs object.
    """
    if (os.geteuid() != 0 or type(expected) is not PidfdIdentity
            or not isinstance(conn, socket.socket) or conn.family != socket.AF_UNIX
            or conn.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_STREAM):
        raise ValueError("root Unix stream and immutable original meter token required")
    # Confirm a connected endpoint, not a listener or unbound socket.
    conn.getpeername()
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    peer_pid, uid, gid = struct.unpack("3i", raw)
    if peer_pid < 0 or uid != 0 or gid != 0:
        raise ValueError("foreign Unix meter credentials")
    # Linux returns a new CLOEXEC pidfd even when peer_pid is zero in the
    # caller's private PID namespace. Any unavailable API fails closed.
    fd = conn.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD)
    try:
        token, pid = _identity(fd)
        if token != expected or pid != peer_pid:
            raise ValueError("Unix peer is not the original pidfs meter object")
        if conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, len(raw)) != raw:
            raise ValueError("Unix peer credentials changed during proof")
        _still_live(fd)
    finally:
        os.close(fd)
    return None
