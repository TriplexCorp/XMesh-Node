"""Dormant non-duplicating TCP listener readback for the future stop chain.

Holding the owner's FD after listen would retain the TCP listener even
if an independent deadman killed its namespace-PID1 child. Read actual
procfs and INET_DIAG state instead; never pidfd_getfd or reopen the socket.
This module never binds, transfers, listens, kills or authorizes traffic.
"""
import os
import socket
import stat
import struct
import subprocess
import time

import public_tls_bound_listener as bound
import public_tls_child_inputs as child_inputs

NETLINK_SOCK_DIAG = 4
SOCK_DIAG_BY_FAMILY = 20
NLMSG_ERROR = 2
NLMSG_DONE = 3
NLM_F_REQUEST = 1
NLM_F_DUMP = 0x300
NLM_F_DUMP_INTR = 0x10
TCP_LISTEN = 10
HEADER = struct.Struct("=IHHII")
MAX_READBACK_NS = 2_000_000_000
MAX_NETLINK_BYTES = 1 << 20
MAX_FDS = 16384


def verify_child_fd(child, fd, token):
    """Verify actual owned child's exact inherited socket without opening it."""
    if (os.geteuid() != 0 or not isinstance(child, subprocess.Popen)
            or type(fd) is not int or fd < 3
            or type(token) is not bound.BoundListenerIdentity):
        raise ValueError("owned child and immutable listener token required")
    started = time.monotonic_ns()
    pidfd = os.pidfd_open(child.pid)
    try:
        birth = child_inputs._alive(child, pidfd)
        name = f"/proc/{child.pid}/fd/{fd}"
        for _ in range(2):
            actual = os.stat(name)
            if (not stat.S_ISSOCK(actual.st_mode)
                    or (actual.st_dev, actual.st_ino) != (token.device, token.inode)
                    or os.readlink(name) != f"socket:[{token.inode}]"):
                raise ValueError("child did not inherit exact original bound socket")
        if (child_inputs._alive(child, pidfd) != birth
                or not 0 <= time.monotonic_ns() - started < MAX_READBACK_NS):
            raise ValueError("owned TLS listener changed birth")
    finally:
        os.close(pidfd)
    return None


def require_no_copy(pid, token):
    """Require an actual supervisor/guardian FD inventory without this socket."""
    if (os.geteuid() != 0 or type(pid) is not int or pid <= 0
            or type(token) is not bound.BoundListenerIdentity):
        raise ValueError("actual process and immutable listener token required")
    started = time.monotonic_ns()
    proc = f"/proc/{pid}/fd"
    with os.scandir(proc) as descriptors:
        for index, entry in enumerate(descriptors, 1):
            if (index > MAX_FDS or not entry.name.isascii() or not entry.name.isdecimal()
                    or not 0 <= time.monotonic_ns() - started < MAX_READBACK_NS):
                raise ValueError("listener owner FD inventory exceeded bound")
            try:
                info = os.stat(entry.path)
            except FileNotFoundError:
                continue
            if (info.st_dev, info.st_ino) == (token.device, token.inode):
                raise ValueError("supervisor or guardian retains original listening socket copy")
    if not 0 <= time.monotonic_ns() - started < MAX_READBACK_NS:
        raise ValueError("listener owner FD inventory exceeded time budget")
    return None


def _messages(raw, seq):
    offset = 0
    while offset < len(raw):
        if len(raw) - offset < HEADER.size:
            raise ValueError("truncated socket diagnostic netlink header")
        size, kind, flags, returned_seq, _ = HEADER.unpack_from(raw, offset)
        if (size < HEADER.size or size > len(raw) - offset
                or returned_seq != seq or flags & NLM_F_DUMP_INTR):
            raise ValueError("invalid or interrupted socket diagnostic dump")
        yield kind, raw[offset + HEADER.size:offset + size]
        offset += (size + 3) & ~3
    if offset != len(raw):
        raise ValueError("unaligned socket diagnostic netlink message")


def _record(payload):
    # Linux inet_diag_msg (72 fixed bytes), carrying inet_diag_sockid.
    # Ports/addresses are network byte order; cookies and inode native UAPI.
    if len(payload) < 72 or payload[0] != socket.AF_INET or payload[1] != TCP_LISTEN:
        raise ValueError("unexpected socket diagnostic family/state")
    port, destination_port = struct.unpack_from("!HH", payload, 4)
    address = socket.inet_ntoa(payload[8:12])
    if destination_port or any(payload[12:40]):
        raise ValueError("connected or noncanonical IPv4 listener diagnostic")
    low, high = struct.unpack_from("=II", payload, 44)
    uid, inode = struct.unpack_from("=II", payload, 64)
    return address, port, uid, inode, low | (high << 32)


def _listener_records(token, deadline):
    # Check the supervisor's actual current network namespace against the
    # original socket; this new unbound reference cannot retain a listener.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reference:
        if bound.network_namespace_cookie(reference) != token.netns_cookie:
            raise ValueError("diagnostic outside original socket network namespace")
    seq = 1
    # inet_diag_req_v2: family, protocol, ext, pad, state bitmap, sockid.
    # Filter by local port; no cookie wildcard substitution in readback.
    sockid = (struct.pack("!HH", token.port, 0) + bytes(32)
              + struct.pack("=III", 0, 0xFFFFFFFF, 0xFFFFFFFF))
    request = struct.pack("=BBBBI", socket.AF_INET, socket.IPPROTO_TCP, 0, 0,
                          1 << TCP_LISTEN) + sockid
    message = HEADER.pack(HEADER.size + len(request), SOCK_DIAG_BY_FAMILY,
                          NLM_F_REQUEST | NLM_F_DUMP, seq, 0) + request
    records = []
    total = 0
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_SOCK_DIAG) as diagnostic:
        diagnostic.bind((0, 0))
        diagnostic.settimeout(1)
        if diagnostic.sendto(message, (0, 0)) != len(message):
            raise ValueError("short socket diagnostic request")
        while True:
            deadline()
            raw, ancillary, flags, source = diagnostic.recvmsg(65536)
            total += len(raw)
            if (not raw or total > MAX_NETLINK_BYTES or ancillary or source != (0, 0)
                    or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)):
                raise ValueError("foreign, truncated or excessive socket diagnostic dump")
            done = False
            for kind, payload in _messages(raw, seq):
                if done:
                    raise ValueError("records after socket diagnostic completion")
                if kind == NLMSG_DONE:
                    if payload not in (b"", bytes(4)):
                        raise ValueError("unsuccessful socket diagnostic completion")
                    done = True
                elif kind == NLMSG_ERROR:
                    raise ValueError("kernel socket diagnostic rejected request")
                elif kind == SOCK_DIAG_BY_FAMILY:
                    records.append(_record(payload))
                else:
                    raise ValueError("unexpected socket diagnostic response")
            if done:
                deadline()
                return records


def verify_listen_state(token, *, listening):
    """Verify exact listener inode/cookie via kernel without a duplicate FD."""
    if (os.geteuid() != 0 or type(token) is not bound.BoundListenerIdentity
            or type(listening) is not bool or token.inode > 0xFFFFFFFF):
        raise ValueError("representable actual Linux listener token required")
    started = time.monotonic_ns()

    def deadline():
        if not 0 <= time.monotonic_ns() - started < MAX_READBACK_NS:
            raise ValueError("socket diagnostic exceeded readback time budget")

    records = _listener_records(token, deadline)
    matches = [(address, port, uid, inode, cookie)
               for address, port, uid, inode, cookie in records
               if port == token.port and (address == token.address
                                           or address == "0.0.0.0"
                                           or token.address == "0.0.0.0")]
    expected = [(token.address, token.port, 0, token.inode, token.cookie)] if listening else []
    if matches != expected:
        raise ValueError("original TCP listener kernel state does not match expected phase")
    return None
