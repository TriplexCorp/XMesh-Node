"""Dormant first-Genesis private route capsule for a future TLS supervisor.

The ordinary Agent's ingress-u* links intentionally advance to successor
meters. A TLS authority bound to the first meter must NOT use mutable
generation routing. This module makes a separate process-private directory,
bound to the exact original cap roster and live kernel Unix peer. It does
not publish a listener, install a permit, or authorize traffic.
"""
import hashlib
import os
from pathlib import Path
import secrets
import select
import socket
import stat
import struct
import time

import public_tls_cap_watch as cap_watch
import vless_ingress
import wal_transport as wal

ROOT = Path("/run/xmesh-quota-v2-public-tls")
ENROLLED_STATE = Path("/var/lib/xmesh-xray-sync")
MAX_CHECK_NS = 5_000_000_000
MAX_CLOCK_DIVERGENCE_MS = 2_000
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _dir_identity(info):
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("unsafe root-private TLS route directory")
    return info.st_dev, info.st_ino


def _socket_identity(fd, tag):
    info = os.stat(tag, dir_fd=fd, follow_symlinks=False)
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
        raise ValueError("unsafe private meter listener inode")
    return info.st_dev, info.st_ino


class FirstGenesisRoutes:
    """Pin a first-Genesis route set; independent of mutable Agent routes.

    The caller must already have authenticated the original signed Genesis,
    measured qualified Xray and constructed the full signed-cap watcher.
    A future child must inherit exactly `directory_fd` and receive
    `ingress_state` as its XMESH_QUOTA_INGRESS_STATE. The trailing '/.'
    resolves the inherited directory, as required by the production Go
    dialer's Lstat directory check; replacing the ordinary state path or
    this capsule's pathname cannot redirect that child to a new directory.

    An inherited directory fd pins the inode, NOT its contents or mount
    permissions. A future launcher must prove effective write denial to the
    child for that exact inode (not merely remount a different pathname
    read-only), and isolate it from mutable state. The supervisor must call
    ensure_current before exec and on stop-monitor ticks and stop/reap the
    child BEFORE closing the capsule. This is not a runtime
    authority, meter proof, systemd service, or positive listener gate.
    """

    def __init__(self, roster, enrolled_fd):
        if os.geteuid() != 0 or not isinstance(roster, cap_watch.SignedCapRosterWatch):
            raise ValueError("root and independently signed TLS roster required")
        self._fds = []
        self._root_fd = self._state_fd = self._meter_fd = self._pidfd = None
        self.directory_fd = None
        self._name = None
        self._identity = None
        self._closed = False
        self._pid = roster._pid
        self._runtime = roster.runtime_id
        self._roster = roster
        self._roster_sha = roster.roster_sha256
        self._links = {}
        self._tags = set()
        self._expires = []
        self._wall_ms = time.time_ns() // 1_000_000
        self._mono_ns = time.monotonic_ns()
        self._grant_identity = None
        self._socket_ids = {}
        self._target = vless_ingress.target(self._pid, self._runtime)
        try:
            deadline = self._deadline()
            for user, (raw, _, emails) in sorted(roster._grants.items()):
                deadline()
                doc = wal.observed.strict_json(raw)
                if (doc["payload"]["kind"] != "xmesh.quota-v2.xray-cap-admission"
                        or not emails):
                    raise ValueError("TLS route capsule requires original first caps")
                self._expires.append(doc["payload"]["validUntilMs"])
                name = f"ingress-u{user}"
                self._links[name] = self._target
                for email in emails:
                    match = cap_watch.EMAIL.fullmatch(email)
                    if match is None or int(match.group(1)) != user:
                        raise ValueError("foreign private meter alias")
                    self._tags.add("vless-" + match.group(2))
            if not self._links or not self._tags:
                raise ValueError("missing original first-Genesis private routes")
            self._grant_identity = self._roster_identity()
            self._expiry_ms = min(self._expires)
            self._check_time()
            self._root_fd = self._own(os.open(ROOT, DIR_FLAGS))
            self._root_id = _dir_identity(os.fstat(self._root_fd))
            self._state_fd = self._own(os.dup(enrolled_fd))
            self._state_id = _dir_identity(os.fstat(self._state_fd))
            self._pidfd = self._own(os.pidfd_open(self._pid, 0))
            self._meter_fd = self._own(os.open(self._target, DIR_FLAGS))
            self._meter_id = _dir_identity(os.fstat(self._meter_fd))

            deadline()
            self._check_source()
            self._check_meter(deadline)
            # The independently owned directory is in a fixed root-private
            # runtime root, NOT the enrolled mutable user's route directory.
            self._name = "first-" + secrets.token_hex(16)
            os.mkdir(self._name, 0o700, dir_fd=self._root_fd)
            self.directory_fd = self._own(os.open(self._name, DIR_FLAGS, dir_fd=self._root_fd))
            self._identity = _dir_identity(os.fstat(self.directory_fd))
            for name, target in self._links.items():
                deadline()
                os.symlink(target, name, dir_fd=self.directory_fd)
            os.fsync(self.directory_fd)
            os.fsync(self._root_fd)
            self._check(deadline)
        except BaseException:
            self.close()
            raise

    def _own(self, fd):
        self._fds.append(fd)
        return fd

    @property
    def ingress_state(self):
        if self._closed or self.directory_fd is None:
            raise ValueError("private TLS route capsule is closed")
        return f"/proc/self/fd/{self.directory_fd}/."

    @staticmethod
    def _deadline():
        start = time.monotonic_ns()

        def check():
            if not 0 <= time.monotonic_ns() - start < MAX_CHECK_NS:
                raise ValueError("private TLS route proof missed watchdog budget")
        return check

    def _roster_identity(self):
        return hashlib.sha256(wal.observed.canonical([
            {"user": user, "grant": hashlib.sha256(raw).hexdigest(),
             "scope": scope, "emails": list(emails)}
            for user, (raw, scope, emails) in sorted(self._roster._grants.items())
        ])).hexdigest()

    def _check_source(self):
        if (_dir_identity(os.stat(ROOT, follow_symlinks=False)) != self._root_id
                or _dir_identity(os.stat(ENROLLED_STATE, follow_symlinks=False)) != self._state_id
                or _dir_identity(os.fstat(self._state_fd)) != self._state_id):
            raise ValueError("enrolled source or private route root was replaced")
        names = set(os.listdir(self._state_fd))
        if ({name for name in names if name.startswith("ingress-u")} != set(self._links)
                or any(name.startswith(".ingress-") for name in names)):
            raise ValueError("incomplete, foreign or pending enrolled ingress routes")
        self._check_links(self._state_fd, self._links)

    @staticmethod
    def _check_links(fd, links):
        for name, target in links.items():
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if (not stat.S_ISLNK(info.st_mode) or info.st_uid != 0
                    or info.st_nlink != 1 or os.readlink(name, dir_fd=fd) != target):
                raise ValueError("private TLS route changed from signed original meter")

    def _check_liveness(self):
        poll = select.poll()
        poll.register(self._pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if (poll.poll(0)
                or wal.runtime_identity.trusted_runtime_identity(self._pid) != self._runtime
                or poll.poll(0)):
            raise ValueError("original TLS meter changed or exited")

    def _check_meter(self, deadline):
        deadline()
        self._check_liveness()
        if (_dir_identity(os.fstat(self._meter_fd)) != self._meter_id
                or _dir_identity(os.stat(self._target, follow_symlinks=False)) != self._meter_id):
            raise ValueError("original meter socket directory changed")
        for tag in sorted(self._tags):
            deadline()
            before = _socket_identity(self._meter_fd, tag)
            if self._socket_ids.get(tag, before) != before:
                raise ValueError("original private VLESS socket was replaced")
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                probe.settimeout(1.5)
                # No client data, no byte allocation or fallback. Authenticate
                # the kernel peer of the exact measured root-private inode.
                probe.connect(f"/proc/self/fd/{self._meter_fd}/{tag}")
                raw = probe.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                if struct.unpack("3i", raw)[:2] != (self._pid, 0):
                    raise ValueError("private VLESS listener belongs to a different kernel peer")
            if _socket_identity(self._meter_fd, tag) != before:
                raise ValueError("private VLESS socket changed during peer proof")
            self._socket_ids[tag] = before
            deadline()
        self._check_liveness()
        if _dir_identity(os.stat(self._target, follow_symlinks=False)) != self._meter_id:
            raise ValueError("original meter socket directory changed during proof")

    def _check_time(self):
        elapsed_ms = (time.monotonic_ns() - self._mono_ns) // 1_000_000
        wall_ms = time.time_ns() // 1_000_000
        if (elapsed_ms < 0 or wall_ms < self._wall_ms
                or abs(wall_ms - self._wall_ms - elapsed_ms) > MAX_CLOCK_DIVERGENCE_MS
                or wall_ms >= self._expiry_ms
                or self._wall_ms + elapsed_ms >= self._expiry_ms):
            raise ValueError("first-Genesis route capsule expired or changed clock")

    def _check(self, deadline):
        self._check_time()
        if (self._closed or self.directory_fd is None
                or self._roster.roster_sha256 != self._roster_sha
                or self._roster_identity() != self._grant_identity):
            raise ValueError("first-Genesis route capsule expired or changed")
        self._check_source()
        if (_dir_identity(os.fstat(self.directory_fd)) != self._identity
                or _dir_identity(os.stat(self._name, dir_fd=self._root_fd,
                                         follow_symlinks=False)) != self._identity
                or set(os.listdir(self.directory_fd)) != set(self._links)):
            raise ValueError("private TLS route capsule changed")
        self._check_links(self.directory_fd, self._links)
        self._check_meter(deadline)
        self._check_source()
        self._check_links(self.directory_fd, self._links)
        if (_dir_identity(os.stat(self._name, dir_fd=self._root_fd,
                                  follow_symlinks=False)) != self._identity
                or set(os.listdir(self.directory_fd)) != set(self._links)):
            raise ValueError("private TLS route capsule changed during proof")
        deadline()
        self._check_time()

    def ensure_current(self):
        """Current peer/route evidence, never a positive ingress decision."""
        self._check(self._deadline())
        return None

    def close(self):
        if self._closed:
            return
        self._closed = True
        # Never recurse into a substituted pathname or delete other state.
        # If corruption exists, leave that directory for inspection, not use.
        if self.directory_fd is not None and self._identity is not None:
            try:
                if _dir_identity(os.fstat(self.directory_fd)) == self._identity:
                    names = set(os.listdir(self.directory_fd))
                    if names <= set(self._links):
                        self._check_links(self.directory_fd, {n: self._links[n] for n in names})
                        for name in names:
                            os.unlink(name, dir_fd=self.directory_fd)
                        os.fsync(self.directory_fd)
                        if _dir_identity(os.stat(self._name, dir_fd=self._root_fd,
                                                 follow_symlinks=False)) == self._identity:
                            os.rmdir(self._name, dir_fd=self._root_fd)
                            os.fsync(self._root_fd)
            except (OSError, ValueError):
                pass
        for fd in reversed(self._fds):
            os.close(fd)
        self._fds.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
