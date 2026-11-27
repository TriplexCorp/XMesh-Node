"""Dormant namespace-safe input bundle for a future authenticated Go dialer.

The existing signed FirstGenesisRoutes remains the supervisor's evidence;
the child must never inherit that host-PID route directory or original
pidfd. Give it only a detached read-only view of the exact original meter
directory and an immutable alias/peer manifest. No listener or traffic
permission is created by this module; the production Go dialer is unchanged.
"""
import fcntl
import os
import stat
import time

import public_tls_cap_watch as caps
import public_tls_certificates as certificates
import public_tls_peer_identity as peers
import public_tls_route_mount as mounts
import public_tls_routes as routes

MAX_MANIFEST_BYTES = 1 << 20
MAX_PROOF_NS = 8_000_000_000


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_gid, info.st_nlink, info.st_size)


def _lock_identity(fd, name):
    # Exact pinned Xray FileLocker creates an empty regular file via
    # os.Create beside each Unix socket. This is not a routing input.
    info = os.stat(name, dir_fd=fd, follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) not in (0o600, 0o644)
            or info.st_nlink != 1 or info.st_size != 0):
        raise ValueError("unsafe original meter lock file")
    return info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode)


class NamespaceMeterInputs:
    """Borrow the original measured route capsule; own only two child FDs.

    Keep the source capsule and its PIDFD alive until the child is stopped
    and reaped, then close this bundle before the source. The manifest has
    no host PID, path, original pidfd or writable Agent descriptor.
    """

    def __init__(self, original):
        if os.geteuid() != 0 or not isinstance(original, routes.FirstGenesisRoutes):
            raise ValueError("root and original signed first-Genesis route capsule required")
        self._original = original
        self._closed = False
        self._view = self._manifest = None
        started = time.monotonic_ns()
        try:
            if original.ensure_current() is not None:
                raise ValueError("original route evidence cannot authorize ingress")
            self._peer = peers.capture_original(original._pidfd, original._pid)
            self._view, self._mount = mounts.readonly_meter_view(
                original._meter_fd, original._pidfd, original._pid)
            names = set(os.listdir(self._view))
            lock_names = {tag + ".lock" for tag in original._tags}
            # Standalone lockless kernel fixtures remain valid. Real Xray
            # must expose a complete, exact lock roster, never a subset.
            if names not in (original._tags, original._tags | lock_names):
                raise ValueError("namespace meter view contains foreign or changed sockets")
            self._lock_ids = {name: _lock_identity(self._view, name)
                              for name in sorted(names & lock_names)}
            self._raw = self._encode()
            if not 0 < len(self._raw) <= MAX_MANIFEST_BYTES:
                raise ValueError("namespace meter manifest exceeded bound")
            self._manifest = certificates._sealed_bytes("xmesh-tls-peer-manifest", self._raw)
            self._manifest_id = _identity(os.fstat(self._manifest))
            self._check_inputs()
            if time.monotonic_ns() - started >= MAX_PROOF_NS:
                raise ValueError("namespace meter input assembly missed budget")
        except BaseException:
            self.close()
            raise

    def _encode(self):
        original = self._original
        aliases = []
        for user, (_, _, emails) in sorted(original._roster._grants.items()):
            for email in sorted(emails):
                match = caps.EMAIL.fullmatch(email)
                if match is None or int(match.group(1)) != user:
                    raise ValueError("foreign original meter alias")
                aliases.append(email)
        if not aliases or len(aliases) != len(set(aliases)):
            raise ValueError("missing or duplicated original meter aliases")
        # Decimal strings retain exact uint64 device/inode values across
        # Python/Go JSON decoders; no float conversion is admissible.
        return routes.wal.observed.canonical({
            "kind": "xmesh.quota-v2.namespace-meter-inputs",
            "version": 2,
            "lockFiles": [
                {"tag": name, "device": str(dev), "inode": str(ino), "mode": mode}
                for name, (dev, ino, mode) in sorted(self._lock_ids.items())
            ],
            "runtimeId": original._runtime,
            "rosterSha256": original._roster_sha,
            "aliases": sorted(aliases),
            "meterDirectoryFd": self._view,
            "meterDirectoryDevice": str(original._meter_id[0]),
            "meterDirectoryInode": str(original._meter_id[1]),
            "meterMountId": str(self._mount),
            "peerDevice": str(self._peer.device),
            "peerInode": str(self._peer.inode),
            "sockets": [
                {"tag": tag, "device": str(original._socket_ids[tag][0]),
                 "inode": str(original._socket_ids[tag][1])}
                for tag in sorted(original._tags)
            ],
        })

    def _check_inputs(self):
        original = self._original
        if (self._closed or original._closed
                or peers.capture_original(original._pidfd, original._pid) != self._peer):
            raise ValueError("original namespace meter no longer live")
        mounts.check_view(original._meter_fd, self._view, self._mount)
        if (routes._dir_identity(os.fstat(self._view)) != original._meter_id
                or routes._dir_identity(os.stat("..", dir_fd=self._view)) != original._meter_id):
            raise ValueError("namespace meter directory is not its exact detached root")
        # The view exposes only the original VLESS sockets and exact
        # empty pinned Xray lock files, never arbitrary files or paths.
        if (set(os.listdir(self._view)) != original._tags | self._lock_ids.keys()
                or any(_lock_identity(self._view, name) != identity
                       for name, identity in self._lock_ids.items())
                or any(routes._socket_identity(self._view, tag) != original._socket_ids.get(tag)
                       for tag in original._tags)):
            raise ValueError("namespace meter view contains foreign or changed sockets")
        info = os.fstat(self._manifest)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 0
                or _identity(info) != self._manifest_id
                or os.get_inheritable(self._manifest)
                or fcntl.fcntl(self._manifest, fcntl.F_GET_SEALS) != certificates.SEALS
                or os.pread(self._manifest, MAX_MANIFEST_BYTES + 1, 0) != self._raw
                or self._encode() != self._raw):
            raise ValueError("namespace meter manifest changed")

    def ensure_current(self):
        started = time.monotonic_ns()
        if self._closed or self._original.ensure_current() is not None:
            raise ValueError("original namespace route evidence unavailable")
        self._check_inputs()
        if time.monotonic_ns() - started >= MAX_PROOF_NS:
            raise ValueError("namespace meter proof missed watchdog budget")
        return None

    @property
    def child_fds(self):
        if self._closed:
            raise ValueError("namespace meter inputs closed")
        return self._view, self._manifest

    def close(self):
        if not self._closed:
            self._closed = True
            for fd in (self._manifest, self._view):
                if fd is not None:
                    os.close(fd)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
