"""Dormant sealed listener inputs anchored to the verified TLS config.

No bind, listen, spawn, positive authority, or ownership transfer happens here.
Borrow the original pinned TLS inputs and original prebound sockets, own only
the new sealed manifest. The future launcher must independently prove child
inheritance, release its actual prebound FD copies, and enforce stop-only
authority before any Go transport adopts those sockets.
"""
import fcntl
import hashlib
import os
import socket
import stat

import public_tls_bound_listener as bound
import public_tls_certificates as certificates
import public_tls_pinned_inputs as pinned
import wal_transport

MAX_MANIFEST = 16 << 10
TAGS = {"vless-main", "vless-cdn"}


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_nlink, info.st_size)


def _config_hash(frozen):
    data = os.pread(frozen.config_fd, certificates.MAX_CONFIG_BYTES + 1, 0)
    if not 0 < len(data) <= certificates.MAX_CONFIG_BYTES:
        raise ValueError("invalid bounded frozen TLS config")
    return hashlib.sha256(data).hexdigest()


class ListenerManifest:
    def __init__(self, *, inputs, config, authority, cap_watch, runtime_pid,
                 sockets, netns_cookie):
        if (os.geteuid() != 0 or not isinstance(inputs, pinned.PinnedTlsInputs)
                or type(sockets) is not dict):
            raise ValueError("exact signed pinned TLS input bundle required")
        self._inputs = inputs
        self._config = config
        self._authority = authority
        self._cap_watch = cap_watch
        self._runtime_pid = runtime_pid
        self._sockets = dict(sockets)
        self._netns_cookie = netns_cookie
        self._manifest = None
        self._closed = False
        try:
            self._check_original()
            inbounds = config["inbounds"]
            if (not 1 <= len(inbounds) <= 2
                    or {row["tag"] for row in inbounds} != set(self._sockets)
                    or not set(self._sockets) <= TAGS
                    or len(inbounds) != len(self._sockets)):
                raise ValueError("prebound listeners must cover exact signed TLS inbounds")
            self._tokens = {}
            self._listener_fds = {}
            for row in inbounds:
                tag, sock = row["tag"], self._sockets[row["tag"]]
                if not isinstance(sock, socket.socket):
                    raise ValueError("actual prebound listener required")
                self._tokens[tag] = bound.capture_bound(
                    sock, row["listen"], row["port"], netns_cookie)
                self._listener_fds[tag] = sock.fileno()
            if len(set(self._tokens.values())) != len(self._tokens):
                raise ValueError("ambiguous inherited listener identity")
            if set(self._listener_fds.values()) & set(inputs.child_fds):
                raise ValueError("listener overlaps protected TLS input FD")
            self._raw = self._encode()
            if not 0 < len(self._raw) <= MAX_MANIFEST:
                raise ValueError("listener manifest exceeded bound")
            self._manifest = certificates._sealed_bytes("xmesh-tls-listener-manifest", self._raw)
            self._manifest_identity = _identity(os.fstat(self._manifest))
            self.ensure_current()
        except BaseException:
            self.close()
            raise

    def _check_original(self):
        if self._closed or self._inputs.ensure_current(
                config=self._config, authority=self._authority,
                cap_watch=self._cap_watch, runtime_pid=self._runtime_pid) is not None:
            raise ValueError("original signed TLS inputs unavailable")

    def _encode(self):
        frozen = self._inputs._certificates
        return wal_transport.observed.canonical({
            "kind": "xmesh.quota-v2.namespace-listener-inputs",
            "version": 1,
            "runtimeId": self._cap_watch.runtime_id,
            "rosterSha256": self._cap_watch.roster_sha256,
            "authoritySha256": hashlib.sha256(self._authority).hexdigest(),
            "configFd": frozen.config_fd,
            "configSha256": _config_hash(frozen),
            "listeners": [
                {"address": token.address, "port": token.port, "tag": tag,
                 "fd": self._listener_fds[tag], "device": str(token.device),
                 "inode": str(token.inode), "cookie": str(token.cookie),
                 "netnsCookie": str(token.netns_cookie)}
                for tag, token in sorted(self._tokens.items())
            ],
        })

    def ensure_manifest(self):
        """Recheck retained manifest/config, even after owner socket release."""
        self._check_original()
        info = os.fstat(self._manifest)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 0
                or _identity(info) != self._manifest_identity
                or os.get_inheritable(self._manifest)
                or fcntl.fcntl(self._manifest, fcntl.F_GET_SEALS) != certificates.SEALS
                or os.pread(self._manifest, MAX_MANIFEST+1, 0) != self._raw
                or self._encode() != self._raw):
            raise ValueError("original sealed listener manifest changed")
        return None

    def ensure_current(self):
        """Pre-transfer proof; never attempt this with a retained live listener."""
        self.ensure_manifest()
        for tag, sock in self._sockets.items():
            if sock.fileno() != self._listener_fds[tag] or os.get_inheritable(sock.fileno()):
                raise ValueError("original prebound listener FD changed")
            bound.verify_bound_socket(sock, self._tokens[tag], listening=False)
        return None

    @property
    def child_fds(self):
        self.ensure_current()
        return self._manifest, *(self._listener_fds[tag] for tag in sorted(self._listener_fds))

    @property
    def manifest_fd(self):
        self.ensure_manifest()
        return self._manifest

    def close(self):
        if not self._closed:
            self._closed = True
            if self._manifest is not None:
                os.close(self._manifest)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
