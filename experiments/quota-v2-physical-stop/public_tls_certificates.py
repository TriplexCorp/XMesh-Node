"""Read-only, fail-closed certificate lineage checks for future public TLS.

No ACME action, listener, Docker restart or quota authorization happens here.
The caller must FIRST verify the separately signed public TLS policy against
the original strict-PQ activation, Genesis, live runtime, and raw VLESS roster.
A valid certificate alone never makes a Node eligible to serve traffic.
"""
from copy import deepcopy
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

import public_tls_frontend as tls

LIVE_ROOT = Path("/etc/letsencrypt/live")
ARCHIVE_ROOT = Path("/etc/letsencrypt/archive")
SYSTEM_CA_FILE = Path("/etc/ssl/certs/ca-certificates.crt")
MAX_CERT_BYTES = 1024 * 1024
MAX_KEY_BYTES = 64 * 1024
MAX_CONFIG_BYTES = 16 << 20
RENEWAL_MARGIN_SECONDS = 24 * 3600
SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL


def _secure_dir(path):
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("unsafe root-owned ACME certificate directory")


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _checked_file(path, limit, *, secret=False):
    info = path.stat(follow_symlinks=False)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_nlink != 1 or not 0 < info.st_size <= limit
            or info.st_mode & 0o022 or (secret and info.st_mode & 0o077)):
        raise ValueError("unsafe certificate, private-key or root CA material")
    return _identity(info)


def _checked_lineage(domain, kind):
    if not isinstance(domain, str) or not tls.DOMAIN.fullmatch(domain):
        raise ValueError("invalid signed ACME domain")
    if kind not in ("fullchain", "privkey"):
        raise ValueError("invalid certificate material")
    for path in (LIVE_ROOT, LIVE_ROOT / domain, ARCHIVE_ROOT, ARCHIVE_ROOT / domain):
        _secure_dir(path)
    link = LIVE_ROOT / domain / (kind + ".pem")
    if not link.is_symlink():
        raise ValueError("expected Certbot-managed lineage symlink")
    resolved = link.resolve(strict=True)
    archive = (ARCHIVE_ROOT / domain).resolve(strict=True)
    if (resolved.parent != archive
            or re.fullmatch(rf"{kind}[1-9][0-9]*\.pem", resolved.name) is None):
        raise ValueError("certificate symlink escaped the signed ACME lineage")
    limit = MAX_KEY_BYTES if kind == "privkey" else MAX_CERT_BYTES
    return link, resolved, _checked_file(resolved, limit, secret=kind == "privkey")


def _sealed_bytes(name, raw):
    """Anonymous kernel-sealed bytes: no on-disk copy or mutable path."""
    fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        os.fchmod(fd, 0o600)
        remaining = memoryview(raw)
        while remaining:
            size = os.write(fd, remaining)
            if size <= 0:
                raise OSError("short anonymous material write")
            remaining = remaining[size:]
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, SEALS)
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _copy_checked(path, identity, limit, name):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        if _identity(os.fstat(fd)) != identity:
            raise ValueError("certificate material was replaced before opening")
        with os.fdopen(os.dup(fd), "rb") as stream:
            raw = stream.read(limit + 1)
        if (not 0 < len(raw) <= limit or len(raw) != identity[5]
                or _identity(os.fstat(fd)) != identity
                or _identity(path.stat(follow_symlinks=False)) != identity):
            raise ValueError("certificate material changed while copying")
        return _sealed_bytes(name, raw)
    finally:
        os.close(fd)


def _openssl(*args, input_bytes=None, fds=()):
    result = subprocess.run(
        ["/usr/bin/openssl", *map(str, args)], input=input_bytes,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, pass_fds=fds,
    )
    if result.returncode != 0 or len(result.stdout) > MAX_CERT_BYTES:
        raise ValueError("TLS certificate validity check failed")
    return result.stdout


def _fd_path(fd):
    return f"/proc/self/fd/{fd}"


def _inbound_identity(inbound):
    if not isinstance(inbound, dict) or inbound.get("tag") not in ("vless-main", "vless-cdn"):
        raise ValueError("foreign public TLS inbound")
    settings = inbound.get("streamSettings", {})
    if not isinstance(settings, dict) or set(settings) != {"network", "security", "tlsSettings"}:
        raise ValueError("unsafe public TLS stream settings")
    tls_settings = settings.get("tlsSettings", {})
    if (not isinstance(tls_settings, dict)
            or set(tls_settings) != {"serverName", "minVersion", "certificates"}
            or settings.get("network") != "tcp" or settings.get("security") != "tls"
            or tls_settings.get("minVersion") != "1.3"
            or not isinstance(tls_settings.get("certificates"), list)
            or len(tls_settings["certificates"]) != 1):
        raise ValueError("noncanonical TLS ingress configuration")
    name = tls_settings.get("serverName")
    if not isinstance(name, str) or not tls.DOMAIN.fullmatch(name):
        raise ValueError("invalid signed public SNI")
    cert_record = tls_settings["certificates"][0]
    expected = "/etc/letsencrypt/live/" + name
    if cert_record != {"certificateFile": expected + "/fullchain.pem",
                       "keyFile": expected + "/privkey.pem"}:
        raise ValueError("TLS config key paths diverged from signed hostname")
    return inbound["tag"], name, cert_record


def _verify_material(name, cert, key, ca):
    # Verify exactly the bytes the future child will read. OpenSSL gets
    # only the required sealed descriptors, never an ambient mutable symlink.
    cert_path, key_path, ca_path = map(_fd_path, (cert, key, ca))
    now = int(time.time())
    # A future-dated leaf/chain might verify at the renewal-margin
    # timestamp while still being invalid at the actual listener start.
    for verify_at in (now, now + RENEWAL_MARGIN_SECONDS):
        _openssl("verify", "-purpose", "sslserver",
                 "-verify_hostname", name, "-attime", str(verify_at),
                 "-CAfile", ca_path, "-untrusted", cert_path, cert_path, fds=(cert, ca))
    _openssl("x509", "-in", cert_path, "-noout", "-checkend", str(RENEWAL_MARGIN_SECONDS),
             fds=(cert,))
    alt = _openssl("x509", "-in", cert_path, "-noout", "-ext", "subjectAltName",
                   fds=(cert,)).decode("ascii")
    san = re.findall(r"(?<![A-Za-z])DNS:([a-zA-Z0-9*.-]+)", alt)
    if name not in san or "*" in "".join(san):
        raise ValueError("certificate does not bind exact signed SNI")
    cert_pem = _openssl("x509", "-in", cert_path, "-noout", "-pubkey", fds=(cert,))
    cert_pub = _openssl("pkey", "-pubin", "-outform", "DER", input_bytes=cert_pem)
    key_pub = _openssl("pkey", "-in", key_path, "-pubout", "-outform", "DER", fds=(key,))
    if cert_pub != key_pub:
        raise ValueError("TLS private key does not match the signed certificate")


class FrozenTlsInputs:
    """Own kernel-sealed TLS material and config; NOT an ingress permit.

    This is a read-only input snapshot for a future supervised launcher.
    Callers must keep the descriptors open (and explicitly inherit only
    `material_fds` into the exact qualified child). Never read private-key
    bytes into a command line, log, or on-disk rewritten config. A changed
    lineage or CA requires a fresh complete preflight; it cannot silently
    reconfigure an already admitted listener.
    """

    def __init__(self):
        self._closed = False
        self._fds = []
        self._fd_identities = {}
        self._sources = {}
        self._ca_identity = None
        self._verified_at = None
        self._wall_at = None
        self.config_fd = None
        self.material_fds = ()
        self.lineages = {}

    def _own(self, fd):
        self._fds.append(fd)
        self._fd_identities[fd] = _identity(os.fstat(fd))
        return fd

    def ensure_current(self):
        if self._closed or self.config_fd is None or self._verified_at is None:
            raise ValueError("TLS input snapshot is not live")
        # Rotation is not authorization to load new bytes. Stop/recheck a
        # future child if the exact live lineage or root trust changes.
        if (SYSTEM_CA_FILE != self._ca_identity[0]
                or _checked_file(SYSTEM_CA_FILE, MAX_CERT_BYTES) != self._ca_identity[1]):
            raise ValueError("system TLS trust changed after snapshot")
        for (domain, kind), source in self._sources.items():
            if _checked_lineage(domain, kind) != source:
                raise ValueError("certificate lineage changed after snapshot")
        # The 24h margin certifies frozen bytes at snapshot time. This object
        # is for a short-lived authority, never a day-long reusable proof.
        elapsed = time.monotonic_ns() - self._verified_at
        wall_elapsed = time.time_ns() - self._wall_at
        if (not 0 <= elapsed < 120_000_000_000
                or not 0 <= wall_elapsed < 120_000_000_000
                or abs(elapsed - wall_elapsed) > 2_000_000_000):
            raise ValueError("TLS input snapshot expired or clock changed")
        if any(fcntl.fcntl(fd, fcntl.F_GET_SEALS) != SEALS
               or _identity(os.fstat(fd)) != self._fd_identities[fd]
               for fd in self._fds):
            raise ValueError("TLS input snapshot is not the original kernel-sealed inode")
        return None

    def close(self):
        if not self._closed:
            self._closed = True
            for fd in reversed(self._fds):
                os.close(fd)
            self._fds.clear()

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()


def freeze_certificate_lineage(config):
    """Freeze verified certificate/key bytes and an exact rewritten config.

    Only the certificate file paths are replaced by inherited sealed memfds;
    the original signed-profile compiler remains the sole authorized source
    of the TLS configuration. This helper never launches Xray or grants
    spending, start, resume, or public authority.
    """
    if os.geteuid() != 0 or not isinstance(config, dict):
        raise ValueError("certificate checks require root and a signed TLS configuration")
    config = deepcopy(config)
    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list) or not 1 <= len(inbounds) <= 2:
        raise ValueError("signed public TLS inbounds are missing")
    frozen = FrozenTlsInputs()
    try:
        # Anchor the entire proof; even slow OpenSSL verification may not
        # make the snapshot look newly verified after the signed time budget.
        frozen._verified_at = time.monotonic_ns()
        frozen._wall_at = time.time_ns()
        ca_identity = _checked_file(SYSTEM_CA_FILE, MAX_CERT_BYTES)
        frozen._ca_identity = (SYSTEM_CA_FILE, ca_identity)
        ca = frozen._own(_copy_checked(SYSTEM_CA_FILE, ca_identity,
                                       MAX_CERT_BYTES, "xmesh-tls-ca"))
        material = []
        for inbound in inbounds:
            tag, name, record = _inbound_identity(inbound)
            if tag in frozen.lineages:
                raise ValueError("duplicate TLS inbound tag")
            links, pair = [], []
            for kind, limit in (("fullchain", MAX_CERT_BYTES), ("privkey", MAX_KEY_BYTES)):
                source = _checked_lineage(name, kind)
                if ((name, kind) in frozen._sources
                        and frozen._sources[name, kind] != source):
                    raise ValueError("certificate lineage changed during snapshot")
                frozen._sources[name, kind] = source
                link, resolved, identity = source
                links.append(link)
                fd = frozen._own(_copy_checked(resolved, identity, limit, "xmesh-tls-" + kind))
                pair.append(fd)
                material.append(fd)
            cert, key = pair
            _verify_material(name, cert, key, ca)
            frozen.lineages[tag] = tuple(links)
            record.update(certificateFile=_fd_path(cert), keyFile=_fd_path(key))
        raw = json.dumps(config, sort_keys=True, ensure_ascii=False, separators=(",", ":"),
                         allow_nan=False).encode("utf-8")
        if not 0 < len(raw) <= MAX_CONFIG_BYTES:
            raise ValueError("oversized frozen TLS configuration")
        frozen.config_fd = frozen._own(_sealed_bytes("xmesh-tls-config", raw))
        frozen.material_fds = tuple(material)
        frozen.ensure_current()
        return frozen
    except BaseException:
        frozen.close()
        raise


def verify_certificate_lineage(config):
    """Validate exact sealed bytes and return diagnostic lineage paths only.

    The legacy preflight/stop-only monitors inspect the live lineages, but
    must not use the returned mutable paths to create a TLS child. A future
    launcher must retain a separate FrozenTlsInputs instance through exec,
    and check its lineage as part of continuous stop supervision.
    """
    with freeze_certificate_lineage(config) as frozen:
        return dict(frozen.lineages)
