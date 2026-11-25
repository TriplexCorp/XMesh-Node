"""Read-only, fail-closed certificate lineage checks for a future public TLS ingress.

No ACME action, listener, Docker restart or quota authorization happens here.
The caller must FIRST verify the separately signed public TLS policy against
the original strict-PQ activation, Genesis, live runtime, and raw VLESS roster.
A valid certificate alone never makes a Node eligible to serve traffic.
"""
import os
from pathlib import Path
import re
import stat
import subprocess

import public_tls_frontend as tls

LIVE_ROOT = Path("/etc/letsencrypt/live")
ARCHIVE_ROOT = Path("/etc/letsencrypt/archive")
MAX_CERT_BYTES = 1024 * 1024
MAX_KEY_BYTES = 64 * 1024
RENEWAL_MARGIN_SECONDS = 24 * 3600


def _secure_dir(path):
    info = path.stat(follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("unsafe root-owned ACME certificate directory")


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
    info = resolved.stat(follow_symlinks=False)
    limit = MAX_KEY_BYTES if kind == "privkey" else MAX_CERT_BYTES
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or info.st_nlink != 1 or not 0 < info.st_size <= limit
            or info.st_mode & 0o022
            or (kind == "privkey" and info.st_mode & 0o077)):
        raise ValueError("unsafe certificate or private-key material")
    return link


def _openssl(*args, input_bytes=None):
    result = subprocess.run(
        ["/usr/bin/openssl", *map(str, args)], input=input_bytes,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    if result.returncode != 0 or len(result.stdout) > MAX_CERT_BYTES:
        raise ValueError("TLS certificate validity check failed")
    return result.stdout


def verify_certificate_lineage(config):
    """Verify every exact signed-TLS hostname's Certbot lineage before use.

    The host's private key must match its signed certificate public key,
    the certificate must have an exact (not wildcard) DNS SAN and remain
    valid throughout a 24h renewal safety window. Recheck before any new
    ingress process, after each renewal and during future active supervision.
    """
    if os.geteuid() != 0 or not isinstance(config, dict):
        raise ValueError("certificate checks require root and a signed TLS configuration")
    inbounds = config.get("inbounds")
    if not isinstance(inbounds, list) or not 1 <= len(inbounds) <= 2:
        raise ValueError("signed public TLS inbounds are missing")
    result = {}
    for inbound in inbounds:
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
        cert = _checked_lineage(name, "fullchain")
        key = _checked_lineage(name, "privkey")
        cert_record = tls_settings["certificates"][0]
        if not isinstance(cert_record, dict) or set(cert_record) != {"certificateFile", "keyFile"}:
            raise ValueError("unexpected TLS certificate configuration")
        # Signed Xray JSON must always contain the immutable production
        # /etc/letsencrypt paths, never a testing or runtime-redirected root.
        # LIVE_ROOT/ARCHIVE_ROOT are replaceable only by isolated unit tests
        # to simulate filesystem ownership and symlink invariants.
        expected = "/etc/letsencrypt/live/" + name
        if (cert_record.get("certificateFile") != expected + "/fullchain.pem"
                or cert_record.get("keyFile") != expected + "/privkey.pem"):
            raise ValueError("TLS config key paths diverged from signed hostname")
        _openssl("x509", "-in", cert, "-noout", "-checkend", str(RENEWAL_MARGIN_SECONDS))
        alt = _openssl("x509", "-in", cert, "-noout", "-ext", "subjectAltName").decode("ascii")
        san = re.findall(r"(?<![A-Za-z])DNS:([a-zA-Z0-9*.-]+)", alt)
        if name not in san or "*" in "".join(san):
            raise ValueError("certificate does not bind exact signed SNI")
        cert_pem = _openssl("x509", "-in", cert, "-noout", "-pubkey")
        cert_pub = _openssl("pkey", "-pubin", "-outform", "DER", input_bytes=cert_pem)
        key_pub = _openssl("pkey", "-in", key, "-pubout", "-outform", "DER")
        if cert_pub != key_pub:
            raise ValueError("TLS private key does not match the signed certificate")
        result[inbound["tag"]] = (cert, key)
    if len(result) != len(inbounds):
        raise ValueError("duplicate TLS inbound tag")
    return result
