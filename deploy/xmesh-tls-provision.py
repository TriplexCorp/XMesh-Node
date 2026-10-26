#!/usr/bin/env python3
"""Provision only explicitly authorized per-node ACME certificates.

Called after xmesh-policy-guard.py prepare verifies the signed desired policy.
Never derive certificate names from Xray stderr or arbitrary profile file paths.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time

STATE = Path("/var/lib/xmesh-xray-sync")
DOMAIN = re.compile(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
EMAIL = re.compile(r"[^\s@]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
COOLDOWN = 1800


def fail(message):
    print("XMesh managed TLS: " + message, file=sys.stderr)
    return 1


def main():
    if len(sys.argv) != 3:
        return fail("expected verified response and effective configuration")
    response = json.loads(Path(sys.argv[1]).read_text())
    config = json.loads(Path(sys.argv[2]).read_text())
    spec = response.get("policy", {}).get("tlsProvision")
    if spec is None:
        return 0
    if not isinstance(spec, dict) or spec.get("provider") != "letsencrypt-http01":
        return fail("unsupported signed TLS provisioning contract")
    domain, email = spec.get("domain"), spec.get("email")
    if not isinstance(domain, str) or not DOMAIN.fullmatch(domain):
        return fail("invalid signed ACME domain")
    if not isinstance(email, str) or len(email) > 254 or not EMAIL.fullmatch(email):
        return fail("invalid signed ACME email")
    base = Path("/etc/letsencrypt/live") / domain
    cert, key = base / "fullchain.pem", base / "privkey.pem"
    tls_inbounds = [
        i for i in config.get("inbounds", [])
        if i.get("streamSettings", {}).get("security") == "tls"
    ]
    if not tls_inbounds:
        return fail("signed provisioning requested without a TLS inbound")
    for inbound in tls_inbounds:
        certificates = inbound.get("streamSettings", {}).get("tlsSettings", {}).get("certificates", [])
        if len(certificates) != 1 or certificates[0].get("certificateFile") != str(cert) or certificates[0].get("keyFile") != str(key):
            return fail("TLS certificate paths disagree with the signed node contract")
    if cert.is_file() and key.is_file() and subprocess.run(
        ["openssl", "x509", "-checkend", "86400", "-noout", "-in", str(cert)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=20
    ).returncode == 0:
        return 0
    # Persistent throttle prevents fast reconciliation timers from causing
    # ACME rate-limit abuse, repeated apt transactions, or repeated DNS probing.
    marker = STATE / ("acme-attempt-" + hashlib.sha256(domain.encode()).hexdigest()[:20])
    if marker.exists() and time.time() - marker.stat().st_mtime < COOLDOWN:
        return fail("certificate unavailable; automatic ACME attempt is in cooldown (30 minutes)")
    marker.touch(mode=0o600)
    try:
        # Do not interfere with an existing reverse proxy or ACME challenge server.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test:
            test.bind(("0.0.0.0", 80))
    except OSError:
        return fail("TCP/80 occupied; HTTP-01 needs a free port or an external certificate manager")
    if not shutil.which("certbot"):
        print("XMesh managed TLS: installing certbot for explicitly configured domain", file=sys.stderr)
        try:
            subprocess.run(["apt-get", "-o", "DPkg::Lock::Timeout=300", "install", "-y", "certbot"],
                           check=True, timeout=300)
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return fail("could not install certbot; check apt repositories")
    print("XMesh managed TLS: requesting ACME certificate for configured node domain", file=sys.stderr)
    try:
        result = subprocess.run([
            "certbot", "certonly", "--standalone", "--preferred-challenges", "http",
            "--non-interactive", "--agree-tos", "--no-eff-email",
            "--email", email, "-d", domain, "--keep-until-expiring",
            "--deploy-hook", "/usr/local/sbin/xmesh-tls-renew-hook",
        ], timeout=240)
    except subprocess.TimeoutExpired:
        return fail("ACME validation timed out; check DNS and external TCP/80")
    if result.returncode:
        return fail("ACME validation failed; verify that DNS points to this node and TCP/80 is reachable")
    if not cert.is_file() or not key.is_file():
        return fail("ACME returned success but certificate files are missing")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as exc:
        sys.exit(f"XMesh managed TLS error: {type(exc).__name__}")
