#!/usr/bin/env python3
"""Bounded HTTPS GeoData acquisition for signed XMesh node-policy manifests.

Runs exclusively on the node. No URLs or paths may be selected by untrusted
Xray client traffic. The caller verifies the signed policy with policy-guard
BEFORE invoking prepare. A failed refresh never overwrites the active dataset.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import time
from urllib.parse import urljoin, urlsplit

MAX_FILE_BYTES = 50 * 1024 * 1024
MAX_REDIRECTS = 4
DEFAULT_UPDATE_HOURS = 24
SYSTEM_CURL = "/usr/bin/curl"
FILE_RE = re.compile(r"^[A-Za-z0-9_-]{1,48}\.dat$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
STATE_NAMES = {"assets", "assets.previous", "assets.next", "geo-status.json", "geo-changed"}


def fail(message):
    raise ValueError(message)


def persist_json(path, obj):
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8") as stream:
        json.dump(obj, stream, sort_keys=True)
    os.chmod(temp, 0o600)
    os.replace(temp, path)


def public_destination(raw):
    if not isinstance(raw, str) or not raw.startswith("https://") or len(raw) > 1024:
        fail("Only bounded HTTPS GeoData URLs are allowed.")
    parsed = urlsplit(raw)
    if parsed.scheme != "https" or parsed.username or parsed.password or parsed.fragment:
        fail("GeoData URL has invalid scheme, credentials or fragment.")
    if parsed.port not in (None, 443) or not parsed.hostname:
        fail("GeoData HTTPS port must be 443.")
    host = parsed.hostname.lower()
    if host in ("localhost",) or host.endswith((".local", ".internal")):
        fail("Local DNS names are denied.")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if "." not in host or not re.fullmatch(r"[a-z0-9.-]{3,253}", host):
            fail("GeoData needs a public DNS hostname.")
    else:
        fail("GeoData literal IP destinations are denied.")
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    ips = list(dict.fromkeys(entry[4][0] for entry in addresses))
    if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
        fail("GeoData hostname resolves to a private or reserved network.")
    return host, ips[0]


def fetch_url(url, target):
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        host, ip = public_destination(current)
        address = f"[{ip}]" if ":" in ip else ip
        headers = target.with_suffix(".headers")
        try:
            # Operational panel POSTs intentionally resolve `curl` through the
            # strict-PQ PATH adapter. GeoData is a separately bounded external
            # HTTPS fetch from a verified signed policy, so it must invoke the
            # real system curl explicitly instead of inheriting that adapter.
            command = [
                SYSTEM_CURL, "--silent", "--show-error", "--noproxy", "*",
                "--proto", "=https", "--tlsv1.2", "--max-time", "60",
                "--connect-timeout", "12", "--max-filesize", str(MAX_FILE_BYTES),
                "--max-redirs", "0", "--resolve", f"{host}:443:{address}",
                "--dump-header", str(headers), "--output", str(target),
                "--write-out", "%{http_code}", current
            ]
            completed = subprocess.run(command, capture_output=True, text=True, timeout=70)
            if completed.returncode:
                fail("GeoData HTTPS download failed: " + completed.stderr.strip()[:200])
            status = int(completed.stdout.strip())
            if status == 200:
                size = target.stat().st_size
                if not (16 <= size <= MAX_FILE_BYTES):
                    fail("GeoData file is empty or exceeds the 50 MiB limit.")
                return
            if status not in (301, 302, 303, 307, 308):
                fail(f"GeoData source returned HTTP {status}.")
            # Resolve redirects explicitly. Every redirect is HTTPS-only,
            # DNS-validated and pinned to a verified public address.
            locations = [
                line.split(":", 1)[1].strip() for line in
                headers.read_text("iso-8859-1").splitlines()
                if line.lower().startswith("location:")
            ]
            if not locations:
                fail("GeoData redirect has no Location.")
            current = urljoin(current, locations[-1])
        finally:
            headers.unlink(missing_ok=True)
    fail("GeoData source exceeded maximum redirects.")


def checksum(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def prepare(state, response):
    # The call site MUST run this only after successful offline-policy guard
    # verification; the guard validates the signed policy and config digest.
    with response.open("r", encoding="utf-8") as stream:
        policy = json.load(stream).get("policy", {})
    manifest = policy.get("geoData")
    if manifest is None:
        return
    if not isinstance(manifest, dict) or manifest.get("version") != 1:
        fail("Unrecognized signed GeoData manifest.")
    hours = manifest.get("intervalHours", DEFAULT_UPDATE_HOURS)
    if isinstance(hours, bool) or not isinstance(hours, int) or not 6 <= hours <= 168:
        fail("Invalid GeoData interval.")
    refresh_revision = manifest.get("refreshRevision", 0)
    if type(refresh_revision) is not int or not 0 <= refresh_revision <= 9223372036854775807:
        fail("Invalid signed GeoData refresh revision.")
    sources = manifest.get("files")
    if not isinstance(sources, list) or not 1 <= len(sources) <= 10:
        fail("Invalid GeoData source list.")
    entries = []
    names = set()
    for source in sources:
        if not isinstance(source, dict):
            fail("Invalid signed GeoData source.")
        name = source.get("name")
        if not isinstance(name, str) or not FILE_RE.fullmatch(name) or name in names:
            fail("Unsafe GeoData filename or duplicate.")
        names.add(name)
        url = source.get("url")
        if not isinstance(url, str):
            fail("Missing GeoData URL.")
        sha = source.get("sha256")
        if sha is not None and (not isinstance(sha, str) or not SHA_RE.fullmatch(sha)):
            fail("Invalid GeoData SHA-256.")
        entries.append((name, url, sha))
    active = state / "assets"
    status_file = state / "geo-status.json"
    status = {}
    if status_file.exists():
        try:
            status = json.loads(status_file.read_text("utf-8"))
        except (ValueError, OSError):
            status = {}
    signature = hashlib.sha256(json.dumps({"files": entries, "refreshRevision": refresh_revision}, sort_keys=True).encode()).hexdigest()
    now = int(time.time())
    if (status.get("manifestHash") == signature
            and now - status.get("checkedAt", 0) < hours * 3600
            and all((active / name).is_file() for name, _, _ in entries)):
        return
    next_dir = state / "assets.next"
    if next_dir.exists():
        shutil.rmtree(next_dir)
    next_dir.mkdir(mode=0o700)
    try:
        for name, url, sha in entries:
            output = next_dir / name
            fetch_url(url, output)
            if sha and checksum(output) != sha:
                fail("GeoData SHA-256 mismatch for " + name)
            os.chmod(output, 0o600)
        digests = {name: checksum(next_dir / name) for name, _, _ in entries}
        changed = (not active.is_dir()
                   or sorted(p.name for p in active.glob("*.dat")) != sorted(digests)
                   or any(checksum(active / name) != digest for name, digest in digests.items()))
        if changed:
            previous = state / "assets.previous"
            if previous.exists():
                # A failed previous deployment must not silently lose rollback.
                fail("Uncommitted GeoData update exists; run rollback first.")
            if active.exists():
                os.rename(active, previous)
            os.rename(next_dir, active)
            (state / "geo-changed").write_text("pending", encoding="utf-8")
        else:
            shutil.rmtree(next_dir)
        persist_json(status_file, {
            "state": "pending" if changed else "current",
            "manifestHash": signature, "refreshRevision": refresh_revision,
            "checkedAt": now, "files": digests,
            "lastError": None
        })
    except Exception as exc:
        if next_dir.exists():
            shutil.rmtree(next_dir)
        persist_json(status_file, {
            **status, "state": "error", "lastError": str(exc)[:220],
        })
        # If downloads fail, preserve the last verified data only if every
        # required dataset already exists. Never deploy unvalidated new rules.
        if not all((active / name).is_file() for name, _, _ in entries):
            raise
        print("GeoData refresh failed; retaining previously installed assets:", exc, file=sys.stderr)


def finish(state, rollback=False):
    previous = state / "assets.previous"
    active = state / "assets"
    marker = state / "geo-changed"
    status_file = state / "geo-status.json"
    if rollback:
        if previous.exists():
            if active.exists():
                shutil.rmtree(active)
            os.rename(previous, active)
        elif marker.exists() and active.exists():
            shutil.rmtree(active)
    elif previous.exists():
        shutil.rmtree(previous)
    marker.unlink(missing_ok=True)
    if status_file.exists():
        status = json.loads(status_file.read_text("utf-8"))
        if rollback:
            status["state"] = "rolled_back"
            status["checkedAt"] = 0
        elif status.get("state") == "pending":
            status["state"] = "current"
        persist_json(status_file, status)


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        sys.exit("usage: xmesh-geodata-sync.py prepare|commit|rollback STATE [verified-response.json]")
    action = sys.argv[1]
    state = Path(sys.argv[2]).resolve()
    if not state.is_dir() or state.is_symlink():
        sys.exit("Invalid managed state directory")
    try:
        if action == "prepare" and len(sys.argv) == 4:
            prepare(state, Path(sys.argv[3]))
        elif action in ("commit", "rollback") and len(sys.argv) == 3:
            finish(state, rollback=action == "rollback")
        else:
            sys.exit("Invalid GeoData action")
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        sys.exit("GeoData: " + str(exc)[:240])
