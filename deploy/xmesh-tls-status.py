#!/usr/bin/env python3
"""Read-only TLS certificate health for signed node heartbeat. Never read private keys."""
import datetime as dt
import json
from pathlib import Path
import re
import subprocess

ACTIVE = Path("/var/lib/xmesh-xray-sync/config.json")
DOMAIN = re.compile(r"^[a-z0-9.-]{1,253}$")


def inspect():
    try:
        config = json.loads(ACTIVE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"state": "unknown", "autoRenew": False}
    certs = [c.get("certificateFile") for i in config.get("inbounds", [])
             for c in i.get("streamSettings", {}).get("tlsSettings", {}).get("certificates", [])]
    if not certs:
        return {"state": "not_configured", "autoRenew": False}
    if len(set(certs)) != 1 or not isinstance(certs[0], str):
        return {"state": "multiple", "autoRenew": False}
    cert = Path(certs[0])
    domain = cert.parent.name
    managed = (cert.parent.parent == Path("/etc/letsencrypt/live")
               and cert.name == "fullchain.pem" and bool(DOMAIN.fullmatch(domain)))
    result = {"state": "unknown", "autoRenew": False}
    if managed:
        result["domain"] = domain
        # A timer being installed does not guarantee future renewals will succeed.
        result["autoRenew"] = (Path("/etc/systemd/system/timers.target.wants/certbot.timer").exists()
                               or Path("/lib/systemd/system/certbot.timer").exists()
                               or Path("/usr/lib/systemd/system/certbot.timer").exists())
    if not cert.is_file():
        result["state"] = "missing"
        result["lastError"] = "certificate_file_missing"
        return result
    try:
        output = subprocess.run(["openssl", "x509", "-in", str(cert), "-noout",
                                 "-startdate", "-enddate", "-issuer"],
                                capture_output=True, text=True, timeout=5, check=True).stdout
        fields = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
        parse = lambda x: dt.datetime.strptime(x, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=dt.timezone.utc)
        before, after = parse(fields["notBefore"]), parse(fields["notAfter"])
        days = int((after - dt.datetime.now(dt.timezone.utc)).total_seconds() // 86400)
        result.update({"issuer": fields.get("issuer", "")[:180],
                       "notBefore": before.isoformat(), "notAfter": after.isoformat(),
                       "daysRemaining": days,
                       "state": "expired" if days < 0 else "expiring" if days < 14 else "valid"})
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        result["state"] = "error"
        result["lastError"] = "certificate_parse_failed"
    return result


if __name__ == "__main__":
    print(json.dumps(inspect(), separators=(",", ":")))
