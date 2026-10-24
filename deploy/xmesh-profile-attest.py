#!/usr/bin/env python3
"""Read-only attestation of an actually running XMesh-managed Xray config.

Policy envelope is verified by xmesh-policy-guard before commit; only read it,
never accept unsigned remote revision claims. No secrets leave this process.
"""
import hashlib
import json
import pathlib
import re
import subprocess
import sys

STATE = pathlib.Path("/var/lib/xmesh-xray-sync")
ACTIVE = STATE / "config.json"
ENVELOPE = STATE / "policy-envelope.json"

def main():
    try:
        envelope = json.loads(ENVELOPE.read_text())
        revision = envelope["policy"]["configSha256"]
        if not isinstance(revision, str) or not re.fullmatch(r"[0-9a-f]{64}", revision):
            return 1
        config = json.loads(ACTIVE.read_text())
        canonical = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
        if hashlib.sha256(canonical).hexdigest() != revision:
            return 1
        proc = subprocess.run(
            ["docker", "inspect", "xmesh-managed-xray"],
            check=True, capture_output=True, text=True, timeout=5,
        )
        item = json.loads(proc.stdout)[0]
        if item.get("State", {}).get("Running") is not True:
            return 1
        mounts = item.get("Mounts", [])
        if not any(
            mount.get("Destination") == "/etc/xray/config.json"
            and pathlib.Path(mount.get("Source", "")).resolve() == ACTIVE.resolve()
            and mount.get("RW") is False
            for mount in mounts
        ):
            return 1
        print(revision)
        return 0
    except (OSError, ValueError, KeyError, IndexError, subprocess.SubprocessError):
        return 1

if __name__ == "__main__":
    sys.exit(main())
