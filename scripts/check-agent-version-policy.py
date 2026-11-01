#!/usr/bin/env python3
"""Enforce the XMesh production Agent versioning contract.

On pull requests, pass the base ref/commit as argv[1]. Any change to deployed
Node/Agent runtime surfaces must increase AGENT_VERSION relative to that base.
The first PR that introduces AGENT_VERSION is treated as policy adoption.
"""
from pathlib import Path
import re
import subprocess
import sys

VERSION_RE = re.compile(r"^control-v([0-9]+)\.([0-9]+)\.([0-9]+)$")
RUNTIME_FILES = {
    "bootstrap.sh",
    "install.sh",
}


def parse_version(raw: str) -> tuple[int, int, int]:
    value = raw.strip()
    match = VERSION_RE.fullmatch(value)
    if match is None:
        raise SystemExit(f"invalid AGENT_VERSION: {value!r}")
    return tuple(int(part) for part in match.groups())


def git(*args: str, check: bool = True) -> str:
    proc = subprocess.run(
        ["git", *args], text=True, capture_output=True, check=False
    )
    if check and proc.returncode != 0:
        raise SystemExit(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout


def is_runtime(path: str) -> bool:
    if path in RUNTIME_FILES or path.startswith("agent/"):
        return True
    if path.startswith("deploy/"):
        name = path.removeprefix("deploy/")
        return not (name.startswith("test-") or name.endswith(".md"))
    return False


current_raw = Path("AGENT_VERSION").read_text(encoding="utf-8").strip()
current = parse_version(current_raw)

installer = Path("deploy/install-xsp-v2-production-agent.sh").read_text(encoding="utf-8")
if 'AGENT_VERSION_FILE="$ROOT/AGENT_VERSION"' not in installer:
    raise SystemExit("production Agent installer must source the canonical AGENT_VERSION file")


product = Path("agent/xspv2/cmd/xmesh-agent-xspv2-product/main.go").read_text(encoding="utf-8")
if "!validProductionVersion(version)" not in product:
    raise SystemExit("product runtime must validate canonical v6 production release versions")

product_installer = Path("deploy/install-xsp-v2-product-client.sh").read_text(encoding="utf-8")
if 'AGENT_VERSION_FILE="$ROOT/AGENT_VERSION"' not in product_installer or 'timeout 10 "$PRODUCT_STAGE" --identity' not in product_installer:
    raise SystemExit("product installer must source canonical AGENT_VERSION and verify identity from executable staging")

operational_installer = Path("deploy/install-v6-strict-operational-agents.sh").read_text(encoding="utf-8")
if ('AGENT_VERSION_FILE="$ROOT/AGENT_VERSION"' not in operational_installer
        or 'grep -Fq "AGENT_VERSION=' not in operational_installer
        or '$AGENT_VERSION' not in operational_installer):
    raise SystemExit("operational installer must require the canonical control-worker Agent version")

if len(sys.argv) > 1:
    base = sys.argv[1]
    changed = [
        line.strip()
        for line in git("diff", "--name-only", base, "HEAD").splitlines()
        if line.strip()
    ]
    runtime_files = [path for path in changed if is_runtime(path)]
    base_raw = git("show", f"{base}:AGENT_VERSION", check=False).strip()
    if base_raw:
        base_version = parse_version(base_raw)
        if current < base_version:
            raise SystemExit(
                f"Agent version regression: {current_raw} is older than {base_raw}"
            )
        if runtime_files and current <= base_version:
            raise SystemExit(
                "deployed Agent/runtime changed without an AGENT_VERSION bump: "
                f"base={base_raw}, current={current_raw}; runtime files: "
                + ", ".join(runtime_files)
            )
    elif runtime_files:
        print("Agent version policy adoption: canonical AGENT_VERSION introduced with runtime changes")

print(f"Agent version policy: {current_raw} OK")
