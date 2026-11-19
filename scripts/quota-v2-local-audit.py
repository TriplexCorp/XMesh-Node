#!/usr/bin/env python3
"""Read-only per-VPS v1/v2 cutover inventory; never a fleet activation permit."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

VERSION = "control-v6.0.21"
STATE = Path("/var/lib/xmesh-xray-sync")
CONTROL = Path("/usr/local/sbin/xmesh-node-control")
ATTEST = Path("/usr/local/libexec/xmesh-profile-attest.py")
ID_FILE = Path("/var/lib/xmesh-agent/v6-production-identity.json")
BINS = {
    "activation": Path("/usr/local/bin/xmesh-agent-xspv2-activate"),
    "product": Path("/usr/local/bin/xmesh-agent-xspv2-product"),
}


def owned_regular(path):
    try:
        s = path.lstat()
        return (stat.S_ISREG(s.st_mode) and s.st_uid == 0
                and s.st_nlink == 1 and not s.st_mode & 0o022)
    except OSError:
        return False


def read_json(path):
    if not owned_regular(path) or path.stat().st_size > 4_194_304:
        raise ValueError("untrusted root-owned JSON file")
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def run(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=8, check=False)


def digest_file(path):
    if not owned_regular(path):
        raise ValueError("untrusted local executable")
    sha = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def verify_binary_manifest():
    manifest = read_json(ID_FILE)
    if (not isinstance(manifest, dict) or manifest.get("version") != VERSION
            or manifest.get("strictPQCapable") is not True
            or manifest.get("strictPQRequired") is not True
            or manifest.get("automaticClassicalFallback") is not False
            or not isinstance(manifest.get("sourceRevision"), str)
            or not re.fullmatch(r"[a-f0-9]{40}", manifest["sourceRevision"])):
        return False
    for kind, path in BINS.items():
        digest = digest_file(path)
        if manifest.get(kind + "ArtifactSha256") != digest:
            return False
        result = run([str(path), "--identity"])
        if result.returncode != 0 or len(result.stdout) > 4096:
            return False
        try:
            identity = json.loads(result.stdout)
        except ValueError:
            return False
        if identity != {"version": VERSION,
                        "sourceRevision": manifest["sourceRevision"],
                        "artifactSha256": digest}:
            return False
    return True


def evaluate(policy, profile_attested, control_current, binaries_verified,
             native_services, now_ms):
    """Pure cutover verdict: this host's managed v2 state ONLY, never the fleet."""
    reasons = []
    version = policy.get("version") if isinstance(policy, dict) else None
    if type(version) is not int or version not in (1, 2):
        reasons.append("signed_policy_missing_or_invalid")
        version = None
    possible_legacy_budget = False
    if version == 1:
        users = policy.get("users")
        expiry = policy.get("validUntilMs")
        if not isinstance(users, list) or type(expiry) is not int:
            reasons.append("legacy_policy_malformed")
        else:
            possible_legacy_budget = now_ms < expiry and any(
                isinstance(user, dict)
                and type(user.get("limitBytes")) is int and user["limitBytes"] > 0
                and type(user.get("offlineBudgetBytes")) is int
                and user["offlineBudgetBytes"] > 0 for user in users)
        reasons.append("committed_v1_signed_policy")
    if not profile_attested:
        reasons.append("running_xray_not_verified_against_signed_policy")
    if not control_current:
        reasons.append("installed_control_worker_version_unverified")
    if not binaries_verified:
        reasons.append("strict_pq_binary_identity_unverified")
    for service, state in native_services.items():
        if state != "inactive":
            reasons.append("legacy_or_unverifiable_" + service.replace(".", "_"))
    return {
        "localPolicyVersion": version,
        "potentialLiveV1OfflineBudget": possible_legacy_budget,
        "localV2AppliedVerified": version == 2 and not reasons,
        "allLegacyCopiesRetiredVerified": False,
        "fleetActivationAuthorized": False,
        "finalMeterVerified": False,
        "refundableBytes": 0,
        "blockers": sorted(set(reasons)),
    }


def inspect_local():
    problems = []
    policy = None
    signed = None
    if os.geteuid() != 0:
        problems.append("requires_root")
    try:
        state = STATE.lstat()
        if not stat.S_ISDIR(state.st_mode) or state.st_uid != 0 or state.st_mode & 0o077:
            raise ValueError("unsafe state directory")
        signed = read_json(STATE / "policy-envelope.json")
        if not isinstance(signed, dict):
            raise ValueError("invalid policy envelope")
        policy = signed.get("policy")
    except (OSError, ValueError, TypeError, KeyError):
        problems.append("committed_signed_policy_unavailable")
    control = False
    try:
        if owned_regular(CONTROL) and CONTROL.stat().st_size < 1024 * 1024:
            control = f'AGENT_VERSION="{VERSION}"' in CONTROL.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        pass
    attested = False
    try:
        if owned_regular(ATTEST):
            response = run([sys.executable, str(ATTEST), "--json"])
            if response.returncode == 0 and len(response.stdout) <= 4096:
                data = json.loads(response.stdout)
                # Bind the attestor's live running config digest to the exact
                # policy bytes seen here. Re-read after inspection: a
                # concurrent signed-policy replacement must not make two
                # independently consistent snapshots look like one.
                attested = (isinstance(data, dict)
                            and data.get("status") == "verified"
                            and isinstance(policy, dict)
                            and data.get("revision") == policy.get("configSha256")
                            and read_json(STATE / "policy-envelope.json") == signed)
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    verified_bins = False
    try:
        verified_bins = verify_binary_manifest()
    except (OSError, ValueError, TypeError, subprocess.SubprocessError):
        pass
    services = {}
    for service in ("xray.service", "v2ray.service"):
        try:
            result = run(["systemctl", "is-active", "--quiet", service])
            services[service] = ("active" if result.returncode == 0 else
                                 "inactive" if result.returncode in (3, 4) else "unknown")
        except (OSError, subprocess.SubprocessError):
            services[service] = "unknown"
    status = evaluate(policy, attested, control, verified_bins,
                      services, int(time.time() * 1000))
    status["blockers"] = sorted(set(status["blockers"] + problems))
    status["localV2AppliedVerified"] &= not problems
    return status


def main():
    parser = argparse.ArgumentParser(description="Read-only local XMesh v1/v2 cutover check")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    status = inspect_local()
    if args.json:
        print(json.dumps(status, separators=(",", ":"), sort_keys=True))
    else:
        print("Managed local v2 applied:", "YES" if status["localV2AppliedVerified"] else "NO")
        print("Blockers:", ", ".join(status["blockers"]) or "none")
        print("This is NOT permission to activate v2 fleet-wide.")
    return 0 if status["localV2AppliedVerified"] else 1


if __name__ == "__main__":
    sys.exit(main())
