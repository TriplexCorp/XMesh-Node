#!/usr/bin/env python3
"""Disposable real Docker/Xray witness for zero-authority measured genesis.

Runs only with explicit opt-in on a GitHub-hosted runner as root. This is NOT
an authorization of user ingress, a reservation or an end-to-end Nexus test.
The Xray container is on Docker's 'none' network for its entire lifetime.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "experiments/quota-v2-physical-stop"))
import wal_transport
import runtime_identity
import journal_integrity

NAME = "xmesh-managed-xray"
IMAGE = ("ghcr.io/xtls/xray-core:26.10.31@sha256:"
         "ceabeac03a89d991d2a247361825c1d1d2e9c91cd5dc010f298c7dc0c2f325c9")
CHALLENGE = "d" * 64


def docker(*args, check=True):
    return subprocess.run(["docker", *args], capture_output=True,
                          text=True, check=check, timeout=60)


def stopped_or_rejected(fn, text):
    try:
        fn()
    except ValueError as exc:
        assert text in str(exc), (text, str(exc))
    else:
        raise AssertionError("Expected measured candidate to be rejected")


def main():
    assert os.geteuid() == 0
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.environ.get("XMESH_DISPOSABLE_MEASURED_GENESIS") == "1"
    docker("info")
    assert docker("inspect", "--type", "container", NAME, check=False).returncode != 0, (
        "Refusing to touch a preexisting managed Xray"
    )
    created = False
    with tempfile.TemporaryDirectory(prefix="quota-v2-measured-real-xray-") as temp:
        root = Path(temp)
        journal = root / "journal"
        journal.mkdir(mode=0o700)
        config = root / "config.json"
        config.write_text(json.dumps({
            "log": {"loglevel": "warning"},
            "inbounds": [],
            "outbounds": [{"protocol": "blackhole"}],
        }), encoding="utf-8")
        config.chmod(0o600)
        try:
            docker("run", "-d", "--name", NAME, "--network", "none",
                   "--restart", "no", "--read-only", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges",
                   "--user", "0:0",
                   "-v", str(config) + ":/etc/xray/config.json:ro",
                   "-v", str(journal) + ":" + journal_integrity.JOURNAL_DEST + ":rw",
                   "--entrypoint", "xray",
                   IMAGE, "run", "-config", "/etc/xray/config.json")
            created = True
            # Print only isolation metadata, never the config or keys.
            inspected = json.loads(docker("inspect", NAME).stdout)[0]
            h = inspected["HostConfig"]
            print("ISOLATION_DIAGNOSTIC=" + json.dumps({
                "networkMode": h.get("NetworkMode"),
                "privileged": h.get("Privileged"),
                "pidMode": h.get("PidMode"),
                "ipcMode": h.get("IpcMode"),
                "capAdd": h.get("CapAdd"),
                "capDrop": h.get("CapDrop"),
                "securityOpt": h.get("SecurityOpt"),
                "readonlyRoot": h.get("ReadonlyRootfs"),
                "devicesCount": len(h.get("Devices") or []),
                "mounts": sorted([
                    {"destination": m.get("Destination"), "type": m.get("Type")}
                    for m in inspected.get("Mounts", [])],
                    key=lambda m: str(m["destination"])),
            }, sort_keys=True), flush=True)
            deadline = time.monotonic() + 15
            while True:
                try:
                    identity = wal_transport._measure_quarantined_runtime()
                    break
                except ValueError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.25)
            cid, started, pid, fingerprint = identity
            assert len(cid) == 64 and len(fingerprint) == 64
            assert fingerprint == runtime_identity.trusted_runtime_identity(pid)
            assert runtime_identity.inspect_managed_xray() == (cid, started, pid)
            evidence = docker("inspect", NAME).stdout
            parsed = json.loads(evidence)[0]
            assert parsed["HostConfig"]["NetworkMode"] == "none"
            assert parsed["HostConfig"]["RestartPolicy"]["Name"] == "no"
            assert not parsed["HostConfig"].get("PortBindings")
            # An actual kernel/Docker verified PID must be passed to Nexus,
            # NOT an arbitrary caller-provided candidate fingerprint.
            dummy = {"algorithm": "Ed25519", "payload": {
                "authorizedBytes": 0, "canStart": False, "canResume": False}}
            with mock.patch.object(wal_transport, "prepare_genesis",
                                   return_value=dummy) as remote:
                got = wal_transport.prepare_measured_genesis(
                    "https://disposable.invalid", 42, CHALLENGE)
            assert got is dummy
            remote.assert_called_once_with(
                "https://disposable.invalid", 42, fingerprint, CHALLENGE)
            print("PASS: real Xray PID/pidfd bound to a no-network, no-restart candidate", flush=True)

            # Docker normally disallows attaching another network to a
            # container created with --network none. Independently verify
            # that a real bridged Xray cannot pass the measured candidate
            # check, without trying to circumvent Docker isolation.
            docker("stop", "-t", "1", NAME)
            stopped_or_rejected(
                wal_transport._measure_quarantined_runtime,
                "network-isolated")
            print("PASS: stopped Xray cannot replay an old measured runtime", flush=True)
            docker("rm", NAME)
            created = False
            docker("run", "-d", "--name", NAME, "--network", "bridge",
                   "--restart", "no", "--read-only", "--cap-drop", "ALL",
                   "--security-opt", "no-new-privileges", "--user", "0:0",
                   "-v", str(config) + ":/etc/xray/config.json:ro",
                   "-v", str(journal) + ":" + journal_integrity.JOURNAL_DEST + ":rw",
                   "--entrypoint", "xray", IMAGE, "run", "-config", "/etc/xray/config.json")
            created = True
            stopped_or_rejected(
                wal_transport._measure_quarantined_runtime,
                "network-isolated")
            print("PASS: real network-attached Xray cannot prepare genesis", flush=True)
        finally:
            if created:
                docker("rm", "-f", NAME, check=False)


if __name__ == "__main__":
    main()
