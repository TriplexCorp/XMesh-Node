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
                    {"destination": m.get("Destination"), "type": m.get("Type"),
                     "driver": m.get("Driver"),
                     "anonymousName64": bool(
                         isinstance(m.get("Name"), str) and
                         len(m["Name"]) == 64 and
                         all(ch in "0123456789abcdef" for ch in m["Name"]))}
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

            # A second, genuinely independently measured successor Xray is
            # required. Merely relabeling the same PID, Docker container,
            # runtime digest or WAL bind cannot create a new quota epoch.
            successor = "xmesh-successor-quarantine"
            assert docker("inspect", "--type", "container", successor,
                          check=False).returncode != 0, (
                "Refusing to touch an existing successor Xray"
            )
            successor_journal = root / "successor-journal"
            successor_journal.mkdir(mode=0o700)
            successor_created = False
            try:
                docker("run", "-d", "--name", successor, "--network", "none",
                       "--restart", "no", "--read-only", "--cap-drop", "ALL",
                       "--security-opt", "no-new-privileges", "--user", "0:0",
                       "-v", str(config) + ":/etc/xray/config.json:ro",
                       "-v", str(successor_journal) + ":" +
                           journal_integrity.JOURNAL_DEST + ":rw",
                       "--entrypoint", "xray",
                       IMAGE, "run", "-config", "/etc/xray/config.json")
                successor_created = True
                until = time.monotonic() + 15
                while True:
                    try:
                        fresh = wal_transport._measure_quarantined_runtime(
                            container_name=successor)
                        break
                    except ValueError:
                        if time.monotonic() >= until:
                            raise
                        time.sleep(0.25)
                assert fresh[0] != cid and fresh[1] != started
                assert fresh[2] != pid and fresh[3] != fingerprint
                assert fresh[3] == runtime_identity.trusted_runtime_identity(fresh[2])
                assert runtime_identity.inspect_managed_xray(successor) == fresh[:3]
                # A new Docker process ID alone is not enough. Re-measure
                # the live kernel executable and the ACTUAL config mounted
                # into this independent process before accepting its proof.
                with open(f"/proc/{fresh[2]}/exe", "rb") as binary:
                    executable_sha = hashlib.file_digest(binary, "sha256").hexdigest()
                config_sha = hashlib.sha256(config.read_bytes()).hexdigest()
                assert wal_transport._measure_quarantined_runtime(
                    pins=(executable_sha, config_sha),
                    container_name=successor) == fresh
                _, old_journal = wal_transport._bound_journal()
                _, separate_journal = wal_transport._bound_journal(successor)
                old_stat, fresh_stat = os.stat(old_journal), os.stat(separate_journal)
                assert (old_stat.st_dev, old_stat.st_ino) != (
                    fresh_stat.st_dev, fresh_stat.st_ino)
                assert old_journal != separate_journal
                assert not any(name.startswith("meter-") or
                               name.startswith("xmesh-meter-inventory-")
                               for name in os.listdir(separate_journal))
                assert wal_transport._measure_quarantined_runtime() == identity
                stopped_or_rejected(
                    lambda: wal_transport._measure_quarantined_runtime(
                        container_name="arbitrary-container"),
                    "unknown measured Xray")
                docker("stop", "-t", "1", successor)
                stopped_or_rejected(
                    lambda: wal_transport._measure_quarantined_runtime(
                        container_name=successor),
                    "network-isolated")
                print("PASS: two separate hardened Xray runtimes, Docker/PID fingerprints and private empty successor WAL", flush=True)
            finally:
                if successor_created:
                    docker("rm", "-f", successor, check=False)

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
