#!/usr/bin/env python3
"""Start a zero-authority first meter from the enrolled Nexus preview."""
import argparse
import os
from pathlib import Path
import stat
import time

import qualified_runtime_image as release
import quarantine_policy as quarantine
import wal_transport as wal

ROOT = Path("/var/lib/xmesh-first-meter")
STATE = "/var/lib/xmesh-xray-sync"
RUNTIME = wal.journal.RUNTIME_DEST
QUALIFICATION = str(release.QUALIFICATION)


def write_once(path, raw):
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or stream.read(len(raw) + 1) != raw):
                raise ValueError("first meter startup identity differs")
    else:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    parent = wal.journal._validate_directory(path.parent)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


def launch_meter(image_id, config, node, activation, key):
    tags = [inbound["tag"] for inbound in config["inbounds"]]
    if not 1 <= len(tags) <= 2 or len(set(tags)) != len(tags) or set(tags) - {"vless-main", "vless-cdn"}:
        raise ValueError("unsupported signed first meter scope")
    runtime = ROOT / "runtime"
    ledger = runtime / "ledger"
    for directory in (ROOT, runtime, ledger):
        directory.mkdir(mode=0o700, exist_ok=True)
        os.close(wal.journal._validate_directory(directory))
    if set(os.listdir(runtime)) - {"ledger", "cap-binding.json"} or os.listdir(ledger):
        raise ValueError("refusing to restart over existing meter evidence")
    config_path = ROOT / "config.json"
    write_once(config_path, wal.observed.canonical(config))
    write_once(runtime / "cap-binding.json", wal.observed.canonical({
        "nodeId": node, "policyPublicKey": key,
        "activationReceiptSha256": activation,
    }))
    release.docker("run", "-d", "--name", "xmesh-managed-xray",
                   "--network=none", "--restart=no", "--read-only", "--cap-drop=ALL",
                   "--security-opt=no-new-privileges", "--user=0:0",
                   "-v", f"{QUALIFICATION}:{QUALIFICATION}:ro",
                   "-v", f"{config_path}:/etc/xray/config.json:ro",
                   "-v", f"{runtime}:{RUNTIME}:rw",
                   "-e", "XMESH_QUOTA_V2_RUNTIME_ROLE=meter",
                   "-e", "XMESH_QUOTA_PRIVATE_VLESS=1",
                   "-e", "XMESH_EXPERIMENTAL_DRAIN=1",
                   "-e", "XMESH_EXPERIMENTAL_SCOPED_INBOUNDS=" + ",".join(tags),
                   "-e", f"XMESH_EXPERIMENTAL_OBSERVED_DIR={RUNTIME}/ledger",
                   "-e", f"XMESH_EXPERIMENTAL_DRAIN_SOCKET={RUNTIME}/drain.sock",
                   "-e", f"XMESH_EXPERIMENTAL_SIGNED_CAP_BINDING={RUNTIME}/cap-binding.json",
                   image_id, "run", "-config", "/etc/xray/config.json")
    deadline = time.monotonic() + 15
    while not (runtime / "drain.sock").is_socket():
        if time.monotonic() >= deadline:
            raise ValueError("qualified meter did not open its private control socket")
        time.sleep(0.1)


def start(panel, node):
    os.umask(0o077)
    record = release.read_identity(release.QUALIFICATION)
    Path(STATE).mkdir(mode=0o700, exist_ok=True)
    os.close(wal.journal._validate_directory(STATE))
    identity = quarantine._enrolled_activation(panel, node)
    # A service restart may find the original live process and durable receipt.
    # Never substitute a new process or a clean WAL for a committed runtime.
    fd, lock = quarantine._locked_private_state(STATE)
    try:
        try:
            original = quarantine._read_private(fd, "genesis-quarantine-envelope.json")
        except FileNotFoundError:
            original = None
        if original is not None:
            policy = original["reply"]["policy"]
            key = wal._panel_pin()
            quarantine._guard().check_signature(policy, original["reply"]["policySignature"], key)
            signed = policy["quotaV2Genesis"]
            if (policy["nodeId"] != node or signed["firstActivationReceiptSha256"] != identity["activationReceiptSha256"]
                    or policy["kind"] != "xmesh.quota-v2.genesis-quarantine-policy"):
                raise ValueError("stored Genesis belongs to another activation")
            measured = wal._measure_quarantined_runtime((record["artifactSha256"], policy["configSha256"]))
            if measured[3] != signed["runtimeId"]:
                raise ValueError("refusing to resume a different metering process")
            return
    finally:
        os.close(lock)
        os.close(fd)
    image = release.build_image()
    quarantine.preview_config(panel, node, STATE)
    fd, lock = quarantine._locked_private_state(STATE)
    try:
        identity = quarantine._enrolled_activation(panel, node)
        key = wal._panel_pin()
        preview = quarantine.validate_preview(
            wal.observed.canonical(quarantine._read_private(fd, quarantine.PREVIEW_FILE)),
            node, identity["activationReceiptSha256"], key)["payload"]
        names = release.docker("ps", "-a", "--filter", "name=^/xmesh-managed-xray$", "--format", "{{.Names}}").splitlines()
        if names:
            if names != [b"xmesh-managed-xray"]:
                raise ValueError("ambiguous first meter identity")
            wal._measure_quarantined_runtime((record["artifactSha256"], preview["configSha256"]))
        else:
            launch_meter(image["imageId"], preview["config"], node, identity["activationReceiptSha256"], key)
    finally:
        os.close(lock)
        os.close(fd)
    quarantine.request_quarantine(panel, node, STATE, image["artifactSha256"])


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel", required=True)
    parser.add_argument("--node", required=True, type=int)
    args = parser.parse_args()
    start(args.panel, args.node)
