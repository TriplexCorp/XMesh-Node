#!/usr/bin/env python3
"""Linux process-bound runtime identity for disposable Xray evidence.

The expected host PID MUST be independently obtained (e.g., from trusted
Docker inspect of the currently managed container). Never take a PID from a
claim, checkpoint or untrusted HTTP request. A matching identity proves only
that the observed Xray process is currently alive, NOT that writers stopped.
"""
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import select
import stat
import subprocess

DOMAIN = b"XMESH_XRAY_RUNTIME_PROC_V1\x00"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z")
NS = re.compile(r"pid:\[[0-9]+\]\Z")


def _runtime_fields(host_pid):
    if type(host_pid) is not int or host_pid <= 0:
        raise ValueError("trusted host PID must be a positive integer")
    proc = Path("/proc") / str(host_pid)
    # All data are read from the Linux kernel's trusted procfs, not from
    # the evidence sender. The process start tick and namespace distinguish
    # replacement processes even when an OS reuses a numeric PID.
    stat_line = (proc / "stat").read_text(encoding="ascii")
    end = stat_line.rfind(")")
    if end < 0 or end + 2 >= len(stat_line):
        raise ValueError("invalid Linux process stat")
    if stat_line.split(" ", 1)[0] != str(host_pid):
        raise ValueError("Linux procfs host PID was substituted")
    fields = stat_line[end + 2:].split()
    if len(fields) <= 19:
        raise ValueError("missing Linux process start ticks")
    ticks = fields[19]
    if not ticks.isdecimal() or int(ticks) <= 0:
        raise ValueError("invalid Linux process start ticks")
    boot = Path("/proc/sys/kernel/random/boot_id").read_text(
        encoding="ascii").strip()
    if UUID.fullmatch(boot) is None:
        raise ValueError("invalid Linux kernel boot identifier")
    namespace = os.readlink(proc / "ns/pid")
    if NS.fullmatch(namespace) is None:
        raise ValueError("invalid Linux PID namespace identifier")
    status = (proc / "status").read_text(encoding="ascii")
    ns_lines = [line for line in status.splitlines()
                if line.startswith("NSpid:")]
    if len(ns_lines) != 1:
        raise ValueError("Linux NSpid chain missing")
    chain = ns_lines[0].split()[1:]
    if not chain or not all(item.isdecimal() and int(item) > 0
                            for item in chain):
        raise ValueError("invalid Linux PID namespace chain")
    if len(chain) > 1 and int(chain[0]) != host_pid:
        raise ValueError("unexpected Linux host PID namespace")
    inner_pid = chain[-1]
    executable = os.stat(proc / "exe")
    if executable.st_ino <= 0:
        raise ValueError("invalid runtime executable inode")
    return (boot, namespace, inner_pid, ticks,
            str(executable.st_dev), str(executable.st_ino))


def trusted_runtime_identity(host_pid):
    """Fingerprint a live Linux process, pinned with a pidfd against exit.

    With no independently trusted PID (or no pidfd support), fail closed.
    An attacker-supplied matching hash or Node heartbeat is not sufficient.
    """
    if type(host_pid) is not int or host_pid <= 0:
        raise ValueError("invalid trusted Xray host PID")
    if not hasattr(os, "pidfd_open"):
        raise ValueError("kernel pidfd support required for runtime proof")
    pidfd = os.pidfd_open(host_pid, 0)
    try:
        first = _runtime_fields(host_pid)
        second = _runtime_fields(host_pid)
        poll = select.poll()
        poll.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if first != second or poll.poll(0):
            raise ValueError("Xray process changed or exited during identity check")
        payload = DOMAIN + "\n".join(first).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()
    finally:
        os.close(pidfd)


def verify_live_runtime(checkpoint, trusted_host_pid):
    if not isinstance(checkpoint, dict):
        raise ValueError("invalid Xray checkpoint for runtime proof")
    claimed = checkpoint.get("runtimeId")
    if not isinstance(claimed, str) or HEX64.fullmatch(claimed) is None:
        raise ValueError("invalid claimed Xray runtime fingerprint")
    actual = trusted_runtime_identity(trusted_host_pid)
    if not hmac.compare_digest(actual, claimed):
        raise ValueError("Xray runtime is not the independently verified live process")
    return True


def verify_quarantined_files(host_pid, executable_sha256, config_sha256):
    """Check the pinned executable and the actual isolated process's config."""
    proc = Path("/proc") / str(host_pid)
    config = "/etc/xray/config.json"
    cmdline = (proc / "cmdline").read_bytes().split(b"\0")
    if len(cmdline) != 5 or cmdline[1:] != [b"run", b"-config", config.encode(), b""]:
        raise ValueError("unexpected managed Xray command line")
    for path, expected, limit in (
        (proc / "exe", executable_sha256, 256 << 20),
        (proc / "root" / config[1:], config_sha256, 2 << 20),
    ):
        # /proc/<pid>/exe is intentionally resolved by the kernel; the
        # configuration must be a regular, non-symlink file in that root.
        nofollow = 0 if path.name == "exe" else os.O_NOFOLLOW
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | nofollow)
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_nlink < 1 or not 0 < before.st_size <= limit:
                raise ValueError("managed Xray file is not a bounded regular file")
            digest = hashlib.file_digest(source, "sha256").hexdigest()
            after = os.fstat(source.fileno())
            if ((before.st_size, before.st_mtime_ns, before.st_ctime_ns) !=
                    (after.st_size, after.st_mtime_ns, after.st_ctime_ns) or
                    not hmac.compare_digest(digest, expected)):
                raise ValueError("managed Xray executable or configuration pin mismatch")


def managed_container_name(name):
    return (name in ("xmesh-managed-xray", "xmesh-successor-quarantine")
            or re.fullmatch(r"xmesh-quota-u[1-9][0-9]{0,18}-[0-9a-f]{32}", name) is not None)


def inspect_managed_xray(container_name="xmesh-managed-xray"):
    """Independently obtain the currently RUNNING container's host PID.

    Never accept a PID, start time, container ID or image name from the
    checkpoint. Docker is authoritative only for process discovery here; it
    is NOT a kernel byte-drain/physical-stop attestation.
    """
    if not managed_container_name(container_name):
        raise ValueError("untrusted Xray runtime container selection")
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{json .}}",
             container_name],
            capture_output=True, text=True, timeout=5, check=True)
        if not isinstance(result.stdout, str) or not 0 < len(result.stdout) < 1_000_000:
            raise ValueError("invalid Docker inspect output size")
        data = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise ValueError("trusted Docker managed Xray inspect unavailable") from exc
    if not isinstance(data, dict) or data.get("Name") != "/" + container_name:
        raise ValueError("unexpected managed Xray container name")
    cid = data.get("Id")
    state = data.get("State")
    if not isinstance(cid, str) or HEX64.fullmatch(cid) is None or (
            not isinstance(state, dict) or state.get("Running") is not True):
        raise ValueError("managed Xray is not an authenticated running container")
    pid = state.get("Pid")
    started = state.get("StartedAt")
    if type(pid) is not int or pid <= 0 or (
            not isinstance(started, str) or "T" not in started or
            started.startswith("0001-01-01")):
        raise ValueError("invalid managed Xray process or start time")
    return (cid, started, pid)


def verify_managed_xray_runtime(checkpoint):
    """Double-inspect Docker around a kernel pidfd verification.

    Caller does not get to specify the PID. If Docker replaces the container
    while stats are sampled, signed evidence is refused. This validates
    process provenance, NOT whether the physical dataplane has drained.
    """
    before = inspect_managed_xray()
    verify_live_runtime(checkpoint, before[2])
    after = inspect_managed_xray()
    if before != after:
        raise ValueError("managed Xray Docker runtime replaced during verification")
    return True
