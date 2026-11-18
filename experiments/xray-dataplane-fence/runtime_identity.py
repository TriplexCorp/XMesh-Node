#!/usr/bin/env python3
"""Linux process-bound runtime identity for disposable Xray evidence.

The expected host PID MUST be independently obtained (e.g., from trusted
Docker inspect of the currently managed container). Never take a PID from a
claim, checkpoint or untrusted HTTP request. A matching identity proves only
that the observed Xray process is currently alive, NOT that writers stopped.
"""
import hashlib
import hmac
import os
from pathlib import Path
import re
import select

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
