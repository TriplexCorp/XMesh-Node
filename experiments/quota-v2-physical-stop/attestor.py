#!/usr/bin/env python3
"""CI-only kernel/Docker physical-stop observation. NEVER a terminal byte receipt.

A pidfd opened *before* the production stop command proves that exact old
process exited. Docker must show the same container permanently stopped,
restart policy disabled, and the real production root-private deny marker
still armed. No Xray StatsService final counter is proven by these checks.
"""
import json
import os
from pathlib import Path
import re
import select
import subprocess

CONTAINER = "xmesh-managed-xray"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


def inspect_managed():
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{json .}}", CONTAINER],
            check=True, capture_output=True, text=True, timeout=5)
        if not 0 < len(result.stdout) <= 200_000:
            raise ValueError("invalid Docker inspection length")
        data = json.loads(result.stdout)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        raise ValueError("managed Docker Xray could not be inspected") from exc
    if not isinstance(data, dict) or data.get("Name") != "/" + CONTAINER:
        raise ValueError("wrong managed Xray container identity")
    if not isinstance(data.get("Id"), str) or not HEX64.fullmatch(data["Id"]):
        raise ValueError("invalid managed Xray container digest")
    state = data.get("State")
    host = data.get("HostConfig")
    policy = host.get("RestartPolicy") if isinstance(host, dict) else None
    if not isinstance(state, dict) or not isinstance(policy, dict):
        raise ValueError("Docker state or restart policy missing")
    started = state.get("StartedAt")
    if not isinstance(started, str) or "T" not in started or (
            started.startswith("0001-01-01")):
        raise ValueError("Docker process start time missing")
    return data


def identity(data):
    state = data["State"]
    return data["Id"], state["StartedAt"]


class OldXrayProbe:
    def __init__(self, pidfd, docker_identity, old_pid):
        self.pidfd = pidfd
        self.docker_identity = docker_identity
        self.old_pid = old_pid

    def close(self):
        if self.pidfd is not None:
            os.close(self.pidfd)
            self.pidfd = None

    def __enter__(self):
        return self

    def __exit__(self, _type, _value, _traceback):
        self.close()


def begin_old_xray_probe():
    """Open old process pidfd while the exact managed Xray is still running."""
    before = inspect_managed()
    state = before["State"]
    pid = state.get("Pid")
    if state.get("Running") is not True or type(pid) is not int or pid <= 0:
        raise ValueError("old managed Xray is not alive for stop proof")
    if not hasattr(os, "pidfd_open"):
        raise ValueError("Linux pidfd support is required for stop proof")
    try:
        pidfd = os.pidfd_open(pid, 0)
    except OSError as exc:
        raise ValueError("old managed Xray exited before pidfd capture") from exc
    try:
        after = inspect_managed()
        if identity(after) != identity(before) or (
                after["State"].get("Running") is not True or
                after["State"].get("Pid") != pid):
            raise ValueError("managed Xray changed during old-process capture")
        poller = select.poll()
        poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
        if poller.poll(0):
            raise ValueError("old managed Xray exited before stop began")
        return OldXrayProbe(pidfd, identity(before), pid)
    except BaseException:
        os.close(pidfd)
        raise


def marker_armed(state_dir, marker_helper):
    """Use the EXACT production marker status parser; no caller string trust."""
    try:
        result = subprocess.run(
            ["python3", str(marker_helper), "status", str(state_dir)],
            capture_output=True, text=True, timeout=5, check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ValueError("durable quota revocation marker unavailable") from exc
    if result.stdout.strip() != "armed":
        raise ValueError("durable quota revocation deny marker is not armed")


def verify_old_xray_physically_stopped(probe, state_dir, marker_helper):
    """Conservatively observe one old PID's exit; never issue a refund proof."""
    if not isinstance(probe, OldXrayProbe) or probe.pidfd is None:
        raise ValueError("old managed Xray pidfd proof missing")
    poller = select.poll()
    poller.register(probe.pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    if not poller.poll(0):
        raise ValueError("old Xray process is still running")
    after = inspect_managed()
    if identity(after) != probe.docker_identity:
        raise ValueError("managed Docker container replaced after Xray stop")
    state = after["State"]
    policy = after["HostConfig"]["RestartPolicy"]
    if state.get("Running") is not False or state.get("Pid") != 0:
        raise ValueError("managed Xray still running or PID not released")
    if policy.get("Name") != "no":
        raise ValueError("revoked Xray automatic restart remains enabled")
    marker_armed(state_dir, marker_helper)
    # Re-inspect last, after the marker check: a concurrent restart must be
    # rejected, not promoted into an apparently durable old-process stop.
    final = inspect_managed()
    if identity(final) != probe.docker_identity or (
            final["State"].get("Running") is not False or
            final["State"].get("Pid") != 0 or
            final["HostConfig"]["RestartPolicy"].get("Name") != "no"):
        raise ValueError("managed Xray restarted during stop verification")
    return {
        "kind": "xmesh.quota-v2.nonfinal-physical-stop-observation",
        "oldContainerId": probe.docker_identity[0],
        "oldStartedAt": probe.docker_identity[1],
        "oldPidfdExited": True,
        "managedContainerStopped": True,
        "restartDisabled": True,
        "durableDenyArmed": True,
        "finalMeterVerified": False,
        "settlementEligible": False,
        "refundableBytes": 0,
    }
