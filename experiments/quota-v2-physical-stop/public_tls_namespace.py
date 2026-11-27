"""Dormant actual procfs proof of an isolated, minimal TLS child root.

No process or mount is created here. This verifies Linux namespace and
mount topology, not seccomp contents, cgroup ownership, executable,
inherited FDs, traffic authority, or the existence of a safe launcher.
Those independent proofs remain mandatory.
"""
from dataclasses import dataclass
import os
import select
import stat
import time

import public_tls_child_inputs as inputs
import public_tls_route_mount as route_mount
from public_tls_peer_identity import _filesystem_magic

TMPFS_MAGIC = 0x01021994
ISOLATED = ("mnt", "pid", "net", "ipc", "uts")
ALL = (*ISOLATED, "user")
VFS = os.ST_RDONLY | os.ST_NOSUID | os.ST_NODEV | os.ST_NOEXEC
FLAGS = {b"ro", b"nosuid", b"nodev", b"noexec"}
MAX_MOUNTINFO = 1 << 20
MAX_NS_PROOF_NS = 2_000_000_000


def _id(info):
    return info.st_dev, info.st_ino


def _root_identity(fd):
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o700
            or os.get_inheritable(fd) or _filesystem_magic(fd) != TMPFS_MAGIC):
        raise ValueError("original private root-owned tmpfs root required")
    # A directory on an unrelated host tmpfs is not the root of the
    # independently mounted sandbox filesystem.
    parent = os.open("..", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC, dir_fd=fd)
    try:
        if route_mount.mount_id(parent) == route_mount.mount_id(fd):
            raise ValueError("original private root-owned tmpfs mount root required")
    finally:
        os.close(parent)
    return _id(info)


def _namespaces(proc):
    return tuple((name, _id(os.stat(f"{proc}/ns/{name}"))) for name in ALL)


@dataclass(frozen=True)
class PinnedRoot:
    root: tuple
    supervisor_namespaces: tuple


def capture_root(root_fd):
    if os.geteuid() != 0:
        raise ValueError("root required for actual TLS namespace proof")
    return PinnedRoot(_root_identity(root_fd), _namespaces("/proc/self"))


def _bounded(path, limit):
    with open(path, "rb") as handle:
        raw = handle.read(limit + 1)
    if not raw or len(raw) > limit:
        raise ValueError("TLS child procfs evidence exceeded bound")
    return raw


def _mounts(proc, root, inner_proc):
    raw = _bounded(f"{proc}/mountinfo", MAX_MOUNTINFO)
    mounts = {}
    for line in raw.splitlines():
        left, sep, right = line.partition(b" - ")
        fields, fs = left.split(), right.split()
        if (not sep or len(fields) != 6 or len(fs) != 3
                or fields[3] != b"/" or fields[4] in mounts
                or not FLAGS <= set(fields[5].split(b","))
                or b"rw" in fields[5].split(b",")
                or any(not x.isdigit() for x in fields[:2])):
            # Exactly two private, non-propagating mountpoints; no
            # optional shared/master/propagate_from/unbindable fields,
            # other root/subpath binds, or writable attachments.
            raise ValueError("foreign, writable or nonprivate child root mount")
        mounts[fields[4]] = (int(fields[0]), int(fields[1]), fields[2], fs[0])
    if set(mounts) != {b"/", b"/proc"}:
        raise ValueError("TLS child root contains unexpected mounts")
    root_row, proc_row = mounts[b"/"], mounts[b"/proc"]

    def device(dev):
        return f"{os.major(dev)}:{os.minor(dev)}".encode("ascii")

    if (root_row[0] == proc_row[0] or proc_row[1] != root_row[0]
            or root_row[2] != device(root[0]) or root_row[3] != b"tmpfs"
            or proc_row[2] != device(inner_proc[0]) or proc_row[3] != b"proc"):
        raise ValueError("TLS child mount IDs or filesystems differ from pinned root")
    return raw


def _pid_birth(proc, pidfd):
    poll = select.poll()
    poll.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    if poll.poll(0):
        raise ValueError("TLS child exited during namespace proof")
    raw = _bounded(f"{proc}/stat", 8192)
    fields = raw[raw.rfind(b")") + 1:].split()
    if len(fields) < 20 or poll.poll(0):
        raise ValueError("missing live TLS child start time")
    return fields[19]


def _snapshot(proc, pinned, deadline):
    namespaces = _namespaces(proc)
    parent = dict(pinned.supervisor_namespaces)
    current = dict(namespaces)
    if any(current[name] == parent[name] for name in ISOLATED) or current["user"] != parent["user"]:
        raise ValueError("TLS child namespace is not independently isolated")
    deadline()
    root = f"{proc}/root"
    inner_proc = f"{root}/proc"
    info = os.stat(root)
    if (_id(info) != pinned.root or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o700
            or os.statvfs(root).f_flag & VFS != VFS
            or os.statvfs(inner_proc).f_flag & VFS != VFS):
        raise ValueError("TLS child root not the exact read-only private tmpfs")
    # Verify that the actual mounted procfs describes the child's own PID1,
    # not an inherited host /proc or a different private PID namespace.
    if (_id(os.stat(f"{inner_proc}/1/ns/pid")) != current["pid"]
            or _id(os.stat(f"{inner_proc}/1/root")) != pinned.root
            or _id(os.stat(f"{inner_proc}/1/exe")) != _id(os.stat(f"{proc}/exe"))):
        raise ValueError("TLS child procfs is not its own PID1 namespace")
    outer_status = _bounded(f"{proc}/status", inputs.MAX_STATUS)
    inner_status = _bounded(f"{inner_proc}/1/status", inputs.MAX_STATUS)
    nspid = [line.split()[1:] for line in outer_status.splitlines() if line.startswith(b"NSpid:")]
    inner_pid = [line.split()[1:] for line in inner_status.splitlines() if line.startswith(b"Pid:")]
    if len(nspid) != 1 or not nspid[0] or nspid[0][-1] != b"1" or inner_pid != [[b"1"]]:
        raise ValueError("TLS child is not namespace init")
    deadline()
    return namespaces, _mounts(proc, pinned.root, _id(os.stat(inner_proc)))


def verify(pid, root_fd, pinned):
    """Read actual namespace/root/kernel thread state for a live measured PID.

    A separate owned-child pidfd/birth and executable proof must establish
    supervision. Never accept this proof alone as launch/listener authority.
    """
    if (os.geteuid() != 0 or type(pid) is not int or pid <= 1 or pid == os.getpid()
            or type(pinned) is not PinnedRoot or capture_root(root_fd) != pinned):
        raise ValueError("exact retained private TLS root required")
    start = time.monotonic_ns()

    def deadline():
        if not 0 <= time.monotonic_ns() - start < MAX_NS_PROOF_NS:
            raise ValueError("TLS child namespace proof exceeded budget")

    proc = f"/proc/{pid}"
    pidfd = os.pidfd_open(pid)
    try:
        birth = _pid_birth(proc, pidfd)
        before = _snapshot(proc, pinned, deadline)
        threads = inputs._capless_threads(pid, deadline)
        if (_snapshot(proc, pinned, deadline) != before
                or inputs._capless_threads(pid, deadline) != threads
                or _pid_birth(proc, pidfd) != birth or capture_root(root_fd) != pinned):
            raise ValueError("TLS child sandbox changed during namespace proof")
        deadline()
    finally:
        os.close(pidfd)
    return None
