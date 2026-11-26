"""Read-only kernel proof of the already-owned child's exact inherited inputs.

Never starts or authorizes a listener. A matching FD is NOT a filesystem,
capability or network sandbox, nor a substitute for signed/WAL evidence.
"""
import os
import select
import subprocess
import time

import public_tls_route_mount as route_mount

MAX_FDS = 16384
MAX_FDINFO = 8192
MAX_STATUS = 65536
MAX_THREADS = 1024
MAX_PROOF_NS = 2_000_000_000


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_gid, info.st_nlink, info.st_size)


def _info(pid, fd):
    path = f"/proc/{pid}/fd/{fd}"
    before = _identity(os.stat(path))
    with open(f"/proc/{pid}/fdinfo/{fd}", "rb") as source:
        raw = source.read(MAX_FDINFO + 1)
    if len(raw) > MAX_FDINFO:
        raise ValueError("qualified child fdinfo exceeded bound")
    fields = {}
    for line in raw.splitlines():
        key, _, value = line.partition(b":")
        if key in (b"flags", b"mnt_id", b"ino"):
            if key in fields:
                raise ValueError("duplicate qualified child fdinfo field")
            fields[key] = int(value.strip(), 8 if key == b"flags" else 10)
    if (set(fields) != {b"flags", b"mnt_id", b"ino"}
            or fields[b"mnt_id"] < 0 or fields[b"ino"] != before[1]
            or _identity(os.stat(path)) != before):
        raise ValueError("qualified child descriptor changed during proof")
    # FD_CLOEXEC is a descriptor flag, not an open-file-description access
    # change. The owner keeps it set; subprocess clears it only for exec.
    return (before, fields[b"mnt_id"], fields[b"flags"] & ~os.O_CLOEXEC)


def _alive(child, pidfd):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLERR | select.POLLHUP)
    if poller.poll(0) or child.poll() is not None:
        raise ValueError("owned TLS child exited during descriptor proof")
    with open(f"/proc/{child.pid}/stat", "rb") as source:
        raw = source.read(8193)
    fields = raw[raw.rfind(b")") + 1:].split()
    if len(raw) > 8192 or len(fields) < 20 or int(fields[1]) != os.getpid():
        raise ValueError("descriptor proof requires an exact directly owned child")
    return fields[19]  # kernel starttime; not a caller's claimed PID


def _capless_threads(pid, deadline):
    """Require actual kernel credentials of every thread, not just TGID."""
    required = {b"Pid", b"Tgid", b"TracerPid", b"Uid", b"Gid", b"Groups",
                b"NoNewPrivs", b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb"}
    proc = f"/proc/{pid}/task"
    seen = set()
    with os.scandir(proc) as threads:
        for count, entry in enumerate(threads, 1):
            deadline()
            if (count > MAX_THREADS or not entry.name.isascii()
                    or not entry.name.isdecimal()):
                raise ValueError("TLS child thread credential scan exceeded bound")
            tid = int(entry.name)
            with open(entry.path + "/status", "rb") as source:
                raw = source.read(MAX_STATUS + 1)
            if len(raw) > MAX_STATUS:
                raise ValueError("TLS child thread status exceeded bound")
            values = {}
            for line in raw.splitlines():
                key, _, value = line.partition(b":")
                if key in required:
                    if key in values:
                        raise ValueError("duplicate TLS child credential field")
                    values[key] = value.split()
            if (set(values) != required
                    or values[b"Pid"] != [str(tid).encode("ascii")]
                    or values[b"Tgid"] != [str(pid).encode("ascii")]
                    or values[b"TracerPid"] != [b"0"]
                    or values[b"Uid"] != [b"0"] * 4
                    or values[b"Gid"] != [b"0"] * 4
                    or set(values[b"Groups"]) - {b"0"}
                    or values[b"NoNewPrivs"] != [b"1"]
                    or any(len(values[key]) != 1
                           or not values[key][0]
                           or set(values[key][0]) != {ord("0")}
                           for key in (b"CapInh", b"CapPrm", b"CapEff", b"CapBnd", b"CapAmb"))):
                raise ValueError("TLS child thread is not untraced capless root with no-new-privs")
            seen.add(tid)
    if pid not in seen:
        raise ValueError("missing TLS child main thread credential evidence")
    deadline()
    return frozenset(seen)


def capture(*, expected, forbidden, route_fd):
    """Capture the owner's exact existing descriptor identities before exec."""
    if (os.geteuid() != 0 or not isinstance(expected, tuple)
            or not isinstance(forbidden, tuple) or not 1 <= len(expected) <= 16
            or len(forbidden) > 32 or len(expected) != len(set(expected))
            or len(forbidden) != len(set(forbidden))
            or route_fd not in expected or set(expected) & set(forbidden)
            or any(type(fd) is not int or fd < 3 for fd in (*expected, *forbidden))):
        raise ValueError("invalid exact child input descriptor set")
    original = {fd: _info(os.getpid(), fd) for fd in expected}
    if len({item[0][:2] for item in original.values()}) != len(expected):
        raise ValueError("ambiguous qualified child input inodes")
    # Anonymous memfds can legitimately have mount ID zero on Linux;
    # the detached route mount must have a distinct positive mount ID.
    if (original[route_fd][1] <= 0
            or original[route_fd][2] & os.O_ACCMODE != os.O_RDONLY
            or os.fstatvfs(route_fd).f_flag & route_mount.VFS_FLAGS
            != route_mount.VFS_FLAGS):
        raise ValueError("owner route descriptor is not read-only")
    return (tuple(original.items()),
            tuple((fd, _identity(os.fstat(fd))) for fd in forbidden), route_fd)


def verify(child, *, expected, forbidden, route_fd, pinned):
    """Match pinned child FD numbers, exact inodes, mount IDs and access flags.

    Forbid all extra FDs pointing at any protected input inode, including the
    owner's writable mount view, CA, Agent state and meter identity handles.
    Unrelated runtime sockets and other ordinary process FDs are not a proof
    of safety; the future launcher still needs a real namespace sandbox.
    Return None, not a permit.
    """
    if (not isinstance(child, subprocess.Popen) or child.poll() is not None):
        raise ValueError("descriptor proof requires a live directly owned child")
    started = time.monotonic_ns()

    def deadline():
        if not 0 <= time.monotonic_ns() - started < MAX_PROOF_NS:
            raise ValueError("child input descriptor proof exceeded time budget")

    pidfd = os.pidfd_open(child.pid, 0)
    try:
        birth = _alive(child, pidfd)
        threads = _capless_threads(child.pid, deadline)
        if capture(expected=expected, forbidden=forbidden, route_fd=route_fd) != pinned:
            raise ValueError("owner pinned input or protected descriptor changed")
        original = dict(pinned[0])
        protected = {item[0][:2] for item in original.values()}
        protected.update(item[:2] for _, item in pinned[1])

        def exact():
            for fd, evidence in original.items():
                deadline()
                try:
                    actual = _info(child.pid, fd)
                except FileNotFoundError:
                    raise ValueError("child lost a pinned input descriptor") from None
                if actual != evidence:
                    raise ValueError("child did not inherit its exact pinned TLS input")
            if (os.statvfs(f"/proc/{child.pid}/fd/{route_fd}").f_flag
                    & route_mount.VFS_FLAGS != route_mount.VFS_FLAGS):
                raise ValueError("child route descriptor is not its pinned read-only mount")

        exact()
        observed = set()
        with os.scandir(f"/proc/{child.pid}/fd") as descriptors:
            for count, entry in enumerate(descriptors, 1):
                deadline()
                if count > MAX_FDS or not entry.name.isascii() or not entry.name.isdecimal():
                    raise ValueError("child input descriptor inventory exceeded bound")
                number = int(entry.name)
                try:
                    info = os.stat(entry.path)
                except FileNotFoundError:
                    if number in original:
                        raise ValueError("child lost a pinned input descriptor") from None
                    continue
                if number in original:
                    observed.add(number)
                elif (info.st_dev, info.st_ino) in protected:
                    raise ValueError("child inherited an extra protected supervisor descriptor")
        if observed != set(expected):
            raise ValueError("child input descriptor inventory is incomplete")
        exact()
        if threads != _capless_threads(child.pid, deadline):
            raise ValueError("TLS child thread set changed during credential proof")
        if (birth != _alive(child, pidfd)
                or capture(expected=expected, forbidden=forbidden, route_fd=route_fd) != pinned):
            raise ValueError("owner or child input identity changed")
        deadline()
    finally:
        os.close(pidfd)
    return None
