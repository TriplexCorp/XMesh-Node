"""Dormant, irreversible network syscall fence for a future isolated TLS child.

Only for a disposable single-thread pre-exec child with independently verified
capless/no-new-privs credentials, private root/PID/net namespaces, and exact
inherited FD inventory. Landlock denies TCP connect/bind even on inherited
sockets; classic seccomp denies new non-Unix sockets and ancillary FD transfer.
This is NOT a complete syscall sandbox, launcher, proof of installed authority,
or an alternative to authenticating every original meter Unix peer.
"""
import ctypes
import os
import platform
import socket

# Explicit native Linux amd64 ABI; x32 and non-native syscalls fail closed.
AUDIT_ARCH_X86_64 = 0xC000003E
X32_SYSCALL = 0x40000000
SYS_LANDLOCK_CREATE_RULESET = 444
SYS_LANDLOCK_RESTRICT_SELF = 446
LANDLOCK_CREATE_RULESET_VERSION = 1
LANDLOCK_ACCESS_NET_BIND_TCP = 1
LANDLOCK_ACCESS_NET_CONNECT_TCP = 2
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
SECCOMP_RET_KILL_PROCESS = 0x80000000
SECCOMP_RET_ERRNO = 0x00050000 | 1  # EPERM
SECCOMP_RET_ALLOW = 0x7FFF0000

# No alternate socket factories, explicit destination send calls, ancillary
# descriptor import/export, or asynchronous syscall engine. The exact inherited
# stream FDs still support listen, accept, read/write and getsockopt.
DENY_SYSCALLS = (
    44, 45, 46, 47, 49, 53,  # sendto, recvfrom, sendmsg, recvmsg, bind, socketpair
    101, 155, 165, 166, 272,  # ptrace, pivot_root, mount/umount2, unshare
    299, 304, 307, 308, 321, 323,  # recvmmsg, open_by_handle_at, sendmmsg, setns, bpf, userfaultfd
    425, 426, 427, 428, 429, 430, 431, 432, 433, 438, 442,
    # io_uring, new mount API, pidfd_getfd, mount_setattr
)


class _Instruction(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32)]


class _Program(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(_Instruction))]


class _Ruleset(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64),
                ("handled_access_net", ctypes.c_uint64)]


def _native():
    if platform.system() != "Linux" or platform.machine() != "x86_64" or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ValueError("exact Linux amd64 network fence required")
    return ctypes.CDLL(None, use_errno=True)


def _check(rc, label):
    if rc < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), label)
    return rc


def _install_landlock(lib):
    version = _check(lib.syscall(SYS_LANDLOCK_CREATE_RULESET, 0, 0,
                                 LANDLOCK_CREATE_RULESET_VERSION), "Landlock ABI")
    if version < 4:
        raise ValueError("Landlock TCP network ABI 4 required")
    ruleset = _Ruleset(0, LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP)
    fd = _check(lib.syscall(SYS_LANDLOCK_CREATE_RULESET, ctypes.byref(ruleset),
                            ctypes.sizeof(ruleset), 0), "Landlock TCP deny ruleset")
    try:
        # No allow rules. All new TCP bind/connect operations must be denied;
        # already-bound listen and established stream I/O remain possible.
        _check(lib.syscall(SYS_LANDLOCK_RESTRICT_SELF, fd, 0), "Landlock TCP restrict_self")
    finally:
        os.close(fd)


def _instructions():
    load, jeq, jset, ret = 0x20, 0x15, 0x45, 0x06
    deny, kill, allow = SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_ALLOW
    # seccomp_data nr=0, arch=4, args=16 (native little endian).
    rows = [(load, 0, 0, 4), (jeq, 1, 0, AUDIT_ARCH_X86_64), (ret, 0, 0, kill),
            (load, 0, 0, 0), (jset, 0, 1, X32_SYSCALL), (ret, 0, 0, kill)]
    for nr in DENY_SYSCALLS:
        rows += [(jeq, 0, 1, nr), (ret, 0, 0, deny)]
    # socket(domain, type, protocol): exactly AF_UNIX, SOCK_STREAM with only
    # NONBLOCK/CLOEXEC optional, protocol 0. Validate both words of each arg.
    # Linux truncates int args, but reject noncanonical high bits anyway.
    checks = [(16, socket.AF_UNIX), (20, 0), (28, 0), (32, 0), (36, 0)]
    socket_rows = []
    for offset, value in checks:
        socket_rows += [(load, 0, 0, offset), (jeq, 1, 0, value), (ret, 0, 0, deny)]
    socket_rows += [(load, 0, 0, 24),
                    (0x54, 0, 0, ~(socket.SOCK_NONBLOCK | socket.SOCK_CLOEXEC) & 0xFFFFFFFF),
                    (jeq, 1, 0, socket.SOCK_STREAM), (ret, 0, 0, deny)]
    rows += [(jeq, 0, len(socket_rows), 41), *socket_rows, (ret, 0, 0, allow)]
    return rows


def _install_socket_filter(lib):
    rows = _instructions()
    instructions = (_Instruction * len(rows))(*(_Instruction(*row) for row in rows))
    program = _Program(len(rows), instructions)
    _check(lib.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER,
                     ctypes.byref(program), 0, 0), "TLS network seccomp filter")


def install():
    """Install both irreversible network fences, or raise; caller MUST exit.

    A failure after Landlock partially installs irreversible state. Never
    allow a fallback, continue serving, or retry using weaker policy.
    """
    lib = _native()
    if os.geteuid() != 0 or os.getegid() != 0:
        raise ValueError("exact capless root child required")
    if len(os.listdir("/proc/self/task")) != 1:
        raise ValueError("network fence must be installed before child threads")
    with open("/proc/self/status", encoding="ascii") as handle:
        status = dict(line.split(":", 1) for line in handle if ":" in line)
    if (status.get("NoNewPrivs", "").strip() != "1"
            or any(int(status.get(key, "-1").strip(), 16) != 0
                   for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"))):
        raise ValueError("exact capless no-new-privs child required")
    _install_landlock(lib)
    _install_socket_filter(lib)
    return None
