"""Dormant immutable executable proof for the future public TLS child.

The copy is bound to the installed release's verified qualification and to
the executable of the independently discovered original live meter. It
never spawns Xray, grants permission, or serves as a containment sandbox.
"""
import fcntl
import hashlib
import os
from pathlib import Path
import select
import stat
import subprocess
import time

import qualified_runtime_image as release
import wal_transport

# Linux >= 6.3. Unsupported memfd policies must fail closed, not fall back
# to executing the mutable installed path or an unsealed temporary file.
MFD_EXEC = 0x0010
F_SEAL_EXEC = 0x0020
F_SEAL_FUTURE_WRITE = 0x0010
SEALS = (fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW |
         fcntl.F_SEAL_SEAL | F_SEAL_EXEC | F_SEAL_FUTURE_WRITE)
READ_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC
MAX_PREP_NS = 8_000_000_000


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
            info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _sealed_identity(info):
    # Linux can update mtime/ctime even for rejected writes to sealed
    # memfds. Content integrity is assured by immutable seals instead.
    return _identity(info)[:6]


def _source_identity(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o755 or info.st_nlink != 1
            or not 0 < info.st_size <= release.MAX_BINARY):
        raise ValueError("unsafe qualified TLS executable")
    return _identity(info)


def _read_hash(fd, deadline, output=None):
    before = _source_identity(os.fstat(fd))
    digest = hashlib.sha256()
    offset = 0
    while chunk := os.pread(fd, 1 << 20, offset):
        deadline()
        offset += len(chunk)
        if offset > release.MAX_BINARY:
            raise ValueError("qualified TLS executable exceeds size bound")
        digest.update(chunk)
        if output is not None:
            pending = memoryview(chunk)
            while pending:
                size = os.write(output, pending)
                if size <= 0:
                    raise OSError("short sealed executable write")
                pending = pending[size:]
    if offset != before[5] or _source_identity(os.fstat(fd)) != before:
        raise ValueError("qualified TLS executable changed while reading")
    deadline()
    return before, digest.hexdigest()


def _ready(pidfd):
    poller = select.poll()
    poller.register(pidfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    return bool(poller.poll(0))


class PinnedTlsExecutable:
    """Own an executable inode with kernel-enforced immutable bytes and mode.

    The trusted caller must supply the measured original meter PID/runtime
    independently of remote claims. This snapshot authenticates bytes only;
    full signed policy, WAL and runtime supervision remain separate gates.
    The future launcher must exec the FD, not the original host pathname,
    verify its owned child's actual kernel executable before serving and
    recheck continuously, retaining this object until the child is reaped.
    """

    def __init__(self, *, runtime_pid, runtime_id):
        if (os.geteuid() != 0 or type(runtime_pid) is not int or runtime_pid <= 1
                or not isinstance(runtime_id, str)):
            raise ValueError("trusted original root-owned meter required")
        self._fd = self._pidfd = None
        self._closed = False
        self._runtime_pid, self._runtime_id = runtime_pid, runtime_id
        start = time.monotonic_ns()

        def deadline():
            if not 0 <= time.monotonic_ns() - start < MAX_PREP_NS:
                raise ValueError("sealed executable preparation exceeded watchdog budget")

        self._record = release.read_identity(release.QUALIFICATION)
        try:
            self._pidfd = os.pidfd_open(runtime_pid, 0)
            self._check_meter()
            with os.fdopen(os.open(release.EXECUTABLE, READ_FLAGS | os.O_NOFOLLOW), "rb") as source:
                writer = os.memfd_create("xmesh-qualified-tls-executable",
                                         os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | MFD_EXEC)
                try:
                    self._source_id, digest = _read_hash(source.fileno(), deadline, writer)
                    if digest != self._record["artifactSha256"]:
                        raise ValueError("installed TLS executable differs from verified release")
                    # No setuid/setgid or mutable executable permission.
                    os.fchmod(writer, 0o500)
                    fcntl.fcntl(writer, fcntl.F_ADD_SEALS, SEALS)
                    self._fd = os.open(f"/proc/self/fd/{writer}", READ_FLAGS)
                    self._sealed_id = _sealed_identity(os.fstat(self._fd))
                finally:
                    # An open writable file description can prevent exec,
                    # even after sealing. Retain only the read-only FD.
                    os.close(writer)
            with os.fdopen(os.open(f"/proc/{runtime_pid}/exe", READ_FLAGS), "rb") as meter:
                self._meter_id, digest = _read_hash(meter.fileno(), deadline)
                if digest != self._record["artifactSha256"]:
                    raise ValueError("original meter executable differs from verified release")
            self.ensure_current()
            deadline()
        except BaseException:
            self.close()
            raise

    def _check_meter(self):
        if (_ready(self._pidfd)
                or wal_transport.runtime_identity.trusted_runtime_identity(self._runtime_pid)
                != self._runtime_id or _ready(self._pidfd)):
            raise ValueError("original qualified meter changed or exited")

    def ensure_current(self):
        if self._closed or self._fd is None:
            raise ValueError("sealed TLS executable is closed")
        self._check_meter()
        info = os.fstat(self._fd)
        if (_sealed_identity(info) != self._sealed_id or not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o500
                or fcntl.fcntl(self._fd, fcntl.F_GET_SEALS) != SEALS
                or fcntl.fcntl(self._fd, fcntl.F_GETFL) & os.O_ACCMODE != os.O_RDONLY
                or os.get_inheritable(self._fd)):
            raise ValueError("sealed TLS executable inode or permissions changed")
        if (release.read_identity(release.QUALIFICATION) != self._record
                or _source_identity(release.EXECUTABLE.stat(follow_symlinks=False))
                != self._source_id
                or _source_identity(Path(f"/proc/{self._runtime_pid}/exe").stat())
                != self._meter_id):
            raise ValueError("installed qualification or original executable changed")
        self._check_meter()
        return None

    @property
    def exec_fd(self):
        self.ensure_current()
        return self._fd

    def verify_child(self, child):
        """Read-only check of the exact live directly owned exec inode.

        This method does not start/stop a process or return authorization.
        The supervisor must stop and reap the owned child on ANY failure.
        """
        self.ensure_current()
        if not isinstance(child, subprocess.Popen) or child.poll() is not None:
            raise ValueError("qualified executable requires a live owned child")
        pidfd = os.pidfd_open(child.pid, 0)
        try:
            proc = Path(f"/proc/{child.pid}")
            # Disallow a replacement/recycled PID and check actual post-exec
            # inode; same bytes executed through an unsealed host path are
            # deliberately insufficient.
            raw = (proc / "stat").read_text(encoding="ascii")
            fields = raw[raw.rfind(")") + 1:].split()
            if (len(fields) < 20 or int(fields[1]) != os.getpid()
                    or _sealed_identity((proc / "exe").stat()) != self._sealed_id
                    or _ready(pidfd) or child.poll() is not None):
                raise ValueError("owned child did not exec the original sealed TLS executable")
            self.ensure_current()
            if (_ready(pidfd) or child.poll() is not None
                    or _sealed_identity((proc / "exe").stat()) != self._sealed_id):
                raise ValueError("owned child executable changed during proof")
        finally:
            os.close(pidfd)
        return None

    def close(self):
        if not self._closed:
            self._closed = True
            for fd in (self._fd, self._pidfd):
                if fd is not None:
                    os.close(fd)
            self._fd = self._pidfd = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
