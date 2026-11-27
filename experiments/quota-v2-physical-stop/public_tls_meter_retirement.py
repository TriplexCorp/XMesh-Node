"""Disposable first-Genesis meter retirement evidence, never settlement.

After TLS has been stopped, bind one freshly authenticated Nexus WAL head
to the exact live meter pidfd; fence EVERY signed user on that same kernel
Unix peer, then require the original process's actual exit, unchanged
Docker incarnation, released lifetime lock and unchanged complete ledger.

This helper never stops Docker, launches services, returns reserve, signs a
settlement, or grants a successor. A caller must establish TLS shutdown,
quiesce the disposable workers, and independently verify the enrolled
first-Genesis roster and installed executable before using it.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import os
from pathlib import Path
import select
import stat
import time
import uuid

import public_tls_cap_watch as cap_watch
import public_tls_wal_watch as watch

wal = watch.wal
journal = wal.journal
DIRECTORY = Path("/var/lib/xmesh-first-meter/runtime/ledger")
FENCE_NAMESPACE = uuid.UUID("74df852d-a5a6-47d8-bac9-55f84d9b102a")
MAX_RETIRE_NS = 30_000_000_000


def _require_disposable():
    if (os.geteuid() != 0 or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("XMESH_AUDIT_DISPOSABLE") != "1"
            or os.environ.get("XMESH_DISPOSABLE_FIRST_METER_RETIREMENT") != "1"
            or not watch.qualification.installed_worker()):
        raise ValueError("first-meter retirement is hosted disposable evidence only")


def _poll_exit(fd):
    poll = select.poll()
    poll.register(fd, select.POLLIN | select.POLLERR | select.POLLHUP)
    events = poll.poll(0)
    if not events:
        return False
    if len(events) != 1 or events[0][0] != fd or not events[0][1] & select.POLLIN:
        raise ValueError("invalid original meter pidfd exit evidence")
    return True


def _directory_identity(fd):
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("unsafe retirement WAL directory")
    return info.st_dev, info.st_ino


def _same_mount(directory, pid, identity):
    inside = os.stat(f"/proc/{pid}/root{journal.RUNTIME_DEST}/ledger",
                     follow_symlinks=False)
    host = os.stat(directory, follow_symlinks=False)
    if (not stat.S_ISDIR(inside.st_mode) or not stat.S_ISDIR(host.st_mode)
            or (inside.st_dev, inside.st_ino) != identity
            or (host.st_dev, host.st_ino) != identity):
        raise ValueError("original meter WAL mount changed before retirement")


def _scope(roster, user):
    _, grant, aliases = roster._grants[user]
    return {
        "email": aliases[0], "nodeId": roster.node, "userId": user,
        "epoch": grant["accountEpoch"], "meterEpoch": grant["meterEpoch"],
        "reservationId": grant["reservationId"], "revision": grant["revision"],
        "revocationId": str(uuid.uuid5(FENCE_NAMESPACE,
                                       roster.runtime_id + ":" + grant["reservationId"])),
    }


def _fence_names(users):
    names = set()
    for user in users:
        digest = hashlib.sha256(f"xmesh-u{user}".encode("ascii")).hexdigest()
        names.update({f"fence-{digest}.json", f"observed-{digest}.json"})
    return names


def _check_docker(docker, measured, running):
    state = docker.get("State", {})
    host = docker.get("HostConfig", {})
    if (docker.get("Name") != "/xmesh-managed-xray"
            or docker.get("Id") != measured[0]
            or state.get("StartedAt") != measured[1]
            or state.get("Running") is not running
            or state.get("Restarting") is not False
            or type(state.get("Pid")) is not int
            or state["Pid"] != (measured[2] if running else 0)
            or host.get("RestartPolicy", {}).get("Name") != "no"
            or host.get("NetworkMode") != "none"):
        raise ValueError("original isolated Docker incarnation changed or restarted")


def _file_hash(fd, name, limit):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    with os.fdopen(os.open(name, flags, dir_fd=fd), "rb") as source:
        info = os.fstat(source.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or not 0 < info.st_size <= limit):
            raise ValueError("invalid original WAL file during retirement")
        digest = hashlib.sha256()
        remaining = info.st_size
        while remaining:
            chunk = source.read(min(65536, remaining))
            if not chunk:
                raise ValueError("original WAL truncated while reading")
            digest.update(chunk)
            remaining -= len(chunk)
        if source.read(1):
            raise ValueError("original WAL grew while reading")
        current = os.fstat(source.fileno())
        named = os.stat(name, dir_fd=fd, follow_symlinks=False)
        def identity(item):
            return (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns,
                    item.st_ctime_ns, item.st_mode, item.st_uid, item.st_nlink)
        if identity(current) != identity(info) or identity(named) != identity(info):
            raise ValueError("original WAL file changed while reading")
        return digest.hexdigest()


@contextmanager
def _released_lifetime_lock(fd, expected):
    lock = os.open(watch.INSTANCE_LOCK, os.O_RDONLY | os.O_NOFOLLOW
                   | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=fd)
    try:
        def check():
            inode = os.fstat(lock)
            named = os.stat(watch.INSTANCE_LOCK, dir_fd=fd, follow_symlinks=False)
            for info in (inode, named):
                if ((info.st_dev, info.st_ino) != expected[:2]
                        or not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                        or info.st_nlink != 1 or info.st_size != 0
                        or stat.S_IMODE(info.st_mode) != 0o600):
                    raise ValueError("original lifetime lock inode changed")
        check()
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("original lifetime lock still held") from exc
        check()
        yield check
        check()
    finally:
        os.close(lock)


class FirstGenesisRetirement:
    """Same-process historical proof. Keep the object open across actual exit."""

    def __init__(self, roster, user, measured, remeasure):
        _require_disposable()
        if (not isinstance(roster, cap_watch.SignedCapRosterWatch)
                or user not in roster._grants or type(user) is not int
                or not isinstance(measured, tuple) or len(measured) != 4
                or measured[2:] != (roster._pid, roster.runtime_id)
                or type(measured[2]) is not int or measured[2] <= 1):
            raise ValueError("independently authenticated first-Genesis roster required")
        self._roster, self._measured, self._remeasure = roster, measured, remeasure
        self._pidfd = self._directory_fd = None
        self._started = time.monotonic_ns()
        self._checkpoints = {}
        self._prestop = None
        try:
            self._pidfd = os.pidfd_open(measured[2], 0)
            self._directory_fd = journal._validate_directory(DIRECTORY)
            self._identity = _directory_identity(self._directory_fd)
            self._live()
            readback_start = time.monotonic_ns()

            def readback_deadline():
                self._deadline()
                if not 0 <= time.monotonic_ns() - readback_start < watch.MAX_CHECK_NS:
                    raise ValueError("first-Genesis WAL readback exceeded time budget")

            self._snapshot, self._witness_sha = watch._checked_evidence(
                roster, user, measured, os.fspath(DIRECTORY), remeasure, readback_deadline)
            if self._snapshot["identity"] != self._identity:
                raise ValueError("WAL witness used another directory")
            self._live()
        except BaseException:
            self.close()
            raise

    def _deadline(self):
        elapsed = time.monotonic_ns() - self._started
        if not 0 <= elapsed < MAX_RETIRE_NS:
            raise ValueError("first-meter retirement exceeded bounded proof budget")

    def _bound(self, running):
        self._deadline()
        if self._pidfd is None or self._directory_fd is None:
            raise ValueError("original meter retirement evidence closed")
        docker, directory = wal._bound_journal()
        _check_docker(docker, self._measured, running)
        if (Path(directory) != DIRECTORY
                or _directory_identity(self._directory_fd) != self._identity):
            raise ValueError("retirement WAL directory changed")
        current = os.stat(DIRECTORY, follow_symlinks=False)
        if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != self._identity:
            raise ValueError("retirement WAL pathname replaced")
        self._deadline()
        return docker

    def _live(self):
        if self._pidfd is None or _poll_exit(self._pidfd):
            raise ValueError("original meter exited before retirement proof")
        if (self._remeasure() != (self._measured, os.fspath(DIRECTORY))
                or wal.runtime_identity.trusted_runtime_identity(self._measured[2])
                != self._measured[3]):
            raise ValueError("live original meter identity changed")
        _same_mount(DIRECTORY, self._measured[2], self._identity)
        docker = self._bound(True)
        if _poll_exit(self._pidfd):
            raise ValueError("original meter exited during retirement proof")
        return docker

    def _ledger(self, docker):
        fd = self._directory_fd
        expected = {watch.INSTANCE_LOCK} | set(self._snapshot["wal"])
        hashes = dict(self._snapshot["wal"])
        for user, (raw, _, _) in self._roster._grants.items():
            name = f"positive-cap-u{user}.json"
            expected.add(name)
            hashes[name] = hashlib.sha256(raw).hexdigest()
        if self._snapshot["sequence"]:
            expected.add(wal.registry.NAME)
            hashes[wal.registry.NAME] = self._snapshot["sha256"]
        expected.update(_fence_names(self._roster._grants))
        if set(os.listdir(fd)) != expected:
            raise ValueError("missing, additional or uncertain first-meter retirement WAL files")
        for name, digest in sorted(hashes.items()):
            self._deadline()
            if _file_hash(fd, name, watch.MAX_SCAN) != digest:
                raise ValueError("committed original WAL bytes changed after signed readback")
        if set(self._checkpoints) != set(self._roster._grants):
            raise ValueError("one or more signed users lack a durable deny")
        fences = {}
        for user, checkpoint in sorted(self._checkpoints.items()):
            self._deadline()
            fences[str(user)] = journal.verify_poststop_journal(checkpoint, DIRECTORY, docker)
        if set(os.listdir(fd)) != expected:
            raise ValueError("original meter journal changed during fence audit")
        self._deadline()
        return fences

    def fence_all(self):
        """Only in the disposable harness, drain every independently signed user."""
        if self._prestop is not None or self._checkpoints:
            raise ValueError("retirement proof is single-use")
        self._live()
        # Require unchanged committed tails BEFORE irreversible local denial.
        if watch._snapshot(DIRECTORY, self._roster, self._deadline) != self._snapshot:
            raise ValueError("original WAL changed before fencing")
        for user in sorted(self._roster._grants):
            self._live()
            scope = _scope(self._roster, user)
            result = watch.cap_install.fence_calendar_in_xray(
                self._roster._socket, self._measured[2], self._measured[3], scope)
            checkpoint = result["observedCheckpoint"]
            aliases = self._roster._grants[user][2]
            if (any(type(checkpoint.get(k)) is not type(v) or checkpoint[k] != v
                    for k, v in scope.items())
                    or checkpoint.get("runtimeId") != self._measured[3]
                    or set(row["email"] for row in checkpoint["inboundMeters"]) != set(aliases)
                    or len(checkpoint["inboundMeters"]) != len(aliases)):
                raise ValueError("durable denial differs from original signed user scope")
            self._checkpoints[user] = checkpoint
        docker = self._live()
        evidence = self._ledger(docker)
        if watch._instance_lock(self._directory_fd, self._measured[2], self._deadline) != self._snapshot["instanceLock"]:
            raise ValueError("original meter lifetime lock changed before stop")
        self._live()
        self._prestop = evidence

    def verify_exited(self):
        """Observe physical exit; do NOT interpret charged bytes as delivery."""
        if self._prestop is None or self._pidfd is None or not _poll_exit(self._pidfd):
            raise ValueError("original meter pidfd has not exited after durable full-roster denial")
        docker = self._bound(False)
        with _released_lifetime_lock(self._directory_fd, self._snapshot["instanceLock"]):
            if self._ledger(docker) != self._prestop:
                raise ValueError("durable deny or original WAL changed across process exit")
            self._bound(False)
            if not _poll_exit(self._pidfd):
                raise ValueError("original meter pidfd exit could not be confirmed")
            return {
                "kind": "xmesh.quota-v2.nonfinal-first-meter-retirement",
                "runtimeId": self._measured[3], "containerId": self._measured[0],
                "startedAt": self._measured[1],
                "signedWalReadbackSha256": self._witness_sha,
                "inventorySha256": self._snapshot["sha256"],
                "committedChargeHeadsSha256": self._snapshot["chargeHeadsSha256"],
                "durableUserDenials": dict(self._prestop),
                "originalMeterPidfdExited": True,
                "lifetimeLockReleased": True,
                "finalMeterVerified": False,
                "settlementEligible": False,
                "canResume": False, "refundableBytes": 0,
            }

    def close(self):
        for name in ("_directory_fd", "_pidfd"):
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
