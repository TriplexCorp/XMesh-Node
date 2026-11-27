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
import fcntl
import hashlib
import os
from pathlib import Path
import select
import secrets
import stat
import time
import uuid

import public_tls_cap_watch as cap_watch
import public_tls_wal_watch as watch

wal = watch.wal
journal = wal.journal
DIRECTORY = Path("/var/lib/xmesh-first-meter/runtime/ledger")
RECORD_DIRECTORY = Path("/var/lib/xmesh-ci-first-meter-retirement")
MAX_RECORD = 8192
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
    if (len(events) != 1 or events[0][0] != fd
            or not events[0][1] & select.POLLIN
            or events[0][1] & (select.POLLERR | select.POLLNVAL)):
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


def _file_evidence(fd, name, deadline):
    """Exact immutable file metadata plus hash, including the empty lock."""
    before = os.stat(name, dir_fd=fd, follow_symlinks=False)
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
            or not 0 <= before.st_size <= watch.MAX_SCAN
            or ((before.st_size == 0) != (name == watch.INSTANCE_LOCK))):
        raise ValueError("invalid original WAL file during retirement")
    expected = watch._file_identity(before)
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    with os.fdopen(os.open(name, flags, dir_fd=fd), "rb") as source:
        if watch._file_identity(os.fstat(source.fileno())) != expected:
            raise ValueError("original WAL file replaced at open")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            deadline()
            chunk = source.read(min(65536, remaining))
            if not chunk:
                raise ValueError("original WAL truncated while reading")
            digest.update(chunk)
            remaining -= len(chunk)
        if (source.read(1)
                or watch._file_identity(os.fstat(source.fileno())) != expected
                or watch._file_identity(os.stat(name, dir_fd=fd, follow_symlinks=False)) != expected):
            raise ValueError("original WAL file changed while reading")
        deadline()
        return (expected, digest.hexdigest())


def _manifest(fd, names, deadline):
    if set(os.listdir(fd)) != names:
        raise ValueError("missing, additional or uncertain first-meter retirement WAL files")
    entries = {}
    total = 0
    for name in sorted(names):
        deadline()
        total += os.stat(name, dir_fd=fd, follow_symlinks=False).st_size
        if total > watch.MAX_SCAN:
            raise ValueError("retirement WAL scan exceeds bounded budget")
        entries[name] = _file_evidence(fd, name, deadline)
    _check_manifest(fd, entries)
    os.fsync(fd)
    deadline()
    return entries


def _check_manifest(fd, entries):
    if (set(os.listdir(fd)) != set(entries)
            or any(watch._file_identity(os.stat(name, dir_fd=fd, follow_symlinks=False))
                   != identity for name, (identity, _) in entries.items())):
        raise ValueError("original meter journal inode changed during audit")


def _publish_record(directory, runtime, raw, before_link):
    """No-replace, fsynced, private historical record. Not a Node signature."""
    if not wal._hex(runtime, 64) or not 0 < len(raw) <= MAX_RECORD:
        raise ValueError("invalid retirement record identity or size")
    fd = journal._validate_directory(directory)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if any(name.startswith(".retirement-pending-") for name in os.listdir(fd)):
            raise ValueError("interrupted retirement publication requires investigation")
        name = "retired-" + runtime + ".json"
        try:
            existing = wal.observed.read_private_record(fd, name)
        except FileNotFoundError:
            pass
        else:
            if existing != raw:
                raise ValueError("conflicting immutable retirement evidence")
            before_link()
            os.fsync(fd)
            return
        pending = ".retirement-pending-" + secrets.token_hex(16)
        out = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL |
                      os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=fd)
        with os.fdopen(out, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.fsync(fd)
        before_link()
        os.link(pending, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
        os.fsync(fd)
        os.unlink(pending, dir_fd=fd)
        os.fsync(fd)
        if wal.observed.read_private_record(fd, name) != raw:
            raise ValueError("retirement evidence changed after publication")
    finally:
        os.close(fd)


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
        self._pidfd = self._directory_fd = self._instance_fd = None
        self._started = time.monotonic_ns()
        self._checkpoints = {}
        self._prestop = None
        try:
            self._pidfd = os.pidfd_open(measured[2], 0)
            self._directory_fd = journal._validate_directory(DIRECTORY)
            self._identity = _directory_identity(self._directory_fd)
            self._instance_fd = os.open(
                watch.INSTANCE_LOCK, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC |
                os.O_NONBLOCK, dir_fd=self._directory_fd)
            self._instance_identity = watch._file_identity(os.fstat(self._instance_fd))
            self._live()
            readback_start = time.monotonic_ns()

            def readback_deadline():
                self._deadline()
                if not 0 <= time.monotonic_ns() - readback_start < watch.MAX_CHECK_NS:
                    raise ValueError("first-Genesis WAL readback exceeded time budget")

            self._snapshot, self._witness_raw = watch._checked_evidence(
                roster, user, measured, os.fspath(DIRECTORY), remeasure, readback_deadline)
            self._witness_sha = hashlib.sha256(self._witness_raw).hexdigest()
            if (self._snapshot["identity"] != self._identity
                    or self._snapshot["inodes"][watch.INSTANCE_LOCK] != self._instance_identity):
                raise ValueError("WAL witness used another directory or lock inode")
            self._check_lock()
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
        if (not stat.S_ISDIR(current.st_mode) or current.st_uid != os.geteuid()
                or stat.S_IMODE(current.st_mode) != 0o700
                or (current.st_dev, current.st_ino) != self._identity):
            raise ValueError("retirement WAL pathname replaced")
        self._check_lock()
        self._deadline()
        return docker

    def _check_lock(self):
        named = os.stat(watch.INSTANCE_LOCK, dir_fd=self._directory_fd,
                        follow_symlinks=False)
        if (watch._file_identity(named) != self._instance_identity
                or watch._file_identity(os.fstat(self._instance_fd)) != self._instance_identity):
            raise ValueError("original lifetime lock inode changed")

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
        hashes[watch.INSTANCE_LOCK] = hashlib.sha256(b"").hexdigest()
        entries = _manifest(fd, expected, self._deadline)
        for name, digest in sorted(hashes.items()):
            self._deadline()
            if entries[name][1] != digest:
                raise ValueError("committed original WAL bytes changed after signed readback")
            if entries[name][0] != self._snapshot["inodes"][name]:
                raise ValueError("committed original WAL inode changed after signed readback")
        if set(self._checkpoints) != set(self._roster._grants):
            raise ValueError("one or more signed users lack a durable deny")
        fences = {}
        for user, checkpoint in sorted(self._checkpoints.items()):
            self._deadline()
            fences[str(user)] = journal.verify_poststop_journal(checkpoint, DIRECTORY, docker)
        _check_manifest(fd, entries)
        self._check_lock()
        self._deadline()
        return fences, entries

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
        # Acquire the SAME already-open inode retained before the first
        # authenticated readback, and retain it until this object closes.
        # No new pathname open and no gap during publication.
        self._check_lock()
        try:
            fcntl.flock(self._instance_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ValueError("original lifetime lock still held") from exc
        self._check_lock()
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
            "durableUserDenials": dict(self._prestop[0]),
            "originalMeterPidfdExited": True,
            "lifetimeLockReleased": True,
            "finalMeterVerified": False,
            "settlementEligible": False,
            "canResume": False, "refundableBytes": 0,
        }

    def publish_exited(self):
        """Optional private audit persistence; no terminal receipt or authority."""
        observation = self.verify_exited()
        manifest = [{"filename": name, "sha256": digest}
                    for name, (_, digest) in sorted(self._prestop[1].items())]
        payload = dict(observation, schemaVersion=1, nodeId=self._roster.node,
                       retiredLedgerSha256=hashlib.sha256(
                           wal.observed.canonical(manifest)).hexdigest(),
                       deliveredBytesVerified=False, nodeSignatureVerified=False,
                       canServePublic=False, canStart=False)
        data = wal.observed.canonical({
            "observation": payload,
            # Preserve the exact authenticated response bytes, NOT a
            # re-encoded subset or a claim that the Node signed this record.
            "nexusResponse": self._witness_raw.decode("utf-8"),
        }) + b"\n"
        RECORD_DIRECTORY.mkdir(mode=0o700, exist_ok=True)

        def before_link():
            if self.verify_exited() != observation:
                raise ValueError("retirement observation changed before publication")

        _publish_record(RECORD_DIRECTORY, self._measured[3], data, before_link)
        return payload

    def close(self):
        for name in ("_instance_fd", "_directory_fd", "_pidfd"):
            fd = getattr(self, name)
            if fd is not None:
                os.close(fd)
                setattr(self, name, None)

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()
