#!/usr/bin/env python3
"""NON-SPENDING isolated successor Xray meter observation (staging only).

Requires: independently pinned Nexus zero-spend preparation, fully closed
OLD Xray with independently checked WAL + final signed Nexus charge receipts,
and a NEW process in an independently measured private Docker/WAL namespace.

This does NOT allocate, sign, install or activate a positive cap, and cannot
refund, reset, or move an old byte. It is not remote hardware attestation.
"""
import hashlib
import subprocess
from qualified_runtime_image import installed_worker
import os
from pathlib import Path
import re
import stat
import time
import uuid

import cap_install
import calendar_fence
import genesis_reservation as lease
import quarantine_policy as quarantine
import renewal_worker
import wal_transport

EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
SUCCESSOR = "xmesh-successor-quarantine"


def _name(user, predecessor):
    return f"calendar-meter-u{user}-{predecessor}.json"


def _verify_fresh_container_env(docker):
    """Bind Xray's ACTUAL observed journal and strict-cap startup to the
    independently inspected Docker WAL mount. A clean, unused Docker bind
    is not proof if Xray secretly writes its bytes somewhere else.
    """
    import journal_integrity
    config = docker.get("Config") if isinstance(docker, dict) else None
    env = config.get("Env") if isinstance(config, dict) else None
    if not isinstance(env, list) or not all(isinstance(x, str) for x in env):
        raise ValueError("untrusted successor Xray process environment")
    runtime_layout = any(m.get("Destination") == journal_integrity.RUNTIME_DEST
                         for m in docker.get("Mounts", []) if isinstance(m, dict))
    # Neither a Docker self-report nor the host environment string
    # GITHUB_ACTIONS=true attests to an isolated CI runner. Require the
    # root-owned staging marker in BOTH CI and non-CI modes. Production
    # may never turn on a fresh spending runtime using environment alone.
    import vless_ingress
    installed = installed_worker()
    if not installed and not vless_ingress._staging_permitted():
        raise ValueError("fresh successor requires the root-only staging marker")
    host_ci = os.environ.get("GITHUB_ACTIONS") == "true"
    if installed:
        if not runtime_layout or any(v.split("=", 1)[0] in {
                "GITHUB_ACTIONS", "XMESH_QUOTA_INGRESS_STAGING", "XMESH_QUOTA_V2_STAGING_RUNTIME",
                "XMESH_EXPERIMENTAL_CRASH_AFTER_DRAIN"} for v in env):
            raise ValueError("installed meter cannot inherit staging or fault injection")
    elif not host_ci:
        mounts = docker.get("Mounts")
        marker = vless_ingress.STAGING_MARKER
        if ("XMESH_QUOTA_V2_STAGING_RUNTIME=1" not in env
                or "GITHUB_ACTIONS=true" in env
                or not isinstance(mounts, list)
                or len([m for m in mounts if isinstance(m, dict)
                        and m.get("Destination") == marker]) != 1
                or not any(isinstance(m, dict)
                           and m.get("Source") == marker
                           and m.get("Destination") == marker
                           and m.get("Type") == "bind"
                           and m.get("RW") is False for m in mounts)):
            raise ValueError("installed successor requires the exact read-only root staging marker mount")
    required = {
        "XMESH_EXPERIMENTAL_DRAIN": "1",
        "XMESH_EXPERIMENTAL_OBSERVED_DIR": (journal_integrity.RUNTIME_DEST + "/ledger"
                                           if runtime_layout else journal_integrity.JOURNAL_DEST),
    }
    if installed:
        required["XMESH_QUOTA_V2_RUNTIME_ROLE"] = "meter"
        required["XMESH_QUOTA_PRIVATE_VLESS"] = "1"
    else:
        required["GITHUB_ACTIONS" if host_ci else "XMESH_QUOTA_V2_STAGING_RUNTIME"] = (
            "true" if host_ci else "1")
    if runtime_layout:
        required.update({
            "XMESH_EXPERIMENTAL_DRAIN_SOCKET": journal_integrity.RUNTIME_DEST + "/drain.sock",
            "XMESH_EXPERIMENTAL_SIGNED_CAP_BINDING": journal_integrity.RUNTIME_DEST + "/cap-binding.json",
        })
    for name, value in required.items():
        found = [entry.split("=", 1)[1] for entry in env
                 if entry.startswith(name + "=")]
        if found != [value]:
            raise ValueError("successor Xray observed WAL environment differs from Docker bind")
    bindings = [entry.split("=", 1)[1] for entry in env
                if entry.startswith("XMESH_EXPERIMENTAL_SIGNED_CAP_BINDING=")]
    if len(bindings) != 1 or not os.path.isabs(bindings[0]):
        raise ValueError("new Xray must start with one absolute signed-cap binding")


def _clean_mount(old_dir, candidate_dir, runtime_id=None):
    """Require a distinct root-owned WAL namespace and verified same-process WAL."""
    old = os.open(old_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    candidate = os.open(candidate_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        a, b = os.fstat(old), os.fstat(candidate)
        if (not stat.S_ISDIR(a.st_mode) or not stat.S_ISDIR(b.st_mode)
                or a.st_uid != os.geteuid() or b.st_uid != os.geteuid()
                or stat.S_IMODE(a.st_mode) != 0o700
                or stat.S_IMODE(b.st_mode) != 0o700
                or (a.st_dev, a.st_ino) == (b.st_dev, b.st_ino)):
            raise ValueError("successor WAL root is foreign or shared with predecessor")
        names = os.listdir(candidate)
        if runtime_id is None:
            if any(name != "xray-instance.lock" for name in names):
                raise ValueError("successor WAL is not a fresh empty meter namespace")
        else:
            meter_names = sorted(name for name in names if name.startswith("meter-"))
            entries, _ = wal_transport.registry.verify_meter_inventory(
                candidate, meter_names, wal_transport.journal._read_meter_wal,
                wal_transport.journal._canonical_go)
            if any(entry["runtimeId"] != runtime_id for entry in entries.values()):
                raise ValueError("successor WAL belongs to another Xray runtime")
            permitted = {"xray-instance.lock", "xmesh-meter-inventory-v1.jsonl", *meter_names}
            # Xray authenticates the peer permits and candidate state over
            # its measured control socket. Filenames supply no authority.
            if any(name not in permitted and re.fullmatch(
                    r"positive-cap-u[1-9][0-9]{0,18}(?:-r[1-9][0-9]{0,18})?\.json", name) is None for name in names):
                raise ValueError("successor WAL root contains unknown state")
        # Xray must already hold its own private, source-pinned instance lock.
        # We do not assume this by just seeing a lock-shaped filename; the
        # independent PID and Unix-peer measurements check the live process.
        if "xray-instance.lock" not in names:
            raise ValueError("successor has no live Xray journal instance")
        lock = os.stat("xray-instance.lock", dir_fd=candidate, follow_symlinks=False)
        if (not stat.S_ISREG(lock.st_mode) or lock.st_uid != os.geteuid()
                or stat.S_IMODE(lock.st_mode) != 0o600 or lock.st_nlink != 1):
            raise ValueError("successor Xray runtime lock was replaced or linked")
    finally:
        os.close(candidate)
        os.close(old)


def _checked_marker(record, old, digest, measured, prep):
    required = {
        "nodeId", "userId", "predecessorId", "successorSha256",
        "candidateMeterEpoch", "candidateReservationId",
        "freshRuntimeId", "freshContainerId", "freshStartedAt",
        "freshHostPid", "freshExecutableSha256", "freshConfigSha256",
        "freshWalInventorySha256", "zeroInitialRawCounters",
        "isolatedNewWalRoot", "authorizedBytes", "canSpend", "canStart",
        "canResume", "finalMeterVerified", "refundableBytes",
    }
    expected = {
        "nodeId": old["nodeId"], "userId": old["userId"],
        "predecessorId": old["reservationId"],
        "successorSha256": digest,
        "candidateMeterEpoch": prep["meterEpoch"],
        "candidateReservationId": prep["reservationId"],
        "freshRuntimeId": measured[3], "freshContainerId": measured[0],
        "freshStartedAt": measured[1], "freshHostPid": measured[2],
        "freshWalInventorySha256": EMPTY_SHA,
        "zeroInitialRawCounters": True, "isolatedNewWalRoot": True,
        "authorizedBytes": 0, "canSpend": False, "canStart": False,
        "canResume": False, "finalMeterVerified": False,
        "refundableBytes": 0,
    }
    if (not isinstance(record, dict) or set(record) != required or
            any(type(record[k]) is not type(value) or record[k] != value
                for k, value in expected.items()) or
            not isinstance(record["freshExecutableSha256"], str) or
            not isinstance(record["freshConfigSha256"], str) or
            not all(len(record[k]) == 64 and
                    all(c in "0123456789abcdef" for c in record[k])
                    for k in ("freshExecutableSha256", "freshConfigSha256"))):
        raise ValueError("fresh meter marker changed its nonauthorizing signed scope")
    return record


def observe_successor_meter(node, user, state, socket_path, executable_pin, config_pin,
                            *, predecessor=None, old_container=None, candidate_container=SUCCESSOR):
    """Capture the original signed scope and verify a separately pristine PID."""
    if (os.geteuid() != 0 or type(node) is not int or node <= 0
            or type(user) is not int or user <= 0
            or not isinstance(executable_pin, str)
            or not isinstance(config_pin, str)
            or any(calendar_fence.caps.HEX64.fullmatch(pin) is None
                   for pin in (executable_pin, config_pin))):
        raise ValueError("successor proof requires root and pinned fresh Xray files")
    old_args = (old_container,) if old_container else ()
    fd, lock = quarantine._locked_private_state(state)
    try:
        names = os.listdir(fd)
        pinned = wal_transport._panel_pin()
        if predecessor is None:
            old = renewal_worker.latest_signed_cap(fd, names, node, user, pinned)
        else:
            import successor_positive
            old = successor_positive.verified_chain(fd, names, node, user, pinned)[-1][0]
            if old != predecessor:
                raise ValueError("successor zero proof targets an obsolete predecessor")
        now = time.time_ns() // 1_000_000
        if now < old["validUntilMs"]:
            raise ValueError("predecessor is not expired")
        prep_name = renewal_worker._successor_filename(user, old)
        reply = lease._identity_file(fd, prep_name, 16384)
        prep = renewal_worker._verify_successor_reply(
            reply, old, node, user, renewal_worker._successor_nonce(old),
            pinned, now)
        digest = hashlib.sha256(wal_transport.observed.canonical(reply)).hexdigest()
        old_closed_name = calendar_fence._fence_name(user, old["reservationId"])
        closed = lease._identity_file(fd, old_closed_name, 32768)
        calendar_fence._checked_saved(closed, old, digest, old["runtimeId"])
        # A local marker is strictly nonauthorizing and only identifies an
        # immutable original close, with off-host birth+charge confirmations.
        if (closed["oldWalChargeConfirmation"][
                "allOldStreamTailsNexusAcknowledged"] is not True):
            raise ValueError("old Xray WAL is not fully acknowledged")
        previous, old_root = wal_transport._bound_journal(*old_args)
        fresh, fresh_root = wal_transport._bound_journal(candidate_container)
        _verify_fresh_container_env(fresh)
        measured = wal_transport._measure_quarantined_runtime(
            (executable_pin, config_pin), container_name=candidate_container)
        # The installed runtime requires independently pinned executable and
        # config on BOTH sides of the generation transition. Derive the old
        # config from the original signed policy, not Docker or the candidate.
        old_pins = None
        if installed_worker():
            original_config = calendar_fence._original_signed_scope(fd, old, node, pinned)
            if original_config != config_pin:
                raise ValueError("successor configuration differs from signed predecessor")
            old_pins = (executable_pin, original_config)
        original = wal_transport._measure_quarantined_runtime(old_pins, *old_args)
        if (measured[0] == original[0] or measured[2] == original[2]
                or measured[3] == original[3] or measured[3] == old["runtimeId"]
                or measured[0] != fresh.get("Id")
                or measured[2] != fresh.get("State", {}).get("Pid")
                or measured[0] == previous.get("Id")):
            raise ValueError("new Xray is the predecessor or an untrusted PID")
        _clean_mount(old_root, fresh_root, measured[3])
        if not 0 < len(old["aliasScopes"]) <= 16:
            raise ValueError("successor signed alias roster is missing")
        scope = {
            "schemaVersion": 1, "nodeId": node, "userId": user,
            "nonce": renewal_worker._successor_nonce(old),
            "meterEpoch": prep["meterEpoch"],
            "reservationId": prep["reservationId"],
            "aliases": old["aliasScopes"],
        }
        observation = cap_install.observe_zero_meter_in_xray(
            socket_path, measured[2], measured[3], scope)
        _clean_mount(old_root, fresh_root, measured[3])
        if wal_transport._measure_quarantined_runtime(
                (executable_pin, config_pin), container_name=candidate_container) != measured:
            raise ValueError("fresh Xray changed during zero-counter proof")
        marker = {
            "nodeId": node, "userId": user,
            "predecessorId": old["reservationId"], "successorSha256": digest,
            "candidateMeterEpoch": prep["meterEpoch"],
            "candidateReservationId": prep["reservationId"],
            "freshRuntimeId": measured[3], "freshContainerId": measured[0],
            "freshStartedAt": measured[1], "freshHostPid": measured[2],
            "freshExecutableSha256": executable_pin,
            "freshConfigSha256": config_pin,
            "freshWalInventorySha256": observation["inventorySha256"],
            "zeroInitialRawCounters": observation["zeroInitialRawCounters"],
            "isolatedNewWalRoot": observation["isolatedNewWalRoot"],
            "authorizedBytes": 0, "canSpend": False, "canStart": False,
            "canResume": False, "finalMeterVerified": False,
            "refundableBytes": 0,
        }
        _checked_marker(marker, old, digest, measured, prep)
        name = _name(user, old["reservationId"])
        if name in names:
            saved = lease._identity_file(fd, name, 16384)
            _checked_marker(saved, old, digest, measured, prep)
            if saved != marker:
                raise ValueError("recorded fresh Xray proof conflicts with new measurement")
            return False
        quarantine._durable_store(fd, marker, name)
        return True
    finally:
        os.close(lock)
        os.close(fd)


def container_for(user, predecessor):
    reservation = uuid.UUID(predecessor)
    if type(user) is not int or not 0 < user < 2**63 or str(reservation) != predecessor:
        raise ValueError("invalid managed generation identity")
    return f"xmesh-quota-u{user}-{reservation.hex}"


def control_socket(container):
    inspect, ledger = wal_transport._bound_journal(container)
    _verify_fresh_container_env(inspect)
    if not any(m.get("Destination") == wal_transport.journal.RUNTIME_DEST
               for m in inspect["Mounts"]):
        raise ValueError("generation requires a private runtime mount")
    return os.path.join(os.path.dirname(ledger), "drain.sock")


def _verify_unlaunched_runtime_root(root):
    """Never repurpose a vanished Xray's runtime directory.

    A stale drain socket, positive cap or any unexpected state could mean
    a previously funded process existed even though Docker lost its name.
    Keep every byte for explicit forensic recovery instead of restarting.
    """
    names = set(os.listdir(root))
    if names - {"ledger", "cap-binding.json"}:
        raise ValueError("unowned prior generation runtime requires recovery")


def _pinned_config_source(docker):
    """Extract exactly one read-only Xray config bind, never StopIteration.

    The caller independently measures the pinned config bytes and real PID;
    this validates Docker's mount shape before launching another candidate.
    """
    mounts = docker.get("Mounts") if isinstance(docker, dict) else None
    if not isinstance(mounts, list):
        raise ValueError("Xray has no verifiable configuration mount list")
    matched = [mount for mount in mounts if isinstance(mount, dict)
               and mount.get("Destination") == "/etc/xray/config.json"]
    if len(matched) != 1:
        raise ValueError("Xray requires one pinned configuration mount")
    mount = matched[0]
    source = mount.get("Source")
    if (mount.get("Type") != "bind" or mount.get("RW") is not False
            or not isinstance(source, str) or not os.path.isabs(source)
            or source in ("/", "/dev/null")):
        raise ValueError("Xray configuration mount differs from read-only pinned source")
    return source


def _signed_inbound_tags(old, user):
    """Validate the exact signed user/class roster before ANY Docker launch.

    A suffix alone is insufficient: a foreign user's email or a MAIN/CDN
    class mismatch must not become an allowed private socket. The same
    immutable policy check applies when reusing an interrupted generation.
    """
    aliases = old.get("aliasScopes") if isinstance(old, dict) else None
    if type(user) is not int or user <= 0 or not isinstance(aliases, list) or not 1 <= len(aliases) <= 2:
        raise ValueError("missing signed predecessor ingress scopes")
    seen = set()
    previous_email = ""
    for alias in aliases:
        if not isinstance(alias, dict) or set(alias) != {"email", "class"}:
            raise ValueError("malformed signed predecessor ingress scope")
        cls, email = alias["class"], alias["email"]
        if (cls not in ("main", "cdn") or type(email) is not str or
                email != f"xmesh-u{user}--vless-{cls}" or email <= previous_email):
            raise ValueError("foreign, unordered or mismatched signed inbound scope")
        tag = "vless-" + cls
        if tag in seen:
            raise ValueError("duplicate signed predecessor ingress scope")
        seen.add(tag)
        previous_email = email
    return sorted(seen)


def verify_reusable_generation(name, state, old, old_container, executable, config, pinned):
    """Accept an existing candidate ONLY as its actual, isolated live Xray.

    Docker name existence is not proof of a running process. Never restart a
    stopped generation here: an interrupted XSP/2 positive grant can already
    be funded remotely even if the local receipt did not reach disk.
    """
    before = wal_transport._measure_quarantined_runtime(
        (executable, config), old_container)
    if before[3] != old["runtimeId"]:
        raise ValueError("existing generation predecessor changed")
    old_inspect, old_ledger = wal_transport._bound_journal(old_container)
    current, ledger = wal_transport._bound_journal(name)
    _verify_fresh_container_env(current)
    root = str(Path(state) / name)
    old_image = old_inspect.get("Image")
    if (not isinstance(old_image, str)
            or re.fullmatch(r"sha256:[0-9a-f]{64}", old_image) is None
            or current.get("Name") != "/" + name
            or current.get("Image") != old_image
            or ledger != str(Path(root) / "ledger")):
        raise ValueError("existing generation has a foreign Docker identity or WAL root")
    # A candidate with the right Docker name, image and WAL, but started
    # without the private-VLESS byte gate must never be reused. The fresh
    # launcher supplies these exact settings from the signed alias roster.
    allowed = _signed_inbound_tags(old, old["userId"])
    config_env = current.get("Config")
    env = config_env.get("Env") if isinstance(config_env, dict) else None
    if not isinstance(env, list) or not all(isinstance(v, str) for v in env):
        raise ValueError("existing generation has no verifiable Xray gate environment")
    for required in ("XMESH_QUOTA_PRIVATE_VLESS=1",
                     "XMESH_EXPERIMENTAL_SCOPED_INBOUNDS=" + ",".join(allowed)):
        if env.count(required) != 1 or any(
                value.startswith(required.partition("=")[0] + "=") and value != required
                for value in env):
            raise ValueError("existing generation lost its private VLESS byte gate")
    mounts = current.get("Mounts")
    old_mounts = old_inspect.get("Mounts")
    if not isinstance(mounts, list) or not isinstance(old_mounts, list):
        raise ValueError("existing generation has no trusted Docker mounts")
    runtime_mounts = [m for m in mounts if isinstance(m, dict)
                      and m.get("Destination") == wal_transport.journal.RUNTIME_DEST
                      and m.get("Type") == "bind" and m.get("RW") is True]
    if (len(runtime_mounts) != 1 or runtime_mounts[0].get("Source") != root
            or _pinned_config_source(current) != _pinned_config_source(old_inspect)):
        raise ValueError("existing generation differs from signed predecessor mounts")
    # The deterministic Docker name is not the binding. Read the exact
    # root-private persisted Node/activation/Ed25519 policy identity that the
    # original launcher fsynced BEFORE starting any candidate Xray.
    expected = wal_transport.observed.canonical({
        "nodeId": old["nodeId"],
        "activationReceiptSha256": old["activationReceiptSha256"],
        "policyPublicKey": pinned,
    })
    binding = os.open(
        str(Path(root) / "cap-binding.json"),
        os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(binding, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                or stream.read(len(expected) + 1) != expected):
            raise ValueError("existing generation has a foreign signed-cap binding")
    if wal_transport._panel_pin() != pinned:
        raise ValueError("panel policy key changed while revalidating existing generation")
    measured = wal_transport._measure_quarantined_runtime(
        (executable, config), name)
    if measured[3] == before[3]:
        raise ValueError("existing generation reused predecessor kernel runtime")
    _clean_mount(old_ledger, ledger, measured[3])
    # At this stage the next action is ZERO-meter attestation, not positive
    # admission. If a previous process installed a cap or wrote byte intents
    # before its Agent receipt, refuse rather than observe a supposedly fresh
    # generation or mint another reservation.
    if any(item.startswith(("positive-cap-", "meter-")) for item in os.listdir(ledger)):
        raise ValueError("existing generation may already have signed spend or WAL")
    if wal_transport._measure_quarantined_runtime(
            (executable, config), old_container) != before:
        raise ValueError("predecessor changed while revalidating existing generation")
    return name


def start_generation(state, node, user, old, old_container, executable, config):
    """Provision only the deterministic empty candidate of a fenced reservation."""
    import vless_ingress

    installed = installed_worker()
    if not installed and not vless_ingress._staging_permitted():
        raise ValueError("automatic generation launch requires isolated staging")
    name = container_for(user, old["reservationId"])
    fd, lock = quarantine._locked_private_state(state)
    try:
        names = os.listdir(fd)
        pin = wal_transport._panel_pin()
        import successor_positive
        if successor_positive.verified_chain(fd, names, node, user, pin)[-1][0] != old:
            raise ValueError("generation predecessor changed before launch")
        prep = lease._identity_file(fd, renewal_worker._successor_filename(user, old), 16384)
        renewal_worker._verify_successor_reply(
            prep, old, node, user, renewal_worker._successor_nonce(old), pin,
            time.time_ns() // 1_000_000)
        digest = hashlib.sha256(wal_transport.observed.canonical(prep)).hexdigest()
        closed = lease._identity_file(fd, calendar_fence._fence_name(user, old["reservationId"]), 32768)
        calendar_fence._checked_saved(closed, old, digest, old["runtimeId"])
        if not closed["oldWalChargeConfirmation"]["allOldStreamTailsNexusAcknowledged"]:
            raise ValueError("generation cannot start before old WAL settlement")
        # Fail before creating or modifying the candidate WAL directory.
        allowed = _signed_inbound_tags(old, user)
        existing = subprocess.check_output([
            "docker", "ps", "-a", "--filter", f"name=^/{name}$", "--format", "{{.Names}}",
        ], timeout=10).decode().splitlines()
        if _name(user, old["reservationId"]) in names:
            raise ValueError("measured generation vanished after zero-WAL proof")
        if existing:
            if existing != [name]:
                raise ValueError("ambiguous managed generation container")
            return verify_reusable_generation(
                name, state, old, old_container, executable, config, pin)
        before = wal_transport._measure_quarantined_runtime((executable, config), old_container)
        if before[3] != old["runtimeId"]:
            raise ValueError("generation launch requires live fenced predecessor")
        container, _ = wal_transport._bound_journal(old_container)
        _verify_fresh_container_env(container)
        image = container.get("Image")
        if not isinstance(image, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise ValueError("generation requires an immutable Xray image")
        config_source = _pinned_config_source(container)
        root = Path(state) / name
        root.mkdir(mode=0o700, exist_ok=True)
        os.close(wal_transport.journal._validate_directory(root))
        _verify_unlaunched_runtime_root(root)
        ledger = root / "ledger"
        ledger.mkdir(mode=0o700, exist_ok=True)
        os.close(wal_transport.journal._validate_directory(ledger))
        if list(ledger.iterdir()):
            raise ValueError("unowned prior generation WAL requires recovery")
        binding = {
            "nodeId": node, "activationReceiptSha256": old["activationReceiptSha256"],
            "policyPublicKey": pin,
        }
        path = root / "cap-binding.json"
        raw = wal_transport.observed.canonical(binding)
        if path.exists():
            binding_fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(binding_fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                        or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                        or stream.read(len(raw) + 1) != raw):
                    raise ValueError("generation binding changed on disk")
        else:
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
        root_fd = wal_transport.journal._validate_directory(root)
        try:
            os.fsync(root_fd)
            os.fsync(fd)
        finally:
            os.close(root_fd)
        dest = wal_transport.journal.RUNTIME_DEST
        args = ["docker", "run", "-d", "--name", name, "--network", "none",
                "--restart=no", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--user", "0:0",
                "-v", f"{config_source}:/etc/xray/config.json:ro",
                "-v", f"{root}:{dest}:rw", "-e", "XMESH_EXPERIMENTAL_DRAIN=1",
                "-e", "XMESH_QUOTA_PRIVATE_VLESS=1",
                "-e", f"XMESH_EXPERIMENTAL_DRAIN_SOCKET={dest}/drain.sock",
                "-e", f"XMESH_EXPERIMENTAL_SIGNED_CAP_BINDING={dest}/cap-binding.json",
                "-e", f"XMESH_EXPERIMENTAL_OBSERVED_DIR={dest}/ledger",
                "-e", f"XMESH_EXPERIMENTAL_SCOPED_INBOUNDS={','.join(allowed)}"]
        if installed:
            from qualified_runtime_image import QUALIFICATION
            args.extend(["-e", "XMESH_QUOTA_V2_RUNTIME_ROLE=meter",
                         "-v", f"{QUALIFICATION}:{QUALIFICATION}:ro"])
        elif os.environ.get("GITHUB_ACTIONS") == "true":
            args.extend(["-e", "GITHUB_ACTIONS=true"])
        else:
            marker = vless_ingress.STAGING_MARKER
            args.extend(["-e", "XMESH_QUOTA_V2_STAGING_RUNTIME=1", "-v", f"{marker}:{marker}:ro"])
        subprocess.check_output(args + [image, "run", "-config", "/etc/xray/config.json"], timeout=30)
        return name
    finally:
        os.close(lock)
        os.close(fd)
