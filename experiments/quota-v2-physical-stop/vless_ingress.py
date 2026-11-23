"""Private per-user routes for the isolated installed-Agent ingress."""
import os
import re
import secrets
import socket
import stat
import struct
import time
import uuid

import wal_transport

STAGING_MARKER = "/etc/xmesh-quota-v2-staging"


def _staging_permitted():
    """Root-owned opt-in for reviewed experimental staging outside CI.

    A marker is NEVER positive spending authority: the enrolled policy,
    executable pin, signed-cap and Xray's private Unix peer all remain
    independently mandatory.
    """
    # GITHUB_ACTIONS is a user-settable environment string, not an
    # attestation of a trusted runner. Even disposable CI must explicitly
    # install the same root-owned opt-in marker as an operator staging node.
    if os.geteuid() != 0:
        return False
    try:
        fd = os.open(STAGING_MARKER, os.O_RDONLY | os.O_NOFOLLOW
                     | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return False
    try:
        info = os.fstat(fd)
        return (stat.S_ISREG(info.st_mode) and info.st_uid == 0
                and info.st_nlink == 1 and stat.S_IMODE(info.st_mode) == 0o600)
    finally:
        os.close(fd)


def target(pid, runtime):
    if type(pid) is not int or pid < 1 or not re.fullmatch("[0-9a-f]{64}", runtime):
        raise ValueError("invalid ingress runtime identity")
    return f"/proc/{pid}/root/dev/shm/xmesh-{runtime}"


def publish(fd, payload, measured, predecessor=None, *, restore_missing=False):
    """Called under the Agent state lock after signed install and WAL evidence."""
    if os.environ.get("XMESH_QUOTA_V2_INGRESS_STAGING") != "1":
        return
    # A route is NOT a new authorization. Only the already verified,
    # currently spendable Nexus cap may be published. A stale or foreign
    # permit must never resurrect a previously fenced user.
    if (not isinstance(payload, dict) or type(measured) not in (tuple, list)
            or len(measured) != 4):
        raise ValueError("invalid independently measured ingress grant")
    user = payload.get("userId")
    now = time.time_ns() // 1_000_000
    if (type(user) is not int or user <= 0
            or type(payload.get("nodeId")) is not int or payload["nodeId"] <= 0
            or payload.get("schemaVersion") != 1
            or payload.get("kind") != "xmesh.quota-v2.xray-cap-admission"
            or type(payload.get("validUntilMs")) is not int
            or now >= payload["validUntilMs"]
            or payload.get("canSpend") is not True
            or payload.get("canStart") is not False
            or payload.get("canResume") is not False
            or payload.get("finalMeterVerified") is not False
            or payload.get("refundableBytes") != 0
            or payload.get("runtimeId") != measured[3]
            or not isinstance(payload.get("aliasScopes"), list)
            or not 1 <= len(payload["aliasScopes"]) <= 16
            or any(not isinstance(payload.get(k), str)
                   or str(uuid.UUID(payload[k])) != payload[k]
                   for k in ("accountEpoch", "meterEpoch", "reservationId"))):
        raise ValueError("expired, foreign or nonspending signed ingress cap")
    pid, runtime = measured[2:]
    destination = target(pid, runtime)
    link = f"ingress-u{user}"
    try:
        current = os.readlink(link, dir_fd=fd)
    except FileNotFoundError:
        current = None
    if current not in (predecessor, destination) and not (restore_missing and current is None):
        raise ValueError("ingress route differs from signed predecessor")
    if wal_transport.runtime_identity.trusted_runtime_identity(pid) != runtime:
        raise ValueError("ingress peer no longer owns this grant")
    previous_email = ""
    for alias in payload["aliasScopes"]:
        if not isinstance(alias, dict) or set(alias) != {"email", "class"}:
            raise ValueError("malformed signed VLESS inbound scope")
        cls, email = alias["class"], alias["email"]
        if (cls not in ("main", "cdn") or not isinstance(email, str)
                or email <= previous_email):
            raise ValueError("duplicate or unordered signed VLESS scope")
        previous_email = email
        tag = "vless-" + cls
        if email != f"xmesh-u{user}--{tag}":
            raise ValueError("invalid ingress class")
        # A kernel PID can be seven digits: the literal
        # /proc/<pid>/root/dev/shm/xmesh-<64hex>/vless-* pathname then
        # exceeds Linux sockaddr_un.sun_path (107 useful bytes).
        # Open the source-pinned PRIVATE inode first and connect through a
        # short /proc/self/fd path, without changing global CWD or creating
        # an attacker-raceable temporary symlink.
        directory = os.open(destination, os.O_RDONLY | os.O_DIRECTORY
                            | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            inode = os.fstat(directory)
            if (not stat.S_ISDIR(inode.st_mode) or
                    stat.S_IMODE(inode.st_mode) != 0o700 or
                    inode.st_uid != os.geteuid()):
                raise ValueError("private VLESS target directory changed")
            with socket.socket(socket.AF_UNIX) as probe:
                probe.settimeout(3)
                probe.connect(f"/proc/self/fd/{directory}/{tag}")
                peer = probe.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                if struct.unpack("3i", peer)[:2] != (pid, os.geteuid()):
                    raise ValueError("private VLESS socket has a different owner")
        finally:
            os.close(directory)
    if wal_transport.runtime_identity.trusted_runtime_identity(pid) != runtime:
        raise ValueError("Xray changed before ingress publication")
    if current != destination:
        pending = ".ingress-" + secrets.token_hex(12)
        os.symlink(destination, pending, dir_fd=fd)
        try:
            os.replace(pending, link, src_dir_fd=fd, dst_dir_fd=fd)
        finally:
            try:
                os.unlink(pending, dir_fd=fd)
            except FileNotFoundError:
                pass
    os.fsync(fd)


def frontend(profile):
    """Build the loopback staging frontend from the measured VLESS roster."""
    if not isinstance(profile, dict) or not isinstance(profile.get("inbounds"), list):
        raise ValueError("signed Xray profile has no bounded inbounds")
    inbounds, rules = [], []
    outbounds = [{"tag": "deny", "protocol": "blackhole"}]
    tags = set()
    for inbound in profile["inbounds"]:
        if not isinstance(inbound, dict):
            raise ValueError("malformed signed VLESS inbound")
        tag = inbound.get("tag")
        if tag in tags:
            raise ValueError("duplicate signed VLESS inbound tag")
        tags.add(tag)
        if (tag not in ("vless-main", "vless-cdn") or inbound["protocol"] != "vless"
                or inbound.get("listen") != "127.0.0.1" or inbound.get("settings", {}).get("fallbacks")):
            raise ValueError("unsupported staging ingress")
        seen = set()
        for client in inbound["settings"]["clients"]:
            email = client["email"]
            identifier = str(uuid.UUID(client["id"]))
            if (not re.fullmatch(r"xmesh-u[1-9][0-9]{0,18}--" + tag, email)
                    or identifier in seen or client.get("flow") or client.get("reverse")
                    or any(o["tag"] == email for o in outbounds)):
                raise ValueError("ambiguous VLESS ingress identity or unsupported flow")
            seen.add(identifier)
            rules.append({"type": "field", "inboundTag": [tag], "user": [email], "outboundTag": email})
            outbounds.append({"tag": email, "protocol": "vless", "settings": {"vnext": [{
                "address": "xmesh-meter.invalid", "port": 1,
                "users": [{"id": identifier, "email": email, "encryption": "none"}],
            }]}})
        inbounds.append(inbound)
    if not inbounds or not rules:
        raise ValueError("missing VLESS roster")
    return {"inbounds": inbounds, "routing": {"rules": rules}, "outbounds": outbounds}


def serve(panel, node, state, binary):
    """Run a persistent loopback frontend from authenticated staging evidence."""
    import fcntl
    import hashlib
    import stat
    import genesis_reservation as lease
    import quarantine_policy as quarantine

    if os.environ.get("XMESH_QUOTA_V2_INGRESS_STAGING") != "1":
        raise ValueError("private ingress is not enabled for this fixture")
    if not _staging_permitted():
        raise ValueError("unverified production ingress: missing root-only staging marker")
    fd, lock = quarantine._locked_private_state(state, read_only=True)
    try:
        enrollment = quarantine._enrolled_activation(panel, node)
        original = lease._identity_file(fd, "genesis-quarantine-envelope.json", quarantine.MAX_REPLY + 4096)
        reply = original["reply"]
        policy = reply["policy"]
        pinned = wal_transport._panel_pin()
        quarantine._guard().check_signature(policy, reply["policySignature"], pinned)
        profile = reply["config"]
        config_sha = hashlib.sha256(wal_transport.observed.canonical(profile)).hexdigest()
        if (policy["nodeId"] != node or policy["configSha256"] != config_sha
                or policy["quotaV2Genesis"]["firstActivationReceiptSha256"] != enrollment["activationReceiptSha256"]):
            raise ValueError("ingress roster differs from enrolled signed policy")
        intent = lease._identity_file(fd, quarantine.INTENT_FILE, 4096)
        exe = os.open(binary, os.O_RDONLY | os.O_NOFOLLOW)
        info = os.fstat(exe)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022
                or not 0 < info.st_size <= 256 << 20 or intent["nodeId"] != node):
            raise ValueError("unsafe ingress executable")
        with os.fdopen(os.dup(exe), "rb") as binary_file:
            if hashlib.file_digest(binary_file, "sha256").hexdigest() != intent["executableSha256"]:
                raise ValueError("ingress executable differs from reviewed Xray")
        config = os.memfd_create("xmesh-ingress", os.MFD_ALLOW_SEALING)
        with os.fdopen(os.dup(config), "wb") as stream:
            stream.write(wal_transport.observed.canonical(frontend(profile)))
        fcntl.fcntl(config, fcntl.F_ADD_SEALS,
                    fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL)
        # Xray's normal file loader requires a recognized filename suffix.
        # Its explicit stdin loader consumes the same sealed, anonymous bytes.
        os.lseek(config, 0, os.SEEK_SET)
        if config == 0:
            os.set_inheritable(0, True)
        else:
            os.dup2(config, 0, inheritable=True)
            os.close(config)
    finally:
        os.close(lock)
        os.close(fd)
    runtime_env = {"XMESH_QUOTA_INGRESS_STATE": state}
    if os.environ.get("GITHUB_ACTIONS") == "true":
        runtime_env["GITHUB_ACTIONS"] = "true"
    else:
        runtime_env["XMESH_QUOTA_INGRESS_STAGING"] = "1"
    os.execve(exe, [binary, "run", "-format", "json", "-config", "stdin:"],
              runtime_env)


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--panel", required=True)
    parser.add_argument("--node", type=int, required=True)
    parser.add_argument("--state", default="/var/lib/xmesh-xray-sync")
    parser.add_argument("--binary", default="/var/lib/xmesh-measured-lab/xray-client")
    serve(**vars(parser.parse_args()))
