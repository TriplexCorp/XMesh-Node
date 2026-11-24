#!/usr/bin/env python3
"""Prepare a content-pinned isolated Xray image from installed release bytes.

This is candidate preparation only: no container is started, no network is
connected, no quota state is created and no traffic is authorized.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile

QUALIFICATION = Path("/var/lib/xmesh-metered-xray")
EXECUTABLE = Path("/usr/local/libexec/xmesh-metered-xray")
FIELDS = ("nexusRevision", "nodeSourceRevision", "upstreamSourceRevision",
          "patchSourceTree", "artifactSha256")
MAX_BINARY = 256 << 20


def parse_identity(raw):
    lines = raw.decode("ascii").split("\n")
    if len(lines) != len(FIELDS) + 1 or lines[-1] != "":
        raise ValueError("invalid qualification record")
    values = {}
    for name, line in zip(FIELDS, lines):
        key, separator, value = line.partition("=")
        if (key != name or not separator or not re.fullmatch(
                r"[0-9a-f]{64}" if key == "artifactSha256" else r"[0-9a-f]{40}", value)):
            raise ValueError("invalid qualification field")
        values[key] = value
    return values


def read_identity(root):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("unsafe qualification directory")
        record = os.open("identity", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
                         | os.O_CLOEXEC, dir_fd=fd)
        with os.fdopen(record, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
                    or not 0 < info.st_size <= 4096):
                raise ValueError("unsafe qualification record")
            raw = stream.read(4097)
            if len(raw) != info.st_size:
                raise ValueError("qualification changed while reading")
            return parse_identity(raw)
    finally:
        os.close(fd)


def stage_binary(source, destination, digest):
    fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o755 or info.st_nlink != 1
                or not 0 < info.st_size <= MAX_BINARY):
            raise ValueError("unsafe installed metered Xray")
        sha = hashlib.sha256()
        total = 0
        with destination.open("xb") as output:
            while chunk := stream.read(1 << 20):
                total += len(chunk)
                if total > MAX_BINARY:
                    raise ValueError("metered executable exceeds size bound")
                sha.update(chunk)
                output.write(chunk)
            output.flush()
            os.fchmod(output.fileno(), 0o755)
            os.fsync(output.fileno())
        if total != info.st_size or sha.hexdigest() != digest:
            raise ValueError("installed executable differs from verified release")


def docker(*args, timeout=90):
    return subprocess.check_output(
        ["docker", *args], env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
                                 "DOCKER_HOST": "unix:///var/run/docker.sock"},
        timeout=timeout,
    )


def verify_image_config(config):
    if (not isinstance(config, dict) or config.get("Entrypoint") != ["/xray"]
            or config.get("Cmd") not in (None, []) or config.get("Volumes") not in (None, {})
            or config.get("ExposedPorts") not in (None, {})
            or config.get("Healthcheck") is not None
            or config.get("OnBuild") not in (None, [])
            or config.get("User") not in ("", "0", "0:0")):
        raise ValueError("unexpected qualified image configuration")


def build_image():
    if os.geteuid() != 0:
        raise ValueError("qualified image preparation requires root")
    identity = read_identity(QUALIFICATION)
    digest = identity["artifactSha256"]
    with tempfile.TemporaryDirectory(prefix="xmesh-qualified-image-") as directory:
        root = Path(directory)
        context = root / "context"
        context.mkdir(mode=0o700)
        stage_binary(EXECUTABLE, context / "xray", digest)
        (context / "Dockerfile").write_text(
            'FROM scratch\nCOPY xray /xray\nENTRYPOINT ["/xray"]\n',
            encoding="ascii",
        )
        iid = root / "image-id"
        # No external base, network fetch, build argument, mutable tag or
        # runtime execution. The image is referenced only by its content ID.
        docker("build", "--network=none", "--pull=false", "--no-cache",
               "--iidfile", str(iid), str(context), timeout=180)
        image = iid.read_text(encoding="ascii").strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise ValueError("Docker did not return an immutable image ID")
        inspected = json.loads(docker("image", "inspect", image))
        if (not isinstance(inspected, list) or len(inspected) != 1
                or inspected[0]["Id"] != image
                or inspected[0]["Architecture"] != "amd64"
                or inspected[0]["Os"] != "linux"):
            raise ValueError("unexpected qualified image identity")
        verify_image_config(inspected[0]["Config"])
        # Read back the executable from a never-started container. A
        # build success or an image label is not proof of the copied bytes.
        cid = docker("create", "--network=none", "--read-only", "--cap-drop=ALL",
                     "--security-opt=no-new-privileges", image).decode("ascii").strip()
        if not re.fullmatch(r"[0-9a-f]{64}", cid):
            raise ValueError("invalid nonrunning image inspection container")
        try:
            copied = root / "checked-xray"
            docker("cp", cid + ":/xray", str(copied))
            info = copied.lstat()
            if (not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BINARY
                    or stat.S_IMODE(info.st_mode) != 0o755):
                raise ValueError("unexpected executable in prepared image")
            with copied.open("rb") as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                    raise ValueError("prepared image executable differs from release")
        finally:
            docker("rm", "-v", cid)
        if read_identity(QUALIFICATION) != identity:
            raise ValueError("qualification changed during image preparation")
        return {"imageId": image, "artifactSha256": digest,
                "nodeSourceRevision": identity["nodeSourceRevision"],
                "productionActivationAuthorized": False}


if __name__ == "__main__":
    print(json.dumps(build_image(), sort_keys=True))
