#!/usr/bin/env python3
"""Install verified namespace candidate bytes side-by-side, never activate.

Only the dedicated candidate directory is written; no product executable,
systemd unit, Node state, production qualification or listener is changed.
The wrapper supplies an independently pinned gh executable. This script
is not invoked by the ordinary bootstrap path.
"""
import ctypes
import errno
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent))
import namespace_candidate_artifact as artifact

ROOT = Path("/var/lib/xmesh-namespace-xray-candidate")
SIGNER = "TriplexCorp/XMesh-Node"
WORKFLOW = SIGNER + "/.github/workflows/quota-v2-namespace-xray-candidate.yml"
FILES = {"xray": (artifact.ARTIFACT_MAX, 0o755),
         "candidate-manifest.json": (artifact.MANIFEST_MAX, 0o600),
         "provenance.jsonl": (artifact.BUNDLE_MAX, 0o600)}
AT_FDCWD = -100
RENAME_NOREPLACE = 1


def private_directory(path):
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise ValueError("unsafe namespace candidate directory")


def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_exact(target, raw, mode):
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, mode)
    with os.fdopen(fd, "wb") as out:
        os.fchmod(out.fileno(), mode)
        out.write(raw)
        out.flush()
        os.fsync(out.fileno())


def check_existing(target, staged):
    private_directory(target)
    if {entry.name for entry in target.iterdir()} != set(FILES):
        raise ValueError("incomplete or foreign installed namespace candidate")
    for name, (limit, mode) in FILES.items():
        path = target/name
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
                or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1
                or artifact.read_bounded(path, limit) != artifact.read_bounded(staged/name, limit)):
            raise ValueError("installed namespace candidate differs; refusing replacement")


def publish(stage, target):
    # Never replace any existing artifact directory, even in a concurrent
    # install. A complete fsynced directory appears atomically.
    libc = ctypes.CDLL(None, use_errno=True)
    if not hasattr(libc, "renameat2"):
        raise ValueError("atomic no-replacement candidate installation required")
    rename = libc.renameat2
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    if rename(AT_FDCWD, os.fsencode(stage), AT_FDCWD, os.fsencode(target), RENAME_NOREPLACE):
        err = ctypes.get_errno()
        if err == errno.EEXIST:
            check_existing(target, stage)
            return
        raise OSError(err, os.strerror(err))
    fsync_dir(target.parent)


def install(source_root, expected_revision, inputs, gh):
    if os.geteuid() != 0 or not re.fullmatch(r"[a-f0-9]{40}", expected_revision):
        raise ValueError("root and exact candidate source revision required")
    source = artifact.expected_source(source_root, expected_revision)
    # Copy first into a private work directory; the attacker-writable
    # download path is never used during verification or installation.
    with tempfile.TemporaryDirectory(prefix="xmesh-namespace-verify-") as directory:
        work = Path(directory)
        private_directory(work)
        for name, (limit, mode) in FILES.items():
            write_exact(work/name, artifact.read_bounded(inputs/name, limit), mode)
        raw = artifact.read_bounded(work/"candidate-manifest.json", artifact.MANIFEST_MAX)
        binary = artifact.read_bounded(work/"xray", artifact.ARTIFACT_MAX)
        artifact.validate(raw, binary, source)
        for subject in ("candidate-manifest.json", "xray"):
            subprocess.run([str(gh), "attestation", "verify", str(work/subject),
                            "--bundle", str(work/"provenance.jsonl"), "--repo", SIGNER,
                            "--signer-workflow", WORKFLOW, "--source-ref", "refs/heads/main",
                            "--source-digest", expected_revision, "--deny-self-hosted-runners"],
                           cwd=work, env={"PATH":"/usr/bin:/bin", "GH_PROMPT_DISABLED":"1",
                                "HOME":str(work), "XDG_CACHE_HOME":str(work/"cache"),
                                "XDG_CONFIG_HOME":str(work/"config"),
                                "GH_CONFIG_DIR":str(work/"gh-config")},
                           check=True, timeout=180)
        # A failed/missing/foreign attestation does not create the
        # candidate installation root or publish any bytes.
        try:
            ROOT.mkdir(mode=0o700)
        except FileExistsError:
            pass
        private_directory(ROOT)
        stage = Path(tempfile.mkdtemp(prefix=".stage-", dir=ROOT))
        target = ROOT/expected_revision
        try:
            private_directory(stage)
            for name, (limit, mode) in FILES.items():
                write_exact(stage/name, artifact.read_bounded(work/name, limit), mode)
            fsync_dir(stage)
            publish(stage, target)
            if stage.exists():
                check_existing(target, stage)
            else:
                check_existing(target, work)
        finally:
            if stage.exists():
                shutil.rmtree(stage)
        fsync_dir(ROOT)
        fsync_dir(ROOT.parent)
        print("Verified side-by-side namespace candidate installed (NOT authorized):", target/"xray")


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit("usage: install_namespace_candidate.py SOURCE REVISION ARTIFACT_DIRECTORY PINNED_GH")
    install(Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), Path(sys.argv[4]))
