#!/usr/bin/env python3
"""Strict byte/source contract for the *separate* namespace Xray candidate.

This contract is not a release pin, permission to publish a listener, or
a replacement for verification of both GitHub attestation subjects.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

UPSTREAM = "a4a3dff5b20c2faae567b742c172c7b95e75c083"
GO_VERSION = "go version go1.27.4 linux/amd64"
BUILD_FLAGS = ["GOOS=linux", "GOARCH=amd64", "GOAMD64=v1", "CGO_ENABLED=0", "-trimpath"]
SCENARIOS = ["signed-witness-expiry", "signed-revocation"]
ARTIFACT_MAX = 256 << 20
MANIFEST_MAX = 16384
BUNDLE_MAX = 1 << 20
TREE_PATHS = {
    "nodeSourceTree": "HEAD^{tree}",
    "patchSourceTree": "HEAD:experiments/xray-dataplane-fence",
    "namespacePeerTree": "HEAD:experiments/quota-v2-physical-stop/namespacepeer",
}


def git(root, rev):
    value = subprocess.check_output(["git", "--no-optional-locks", "-c", f"safe.directory={root}", "-C", str(root), "rev-parse", "--verify", rev],
                                    text=True, timeout=10).strip()
    if not re.fullmatch(r"[a-f0-9]{40}", value):
        raise ValueError("untrusted candidate source identity")
    return value


def expected_source(root, revision):
    if (not re.fullmatch(r"[a-f0-9]{40}", revision or "")
            or git(root, "HEAD") != revision):
        raise ValueError("candidate verifier must be the exact expected source checkout")
    dirty = subprocess.check_output(["git", "--no-optional-locks", "-c", f"safe.directory={root}", "-C", str(root), "status", "--porcelain",
                                     "--untracked-files=all"], timeout=10)
    if dirty:
        raise ValueError("candidate source checkout must be clean: " + repr(dirty[:2048]))
    return {"nodeSourceRevision": revision, "upstreamSourceRevision": UPSTREAM,
            **{field: git(root, path) for field, path in TREE_PATHS.items()}}


def read_bounded(path, maximum):
    """Read a regular, single-link file without following an input symlink."""
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC),
                   "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or not 0 < before.st_size <= maximum):
            raise ValueError("invalid candidate subject file")
        raw = source.read(maximum+1)
        after = os.fstat(source.fileno())
        if (len(raw) != before.st_size or
                (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)):
            raise ValueError("candidate subject file changed during read")
        return raw


def canonical(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False)
            + "\n").encode("ascii")


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate candidate manifest field")
        result[key] = value
    return result


def contract(source, digest):
    return {
        "schemaVersion": 1,
        "kind": "xmesh.namespace-xray-candidate",
        **source,
        "goVersion": GO_VERSION,
        "buildFlags": BUILD_FLAGS,
        "artifactSha256": digest,
        "independentRebuildMatched": True,
        "verifiedScenarios": SCENARIOS,
        "candidateOnly": True,
        "productionActivationAuthorized": False,
    }


def validate(raw, binary, source):
    if not 0 < len(raw) <= MANIFEST_MAX:
        raise ValueError("candidate manifest exceeds bound")
    value = json.loads(raw, object_pairs_hook=_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite manifest")))
    digest = hashlib.sha256(binary).hexdigest()
    expected = contract(source, digest)
    # Canonical bytes reject duplicate keys, type coercions, alternate
    # numeric encodings, unknown fields and even trailing whitespace.
    if raw != canonical(expected) or value != expected:
        raise ValueError("foreign, mutable or authorizing namespace candidate manifest")
    if not binary.startswith(b"\x7fELF"):
        raise ValueError("candidate subject is not an ELF executable")
    return expected


def generate(root, revision, binary_path, rebuilt_path, output):
    source = expected_source(root, revision)
    binary = read_bounded(binary_path, ARTIFACT_MAX)
    rebuilt = read_bounded(rebuilt_path, ARTIFACT_MAX)
    if binary != rebuilt:
        raise ValueError("independent namespace candidate rebuild differs")
    if subprocess.check_output(["go", "version"], text=True, timeout=10).strip() != GO_VERSION:
        raise ValueError("unexpected namespace compiler identity")
    manifest = canonical(contract(source, hashlib.sha256(binary).hexdigest()))
    validate(manifest, binary, source)
    output.mkdir(mode=0o700, exist_ok=False)
    (output/"xray").write_bytes(binary)
    (output/"xray").chmod(0o755)
    (output/"candidate-manifest.json").write_bytes(manifest)
    print(manifest.decode("ascii"), end="")


def check(root, revision, directory):
    source = expected_source(root, revision)
    manifest = read_bounded(directory/"candidate-manifest.json", MANIFEST_MAX)
    binary = read_bounded(directory/"xray", ARTIFACT_MAX)
    value = validate(manifest, binary, source)
    print(canonical(value).decode("ascii"), end="")


if __name__ == "__main__":
    if len(sys.argv) == 7 and sys.argv[1] == "generate":
        generate(Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]), Path(sys.argv[5]), Path(sys.argv[6]))
    elif len(sys.argv) == 5 and sys.argv[1] == "check":
        check(Path(sys.argv[2]), sys.argv[3], Path(sys.argv[4]))
    else:
        raise SystemExit("usage: namespace_candidate_artifact.py generate SOURCE REVISION BINARY REBUILD OUTPUT | check SOURCE REVISION DIRECTORY")
