"""Hosted-only, two-independent-artifact executable binding.

The signed namespace TLS executable is installed separately by the qualified
candidate installer. Its manifest and provenance hashes must come from the
reviewed input bundle, not the current installed directory. The ordinary
original meter remains bound to its *own* installed qualification and measured
process. This proof does not verify Sigstore itself, publish a listener, change
the ordinary release, or authorize production. Never use this path without
first running the independently pinned candidate installer.
"""
import hashlib
import os
from pathlib import Path
import re
import stat
import time

import install_namespace_candidate as installation
import namespace_candidate_artifact as artifact
import public_tls_executable as executable

HEX64 = re.compile(r"[a-f0-9]{64}\Z")


def _metadata(path, mode):
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1):
        raise ValueError("unsafe installed namespace candidate subject")
    return executable._identity(info)


class PinnedNamespaceCandidateExecutable(executable.PinnedTlsExecutable):
    """Seal a qualified frontend independently of the ordinary meter bytes.

    Normal operation is the ordinary measured release. The same-candidate
    meter variant is restricted to the existing isolated Node qualification
    fixture, without manufacturing an ordinary release identity.
    """

    def __init__(self, *, runtime_pid, runtime_id, source_root, revision,
                 manifest_sha256, provenance_sha256, fixture_same_candidate=False):
        if (os.geteuid() != 0 or os.getegid() != 0
                or os.environ.get("GITHUB_ACTIONS") != "true"
                or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
                or os.environ.get("XMESH_DISPOSABLE_BOUND_LISTENER_TEST") != "1"):
            raise ValueError("namespace executable proof requires disposable hosted qualification")
        if (type(fixture_same_candidate) is not bool
                or not all(isinstance(v, str) and HEX64.fullmatch(v)
                           for v in (manifest_sha256, provenance_sha256))):
            raise ValueError("exact reviewed namespace subject pins required")
        self._source = artifact.expected_source(Path(source_root), revision)
        self._candidate = installation.ROOT / revision
        self._manifest_sha = manifest_sha256
        self._provenance_sha = provenance_sha256
        self._same = fixture_same_candidate
        # Verify actual installed manifest+binary before starting the sealed
        # executable proof. Preserve metadata and exact signed byte digests
        # on every stop-monitor readback, with no online signing dependency.
        self._check_installation()
        raw = artifact.read_bounded(self._candidate/"candidate-manifest.json", artifact.MANIFEST_MAX)
        self._candidate_record = artifact.validate(
            raw, artifact.read_bounded(self._source_path(), artifact.ARTIFACT_MAX), self._source)
        if hashlib.sha256(raw).hexdigest() != self._manifest_sha:
            raise ValueError("installed namespace manifest differs from reviewed pin")
        if not self._same:
            identity = executable.release.read_identity(executable.release.QUALIFICATION)
            start = time.monotonic_ns()
            def deadline():
                if not 0 <= time.monotonic_ns()-start < executable.MAX_PREP_NS:
                    raise ValueError("ordinary meter preparation exceeded watchdog budget")
            with os.fdopen(os.open(executable.release.EXECUTABLE,
                    executable.READ_FLAGS | os.O_NOFOLLOW), "rb") as ordinary:
                self._ordinary_id, digest = executable._read_hash(ordinary.fileno(), deadline)
            if digest != identity["artifactSha256"]:
                raise ValueError("ordinary installed executable differs from its verified release")
            self._ordinary_record = identity
        super().__init__(runtime_pid=runtime_pid, runtime_id=runtime_id)

    def _source_path(self):
        return self._candidate/"xray"

    def _check_installation(self):
        installation.private_directory(installation.ROOT)
        installation.private_directory(self._candidate)
        if {item.name for item in self._candidate.iterdir()} != set(installation.FILES):
            raise ValueError("foreign or incomplete installed namespace candidate")
        states = {}
        for name, (limit, mode) in installation.FILES.items():
            path = self._candidate/name
            before = _metadata(path, mode)
            if name != "xray":
                expected = self._manifest_sha if name == "candidate-manifest.json" else self._provenance_sha
                actual = hashlib.sha256(artifact.read_bounded(path, limit)).hexdigest()
                if actual != expected:
                    raise ValueError("installed namespace subject differs from reviewed pin")
            if _metadata(path, mode) != before:
                raise ValueError("installed namespace subject changed during proof")
            states[name] = before
        root = installation.ROOT.lstat()
        directory = self._candidate.lstat()
        return ((root.st_dev, root.st_ino), (directory.st_dev, directory.st_ino), states)

    def _read_record(self):
        states = self._check_installation()
        record = {"artifactSha256": self._candidate_record["artifactSha256"],
                  "candidateInstallation": states}
        if not self._same:
            if (executable.release.read_identity(executable.release.QUALIFICATION)
                    != self._ordinary_record
                    or executable._source_identity(executable.release.EXECUTABLE.lstat())
                    != self._ordinary_id):
                raise ValueError("ordinary installed qualification or executable changed")
            record["originalMeter"] = self._ordinary_record
        return record

    def _meter_digest(self, record):
        return (record["artifactSha256"] if self._same
                else record["originalMeter"]["artifactSha256"])
