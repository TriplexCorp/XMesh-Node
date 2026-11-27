#!/usr/bin/env python3
"""Check a cold meter build against its exact attested source checkout.

Only the explicitly reviewed namespace-only extension of the current
ordinary-meter tree is compatible with that older signed base. The ordinary
meter is always built from the separate attested source, never the extension.
"""
import re
import subprocess
import sys

PATH = "experiments/xray-dataplane-fence"
SIGNED_BASE = "838bf0d56374f437df02275812953719a3937efe"
REVIEWED_EXTENSION = "2d4716bc6445d6143ea9b10d6c231f5246062f69"
EXTRA = frozenset((
    "apply-namespace-ingress-candidate.py",
    "install-namespace-xray-candidate.sh",
    "install_namespace_candidate.py",
    "namespace_candidate_artifact.py",
    "namespace_candidate_executable.py",
    "namespace_ingress_candidate.go.txt",
    "test_xray_namespace_ingress_candidate.py",
    "test_xray_namespace_systemd.py",
))


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def git(root, *args):
    # Under sudo, even a read-only git status must not refresh the user's
    # index with root ownership or the installer's private umask.
    return subprocess.check_output(["git", "--no-optional-locks", "-C", str(root), *args], timeout=20)


def entries(raw):
    require(raw.endswith(b"\0"), "empty or malformed patch tree")
    result = {}
    for row in raw[:-1].split(b"\0"):
        identity, name = row.split(b"\t", 1)
        mode, kind, digest = identity.split(b" ")
        require(mode in (b"100644", b"100755") and kind == b"blob"
                and re.fullmatch(rb"[0-9a-f]{40}", digest), "non-regular patch source")
        name = name.decode("ascii")
        require(re.fullmatch(r"[A-Za-z0-9_.-]+", name) and name not in (".", "..")
                and name not in result, "unexpected or duplicate patch source path")
        result[name] = identity
    return result


def verify_projection(installed_tree, attested_tree, installed, attested):
    require(attested and installed, "missing patch source")
    if installed_tree == attested_tree:
        require(installed == attested, "identical tree IDs must have identical entries")
        return
    require(attested_tree == SIGNED_BASE and installed_tree == REVIEWED_EXTENSION,
            "unqualified ordinary-meter patch tree")
    require(set(installed) == set(attested) | EXTRA and not set(attested) & EXTRA,
            "unreviewed namespace-only extension")
    require(all(installed[name] == value for name, value in attested.items()),
            "signed ordinary-meter source changed")


def verify(installed, signed, revision, tree):
    require(re.fullmatch(r"[0-9a-f]{40}", revision) and re.fullmatch(r"[0-9a-f]{40}", tree),
            "invalid signed source identity")
    require(git(signed, "rev-parse", "HEAD").strip().decode() == revision,
            "attested source checkout differs")
    require(git(signed, "rev-parse", "HEAD:" + PATH).strip().decode() == tree,
            "attested patch tree differs")
    for root in (installed, signed):
        require(not git(root, "status", "--porcelain=v1", "--untracked-files=all", "--", PATH),
                "dirty patch source checkout")
    actual = git(installed, "rev-parse", "HEAD:" + PATH).strip().decode()
    verify_projection(actual, tree, entries(git(installed, "ls-tree", "-r", "-z", "HEAD:" + PATH)),
                      entries(git(signed, "ls-tree", "-r", "-z", "HEAD:" + PATH)))


if __name__ == "__main__":
    if len(sys.argv) != 5:
        raise SystemExit("usage: verify-metered-xray-patch-source.py INSTALLED SIGNED REVISION TREE")
    try:
        verify(*sys.argv[1:])
    except (ValueError, UnicodeError, subprocess.SubprocessError) as error:
        raise SystemExit("Metered Xray source rejected: " + str(error))
