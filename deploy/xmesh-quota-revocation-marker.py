#!/usr/bin/env python3
"""Durable, root-owned quota-v2 deny marker for the production Xray reconciler.

A marker is admission DENIAL only; it is never metering evidence or a
permission to release outstanding quota reservations. State-dir ownership,
symlinks, inode replacement, hardlinking and failed fsync fail closed.
"""
import argparse
import os
import secrets
import stat
import sys

MARKER = "quota-revocation-deny-pending"
CONTENT = b"signed-v2-deny\n"
CLOEXEC = getattr(os, "O_CLOEXEC", 0)
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)


def open_private_dir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | NOFOLLOW | CLOEXEC)
    info = os.fstat(fd)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or (info.st_mode & 0o077):
        os.close(fd)
        raise ValueError("unsafe quota-v2 state directory")
    return fd


def verify_marker(dirfd):
    try:
        info = os.stat(MARKER, dir_fd=dirfd, follow_symlinks=False)
    except FileNotFoundError:
        return False
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or info.st_size != len(CONTENT)):
        raise ValueError("unsafe or substituted quota-v2 revocation marker")
    fd = os.open(MARKER, os.O_RDONLY | NOFOLLOW | CLOEXEC, dir_fd=dirfd)
    try:
        opened = os.fstat(fd)
        if (opened.st_dev != info.st_dev or opened.st_ino != info.st_ino
                or opened.st_nlink != 1 or opened.st_uid != os.geteuid()):
            raise ValueError("quota-v2 marker changed during verification")
        if os.read(fd, len(CONTENT) + 1) != CONTENT:
            raise ValueError("invalid quota-v2 revocation marker content")
    finally:
        os.close(fd)
    return True


def arm(dirfd):
    if verify_marker(dirfd):
        # A crash might have left the existing link visible but not durable.
        os.fsync(dirfd)
        return
    tmp = ".quota-v2-intent-" + secrets.token_hex(16)
    filefd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW | CLOEXEC,
                     0o600, dir_fd=dirfd)
    try:
        try:
            written = os.write(filefd, CONTENT)
            if written != len(CONTENT):
                raise OSError("short quota-v2 marker write")
            os.fsync(filefd)
        finally:
            os.close(filefd)
        # Atomic exclusive publication: never overwrite an existing denial.
        os.link(tmp, MARKER, src_dir_fd=dirfd, dst_dir_fd=dirfd,
                follow_symlinks=False)
        os.fsync(dirfd)
    finally:
        # The temporary hardlink is never a valid denial marker. If SIGKILL
        # interrupts cleanup, startup refuses the ambiguous link count.
        os.unlink(tmp, dir_fd=dirfd)
        os.fsync(dirfd)
    if not verify_marker(dirfd):
        raise ValueError("quota-v2 denial was not durably published")


def clear(dirfd):
    # Must be called ONLY after committed signed policy and successful router
    # reconciliation. A stale marker after failed sync causes a safe outage.
    if verify_marker(dirfd):
        os.unlink(MARKER, dir_fd=dirfd)
    os.fsync(dirfd)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("operation", choices=("status", "arm", "clear"))
    parser.add_argument("state_dir")
    args = parser.parse_args()
    dirfd = open_private_dir(args.state_dir)
    try:
        if args.operation == "status":
            print("armed" if verify_marker(dirfd) else "clear")
        elif args.operation == "arm":
            arm(dirfd)
        else:
            clear(dirfd)
    finally:
        os.close(dirfd)


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError) as exc:
        print(f"CRITICAL: quota-v2 durable revocation marker: {exc}", file=sys.stderr)
        sys.exit(1)
