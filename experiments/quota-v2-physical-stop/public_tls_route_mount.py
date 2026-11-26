"""Detached, read-only Linux mount view of an exact private route inode.

This does not make the underlying source filesystem or other paths immutable.
It does not create a mountpoint in the host namespace, start Xray or grant
authority. No weaker pathname-only fallback is permitted.
"""
import ctypes
import os

AT_EMPTY_PATH = 0x1000
OPEN_TREE_CLONE = 1
MOUNT_ATTR_RDONLY = 0x00000001
MOUNT_ATTR_NOSUID = 0x00000002
MOUNT_ATTR_NODEV = 0x00000004
MOUNT_ATTR_NOEXEC = 0x00000008
ATTRS = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC
VFS_FLAGS = os.ST_RDONLY | os.ST_NOSUID | os.ST_NODEV | os.ST_NOEXEC
DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


class MountAttr(ctypes.Structure):
    _fields_ = [(name, ctypes.c_uint64) for name in
                ("attr_set", "attr_clr", "propagation", "userns_fd")]


def _libc():
    # Fail closed if the local Linux kernel/libc cannot provide the modern
    # mount FD API. Do not edit the host's mount namespace or fall back to
    # a pathname remount that leaves an inherited writable FD.
    libc = ctypes.CDLL(None, use_errno=True)
    libc.open_tree.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    libc.open_tree.restype = ctypes.c_int
    libc.mount_setattr.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint,
                                  ctypes.POINTER(MountAttr), ctypes.c_size_t]
    libc.mount_setattr.restype = ctypes.c_int
    return libc


def mount_id(fd):
    with open(f"/proc/self/fdinfo/{fd}", encoding="ascii") as handle:
        found = [line.split(":", 1)[1].strip() for line in handle
                 if line.startswith("mnt_id:")]
    if len(found) != 1 or not found[0].isdigit() or int(found[0]) <= 0:
        raise ValueError("missing kernel route mount identity")
    return int(found[0])


def check_view(source_fd, readonly_fd, expected_mount):
    source = os.fstat(source_fd)
    view = os.fstat(readonly_fd)
    flags = os.fstatvfs(readonly_fd).f_flag
    if ((source.st_dev, source.st_ino) != (view.st_dev, view.st_ino)
            or mount_id(readonly_fd) != expected_mount
            or mount_id(source_fd) == expected_mount
            or flags & VFS_FLAGS != VFS_FLAGS
            or os.get_inheritable(readonly_fd)):
        raise ValueError("private TLS route descriptor is not its pinned read-only mount")


def readonly_view(source_fd):
    """Return a CLOEXEC directory FD on a detached mount, same source inode."""
    if os.geteuid() != 0:
        raise ValueError("root required for detached private route mount")
    libc = _libc()
    tree = libc.open_tree(source_fd, b"", AT_EMPTY_PATH | OPEN_TREE_CLONE | os.O_CLOEXEC)
    if tree < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err), "open_tree route capsule")
    view = None
    try:
        attr = MountAttr(ATTRS, 0, 0, 0)
        if libc.mount_setattr(tree, b"", AT_EMPTY_PATH, ctypes.byref(attr), ctypes.sizeof(attr)) < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err), "mount_setattr route capsule")
        # open_tree yields O_PATH. Reopen the exact detached mount's root
        # through that FD for listdir/fstat; never reopen the original path.
        view = os.open(".", DIR_FLAGS, dir_fd=tree)
        identity = mount_id(tree)
        check_view(source_fd, view, identity)
        result = view, identity
        view = None
        return result
    finally:
        if view is not None:
            os.close(view)
        os.close(tree)
