"""Detached, read-only Linux mount view of an exact private route inode.

This does not make the underlying source filesystem or other paths immutable.
It does not create a mountpoint in the host namespace, start Xray or grant
authority. No weaker pathname-only fallback is permitted.
"""
import ctypes
import errno
import os
import signal
import socket
import struct
import time

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


def _clone_readonly(source_fd):
    """Clone and restrict an exact FD in its own mount namespace.

    No pathname or procfs read is needed while accessing the foreign mount.
    The caller must independently check the returned descriptor.
    """
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
        result = view
        view = None
        return result
    finally:
        if view is not None:
            os.close(view)
        os.close(tree)


def readonly_view(source_fd):
    """Return a CLOEXEC directory FD on a detached mount, same source inode."""
    view = _clone_readonly(source_fd)
    try:
        identity = mount_id(view)
        check_view(source_fd, view, identity)
        return view, identity
    except BaseException:
        os.close(view)
        raise


def _close_except(keep):
    for entry in os.listdir("/proc/self/fd"):
        fd = int(entry)
        if fd not in keep:
            try:
                os.close(fd)
            except OSError as exc:
                # listdir's own temporary descriptor is already closed.
                if exc.errno != errno.EBADF:
                    raise


def readonly_meter_view(source_fd, pidfd, pid):
    """Clone an actual original meter directory across mount namespaces.

    The kernel rejects open_tree(CLONE) on a mount outside the caller's
    namespace. A single-use forked helper enters the exact pinned *pidfd*'s
    mount namespace, clones only the already-open source FD and restricts
    the detached tree before returning one FD. The supervisor never changes
    namespaces; neither the helper nor the native process may retain an
    original namespace/root, writable route, relay or arbitrary other FD.
    No bind mount, path reopen, mutable remount or fallback is permitted.
    """
    import public_tls_peer_identity as peers

    if (os.geteuid() != 0 or os.getegid() != 0
            or len(os.listdir('/proc/self/task')) != 1
            or type(source_fd) is not int or source_fd < 3
            or os.get_inheritable(source_fd) or source_fd == pidfd):
        raise ValueError("single-thread root and private meter descriptors required")
    peer = peers.capture_original(pidfd, pid)
    own_ns = os.readlink('/proc/self/ns/mnt')
    meter_ns = os.readlink(f'/proc/{pid}/ns/mnt')
    if own_ns == meter_ns:
        view, identity = readonly_view(source_fd)
        try:
            if (os.readlink(f'/proc/{pid}/ns/mnt') != meter_ns
                    or peers.capture_original(pidfd, pid) != peer):
                raise ValueError("original meter changed during same-namespace clone")
            return view, identity
        except BaseException:
            os.close(view)
            raise

    creds = struct.Struct('3i')
    integer = struct.Struct('i')
    parent, child = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET | socket.SOCK_CLOEXEC)
    helper = None
    received = []
    try:
        parent.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        parent.settimeout(3)
        helper = os.fork()
        if helper == 0:
            try:
                # Close copies of ALL supervisor-owned inputs except the
                # two already-pinned meter FDs and the one return socket,
                # *before* entering the original meter's mount namespace.
                parent.close()
                _close_except({source_fd, pidfd, child.fileno()})
                os.setns(pidfd, os.CLONE_NEWNS)
                view = _clone_readonly(source_fd)
                if child.sendmsg([b'R'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                           integer.pack(view))]) != 1:
                    os._exit(1)
                os.close(view)
                os._exit(0)
            except BaseException:
                os._exit(1)
        child.close()
        raw, ancillary, flags, _ = parent.recvmsg(2,
            socket.CMSG_SPACE(creds.size) + socket.CMSG_SPACE(integer.size),
            socket.MSG_CMSG_CLOEXEC)
        credentials = []
        unexpected = False
        for level, kind, data in ancillary:
            if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                # Close even partial received descriptors on error.
                for offset in range(0, len(data)-integer.size+1, integer.size):
                    received.append(integer.unpack_from(data, offset)[0])
                unexpected |= len(data) != integer.size
            elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS and len(data) == creds.size:
                credentials.append(creds.unpack(data))
            else:
                unexpected = True
        if (raw != b'R' or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC)
                or unexpected or len(received) != 1 or credentials != [(helper, 0, 0)]):
            raise ValueError("invalid exact detached meter FD transfer")
        # Child must have exited before the supervisor can accept this view.
        end = time.monotonic() + 1
        while True:
            waited, status = os.waitpid(helper, os.WNOHANG)
            if waited:
                helper = None
                if status != 0:
                    raise ValueError("detached meter helper failed")
                break
            if time.monotonic() >= end:
                raise ValueError("detached meter helper did not exit")
            time.sleep(0.01)
        view = received[0]
        identity = mount_id(view)
        check_view(source_fd, view, identity)
        if (os.readlink('/proc/self/ns/mnt') != own_ns
                or os.readlink(f'/proc/{pid}/ns/mnt') != meter_ns
                or peers.capture_original(pidfd, pid) != peer):
            raise ValueError("original meter or supervisor mount namespace changed")
        received.clear()
        return view, identity
    finally:
        parent.close()
        child.close()
        for fd in received:
            os.close(fd)
        if helper is not None and helper > 0:
            # The unreaped directly-owned PID cannot be recycled.
            os.kill(helper, signal.SIGKILL)
            os.waitpid(helper, 0)
