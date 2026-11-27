"""Disposable native Xray bootstrap with an immutable fence source snapshot.

This is not a service installer or permission to publish traffic. The caller
owns the original meter, signed evidence, pinned listener sockets and must
verify readback, transfer exclusivity and start the independent stop monitor.
No production activation or fallback path is implemented.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import public_tls_certificates as certificates
import public_tls_listener_manifest as manifests
import public_tls_namespace as namespace
import public_tls_namespace_inputs as namespace_inputs
import public_tls_spawn_preflight as preflight

SOURCE = Path(__file__).resolve().with_name("public_tls_network_fence.py")
MAX_SOURCE = 65536
CLONE_NEWPID = 0x20000000

SOURCE_LOADER = r"""
import fcntl, hashlib, os, stat, types

def load_sealed_network(fd, digest):
    info = os.fstat(fd)
    seals = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 0
            or not 0 < info.st_size <= 65536
            or fcntl.fcntl(fd, fcntl.F_GET_SEALS) != seals):
        raise ValueError("exact immutable network fence source required")
    raw = os.pread(fd, 65537, 0)
    if len(raw) != info.st_size or hashlib.sha256(raw).hexdigest() != digest:
        raise ValueError("network fence source digest mismatch")
    # The checked bytes, not an import or second pathname read, become code.
    network = types.ModuleType("xmesh_sealed_network_fence")
    exec(compile(raw, "<sealed-network-fence>", "exec"), network.__dict__)
    return network
"""

PIVOT_EXEC = SOURCE_LOADER + r"""
import codecs, ctypes, sys
from pathlib import Path
source, digest, root, executable, config, inventory = sys.argv[1:]
source, executable, config = int(source), int(executable), int(config)
expected = {int(fd) for fd in inventory.split(",")}
assert os.getpid() == 1 and os.geteuid() == os.getegid() == 0
assert {0, 1, 2, source, executable, config} <= expected
def open_fds():
    found = set()
    for item in os.listdir("/proc/self/fd"):
        try:
            fd = int(item)
            os.fstat(fd)
        except OSError:
            continue  # directory listing's already-closed FD
        found.add(fd)
    return found
assert open_fds() == expected
network = load_sealed_network(source, digest)
os.close(source)
assert open_fds() == expected - {source}
# Resolve layouts and module imports while original root is still available.
lib = ctypes.CDLL(None,use_errno=True)
lib.mount.argtypes = [ctypes.c_char_p,ctypes.c_char_p,ctypes.c_char_p,ctypes.c_ulong,ctypes.c_char_p]
lib.umount2.argtypes = [ctypes.c_char_p,ctypes.c_int]
class Header(ctypes.Structure):
    _fields_ = [("version",ctypes.c_uint32),("pid",ctypes.c_int)]
class Caps(ctypes.Structure):
    _fields_ = [(x,ctypes.c_uint32) for x in ("effective","permitted","inheritable")]
header,caps = Header(0x20080522,0),(Caps*2)()
network._Instruction(0,0,0,0)
network._Program()
network._Ruleset()
network._native()
# Python lazily resolves ASCII on the first text-mode status read.
# Cache the codec before detaching the original filesystem; the sandbox
# must contain no Python installation or other host files.
codecs.lookup("ascii")
last_cap = int(Path("/proc/sys/kernel/cap_last_cap").read_text())
RDONLY,NOSUID,NODEV,NOEXEC,REMOUNT,REC,PRIVATE = 1,2,4,8,32,16384,1<<18
def check(rc,msg):
    if rc:
        e=ctypes.get_errno()
        raise OSError(e,os.strerror(e),msg)
check(lib.mount(None,b"/",None,REC|PRIVATE,None),"private propagation")
check(lib.mount(b"proc",os.fsencode(root+"/proc"),b"proc",RDONLY|NOSUID|NODEV|NOEXEC,None),"readonly own proc")
os.chdir(root)
check(lib.syscall(155,b".",b"oldroot"),"pivot_root")
os.chdir("/")
check(lib.umount2(b"/oldroot",2),"detach old root")
os.rmdir("/oldroot")
check(lib.mount(None,b"/",None,REMOUNT|RDONLY|NOSUID|NODEV|NOEXEC,None),"readonly private root")
assert os.listdir("/") == ["proc"]
os.setgroups([])
for cap in range(last_cap+1):
    check(lib.prctl(24,cap,0,0,0),"drop bounding cap")
check(lib.capset(ctypes.byref(header),ctypes.byref(caps)),"clear caps")
check(lib.prctl(38,1,0,0,0),"no new privs")
assert network.install() is None
os.set_inheritable(executable,False)
os.execve(executable,["namespace-xray-candidate","run","-format","json","-config",
                     f"/proc/self/fd/{config}"],os.environ)
"""


def snapshot_fence(path=SOURCE):
    """Capture the exact source bytes once before launching the child."""
    import stat
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or not 0 < info.st_size <= MAX_SOURCE):
            raise ValueError("unsafe network fence source file")
        raw = os.pread(fd, MAX_SOURCE+1, 0)
        after = os.fstat(fd)
        identity = lambda i: (i.st_dev, i.st_ino, i.st_size, i.st_mtime_ns, i.st_ctime_ns)
        if len(raw) != info.st_size or identity(info) != identity(after):
            raise ValueError("network fence source changed while reading")
        compile(raw, "<sealed-network-fence>", "exec")
        return certificates._sealed_bytes("xmesh-network-fence-source", raw), hashlib.sha256(raw).hexdigest()
    finally:
        os.close(fd)


def spawn_disposable(*, original_ns, proof_args):
    """Return sole directly owned prebound diagnostic child; never listen.

    Preflight must be exact and fresh. The child inherits only declared inputs
    and closes the verified source before exec. All later readback and
    stop-monitor obligations remain mandatory, even if spawn succeeds.
    """
    if (os.geteuid() != 0 or os.getegid() != 0
            or os.environ.get("GITHUB_ACTIONS") != "true"
            or os.environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
            or os.environ.get("XMESH_DISPOSABLE_BOUND_LISTENER_TEST") != "1"
            or os.readlink("/proc/self/ns/net") == original_ns
            or os.readlink("/proc/1/ns/net") != original_ns
            or len(os.listdir("/proc/self/task")) != 1):
        raise ValueError("disposable hosted private network and single-thread owner required")
    links = json.loads(subprocess.check_output(["ip", "-j", "link", "show"], timeout=5))
    if len(links) != 1 or links[0]["ifname"] != "lo":
        raise ValueError("only a private loopback diagnostic namespace is allowed")
    native = proof_args.get("pinned_inputs")
    if type(native) is not namespace_inputs.NamespaceTlsInputs or native._child is not None:
        raise ValueError("exact unused native namespace inputs required")
    manifest = native._manifest
    root = os.readlink(f"/proc/self/fd/{native._root_fd}")
    if namespace.capture_root(native._root_fd) != native._root_token:
        raise ValueError("private root identity changed")
    info = os.stat(root, follow_symlinks=False)
    if (info.st_dev, info.st_ino) != native._root_token.root:
        raise ValueError("private root path differs from pinned inode")
    manifest.ensure_current()
    executable = proof_args["pinned_executable"].exec_fd
    config = native._original._certificates.config_fd
    doc = json.loads(os.pread(manifest.manifest_fd, manifests.MAX_MANIFEST, 0))
    env = dict(XMESH_NAMESPACE_INGRESS_DIAGNOSTIC="1",
               XMESH_NAMESPACE_CONFIG_FD=str(config),
               XMESH_NAMESPACE_LISTENER_MANIFEST_FD=str(manifest.manifest_fd),
               XMESH_NAMESPACE_ROUTE_MANIFEST_FD=str(native._native.child_fds[1]),
               XMESH_NAMESPACE_RUNTIME_ID=proof_args["runtime_id"],
               XMESH_NAMESPACE_ROSTER_SHA256=proof_args["cap_watch"].roster_sha256,
               XMESH_NAMESPACE_AUTHORITY_SHA256=doc["authoritySha256"],
               XMESH_NAMESPACE_CONFIG_SHA256=doc["configSha256"])
    source, digest = snapshot_fence()
    saved = child = None
    try:
        fds = (*native.child_fds, *manifest._listener_fds.values(), executable, source)
        if (len(fds) != len(set(fds)) or any(fd < 3 or os.get_inheritable(fd) for fd in fds)
                or len(fds) > 20):
            raise ValueError("invalid exact bootstrap FD set")
        if preflight.check_before_spawn(**proof_args) is not None:
            raise ValueError("preflight cannot authorize ingress")
        saved = os.open("/proc/self/ns/pid", os.O_RDONLY | os.O_CLOEXEC)
        lib = ctypes.CDLL(None, use_errno=True)
        def check(rc):
            if rc:
                error = ctypes.get_errno()
                raise OSError(error, os.strerror(error))
        check(lib.unshare(CLONE_NEWPID))
        try:
            child = subprocess.Popen(["/usr/bin/unshare", "--mount", "--net", "--ipc", "--uts",
                "--mount-proc", sys.executable, "-I", "-B", "-c", PIVOT_EXEC,
                str(source), digest, root, str(executable), str(config),
                ",".join(str(fd) for fd in (0,1,2,*fds))],
                pass_fds=fds, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, text=True)
        finally:
            check(lib.setns(saved, CLONE_NEWPID))
        return child
    except BaseException:
        if child is not None:
            if child.poll() is None:
                child.kill()
            child.wait(timeout=5)
        raise
    finally:
        if saved is not None:
            os.close(saved)
        os.close(source)
