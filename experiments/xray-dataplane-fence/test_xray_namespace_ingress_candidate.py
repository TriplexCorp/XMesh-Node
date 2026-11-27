#!/usr/bin/env python3
"""Real disposable namespace TLS frontend -> original signed metered Xray.

No production installation, public interface, issued Nexus authority or
release evidence. Both TLS ports are bound ONLY in a loopback-only
private test namespace, using ephemeral fixture signatures/certificates.
"""
from contextlib import ExitStack
import ctypes
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import select
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import uuid
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "experiments/quota-v2-physical-stop"))
from test_quota_v2_public_tls_bound_listener import require_disposable_namespace
from test_quota_v2_public_tls_certificates import CertificateTests, DOMAIN_A, DOMAIN_B
from test_quota_v2_xray_user_inbound_drain import recv_exact
from test_xray_live_ingress_cutover import (
    NODE, ACTIVATION, USER_A, USER_B, UUID_A, UUID_B, CLASSES,
    server_profile, signed_pair, canonical, sign, reserve_port,
)
from test_xray_patched_fence import await_socket, query_direction_counters
import cap_install
import public_tls_bound_listener as bound
import public_tls_cap_watch as cap_watch
import public_tls_child_inputs as child_inputs
import public_tls_deadman as deadman
import public_tls_frontend as tls
import public_tls_listener_manifest as manifests
import public_tls_listener_readback as readback
import public_tls_namespace as namespace
import public_tls_namespace_route as namespace_route
import public_tls_pinned_inputs as pinned
import public_tls_routes as routes
import runtime_identity
import vless_ingress

PIVOT_EXEC = r"""
import ctypes, os, sys
from pathlib import Path
module_dir, module_sha, root, executable, config = sys.argv[1:]
sys.path.insert(0,module_dir)
import public_tls_network_fence as network
import hashlib
assert hashlib.sha256(Path(network.__file__).read_bytes()).hexdigest() == module_sha
assert os.getpid() == 1 and os.geteuid() == 0
executable,config = int(executable),int(config)
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

ECHO = r"""
import socketserver
class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        while True:
            data=self.request.recv(65536)
            if not data: return
            self.request.sendall(data)
class Server(socketserver.ThreadingTCPServer):
    daemon_threads=True
with Server(("127.0.0.1",0),Handler) as server:
    print(server.server_address[1],flush=True)
    server.serve_forever()
"""


def stop(process):
    if process.poll() is None:
        process.kill()
    process.wait(timeout=5)


def seal_binary(path):
    fd = os.memfd_create("xmesh-disposable-namespace-xray",
                         os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING | 0x10)
    try:
        with path.open("rb") as src, os.fdopen(os.dup(fd), "wb") as dst:
            shutil.copyfileobj(src, dst)
        os.fchmod(fd, 0o755)
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_SHRINK |
                    fcntl.F_SEAL_GROW | fcntl.F_SEAL_SEAL | 0x10 | 0x20)
        with path.open("rb") as src, os.fdopen(os.dup(fd), "rb") as dst:
            dst.seek(0)
            assert hashlib.file_digest(src,"sha256").digest() == hashlib.file_digest(dst,"sha256").digest()
        return fd
    except BaseException:
        os.close(fd)
        raise


def child_line(child, expected_prefix, timeout=10):
    # Read from the pipe itself: TextIOWrapper.readline can buffer the
    # second listener marker while select sees no additional kernel bytes.
    deadline = time.monotonic()+timeout
    data = getattr(child, "_xmesh_stage_buffer", b"")
    while time.monotonic() < deadline:
        if b"\n" not in data:
            if not select.select([child.stdout],[],[],max(0,deadline-time.monotonic()))[0]:
                break
            block = os.read(child.stdout.fileno(),65536)
            if not block:
                break
            data += block
            if len(data) > 1<<20:
                raise AssertionError("candidate stage output exceeded bound")
            continue
        raw,data = data.split(b"\n",1)
        child._xmesh_stage_buffer = data
        line = raw.decode("utf-8","replace").strip()
        print("candidate:",line,flush=True)
        if line.startswith(expected_prefix):
            return line
    raise AssertionError("missing actual candidate stage "+expected_prefix)


def tls_echo(port,domain,ca,user_uuid,echo_port,payload):
    context = ssl.create_default_context(cafile=str(ca))
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    with socket.create_connection(("127.0.0.1",port),timeout=3) as raw:
        with context.wrap_socket(raw,server_hostname=domain) as client:
            assert client.version() == "TLSv1.3"
            client.settimeout(4)
            header = (b"\x00"+uuid.UUID(user_uuid).bytes+b"\x00\x01"+
                      struct.pack(">H",echo_port)+b"\x01"+socket.inet_aton("127.0.0.1"))
            client.sendall(header+payload)
            response = recv_exact(client,2)
            assert response[0] == 0
            if response[1]:
                recv_exact(client,response[1])
            assert recv_exact(client,len(payload)) == payload


def run(binary, original_ns):
    require_disposable_namespace(original_ns)
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="xmesh-namespace-xray-")))
        executable = root/"xray"
        shutil.copyfile(binary,executable)
        executable.chmod(0o700)
        assert hashlib.sha256(executable.read_bytes()).digest() == hashlib.sha256(binary.read_bytes()).digest()
        echo = subprocess.Popen([sys.executable,"-I","-B","-c",ECHO],stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,text=True)
        stack.callback(stop,echo)
        echo_port = int(child_line(echo,""))
        ports = {"main":8443,"cdn":443}
        domains = {"main":DOMAIN_B,"cdn":DOMAIN_A}
        api_port = reserve_port()
        profile = server_profile(echo_port,ports,api_port)
        policy = hashlib.sha256(canonical(profile)).hexdigest()
        backend = json.loads(json.dumps(profile))
        for inbound in backend["inbounds"]:
            inbound.pop("port")
            inbound["listen"] = str(root/("unused-"+inbound["tag"]+".sock"))
        (root/"meter.json").write_bytes(canonical(backend))
        ledger = root/"ledger"
        ledger.mkdir(mode=0o700)
        key = root/"nexus-key.pem"
        subprocess.run(["openssl","genpkey","-algorithm","ED25519","-out",str(key)],check=True,timeout=10)
        public = subprocess.check_output(["openssl","pkey","-in",str(key),"-pubout","-outform","DER"])
        assert len(public)==44
        public = public[-32:].hex()
        binding = root/"binding.json"
        binding.write_bytes(canonical({"nodeId":NODE,"activationReceiptSha256":ACTIVATION,
                                       "policyPublicKey":public}))
        binding.chmod(0o600)
        control = root/"control.sock"
        meterlog = stack.enter_context((root/"meter.log").open("wb"))
        meter = subprocess.Popen([str(executable),"run","-config",str(root/"meter.json")],
            stdout=meterlog,stderr=subprocess.STDOUT,env=dict(os.environ,
                GITHUB_ACTIONS="true",XMESH_EXPERIMENTAL_DRAIN="1",
                XMESH_QUOTA_PRIVATE_VLESS="1",
                XMESH_EXPERIMENTAL_SCOPED_INBOUNDS="vless-cdn,vless-main",
                XMESH_EXPERIMENTAL_SIGNED_CAP_BINDING=str(binding),
                XMESH_EXPERIMENTAL_OBSERVED_DIR=str(ledger),
                XMESH_EXPERIMENTAL_DRAIN_SOCKET=str(control)))
        stack.callback(stop,meter)
        await_socket(control,meter)
        runtime = runtime_identity.trusted_runtime_identity(meter.pid)
        meter_dir = Path("/dev/shm/xmesh-"+runtime)
        stack.callback(shutil.rmtree,meter_dir,True)
        deadline = time.monotonic()+10
        while not all((meter_dir/("vless-"+cls)).is_socket() for cls in CLASSES):
            if meter.poll() is not None or time.monotonic() >= deadline:
                raise AssertionError("actual signed-meter private listeners did not start")
            time.sleep(.05)
        enrolled = root/"enrolled"
        enrolled.mkdir(mode=0o700)
        capsule = root/"capsule"
        capsule.mkdir(mode=0o700)
        stack.enter_context(mock.patch.object(routes,"ROOT",capsule))
        stack.enter_context(mock.patch.object(routes,"ENROLLED_STATE",enrolled))
        enrolled_fd = os.open(enrolled,routes.DIR_FLAGS)
        stack.callback(os.close,enrolled_fd)
        grants = {}
        epoch = str(uuid.uuid4())
        for user in (USER_A,USER_B):
            genesis,grant,scope,claims = signed_pair(
                root,key,runtime,policy,user,epoch,str(uuid.uuid4()),str(uuid.uuid4()))
            cap_install.install_in_xray(str(control),meter.pid,runtime,genesis,grant,scope)
            grants[user] = grant
            with mock.patch.dict(os.environ,{"XMESH_QUOTA_V2_INGRESS_STAGING":"1"}):
                vless_ingress.publish(enrolled_fd,claims,("a"*64,"unused",meter.pid,runtime))
        witness = cap_watch.SignedCapRosterWatch(profile=profile,signed_grants=grants,
            pinned=public,node=NODE,activation=ACTIVATION,genesis_sha=policy,
            runtime_id=runtime,trusted_pid=meter.pid,socket_path=control)
        assert witness.check() is None
        certificate = CertificateTests("test_two_independent_root_owned_lineages_and_signed_paths")
        certificate.setUp()
        stack.callback(certificate.doCleanups)
        now = time.time_ns()//1_000_000
        authority = sign(root,key,b"",{
            "schemaVersion":1,"kind":"xmesh.quota-v2.public-tls-ingress","nodeId":NODE,
            "activationReceiptSha256":ACTIVATION,"genesisPolicySha256":policy,
            "runtimeId":runtime,"profileRevision":policy,"issuedAtMs":now,
            "validUntilMs":now+60_000,"canServePublic":True,
            "bindings":[{"tag":"vless-"+cls,"port":ports[cls],"domain":domains[cls]} for cls in CLASSES],
        })
        binding_args = dict(node=NODE,activation=ACTIVATION,genesis_sha=policy,runtime_id=runtime,pinned=public)
        config = tls.compile_signed_public_tls(profile,authority,**binding_args)
        inputs = stack.enter_context(pinned.PinnedTlsInputs(profile=profile,authority=authority,
            cap_watch=witness,enrolled_fd=enrolled_fd,runtime_pid=meter.pid,**binding_args))
        native_routes = stack.enter_context(namespace_route.NamespaceMeterInputs(inputs._routes))
        sockets = {}
        for row in config["inbounds"]:
            owner = stack.enter_context(socket.socket(socket.AF_INET,socket.SOCK_STREAM))
            owner.bind((row["listen"],row["port"]))
            sockets[row["tag"]] = owner
        network_cookie = bound.network_namespace_cookie(next(iter(sockets.values())))
        manifest = stack.enter_context(manifests.ListenerManifest(inputs=inputs,config=config,
            authority=authority,cap_watch=witness,runtime_pid=meter.pid,sockets=sockets,
            netns_cookie=network_cookie))
        tokens = dict(manifest._tokens)
        fixed = (inputs._certificates.config_fd,*inputs._certificates.material_fds,
                 *native_routes.child_fds,manifest.manifest_fd)
        forbidden = tuple(fd for fd in (*inputs._certificates._fds,*inputs._routes._fds) if fd not in fixed)
        route_fd = native_routes.child_fds[0]
        child_token = child_inputs.capture(expected=fixed,forbidden=forbidden,route_fd=route_fd)
        sandbox = root/"sandbox"
        sandbox.mkdir(mode=0o700)
        subprocess.run(["mount","-t","tmpfs","-o","mode=0700,size=1m,nosuid,nodev,noexec",
                        "tmpfs",str(sandbox)],check=True,timeout=5)
        stack.callback(subprocess.run,["umount",str(sandbox)],check=True,timeout=5)
        (sandbox/"proc").mkdir(mode=0o700)
        (sandbox/"oldroot").mkdir(mode=0o700)
        root_fd = os.open(sandbox,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        stack.callback(os.close,root_fd)
        root_token = namespace.capture_root(root_fd)
        executable_fd = seal_binary(executable)
        stack.callback(os.close,executable_fd)
        fence_contents = (ROOT/"experiments/quota-v2-physical-stop/public_tls_network_fence.py").read_bytes()
        module_dir = root/"modules"
        module_dir.mkdir(mode=0o700)
        (module_dir/"public_tls_network_fence.py").write_bytes(fence_contents)
        (module_dir/"public_tls_network_fence.py").chmod(0o600)
        manifest_doc = json.loads(os.pread(manifest.manifest_fd,manifests.MAX_MANIFEST,0))
        env = dict(XMESH_NAMESPACE_INGRESS_DIAGNOSTIC="1",
                   XMESH_NAMESPACE_CONFIG_FD=str(inputs._certificates.config_fd),
                   XMESH_NAMESPACE_LISTENER_MANIFEST_FD=str(manifest.manifest_fd),
                   XMESH_NAMESPACE_ROUTE_MANIFEST_FD=str(native_routes.child_fds[1]),
                   XMESH_NAMESPACE_RUNTIME_ID=runtime,
                   XMESH_NAMESPACE_ROSTER_SHA256=witness.roster_sha256,
                   XMESH_NAMESPACE_AUTHORITY_SHA256=manifest_doc["authoritySha256"],
                   XMESH_NAMESPACE_CONFIG_SHA256=manifest_doc["configSha256"])
        assert len(os.listdir("/proc/self/task")) == 1
        saved = os.open("/proc/self/ns/pid",os.O_RDONLY|os.O_CLOEXEC)
        libc = ctypes.CDLL(None,use_errno=True)
        def check(rc):
            if rc:
                e=ctypes.get_errno()
                raise OSError(e,os.strerror(e))
        child = None
        try:
            check(libc.unshare(0x20000000))
            try:
                child = subprocess.Popen(["unshare","--mount","--net","--ipc","--uts",
                    "--mount-proc",sys.executable,"-I","-B","-c",PIVOT_EXEC,
                    str(module_dir),hashlib.sha256(fence_contents).hexdigest(),str(sandbox),
                    str(executable_fd),str(inputs._certificates.config_fd)],
                    pass_fds=(*fixed,*[s.fileno() for s in sockets.values()],executable_fd),
                    env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,text=True)
            finally:
                check(libc.setns(saved,0x20000000))
        finally:
            os.close(saved)
        assert child is not None
        stack.callback(stop,child)
        try:
            child_line(child,"xmesh_namespace_candidate_prebound")
            assert namespace.verify(child.pid,root_fd,root_token) is None
            assert child_inputs.verify(child,expected=fixed,forbidden=forbidden,route_fd=route_fd,
                                       pinned=child_token) is None
            assert os.path.samestat(os.stat(f"/proc/{child.pid}/exe"),os.fstat(executable_fd))
            assert witness.check() is None
            for tag, owner in sockets.items():
                readback.verify_child_fd(child,owner.fileno(),tokens[tag])
                readback.verify_listen_state(tokens[tag],listening=False)
            for tag, owner in sockets.items():
                owner.close()
                readback.require_no_copy(os.getpid(),tokens[tag])
            guardian = deadman.StopOnlyDeadman(child=child,timeout_ms=10_000)
            stack.callback(guardian.close)
            for token in tokens.values():
                readback.require_no_copy(guardian._guardian.pid,token)
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:
                    probe.settimeout(2)
                    assert probe.connect_ex(("127.0.0.1",token.port)) == errno.ECONNREFUSED
            guardian.pulse(deadline_ns=time.monotonic_ns()+8_000_000_000,
                           wall_deadline_ms=time.time_ns()//1_000_000+8000)
            child.stdin.write("fixture_namespace_xray_transfer\n")
            child.stdin.flush()
            found = set()
            for _ in tokens:
                line = child_line(child,"xmesh_namespace_candidate_listener:")
                _,port,fd = line.split(":")
                port,fd=int(port),int(fd)
                assert port not in found
                found.add(port)
                token=next(t for t in tokens.values() if t.port==port)
                readback.verify_child_fd(child,fd,token)
                readback.verify_listen_state(token,listening=True)
            assert found == set(ports.values())
            for cls,user in (("main",UUID_A),("cdn",UUID_B)):
                tls_echo(ports[cls],domains[cls],certificate.ca_cert,user,echo_port,os.urandom(16384))
            assert witness.check() is None
            assert namespace.verify(child.pid,root_fd,root_token) is None
            assert manifest.ensure_manifest() is None
            assert native_routes.ensure_current() is None
            guardian.pulse(deadline_ns=time.monotonic_ns()+4_000_000_000,
                           wall_deadline_ms=time.time_ns()//1_000_000+4000)
            for user,cls in ((USER_A,"main"),(USER_B,"cdn")):
                assert query_direction_counters(str(executable),api_port,
                    f"xmesh-u{user}--vless-{cls}") == {"uplink":16384,"downlink":16384}
            assert child.wait(timeout=6)==-9
            assert guardian._guardian.wait(timeout=2)==1
            for token in tokens.values():
                readback.verify_listen_state(token,listening=False)
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:
                    probe.settimeout(2)
                    assert probe.connect_ex(("127.0.0.1",token.port))==errno.ECONNREFUSED
            print("PASS: actual isolated sealed Xray TLS candidate -> original authenticated "
                  "signed MAIN/CDN meter; exact 16KiB each direction; physical stop of both ports.")
        finally:
            stop(child)
            remainder=getattr(child,"_xmesh_stage_buffer",b"").decode("utf-8","replace")+child.stdout.read()
            if remainder:
                print(remainder,file=sys.stderr)
            meterlog.flush()
            print((root/"meter.log").read_text(errors="replace")[-12000:],file=sys.stderr)


if __name__ == "__main__":
    assert len(sys.argv)==3
    run(Path(sys.argv[1]).resolve(),sys.argv[2])
