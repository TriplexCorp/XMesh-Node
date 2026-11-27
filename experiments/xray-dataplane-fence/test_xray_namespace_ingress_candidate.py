#!/usr/bin/env python3
"""Real disposable namespace TLS frontend -> original signed metered Xray.

No production installation, public interface, live Nexus issuer or
production release evidence. An independently attested side-by-side
candidate may be selected only on the disposable installed-candidate test path. Both TLS ports are bound ONLY in a loopback-only
private test namespace, using ephemeral fixture signatures/certificates.
"""
from contextlib import ExitStack
import errno
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
import journal_integrity as journal
import meter_inventory_audit as inventory
import public_tls_bound_listener as bound
import public_tls_cap_watch as cap_watch
import public_tls_executable as qualified_executable
import public_tls_frontend as tls
import public_tls_listener_manifest as manifests
import public_tls_listener_readback as readback
import public_tls_namespace as namespace
import public_tls_namespace_route as namespace_route
import public_tls_namespace_inputs as namespace_inputs
import public_tls_pinned_inputs as pinned
import public_tls_revocation_watch as revocation
import public_tls_namespace_launcher as launcher
import public_tls_stop_monitor as stop_monitor
import public_tls_routes as routes
import runtime_identity
import vless_ingress


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


def run(binary, original_ns, stop_mode, installed=False):
    assert stop_mode in {"expiry", "revoked"}
    require_disposable_namespace(original_ns)
    with ExitStack() as stack:
        root = Path(stack.enter_context(tempfile.TemporaryDirectory(prefix="xmesh-namespace-xray-")))
        if installed:
            # The separately signed qualification job installed this exact
            # file in the isolated candidate store. Never copy or rename it
            # over the normal product metered Xray.
            import namespace_candidate_artifact as artifact
            import install_namespace_candidate as installation
            revision = artifact.git(ROOT, "HEAD")
            assert binary == installation.ROOT/revision/"xray"
            installation.private_directory(installation.ROOT)
            installation.private_directory(binary.parent)
            artifact.check(ROOT, revision, binary.parent)
            executable = binary
        else:
            executable = root/"xray"
            shutil.copyfile(binary,executable)
            executable.chmod(0o755)
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
        stack.callback(stop,meter)
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
        # Real PinnedTlsExecutable against a disposable qualification
        # record scoped to this candidate, not the installed host path.
        qualification = root/"fixture-qualification"
        qualification.mkdir(mode=0o700)
        record = qualification/"identity"
        digest = hashlib.sha256(executable.read_bytes()).hexdigest()
        record.write_text("".join(
            f"{k}={digest if k == 'artifactSha256' else 'a'*40}\n"
            for k in qualified_executable.release.FIELDS), encoding="ascii")
        record.chmod(0o600)
        stack.enter_context(mock.patch.object(qualified_executable.release,"QUALIFICATION",qualification))
        stack.enter_context(mock.patch.object(qualified_executable.release,"EXECUTABLE",executable))
        exec_proof = stack.enter_context(qualified_executable.PinnedTlsExecutable(
            runtime_pid=meter.pid,runtime_id=runtime))
        native_inputs = namespace_inputs.NamespaceTlsInputs(original=inputs,native=native_routes,
            manifest=manifest,root_fd=root_fd,root_token=root_token)
        state = {"revoked":False,"ttl":7000}
        authority_sha = hashlib.sha256(authority).hexdigest()

        def fetch(challenge):
            # Only an ephemeral fixture signer. No live Nexus SQL or
            # production authority asserted by this diagnostic.
            issued = time.time_ns()//1_000_000
            return sign(root,key,b"",{
                "schemaVersion":1,"kind":"xmesh.quota-v2.public-tls-revocation-witness",
                "nodeId":NODE,"activationReceiptSha256":ACTIVATION,
                "genesisPolicySha256":policy,"runtimeId":runtime,"profileRevision":policy,
                "authoritySha256":authority_sha,"capRosterSha256":witness.roster_sha256,
                "challenge":challenge,"issuedAtMs":issued,"validUntilMs":issued+state["ttl"],
                "revoked":state["revoked"],"canServePublic":False,"canStart":False,"canResume":False,
            })+b"\n"

        revocation_watch = revocation.SignedTlsRevocationWatch(fetch=fetch,
            node=NODE,activation=ACTIVATION,genesis_sha=policy,runtime_id=runtime,
            profile_sha256=policy,authority_sha256=authority_sha,
            roster_sha256=witness.roster_sha256,pinned=public)
        proof_args = dict(profile=profile,authority=authority,runtime_pid=meter.pid,
            cap_watch=witness,revocation_watch=revocation_watch,pinned_inputs=native_inputs,
            pinned_executable=exec_proof,**binding_args)
        child = launcher.spawn_disposable(original_ns=original_ns, proof_args=proof_args)
        stack.callback(stop,child)
        try:
            child_line(child,"xmesh_namespace_candidate_prebound")
            assert exec_proof.verify_child(child) is None
            assert native_inputs.verify_pretransfer(child) is None
            try:
                native_inputs.verify_child(child)
            except ValueError as exc:
                assert "retains original listening socket copy" in str(exc)
            else:
                raise AssertionError("stop-only proof accepted nonexclusive transfer")
            for owner in sockets.values():
                owner.close()
            # StopOnlyTlsMonitor starts the independent guardian before
            # it rechecks original evidence and the exact exclusive FDs.
            monitor = stop_monitor.StopOnlyTlsMonitor(child=child,**proof_args)
            guardian = monitor._deadman
            stack.callback(guardian.close)
            assert not monitor.stopped
            for token in tokens.values():
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:
                    probe.settimeout(2)
                    assert probe.connect_ex(("127.0.0.1",token.port)) == errno.ECONNREFUSED
            child.stdin.write("fixture_namespace_xray_transfer\n")
            child.stdin.flush()
            found = {}
            for _ in tokens:
                line = child_line(child,"xmesh_namespace_candidate_listener:")
                _,port,fd = line.split(":")
                port,fd=int(port),int(fd)
                assert port not in found
                found[port] = fd
            assert set(found) == set(ports.values())
            assert native_inputs.observe_adopted(
                child,{tag:found[token.port] for tag,token in tokens.items()}) is None
            assert monitor.check_stop_only() is None
            for cls,user in (("main",UUID_A),("cdn",UUID_B)):
                tls_echo(ports[cls],domains[cls],certificate.ca_cert,user,echo_port,os.urandom(16384))
            for user,cls in ((USER_A,"main"),(USER_B,"cdn")):
                assert query_direction_counters(str(executable),api_port,
                    f"xmesh-u{user}--vless-{cls}") == {"uplink":16384,"downlink":16384}
            # Independently audit actual fsynced Xray WAL records and
            # their hash-chained birth registry. The expected scope is
            # derived from the two actual authenticated client flows.
            ledger_fd=os.open(ledger,os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            try:
                _,wals=inventory.verify_meter_inventory(ledger_fd,
                    sorted(name for name in os.listdir(ledger_fd) if name.startswith("meter-")),
                    journal._read_meter_wal,journal._canonical_go)
                assert len(wals)==4
                assert {(tail["runtimeId"],tail["email"],tail["direction"],tail["nextBytes"])
                        for tail,_,_ in wals.values()} == {
                    (runtime,f"xmesh-u{user}--vless-{cls}",direction,16384)
                    for user,cls in ((USER_A,"main"),(USER_B,"cdn"))
                    for direction in ("uplink","downlink")}
            finally:
                os.close(ledger_fd)
            if stop_mode == "revoked":
                state["revoked"] = True
                try:
                    monitor.check_stop_only()
                except ValueError as exc:
                    assert "signed Nexus revocation witness lost or revoked" in str(exc), exc
                else:
                    raise AssertionError("signed revocation did not stop actual TLS child")
                assert monitor.stopped
                assert child.wait(timeout=2)==-9
            else:
                state["ttl"] = 4000
                assert monitor.check_stop_only() is None
                # No more ticks. Independent deadman, not the fixture
                # supervisor, must stop both listeners at signed expiry.
                assert child.wait(timeout=6)==-9
                assert guardian._guardian.wait(timeout=2)==1
            for token in tokens.values():
                readback.verify_listen_state(token,listening=False)
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as probe:
                    probe.settimeout(2)
                    assert probe.connect_ex(("127.0.0.1",token.port))==errno.ECONNREFUSED
            print("PASS: actual isolated sealed Xray TLS candidate -> original authenticated "
                  f"signed MAIN/CDN meter; exact 16KiB each direction; physical stop of both ports: {stop_mode}.")
        finally:
            stop(child)
            remainder=getattr(child,"_xmesh_stage_buffer",b"").decode("utf-8","replace")+child.stdout.read()
            if remainder:
                print(remainder,file=sys.stderr)
            meterlog.flush()
            print((root/"meter.log").read_text(errors="replace")[-12000:],file=sys.stderr)


if __name__ == "__main__":
    assert len(sys.argv) in (4,5)
    assert len(sys.argv)==4 or sys.argv[4]=="--installed-candidate"
    run(Path(sys.argv[1]).resolve(),sys.argv[2],sys.argv[3],len(sys.argv)==5)
