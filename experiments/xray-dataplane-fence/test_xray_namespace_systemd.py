#!/usr/bin/env python3
"""Actual hosted PID1 containment of the diagnostic native Xray TLS process.

Only a disposable service/private loopback network with fixture signing.
The external test holds the original network namespace AND real MAIN/CDN
VLESS TLS 1.3 sessions across simultaneous supervisor/guardian SIGSTOP.
"""
from contextlib import ExitStack
import errno
import json
import os
from pathlib import Path
import select
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time
import uuid

from test_xray_namespace_ingress_candidate import (
    child_line, stop, recv_exact, UUID_A, UUID_B,
)
from test_quota_v2_public_tls_systemd import require_hosted_ci, run

HERE = Path(__file__).resolve().parent
PREFIX = "xmesh-native-xray-containment-ci-"


def properties(unit, *names):
    args = ["systemctl", "show", unit]
    for name in names:
        args.extend(["--property", name])
    return dict(line.split("=", 1) for line in run(*args).stdout.splitlines())


def probe(root, original_ns, expected_ns):
    # nsenter must have moved this *outside-service* process to the private
    # original listener namespace. Never touch a host port.
    assert os.readlink("/proc/self/ns/net") == expected_ns != original_ns
    info = json.loads((root/"ready.json").read_text())
    context = ssl.create_default_context(cafile=info["ca"])
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    with ExitStack() as stack:
        wires = []
        for cls, user in (("main",UUID_A), ("cdn",UUID_B)):
            raw = stack.enter_context(socket.create_connection(
                ("127.0.0.1", info["ports"][cls]), timeout=3))
            wire = stack.enter_context(context.wrap_socket(raw, server_hostname=info["domains"][cls]))
            assert wire.version()=="TLSv1.3"
            wire.settimeout(3)
            payload = b"active-watchdog"
            header = (b"\x00"+uuid.UUID(user).bytes+b"\x00\x01"+
                      struct.pack(">H",info["echoPort"])+b"\x01"+socket.inet_aton("127.0.0.1"))
            wire.sendall(header+payload)
            response = recv_exact(wire,2)
            assert response[0]==0
            if response[1]:
                recv_exact(wire,response[1])
            assert recv_exact(wire,len(payload))==payload
            wires.append(wire)
        print("both_live_tls_vless", flush=True)
        assert sys.stdin.readline().strip()=="verify_stopped"
        for wire in wires:
            try:
                assert not wire.recv(1), "existing authenticated TLS survived PID1 stop"
            except (ConnectionResetError, ssl.SSLEOFError):
                pass
        for port in info["ports"].values():
            with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                assert sock.connect_ex(("127.0.0.1",port))==errno.ECONNREFUSED
        print("both_tls_closed_and_new_refused",flush=True)


def stopped(fd, timeout_ms=0):
    poll = select.poll()
    poll.register(fd, select.POLLIN | select.POLLHUP)
    return bool(poll.poll(timeout_ms))


def contain(binary, host_ns, installed=False):
    require_hosted_ci()
    assert os.readlink("/proc/self/ns/net")==host_ns==os.readlink("/proc/1/ns/net")
    unit = PREFIX+uuid.uuid4().hex+".service"
    with tempfile.TemporaryDirectory(prefix=PREFIX, dir="/run") as directory, ExitStack() as stack:
        root = Path(directory)
        def cleanup():
            run("systemctl","stop",unit,check=False,timeout=10)
            print(run("journalctl","--no-pager","-u",unit,"-n","80",check=False).stdout,flush=True)
            run("systemctl","reset-failed",unit,check=False)
        stack.callback(cleanup)
        candidate_pins = ()
        if installed:
            candidate_pins = tuple("--setenv="+name+"="+os.environ[name] for name in
                                   ("XMESH_NAMESPACE_MANIFEST_PIN", "XMESH_NAMESPACE_PROVENANCE_PIN"))
        launch = run("systemd-run","--quiet","--unit",unit,
            "--property=Type=notify","--property=NotifyAccess=main",
            "--property=WatchdogSec=3s","--property=WatchdogSignal=SIGKILL",
            "--property=KillMode=control-group","--property=SendSIGKILL=yes",
            "--property=TimeoutStopSec=1s","--property=TimeoutStartSec=60s",
            "--property=Restart=no","--property=PrivateNetwork=yes",
            "--property=PrivateMounts=yes","--property=NoNewPrivileges=yes",
            "--property=UMask=0077",
            "--setenv=GITHUB_ACTIONS=true","--setenv=RUNNER_ENVIRONMENT=github-hosted",
            "--setenv=XMESH_DISPOSABLE_BOUND_LISTENER_TEST=1",
            "--setenv=XMESH_DISPOSABLE_TLS_SYSTEMD_TEST=1",
            *candidate_pins,
            sys.executable,"-B",str(HERE/"test_xray_namespace_ingress_candidate.py"),
            str(binary),host_ns,"systemd","--systemd-fixture",str(root),
            *(("--installed-candidate",) if installed else ()), check=False,timeout=65)
        assert launch.returncode==0, launch.stderr
        info=json.loads((root/"ready.json").read_text())
        props=properties(unit,"MainPID","ControlGroup","KillMode","WatchdogUSec",
            "WatchdogSignal","Restart","NotifyAccess","SendSIGKILL","PrivateNetwork","PrivateMounts")
        assert int(props["MainPID"])==info["main"]
        assert props["KillMode"]=="control-group" and props["NotifyAccess"]=="main"
        assert props["Restart"]=="no" and props["SendSIGKILL"]=="yes"
        assert props["PrivateNetwork"]==props["PrivateMounts"]=="yes"
        assert props["WatchdogSignal"] in {"9","SIGKILL"}
        assert props["WatchdogUSec"] not in {"0","infinity","0us",""}
        group=Path("/sys/fs/cgroup")/props["ControlGroup"].lstrip("/")
        assert props["ControlGroup"].endswith("/"+unit)
        fields=("main","guardian","listener","meter","echo")
        pids={info[name] for name in fields}
        assert len(pids)==len(fields)
        members={int(x) for x in (group/"cgroup.procs").read_text().split()}
        assert pids <= members, (pids,members)
        pidfds={}
        for name in fields:
            pidfds[name]=os.pidfd_open(info[name],0)
            stack.callback(os.close,pidfds[name])
            assert not stopped(pidfds[name])
        # Keep the original network namespace alive independent of the
        # service. Thus a disappearing netns cannot fake port closure.
        netpath=f"/proc/{info['main']}/ns/net"
        listener_ns=os.readlink(netpath)
        assert listener_ns!=host_ns
        netfd=os.open(netpath,os.O_RDONLY|os.O_CLOEXEC)
        stack.callback(os.close,netfd)
        outside=subprocess.Popen(["nsenter",f"--net=/proc/self/fd/{netfd}",
            sys.executable,"-B",str(Path(__file__).resolve()),"--probe",str(root),host_ns,listener_ns],
            pass_fds=(netfd,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,text=True)
        stack.callback(stop,outside)
        child_line(outside,"both_live_tls_vless")
        # Freeze immediately after a real signed check and guardian ACK so
        # the independent watchdog must act *before* signed witness expiry.
        info=json.loads((root/"ready.json").read_text())
        assert info["deadlineNs"]-time.monotonic_ns()>4_500_000_000
        start=time.monotonic_ns()
        signal.pidfd_send_signal(pidfds["main"],signal.SIGSTOP,None,0)
        signal.pidfd_send_signal(pidfds["guardian"],signal.SIGSTOP,None,0)
        for name in ("main","guardian"):
            status=Path(f"/proc/{info[name]}/status")
            until=time.monotonic()+.5
            while time.monotonic()<until:
                if "\nState:\tT" in status.read_text():
                    break
                time.sleep(.01)
            else:
                raise AssertionError(name+" was not actually frozen")
        for name, fd in pidfds.items():
            assert stopped(fd,4000), name+" survived actual service watchdog"
        end=time.monotonic_ns()
        assert end-start<4_000_000_000 and end<info["deadlineNs"]
        until=time.monotonic()+2
        while time.monotonic()<until:
            result=properties(unit,"ActiveState","Result")
            try:
                members=(group/"cgroup.procs").read_text().strip()
            except FileNotFoundError:
                members=""
            if result["ActiveState"] in {"failed","inactive"} and not members:
                break
            time.sleep(.05)
        assert result["ActiveState"] in {"failed","inactive"} and result["Result"]=="watchdog", result
        assert not members, members
        outside.stdin.write("verify_stopped\n")
        outside.stdin.flush()
        child_line(outside,"both_tls_closed_and_new_refused")
        assert outside.wait(timeout=5)==0
        print("PASS: PID1 watchdog killed frozen supervisor + guardian + actual isolated Xray + original meter; both authenticated TLS sessions closed; ports 443/8443 refused in retained network namespace before signed expiry.",flush=True)


if __name__=="__main__":
    if len(sys.argv)==5 and sys.argv[1]=="--probe":
        probe(Path(sys.argv[2]),sys.argv[3],sys.argv[4])
    else:
        assert len(sys.argv) in (3,4)
        assert len(sys.argv)==3 or sys.argv[3]=="--installed-candidate"
        contain(Path(sys.argv[1]).resolve(),sys.argv[2],len(sys.argv)==4)
