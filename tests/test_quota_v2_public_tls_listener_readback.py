#!/usr/bin/env python3
"""Nonduplicating real listener transfer/stop qualification, no public bind."""
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from test_quota_v2_public_tls_bound_listener import (
    CAPLESS, MODULES, require_disposable_namespace,
)

import public_tls_bound_listener as bound
import public_tls_deadman as deadman
import public_tls_listener_readback as readback

INNER = r"""
import hashlib, json, os, socket, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import public_tls_bound_listener as bound
module = Path(bound.__file__)
assert module.stat().st_uid == 0 and module.stat().st_mode & 0o777 == 0o600
assert hashlib.sha256(module.read_bytes()).hexdigest() == sys.argv[2]
fd = int(sys.argv[3])
token = bound.BoundListenerIdentity(**json.loads(sys.argv[4]))
assert os.getpid() == 1 and os.geteuid() == os.getegid() == 0
status = dict(line.split(":",1) for line in open("/proc/self/status") if ":" in line)
assert status["NoNewPrivs"].strip() == "1"
for key in ("CapInh","CapPrm","CapEff","CapBnd","CapAmb"):
    assert int(status[key].strip(),16) == 0
with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as reference:
    assert bound.network_namespace_cookie(reference) != token.netns_cookie
with socket.socket(fileno=fd) as listener:
    assert bound.verify_bound_socket(listener,token,listening=False) is None
    print("child_has_original_not_listening",flush=True)
    assert sys.stdin.readline().strip() == "fixture_after_exclusive_transfer"
    listener.listen(1)
    assert bound.verify_bound_socket(listener,token,listening=True) is None
    print("child_listening",flush=True)
    with listener.accept()[0] as conn:
        assert conn.recv(1) == b"x"
        conn.sendall(b"y")
    print("echo",flush=True)
    # Never close voluntarily. The independent guardian must kill this
    # exact namespace init, which now owns the sole listener reference.
    sys.stdin.read()
"""


class Structure(unittest.TestCase):
    def setUp(self):
        self.token = bound.BoundListenerIdentity(
            "127.0.0.1",443,1,123,0x123456780000ABCD,3)

    def test_diag_exact_cookie_inode_parse_and_reject_truncation(self):
        payload = bytearray(72)
        payload[0] = socket.AF_INET
        payload[1] = readback.TCP_LISTEN
        struct.pack_into("!HH",payload,4,443,0)
        payload[8:12] = socket.inet_aton("127.0.0.1")
        struct.pack_into("=II",payload,44,0xABCD,0x12345678)
        struct.pack_into("=II",payload,64,0,123)
        record = ("127.0.0.1",443,0,123,self.token.cookie)
        self.assertEqual(readback._record(payload), record)
        with self.assertRaises(ValueError):
            readback._record(payload[:71])
        payload[24] = 1
        with self.assertRaises(ValueError):
            readback._record(payload)

    def test_netlink_sequence_alignment_interrupt_and_truncation(self):
        data = readback.HEADER.pack(20,readback.NLMSG_DONE,0,1,0) + bytes(4)
        self.assertEqual(list(readback._messages(data,1)), [(readback.NLMSG_DONE, bytes(4))])
        for raw in [data[:-1], data+b"x", readback.HEADER.pack(20,3,0x10,1,0)+bytes(4),
                    readback.HEADER.pack(20,3,0,2,0)+bytes(4)]:
            with self.assertRaises(ValueError):
                list(readback._messages(raw,1))

    def test_listening_phase_requires_exact_uid_inode_cookie_and_no_overlap(self):
        record = (self.token.address,self.token.port,0,self.token.inode,self.token.cookie)
        with patch.object(readback.os,"geteuid",return_value=0):
            with patch.object(readback,"_listener_records",return_value=[record]):
                self.assertIsNone(readback.verify_listen_state(self.token,listening=True))
                with self.assertRaises(ValueError):
                    readback.verify_listen_state(self.token,listening=False)
            with patch.object(readback,"_listener_records",return_value=[]):
                self.assertIsNone(readback.verify_listen_state(self.token,listening=False))
                with self.assertRaises(ValueError):
                    readback.verify_listen_state(self.token,listening=True)
            for records in ([record[:-1]+(8,)], [record[:3]+(7,record[-1])],
                            [record,("0.0.0.0",443,0,1,2)]):
                with patch.object(readback,"_listener_records",return_value=records):
                    with self.assertRaises(ValueError):
                        readback.verify_listen_state(self.token,listening=True)


def live(original_ns):
    require_disposable_namespace(original_ns)
    with tempfile.TemporaryDirectory(prefix="xmesh-tls-transfer-") as temporary:
        module = Path(temporary) / "public_tls_bound_listener.py"
        content = (MODULES/module.name).read_bytes()
        module.write_bytes(content)
        module.chmod(0o600)
        digest = hashlib.sha256(content).hexdigest()
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as owner:
            owner.bind(("127.0.0.1",443))
            token = bound.capture_bound(owner,"127.0.0.1",443,
                                        bound.network_namespace_cookie(owner))
            fd = owner.fileno()
            readback.verify_listen_state(token,listening=False)
            # A deliberately retained copy MUST be noticed.
            try:
                readback.require_no_copy(os.getpid(),token)
            except ValueError:
                pass
            else:
                raise AssertionError("retained listener copy was accepted")
            assert len(os.listdir("/proc/self/task")) == 1
            original_pidns = os.readlink("/proc/self/ns/pid")
            assert os.readlink("/proc/self/ns/pid_for_children") == original_pidns
            saved = os.open("/proc/self/ns/pid",os.O_RDONLY|os.O_CLOEXEC)
            lib = ctypes.CDLL(None,use_errno=True)

            def check(rc):
                if rc:
                    e = ctypes.get_errno()
                    raise OSError(e,os.strerror(e))

            child = guardian = None
            try:
                check(lib.unshare(0x20000000))
                try:
                    child = subprocess.Popen(
                        ["unshare","--net","--mount-proc",*CAPLESS,
                         sys.executable,"-I","-B","-c",INNER,
                         temporary,digest,str(fd),json.dumps(token.__dict__)],
                        pass_fds=(fd,),stdin=subprocess.PIPE,stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,text=True)
                finally:
                    check(lib.setns(saved,0x20000000))
                os.close(saved)
                saved = None
                assert os.readlink("/proc/self/ns/pid_for_children") == original_pidns

                def wait(message):
                    assert select.select([child.stdout],[],[],8)[0], message
                    assert child.stdout.readline().strip() == message

                wait("child_has_original_not_listening")
                readback.verify_child_fd(child,fd,token)
                # No other process may retain the original socket during
                # listen. Close the actual owner BEFORE starting guardian
                # and before even the artificial fixture gate.
                owner.close()
                readback.require_no_copy(os.getpid(),token)
                guardian = deadman.StopOnlyDeadman(child=child,timeout_ms=7000)
                readback.require_no_copy(guardian._guardian.pid,token)
                readback.verify_listen_state(token,listening=False)
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as client:
                    client.settimeout(2)
                    assert client.connect_ex(("127.0.0.1",443)) == errno.ECONNREFUSED
                guardian.pulse(deadline_ns=time.monotonic_ns()+4_000_000_000,
                               wall_deadline_ms=time.time_ns()//1_000_000+4000)
                child.stdin.write("fixture_after_exclusive_transfer\n")
                child.stdin.flush()
                wait("child_listening")
                readback.verify_child_fd(child,fd,token)
                readback.verify_listen_state(token,listening=True)
                readback.require_no_copy(os.getpid(),token)
                readback.require_no_copy(guardian._guardian.pid,token)
                with socket.create_connection(("127.0.0.1",443),timeout=2) as client:
                    client.sendall(b"x")
                    assert client.recv(1) == b"y"
                wait("echo")
                # The parent stays alive, but deliberately sends no further
                # heartbeats. Independent exact-PID1 SIGKILL must close
                # the TCP listener, not merely leave it accepting SYNs.
                assert child.wait(timeout=6) == -9
                assert guardian._guardian.wait(timeout=2) == 1
                readback.verify_listen_state(token,listening=False)
                with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as client:
                    client.settimeout(2)
                    assert client.connect_ex(("127.0.0.1",443)) == errno.ECONNREFUSED
                print("PASS: exact child-owned privileged socket physically closed by the real "
                      "deadman; no owner/guardian copy, INET_DIAG cookie/inode, ECONNREFUSED.")
            finally:
                if saved is not None:
                    os.close(saved)
                if guardian is not None:
                    guardian.close()
                if child is not None:
                    if child.poll() is None:
                        child.kill()
                    _, stderr = child.communicate(timeout=5)
                    if stderr:
                        print(stderr,file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--live":
        live(sys.argv[2])
    else:
        unittest.main()
