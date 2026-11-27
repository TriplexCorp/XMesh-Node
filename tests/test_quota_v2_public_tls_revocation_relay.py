#!/usr/bin/env python3
"""Real kernel SCM credentials across an unshared netns and actual signatures.

The enrolled network RPC is a fixture. The private observer verifies fresh
Ed25519 responses itself; no Nexus, listener, positive issuer or production
permission is asserted by these transport tests.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "experiments/quota-v2-physical-stop"
sys.path.insert(0, str(SOURCE))
import public_tls_revocation_relay as relay
import public_tls_revocation_watch as watch
import test_quota_v2_public_tls_revocation_watch as signed_tests

ENV = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted",
       "XMESH_DISPOSABLE_BOUND_LISTENER_TEST": "1"}

SUPERVISOR = r"""
import json
import os
import socket
import struct
import subprocess
import sys
import time
sys.path.insert(0, sys.argv[1])
import public_tls_revocation_relay as relay
import public_tls_revocation_watch as watch
fd, parent, original, mode = int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5]
args = json.loads(sys.argv[6])
assert os.readlink("/proc/self/ns/net") != original
if mode in ("oversize", "wrong_sender", "bad_nonce", "fd_injection", "repeat"):
    ep = socket.socket(fileno=fd)
    if mode == "oversize":
        ep.send(b"a"*65)
    elif mode == "bad_nonce":
        ep.send(b"G"*64)
    elif mode == "repeat":
        ep.send(b"a"*64)
        assert ep.recv(4096)
        ep.send(b"a"*64)
    elif mode == "fd_injection":
        with open("/dev/null", "rb") as other:
            ep.sendmsg([b"a"*64], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack("i", other.fileno()))])
    else:
        # The anonymous socket description is reachable by a forked
        # descendant, but its kernel per-message PID is not the supervisor.
        child = os.fork()
        if child == 0:
            ep.send(b"a"*64)
            os._exit(0)
        os.waitpid(child, 0)
    time.sleep(0.5)
    ep.close()
    sys.exit(0)
with relay.PrivateRevocationFetch(fd=fd, broker_pid=parent, original_ns=original) as fetch:
    # Fork/exec of the native child must NOT inherit the witness socket or
    # broker pidfd. No path is available for reconnecting.
    assert not os.get_inheritable(fd)
    assert not os.get_inheritable(fetch._pidfd)
    assert subprocess.check_output([sys.executable, "-I", "-c",
        "import os,sys; assert not os.path.exists('/proc/self/fd/'+sys.argv[1]); print('closed')",
        str(fd)]).strip() == b"closed"
    observer = watch.SignedTlsRevocationWatch(fetch=fetch, **args)
    if mode in ("closed", "timeout"):
        started = time.monotonic()
        try:
            observer.check()
        except (OSError, ValueError):
            if mode == "timeout":
                assert 2.8 <= time.monotonic()-started < 3.5
            print("closed")
        else:
            raise AssertionError("closed relay admitted witness")
    else:
        assert observer.check() is None
        assert observer.ensure_fresh() is None
        try:
            observer.check()
        except ValueError as exc:
            assert "revoked" in str(exc), exc
        else:
            raise AssertionError("signed revocation accepted")
        print("clear-then-revoked")
"""


class RelayTests(unittest.TestCase):
    def setUp(self):
        self.assertEqual(os.geteuid(), 0)
        env = mock.patch.dict(os.environ, ENV)
        env.start()
        self.addCleanup(env.stop)
        # Reuse the existing actual OpenSSL Ed25519 signing fixture (no
        # inherited test case execution and no private key in supervisor).
        self.signer = signed_tests.SignedRevocationWitnessTests()
        self.signer.setUp()
        self.addCleanup(self.signer.doCleanups)
        self.args = dict(self.signer.args)
        self.binding = dict(self.args)
        self.binding.pop("pinned")
        self.count = 0

    def open(self):
        instance = relay.HostedEnrolledRevocationRelay(
            state=str(self.signer.root), user=91, **self.binding)
        self.addCleanup(instance.close)
        return instance

    def spawn(self, instance, mode):
        fd = instance.supervisor_fd
        child = subprocess.Popen(
            ["unshare", "--net", "--", sys.executable, "-I", "-B", "-c", SUPERVISOR,
             str(SOURCE), str(fd), str(instance.pid), instance.original_ns, mode,
             json.dumps(self.args)], pass_fds=(fd,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def cleanup():
            if child.poll() is None:
                child.kill()
            child.communicate(timeout=5)
        self.addCleanup(cleanup)
        instance.bind_supervisor(child)
        return child

    def reply(self, request, state, path):
        self.count += 1
        self.assertEqual(state, str(self.signer.root))
        self.assertEqual(path, watch.quarantine_policy.TLS_REVOCATION_PATH)
        self.assertEqual(request["scope"], {
            "nodeId": 47, "userId": 91, "activationReceiptSha256": "a"*64,
            "genesisPolicySha256": "b"*64, "runtimeId": "c"*64,
            "profileRevision": "d"*64, "capRosterSha256": "f"*64,
            "requiredLifetimeMs": 7000,
        })
        self.assertEqual(request["authoritySha256"], "e"*64)
        self.assertEqual(set(request), {"scope", "authoritySha256", "challenge"})
        return self.signer.signed(dict(self.signer.payload(request["challenge"]),
                                       revoked=self.count > 1))

    def poll_until(self, instance, expected):
        deadline = time.monotonic()+5
        count = 0
        while count < expected and time.monotonic() < deadline:
            if instance.poll():
                count += 1
        self.assertEqual(count, expected)

    def result(self, child, expected):
        stdout, stderr = child.communicate(timeout=5)
        self.assertEqual(child.returncode, 0, stderr.decode(errors="replace"))
        self.assertEqual(stdout.strip(), expected)

    def test_cross_namespace_exact_scope_clear_then_signed_revocation(self):
        with mock.patch.object(watch.quarantine_policy, "_post_quarantined_desired",
                               side_effect=self.reply):
            instance = self.open()
            child = self.spawn(instance, "signed")
            self.poll_until(instance, 2)
            address = instance._parent.getsockname()
            if isinstance(address, bytes):
                with self.assertRaises(OSError):
                    with socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET) as foreign:
                        foreign.connect(address)
            self.result(child, b"clear-then-revoked")
            self.assertEqual(self.count, 2)

    def test_malformed_oversized_ancillary_or_descendant_sender_never_reaches_nexus(self):
        for mode in ("oversize", "wrong_sender", "bad_nonce", "fd_injection"):
            with self.subTest(mode=mode), mock.patch.object(
                    watch.quarantine_policy, "_post_quarantined_desired",
                    side_effect=AssertionError("untrusted packet reached enrolled transport")):
                instance = self.open()
                child = self.spawn(instance, mode)
                with self.assertRaises(ValueError):
                    self.poll_until(instance, 1)
                self.assertIsNone(instance._parent)
                self.result(child, b"")

    def test_duplicate_challenge_never_reaches_second_poll(self):
        with mock.patch.object(watch.quarantine_policy, "_post_quarantined_desired",
                               side_effect=self.reply):
            instance = self.open()
            child = self.spawn(instance, "repeat")
            self.poll_until(instance, 1)
            with self.assertRaises(ValueError):
                self.poll_until(instance, 1)
            self.assertEqual(self.count, 1)
            self.assertIsNone(instance._parent)
            self.result(child, b"")

    def test_unresponsive_parent_cannot_extend_witness_deadline(self):
        instance = self.open()
        child = self.spawn(instance, "timeout")
        self.result(child, b"closed")

    def test_parent_closed_is_not_a_witness(self):
        instance = self.open()
        child = self.spawn(instance, "closed")
        instance.close()
        self.result(child, b"closed")

    def test_hosted_guard_and_unchanged_namespace(self):
        for key in ENV:
            with self.subTest(key=key), mock.patch.dict(os.environ, {key: "no"}):
                with self.assertRaises(ValueError):
                    self.open()
        instance = self.open()
        # A fork/exec in the original namespace is not a valid private
        # supervisor, even with the correct original-network parent.
        child = subprocess.Popen([sys.executable, "-I", "-B", "-c",
            "import sys; sys.path.insert(0,sys.argv[1]); import public_tls_revocation_relay as r; "
            "r.PrivateRevocationFetch(fd=int(sys.argv[2]),broker_pid=int(sys.argv[3]),original_ns=sys.argv[4])",
            str(SOURCE), str(instance.supervisor_fd), str(instance.pid), instance.original_ns],
            pass_fds=(instance.supervisor_fd,), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, stderr = child.communicate(timeout=5)
        self.assertNotEqual(child.returncode, 0)
        self.assertIn(b"exact original-network parent and private supervisor required", stderr)


if __name__ == "__main__":
    unittest.main()
