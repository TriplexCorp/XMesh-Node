#!/usr/bin/env python3
"""Read-only socket identity tests and actual isolated privileged-port proof."""
import errno
import hashlib
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
MODULES = ROOT / "experiments/quota-v2-physical-stop"
sys.path.insert(0, str(MODULES))
import public_tls_bound_listener as proof

CAPLESS = ["setpriv", "--no-new-privs", "--bounding-set=-all",
           "--inh-caps=-all", "--ambient-caps=-all"]

INNER = r"""
import errno, hashlib, json, os, socket, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import public_tls_bound_listener as proof
digest, fd, original_namespace, raw = sys.argv[2:]
path = Path(proof.__file__)
assert path == Path(sys.argv[1]) / "public_tls_bound_listener.py"
assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
assert path.stat().st_uid == 0 and path.stat().st_mode & 0o777 == 0o600
expected = proof.BoundListenerIdentity(**json.loads(raw))
assert os.getpid() == 1 and os.geteuid() == os.getegid() == 0
assert os.readlink("/proc/self/ns/net") != original_namespace
status = dict(line.split(":", 1) for line in open("/proc/self/status") if ":" in line)
assert status["NoNewPrivs"].strip() == "1"
for key in ("CapEff", "CapInh", "CapPrm", "CapBnd", "CapAmb"):
    assert int(status[key].strip(), 16) == 0
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
    assert proof.network_namespace_cookie(probe) != expected.netns_cookie
with socket.socket(fileno=int(fd)) as listener:
    assert proof.verify_bound_socket(listener, expected, listening=False) is None
    print("bound_not_listening", flush=True)
    assert sys.stdin.readline().strip() == "fixture_listen_only"
    # This listen is ONLY on the disposable ancestor's private loopback,
    # after explicit fixture synchronization, not a production gate.
    listener.listen(1)
    assert proof.verify_bound_socket(listener, expected, listening=True) is None
    print("listening_private_fixture", flush=True)
    listener.settimeout(5)
    conn, _ = listener.accept()
    with conn:
        assert conn.getsockname() == (expected.address, expected.port)
        received = bytearray()
        while len(received) < 7:
            block = conn.recv(7 - len(received))
            assert block
            received += block
        assert received == b"fixture"
        conn.sendall(b"echo")
    print("actual_echo", flush=True)
"""


class StructureTests(unittest.TestCase):
    def test_strict_tokens_and_non_tcp_refusal(self):
        base = dict(address="127.0.0.1", port=443, device=1, inode=2,
                    cookie=3, netns_cookie=4)
        self.assertEqual(proof.BoundListenerIdentity(**base).port, 443)
        for field, bad in (("address", "::1"), ("address", "127.000.0.1"),
                           ("port", True), ("port", 0), ("device", 0),
                           ("inode", 2**64), ("cookie", True), ("netns_cookie", 0)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                proof.BoundListenerIdentity(**{**base, field: bad})
        if os.geteuid() == 0:
            a, b = socket.socketpair()
            with a, b:
                with self.assertRaisesRegex(ValueError, "exclusive IPv4 TCP"):
                    proof.capture_bound(a, "127.0.0.1", 443, 1)
                with self.assertRaises(ValueError):
                    proof.verify_bound_socket(a, proof.BoundListenerIdentity(**base),
                                              listening=False)


def require_disposable_namespace(original_ns):
    # Never write sysctl or bind a test port in a host or production
    # namespace. This is only the explicit hosted root disposable CI run.
    assert os.environ.get("GITHUB_ACTIONS") == "true"
    assert os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    assert os.environ.get("XMESH_DISPOSABLE_BOUND_LISTENER_TEST") == "1"
    assert os.geteuid() == 0
    current = os.readlink("/proc/self/ns/net")
    assert current != original_ns == os.readlink("/proc/1/ns/net")
    links = json.loads(subprocess.check_output(["ip", "-j", "link", "show"]))
    assert len(links) == 1 and links[0]["ifname"] == "lo", links
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True, timeout=5)
    sysctl = Path("/proc/sys/net/ipv4/ip_unprivileged_port_start")
    sysctl.write_text("1024\n")
    assert sysctl.read_text().strip() == "1024"
    return current


def live(original_ns):
    current_ns = require_disposable_namespace(original_ns)
    # First prove that capless root really is denied a *new* privileged
    # bind with this network namespace's actual privileged-port sysctl.
    denied = r"""
import errno, socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    try:
        s.bind(("127.0.0.1",443))
    except OSError as exc:
        assert exc.errno == errno.EACCES, exc
    else:
        raise AssertionError("capless process bound a privileged port")
"""
    subprocess.run([*CAPLESS, sys.executable, "-I", "-B", "-c", denied],
                   check=True, timeout=5)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reference:
        ns_cookie = proof.network_namespace_cookie(reference)
    with (socket.socket(socket.AF_INET, socket.SOCK_STREAM) as owner,
          tempfile.TemporaryDirectory(prefix="xmesh-bound-listener-module-") as temporary):
        module = Path(temporary) / "public_tls_bound_listener.py"
        source = (MODULES / module.name).read_bytes()
        with module.open("xb") as handle:
            handle.write(source)
        module.chmod(0o600)
        digest = hashlib.sha256(source).hexdigest()
        owner.bind(("127.0.0.1", 443))
        token = proof.capture_bound(owner, "127.0.0.1", 443, ns_cookie)
        for addr, port, ns in (("0.0.0.0", 443, ns_cookie),
                               ("127.0.0.1", 444, ns_cookie),
                               ("127.0.0.1", 443, ns_cookie ^ 1)):
            try:
                proof.capture_bound(owner, addr, port, ns)
            except ValueError:
                pass
            else:
                raise AssertionError("wrong signed endpoint or network namespace accepted")

        # A separate prebound socket in the same namespace is not this
        # exact object (even a forged token with its endpoint must fail).
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as alternate:
            alternate.bind(("127.0.0.1", 0))
            other = proof.capture_bound(alternate, *alternate.getsockname(), ns_cookie)
            assert other.cookie != token.cookie and other.inode != token.inode
            try:
                proof.verify_bound_socket(alternate, token, listening=False)
            except ValueError:
                pass
            else:
                raise AssertionError("alternate bound socket accepted")
            alternate.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                proof.capture_bound(alternate, *alternate.getsockname(), ns_cookie)
            except ValueError:
                pass
            else:
                raise AssertionError("nonexclusive reusable socket accepted")

        child = subprocess.Popen(
            ["unshare", "--net", "--pid", "--fork", "--kill-child=SIGKILL", "--mount-proc",
             *CAPLESS, sys.executable, "-I", "-B", "-c", INNER,
             temporary, digest, str(owner.fileno()), current_ns, json.dumps(token.__dict__)],
            pass_fds=(owner.fileno(),), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True,
        )

        def wait(message):
            assert select.select([child.stdout], [], [], 8)[0], message
            assert child.stdout.readline().strip() == message

        try:
            wait("bound_not_listening")
            assert proof.verify_bound_socket(owner, token, listening=False) is None
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
                client.settimeout(3)
                assert client.connect_ex(("127.0.0.1", 443)) == errno.ECONNREFUSED
            child.stdin.write("fixture_listen_only\n")
            child.stdin.flush()
            wait("listening_private_fixture")
            assert proof.verify_bound_socket(owner, token, listening=True) is None
            try:
                proof.capture_bound(owner, "127.0.0.1", 443, ns_cookie)
            except ValueError:
                pass
            else:
                raise AssertionError("already listening socket passed pre-spawn proof")
            with socket.create_connection(("127.0.0.1", 443), timeout=5) as client:
                client.sendall(b"fixture")
                response = bytearray()
                while len(response) < 4:
                    block = client.recv(4 - len(response))
                    assert block
                    response += block
                assert response == b"echo"
            wait("actual_echo")
            assert child.wait(timeout=5) == 0
        finally:
            if child.poll() is None:
                child.kill()
            _, stderr = child.communicate(timeout=5)
            if child.returncode != 0 and stderr:
                print(stderr, file=sys.stderr)
    print("PASS: actual private-netns capless child served exact inherited privileged loopback socket; "
          "no listener before fixture gate and no host sysctl change.")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--live":
        live(sys.argv[2])
    else:
        unittest.main()
