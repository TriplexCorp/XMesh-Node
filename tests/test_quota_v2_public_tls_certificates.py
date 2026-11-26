#!/usr/bin/env python3
"""Root-only Certbot lineage negatives for an inactive Quota V2 public TLS gate."""
import copy
from datetime import datetime, timedelta, timezone
import errno
import fcntl
import hashlib
import json
import os
import socket
import ssl
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

HERE = Path(__file__).resolve().parents[1] / "experiments/quota-v2-physical-stop"
sys.path.insert(0, str(HERE))
import public_tls_certificates as certs
import public_tls_frontend as tls

DOMAIN_A = "cdn.example.com"
DOMAIN_B = "vpn.example.com"
UUID = "11111111-1111-4111-8111-111111111111"


def profile():
    return {"inbounds": [
        {"tag": "vless-" + name, "listen": "127.0.0.1",
         "port": 20001 + idx, "protocol": "vless",
         "settings": {"decryption": "none", "clients": [
             {"email": "xmesh-u41--vless-" + name, "id": UUID}
         ]}}
        for idx, name in enumerate(("cdn", "main"))
    ]}


def signed_compiled_config():
    return tls._compile_verified_tls_config(profile(), [
        {"tag": "vless-cdn", "domain": DOMAIN_A, "port": 443},
        {"tag": "vless-main", "domain": DOMAIN_B, "port": 8443},
    ])


class CertificateTests(unittest.TestCase):
    def setUp(self):
        if os.geteuid() != 0:
            self.skipTest("production certificate gate requires real root")
        self.temp = tempfile.TemporaryDirectory(prefix="xmesh-public-tls-cert-")
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.live, self.archive = base / "live", base / "archive"
        self.live.mkdir(mode=0o700)
        self.archive.mkdir(mode=0o700)
        self.patch_live = mock.patch.object(certs, "LIVE_ROOT", self.live)
        self.patch_archive = mock.patch.object(certs, "ARCHIVE_ROOT", self.archive)
        self.patch_live.start()
        self.patch_archive.start()
        self.addCleanup(self.patch_live.stop)
        self.addCleanup(self.patch_archive.stop)
        self.ca_cert = base / "trusted-root.pem"
        self.ca_key = base / "trusted-root.key"
        subprocess.run([
            "/usr/bin/openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-days", "30", "-keyout", str(self.ca_key),
            "-out", str(self.ca_cert), "-subj", "/CN=XMesh disposable CA",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ], check=True, stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE, timeout=15)
        self.ca_key.chmod(0o600)
        self.ca_cert.chmod(0o644)
        self.patch_ca = mock.patch.object(certs, "SYSTEM_CA_FILE", self.ca_cert)
        self.patch_ca.start()
        self.addCleanup(self.patch_ca.stop)
        for domain in (DOMAIN_A, DOMAIN_B):
            self.make_lineage(domain)

    def make_lineage(self, domain, *, subject=None, days=7):
        live = self.live / domain
        archive = self.archive / domain
        live.mkdir(mode=0o700, exist_ok=True)
        archive.mkdir(mode=0o700, exist_ok=True)
        cert = archive / "fullchain1.pem"
        key = archive / "privkey1.pem"
        csr = archive / "request.csr"
        leaf = archive / "leaf.pem"
        extensions = archive / "tls-server.ext"
        extensions.write_text(
            "[server_cert]\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=serverAuth\n"
            "subjectAltName=DNS:" + (subject or domain) + "\n"
        )
        subprocess.run([
            "/usr/bin/openssl", "req", "-new", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-out", str(csr), "-keyout", str(key),
            "-subj", "/CN=" + domain,
        ], check=True, stdout=subprocess.DEVNULL,
           stderr=subprocess.PIPE, timeout=15)
        subprocess.run([
            "/usr/bin/openssl", "x509", "-req", "-in", str(csr),
            "-CA", str(self.ca_cert), "-CAkey", str(self.ca_key),
            "-CAcreateserial", "-days", str(days), "-out", str(leaf),
            "-extensions", "server_cert", "-extfile", str(extensions),
        ], check=True, stdout=subprocess.DEVNULL,
           stderr=subprocess.PIPE, timeout=15)
        cert.write_bytes(leaf.read_bytes() + self.ca_cert.read_bytes())
        key.chmod(0o600)
        cert.chmod(0o644)
        for kind in ("fullchain", "privkey"):
            pointer = live / (kind + ".pem")
            if pointer.exists() or pointer.is_symlink():
                pointer.unlink()
            pointer.symlink_to("../../archive/" + domain + "/" + kind + "1.pem")

    def test_two_independent_root_owned_lineages_and_signed_paths(self):
        result = certs.verify_certificate_lineage(signed_compiled_config())
        self.assertEqual(set(result), {"vless-cdn", "vless-main"})
        self.assertEqual(str(result["vless-cdn"][0]),
                         str(self.live / DOMAIN_A / "fullchain.pem"))

    def test_sealed_child_config_keeps_exact_verified_bytes_after_certbot_rotation(self):
        original = signed_compiled_config()
        expected = {}
        for inbound in original["inbounds"]:
            tag = inbound["tag"]
            domain = inbound["streamSettings"]["tlsSettings"]["serverName"]
            expected[tag] = tuple(hashlib.sha256((self.archive / domain / name).read_bytes()).hexdigest()
                                  for name in ("fullchain1.pem", "privkey1.pem"))
        with certs.freeze_certificate_lineage(original) as frozen:
            self.assertIsNone(frozen.ensure_current())
            # The exact fd-backed config is handed to an independent process.
            # That process reads the inherited paths the same way Xray would.
            script = """
import hashlib, json, sys
from pathlib import Path
config = json.load(sys.stdin)
out = {}
for inbound in config['inbounds']:
    pair = inbound['streamSettings']['tlsSettings']['certificates'][0]
    out[inbound['tag']] = [hashlib.sha256(Path(pair[k]).read_bytes()).hexdigest()
                            for k in ('certificateFile', 'keyFile')]
print(json.dumps(out))
"""
            def child():
                os.lseek(frozen.config_fd, 0, os.SEEK_SET)
                raw = subprocess.check_output(
                    [sys.executable, "-c", script], stdin=frozen.config_fd,
                    pass_fds=frozen.material_fds, timeout=8)
                return {tag: tuple(digests) for tag, digests in json.loads(raw).items()}

            self.assertEqual(child(), expected)
            # The original configuration is unchanged. Neither literal
            # private-key bytes nor a mutable live symlink go to the child.
            compiled = json.loads(os.pread(frozen.config_fd, certs.MAX_CONFIG_BYTES, 0))
            for before, after in zip(original["inbounds"], compiled["inbounds"]):
                before = copy.deepcopy(before)
                record = before["streamSettings"]["tlsSettings"]["certificates"][0]
                record.update(after["streamSettings"]["tlsSettings"]["certificates"][0])
                self.assertEqual(before, after)
                for path in record.values():
                    self.assertTrue(path.startswith("/proc/self/fd/"))
            for fd in (*frozen.material_fds, frozen.config_fd):
                self.assertFalse(os.get_inheritable(fd))
                self.assertEqual(fcntl.fcntl(fd, fcntl.F_GET_SEALS), certs.SEALS)
                with self.assertRaises(OSError) as denied:
                    os.pwrite(fd, b"x", 0)
                self.assertEqual(denied.exception.errno, errno.EPERM)
            # Real Certbot-style atomic symlink replacement after proof.
            archive = self.archive / DOMAIN_A
            replacement = archive / "fullchain2.pem"
            replacement.write_bytes((archive / "fullchain1.pem").read_bytes())
            live = self.live / DOMAIN_A
            next_link = live / "next"
            next_link.symlink_to("../../archive/" + DOMAIN_A + "/fullchain2.pem")
            os.replace(next_link, live / "fullchain.pem")
            with self.assertRaisesRegex(ValueError, "lineage changed"):
                frozen.ensure_current()
            self.assertEqual(child(), expected)
            # In-place change to an already copied file cannot affect the
            # child's material either, even before a changed-link recheck.
            (archive / "privkey1.pem").write_bytes(b"invalid")
            self.assertEqual(child(), expected)
            fds = (*frozen.material_fds, frozen.config_fd)
        for fd in fds:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_real_tls13_child_uses_sealed_key_and_chain_without_public_listener(self):
        with certs.freeze_certificate_lineage(signed_compiled_config()) as frozen:
            # No public socket or even TCP port: an actual TLS 1.3 handshake
            # over a kernel socketpair, in an independently exec'd process.
            script = """
import json, socket, ssl, sys
config = json.load(sys.stdin)
pair = config['inbounds'][0]['streamSettings']['tlsSettings']['certificates'][0]
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3
context.load_cert_chain(pair['certificateFile'], pair['keyFile'])
with socket.socket(fileno=int(sys.argv[1])) as sock:
    sock.settimeout(8)
    with context.wrap_socket(sock, server_side=True) as tls:
        assert tls.version() == 'TLSv1.3'
        assert tls.recv(8) == b'ping'
        tls.sendall(b'pong')
"""
            # Destroy the mutable source key after validation. The actual
            # child must still use the captured original—not a changed path.
            (self.archive / DOMAIN_A / "privkey1.pem").write_bytes(b"broken")
            os.lseek(frozen.config_fd, 0, os.SEEK_SET)
            left, right = socket.socketpair()
            try:
                child = subprocess.Popen(
                    [sys.executable, "-c", script, str(right.fileno())],
                    stdin=frozen.config_fd,
                    pass_fds=(*frozen.material_fds, right.fileno()),
                    stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                right.close()
                try:
                    context = ssl.create_default_context(cafile=str(self.ca_cert))
                    context.minimum_version = ssl.TLSVersion.TLSv1_3
                    left.settimeout(8)
                    with context.wrap_socket(left, server_hostname=DOMAIN_A) as tls:
                        self.assertEqual(tls.version(), "TLSv1.3")
                        tls.sendall(b"ping")
                        self.assertEqual(tls.recv(8), b"pong")
                    _, error = child.communicate(timeout=8)
                    self.assertEqual(child.returncode, 0, error)
                finally:
                    if child.poll() is None:
                        child.kill()
                        child.communicate(timeout=8)
                with self.assertRaisesRegex(ValueError, "lineage changed"):
                    frozen.ensure_current()
            finally:
                left.close()
                right.close()

    def test_future_dated_certificate_does_not_pass_renewal_margin_only(self):
        # Generate a real CA-signed server leaf that starts in 2h and will
        # be valid at the 24-hour renewal-margin timestamp. It is not valid
        # right now and must never pass the startup proof.
        root = Path(self.temp.name)
        archive = self.archive / DOMAIN_A
        database = root / "index.txt"
        database.touch()
        serial = root / "serial"
        serial.write_text("1000\n")
        config = root / "future-ca.cnf"
        config.write_text(
            f"[ca]\ndefault_ca=local\n[local]\ndatabase={database}\n"
            f"serial={serial}\nnew_certs_dir={root}\ncertificate={self.ca_cert}\n"
            f"private_key={self.ca_key}\ndefault_md=sha256\npolicy=policy\n"
            "unique_subject=no\n[policy]\ncommonName=supplied\n")
        now = datetime.now(timezone.utc)
        start = (now + timedelta(hours=2)).strftime("%Y%m%d%H%M%SZ")
        end = (now + timedelta(days=7)).strftime("%Y%m%d%H%M%SZ")
        leaf = archive / "future.pem"
        subprocess.run([
            "/usr/bin/openssl", "ca", "-batch", "-config", str(config),
            "-in", str(archive / "request.csr"), "-out", str(leaf), "-notext",
            "-startdate", start, "-enddate", end,
            "-extfile", str(archive / "tls-server.ext"), "-extensions", "server_cert",
        ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        chain = archive / "fullchain1.pem"
        chain.write_bytes(leaf.read_bytes() + self.ca_cert.read_bytes())
        # Demonstrate that future-only validation would in fact pass.
        subprocess.run([
            "/usr/bin/openssl", "verify", "-purpose", "sslserver",
            "-verify_hostname", DOMAIN_A, "-attime", str(int(now.timestamp()) + 86400),
            "-CAfile", str(self.ca_cert), "-untrusted", str(chain), str(chain),
        ], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        with self.assertRaisesRegex(ValueError, "TLS certificate validity"):
            certs.freeze_certificate_lineage(signed_compiled_config())

    def test_rotation_during_openssl_verification_denies_and_closes_every_fd(self):
        initial = set(os.listdir("/proc/self/fd"))
        original = certs._verify_material

        def rotate(name, cert, key, ca):
            original(name, cert, key, ca)
            if name == DOMAIN_A:
                target = self.archive / name / "fullchain2.pem"
                target.write_bytes((self.archive / name / "fullchain1.pem").read_bytes())
                live = self.live / name / "fullchain.pem"
                live.unlink()
                live.symlink_to("../../archive/" + name + "/fullchain2.pem")

        with mock.patch.object(certs, "_verify_material", side_effect=rotate):
            with self.assertRaisesRegex(ValueError, "lineage changed"):
                certs.freeze_certificate_lineage(signed_compiled_config())
        self.assertEqual(set(os.listdir("/proc/self/fd")), initial)

    def test_frozen_input_rejects_ca_change_or_clock_discontinuity(self):
        with certs.freeze_certificate_lineage(signed_compiled_config()) as frozen:
            with mock.patch.object(certs.time, "time_ns",
                                   return_value=certs.time.time_ns() + 3_000_000_000):
                with self.assertRaisesRegex(ValueError, "clock changed"):
                    frozen.ensure_current()
            self.ca_cert.write_bytes(self.ca_cert.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "trust changed"):
                frozen.ensure_current()

    def test_descriptor_substitution_is_rejected_even_when_replacement_is_sealed(self):
        with certs.freeze_certificate_lineage(signed_compiled_config()) as frozen:
            fd = frozen.material_fds[0]
            forged = certs._sealed_bytes("foreign", b"foreign")
            try:
                os.dup2(forged, fd, inheritable=False)
                with self.assertRaisesRegex(ValueError, "original kernel-sealed inode"):
                    frozen.ensure_current()
            finally:
                os.close(forged)

    def test_mismatched_private_key_is_denied(self):
        other = self.archive / DOMAIN_B / "privkey1.pem"
        key = self.archive / DOMAIN_A / "privkey1.pem"
        key.write_bytes(other.read_bytes())
        key.chmod(0o600)
        with self.assertRaises(ValueError):
            certs.verify_certificate_lineage(signed_compiled_config())

    def test_foreign_san_and_near_expiry_denied(self):
        self.make_lineage(DOMAIN_A, subject="foreign.example.com")
        with self.assertRaises(ValueError):
            certs.verify_certificate_lineage(signed_compiled_config())
        self.make_lineage(DOMAIN_A, days=1)
        with self.assertRaises(ValueError):
            certs.verify_certificate_lineage(signed_compiled_config())

    def test_certbot_lineage_escape_and_writable_secrets_denied(self):
        pointer = self.live / DOMAIN_A / "fullchain.pem"
        pointer.unlink()
        pointer.symlink_to(str(self.archive / DOMAIN_B / "fullchain1.pem"))
        with self.assertRaises(ValueError):
            certs.verify_certificate_lineage(signed_compiled_config())
        self.make_lineage(DOMAIN_A)
        key = self.archive / DOMAIN_A / "privkey1.pem"
        key.chmod(0o644)
        with self.assertRaises(ValueError):
            certs.verify_certificate_lineage(signed_compiled_config())
        key.chmod(0o600)
        (self.archive / DOMAIN_A).chmod(0o777)
        with self.assertRaises(ValueError):
            certs.verify_certificate_lineage(signed_compiled_config())

    def test_self_signed_or_untrusted_server_certificate_is_denied(self):
        archive = self.archive / DOMAIN_A
        cert, key = archive / "fullchain1.pem", archive / "privkey1.pem"
        subprocess.run([
            "/usr/bin/openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
            "-days", "7", "-out", str(cert), "-keyout", str(key),
            "-subj", "/CN=" + DOMAIN_A,
            "-addext", "subjectAltName=DNS:" + DOMAIN_A,
            "-addext", "extendedKeyUsage=serverAuth",
        ], check=True, stdout=subprocess.DEVNULL,
           stderr=subprocess.PIPE, timeout=15)
        key.chmod(0o600)
        cert.chmod(0o644)
        with self.assertRaises(ValueError):
            certs.verify_certificate_lineage(signed_compiled_config())

    def test_root_ca_bundle_must_be_root_owned_and_not_writable(self):
        self.ca_cert.chmod(0o666)
        with self.assertRaises(ValueError):
            certs.verify_certificate_lineage(signed_compiled_config())
        self.ca_cert.chmod(0o644)
        certs.verify_certificate_lineage(signed_compiled_config())

    def test_certificate_without_tls_server_eku_is_denied(self):
        archive = self.archive / DOMAIN_A
        extensions = archive / "tls-server.ext"
        extensions.write_text(
            "[bad_client_cert]\n"
            "basicConstraints=critical,CA:FALSE\n"
            "keyUsage=critical,digitalSignature\n"
            "extendedKeyUsage=clientAuth\n"
            "subjectAltName=DNS:" + DOMAIN_A + "\n"
        )
        leaf = archive / "leaf.pem"
        subprocess.run([
            "/usr/bin/openssl", "x509", "-req",
            "-in", str(archive / "request.csr"),
            "-CA", str(self.ca_cert), "-CAkey", str(self.ca_key),
            "-CAcreateserial", "-days", "7", "-out", str(leaf),
            "-extensions", "bad_client_cert", "-extfile", str(extensions),
        ], check=True, stdout=subprocess.DEVNULL,
           stderr=subprocess.PIPE, timeout=15)
        cert = archive / "fullchain1.pem"
        cert.write_bytes(leaf.read_bytes() + self.ca_cert.read_bytes())
        with self.assertRaises(ValueError):
            certs.verify_certificate_lineage(signed_compiled_config())

    def test_cannot_bypass_signed_tls_config_shape(self):
        original = signed_compiled_config()
        changes = [
            lambda c: c["inbounds"][0]["streamSettings"].update(
                allowInsecure=True),
            lambda c: c["inbounds"][0]["streamSettings"]["tlsSettings"].update(
                rejectUnknownSni=False),
            lambda c: c["inbounds"][0]["streamSettings"]["tlsSettings"][
                "certificates"][0].update(certificateFile="/tmp/wrong.pem"),
            lambda c: c["inbounds"][0]["streamSettings"].update(
                security="none"),
            lambda c: c["inbounds"][0].update(tag="unknown"),
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                modified = copy.deepcopy(original)
                change(modified)
                certs.verify_certificate_lineage(modified)
        with mock.patch.object(certs.os, "geteuid", return_value=1000):
            with self.assertRaises(ValueError):
                certs.verify_certificate_lineage(original)


if __name__ == "__main__":
    unittest.main()
