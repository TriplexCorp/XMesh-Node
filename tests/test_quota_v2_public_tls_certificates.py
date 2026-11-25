#!/usr/bin/env python3
"""Root-only Certbot lineage negatives for an inactive Quota V2 public TLS gate."""
import copy
import os
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
        for domain in (DOMAIN_A, DOMAIN_B):
            self.make_lineage(domain)

    def make_lineage(self, domain, *, subject=None, days=7):
        live = self.live / domain
        archive = self.archive / domain
        live.mkdir(mode=0o700, exist_ok=True)
        archive.mkdir(mode=0o700, exist_ok=True)
        cert = archive / "fullchain1.pem"
        key = archive / "privkey1.pem"
        command = [
            "/usr/bin/openssl", "req", "-x509", "-newkey", "ec",
            "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-days", str(days), "-out", str(cert),
            "-keyout", str(key), "-subj", "/CN=" + domain,
            "-addext", "subjectAltName=DNS:" + (subject or domain),
        ]
        subprocess.run(command, check=True, stdout=subprocess.DEVNULL,
                       stderr=subprocess.PIPE, timeout=15)
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
