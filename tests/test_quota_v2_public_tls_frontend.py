#!/usr/bin/env python3
"""Pure public TLS VLESS config checks; no public listener or cap issuer."""
import copy
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] /
                       "experiments" / "quota-v2-physical-stop"))
import public_tls_frontend as tls

USER = 941
UUID = "11111111-1111-4111-8111-111111111111"


def profile():
    return {"inbounds": [
        {"tag": "vless-" + cls, "listen": "127.0.0.1", "port": 20000 + i,
         "protocol": "vless", "settings": {"decryption": "none", "clients": [
             {"id": UUID, "email": f"xmesh-u{USER}--vless-{cls}"}
         ]}}
        for i, cls in enumerate(("cdn", "main"))
    ]}


def bindings():
    return [
        {"tag": "vless-cdn", "domain": "cdn.example.com", "port": 443},
        {"tag": "vless-main", "domain": "vpn.example.com", "port": 8443},
    ]


class PublicTlsCompilerTests(unittest.TestCase):
    def test_tls_is_only_on_isolated_ingress_and_never_changes_meter(self):
        original = profile()
        previous = copy.deepcopy(original)
        out = tls.compile_public_tls(original, bindings())
        self.assertEqual(original, previous)
        self.assertEqual(len(out["inbounds"]), 2)
        for inbound, binding in zip(out["inbounds"], bindings()):
            self.assertEqual(inbound["tag"], binding["tag"])
            self.assertEqual(inbound["listen"], "0.0.0.0")
            self.assertEqual(inbound["port"], binding["port"])
            self.assertEqual(inbound["streamSettings"]["security"], "tls")
            settings = inbound["streamSettings"]["tlsSettings"]
            self.assertEqual(settings["minVersion"], "1.3")
            self.assertEqual(settings["serverName"], binding["domain"])
            cert = settings["certificates"][0]
            self.assertEqual(
                cert["certificateFile"],
                "/etc/letsencrypt/live/" + binding["domain"] + "/fullchain.pem")
            self.assertEqual(
                cert["keyFile"],
                "/etc/letsencrypt/live/" + binding["domain"] + "/privkey.pem")
        self.assertEqual(len(out["routing"]["rules"]), 2)
        self.assertEqual(out["outbounds"][0], {"tag": "deny", "protocol": "blackhole"})
        self.assertEqual({o["protocol"] for o in out["outbounds"][1:]}, {"vless"})
        self.assertEqual(
            {o["settings"]["vnext"][0]["address"] for o in out["outbounds"][1:]},
            {"xmesh-meter.invalid"})

    def test_scope_must_have_distinct_public_ports(self):
        good = bindings()
        malformed = [
            [], [good[0]], good + [good[1]], [good[0], good[0]],
            [good[0], dict(good[1], port=443)],
            [good[0], dict(good[1], tag="vless-foreign")],
            [good[0], dict(good[1], tag="vless-cdn")],
            [good[0], dict(good[1], port=0)],
            [good[0], dict(good[1], port=65536)],
            [good[0], dict(good[1], port=True)],
            [good[0], dict(good[1], port="8443")],
        ]
        for bad in malformed:
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                tls.compile_public_tls(profile(), bad)

    def test_domain_canonical_and_cert_paths_not_caller_supplied(self):
        for domain in ("UPPER.example.com", "*.example.com", "../example.com",
                       "example.com.", "localhost", "127.0.0.1",
                       "a_b.example.com", "-bad.example.com", "bad-.example.com",
                       "test..example.com", "éxample.com",
                       "foo/bar.example.com", "x" * 64 + ".example.com"):
            with self.subTest(domain=domain), self.assertRaises(ValueError):
                tls.compile_public_tls(
                    profile(), [bindings()[0], dict(bindings()[1], domain=domain)])
        for extra in ({"certificateFile": "/etc/ssl/unsafe"},
                      {"fallback": True}, {"listen": "127.0.0.1"},
                      {"tlsSettings": {}}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                tls.compile_public_tls(
                    profile(), [dict(bindings()[0], **extra), bindings()[1]])

    def test_untrusted_meter_and_unsupported_transport_refused(self):
        for mutate in (
            lambda p: p["inbounds"][0].update(listen="0.0.0.0"),
            lambda p: p["inbounds"][0].update(protocol="trojan"),
            lambda p: p["inbounds"][0]["settings"].update(fallbacks=[{"dest": 80}]),
            lambda p: p["inbounds"][0]["settings"]["clients"][0].update(flow="xtls-rprx-vision"),
            lambda p: p["inbounds"][0].update(streamSettings={"network": "xhttp"}),
            lambda p: p["inbounds"][0].update(streamSettings={"security": "tls"}),
            lambda p: p["inbounds"][0].update(
                streamSettings={"network": "tcp", "security": "none", "sockopt": {}}),
        ):
            with self.subTest(mutate=mutate), self.assertRaises(
                    (ValueError, TypeError, KeyError)):
                p = profile()
                mutate(p)
                tls.compile_public_tls(p, bindings())


if __name__ == "__main__":
    unittest.main()
