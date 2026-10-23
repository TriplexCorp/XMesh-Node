#!/usr/bin/env python3
"""Offline GeoData worker regression tests; no network or Docker required."""
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

MODULE = Path(__file__).resolve().parents[1] / "deploy" / "xmesh-geodata-sync.py"
spec = importlib.util.spec_from_file_location("xmesh_geodata", MODULE)
geo = importlib.util.module_from_spec(spec)
spec.loader.exec_module(geo)


def payload(files):
    return {"policy": {"geoData": {"version": 1, "intervalHours": 24, "files": files}}}


class GeoDataWorkerTests(unittest.TestCase):
    def test_private_hosts_rejected(self):
        for url in ("http://example.org/a.dat", "https://localhost/a",
                    "https://127.0.0.1/a", "https://a.local/a",
                    "https://user:pass@example.org/a.dat"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                geo.public_destination(url)

    def test_update_is_transactional_and_reports_hashes(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp)
            manifest = state / "verified.json"
            manifest.write_text(json.dumps(payload([
                {"name": "geosite.dat", "url": "https://example.org/geosite.dat", "sha256": None},
                {"name": "geoip.dat", "url": "https://example.org/geoip.dat", "sha256": None},
            ])))
            def first(_url, destination):
                destination.write_bytes(b"valid-test-geodata-1" * 2)
            with patch.object(geo, "fetch_url", side_effect=first):
                geo.prepare(state, manifest)
            self.assertTrue((state / "geo-changed").exists())
            self.assertTrue((state / "assets" / "geosite.dat").exists())
            geo.finish(state)
            self.assertFalse((state / "geo-changed").exists())
            self.assertEqual(json.loads((state/"geo-status.json").read_text())["state"], "current")

            # Same manifest before the configured interval must not refetch.
            with patch.object(geo, "fetch_url", side_effect=AssertionError("unexpected fetch")):
                geo.prepare(state, manifest)
            status = json.loads((state / "geo-status.json").read_text())
            status["checkedAt"] = 0
            geo.persist_json(state / "geo-status.json", status)
            def second(_url, destination):
                destination.write_bytes(b"replacement-test-geodata-2" * 2)
            with patch.object(geo, "fetch_url", side_effect=second):
                geo.prepare(state, manifest)
            self.assertTrue((state/"assets.previous").exists())
            geo.finish(state, rollback=True)
            self.assertEqual((state/"assets"/"geosite.dat").read_bytes(),
                             b"valid-test-geodata-1" * 2)
            self.assertFalse((state/"geo-changed").exists())

    def test_bad_sha_does_not_replace_existing_assets(self):
        with tempfile.TemporaryDirectory() as temp:
            state = Path(temp)
            source = state / "verified.json"
            source.write_text(json.dumps(payload([{
                "name": "geosite.dat", "url": "https://example.org/ads.dat",
                "sha256": "0" * 64
            }])))
            with patch.object(geo, "fetch_url", side_effect=lambda u, p:p.write_bytes(b"bad-content-bad-content")):
                with self.assertRaises(ValueError):
                    geo.prepare(state, source)
            self.assertFalse((state/"assets").exists())


if __name__ == "__main__":
    unittest.main()
