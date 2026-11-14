"""--update and the downloaded-indicator cache (zbtriage/feeds.py).

Pinned here, all without touching the network (downloads are injected):
  - only allow-listed sources can be fetched, and a redirect elsewhere is refused;
  - a failed, HTML or unparseable download never replaces the previous good copy;
  - a cached file edited after download is refused at scan time;
  - the older Amnesty list formats are validated like STIX;
  - a default scan without downloaded sets says so, in must_relay.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import cli, feeds  # noqa: E402
from zbtriage.iocs import TYPE_DOMAIN, TYPE_IP, IocError  # noqa: E402

STIX_OK = json.dumps({"type": "bundle", "objects": [
    {"type": "malware", "id": "malware--1", "name": "Pegasus"},
    {"type": "indicator", "id": "indicator--1", "pattern": "[domain-name:value='feed-one.example']"},
    {"type": "relationship", "relationship_type": "indicates",
     "source_ref": "indicator--1", "target_ref": "malware--1"}]}).encode()
STIX_OK2 = STIX_OK.replace(b"feed-one", b"feed-two")

SRC = {"id": "test-src", "name": "Test source", "format": "stix2", "cite": "Test",
       "category": "mercenary", "family": "",
       "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/x/test.stix2"}


def fake_fetch(responses):
    def fetch(url):
        r = responses[url] if isinstance(responses, dict) else responses
        if isinstance(r, Exception):
            raise r
        return r
    return fetch


class TestAllowList(unittest.TestCase):
    def test_only_allow_listed_github_paths(self):
        self.assertTrue(feeds.url_allowed(SRC["url"]))
        for bad in ("http://raw.githubusercontent.com/mvt-project/mvt-indicators/main/x",
                    "https://raw.githubusercontent.com/someone-else/repo/main/x.stix2",
                    "https://evil.example/mvt-project/mvt-indicators/x",
                    "https://raw.githubusercontent.com/mvt-project/mvt-indicators/../../x",
                    "https://raw.githubusercontent.com.evil.example/mvt-project/mvt-indicators/x"):
            with self.subTest(url=bad):
                self.assertFalse(feeds.url_allowed(bad))

    def test_every_built_in_source_is_allow_listed(self):
        ids = [s["id"] for s in feeds.SOURCES]
        self.assertEqual(len(ids), len(set(ids)))
        for s in feeds.SOURCES:
            self.assertTrue(feeds.url_allowed(s["url"]), s["id"])

    def test_redirect_outside_the_allow_list_is_refused(self):
        handler = feeds._AllowListRedirect()
        with self.assertRaises(Exception):
            handler.redirect_request(None, None, 302, "Found", {},
                                     "https://evil.example/payload.stix2")

    def test_fetch_refuses_a_disallowed_url_before_any_network(self):
        with patch("urllib.request.build_opener", side_effect=AssertionError("network")):
            with self.assertRaises(IocError):
                feeds._fetch("https://evil.example/x.stix2")


class TestUpdate(unittest.TestCase):
    def setUp(self):
        self.cache = tempfile.mkdtemp(prefix="feeds_")
        # cached_sets() only trusts sources in the built-in list.
        self.src_patch = patch.object(feeds, "SOURCES", [SRC])
        self.src_patch.start()
        # these tests are about the download cache itself: no built-in copies, no known-good lists
        self.builtin_patch = patch.object(feeds, "MVT_BUILTIN", {})
        self.builtin_patch.start()
        self.kg_patch = patch.object(feeds, "KNOWN_GOOD_SOURCES", [])
        self.kg_patch.start()

    def tearDown(self):
        self.src_patch.stop()
        self.builtin_patch.stop()
        self.kg_patch.stop()

    def update(self, response):
        return feeds.update(self.cache, sources=[SRC], fetch=fake_fetch(response))

    def test_successful_update_writes_file_and_manifest(self):
        s = self.update(STIX_OK)
        self.assertEqual((s["ok"], s["failed"]), (1, 0))
        meta = feeds.read_manifest(self.cache)["test-src"]
        self.assertEqual(meta["indicators"], 1)
        self.assertEqual(len(meta["sha256"]), 64)
        self.assertTrue(os.path.exists(os.path.join(self.cache, meta["file"])))

    def test_same_content_is_reported_unchanged(self):
        self.update(STIX_OK)
        s = self.update(STIX_OK)
        self.assertEqual(s["sources"][0]["status"], "unchanged")

    def test_bad_downloads_keep_the_previous_good_copy(self):
        self.update(STIX_OK)
        for bad in (b"<!DOCTYPE html><html>rate limited</html>", b"not json",
                    json.dumps({"objects": []}).encode(), OSError("network down")):
            with self.subTest(bad=str(bad)[:30]):
                s = self.update(bad)
                self.assertEqual(s["failed"], 1)
                self.assertTrue(s["sources"][0]["kept_previous"])
                sets, status = feeds.cached_sets(self.cache)
                self.assertEqual([i.value for i in sets[0].indicators], ["feed-one.example"])
        leftovers = [f for f in os.listdir(self.cache) if f.startswith(".dl.")]
        self.assertEqual(leftovers, [])

    def test_new_content_replaces_the_old(self):
        self.update(STIX_OK)
        self.update(STIX_OK2)
        sets, _ = feeds.cached_sets(self.cache)
        self.assertEqual([i.value for i in sets[0].indicators], ["feed-two.example"])

    @unittest.skipUnless(sys.platform == "win32", "Windows-only behaviour")
    def test_cache_on_a_network_path_is_refused(self):
        with self.assertRaises(IocError):
            feeds.update(r"\\server\share\cache", sources=[SRC], fetch=fake_fetch(STIX_OK))


class TestCachedSets(unittest.TestCase):
    def setUp(self):
        self.cache = tempfile.mkdtemp(prefix="feeds_")
        feeds.update(self.cache, sources=[SRC], fetch=fake_fetch(STIX_OK))
        self.src_patch = patch.object(feeds, "SOURCES", [SRC])
        self.src_patch.start()
        # these tests are about the download cache itself: no built-in copies, no known-good lists
        self.builtin_patch = patch.object(feeds, "MVT_BUILTIN", {})
        self.builtin_patch.start()
        self.kg_patch = patch.object(feeds, "KNOWN_GOOD_SOURCES", [])
        self.kg_patch.start()

    def tearDown(self):
        self.src_patch.stop()
        self.builtin_patch.stop()
        self.kg_patch.stop()

    def test_verified_file_loads_with_its_family(self):
        sets, status = feeds.cached_sets(self.cache)
        self.assertEqual(len(status["loaded"]), 1)
        self.assertEqual(sets[0].indicators[0].family, "Pegasus")

    def test_a_file_edited_after_download_is_refused(self):
        meta = feeds.read_manifest(self.cache)["test-src"]
        with open(os.path.join(self.cache, meta["file"]), "ab") as fh:
            fh.write(b" ")
        sets, status = feeds.cached_sets(self.cache)
        self.assertEqual(sets, [])
        self.assertEqual(status["refused"][0]["reason"], "file changed since download")

    def test_missing_file_is_reported_not_fatal(self):
        meta = feeds.read_manifest(self.cache)["test-src"]
        os.unlink(os.path.join(self.cache, meta["file"]))
        sets, status = feeds.cached_sets(self.cache)
        self.assertEqual(status["missing"], ["test-src"])

    def test_unknown_source_in_manifest_is_refused(self):
        with patch.object(feeds, "SOURCES", []):
            sets, status = feeds.cached_sets(self.cache)
        self.assertEqual(status["refused"][0]["reason"], "not a known source")


class TestListFormats(unittest.TestCase):
    def write(self, text, name):
        path = os.path.join(tempfile.mkdtemp(prefix="list_"), name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)
        return path

    def test_domains_txt(self):
        s = feeds.load_list(self.write("stopsms.biz\n\n# comment\nbad domain\n10.0.0.1\n",
                                       "d.txt"), "domains-txt", "Amnesty", "Pegasus")
        self.assertEqual([(i.value, i.type) for i in s.indicators], [("stopsms.biz", TYPE_DOMAIN)])
        self.assertEqual(sum(s.sets[0]["refused_invalid"].values()), 2)
        self.assertEqual(s.indicators[0].family, "Pegasus")

    def test_csv_domain_ip(self):
        s = feeds.load_list(self.write('domain_name,ip_address\n"a-nso.example","5.6.7.8"\n'
                                       '"b-nso.example","192.168.1.1"\n', "i.csv"),
                            "csv-domain-ip", "Amnesty", "Pegasus")
        got = {(i.value, i.type, i.tier) for i in s.indicators}
        self.assertIn(("a-nso.example", TYPE_DOMAIN, "infrastructure"), got)
        self.assertIn(("5.6.7.8", TYPE_IP, "infrastructure-ip"), got)
        self.assertNotIn("192.168.1.1", {i.value for i in s.indicators})

    def test_empty_list_is_an_error(self):
        with self.assertRaises(IocError):
            feeds.load_list(self.write("# nothing\n", "e.txt"), "domains-txt", "x", "y")


class TestCliFeeds(unittest.TestCase):
    def test_default_scan_without_downloads_says_so(self):
        empty = tempfile.mkdtemp(prefix="nocache_")
        report = os.path.join(tempfile.mkdtemp(prefix="rep_"), "r.json")
        with patch.object(cli, "_run_modules", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            cli.main(["--indicator-cache", empty, "--json", report])
        doc = json.load(open(report, encoding="utf-8"))
        # only the lists built into the release load; the report still asks for an update
        self.assertTrue(all(e.get("built_in") for e in doc["ioc_set"]["feeds"]["loaded"]))
        self.assertIn("feeds-missing", [m["id"] for m in doc["must_relay"]])
        self.assertIn("update-indicators", [s["id"] for s in doc["next_steps"]])

    def test_explicit_iocs_do_not_pull_in_the_cache(self):
        report = os.path.join(tempfile.mkdtemp(prefix="rep_"), "r.json")
        with patch.object(cli, "_run_modules", return_value=[]), \
                patch.object(feeds, "cached_sets", side_effect=AssertionError("cache read")), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            cli.main(["--iocs", cli._default_ioc_path(), "--json", report])
        doc = json.load(open(report, encoding="utf-8"))
        self.assertEqual(doc["ioc_set"]["feeds"], {"used": False, "reason": "--iocs given"})
        self.assertNotIn("feeds-missing", [m["id"] for m in doc["must_relay"]])

    def test_update_never_runs_during_a_scan(self):
        with patch.object(feeds, "update", side_effect=AssertionError("network during scan")), \
                patch.object(cli, "_run_modules", return_value=[]), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            cli.main(["--indicator-cache", tempfile.mkdtemp(prefix="c_")])


if __name__ == "__main__":
    unittest.main()
