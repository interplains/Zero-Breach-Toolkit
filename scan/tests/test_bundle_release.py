"""Exercise the shipped entry point and feeds using only synthetic temp data."""

import contextlib
import datetime
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scan"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from zbtriage import iocs
from test_browser_launch import chromium_cookie_db
from reader_fixtures import stub_registered_readers


def import_file(name, path):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class TestDownloadedEntryPoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_tmp = tempfile.TemporaryDirectory(prefix="bundle_release_")
        path = Path(cls.build_tmp.name) / "scanner.py"
        subprocess.run([sys.executable, "-B", str(ROOT / "build/bundle.py"),
                        str(ROOT), str(path)], check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        cls.bundle = import_file("_release_test_bundle", path)

    @classmethod
    def tearDownClass(cls):
        sys.modules.pop("_release_test_bundle", None)
        cls.build_tmp.cleanup()

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="bundle_fixture_")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.ud = self.root / "User Data"
        self.ioc_path = self.root / "iocs.txt"
        self.ioc_path.write_text(
            "# as-of: 2026-10-18\n"
            "review.invalid\tcc\tprimary\ttest\n"
            "later.invalid\tcc\tprimary\ttest\n", encoding="utf-8")

    def run_bundle(self, browser_run=None, extra=()):
        b = self.bundle
        documents = []
        with contextlib.ExitStack() as stack:
            stub_registered_readers(stack, b, keep=("browser", "android", "ios", "android-intrusion"))
            stack.enter_context(patch.object(b, "CHROMIUM_ROOTS",
                                             [("test", str(self.ud))]))
            stack.enter_context(patch.object(b, "FIREFOX_ROOTS", []))
            stack.enter_context(patch.object(b, "_force_utf8_io", lambda: None))
            stack.enter_context(patch.object(
                b, "render_human", lambda doc: documents.append(doc) or ""))
            if browser_run is not None:
                stack.enter_context(patch.object(b, "run_browser", browser_run))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            code = b.main(["--no-pause", "--iocs", str(self.ioc_path)] + list(extra))
        return code, documents[0]

    # The download has its own entry point, separate from the source CLI. The
    # network-path guard was once added only to cli.py and was silently absent
    # from the file people actually download, so it is tested here directly.
    @unittest.skipUnless(sys.platform == "win32",
                         "UNC and mapped-drive paths are a Windows concept")
    def test_download_refuses_network_paths_before_opening_anything(self):
        b = self.bundle
        bs = chr(92)
        unc = bs + bs + "server.invalid" + bs + "share" + bs + "x.txt"
        opened = []

        def must_not_load(*args, **kwargs):
            opened.append(args)
            raise AssertionError("indicator file opened before the refusal")

        for flag in ("--iocs", "--json", "--share-json"):
            err = io.StringIO()
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(b, "_load_embedded_iocs",
                                                 must_not_load))
                stack.enter_context(patch.object(b, "_force_utf8_io",
                                                 lambda: None))
                stack.enter_context(contextlib.redirect_stderr(err))
                stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
                code = b.main(["--no-pause", flag, unc])
            self.assertEqual(code, 1, flag)
            self.assertIn("local disk", err.getvalue(), flag)
        self.assertEqual(opened, [])

    def test_update_output_is_guarded_before_downloading(self):
        b = self.bundle
        with patch.object(b, "path_problem", return_value="refused"), \
                patch.object(b, "update_command") as updater, \
                patch.object(b, "_force_utf8_io", lambda: None), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(b.main(["--no-pause", "--no-banner", "--update", "--json", "x.json"]), 1)
        updater.assert_not_called()

    def test_phone_bundle_preserves_hits_and_reports_malformed_files(self):
        b = self.bundle
        phone = self.root / "phone"
        phone.mkdir()
        (phone / "packages.json").write_text("{}")
        (phone / "files.json").write_text("null")
        (phone / "logcat.txt").write_text("review.invalid")
        code, doc = self.run_bundle(extra=("--phone", str(phone)))
        self.assertEqual(code, 2)
        self.assertEqual(set(doc["modules"]), {"android", "android-intrusion"})
        self.assertTrue(doc["verdict"]["gaps"])
        self.assertEqual(doc["verdict"]["findings_total"], 1)

    def test_download_accepts_a_relative_local_json_path(self):
        # "--json report.json" is the documented usage and must keep working.
        old = os.getcwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, old)
        code, _document = self.run_bundle(extra=("--json", "report.json"))
        self.assertNotEqual(code, 1)
        self.assertTrue((self.root / "report.json").exists())

    def test_module_failure_preserves_already_observed_hit(self):
        b = self.bundle

        def interrupted(ctx):
            result = b.ModuleResult("browser")
            ctx.partial = result
            result.add_hit(b.Hit("review.invalid", "synthetic", "cookie host",
                                tier="cc", evidence="contacted"))
            raise ValueError("synthetic late failure")

        code, doc = self.run_bundle(interrupted)
        self.assertEqual(code, 2)
        self.assertEqual(doc["verdict"]["hits_total"], 1)
        self.assertEqual(doc["verdict"]["status"], "INDICATORS_FOUND")
        self.assertTrue(any("synthetic late failure" in gap
                            for gap in doc["verdict"]["gaps"]))
        self.assertEqual(doc["modules"]["hash"]["hits"], [])

    def test_real_malformed_connection_state_keeps_hits_and_later_profiles(self):
        first = self.ud / "Default" / "Network"
        later = self.ud / "Profile 1" / "Network"
        chromium_cookie_db(str(first / "Cookies"), host=".review.invalid")
        chromium_cookie_db(str(later / "Cookies"), host=".later.invalid")
        (first / "Network Persistent State").write_text(
            json.dumps({"net": 42}), encoding="utf-8")

        code, doc = self.run_bundle()

        self.assertEqual(code, 2)
        hits = doc["modules"]["browser"]["hits"]
        self.assertEqual({h["indicator"] for h in hits},
                         {"review.invalid", "later.invalid"})
        self.assertTrue(any("connection-records" in gap
                            for gap in doc["verdict"]["gaps"]))

    def test_bundle_reports_the_package_version(self):
        # v0.1.7 shipped a single file that reported "0.1.6" because the version
        # was hardcoded in build/bundle.py and drifted from the package. The
        # bundle now derives it, so the two can never disagree again.
        from zbtriage import __version__ as pkg_version
        self.assertTrue(
            self.bundle.__version__.startswith(pkg_version),
            "bundle reports {!r}, package is {!r}".format(
                self.bundle.__version__, pkg_version))


class TestStixDriverWithdrawal(unittest.TestCase):
    DRIVER = "6a4875ae86131a594019dec4abd46ac6ba47e57a88287b814d07d929858fe3e5"
    INDICATOR_ID = "indicator--80275ed1-64f2-58c7-97dc-9cdacac0ff5d"
    RELATIONSHIP_ID = "relationship--66b188af-2489-5b41-a84f-b90c34f5fc73"

    @classmethod
    def setUpClass(cls):
        cls.emitter = import_file("_release_test_stix", ROOT / "build/emit_stix.py")

    @classmethod
    def tearDownClass(cls):
        sys.modules.pop("_release_test_stix", None)

    def active(self, driver_tier):
        with tempfile.TemporaryDirectory(prefix="stix_fixture_") as tmp:
            path = Path(tmp) / "iocs.txt"
            path.write_text(
                "# as-of: 2026-10-18\n"
                + self.DRIVER + "\t" + driver_tier + "\tsecondary\tavast-2022\n"
                + "a" * 64 + "\tsample\tprimary\ttest\n", encoding="utf-8")
            return self.emitter.build_bundle(iocs.load(str(path)),
                                             datetime.datetime(2026, 10, 18))

    def test_legitimate_driver_is_absent_but_real_sample_remains_active(self):
        for tier in ("vuln-driver", "sample"):
            with self.subTest(tier=tier):
                bundle = self.active(tier)
                indicators = [o for o in bundle["objects"]
                              if o["type"] == "indicator"]
                self.assertEqual([o["name"] for o in indicators], ["a" * 64])
                self.assertNotIn(self.INDICATOR_ID,
                                 {o["id"] for o in bundle["objects"]})
                self.assert_references_resolve(bundle)

    def assert_references_resolve(self, bundle):
        ids = {o["id"] for o in bundle["objects"]}
        for obj in bundle["objects"]:
            for key in ("source_ref", "target_ref", "created_by_ref"):
                if key in obj:
                    self.assertIn(obj[key], ids)

    def test_published_ids_are_permanently_revoked_with_newer_versions(self):
        bundle = self.emitter.withdrawal_bundle()
        revoked = {o["id"]: o for o in bundle["objects"] if o.get("revoked")}
        self.assertEqual(set(revoked), {self.INDICATOR_ID, self.RELATIONSHIP_ID})
        for obj in revoked.values():
            self.assertEqual(obj["created"], "2026-10-18T00:00:00.000Z")
            self.assertGreater(obj["modified"], obj["created"])
        self.assertIn("not spyware", revoked[self.INDICATOR_ID]["description"])
        self.assert_references_resolve(bundle)

    def test_corrected_active_objects_have_new_versions_and_valid_timestamps(self):
        bundle = self.active("vuln-driver")
        for obj in bundle["objects"]:
            self.assertEqual(obj["created"], "2026-10-18T00:00:00.000Z")
            self.assertEqual(obj["modified"], self.emitter.EXPORT_REVISION)
            self.assertGreater(obj["modified"], obj["created"])
            for field in ("created", "modified", "valid_from"):
                if field in obj:
                    datetime.datetime.strptime(obj[field], "%Y-%m-%dT%H:%M:%S.%fZ")

    def test_emitter_writes_separate_deterministic_withdrawal_feed(self):
        with tempfile.TemporaryDirectory(prefix="stix_output_") as tmp:
            out = Path(tmp) / "active.json"
            args = ["--iocs", str(ROOT / "iocs/adfection_iocs.txt"),
                    "--out", str(out)]
            with contextlib.redirect_stdout(io.StringIO()):
                self.emitter.main(args)
                first = out.read_bytes()
                withdrawal_path = out.with_name("adfection.withdrawals.stix.json")
                withdrawn_first = withdrawal_path.read_bytes()
                self.emitter.main(args)
            self.assertEqual(first, out.read_bytes())
            self.assertEqual(withdrawn_first, withdrawal_path.read_bytes())
            self.assertFalse(any(o.get("revoked") for o in json.loads(first)["objects"]))


if __name__ == "__main__":
    unittest.main()
