"""A locked browser database is a GAP, not a clean result.

This is the pre-launch bug these tests were written for. The old browser module
called `r.ran(...)` the instant a browser folder existed and then only bumped
`r.skipped` when a database was locked. The verdict is built from `r.checks`, so
a browser whose databases were ALL locked - the normal state of a browser that
is currently open - rolled up to CLEAN with no gap. For a journalist who happens
to have Chrome running, that is the tool saying "nothing found" having been
unable to look: exactly the false "all clear" the whole project exists to avoid.

The fix tracks, per (browser, artifact kind), whether any profile could actually
be read, and turns that into a check that ran (clean) or a check that
could_not_run (a gap the verdict surfaces). These tests pin that behaviour:

  - all artifacts locked           -> UNKNOWN, never CLEAN, with gaps
  - one kind readable, one locked  -> PARTIAL, naming the locked kind
  - absent artifacts               -> NOT gaps (nothing to look at is not a gap)
  - one profile OK, one locked     -> the kind ran for the profile that was read,
                                      AND the locked profile is its own named gap
  - the temp copy is always cleaned up, including when the copy itself fails
  - the new Firefox favicons / HSTS artifacts are found and graded contacted

Hermetic: reserved-TLD indicator, every path inside a temp dir, the browser
module's import-time path globals monkeypatched directly (patching os.environ
would be too late). A lock is simulated by making `browser.copy_locked` raise
PermissionError, the same OSError the real lock path raises - no real browser is
needed and nothing on the real machine is touched.
"""

from __future__ import annotations

import glob
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import iocs as iocmod                       # noqa: E402
from zbtriage import report                               # noqa: E402
from zbtriage.context import ScanContext                  # noqa: E402
from zbtriage.modules import browser                      # noqa: E402
from zbtriage.result import CLEAN, HITS, PARTIAL, UNKNOWN  # noqa: E402

TEST_DOMAIN = "synthetic-test-indicator.invalid"


def chromium_cookie_db(path, host="." + TEST_DOMAIN):
    """A minimal but real Chromium-shaped Cookies database."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE cookies (host_key TEXT, name TEXT, "
                "creation_utc INTEGER)")
    con.execute("INSERT INTO cookies VALUES (?, 'sid', 13300000000000000)",
                (host,))
    con.commit()
    con.close()


def chromium_history_db(path, url="https://example.org/ordinary-page"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    con = sqlite3.connect(path)
    con.execute("CREATE TABLE urls (url TEXT, title TEXT)")
    con.execute("INSERT INTO urls VALUES (?, 'a page')", (url,))
    con.commit()
    con.close()


class BrowserLaunchBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="blaunch_")
        self.empty = os.path.join(self.tmp, "empty")
        os.makedirs(self.empty)
        ioc_path = os.path.join(self.tmp, "iocs.txt")
        with open(ioc_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("{}\tdelivery\tprimary\ttest-source\n".format(TEST_DOMAIN))
        self.ctx = ScanContext(iocs=iocmod.load(ioc_path), emit=lambda _m: None)
        self._saved = (browser.CHROMIUM_ROOTS, browser.ROAMING, browser.LOCAL,
                       browser.copy_locked, browser.FIREFOX_ROOTS)
        # No Firefox in these Chromium tests. Pin it to [] so the suite never
        # reads the tester's real Firefox profile (it would on macOS/Linux, where
        # _firefox_roots ignores ROAMING/LOCAL) and so an all-locked Chromium run
        # rolls up to UNKNOWN, not PARTIAL.
        browser.FIREFOX_ROOTS = []

    def tearDown(self):
        (browser.CHROMIUM_ROOTS, browser.ROAMING, browser.LOCAL,
         browser.copy_locked, browser.FIREFOX_ROOTS) = self._saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_chromium(self, root):
        browser.CHROMIUM_ROOTS = [("test", root)]
        browser.ROAMING = self.empty
        browser.LOCAL = self.empty
        return browser.run(self.ctx)

    def lock(self, predicate):
        """Make copy_locked raise PermissionError for paths matching predicate,
        exactly as the real locked-database path does, and copy normally for the
        rest."""
        real = self._saved[3]

        def faux(path):
            if predicate(path):
                raise PermissionError(13, "database is locked")
            return real(path)

        browser.copy_locked = faux


class TestAllLockedIsAGapNotClean(BrowserLaunchBase):
    def test_every_database_locked_rolls_up_to_unknown_with_gaps(self):
        prof = os.path.join(self.tmp, "User Data", "Default")
        chromium_history_db(os.path.join(prof, "History"))
        chromium_cookie_db(os.path.join(prof, "Network", "Cookies"))
        self.lock(lambda p: True)  # nothing can be snapshotted

        r = self.run_chromium(os.path.join(self.tmp, "User Data"))

        self.assertEqual(r.hits, [], "a locked db must not somehow produce a hit")
        self.assertEqual(r.status, UNKNOWN,
                         "a browser whose every database was locked observed "
                         "nothing; that is UNKNOWN, never CLEAN")
        self.assertNotEqual(r.status, CLEAN)
        self.assertTrue(any(not c.ran for c in r.checks),
                        "the locked databases must be recorded as checks that "
                        "could NOT run")
        # And the gap must reach the verdict, which is what the user reads.
        import datetime
        doc = report.build_document(self.ctx.iocs, [r], datetime.datetime.now())
        self.assertTrue(doc["verdict"]["gaps"],
                        "the locked-database gap must surface in the verdict - "
                        "this is the bug: it used to roll up to a clean result")


class TestPartialWhenSomeLocked(BrowserLaunchBase):
    def test_readable_history_and_locked_cookies_is_partial(self):
        prof = os.path.join(self.tmp, "User Data", "Default")
        chromium_history_db(os.path.join(prof, "History"))
        chromium_cookie_db(os.path.join(prof, "Network", "Cookies"))
        self.lock(lambda p: "Cookies" in p)

        r = self.run_chromium(os.path.join(self.tmp, "User Data"))

        self.assertEqual(r.hits, [])
        self.assertEqual(r.status, PARTIAL,
                         "one kind ran clean and one could not run: PARTIAL")
        ran = {c.name for c in r.checks if c.ran}
        gaps = {c.name for c in r.checks if not c.ran}
        self.assertIn("test:history", ran)
        self.assertIn("test:cookies", gaps,
                      "the locked cookie store is the gap")
        self.assertTrue(any("locked" in c.reason.lower()
                            for c in r.checks if not c.ran),
                        "the gap must carry a reason the user can act on")


class TestAbsentArtifactsAreNotGaps(BrowserLaunchBase):
    def test_a_browser_with_only_a_readable_history_has_no_gaps(self):
        prof = os.path.join(self.tmp, "User Data", "Default")
        chromium_history_db(os.path.join(prof, "History"))

        r = self.run_chromium(os.path.join(self.tmp, "User Data"))

        self.assertEqual(r.hits, [])
        self.assertEqual(r.status, CLEAN,
                         "nothing was locked and the one present artifact was "
                         "read; an absent cookie store is not a gap")
        self.assertTrue(all(c.ran for c in r.checks))
        self.assertIn("test:history", [c.name for c in r.checks])
        self.assertNotIn("test:cookies", [c.name for c in r.checks],
                         "a cookie store the browser never created must not be "
                         "reported as a check at all")


class TestOneProfileSucceedsRollsUpToRan(BrowserLaunchBase):
    """A readable profile must not stand in for an unreadable one.

    This originally asserted that a locked profile was "a note, not a gap" as
    long as some OTHER profile of the same browser read fine. A review showed
    that is the D3 violation the rest of this file exists to prevent: the locked
    profile was never searched, so nothing has been cleared for it, yet the scan
    reported no gap at all and a reader saw an unqualified clean sweep. The
    readable profile is now reported as a check that ran AND the locked one as
    its own gap, named with the account so the report can say which was missed.
    """

    def test_a_locked_profile_is_a_gap_even_when_another_profile_reads(self):
        ud = os.path.join(self.tmp, "User Data")
        chromium_cookie_db(os.path.join(ud, "Default", "Network", "Cookies"),
                           host="." + TEST_DOMAIN)
        chromium_cookie_db(os.path.join(ud, "Profile 1", "Network", "Cookies"),
                           host=".example.net")
        # The second profile's cookie store is locked; the first reads fine.
        self.lock(lambda p: "Profile 1" in p)

        r = self.run_chromium(ud)

        # The profile that WAS read is a check that ran.
        self.assertTrue(any(c.name == "test:cookies" and c.ran for c in r.checks))
        # The profile that was NOT read is a gap, named with its account, so the
        # report can never present this scan as full coverage of this browser.
        gaps = [c for c in r.checks
                if not c.ran and c.name.startswith("test:cookies")]
        self.assertTrue(gaps, "the locked profile must surface as its own gap")
        self.assertTrue(any("Profile 1" in c.name for c in gaps),
                        "the gap must name the profile that was not covered")
        self.assertGreaterEqual(r.skipped, 1)
        self.assertTrue(any("locked" in n.lower() for n in r.notes))
        # The readable profile's indicator cookie is still found.
        self.assertEqual(r.status, HITS)
        self.assertTrue(any(h.indicator == TEST_DOMAIN and h.evidence == "contacted"
                            for h in r.hits))


class TestTempCopyIsAlwaysCleanedUp(BrowserLaunchBase):
    def setUp(self):
        super().setUp()
        # A private temp folder: with tests running in parallel, other browser
        # scans create bscan_* folders in the shared one at the same moment.
        private = tempfile.mkdtemp(prefix="zb-bscan-test-")
        self.addCleanup(shutil.rmtree, private, True)
        saved = tempfile.tempdir
        tempfile.tempdir = private
        self.addCleanup(setattr, tempfile, "tempdir", saved)
        # The scanner picks its folder from TMPDIR/TEMP/TMP (localpaths.local_temp_dir).
        env = mock.patch.dict(os.environ, {"TMPDIR": private, "TEMP": private, "TMP": private})
        env.start()
        self.addCleanup(env.stop)

    def _bscan_dirs(self):
        return set(glob.glob(os.path.join(tempfile.gettempdir(), "bscan_*")))

    def test_copy_locked_cleans_its_temp_dir_when_the_copy_fails(self):
        # Point copy_locked at a path that exists but cannot be copied (a
        # directory where a file is expected). It must raise, and it must not
        # leave its own temp dir behind.
        not_a_file = os.path.join(self.tmp, "a-directory")
        os.makedirs(not_a_file)
        before = self._bscan_dirs()
        with self.assertRaises(OSError):
            self._saved[3](not_a_file)   # the real copy_locked
        after = self._bscan_dirs()
        self.assertEqual(before, after,
                         "copy_locked leaked a temp dir on the failure path")

    def test_run_leaves_no_temp_dir_behind_when_a_db_cannot_be_copied(self):
        prof = os.path.join(self.tmp, "User Data", "Default")
        # A real file, but copy_locked is forced to fail on it mid-copy.
        chromium_cookie_db(os.path.join(prof, "Network", "Cookies"))
        self.lock(lambda p: "Cookies" in p)
        before = self._bscan_dirs()
        self.run_chromium(os.path.join(self.tmp, "User Data"))
        after = self._bscan_dirs()
        self.assertEqual(before, after,
                         "a failed snapshot must not leave a temp dir behind")


class FirefoxArtifactBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="bff_")
        self.roaming = os.path.join(self.tmp, "Roaming")
        self.prof = os.path.join(self.roaming, "Mozilla", "Firefox", "Profiles",
                                 "abc123.default-release")
        os.makedirs(self.prof)
        ioc_path = os.path.join(self.tmp, "iocs.txt")
        with open(ioc_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("{}\tdelivery\tprimary\ttest-source\n".format(TEST_DOMAIN))
        self.ctx = ScanContext(iocs=iocmod.load(ioc_path), emit=lambda _m: None)
        self._saved = (browser.CHROMIUM_ROOTS, browser.ROAMING, browser.LOCAL,
                       browser.FIREFOX_ROOTS)
        browser.CHROMIUM_ROOTS = []           # no Chromium browsers at all
        browser.LOCAL = os.path.join(self.tmp, "Local")  # no Firefox cache there
        os.makedirs(browser.LOCAL)
        # Point Firefox straight at the planted profile tree, on every OS - the
        # explicit override is what makes this test hermetic on macOS/Linux too.
        browser.FIREFOX_ROOTS = [(os.path.join(self.roaming, "Mozilla", "Firefox",
                                               "Profiles"), browser.LOCAL)]

    def tearDown(self):
        (browser.CHROMIUM_ROOTS, browser.ROAMING, browser.LOCAL,
         browser.FIREFOX_ROOTS) = self._saved
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestFirefoxFavicons(FirefoxArtifactBase):
    def test_favicon_for_an_indicator_is_contacted(self):
        con = sqlite3.connect(os.path.join(self.prof, "favicons.sqlite"))
        con.execute("CREATE TABLE moz_icons (id INTEGER, icon_url TEXT)")
        con.execute("INSERT INTO moz_icons VALUES (1, ?)",
                    ("https://" + TEST_DOMAIN + "/favicon.ico",))
        con.execute("INSERT INTO moz_icons VALUES (2, 'https://unrelated.example/f.ico')")
        con.commit()
        con.close()

        r = browser.run(self.ctx)

        fav = [h for h in r.hits if h.detail.startswith("favicon")]
        self.assertEqual(len(fav), 1, "the indicator favicon must be found once")
        self.assertEqual(fav[0].indicator, TEST_DOMAIN)
        self.assertEqual(fav[0].evidence, "contacted",
                         "a stored favicon means the browser fetched it from "
                         "that host")
        self.assertIn("firefox:favicons", [c.name for c in r.checks])


class TestFirefoxHsts(FirefoxArtifactBase):
    def test_hsts_entry_for_an_indicator_is_contacted(self):
        # SiteSecurityServiceState.txt keeps hostnames in plaintext, one entry
        # per line, keyed "<host>:HSTS". The value columns are irrelevant to us.
        with open(os.path.join(self.prof, "SiteSecurityServiceState.txt"),
                  "w", encoding="utf-8", newline="\n") as fh:
            fh.write("unrelated.example:HSTS\t0\t17\t18000,1,0\n")
            fh.write("{}:HSTS\t0\t17\t18000,1,0\n".format(TEST_DOMAIN))

        r = browser.run(self.ctx)

        hits = [h for h in r.hits if h.evidence == "contacted"]
        self.assertEqual(len(hits), 1, "the HSTS entry should be one contacted hit")
        self.assertEqual(hits[0].indicator, TEST_DOMAIN)
        self.assertIn("firefox:hsts", [c.name for c in r.checks])
        # No other hostname from the file may reach the output.
        self.assertNotIn("unrelated.example", repr(r.to_dict()))

    def test_hsts_file_with_no_indicator_is_clean_not_a_hit(self):
        with open(os.path.join(self.prof, "SiteSecurityServiceState.txt"),
                  "w", encoding="utf-8", newline="\n") as fh:
            fh.write("unrelated.example:HSTS\t0\t17\t18000,1,0\n")
        r = browser.run(self.ctx)
        self.assertEqual(r.hits, [])
        self.assertIn("firefox:hsts", [c.name for c in r.checks if c.ran])
        self.assertEqual(r.status, CLEAN)


if __name__ == "__main__":
    unittest.main(verbosity=2)
