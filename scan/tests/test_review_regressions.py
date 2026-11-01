"""Regressions for coverage-honesty and grading bugs.

Each test below corresponds to a confirmed defect where the scanner told the
reader something stronger than the evidence supported. They are grouped here,
rather than spread across the suite, because they share one root cause: a
failure that was counted as a success, or an artifact whose meaning was assumed
instead of established.

  - a root where nothing could be fingerprinted was reported as a clean check
  - a malformed artifact late in a walk destroyed the hits already collected
  - a domain sitting in STORED PAGE CONTENT was graded as proof of contact
  - a legitimate signed driver this actor abuses was reported as spyware

Hermetic: reserved-TLD indicators, every path inside a temp dir, module-level
path globals monkeypatched directly. Nothing on the real machine is read.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_HERE))   # scan/
sys.path.insert(0, _HERE)                    # the tests dir, for the shared harness

from zbtriage import iocs as iocmod                        # noqa: E402
from zbtriage import report                                # noqa: E402
from zbtriage.context import ScanContext                   # noqa: E402
from zbtriage.modules import browser, hashscan             # noqa: E402
from zbtriage.result import (CLEAN, EV_CONTACTED,          # noqa: E402
                               EV_ON_DISK, EV_REFERENCED)

from test_browser_launch import (BrowserLaunchBase,          # noqa: E402
                                 TEST_DOMAIN, chromium_cookie_db)

# A syntactically valid SHA-256 that matches nothing real.
FAKE_HASH = "a" * 64


class TestHashRootThatCouldNotBeRead(unittest.TestCase):
    """A root whose files all fail to open has not been searched.

    The module used to call r.ran("root:...") BEFORE walking, so a root where
    every candidate file was locked still counted as a check that completed.
    Nothing was fingerprinted, nothing was reported, and the scan came out
    CLEAN with no gap - a clean bill of health for a search that never happened.
    """

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="hashreg_")
        ioc_path = os.path.join(self.tmp, "iocs.txt")
        with open(ioc_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("{}\tsample\tprimary\ttest-source\n".format(FAKE_HASH))
        self.ctx = ScanContext(iocs=iocmod.load(ioc_path), emit=lambda _m: None)
        self.root = os.path.join(self.tmp, "target")
        os.makedirs(self.root)
        with open(os.path.join(self.root, "thing.dll"), "wb") as fh:
            fh.write(b"content")
        self._saved = (hashscan._roots, hashscan._sha256)
        hashscan._roots = lambda: [self.root]

    def tearDown(self):
        hashscan._roots, hashscan._sha256 = self._saved
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_root_where_every_file_is_unreadable_is_a_gap_not_clean(self):
        def unreadable(_full, *_rest):
            raise PermissionError(13, "in use by another process")

        hashscan._sha256 = unreadable

        r = hashscan.run(self.ctx)

        self.assertNotEqual(r.status, CLEAN,
                            "nothing was fingerprinted, so nothing is cleared")
        gaps = [c for c in r.checks if not c.ran]
        self.assertTrue(gaps, "an unsearchable root must surface as a gap")
        self.assertTrue(any(self.root in c.name for c in gaps),
                        "the gap must name the root that was not searched")

    def test_a_root_that_walks_cleanly_with_nothing_to_hash_still_ran(self):
        # The opposite error: an empty root really was covered, and must not be
        # reported as a gap or the report fills with noise people learn to skip.
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        hashscan._roots = lambda: [empty]

        r = hashscan.run(self.ctx)

        self.assertTrue(any(c.name == "root:" + empty and c.ran
                            for c in r.checks))


class TestAMalformedArtifactDoesNotDestroyFindings(BrowserLaunchBase):
    """One bad file must not erase evidence already collected.

    A TransportSecurity file whose "sts" key held a number rather than a list
    made len() raise TypeError. That escaped the artifact's own handler, left
    the module entirely, and the CLI replaced the whole result with an empty
    one - throwing away a matching cookie that had already been read. The
    malformed file is a gap for that artifact and nothing more.
    """

    def test_a_cookie_hit_survives_a_malformed_transport_security_file(self):
        ud = os.path.join(self.tmp, "User Data")
        prof = os.path.join(ud, "Default")
        chromium_cookie_db(os.path.join(prof, "Network", "Cookies"),
                           host="." + TEST_DOMAIN)
        net = os.path.join(prof, "Network")
        os.makedirs(net, exist_ok=True)
        with open(os.path.join(net, "TransportSecurity"), "w",
                  encoding="utf-8") as fh:
            fh.write('{"sts": 42}')

        r = self.run_chromium(ud)

        self.assertTrue(
            any(h.indicator == TEST_DOMAIN for h in r.hits),
            "the cookie hit read before the malformed file must survive it")
        self.assertTrue([c for c in r.checks if not c.ran],
                        "the unreadable artifact is still reported as a gap")


class TestStorageContentIsNotProofOfContact(BrowserLaunchBase):
    """Local Storage is keyed by origin, but it also holds page CONTENT.

    The whole file was byte-searched and every match graded `contacted`, so an
    article about this campaign saved into storage read as "this device
    demonstrably communicated with it" - a false alarm aimed squarely at the
    people this tool is for, who are the ones reading about the campaign.
    """

    def _leveldb(self, ud, payload):
        d = os.path.join(ud, "Default", "Local Storage", "leveldb")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "000003.log"), "wb") as fh:
            fh.write(payload)

    def test_an_indicator_in_stored_content_is_only_referenced(self):
        ud = os.path.join(self.tmp, "User Data")
        self._leveldb(ud, ("a saved news article mentioning "
                           + TEST_DOMAIN).encode("utf-8"))

        r = self.run_chromium(ud)

        hits = [h for h in r.hits if h.indicator == TEST_DOMAIN]
        self.assertTrue(hits, "the match itself is still reported")
        for h in hits:
            self.assertEqual(h.evidence, EV_REFERENCED,
                             "content is not contact")

    def test_origin_looking_raw_bytes_do_not_prove_contact(self):
        # An arbitrary saved value can imitate an origin key exactly.
        ud = os.path.join(self.tmp, "User Data")
        self._leveldb(ud, b"_https://" + TEST_DOMAIN.encode("utf-8")
                      + b"\x00\x01token")

        r = self.run_chromium(ud)

        hits = [h for h in r.hits if h.indicator == TEST_DOMAIN]
        self.assertTrue(hits)
        self.assertTrue(all(h.evidence == EV_REFERENCED for h in hits))


class TestAbusedLegitimateSoftwareIsNotCalledSpyware(unittest.TestCase):
    """The second shipped hash is a legitimate signed driver, not spyware.

    It identifies HW.sys / HW64.sys, signed by Marvin Test Solutions, which this
    actor loads to disable protections. It is installed for honest reasons on
    machines that use that hardware. Shipped as tier `sample` it produced "A
    KNOWN SPYWARE FILE IS ON THIS MACHINE" and the word "conclusive" - telling
    an innocent owner they were infected, the worst failure this tool can have.
    """

    def test_a_vuln_driver_on_disk_is_not_announced_as_spyware(self):
        hit = {"tier": "vuln-driver", "evidence": EV_ON_DISK}
        headline = report._headline_for(hit)
        gloss = report._evidence_gloss(hit)

        self.assertNotIn("SPYWARE", headline.upper())
        self.assertNotIn("conclusive", gloss.lower())
        self.assertIn("not spyware", gloss.lower())

    def test_a_real_sample_on_disk_is_still_announced_plainly(self):
        # The fix must not soften the case it was built for.
        hit = {"tier": "sample", "evidence": EV_ON_DISK}

        self.assertIn("SPYWARE", report._headline_for(hit).upper())
        self.assertIn("conclusive", report._evidence_gloss(hit).lower())

    def test_the_shipped_driver_hash_is_tiered_apart_from_samples(self):
        path = os.path.join(os.path.dirname(_HERE), "..", "iocs",
                            "adfection_iocs.txt")
        path = os.path.abspath(path)
        if not os.path.exists(path):          # not present in a packaged build
            self.skipTest("indicator file not present")
        loaded = iocmod.load(path)
        driver = loaded.lookup(
            "6a4875ae86131a594019dec4abd46ac6ba47e57a88287b814d07d929858fe3e5")
        self.assertIsNotNone(driver, "the driver hash is still shipped")
        self.assertEqual(driver.tier, "vuln-driver",
                         "a legitimate abused driver must never be tier=sample")


if __name__ == "__main__":
    unittest.main()
