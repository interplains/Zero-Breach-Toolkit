"""The time-window statement must be true, because users act on it.

An earlier version printed "windows DO NOT OVERLAP" whenever the oldest evidence
post-dated the campaign's START — which is false whenever evidence begins inside
the campaign. The reference machine's Chrome cookie store reached back to
2024-11-18, inside 2024-2025, so it printed exactly that false statement. These
tests pin all three cases and prove the cookie window is actually measured.
"""

from __future__ import annotations

import datetime
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import iocs as iocmod  # noqa: E402
from zbtriage import report  # noqa: E402
from zbtriage.context import ScanContext  # noqa: E402
from zbtriage.modules import browser  # noqa: E402
from zbtriage.modules import host
from zbtriage.result import ModuleResult


class TestOverlapStatement(unittest.TestCase):
    def text(self, d):
        return " ".join(" ".join(report.overlap_statement(d, "browser/cookies")).split())

    def test_evidence_after_campaign_end_says_no_overlap(self):
        t = self.text(datetime.date(2026, 6, 21))
        self.assertIn("DO NOT OVERLAP", t)

    def test_evidence_starting_inside_campaign_is_partial_not_none(self):
        t = self.text(datetime.date(2024, 11, 18))
        self.assertNotIn("DO NOT OVERLAP", t,
                         "evidence from inside 2024-2025 must not be reported as "
                         "having no overlap with it")
        self.assertIn("PART of the AdFection campaign period", t)
        self.assertIn("browser/cookies", t, "must name which record reached back")

    def test_evidence_before_campaign_still_hedged(self):
        t = self.text(datetime.date(2023, 5, 1))
        self.assertNotIn("DO NOT OVERLAP", t)
        self.assertIn("never everything", t,
                      "even full-window coverage is survivorship, not a full record")

    def test_boundary_days(self):
        self.assertIn("DO NOT OVERLAP", self.text(datetime.date(2026, 1, 1)))
        self.assertNotIn("DO NOT OVERLAP", self.text(datetime.date(2025, 12, 31)))

    def test_all_windows_are_scoped_to_reported_evidence(self):
        for date in (datetime.date(2023, 1, 1), datetime.date(2024, 6, 1),
                     datetime.date(2026, 1, 1)):
            with self.subTest(date=date):
                text = self.text(date)
                self.assertIn('reported by this scan', text)
                self.assertIn('browser/cookies', text)
                self.assertIn('cannot rule out past contact', text)
                self.assertNotIn('on this machine', text)
                self.assertNotIn('is gone', text)
                self.assertNotIn('spans the whole window', text)


class TestReachScope(unittest.TestCase):
    def render(self, reach, gaps=()):
        result = {'modules': {'host': {'reach': reach}}, 'verdict': {'gaps': list(gaps)}}
        lines = []
        report._render_reach(lines.append, result)
        return ' '.join(' '.join(lines).split())

    def test_unread_older_dns_records_do_not_become_absence_claim(self):
        text = self.render({'dns-log': {'earliest': '2026-01-01',
            'basis': 'oldest of 50,000 DNS events read (cap 50,000)',
            'note': 'Older retained events were not read.'}}, ['host/dns-log-older-events'])
        self.assertIn('reported by this scan', text)
        self.assertIn('Older or unread records may still exist', text)
        self.assertNotIn('this machine holds no', text)
        self.assertNotIn('oldest evidence of any kind', text)

    def test_cache_dates_do_not_claim_nothing_else_exists(self):
        for older in (False, True):
            reach = {'cache': {'earliest': '2026-01-01', 'by_year': {2026: 2}}}
            if older:
                reach['cookies'] = {'earliest': '2024-06-01'}
            with self.subTest(older=older):
                text = self.render(reach)
                self.assertNotIn('NOTHING on this machine', text)
                if older:
                    self.assertIn('No browser CACHE file examined', text)
                else:
                    self.assertIn('No dated evidence summarised here', text)

    def test_unknown_date_is_not_reported_as_nothing_recorded(self):
        text = self.render({'dns-log': {'earliest': None, 'basis': 'log could not be read'}})
        self.assertIn('unknown (no date established)', text)
        self.assertNotIn('nothing recorded', text)

    def test_unreadable_log_metadata_does_not_claim_history_never_existed(self):
        result = ModuleResult('host')
        with patch.object(host, '_ps_json', return_value=([], 'fixture access denied')):
            host._check_dns_log(result, ScanContext(iocs=None, emit=lambda _: None))
        text = self.render(result.reach)
        self.assertIn('metadata could not be read', text)
        self.assertIn('unread records may still exist', text)
        self.assertNotIn('Nothing was ever recorded', text)
        self.assertNotIn('no DNS history exists', text)


class TestCookieWindowMeasured(unittest.TestCase):
    """A real Chromium-shaped cookie DB with a known oldest creation time."""

    def test_browser_reports_oldest_cookie(self):
        tmp = tempfile.mkdtemp(prefix="reach_")
        root = os.path.join(tmp, "User Data")
        net = os.path.join(root, "Default", "Network")
        os.makedirs(net)
        # 2024-11-18 in Chromium time: microseconds since 1601-01-01.
        target = datetime.datetime(2024, 11, 18, 12, 0, 0)
        us = int((target - datetime.datetime(1601, 1, 1)).total_seconds() * 1e6)
        con = sqlite3.connect(os.path.join(net, "Cookies"))
        con.execute("CREATE TABLE cookies (host_key TEXT, name TEXT, creation_utc INTEGER)")
        con.execute("INSERT INTO cookies VALUES ('.example.org', 'a', ?)", (us,))
        con.execute("INSERT INTO cookies VALUES ('.example.net', 'b', ?)", (us + 10**12,))
        con.commit()
        con.close()

        ioc_path = os.path.join(tmp, "iocs.txt")
        with open(ioc_path, "w", encoding="utf-8") as fh:
            fh.write("synthetic-test-indicator.invalid\tdelivery\tprimary\n")
        ctx = ScanContext(iocs=iocmod.load(ioc_path), emit=lambda _m: None)

        saved = (browser.CHROMIUM_ROOTS, browser.ROAMING, browser.LOCAL,
                 browser.FIREFOX_ROOTS)
        empty = os.path.join(tmp, "empty")
        os.makedirs(empty)
        try:
            browser.CHROMIUM_ROOTS = [("test", root)]
            browser.ROAMING = empty
            browser.LOCAL = empty
            browser.FIREFOX_ROOTS = []
            r = browser.run(ctx)
        finally:
            (browser.CHROMIUM_ROOTS, browser.ROAMING, browser.LOCAL,
             browser.FIREFOX_ROOTS) = saved

        self.assertIn("cookies", r.reach,
                      "the cookie store reaches furthest back; omitting it "
                      "understates what the scan can see")
        self.assertEqual(r.reach["cookies"]["earliest"][:10], "2024-11-18")


if __name__ == "__main__":
    unittest.main(verbosity=2)
