"""2.0.3: domain boundaries, Linux/macOS startup roots, execution records,
installed-program checks and the file-fingerprint scope note.

Fixture sources:
  * Domain text: percent-encoding is RFC 3986 (``%2e`` is ".", ``%2d`` is "-",
    ``%5f`` is "_"; ``%252e`` is the same escape encoded twice). The matcher's own
    rule is the DNS label rule in iocs.py (_LABEL): a name goes on through letters,
    digits, "-" and "_" and "." followed by another label character.
  * macOS launch items: Apple property lists (``plistlib``). Cron/systemd files:
    crontab(5) and systemd.unit(5).
  * Amcache.hve: Windows registry hive read by winrecords.read_amcache; the reader
    is replaced here by one that yields rows in the shape the real one yields
    (path/name/key, or an error row), because building a hive by hand would only
    test the author's reading of the format.
  * CISA Known Exploited Vulnerabilities catalogue entries: {"cve", "target",
    "dateAdded", "ranges", "ransomware"} as written by kevdata.py.
Synthetic values only.
"""
import os
import plistlib
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import execution, exploited, hashscan, posix


def _iocs(*values):
    return IocSet([Indicator(v, "cc", "primary", "domain", "fixture", "Family") for v in values], "fixture", None)


def _ran(result, name):
    return any(c.ran and c.name == name for c in result.checks)


def _gap(result, name):
    return any((not c.ran) and c.name.startswith(name) for c in result.checks)


# --- Item 8: where a domain match ends ----------------------------------------------------

CONTINUES = ["example.test%2eevil", "example.test%2eevil.test", "example.test%252eevil.test",
             "example.test%2devil.test", "example.test%5fevil", "example.test%252devil", "example.test%255fevil"]
STILL_ENDS = ["https://example.test%2fbeacon", "https%3a%2f%2fexample.test%2fbeacon", "u=example.test%26x=1",
              "example.test%3a443", "example.test%20", "链接example.test点击", "رابطexample.testاضغط",
              "example.testé", "see example.test.", "example.test/path"]
NOT_THIS_NAME = ["example.test.evil.test", "notexample.test", "example.test-evil", "example.test_evil"]


@pytest.mark.parametrize("text", CONTINUES + NOT_THIS_NAME)
def test_a_longer_name_is_not_the_indicator(text):
    ind = _iocs("example.test")
    assert [i.value for i in ind.search(text)] == []
    assert [i.value for i in ind.search_bytes(text.encode("utf-8"))] == []
    # The same text as UTF-16 (Chromium storage and Windows records).
    assert [i.value for i in ind.search_bytes(text.encode("utf-16-le"))] == []


@pytest.mark.parametrize("text", STILL_ENDS)
def test_an_encoded_or_glued_link_still_matches(text):
    ind = _iocs("example.test")
    assert [i.value for i in ind.search(text)] == ["example.test"]
    assert [i.value for i in ind.search_bytes(text.encode("utf-8"))] == ["example.test"]


def test_an_ip_address_is_not_changed_by_the_percent_rule():
    ind = IocSet([Indicator("203.0.113.9", "cc", "primary", "ip", "fixture", "Family")], "fixture", None)
    assert [i.value for i in ind.search("connect 203.0.113.9%2f80")] == ["203.0.113.9"]


# --- Linux/macOS startup roots ---------------------------------------------------------------

def _posix_run(root, kind="plist", check="macos-launch-items"):
    ctx = ScanContext(iocs=_iocs("spy-c2.test"), emit=lambda _m: None)
    with patch.object(posix, "_ux_roots", lambda: [(check, str(root), kind)]):
        return posix.run(ctx)


def test_a_root_whose_every_file_is_unreadable_is_not_a_clean_read(tmp_path):
    (tmp_path / "broken.plist").write_bytes(b"this is not a property list \x00\xff")
    result = _posix_run(tmp_path)
    assert not _ran(result, "macos-launch-items")
    assert _gap(result, "macos-launch-items")


def test_a_root_with_one_readable_file_among_damaged_ones_is_read_with_a_gap(tmp_path):
    (tmp_path / "broken.plist").write_bytes(b"this is not a property list \x00\xff")
    (tmp_path / "good.plist").write_bytes(plistlib.dumps({"Label": "org.example.agent", "ProgramArguments": ["/bin/true"]}))
    result = _posix_run(tmp_path)
    assert _ran(result, "macos-launch-items")
    assert _gap(result, "macos-launch-items")


def test_an_empty_root_and_a_missing_root_are_clean_reads(tmp_path):
    assert _ran(_posix_run(tmp_path), "macos-launch-items")
    assert _ran(_posix_run(tmp_path / "absent"), "macos-launch-items")


# --- Windows execution records ----------------------------------------------------------------

def _amcache_run(tmp_path, rows):
    hive = tmp_path / "Amcache.hve"
    hive.write_bytes(b"regf" + b"\0" * 64)
    ctx = ScanContext(iocs=_iocs("spy-c2.test"), emit=lambda _m: None, targets=(str(hive),))
    with patch.object(execution, "read_amcache", lambda raw: iter(rows)):
        return execution.run(ctx)


def test_an_amcache_with_only_unreadable_records_is_not_a_clean_read(tmp_path):
    result = _amcache_run(tmp_path, [{"error": "Amcache record path missing", "key": "Root\\File\\cell-1"}])
    assert not _ran(result, "windows-amcache")
    assert _gap(result, "windows-amcache")


def test_an_amcache_with_records_is_a_clean_read(tmp_path):
    rows = [{"path": "c:\\fixture\\ordinary.exe", "name": "ordinary.exe",
             "key": "Root\\InventoryApplicationFile\\ordinary", "error": ""}]
    result = _amcache_run(tmp_path, rows)
    assert _ran(result, "windows-amcache")


# --- Installed programs against the exploited-vulnerability list ----------------------------------

def _exploited_run(installed):
    catalogue = {"catalogVersion": "2026.10.30", "downloaded_utc": "2026-10-31",
                 "entries": [{"cve": "CVE-2000-0001", "target": "windows", "dateAdded": "2026-01-01",
                              "ranges": [], "ransomware": False}]}
    with patch.object(exploited, "kev_load", lambda cache: (catalogue, "")), \
            patch.object(exploited, "ex_installed", lambda: installed), \
            patch.object(exploited.sys, "platform", "win32"):
        return exploited.run(ScanContext(iocs=_iocs("spy-c2.test"), emit=lambda _m: None))


def test_no_installed_programs_is_not_a_clean_read():
    result = _exploited_run([])
    assert not _ran(result, exploited.NAME)
    assert _gap(result, exploited.NAME)


def test_listed_programs_are_a_clean_read():
    target = next(t for t in exploited.KEV_TARGETS if t["key"] == "windows")
    result = _exploited_run([(target, "10.0.26100.4061", "Windows 11 Version 24H2")])
    assert _ran(result, exploited.NAME)


# --- Item 6: what the Standard fingerprint check leaves out --------------------------------------

def test_the_standard_fingerprint_check_names_the_file_types_it_skips(tmp_path):
    (tmp_path / "ordinary.dll").write_bytes(b"MZ not a sample")
    ind = IocSet([Indicator("b" * 64, "sample", "primary", "sha256", "fixture", "Family")], "fixture", None)
    ctx = ScanContext(iocs=ind, emit=lambda _m: None)
    with patch.object(hashscan, "_roots", lambda: [str(tmp_path)]):
        result = hashscan.run(ctx)
    notes = [n for n in result.notes if str(tmp_path) in n and "fingerprint" in n.lower()]
    assert notes, result.notes
    assert ".msi" in notes[0] and ".ps1" in notes[0] and "Full check" in notes[0]
    assert ".dll" in notes[0]


def test_the_full_check_has_no_such_note(tmp_path):
    (tmp_path / "ordinary.dll").write_bytes(b"MZ not a sample")
    ind = IocSet([Indicator("b" * 64, "sample", "primary", "sha256", "fixture", "Family")], "fixture", None)
    ctx = ScanContext(iocs=ind, emit=lambda _m: None, full=True)
    with patch.object(hashscan, "_roots", lambda: [str(tmp_path)]):
        result = hashscan.run(ctx)
    assert not [n for n in result.notes if "Full check" in n]


# --- Item 18: one enormous run of name characters and dots must not cost 19x its size ---------------

def test_a_huge_dotted_run_stays_within_a_few_times_its_size():
    import tracemalloc
    data = b"a." * (3 * 1024 * 1024)                       # 6 MB of "a.a.a.a."
    ind = _iocs("spy-c2.test")
    tracemalloc.start()
    try:
        ind.search_bytes(data)
        _current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 8 * len(data), "peak {:.1f}x the input".format(peak / len(data))


def test_the_indicator_is_still_found_at_the_end_of_a_huge_run():
    data = b"a." * (3 * 1024 * 1024) + b"spy-c2.test"
    assert [i.value for i in _iocs("spy-c2.test").search_bytes(data)] == ["spy-c2.test"]
    assert [i.value for i in _iocs("spy-c2.test").search_bytes(b"x" + data)] == ["spy-c2.test"]
