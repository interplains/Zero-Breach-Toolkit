"""Exploited-vulnerability comparison per release line, and the iPhone's iOS version.

Apple's CVE records list one fixed version per supported release line, all
starting at 0. CVE-2025-43529's record (cvelistV5) gives, for "iOS and iPadOS",
"affected below 18.7.3" and "affected below 26.2". Read as independent cut-offs,
a fully updated 18.7.3 was "below 26.2" and reported out of date.
"""
import hashlib
import json

import pytest

from zbtriage.kevdata import KEV_FILE, KEV_MANIFEST, kev_affected, kev_target_for
from zbtriage.modules.ios import ios_outdated
from zbtriage.result import ModuleResult

IOS = [{"product": "iOS and iPadOS", "version": "0", "lessThan": "18.7.3", "lessThanOrEqual": ""},
       {"product": "iOS and iPadOS", "version": "0", "lessThan": "26.2", "lessThanOrEqual": ""}]
MACOS = [{"product": "macOS", "version": "0", "lessThan": "14.8.3", "lessThanOrEqual": ""},
         {"product": "macOS", "version": "0", "lessThan": "15.7.3", "lessThanOrEqual": ""},
         {"product": "macOS", "version": "0", "lessThan": "26.2", "lessThanOrEqual": ""}]


@pytest.mark.parametrize("version,affected", [
    ("18.7.3", False), ("18.7.4", False), ("18.7.2", True), ("18.0", True),
    ("26.1", True), ("26.2", False), ("26.2.1", False), ("27.0", False),
    ("16.7.10", True),   # an older line that no longer gets this fix
])
def test_ios_release_lines(version, affected):
    assert kev_affected(version, IOS) is affected


@pytest.mark.parametrize("version,affected", [
    ("14.8.3", False), ("14.8.2", True), ("15.7.3", False), ("15.7.2", True),
    ("26.2", False), ("26.0", True), ("13.7.8", True)])
def test_macos_release_lines(version, affected):
    assert kev_affected(version, MACOS) is affected


def test_unlisted_line_between_listed_lines_is_not_compared():
    # CVE-2021-30883's record lists macOS lines 8, 11, 12 and 15; Sonoma (14) was released
    # after the fix and is not listed, so the record cannot say it is affected.
    ranges = [{"product": "macOS", "version": "0", "lessThan": v, "lessThanOrEqual": ""}
              for v in ("12.0", "11.6", "8.1", "15.1")]
    assert kev_affected("14.8.3", ranges) is None
    assert kev_affected("15.0", ranges) is True
    assert kev_affected("15.1", ranges) is False


def test_single_range_unchanged():
    chrome = [{"product": "Chrome", "version": "139.0.7258.66", "lessThan": "139.0.7258.66", "lessThanOrEqual": ""}]
    assert kev_affected("139.0.7258.65", chrome) is True
    assert kev_affected("139.0.7258.66", chrome) is False


def test_ranges_with_real_start_versions_unchanged():
    windows = [{"product": "Windows 11 Version 24H2", "version": "10.0.26100.0", "lessThan": "10.0.26100.4061",
                "lessThanOrEqual": ""},
               {"product": "Windows 10 Version 22H2", "version": "10.0.19045.0", "lessThan": "10.0.19045.5854",
                "lessThanOrEqual": ""}]
    assert kev_affected("10.0.26100.4060", windows) is True
    assert kev_affected("10.0.26100.4061", windows) is False
    assert kev_affected("10.0.19045.5854", windows) is False


def test_ios_target_selection():
    keys = lambda product: sorted(t["key"] for t in kev_target_for({"vendorProject": "Apple", "product": product}))
    assert "ios" in keys("iOS and iPadOS")
    assert "ios" in keys("Multiple Products")
    assert "ios" in keys("WebKit")
    assert "ios" not in keys("macOS")


def write_kev(cache, rows):
    data = json.dumps({"catalogVersion": "2026.11.07", "entries": rows}).encode("utf-8")
    (cache / KEV_FILE).write_bytes(data)
    (cache / KEV_MANIFEST).write_text(hashlib.sha256(data).hexdigest() + "  " + KEV_FILE + "\n")


def test_outdated_iphone_gets_a_lead(tmp_path):
    write_kev(tmp_path, [{"cve": "CVE-2025-43529", "target": "ios", "dateAdded": "2025-12-15", "ranges": IOS},
                         {"cve": "CVE-2025-00001", "target": "macos", "dateAdded": "2025-12-16", "ranges": MACOS}])
    r = ModuleResult("ios")
    ios_outdated(r, "18.6", str(tmp_path))
    assert len(r.leads) == 1
    assert "CVE-2025-43529" in r.leads[0].what and "18.6" in r.leads[0].what
    assert not r.hits and not r.checks


def test_updated_iphone_gets_a_note_only(tmp_path):
    write_kev(tmp_path, [{"cve": "CVE-2025-43529", "target": "ios", "dateAdded": "2025-12-15", "ranges": IOS}])
    r = ModuleResult("ios")
    ios_outdated(r, "18.7.3", str(tmp_path))
    assert not r.leads
    assert any("not older than any fix" in n for n in r.notes)


def test_no_saved_list_says_so(tmp_path):
    r = ModuleResult("ios")
    ios_outdated(r, "18.6", str(tmp_path))
    assert not r.leads
    assert any("not compared" in n for n in r.notes)


def test_altered_list_is_refused(tmp_path):
    write_kev(tmp_path, [{"cve": "CVE-2025-43529", "target": "ios", "dateAdded": "2025-12-15", "ranges": IOS}])
    (tmp_path / KEV_FILE).write_bytes(b'{"entries": []}')
    r = ModuleResult("ios")
    ios_outdated(r, "18.6", str(tmp_path))
    assert not r.leads
    assert any("changed since it was downloaded" in n for n in r.notes)
