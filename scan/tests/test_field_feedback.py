"""Fixes from field reports and review: macOS privacy refusals are not called
locks, hash gaps say why, aliases are not gaps, folders the hash check could
not open are not counted as files, Opera bookmark roots are read,
reports never replace fingerprinted files, unreadable download-origin records
and Android files without fingerprints are gaps."""
import argparse
import json
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import workflow
from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import android, browser, hashscan, traces
from zbtriage.result import ModuleResult
from test_evidence_safety import _ctx, safety_api  # noqa: F401
from test_followup_fixes import bundle  # noqa: F401

BAD = "bad-c2.example"
DIGEST = "a" * 64


def test_macos_permission_refusal_is_not_called_a_lock(monkeypatch):
    monkeypatch.setattr(browser.sys, "platform", "darwin")
    note = browser._locked_note("/Users/x/Library/Containers/com.apple.Safari/Data/Library/Safari/SafariTabs.db",
                                PermissionError(1, "Operation not permitted"))
    assert "Full Disk Access" in note and "Safari" in note and "was running" not in note


def test_windows_sharing_violation_is_still_a_lock(monkeypatch):
    monkeypatch.setattr(browser.sys, "platform", "win32")
    note = browser._locked_note(r"C:\Users\x\AppData\Local\Google\Chrome\User Data\Default\History",
                                PermissionError(13, "Permission denied"))
    assert "was running" in note


def test_summary_groups_macos_privacy_gaps():
    from zbtriage.report import _gap_lines
    lines = _gap_lines(["browser/safari:safari-tabs: macOS privacy protection blocked Safari (SafariTabs.db), "
                        "so it was not checked. Give Terminal Full Disk Access (System Settings > Privacy & "
                        "Security > Full Disk Access), then run again."])
    assert len(lines) == 1 and lines[0].startswith("macOS privacy protection kept some records") and "Safari" in lines[0]


def test_hash_gap_names_reasons_and_skips_links(tmp_path, monkeypatch):
    big = tmp_path / "big.bin"
    big.write_bytes(b"x")
    ok = tmp_path / "ok.bin"
    ok.write_bytes(b"y")
    try:
        os.symlink(str(ok), str(tmp_path / "alias.bin"))
        has_link = True
    except (OSError, NotImplementedError):
        has_link = False
    monkeypatch.setattr(hashscan, "MAX_BYTES", 0)  # every real file is "over the limit"
    ctx = ScanContext(IocSet([Indicator(DIGEST, "s", "primary", "sha256", "t")], "t", None),
                      targets=[str(tmp_path)], emit=lambda _: None)
    r = hashscan.run(ctx)
    gap = [c.reason for c in r.checks if not c.ran][0]
    assert "over 0 MB" in gap and "candidate file(s)" in gap
    assert "2 candidate" in gap  # the alias is not counted as a missed file
    if has_link:
        assert r.submetrics.get("links_not_followed") == 1


def _walk_refusing(names, real_walk):
    """walk_local that first reports each named folder as refused by macOS."""
    def walk(root, onerror=None):
        for name in names:
            onerror(PermissionError(1, "Operation not permitted", os.path.join(root, name)))
        yield from real_walk(root, onerror=onerror)
    return walk


def _hash_gap(tmp_path):
    ctx = ScanContext(IocSet([Indicator(DIGEST, "s", "primary", "sha256", "t")], "t", None),
                      targets=[str(tmp_path)], emit=lambda _: None)
    r = hashscan.run(ctx)
    return r, [c.reason for c in r.checks if not c.ran]


def test_unopened_folders_are_not_counted_as_candidate_files(tmp_path, monkeypatch):
    # A refused folder is not a candidate file. Adding it to the file tally made
    # one readable file and three refused folders report "3 of 1 candidate file(s)".
    (tmp_path / "ok.bin").write_bytes(b"y")
    monkeypatch.setattr(hashscan, "walk_local",
                        _walk_refusing(("Photos", "Mail", "Music"), hashscan.walk_local))
    r, gaps = _hash_gap(tmp_path)
    assert r.checked == 1 and len(gaps) == 1
    assert "candidate file(s)" not in gaps[0]
    assert "3 folder(s) or item(s)" in gaps[0]


def test_unopened_folders_and_unread_files_are_counted_apart(tmp_path, monkeypatch):
    (tmp_path / "ok.bin").write_bytes(b"y")
    (tmp_path / "locked.bin").write_bytes(b"z")
    real_hash = hashscan._sha256
    def locked(full):
        if full.endswith("locked.bin"):
            raise PermissionError(13, "locked")
        return real_hash(full)
    monkeypatch.setattr(hashscan, "_sha256", locked)
    monkeypatch.setattr(hashscan, "walk_local",
                        _walk_refusing(("Photos", "Mail"), hashscan.walk_local))
    r, gaps = _hash_gap(tmp_path)
    assert len(gaps) == 1
    assert "1 of 2 candidate file(s)" in gaps[0] and "2 folder(s) or item(s)" in gaps[0]


def test_root_of_only_unopened_folders_does_not_claim_candidate_files(tmp_path, monkeypatch):
    monkeypatch.setattr(hashscan, "walk_local",
                        _walk_refusing(("Photos", "Mail"), hashscan.walk_local))
    r, gaps = _hash_gap(tmp_path)
    assert r.checked == 0 and len(gaps) == 1
    assert "candidate file(s)" not in gaps[0] and "2 folder(s) or item(s)" in gaps[0]


def test_summary_counts_unopened_folders_apart_from_program_files():
    from zbtriage.report import _gap_lines
    lines = _gap_lines([
        "hash/root:/Users/x/Downloads (partial): 1 of 47 candidate file(s) under this root were "
        "not compared against the known hashes (1 over 120 MB); 12 folder(s) or item(s) under "
        "this root could not be opened, so nothing in them was compared (12 permission denied)",
        "hash/root:/Users/x/Documents: 3 folder(s) or item(s) under this root could not be "
        "opened, so nothing in them was compared (3 permission denied)",
    ])
    assert any(line.startswith("1 program file(s)") for line in lines), lines
    assert any(line.startswith("15 folder(s)") for line in lines), lines
    assert not any("13 program" in line or "16 folder" in line for line in lines), lines


def test_permission_denied_is_named_with_the_macos_fix(monkeypatch):
    monkeypatch.setattr(hashscan.sys, "platform", "darwin")
    text = hashscan._hs_reasons({"denied": 3, "large": 1, "unreadable": 0})
    assert "3 permission denied" in text and "1 over" in text and "Full Disk Access" in text


def test_opera_custom_root_bookmarks_are_read(tmp_path, monkeypatch, safety_api):
    user_data = tmp_path / "Opera Stable"
    profile = user_data / "Default"
    profile.mkdir(parents=True)
    (profile / "Bookmarks").write_text(json.dumps({"roots": {
        "bookmark_bar": {"type": "folder", "children": []},
        "custom_root": {"speedDial": {"type": "folder", "children": [
            {"type": "url", "url": "https://" + BAD + "/dial"}]},
            "trash": {"type": "folder", "children": []}}}}))
    api = safety_api.browser
    monkeypatch.setattr(api, "CHROMIUM_ROOTS", [("opera", str(user_data))])
    monkeypatch.setattr(api, "_DEFAULT_CHROMIUM_ROOTS", [("opera", str(user_data))])
    monkeypatch.setattr(api, "FIREFOX_ROOTS", [])
    monkeypatch.setattr(api, "APP_ROOTS", [])
    monkeypatch.setattr(api, "_browser_safari_roots", lambda: [])
    ctx = _ctx()
    ctx.iocs = IocSet([Indicator(BAD, "infrastructure", "primary", "domain", "fixture")], "fixture", None)
    result = safety_api.browser_run(ctx)
    assert any(h.indicator == BAD for h in result.hits)
    assert not any(not c.ran and "bookmarks" in c.name for c in result.checks)


def _guard_args(path):
    return argparse.Namespace(iocs=[], target=[], evidence_file=[], pattern_path=[], collect_android=None,
                              phone=None, json=str(path), share_json=None, report=None)


def test_report_cannot_replace_a_file_the_hash_check_reads(tmp_path, monkeypatch):
    evidence = tmp_path / "Downloads" / "evidence.bin"
    evidence.parent.mkdir()
    evidence.write_bytes(b"MZ evidence")
    monkeypatch.setattr(hashscan, "_roots", lambda: [str(evidence.parent)])
    monkeypatch.setattr(browser, "_app_bases", lambda: [])
    monkeypatch.setattr(browser, "_app_cache_bases", lambda: [])
    with pytest.raises(ValueError, match="new filename"):
        workflow.workflow_output_guard(_guard_args(evidence), str(evidence))
    assert evidence.read_bytes() == b"MZ evidence"


@pytest.mark.parametrize("content", [
    json.dumps({"schema_version": "1.6", "tool": {"name": "zero-breach-toolkit"}}).encode(),
    b'{ "schema_version" "zero-breach-example" THIS IS NOT VALID JSON',
    b"Zero Breach Toolkit 0.1.2 - spyware indicator check",
])
def test_no_existing_file_in_a_hashed_folder_is_replaced_whatever_it_contains(tmp_path, monkeypatch, content):
    target = tmp_path / "Downloads" / "report.json"
    target.parent.mkdir()
    target.write_bytes(content)
    monkeypatch.setattr(hashscan, "_roots", lambda: [str(target.parent)])
    monkeypatch.setattr(browser, "_app_bases", lambda: [])
    monkeypatch.setattr(browser, "_app_cache_bases", lambda: [])
    with pytest.raises(ValueError, match="new filename"):
        workflow.workflow_output_guard(_guard_args(target), str(target))
    assert target.read_bytes() == content


def test_a_new_report_in_a_hashed_folder_is_allowed(tmp_path, monkeypatch):
    folder = tmp_path / "Downloads"
    folder.mkdir()
    monkeypatch.setattr(hashscan, "_roots", lambda: [str(folder)])
    monkeypatch.setattr(browser, "_app_bases", lambda: [])
    monkeypatch.setattr(browser, "_app_cache_bases", lambda: [])
    workflow.workflow_output_guard(_guard_args(folder / "new.json"), str(folder / "new.json"))


def _motw(tmp_path, read_zone):
    ctx = ScanContext(IocSet([Indicator(BAD, "cc", "primary", "domain", "t")], "t", None), emit=lambda _: None)
    r = ModuleResult("traces")
    with patch.object(traces, "_tr_motw_roots", lambda: [str(tmp_path)]), \
            patch.object(traces, "_tr_read_zone", read_zone):
        traces._tr_check_motw(r, ctx)
    return r


def test_unreadable_download_origin_is_a_gap(tmp_path):
    (tmp_path / "a.exe").write_bytes(b"x")
    r = _motw(tmp_path, lambda p: {"_unreadable": "1"})
    assert any(c.name == "mark-of-the-web: unreadable" and not c.ran for c in r.checks)


def test_permission_error_reading_the_stream_is_unreadable_not_absent(tmp_path, monkeypatch):
    real_open = open

    def fake_open(path, *a, **k):
        if str(path).endswith(":Zone.Identifier"):
            raise PermissionError(13, "denied")
        return real_open(path, *a, **k)

    monkeypatch.setattr("builtins.open", fake_open)
    assert traces._tr_read_zone(str(tmp_path / "f.exe")) == {"_unreadable": "1"}


def test_folders_below_the_depth_limit_are_a_gap(tmp_path):
    deep = tmp_path
    for n in range(traces._TR_MAX_DEPTH + 2):
        deep = deep / ("d%d" % n)
    deep.mkdir(parents=True)
    (deep / "payload.exe").write_bytes(b"x")
    r = _motw(tmp_path, lambda p: {"hosturl": "https://" + BAD + "/x"})
    assert any(c.name == "mark-of-the-web: deep folders" and not c.ran for c in r.checks)
    assert not any(h.indicator == BAD for h in r.hits)


@pytest.mark.parametrize("records,expected", [
    ([{"path": "/data/a", "sha256": DIGEST}], True),
    ([{"path": "/data/a"}], False),
    ([{"path": "/data/a", "sha256": "not-a-hash"}], False),
])
def test_android_file_fingerprint_coverage_is_reported(tmp_path, records, expected):
    (tmp_path / "files.json").write_text(json.dumps(records))
    ctx = ScanContext(IocSet([Indicator(DIGEST, "s", "primary", "sha256", "t")], "t", None), emit=lambda _: None)
    r = ModuleResult("android")
    android._an_files(r, ctx, str(tmp_path))
    assert any(c.name == "android:files" and c.ran for c in r.checks)
    hashes = [c for c in r.checks if c.name == "android:file-hashes"]
    assert hashes and hashes[0].ran is expected


def test_invisible_characters_are_removed_from_report_and_handoff_text():
    from zbtriage import contract, report
    hidden = "\u200b\u200d\u2060fearevolve.com\u200b\u200d\u2060\ufeff\u00ad\u200e"
    for clean in (report._safe_text(hidden), contract.sanitize_untrusted(hidden)):
        assert clean == "fearevolve.com"
    persian = "می\u200cخواهم"
    assert report._safe_text(persian) == persian.replace("\u200c", "")
    assert "�" in report._safe_text("a\x1b[31mb\u202ec")
