"""2.0.6 batch: findings from testing 2.0.5 on a real Mac (issue #37)."""
import os
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from zbtriage.modules import patternscan as patterns
from zbtriage.result import UNKNOWN

from test_evidence_safety import _ctx, safety_api  # noqa: F401
from test_followup_fixes import bundle  # noqa: F401
from test_safari_stores import _run, _safari


def _pattern_ctx(tmp_path):
    return SimpleNamespace(pattern_paths=(str(tmp_path),), emit=lambda *a: None, partial=None)


@pytest.mark.parametrize("code", [-9, 137, -6])
def test_a_crashing_pattern_engine_skips_the_check_instead_of_killing_the_scan(tmp_path, code):
    """yara-x killed Apple's Python 3.9 with no message; the trial run must catch it."""
    crashed = SimpleNamespace(returncode=code, stdout="", stderr="")
    with patch.object(patterns._pattern_sys, "version_info", (3, 9)), \
            patch.object(subprocess, "run", return_value=crashed), \
            patch.object(patterns._pattern_importlib, "import_module") as imported:
        result = patterns.run(_pattern_ctx(tmp_path))
    assert result.status == UNKNOWN
    text = " ".join(result.notes)
    assert "crashed during a one-line test scan" in text and "rest of the scan is unaffected" in text
    imported.assert_not_called()  # yara-x is never loaded into the scan's own process


def test_a_failing_pattern_engine_says_why(tmp_path):
    failed = SimpleNamespace(returncode=1, stdout="", stderr="Traceback...\nRuntimeError: boom")
    with patch.object(patterns._pattern_sys, "version_info", (3, 9)), \
            patch.object(subprocess, "run", return_value=failed):
        result = patterns.run(_pattern_ctx(tmp_path))
    assert result.status == UNKNOWN and "RuntimeError: boom" in " ".join(result.notes)


def test_a_hanging_pattern_engine_is_skipped(tmp_path):
    with patch.object(patterns._pattern_sys, "version_info", (3, 9)), \
            patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired("python", 60)):
        result = patterns.run(_pattern_ctx(tmp_path))
    assert result.status == UNKNOWN and "within 60 seconds" in " ".join(result.notes)


def test_a_missing_pattern_engine_keeps_the_usual_message(tmp_path):
    missing = SimpleNamespace(returncode=1, stdout="", stderr="ModuleNotFoundError: No module named 'yara_x'")
    with patch.object(patterns._pattern_sys, "version_info", (3, 9)), \
            patch.object(subprocess, "run", return_value=missing), \
            patch.object(patterns._pattern_importlib, "import_module",
                         side_effect=ModuleNotFoundError("No module named 'yara_x'")):
        result = patterns.run(_pattern_ctx(tmp_path))
    assert result.status == UNKNOWN and "optional pinned yara-x" in " ".join(result.notes)


def test_the_trial_run_starts_in_an_empty_folder_and_is_cleaned_up(tmp_path):
    seen = {}

    def fake_run(cmd, **kw):
        seen["cwd"] = kw["cwd"]
        seen["listing"] = os.listdir(kw["cwd"])
        return SimpleNamespace(returncode=0, stdout="probe-ok\n", stderr="")

    with patch.object(subprocess, "run", side_effect=fake_run):
        patterns._pattern_probe()
    assert seen["listing"] == [] and not os.path.exists(seen["cwd"])


def test_the_packaged_program_skips_the_trial_run():
    with patch.object(patterns._pattern_sys, "frozen", True, create=True), \
            patch.object(subprocess, "run") as ran:
        patterns._pattern_probe()
    ran.assert_not_called()


def test_a_refused_safari_cookie_file_explains_full_disk_access(tmp_path, monkeypatch, safety_api):
    """macOS refused Cookies.binarycookies and the report printed a raw errno."""
    root = _safari(tmp_path)
    api = safety_api.browser
    real = api._browser_read_small

    def refuse(path, *a, **kw):
        if path.endswith("Cookies.binarycookies"):
            raise PermissionError(1, "Operation not permitted", path)
        return real(path, *a, **kw)

    monkeypatch.setattr(api, "_browser_read_small", refuse)
    monkeypatch.setattr(api.sys, "platform", "darwin")
    result = _run(safety_api, monkeypatch, root)
    gaps = [c for c in result.checks if not c.ran and "safari-cookies" in c.name]
    assert gaps, [c.name for c in result.checks]
    reason = " ".join(str(c.reason) for c in gaps)
    assert "Full Disk Access" in reason and "Errno" not in reason, reason


def test_a_damaged_safari_cookie_file_is_still_called_damaged(tmp_path, monkeypatch, safety_api):
    root = _safari(tmp_path)
    cookies = tmp_path / "Library" / "Containers" / "com.apple.Safari" / "Data" / "Library" / "Cookies" / "Cookies.binarycookies"
    cookies.write_bytes(cookies.read_bytes()[:40])
    result = _run(safety_api, monkeypatch, root)
    reason = " ".join(str(c.reason) for c in result.checks if not c.ran and "safari-cookies" in c.name)
    assert "unreadable or unsupported" in reason and "Full Disk Access" not in reason


def test_a_refused_bookmark_file_explains_itself(monkeypatch):
    from zbtriage.modules import browser
    monkeypatch.setattr(browser.sys, "platform", "darwin")
    note = browser._locked_note("/Users/x/Library/Application Support/Google/Chrome/Default/Bookmarks",
                                PermissionError(1, "Operation not permitted"))
    assert "Full Disk Access" in note and "PermissionError" not in note
