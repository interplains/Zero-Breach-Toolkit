"""Tests never use the internet. Any web request a test makes (through the
source package or the single-file build, which both use urllib) fails at once
instead of reaching a real server; local test servers still work."""
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

import pytest

# Lets a single test file run on its own (`pytest scan/tests/test_x.py`) from any folder.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

_REAL_OPEN = urllib.request.OpenerDirector.open


def _offline_open(self, fullurl, *args, **kwargs):
    url = fullurl if isinstance(fullurl, str) else fullurl.get_full_url()
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    if host in ("localhost", "127.0.0.1", "::1"):
        return _REAL_OPEN(self, fullurl, *args, **kwargs)
    raise urllib.error.URLError("network disabled in tests: " + url[:100])


@pytest.fixture(autouse=True)
def _no_internet(monkeypatch):
    monkeypatch.setattr(urllib.request.OpenerDirector, "open", _offline_open)


@pytest.fixture(autouse=True)
def _own_program_folder(monkeypatch, tmp_path_factory):
    """The window's small memory files (first-open question shown, an unfinished iPhone backup) go to a temporary
    folder, never the real user's, and the first-open question is already 'asked' so it never pops up in a test."""
    try:
        from zbtriage import resume
    except ImportError:
        return
    folder = tmp_path_factory.mktemp("program-folder")      # never the test's own folder: some tests need it empty
    flags = str(folder / "window-choices.json")
    step = str(folder / "unfinished-step.json")
    open(flags, "w").write('{"asked-what-happened": true}')
    monkeypatch.setattr(resume, "_flags_path", lambda: flags)
    monkeypatch.setattr(resume, "resume_path", lambda: step)
    from zbtriage import accounts
    answers = str(folder / "account-checklist-answers.json")
    real_load, real_save = accounts.ac_load_answers, accounts.ac_save_answers
    monkeypatch.setattr(accounts, "ac_load_answers", lambda path="": real_load(path or answers))
    monkeypatch.setattr(accounts, "ac_save_answers", lambda a, path="": real_save(a, path or answers))
