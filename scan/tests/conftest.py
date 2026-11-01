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
