"""An ad-blocker's own copy of a filter list holds indicator domains in order to
block them. Finding them there is protection, not contact, so it must never be a
finding; ordinary cached pages that mention an indicator still are."""
import os
import struct
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_evidence_safety import _ctx, _history, safety_api  # noqa: F401
from test_followup_fixes import bundle  # noqa: F401

UBO = "chrome-extension://cjpalhdlnbpafiamejdnhcphjbkeiagm"
LIST_BODY = b"! Title: test list\n||fixture.invalid^\n||second.invalid^\n"


def _simple_cache_entry(key, body):
    """A Chromium simple-cache entry: magic, version, key length, key hash, pad, key, body."""
    key = key.encode("latin-1")
    header = struct.pack("<QIII", 0xfcfb6d1ba7725c30, 5, len(key), 0) + b"\0" * 4
    return header + key + body


def _firefox_cache_entry(key, body):
    """A Firefox cache2 entry: body, then metadata holding the key, then its offset."""
    meta = b"\0" * 6 + struct.pack(">IIIIIIII", 3, 1, 0, 0, 0, 0, len(key), 0)
    meta += key.encode("latin-1") + b"\0" + b"request-method\0GET\0"
    return body + meta + struct.pack(">I", len(body))


def _chrome(tmp_path, monkeypatch, api):
    root = tmp_path / "chrome"
    _history(root / "Default", "ordinary.invalid")
    monkeypatch.setattr(api, "CHROMIUM_ROOTS", [("chrome", str(root))])
    monkeypatch.setattr(api, "FIREFOX_ROOTS", [])
    monkeypatch.setattr(api, "APP_ROOTS", [])
    return root / "Default"


def _cache_hits(result):
    return [h for h in result.hits if h.indicator in ("fixture.invalid", "second.invalid")]


@pytest.mark.parametrize("key", (
    "1/0/_dk_{0} {0} https://ublockorigin.github.io/uAssets/filters/filters.min.txt".format(UBO),
    "https://raw.githubusercontent.com/interplains/zero-breach/main/dist/adfection.adblock.txt",
    "1/0/_dk_https://example.org https://example.org https://easylist.to/easylist/easylist.txt",
    "1/0/_dk_{0} {0} https://lists.example.net/custom.txt".format(UBO),
))
def test_chromium_cached_filter_list_is_not_a_finding(tmp_path, monkeypatch, safety_api, key):
    api = safety_api.browser
    profile = _chrome(tmp_path, monkeypatch, api)
    entry = profile / "Cache" / "Cache_Data" / "0123456789abcdef_0"
    entry.parent.mkdir(parents=True)
    entry.write_bytes(_simple_cache_entry(key, LIST_BODY))
    result = safety_api.browser_run(_ctx())
    assert _cache_hits(result) == []
    assert result.submetrics.get("filter_list_indicators") == 2
    assert any("filter list" in n and "not a sign of contact" in n for n in result.notes)


@pytest.mark.parametrize("key", (
    "1/0/_dk_https://news.example https://news.example https://news.example/story",
    # A page ON a list site still loads ordinary resources: the requesting site
    # must not decide, only the downloaded address.
    "1/0/_dk_https://pgl.yoyo.org https://pgl.yoyo.org https://ads.example/x.js",
    # Lookalikes of list hosts and other repositories on a shared host.
    "https://ublockorigin.github.io.evil.example/filters.txt",
    "https://raw.githubusercontent.com/someone/project/main/page.html",
))
def test_ordinary_cached_content_still_reports(tmp_path, monkeypatch, safety_api, key):
    api = safety_api.browser
    profile = _chrome(tmp_path, monkeypatch, api)
    entry = profile / "Cache" / "Cache_Data" / "0123456789abcdef_0"
    entry.parent.mkdir(parents=True)
    entry.write_bytes(_simple_cache_entry(key, b"a page that mentions fixture.invalid"))
    result = safety_api.browser_run(_ctx())
    hits = _cache_hits(result)
    assert hits and all(h.evidence == "referenced" for h in hits)
    assert not result.submetrics.get("filter_list_indicators")


@pytest.mark.parametrize("owner,listed", ((UBO + "/", True), ("https://news.example/", False)))
def test_service_worker_cache_owned_by_a_content_blocker(tmp_path, monkeypatch, safety_api, owner, listed):
    api = safety_api.browser
    profile = _chrome(tmp_path, monkeypatch, api)
    origin_dir = profile / "Service Worker" / "CacheStorage" / "a1b2c3"
    store = origin_dir / "0f1e2d3c-uuid"
    store.mkdir(parents=True)
    (origin_dir / "index.txt").write_bytes(b"\x0a\x20" + owner.encode() + b"\x12\x04name")
    (store / "fedcba9876543210_0").write_bytes(LIST_BODY)
    result = safety_api.browser_run(_ctx())
    assert bool(_cache_hits(result)) is not listed
    assert bool(result.submetrics.get("filter_list_indicators")) is listed


@pytest.mark.parametrize("url,listed", (
    ("https://raw.githubusercontent.com/interplains/zero-breach/main/dist/adfection.adblock.txt", True),
    ("https://filters.adtidy.org/extension/ublock/filters/2.txt", True),
    ("https://news.example/report.html", False),
))
def test_firefox_cached_filter_list(tmp_path, monkeypatch, safety_api, url, listed):
    api = safety_api.browser
    profiles = tmp_path / "ff" / "Profiles"
    caches = tmp_path / "ffcache" / "Profiles"
    (profiles / "abc.default").mkdir(parents=True)
    (profiles / "abc.default" / "prefs.js").write_text("")
    entry = caches / "abc.default" / "cache2" / "entries" / "0123456789ABCDEF0123456789ABCDEF01234567"
    entry.parent.mkdir(parents=True)
    entry.write_bytes(_firefox_cache_entry("a,:" + url, LIST_BODY))
    monkeypatch.setattr(api, "CHROMIUM_ROOTS", [])
    monkeypatch.setattr(api, "APP_ROOTS", [])
    monkeypatch.setattr(api, "FIREFOX_ROOTS", [(str(profiles), str(caches))])
    result = safety_api.browser_run(_ctx())
    assert bool(_cache_hits(result)) is not listed
    assert bool(result.submetrics.get("filter_list_indicators")) is listed


def test_firefox_layout_is_not_guessed_outside_a_firefox_cache(tmp_path, monkeypatch, safety_api):
    """A Chromium storage file whose tail happens to look like a Firefox key is
    still searched normally."""
    api = safety_api.browser
    profile = _chrome(tmp_path, monkeypatch, api)
    store = profile / "Local Storage" / "leveldb" / "000003.log"
    store.parent.mkdir(parents=True)
    store.write_bytes(_firefox_cache_entry("a,:https://easylist.to/easylist/easylist.txt",
                                           b"saved page mentioning fixture.invalid"))
    result = safety_api.browser_run(_ctx())
    assert _cache_hits(result)


def _blockfile_cache(folder, key, body, long_key=False):
    """A Chromium block-file cache (the Windows layout): an index entry in data_1
    whose body stream points at the external file f_000001."""
    folder.mkdir(parents=True)
    raw = key.encode("latin-1")
    entry = bytearray(256)
    struct.pack_into("<iI", entry, 32, len(raw), 0)
    struct.pack_into("<I", entry, 60, 0x80000000 | 1)        # external file f_000001
    if long_key:
        struct.pack_into("<I", entry, 36, 0x80000000 | (3 << 28) | (2 << 16) | 0)
        data_2 = bytearray(8192 + 1024)
        data_2[8192:8192 + len(raw)] = raw
        (folder / "data_2").write_bytes(bytes(data_2))
    else:
        entry[96:96 + len(raw)] = raw
    (folder / "data_1").write_bytes(b"\0" * 8192 + bytes(entry))
    (folder / "f_000001").write_bytes(body)


@pytest.mark.parametrize("long_key", (False, True))
@pytest.mark.parametrize("url,listed", (
    ("https://ublockorigin.github.io/uAssets/filters/filters.min.txt", True),
    ("https://news.example/report.html", False),
))
def test_windows_block_file_cache(tmp_path, monkeypatch, safety_api, long_key, url, listed):
    api = safety_api.browser
    profile = _chrome(tmp_path, monkeypatch, api)
    key = "1/0/_dk_https://news.example https://news.example " + url
    _blockfile_cache(profile / "Cache" / "Cache_Data", key, b"body naming fixture.invalid", long_key)
    result = safety_api.browser_run(_ctx())
    listed_hits = [h for h in _cache_hits(result) if h.location.endswith("f_000001")]
    assert bool(listed_hits) is not listed


@pytest.mark.parametrize("body,listed", (
    (LIST_BODY, True),
    (b"[Adblock Plus 2.0]\n! Title: x\n||fixture.invalid^\n||other.example^\n", True),
    (b"!function(){var a='fixture.invalid';}();\n", False),
    (b"! one line\nvar a = 'fixture.invalid';\nfunction b() {}\nreturn a;\n", False),
))
def test_windows_cache_body_without_a_readable_index(tmp_path, monkeypatch, safety_api, body, listed):
    """While the browser runs, its index is locked; only a body that is plainly a
    filter list is recognised then."""
    api = safety_api.browser
    profile = _chrome(tmp_path, monkeypatch, api)
    folder = profile / "Cache" / "Cache_Data"
    folder.mkdir(parents=True)
    (folder / "f_000001").write_bytes(body)
    result = safety_api.browser_run(_ctx())
    assert bool(_cache_hits(result)) is not listed
