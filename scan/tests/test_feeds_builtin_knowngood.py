"""Built-in copies of the mvt-indicators files, and the known-good lists (MISP warninglists).
No network: downloads are injected, built-in copies come from the release itself."""
import hashlib
import json
import os
import tempfile
from unittest.mock import patch

import pytest

from zbtriage import feeds, mvtdata
from zbtriage.iocs import TYPE_DOMAIN, TYPE_IP, TYPE_SHA256, Indicator, IocSet


# --- built-in copies -------------------------------------------------------------------------------------------

def test_every_built_in_copy_is_exactly_the_file_this_release_pins():
    assert set(mvtdata.MVT_BUILTIN) == {s["id"] for s in feeds.SOURCES if s["repo"] == "mvt-project/mvt-indicators"}
    assert mvtdata.MVT_BUILTIN_COMMIT == feeds.FEED_PINS["mvt-project/mvt-indicators"]
    for sid in mvtdata.MVT_BUILTIN:
        data = feeds.builtin_bytes(sid)
        assert data is not None and hashlib.sha256(data).hexdigest() == feeds.FEED_FILE_SHA256[sid]


def test_only_mit_licensed_files_are_built_in():
    # Amnesty, Citizen Lab and Echap files carry no licence file: download-only, never built in
    repos = {s["repo"] for s in feeds.SOURCES if s["id"] in mvtdata.MVT_BUILTIN}
    assert repos == {"mvt-project/mvt-indicators"}


def test_a_built_in_copy_that_does_not_match_the_pin_is_refused(monkeypatch):
    sid = sorted(mvtdata.MVT_BUILTIN)[0]
    monkeypatch.setitem(feeds.FEED_FILE_SHA256, sid, "0" * 64)
    assert feeds.builtin_bytes(sid) is None
    sets, status = feeds.cached_sets(tempfile.mkdtemp(prefix="nocache_"))
    assert any(r["id"] == sid and "built-in" in r["reason"] for r in status["refused"])
    assert sid not in {e["id"] for e in status["loaded"]}


def test_a_scan_with_no_downloads_uses_the_built_in_copies():
    sets, status = feeds.cached_sets(tempfile.mkdtemp(prefix="nocache_"))
    built = [e for e in status["loaded"] if e.get("built_in")]
    assert {e["id"] for e in built} == set(mvtdata.MVT_BUILTIN)
    assert all(e["indicators"] > 0 and e["pinned_for_this_release"] for e in built)
    assert not set(mvtdata.MVT_BUILTIN) & set(status["missing"])
    assert "amnesty-pegasus-2021" in status["missing"]          # unlicensed: still has to be downloaded
    assert status["downloaded"] is False


def test_built_in_copies_age_like_downloads():
    sets, status = feeds.cached_sets(tempfile.mkdtemp(prefix="nocache_"))
    assert all(e["age_days"] is not None and not e["freshness_unknown"]
               for e in status["loaded"] if e.get("built_in"))


def test_a_good_downloaded_copy_wins_over_the_built_in_one():
    sid = "mvt-cellebrite"
    src = next(s for s in feeds.SOURCES if s["id"] == sid)
    cache = tempfile.mkdtemp(prefix="feeds_")
    data = feeds.builtin_bytes(sid)
    feeds.update(cache, sources=[src], fetch=lambda url: data)
    sets, status = feeds.cached_sets(cache)
    entry = next(e for e in status["loaded"] if e["id"] == sid)
    assert not entry.get("built_in")


def test_a_refused_download_falls_back_to_the_built_in_copy():
    sid = "mvt-cellebrite"
    src = next(s for s in feeds.SOURCES if s["id"] == sid)
    cache = tempfile.mkdtemp(prefix="feeds_")
    feeds.update(cache, sources=[src], fetch=lambda url: feeds.builtin_bytes(sid))
    path = os.path.join(cache, sid + ".stix2")
    with open(path, "ab") as fh:
        fh.write(b" ")                                   # edited after download: refused
    sets, status = feeds.cached_sets(cache)
    assert any(r["id"] == sid for r in status["refused"])
    assert next(e for e in status["loaded"] if e["id"] == sid).get("built_in")


def test_built_in_copies_leave_no_temporary_files():
    before = set(os.listdir(tempfile.gettempdir()))
    feeds.cached_sets(tempfile.mkdtemp(prefix="nocache_"))
    after = {n for n in os.listdir(tempfile.gettempdir()) if n.startswith(".zb-builtin.")}
    assert not (after - before)


# --- known-good lists ------------------------------------------------------------------------------------------

def _warninglist(tmp_path, name, kind, values):
    path = tmp_path / (name + ".json")
    path.write_text(json.dumps({"name": name, "type": kind, "list": values}), encoding="utf-8")
    return str(path)


def _ind(value, kind):
    return Indicator(value, "primary", "primary", kind, "test", "Family")


def test_exact_values_only_never_subdomains(tmp_path):
    kg = feeds.load_warninglist(_warninglist(tmp_path, "ddns", "hostname", [".duckdns.org", "bit.ly"]), "DDNS", False)
    assert kg.covers(_ind("duckdns.org", TYPE_DOMAIN)) == "DDNS"
    assert kg.covers(_ind("bit.ly", TYPE_DOMAIN)) == "DDNS"
    assert kg.covers(_ind("evil.duckdns.org", TYPE_DOMAIN)) == ""     # a real attacker subdomain stays
    assert kg.covers(_ind("notbit.ly", TYPE_DOMAIN)) == ""


def test_address_ranges_only_for_lists_marked_fixed(tmp_path):
    path = _warninglist(tmp_path, "ranges", "cidr", ["10.0.0.0/8", "8.8.8.8"])
    fixed = feeds.load_warninglist(path, "Fixed", True)
    loose = feeds.load_warninglist(path, "Loose", False)
    assert fixed.covers(_ind("10.9.9.9", TYPE_IP)) == "Fixed"
    assert loose.covers(_ind("10.9.9.9", TYPE_IP)) == ""           # a range from a list not marked fixed is unused
    assert loose.covers(_ind("8.8.8.8", TYPE_IP)) == "Loose"       # single addresses are exact values
    assert fixed.covers(_ind("45.77.10.10", TYPE_IP)) == ""


def test_substring_and_regex_lists_are_not_used(tmp_path):
    with pytest.raises(feeds.IocError):
        feeds.load_warninglist(_warninglist(tmp_path, "sub", "substring", ["google"]), "Sub", False)


def test_broken_warninglists_are_refused(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text('{"name": "x", "type": "string"}', encoding="utf-8")
    with pytest.raises(feeds.IocError):
        feeds.load_warninglist(str(bad), "Bad", False)


def test_set_aside_indicators_are_counted_with_the_reason(tmp_path):
    kg = feeds.load_warninglist(_warninglist(tmp_path, "dns", "cidr", ["1.1.1.1"]), "Public DNS", True)
    empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    kg.merge(feeds.load_warninglist(_warninglist(tmp_path, "empty", "string", [empty]), "Empty files", False))
    s = IocSet([_ind("1.1.1.1", TYPE_IP), _ind(empty, TYPE_SHA256), _ind("spy-c2.example", TYPE_DOMAIN)], "x", None)
    s.sets = [{"path": "x", "not_applicable_to_this_scan": {}}]
    sets = [s]
    assert feeds.apply_known_good(sets, kg) == 2
    assert [i.value for i in sets[0].indicators] == ["spy-c2.example"]
    assert sets[0].sets[0]["not_applicable_to_this_scan"][feeds.KNOWN_GOOD_REASON] == 2


def test_known_good_lists_are_downloaded_pinned_and_allow_listed():
    for src in feeds.KNOWN_GOOD_SOURCES:
        assert src["category"] == "known-good" and src["format"] == "misp-warninglist"
        assert feeds.url_allowed(src["url"])
        assert src["id"] in feeds.FEED_FILE_SHA256
    assert "MISP/misp-warninglists" in feeds.FEED_PINS
    # none of them is an indicator source, and no ranking ("top sites") or cloud/VPN/Tor range list was chosen
    assert not {s["id"] for s in feeds.KNOWN_GOOD_SOURCES} & {s["id"] for s in feeds.SOURCES}
    names = " ".join(s["path"] for s in feeds.KNOWN_GOOD_SOURCES)
    for word in ("top", "tranco", "majestic", "alexa", "aws", "azure", "gcp", "vpn", "tor-exit", "scanning",
                 "datacenter", "digitalocean", "windows-binary-hashes"):
        assert word not in names


def test_known_good_lists_loaded_from_the_cache_filter_the_indicator_sets(tmp_path):
    src_ind = {"id": "test-src", "name": "Test source", "format": "stix2", "cite": "Test", "category": "mercenary",
               "family": "", "repo": "mvt-project/mvt-indicators", "path": "x/test.stix2",
               "url": "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/x/test.stix2"}
    src_kg = dict(feeds.KNOWN_GOOD_SOURCES[0], id="kg-test", cidr_ok=True,
                  url="https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/t/list.json",
                  path="lists/t/list.json")
    stix = json.dumps({"type": "bundle", "objects": [
        {"type": "malware", "id": "malware--1", "name": "Pegasus"},
        {"type": "indicator", "id": "indicator--1", "pattern": "[domain-name:value='spy-c2.example']"},
        {"type": "indicator", "id": "indicator--2", "pattern": "[ipv4-addr:value='9.9.9.9']"},
        {"type": "relationship", "relationship_type": "indicates", "source_ref": "indicator--1",
         "target_ref": "malware--1"},
        {"type": "relationship", "relationship_type": "indicates", "source_ref": "indicator--2",
         "target_ref": "malware--1"}]}).encode()
    wl = json.dumps({"name": "dns", "type": "cidr", "list": ["9.9.9.9"]}).encode()
    cache = str(tmp_path / "cache")
    responses = {src_ind["url"]: stix, src_kg["url"]: wl}
    with patch.object(feeds, "SOURCES", [src_ind]), patch.object(feeds, "KNOWN_GOOD_SOURCES", [src_kg]), \
            patch.object(feeds, "MVT_BUILTIN", {}), patch.object(feeds, "FEED_PINS", {}):
        feeds.update(cache, fetch=lambda url: responses[url])
        sets, status = feeds.cached_sets(cache)
    assert [i.value for s in sets for i in s.indicators] == ["spy-c2.example"]
    assert status["known_good"]["set_aside"] == 1
    assert [e["id"] for e in status["known_good"]["lists"]] == ["kg-test"]
    assert "kg-test" not in status["missing"]                      # a known-good list is never an indicator gap
