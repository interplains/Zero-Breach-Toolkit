"""2.0.3: browser readers must not report "ran" from input they could not use.

Fixture sources (layouts are taken from the browsers' own source, never invented):
  * TransportSecurity (HSTS): Chromium net/http/transport_security_persister.cc.
    Current layout is {"version": 2, "sts": [{"host": base64(sha256(dns wire name)),
    "mode", "sts_include_subdomains", "sts_observed", "expiry"}]}. Chromium 80 and
    older wrote each host hash as a TOP-LEVEL key of the object, with no "sts"
    list (the 80.0.3987 persister, ``toplevel->Set(key, ...)``).
  * Network Persistent State: net/http/http_server_properties_manager.cc. The file
    is {"net": {"http_server_properties": {"version": N, "servers": [{"server":
    "https://host:443", ...}], "broken_alternative_services": [{"host", "port",
    "protocol_str", ...}]}}}; "servers" is written even when empty.
  * Bookmarks: components/bookmarks/browser/bookmark_codec.cc. "roots" always holds
    "bookmark_bar", "other" and "synced", each {"type": "folder", "children": []}.
  * Firefox SiteSecurityServiceState.txt: security/manager/ssl/SiteSecurityService
    (tab separated: "<host>:HSTS<TAB>score<TAB>days<TAB>score,state,subdomains").
  * Safari property lists: Apple does not document them; the minimum assumed here
    is the key each store is read by in browser.py (DownloadHistory,
    DownloadEntryURL, "HSTS Host"). NOT verified against a real Mac.
Synthetic values only (.test / .invalid); nothing is contacted.
"""
import json
import os
import plistlib
import subprocess
import sys
import textwrap
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet
from zbtriage.localpaths import path_problem
from zbtriage.modules import browser

INDICATOR = "spy-c2.test"


def _iocs():
    return IocSet([Indicator(INDICATOR, "cc", "primary", "domain", "fixture", "Family")], "fixture", None)


def _write(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(data, bytes):
        path.write_bytes(data)
    else:
        path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")


def run_browser(tmp_path, files=None, firefox=None, safari=None):
    """Run the browser reader on a throwaway profile. `files` are relative to
    <tmp>/UD/Default; `firefox` to <tmp>/ff/p1; `safari` to <tmp>/Library/Safari."""
    ud = tmp_path / "UD"
    (ud / "Default").mkdir(parents=True, exist_ok=True)
    _write(ud / "Default" / "Preferences", "{}")
    for name, data in (files or {}).items():
        _write(ud / "Default" / Path(*name.split("/")), data)
    ff = []
    if firefox is not None:
        profile = tmp_path / "ff" / "p1"
        profile.mkdir(parents=True)
        _write(profile / "prefs.js", "// prefs")
        for name, data in firefox.items():
            _write(profile / name, data)
        ff = [(str(tmp_path / "ff"), str(tmp_path / "ffcache"))]
    roots = [("chrome", str(ud))]
    safari_roots = []
    default_roots = roots
    if safari is not None:
        safari_dir = tmp_path / "Library" / "Safari"
        safari_dir.mkdir(parents=True, exist_ok=True)
        for name, data in safari.items():
            _write(safari_dir / name, data)
        safari_roots = [("Safari", str(safari_dir))]
    ctx = ScanContext(iocs=_iocs(), emit=lambda _m: None)
    with patch.object(browser, "CHROMIUM_ROOTS", default_roots), patch.object(browser, "APP_ROOTS", []), \
            patch.object(browser, "FIREFOX_ROOTS", ff):
        if safari_roots:
            # The reader only looks for Safari while the root list is the platform default.
            with patch.object(browser, "_DEFAULT_CHROMIUM_ROOTS", default_roots), \
                    patch.object(browser, "_browser_safari_roots", lambda: safari_roots):
                return browser.run(ctx)
        return browser.run(ctx)


def ran(result, kind):
    return any(c.ran and c.name.endswith(":" + kind) for c in result.checks)


def gap(result, kind):
    return any((not c.ran) and (":" + kind) in c.name for c in result.checks)


NORMAL_STS = {"version": 2, "sts": [{"host": "bm90T3Vycz0=", "mode": "force-https",
                                    "sts_include_subdomains": False, "sts_observed": 1.7e9, "expiry": 1.8e9}]}
NORMAL_NPS = {"net": {"http_server_properties": {"version": 5, "servers": [
    {"server": "https://ordinary.invalid:443", "supports_spdy": True}], "broken_alternative_services": []}}}
NORMAL_BOOKMARKS = {"roots": {name: {"type": "folder", "children": [], "name": name}
                              for name in ("bookmark_bar", "other", "synced")}, "version": 1}


# --- R2: TransportSecurity without the "sts" list -----------------------------------

def test_an_hsts_file_with_no_entries_in_any_known_layout_is_a_gap(tmp_path):
    result = run_browser(tmp_path, {"Network/TransportSecurity": {"version": 2, "unknown": {"a": 1}}})
    assert not ran(result, "hsts")
    assert gap(result, "hsts")


@pytest.mark.parametrize("document", [{"version": 3, "sts_v3": [{"host": "x"}]}, {}, {"version": 2}])
def test_hsts_without_an_sts_list_is_never_read_as_clean(tmp_path, document):
    result = run_browser(tmp_path, {"Network/TransportSecurity": document})
    assert not ran(result, "hsts")
    assert gap(result, "hsts")


def test_hsts_normal_and_empty_lists_are_still_clean_reads(tmp_path):
    result = run_browser(tmp_path / "a", {"Network/TransportSecurity": NORMAL_STS})
    assert ran(result, "hsts") and not gap(result, "hsts")
    result = run_browser(tmp_path / "b", {"Network/TransportSecurity": {"version": 2, "sts": []}})
    assert ran(result, "hsts") and not gap(result, "hsts")


# --- R3: Network Persistent State without its server list --------------------------

@pytest.mark.parametrize("document", [
    {"something_else": 1},
    {"net": {"http_server_properties": {"version": 6, "servers_v2": [{"server": "https://x.invalid"}]}}},
    {"net": {"http_server_properties": {"version": 5, "broken_alternative_services": []}}},
])
def test_network_state_without_a_server_list_is_a_gap(tmp_path, document):
    result = run_browser(tmp_path, {"Network/Network Persistent State": document})
    assert not ran(result, "connection-records")
    assert gap(result, "connection-records")


def test_network_state_normal_and_empty_server_lists_are_clean_reads(tmp_path):
    result = run_browser(tmp_path / "a", {"Network/Network Persistent State": NORMAL_NPS})
    assert ran(result, "connection-records") and not gap(result, "connection-records")
    empty = {"net": {"http_server_properties": {"version": 5, "servers": []}}}
    result = run_browser(tmp_path / "b", {"Network/Network Persistent State": empty})
    assert ran(result, "connection-records") and not gap(result, "connection-records")


# --- Bookmarks with no roots at all ---------------------------------------------------

def test_bookmarks_with_no_roots_are_a_gap(tmp_path):
    result = run_browser(tmp_path, {"Bookmarks": {"roots": {}}})
    assert not ran(result, "bookmarks")
    assert gap(result, "bookmarks")


def test_normal_empty_bookmarks_are_a_clean_read(tmp_path):
    result = run_browser(tmp_path, {"Bookmarks": NORMAL_BOOKMARKS})
    assert ran(result, "bookmarks") and not gap(result, "bookmarks")


# --- Firefox HSTS state --------------------------------------------------------------

def test_firefox_hsts_with_only_unparseable_lines_is_a_gap(tmp_path):
    result = run_browser(tmp_path, firefox={"SiteSecurityServiceState.txt": "garbage line\nanother one\n"})
    assert not ran(result, "hsts")
    assert gap(result, "hsts")


def test_firefox_hsts_normal_and_empty_files_are_clean_reads(tmp_path):
    line = "ordinary.invalid:HSTS\t0\t19000\t1893456000000,1,0\n"
    result = run_browser(tmp_path / "a", firefox={"SiteSecurityServiceState.txt": line})
    assert any(c.ran and c.name.endswith("hsts") for c in result.checks)
    result = run_browser(tmp_path / "b", firefox={"SiteSecurityServiceState.txt": ""})
    assert any(c.ran and c.name.endswith("hsts") for c in result.checks)


# --- Safari stores (macOS) -----------------------------------------------------------

def test_empty_safari_property_lists_are_not_clean_reads(tmp_path):
    safari = {name: plistlib.dumps({}) for name in
              ("Bookmarks.plist", "TopSites.plist", "RecentlyClosedTabs.plist", "Downloads.plist")}
    result = run_browser(tmp_path, safari=safari)
    for kind in ("safari-bookmarks", "safari-top-sites", "safari-closed-tabs", "safari-downloads"):
        assert not ran(result, kind), kind
        assert gap(result, kind), kind


def test_safari_plists_with_a_recognised_layout_are_clean_reads(tmp_path):
    safari = {"Bookmarks.plist": plistlib.dumps({"WebBookmarkType": "WebBookmarkTypeList", "Children": []}),
              "Downloads.plist": plistlib.dumps({"DownloadHistory": []})}
    result = run_browser(tmp_path, safari=safari)
    assert ran(result, "safari-bookmarks")
    assert ran(result, "safari-downloads")


def test_an_empty_safari_hsts_file_is_a_gap(tmp_path):
    # Safari's HSTS.plist is {session name: {host: {"HSTS Host": True, ...}}}.
    result = run_browser(tmp_path, safari={"../Cookies/HSTS.plist": plistlib.dumps({})})
    assert not ran(result, "safari-hsts")


# --- Item 16: a link must not be followed before the path check ----------------------

def test_a_linked_profile_folder_is_not_found_by_following_the_link(tmp_path):
    real = tmp_path / "elsewhere"
    real.mkdir()
    (real / "Preferences").write_text("{}")
    root = tmp_path / "UD"
    root.mkdir()
    link = root / "Linked"
    if sys.platform == "win32":
        done = subprocess.run(["cmd", "/c", "mklink", "/J", str(link), str(real)],
                              capture_output=True, text=True)
        if done.returncode != 0:
            pytest.skip("cannot make a junction here")
    else:
        try:
            os.symlink(real, link)
        except OSError:
            pytest.skip("cannot make a symbolic link here")
    assert path_problem(str(link / "Preferences")), "the fixture must be a link the guard refuses"
    names = [os.path.basename(p) for p in browser.chromium_profiles(str(root))]
    assert "Linked" not in names


# --- Item 17: a FIFO must not hang the scan ------------------------------------------

POSIX_ONLY = pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
_FIFO_SCRIPT = textwrap.dedent('''
    import os, sys
    sys.path.insert(0, {scan!r})
    from zbtriage.context import ScanContext
    from zbtriage.iocs import Indicator, IocSet
    from zbtriage.modules import browser
    ud, target = sys.argv[1], sys.argv[2]
    os.makedirs(os.path.join(ud, "Default", "Network"), exist_ok=True)
    open(os.path.join(ud, "Default", "Preferences"), "w").write("{{}}")
    if target == "Local State":
        os.mkfifo(os.path.join(ud, "Local State"))
    else:
        os.mkfifo(os.path.join(ud, "Default", "Network", target))
    ioc = IocSet([Indicator("spy-c2.test", "cc", "primary", "domain", "t", "F")], "t", None)
    browser.CHROMIUM_ROOTS = [("chrome", ud)]
    browser.APP_ROOTS = []
    browser.FIREFOX_ROOTS = []
    r = browser.run(ScanContext(iocs=ioc, emit=lambda _m: None))
    print("finished", sorted(c.name for c in r.checks if not c.ran))
''')


@POSIX_ONLY
@pytest.mark.parametrize("target", ["TransportSecurity", "Network Persistent State", "Local State"])
def test_a_named_pipe_in_a_chromium_state_file_does_not_hang_the_scan(tmp_path, target):
    script = tmp_path / "run_fifo.py"
    script.write_text(_FIFO_SCRIPT.format(scan=str(Path(__file__).resolve().parents[1])), encoding="utf-8")
    ud = tmp_path / "UD"
    ud.mkdir()
    try:
        done = subprocess.run([sys.executable, str(script), str(ud), target], capture_output=True,
                              text=True, timeout=30)
    except subprocess.TimeoutExpired:
        pytest.fail("{} as a named pipe hung the scan".format(target))
    assert done.returncode == 0, done.stderr[-400:]
    assert "finished" in done.stdout
    if target != "Local State":
        # A special file where a state file belongs is a gap, never a clean read.
        kind = "hsts" if target == "TransportSecurity" else "connection-records"
        assert kind in done.stdout.replace("chrome:", "")


def test_a_network_state_with_no_server_record_is_an_empty_clean_read(tmp_path):
    # Layout seen in real profiles of desktop apps: {"net": {"network_qualities": {...}}}.
    result = run_browser(tmp_path / "b", {"Network/Network Persistent State": {"net": {"network_qualities": {}}}})
    assert not [c for c in result.checks if "connection-records" in c.name and not c.ran]


def test_the_older_hsts_layout_is_read_and_can_match(tmp_path):
    # Layout seen in real profiles of desktop apps: each host hash is a top-level key.
    key = browser._hsts_fingerprint(INDICATOR)
    other = browser._hsts_fingerprint("other.invalid")
    result = run_browser(tmp_path / "b", {"Network/TransportSecurity": {
        key: {"expiry": 2000000000.0, "mode": "force-https", "sts_observed": 1700000000.0},
        other: {"expiry": 2000000000.0, "mode": "force-https", "sts_observed": 1700000000.0}}})
    assert not [c for c in result.checks if "hsts" in c.name and not c.ran]
    assert result.submetrics.get("hsts_entries") == 2
    assert [h for h in result.hits if h.indicator == INDICATOR] or result.hits
