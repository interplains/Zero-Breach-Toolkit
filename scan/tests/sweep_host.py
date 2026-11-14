"""Sweep registry for the computer-side readers (browsers, Windows traces, host
checks, file fingerprints, patterns, Linux/macOS startup files, execution records).

Read test_unusable_input_sweep.py first: it defines the three registries and the
rule behind them (a check may report "ran" only with proof it read usable input).

Fixture sources (cited again in the test files these reuse):
  Chromium: net/http/transport_security_persister.cc, net/http/http_server_properties_manager.cc,
    components/bookmarks/browser/bookmark_codec.cc, components/history (History/Cookies/
    Favicons table names), net/extras/sqlite (Cookies).
  Firefox: places.sqlite (moz_places), cookies.sqlite (moz_cookies), favicons.sqlite (moz_icons),
    SiteSecurityServiceState.txt.
  Safari: History.db (history_items, history_visits); the other Safari stores use the tables and
    keys browser.py reads. NOT verified against a real Mac.
  Windows: ShimCache / PcaAppLaunchDic.txt / Task Scheduler XML / winreg call shapes
    (see test_fix_host_traces.py).
  Linux/macOS: crontab(5), systemd.unit(5), the XDG autostart specification, Apple property lists.
Every value is synthetic. Windows-only readers run on any platform because the OS seam they
read through (registry, event log, PowerShell) is replaced by the same fakes the older tests use.

Check names: browser checks are reported as "<browser>:<kind>"; the factories here strip the
browser label so the registry key is the kind (hsts, history, ...).
"""
import contextlib
import json
import os
import plistlib
import sqlite3
import struct
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import execution, exploited, hashscan, host, intrusion, patternscan, posix, traces, trust, wifi
from zbtriage.result import ModuleResult

import test_fix_host_browser as tb
import test_fix_host_traces as tt

UNUSABLE = {}
LEGIT_EMPTY = {}
NOT_FILE_BASED = {}
DYNAMIC = {}

_LABELS = ("chrome", "firefox", "Safari")


def _norm(result):
    for check in result.checks:
        head, sep, tail = check.name.partition(":")
        if sep and head in _LABELS:
            check.name = tail
        elif sep and head == "root":
            check.name = "root"      # "root:<folder>": one check per scanned folder
    return result


def _case(registry, name, case_id, factory):
    registry.setdefault(name, []).append((case_id, factory))


def _ctx(**kw):
    ioc = IocSet([Indicator("spy-c2.test", "cc", "primary", "domain", "fixture", "Family"),
                  Indicator("c" * 64, "sample", "primary", "sha256", "fixture", "Family")], "fixture", None)
    return ScanContext(iocs=ioc, emit=lambda _m: None, **kw)


def _db(path, statements):
    path.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.closing(sqlite3.connect(str(path))) as con:
        for sql in statements:
            con.execute(sql)
        con.commit()


GARBAGE = b"this is not the file format this reader expects \x00\xff\xfe" * 4
TRUNCATED_SQLITE = b"SQLite format 3\x00" + b"\x10\x00\x01\x01\x00\x40\x20\x20"


def _browser(files=None, **kw):
    return lambda tmp: _norm(tb.run_browser(tmp, files, **kw))


# --- Chromium / Firefox / Safari stores ------------------------------------------------------

HISTORY_EMPTY = ["CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, last_visit_time INTEGER)"]


def _history_files(statements):
    def build(tmp):
        _db(tmp / "UD" / "Default" / "History", statements)
        return _norm(tb.run_browser(tmp))
    return build


for kind, relative, schema_ok, schema_wrong in (
        ("history", "History", HISTORY_EMPTY, ["CREATE TABLE urls(id INTEGER PRIMARY KEY, title TEXT)"]),
        ("cookies", "Network/Cookies", ["CREATE TABLE cookies(host_key TEXT, name TEXT, creation_utc INTEGER)"],
         ["CREATE TABLE cookies(name TEXT)"]),
        ("favicons", "Favicons", ["CREATE TABLE favicons(id INTEGER PRIMARY KEY, url TEXT, icon_type INTEGER)",
                                  "CREATE TABLE favicon_bitmaps(id INTEGER PRIMARY KEY, icon_id INTEGER, image_data BLOB)"],
         ["CREATE TABLE other(x)"])):
    _case(UNUSABLE, kind, "garbage file", _browser({relative: GARBAGE}))
    _case(UNUSABLE, kind, "empty file", _browser({relative: b""}))
    _case(UNUSABLE, kind, "truncated database", _browser({relative: TRUNCATED_SQLITE}))

    def wrong(tmp, relative=relative, schema_wrong=schema_wrong):
        _db(tmp / "UD" / "Default" / Path(*relative.split("/")), schema_wrong)
        return _norm(tb.run_browser(tmp))
    _case(UNUSABLE, kind, "table without the columns the reader needs", wrong)

    def right(tmp, relative=relative, schema_ok=schema_ok):
        _db(tmp / "UD" / "Default" / Path(*relative.split("/")), schema_ok)
        return _norm(tb.run_browser(tmp))
    LEGIT_EMPTY[kind] = ("a recognised {} store with zero rows is a browser with no such records".format(kind), right)

_case(UNUSABLE, "history", "Firefox places.sqlite is garbage",
      lambda tmp: _norm(tb.run_browser(tmp, firefox={"places.sqlite": GARBAGE})))

_case(UNUSABLE, "bookmarks", "garbage", _browser({"Bookmarks": GARBAGE}))
_case(UNUSABLE, "bookmarks", "no roots", _browser({"Bookmarks": {"roots": {}}}))
LEGIT_EMPTY["bookmarks"] = ("Chromium's own empty bookmark roots (bookmark_bar, other, synced)",
                            _browser({"Bookmarks": tb.NORMAL_BOOKMARKS}))

_case(UNUSABLE, "hsts", "Chromium 80 layout", _browser({"Network/TransportSecurity": {
    "d2luZ3MtdGVzdC1oYXNo": {"expiry": 2e9, "mode": "force-https", "sts_observed": 1.7e9}}}))
_case(UNUSABLE, "hsts", "garbage", _browser({"Network/TransportSecurity": GARBAGE}))
_case(UNUSABLE, "hsts", "empty object", _browser({"Network/TransportSecurity": {}}))
_case(UNUSABLE, "hsts", "Firefox store with only unreadable lines",
      lambda tmp: _norm(tb.run_browser(tmp, firefox={"SiteSecurityServiceState.txt": "garbage\nmore garbage\n"})))
LEGIT_EMPTY["hsts"] = ("an HSTS state with its list present and empty: the browser has received no HSTS header",
                       _browser({"Network/TransportSecurity": {"version": 2, "sts": []}}))

_case(UNUSABLE, "connection-records", "no net object", _browser({"Network/Network Persistent State": {"x": 1}}))
_case(UNUSABLE, "connection-records", "garbage", _browser({"Network/Network Persistent State": GARBAGE}))
_case(UNUSABLE, "connection-records", "servers list missing", _browser({"Network/Network Persistent State": {
    "net": {"http_server_properties": {"version": 5}}}}))
LEGIT_EMPTY["connection-records"] = (
    "Network Persistent State with its servers list present and empty: no server was recorded",
    _browser({"Network/Network Persistent State": {"net": {"http_server_properties": {"version": 5, "servers": []}}}}))


def _history_without_chains(tmp):
    _db(tmp / "UD" / "Default" / "History", HISTORY_EMPTY)
    return _norm(tb.run_browser(tmp))


def _history_with_chains(tmp):
    _db(tmp / "UD" / "Default" / "History", HISTORY_EMPTY + [
        "CREATE TABLE downloads(id INTEGER PRIMARY KEY, current_path TEXT, tab_url TEXT, referrer TEXT, "
        "state INTEGER, received_bytes INTEGER)",
        "CREATE TABLE downloads_url_chains(id INTEGER, chain_index INTEGER, url TEXT)"])
    return _norm(tb.run_browser(tmp))


_case(UNUSABLE, "download-chains", "History without a downloads_url_chains table", _history_without_chains)
LEGIT_EMPTY["download-chains"] = ("a Chromium History with the downloads tables present and no download rows",
                                  _history_with_chains)


def _cache(files):
    def build(tmp):
        return _norm(tb.run_browser(tmp, files))
    return build


LEGIT_EMPTY["blobs"] = ("a cache or storage folder that exists and holds no files is a clean, empty cache",
                        lambda tmp: (_ensure_dir(tmp / "UD" / "Default" / "Cache" / "Cache_Data") or
                                     _norm(tb.run_browser(tmp))))


def _ensure_dir(path):
    path.mkdir(parents=True, exist_ok=True)


def _blobs_unreadable(tmp):
    cache = tmp / "UD" / "Default" / "Cache" / "Cache_Data"
    cache.mkdir(parents=True)
    (cache / "f_000001").write_bytes(b"cached bytes")
    real_open = __import__("io").open

    def refuse(file, *args, **kwargs):
        if str(file).endswith("f_000001"):
            raise PermissionError(13, "Access is denied", str(file))
        return real_open(file, *args, **kwargs)
    with patch("zbtriage.modules.browser.io.open", refuse):
        return _norm(tb.run_browser(tmp))


_case(UNUSABLE, "blobs", "the only file in the cache cannot be read", _blobs_unreadable)

# Safari (macOS). Library/Safari is the root; sibling folders are under Library.
for kind, name in (("safari-tabs", "SafariTabs.db"), ("safari-cloud-tabs", "CloudTabs.db"),
                   ("safari-cache", "../Caches/com.apple.Safari/Cache.db"),
                   ("safari-webkit-statistics", "../WebKit/WebsiteData/ResourceLoadStatistics/observations.db")):
    _case(UNUSABLE, kind, "garbage database",
          lambda tmp, name=name: _norm(tb.run_browser(tmp, safari={name: GARBAGE})))
    schema = {"safari-tabs": "CREATE TABLE bookmarks(id INTEGER PRIMARY KEY, url TEXT)",
              "safari-cloud-tabs": "CREATE TABLE cloud_tabs(id INTEGER PRIMARY KEY, url TEXT)",
              "safari-cache": "CREATE TABLE cfurl_cache_response(entry_ID INTEGER PRIMARY KEY, request_key TEXT)",
              "safari-webkit-statistics": "CREATE TABLE ObservedDomains(registrableDomain TEXT)"}[kind]

    def right(tmp, name=name, schema=schema):
        target = tmp / "Library" / "Safari" / name
        _db(target, [schema])
        # The Safari folder must exist before the fixture adds files beside it.
        return _norm(tb.run_browser(tmp, safari={}))
    LEGIT_EMPTY[kind] = ("a recognised Safari store with zero rows holds no such records", right)

_case(UNUSABLE, "safari-history", "garbage History.db", lambda tmp: _norm(tb.run_browser(tmp, safari={"History.db": GARBAGE})))


def _safari_history_empty(tmp):
    _db(tmp / "Library" / "Safari" / "History.db", [
        "CREATE TABLE history_items(id INTEGER PRIMARY KEY, url TEXT)",
        "CREATE TABLE history_visits(id INTEGER PRIMARY KEY, history_item INTEGER, visit_time REAL)"])
    return _norm(tb.run_browser(tmp, safari={}))


LEGIT_EMPTY["safari-history"] = ("Safari History.db with its two tables and no rows", _safari_history_empty)

for kind, name, good in (
        ("safari-bookmarks", "Bookmarks.plist", {"WebBookmarkType": "WebBookmarkTypeList", "Children": []}),
        ("safari-top-sites", "TopSites.plist", {"TopSites": []}),
        ("safari-closed-tabs", "RecentlyClosedTabs.plist", {"ClosedTabOrWindowPersistentStates": []}),
        ("safari-downloads", "Downloads.plist", {"DownloadHistory": []})):
    _case(UNUSABLE, kind, "garbage property list", lambda tmp, name=name: _norm(tb.run_browser(tmp, safari={name: GARBAGE})))
    _case(UNUSABLE, kind, "empty property list",
          lambda tmp, name=name: _norm(tb.run_browser(tmp, safari={name: plistlib.dumps({})})))
    LEGIT_EMPTY[kind] = ("a property list with the store's own list key present and empty",
                         lambda tmp, name=name, good=good: _norm(tb.run_browser(tmp, safari={name: plistlib.dumps(good)})))

_case(UNUSABLE, "safari-hsts", "empty property list",
      lambda tmp: _norm(tb.run_browser(tmp, safari={"../Cookies/HSTS.plist": plistlib.dumps({})})))
_case(UNUSABLE, "safari-hsts", "garbage", lambda tmp: _norm(tb.run_browser(tmp, safari={"../Cookies/HSTS.plist": GARBAGE})))
LEGIT_EMPTY["safari-hsts"] = (
    "an HSTS.plist with a session that lists no host: no site has set HSTS",
    lambda tmp: _norm(tb.run_browser(tmp, safari={"../Cookies/HSTS.plist": plistlib.dumps(
        {"com.apple.CFNetwork.defaultStorageSession": {}})})))
_case(UNUSABLE, "safari-cookies", "garbage", lambda tmp: _norm(tb.run_browser(
    tmp, safari={"../Cookies/Cookies.binarycookies": GARBAGE})))
LEGIT_EMPTY["safari-cookies"] = (
    "a Cookies.binarycookies header ('cook' and zero pages): no cookie was stored",
    lambda tmp: _norm(tb.run_browser(tmp, safari={"../Cookies/Cookies.binarycookies": b"cook" + struct.pack(">I", 0)})))

DYNAMIC[("modules/browser.py", "kind")] = (
    "mark_ok(label, kind): bookmarks, history, cookies, favicons, blobs, safari-history, safari-tabs, "
    "safari-cloud-tabs, safari-cache, safari-webkit-statistics, safari-bookmarks, safari-top-sites, "
    "safari-closed-tabs, safari-downloads, safari-hsts, safari-cookies - swept above")
DYNAMIC[("modules/execution.py", "check")] = "windows-prefetch / windows-amcache, swept above"
DYNAMIC[("modules/exploited.py", "NAME")] = "exploited-software, swept above"
DYNAMIC[("modules/browser.py", "check_name")] = "the rollup of every kind above into '<browser>:<kind>'"


# --- Windows traces --------------------------------------------------------------------------

def _run(function, *args, **kw):
    result = ModuleResult("traces")
    function(result, *args, **kw)
    return result


def _motw(walk=None, roots=lambda tmp: [str(tmp)]):
    def build(tmp):
        with patch.object(traces, "_tr_motw_roots", lambda: roots(tmp)):
            if walk:
                with patch.object(traces, "walk_local", walk):
                    return _run(traces._tr_check_motw, _ctx())
            return _run(traces._tr_check_motw, _ctx())
    return build


_case(UNUSABLE, "mark-of-the-web", "every folder unreadable", _motw(walk=tt._walk_that_fails))
LEGIT_EMPTY["mark-of-the-web"] = ("a readable Downloads/Desktop/Documents folder with no downloaded files", _motw())

def _runbox(read):
    result = ModuleResult("traces")
    with patch.object(traces, "_tr_read_runmru", lambda: read):
        traces._tr_check_runbox(result, _ctx(), traces._TrLeads(result))
    return result


_case(UNUSABLE, "run-history", "the history could not be read", lambda tmp: _runbox(({}, "", "access denied")))
LEGIT_EMPTY["run-history"] = ("no Win+R key means nothing was ever typed into the Run box", lambda tmp: _runbox(({}, "", "")))


def _events(rows, error=""):
    def fake(log, ids, cap, fields):
        return list(rows), error
    return fake


def _defender(rows, error=""):
    result = ModuleResult("traces")
    with patch.object(traces, "_tr_events", _events(rows, error)):
        traces._tr_check_defender(result, _ctx(), traces._TrLeads(result))
    return result


_case(UNUSABLE, "defender-history", "the log could not be read", lambda tmp: _defender([], "Access is denied"))
LEGIT_EMPTY["defender-history"] = ("a readable Defender log with no detection or exclusion events", lambda tmp: _defender([]))


def _powershell(rows, error=""):
    result = ModuleResult("traces")
    with patch.object(traces, "_tr_events", _events(rows, error)):
        traces._tr_check_powershell(result, _ctx(), traces._TrLeads(result))
    return result


_case(UNUSABLE, "powershell-history", "the log could not be read", lambda tmp: _powershell([], "Access is denied"))
LEGIT_EMPTY["powershell-history"] = (
    "a readable log with no script blocks (script-block logging is off by default; the report carries a note)",
    lambda tmp: _powershell([]))


def _antivirus(products, error):
    result = ModuleResult("traces")
    with patch.object(traces, "_tr_antivirus_products", lambda: (products, error)):
        traces._tr_check_antivirus(result, traces._TrLeads(result))
    return result


_case(UNUSABLE, "antivirus-status", "Security Center could not be queried", lambda tmp: _antivirus([], "WMI unavailable"))
LEGIT_EMPTY["antivirus-status"] = ("Security Center answered and lists no antivirus: the report adds a look-at-this lead",
                                   lambda tmp: _antivirus([], ""))


def _ran_programs(programs, errors):
    result = ModuleResult("traces")
    with patch.object(traces, "_tr_ran_programs", lambda: (programs, errors)):
        traces._tr_check_ran_programs(result, _ctx())
    return result


_case(UNUSABLE, "ran-programs", "no programs from any source", lambda tmp: _ran_programs([], {}))
_case(UNUSABLE, "ran-programs", "only non-file entries",
      lambda tmp: _ran_programs([("Microsoft.WindowsCalculator_8wekyb3d8bbwe!App", "", "launch list")], {}))
_case(UNUSABLE, "ran-programs", "both sources failed", lambda tmp: _ran_programs([], {"shim cache": "denied", "launch list": "denied"}))

_case(UNUSABLE, "extended-process-events", "the event log could not be read",
      lambda tmp: _extended([], "Access is denied"))


def _extended(rows, error=""):
    result = ModuleResult("traces")
    with patch.object(traces, "_tr_events", _events(rows, error)):
        traces._tr_extended(result, _ctx(extended_windows=True))
    return result


LEGIT_EMPTY["extended-process-events"] = ("an opt-in readable Sysmon/Security log holding no matching events",
                                          lambda tmp: _extended([]))


def _extra_history(appdata, winreg_tree=None):
    result = ModuleResult("traces")
    module = tt.fake_winreg(winreg_tree if winreg_tree is not None else {})
    with patch.dict(os.environ, {"APPDATA": appdata}), patch.dict(sys.modules, {"winreg": module}):
        traces._tr_extra_history(result, _ctx())
    return result


_case(UNUSABLE, "psreadline-history", "the history folder is refused",
      lambda tmp: _extra_history(""))
LEGIT_EMPTY["psreadline-history"] = ("an existing profile with no PSReadLine history file: nothing was typed in a saved session",
                                     lambda tmp: _extra_history(str(tmp)))
_case(UNUSABLE, "explorer-typed-paths", "the key cannot be opened", lambda tmp: _typed_paths_denied())
LEGIT_EMPTY["explorer-typed-paths"] = ("no TypedPaths key: nothing was typed in the Explorer address bar",
                                       lambda tmp: _extra_history(str(tmp)))


def _typed_paths_denied():
    result = ModuleResult("traces")
    module = tt.fake_winreg({})

    def deny(*args, **kw):
        raise PermissionError(13, "Access is denied")
    module.OpenKey = deny
    with patch.dict(os.environ, {"APPDATA": ""}), patch.dict(sys.modules, {"winreg": module}):
        traces._tr_extra_history(result, _ctx())
    return result


def _persistence(tmp, **kw):
    return tt._persistence(tmp, **kw)


_case(UNUSABLE, "scheduled-task-actions", "the folder cannot be walked", lambda tmp: _persistence(tmp, walk=tt._walk_that_fails))
_case(UNUSABLE, "startup-files", "the folder cannot be walked", lambda tmp: _persistence(tmp, walk=tt._walk_that_fails))
_case(UNUSABLE, "service-registrations", "an empty services key", lambda tmp: _persistence(tmp, services=tt.FakeKey(subkeys=[])))
LEGIT_EMPTY["scheduled-task-actions"] = ("a readable Tasks folder with no task files", lambda tmp: _persistence(tmp))
LEGIT_EMPTY["startup-files"] = ("readable Startup folders with no entries", lambda tmp: _persistence(tmp))
LEGIT_EMPTY["startup-registrations"] = ("Run/RunOnce keys that do not exist: no auto-start value is registered",
                                        lambda tmp: _persistence(tmp))


def _registry_broken(tmp):
    result = ModuleResult("traces")
    module = tt.fake_winreg({})

    def broken(*args, **kw):
        raise PermissionError(13, "Access is denied")
    module.OpenKey = broken
    with patch.dict(sys.modules, {"winreg": module}), patch.dict(os.environ, {"SystemRoot": str(tmp / "none"), "APPDATA": "", "PROGRAMDATA": ""}):
        traces._tr_persistence(result, _ctx())
    return result


_case(UNUSABLE, "startup-registrations", "the registry is unreadable", _registry_broken)

DYNAMIC[("modules/traces.py", "check")] = ("startup-files / scheduled-task-actions (r.ran(check) in _tr_persistence) and "
                                           "the hash/other readers' dynamic names; swept above")


# --- Host checks ----------------------------------------------------------------------------------

def _com(entries, partial):
    result = ModuleResult("host")
    with patch.object(host, "_enum_com_registrations", lambda r: (entries, partial)):
        host._check_com(result, _ctx())
    return result


_case(UNUSABLE, "com-persistence", "the registry could not be fully enumerated",
      lambda tmp: _com([], ["HKCU\\Software\\Classes\\CLSID: access denied"]))
LEGIT_EMPTY["com-persistence"] = ("no per-user COM registration exists, the usual state of an ordinary profile",
                                  lambda tmp: _com([], []))


def _dns_cache(rows, error=""):
    result = ModuleResult("host")
    with patch.object(host, "_ps_json", lambda *a, **k: (rows, error)), \
            patch.object(host, "_boot_time", lambda: ("", "unavailable")):
        host._check_dns_cache(result, _ctx())
    return result


_case(UNUSABLE, "dns-cache", "the cache could not be read", lambda tmp: _dns_cache([], "Get-DnsClientCache failed"))
LEGIT_EMPTY["dns-cache"] = ("a readable resolver cache with no entry (a freshly started DNS client)", lambda tmp: _dns_cache([]))


def _dns_log(rows, error=""):
    result = ModuleResult("host")
    with patch.object(host, "_ps_json", lambda *a, **k: (rows, error)):
        host._check_dns_log(result, _ctx())
    return result


_case(UNUSABLE, "dns-log", "the log is absent", lambda tmp: _dns_log([], "no such log"))
_case(UNUSABLE, "dns-log", "the log holds no records", lambda tmp: _dns_log([{"IsEnabled": False, "RecordCount": 0}]))


def _hosts(path):
    result = ModuleResult("host")
    with patch.object(host, "_hosts_path", lambda: str(path)):
        host._check_hosts(result, _ctx())
    return result


_case(UNUSABLE, "hosts-file", "no hosts file", lambda tmp: _hosts(tmp / "absent"))
_case(UNUSABLE, "hosts-file", "the path is a folder", lambda tmp: _hosts(tmp))


def _empty_hosts(tmp):
    (tmp / "hosts").write_text("", encoding="utf-8")
    return _hosts(tmp / "hosts")


LEGIT_EMPTY["hosts-file"] = ("a readable hosts file with no active line", _empty_hosts)


def _known_paths_refused(tmp):
    result = ModuleResult("host")
    with patch.object(host, "path_problem", lambda p: "refused for the fixture"):
        host._check_known_paths(result, _ctx())
    return result


_case(UNUSABLE, "known-paths", "every path is refused", _known_paths_refused)
NOT_FILE_BASED["known-paths"] = "probes fixed Windows paths; the file being absent is the clean answer (refusal is swept above)"


def _devilstongue_refused(tmp):
    result = ModuleResult("host")
    with patch.object(host, "path_problem", lambda p: "refused for the fixture"):
        host._check_devilstongue(result, _ctx())
    return result


_case(UNUSABLE, "devilstongue-traces", "a path is refused", _devilstongue_refused)
NOT_FILE_BASED["devilstongue-traces"] = "probes fixed Windows paths and registry classes; absence is the clean answer (refusal is swept above)"


def _dante_refused(tmp):
    result = ModuleResult("host")
    with patch.dict(os.environ, {"LOCALAPPDATA": str(tmp)}), \
            patch.object(host, "_dt_class_server", lambda hive, clsid: None), \
            patch.object(host, "path_problem", lambda p: "refused for the fixture"):
        host._check_dante(result, _ctx())
    return result


_case(UNUSABLE, "dante-traces", "LocalAppData is refused", _dante_refused)
NOT_FILE_BASED["dante-traces"] = "probes one registry class and the folders directly under LocalAppData; absence is the clean answer (refusal is swept above)"
NOT_FILE_BASED["remote-access-software"] = "reads installed program names (registry / app folders); none installed is the clean answer"


def _downloads(make_folders):
    def build(tmp):
        from zbtriage.modules import doors
        folders = make_folders(tmp)
        result = ModuleResult("doors")
        with patch.object(doors, "dr_download_folders", lambda home: folders):
            doors._check_downloads(result)
        return result
    return build


def _downloads_refused(tmp):
    """The folders exist but cannot be opened (macOS privacy controls refusing access, permissions)."""
    (tmp / "Downloads").mkdir()

    def refuse(*_a, **_k):
        raise PermissionError("refused")
    with patch("os.scandir", refuse):
        return _downloads(lambda t: [(str(t / "Downloads"), 2)])(tmp)


_case(UNUSABLE, "remote-access-downloads", "the folders exist but cannot be opened", _downloads_refused)
# No Downloads/Desktop/Documents folder at all (a server, another layout) is not unusable input: nothing can be
# waiting in a folder that does not exist. That case is a note, not a gap (2026-11-14).
LEGIT_EMPTY["remote-access-downloads"] = (
    "readable Downloads/Desktop/Documents folders holding no remote-access program",
    _downloads(lambda tmp: [((tmp / "Downloads").mkdir() or (str(tmp / "Downloads"), 2))]))


def _drivers(files, folder_read=True):
    def build(tmp):
        from zbtriage.modules import doors
        paths = []
        for name, data in files:
            (tmp / name).write_bytes(data)
            paths.append(str(tmp / name))
        paths.append(str(tmp / "missing.sys"))
        matches, done, unread = doors.dr_fingerprint_files(paths, problem=lambda p: "")
        result = ModuleResult("doors")
        doors.dr_driver_doors(result, matches, done, unread, folder_read)
        return result
    return build


_case(UNUSABLE, "windows-drivers", "the drivers folder could not be listed", _drivers([], folder_read=False))
_case(UNUSABLE, "windows-drivers", "the folder lists but no driver file can be read", _drivers([]))
LEGIT_EMPTY["windows-drivers"] = ("readable driver files, none of them on the list",
                                  _drivers([("ordinary.sys", GARBAGE)]))
NOT_FILE_BASED["windows-settings"] = "reads Windows settings; an unreadable one becomes a 'could not check' door, never a closed one"
NOT_FILE_BASED["macos-settings"] = "runs macOS status commands; an unreadable one becomes a 'could not check' door"
NOT_FILE_BASED["linux-settings"] = "reads lsblk/ss/display-manager files; an unreadable one becomes a 'could not check' door"
NOT_FILE_BASED["browser-extensions"] = "lists extension folders and reads their manifests; no extensions is the clean answer"


# --- File fingerprints and patterns -----------------------------------------------------------------

def _hash_root(tmp, outcome):
    (tmp / "ordinary.dll").write_bytes(b"MZ not a sample")
    result = None
    with patch.object(hashscan, "_roots", lambda: [str(tmp)]), \
            patch.object(hashscan, "_hash_outcomes", lambda candidates, ctx: outcome(candidates)):
        result = hashscan.run(_ctx())
    return _norm(result)


_case(UNUSABLE, "root", "every candidate file is unreadable",
      lambda tmp: _hash_root(tmp, lambda candidates: [(c, None, 0, "unreadable") for c in candidates]))


def _hash_empty_root(tmp):
    with patch.object(hashscan, "_roots", lambda: [str(tmp)]):
        return _norm(hashscan.run(_ctx()))


LEGIT_EMPTY["root"] = ("a scanned folder that holds no candidate file: genuinely covered", _hash_empty_root)
DYNAMIC[("modules/hashscan.py", "name")] = "root:<path> per scanned folder (swept as 'root')"


class _FakeScan:
    matching_rules = []


class _FakeScanner:
    def scan(self, data):
        return _FakeScan()


def _patterns(tmp, files=None, read=None):
    for name, data in (files or {}).items():
        (tmp / name).write_bytes(data)
    ctx = _ctx()
    ctx.pattern_paths = (str(tmp),)
    patches = [patch.object(patternscan, "_pattern_engine", lambda: _FakeScanner())]
    if read:
        patches.append(patch.object(patternscan, "_pattern_read", read))
    with contextlib.ExitStack() as stack:
        for p in patches:
            stack.enter_context(p)
        return _norm(patternscan.run(ctx))


def _unreadable(path):
    raise patternscan._PatternNoRead("the fixture cannot be read")


_case(UNUSABLE, "root", "an empty folder", lambda tmp: _patterns(tmp))
_case(UNUSABLE, "root", "every file unreadable", lambda tmp: _patterns(tmp, {"a.bin": b"data"}, _unreadable))
DYNAMIC[("modules/patternscan.py", "name")] = "root:<path> per scanned folder (swept as 'root')"
DYNAMIC[("modules/patternscan.py", "name + ' (scanned subset)'")] = "root:<path> (scanned subset); only after files were scanned"


# --- Linux / macOS startup files --------------------------------------------------------------------

def _posix(check, kind, name, data):
    def build(tmp):
        root = tmp
        if kind.endswith("-file"):
            root = tmp / "single-file"       # a single-file root is the file itself
            root.write_bytes(data)
        elif name is not None:
            (tmp / name).write_bytes(data)
        with patch.object(posix, "_ux_roots", lambda: [(check, str(root), kind)]):
            return posix.run(_ctx())
    return build


_case(UNUSABLE, "macos-launch-items", "damaged property list", _posix("macos-launch-items", "plist", "a.plist", GARBAGE))
_case(UNUSABLE, "linux-autostart", "damaged desktop entry", _posix("linux-autostart", "desktop", "a.desktop", b"\xff\xfe\x00broken"))
_case(UNUSABLE, "linux-systemd-units", "damaged unit", _posix("linux-systemd-units", "unit", "a.service", b"\xff\xfe\x00broken"))
for check, kind in (("macos-launch-items", "plist"), ("linux-autostart", "desktop"), ("linux-systemd-units", "unit"),
                    ("linux-cron", "cron"), ("unix-shell-history", "history-file"), ("unix-shell-profiles", "shell-dir"),
                    ("unix-system-logs", "log-file")):
    LEGIT_EMPTY.setdefault(check, ("a readable folder with no configuration file of this kind", _posix(check, kind, None, b"")))
DYNAMIC[("modules/posix.py", "check")] = ("macos-launch-items, linux-autostart, linux-systemd-units, linux-cron, "
                                          "unix-shell-history, unix-shell-profiles, unix-system-logs - swept above")


# --- Execution records, exploited-software list, intrusion logs ------------------------------------------

def _prefetch(tmp, data):
    target = tmp / "ORDINARY.EXE-AAAAAAAA.pf"
    target.write_bytes(data)
    return execution.run(_ctx(targets=(str(target),)))


_case(UNUSABLE, "windows-prefetch", "garbage file", lambda tmp: _prefetch(tmp, GARBAGE))
_case(UNUSABLE, "windows-prefetch", "empty file", lambda tmp: _prefetch(tmp, b""))


def _amcache(tmp, data):
    target = tmp / "Amcache.hve"
    target.write_bytes(data)
    return execution.run(_ctx(targets=(str(target),)))


_case(UNUSABLE, "windows-amcache", "garbage hive", lambda tmp: _amcache(tmp, GARBAGE))
_case(UNUSABLE, "windows-amcache", "only unreadable records", lambda tmp: _unreadable_amcache(tmp))


def _unreadable_amcache(tmp):
    (tmp / "Amcache.hve").write_bytes(b"regf" + b"\0" * 64)
    with patch.object(execution, "read_amcache", lambda raw: iter([{"error": "path missing", "key": "k"}])):
        return execution.run(_ctx(targets=(str(tmp / "Amcache.hve"),)))


def _exploited_empty(tmp):
    from test_fix_host_other import _exploited_run
    return _exploited_run([])


_case(UNUSABLE, exploited.NAME, "no installed program could be listed", _exploited_empty)


# --- Saved Wi-Fi settings -----------------------------------------------------------------------
# Formats: Windows WLANProfile XML (Microsoft WLAN_profile schema v1, as `netsh wlan export profile`
# writes it); NetworkManager `nmcli -g` values; macOS `system_profiler SPAirPortDataType -json`.

def _wifi_windows(tmp, files, rc=0, out="", err="", visible_error=None):
    from test_wifi_settings import run_windows
    return run_windows(files, rc=rc, out=out, err=err, visible_error=visible_error)


def _wifi_lookalike_unlisted(tmp):
    from test_wifi_settings import profile_xml
    return _wifi_windows(tmp, [profile_xml("Home", "WPA2PSK", "AES")], visible_error=OSError("WlanOpenHandle failed (5)"))


_case(UNUSABLE, "wifi-lookalike", "nearby networks could not be listed", _wifi_lookalike_unlisted)


def _wifi_linux(tmp, listing, values):
    def fake(argv, timeout=60):
        return (0, listing, "") if argv[:3] == ["nmcli", "-t", "-f"] else (1, values, "error")
    with patch.object(wifi.sys, "platform", "linux"), \
            patch.object(wifi.shutil, "which", return_value="/usr/bin/nmcli"), patch.object(wifi, "_wifi_run", fake):
        return wifi.run(_ctx())


def _wifi_mac(tmp, text, rc=0):
    with patch.object(wifi.sys, "platform", "darwin"), patch.object(wifi, "_wifi_run", return_value=(rc, text, "")):
        return wifi.run(_ctx())


_case(UNUSABLE, wifi.NAME, "export refused", lambda tmp: _wifi_windows(tmp, [], rc=5, err="Access is denied."))
_case(UNUSABLE, wifi.NAME, "every exported profile damaged", lambda tmp: _wifi_windows(tmp, ["<garbage", "nope"]))
_case(UNUSABLE, wifi.NAME, "listed connections unreadable",
      lambda tmp: _wifi_linux(tmp, "u1:802-11-wireless\n", ""))
_case(UNUSABLE, wifi.NAME, "macOS report not JSON", lambda tmp: _wifi_mac(tmp, GARBAGE.decode("latin-1")))
_case(UNUSABLE, wifi.NAME, "macOS report refused", lambda tmp: _wifi_mac(tmp, "", rc=1))
LEGIT_EMPTY[wifi.NAME] = (
    "a computer without Wi-Fi (the Wi-Fi service is not running): there are no Wi-Fi settings to check",
    lambda tmp: _wifi_windows(tmp, [], rc=1, out="The Wireless AutoConfig Service (wlansvc) is not running."))
DYNAMIC[("modules/wifi.py", "NAME")] = "wifi-settings, swept above"


# --- DNS logs (--dns-log) ------------------------------------------------------------------------
# Formats: dnsmasq/Pi-hole text log lines; Pi-hole FTL database table "queries"; AdGuard Home
# querylog.json lines; BIND, Unbound, Windows DNS Server debug and Zeek dns.log.

def _dnslog_file(tmp, name, data):
    from zbtriage.modules import dnslogs
    path = tmp / name
    path.write_bytes(data)
    return dnslogs.run(_ctx(dns_logs=(str(path),)))


for _name, _data in (("pihole.log", GARBAGE), ("querylog.json", b'{"not": "a query"}\n'),
                     ("pihole-FTL.db", b"SQLite format 3\x00" + bytes(100)), ("empty.log", b"")):
    _case(UNUSABLE, "dns-log:" + _name, "unusable " + _name,
          lambda tmp, n=_name, d=_data: _dnslog_file(tmp, n, d))
DYNAMIC[("modules/dnslogs.py", "'dns-log:' + label")] = "dns-log:<file>, swept above"


# --- Trust settings: root certificates, proxy, DNS servers, gateway ---------------------------
# Formats: PowerShell certificate-store rows (Thumbprint/Subject/Store); `security dump-trust-settings`
# text; Windows TCP/IP NameServer values; /proc/net/route and /proc/net/arp; Get-NetNeighbor rows.

def _trust(check, platform, patches):
    from contextlib import ExitStack
    with ExitStack() as stack:
        stack.enter_context(patch.object(trust.sys, "platform", platform))
        for target, value in patches:
            stack.enter_context(patch(target, value))
        result = ModuleResult(trust.NAME)
        check(result, _ctx())
        return result


def _ps_fail(*_a, **_k):
    return [], "Access is denied"


def _no_dns():
    raise OSError("registry unreadable")


def _mac_trust_refused(argv, timeout=60):
    return 1, "", "SecTrustSettingsCopyCertificates: unknown error"


_case(UNUSABLE, "root-certificates", "certificate stores refused",
      lambda tmp: _trust(trust._check_roots, "win32", [("zbtriage.modules.host._ps_json", _ps_fail)]))
_case(UNUSABLE, "root-certificates", "macOS trust settings refused",
      lambda tmp: _trust(trust._check_roots, "darwin", [("zbtriage.modules.trust._tr_run", _mac_trust_refused)]))
_case(UNUSABLE, "dns-settings", "DNS settings unreadable",
      lambda tmp: _trust(trust._check_dns, "win32", [("zbtriage.modules.trust._tr_windows_dns", _no_dns)]))
_case(UNUSABLE, "gateway", "route table refused",
      lambda tmp: _trust(trust._check_gateway, "win32", [("zbtriage.modules.host._ps_json", _ps_fail)]))
_case(UNUSABLE, "proxy-settings", "macOS proxy settings refused",
      lambda tmp: _trust(trust._check_proxy, "darwin", [("zbtriage.modules.trust._tr_run", _mac_trust_refused)]))
LEGIT_EMPTY["gateway"] = (
    "no default route: the computer is not on a routed network, so there is no router to check",
    lambda tmp: _trust(trust._check_gateway, "linux",
                       [("zbtriage.modules.trust._tr_linux_neighbours", lambda: (None, []))]))


def _intrusion(tmp, name, data):
    folder = tmp / "intrusion_logs"
    folder.mkdir()
    (folder / name).write_bytes(data)
    ctx = _ctx(phone_path=str(tmp))
    return intrusion.run(ctx)


for check in ("android-intrusion:dns", "android-intrusion:connections", "android-intrusion:processes"):
    _case(UNUSABLE, check, "a log that is not JSON lines", lambda tmp: _intrusion(tmp, "events.jsonl", GARBAGE))
    _case(UNUSABLE, check, "an empty log", lambda tmp: _intrusion(tmp, "events.jsonl", b""))
DYNAMIC[("modules/intrusion.py", "check")] = "android-intrusion:dns / :connections / :processes, only after an event of that kind parsed"
