"""Sweep registry for the iPhone readers (see test_unusable_input_sweep.py).

Every iPhone check that can report "ran" is listed here with input it cannot
use, or - where a recognised, valid, empty input is a real clean read - with the
one-line reason it is allowed.

Format sources the fixtures rely on (a fixture that invents fields is a bug):
  * iTunes/Finder backup: Manifest.db table Files(fileID, domain, relativePath,
    flags, file) and Info.plist "Installed Applications" - MVT
    mvt/ios/modules/backup/manifest.py and backup_info.py; Apple Platform
    Security guide, "Backup" section.
  * SMS: ~/Library/SMS/sms.db tables message(text, date, is_from_me),
    handle(id, service), attachment(filename, mime_type, created_date) - MVT
    mvt/ios/modules/mixed/sms.py and sms_attachments.py.
  * Safari History.db: history_items(id, url), history_visits(history_item,
    visit_time) - WebKit HistoryDatabase schema; MVT safari_history.py.
  * DataUsage.sqlite ZPROCESS(ZPROCNAME, ZBUNDLENAME) - MVT net_datausage.py.
  * Chrome History: urls(id, url), visits(id, url, visit_time) - Chromium
    components/history/core/browser/history_types and history_database.cc.
  * Network Persistent State JSON net.http_server_properties.servers[].server -
    Chromium net/http/http_server_properties_manager.cc.
  * Cache.db tables cfurl_cache_response(request_key, time_stamp),
    cfurl_cache_blob_data - Apple CFNetwork NSURLCache store; MVT
    mvt/ios/modules/fs/cache_files.py.
  * Keychain analytics hard_failures / soft_failures / notes(data, timestamp) -
    MVT mvt/ios/modules/fs/analytics.py.
  * .ips: a JSON metadata line then a body; crash bug_type 309 and 109 carry
    procName/procPath (Apple, "Interpreting the JSON format of a crash report");
    298 JetsamEvent processes[].name and 288 stackshot processByPid.*.procname as
    documented in this repo's docs/IPHONE.md (no public Apple specification).
  * Property lists: Apple plist format; locationd clients.plist, osanalytics
    addaily.plist, configuration profile .stub / MCProfileEvents.plist, IDS
    idstatuscache.plist - MVT mvt/ios/modules/fs/*.py.
  * Text logs: shutdown.log "remaining client pid", mobile_installation.log,
    sysdiagnose ps.txt - MVT shutdownlog.py, installd logs, Apple sysdiagnose.
Values are synthetic (.invalid) and are never contacted.
"""
import io
import json
import os
import plistlib
import sqlite3
import tarfile
from pathlib import Path

from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import ios

DOMAIN = "sweep.invalid"
PROCESS = "sweepd"
APP = "com.sweep.app"


def _iocs():
    return IocSet([Indicator(DOMAIN, "fixture", "primary", "domain", "fixture"),
                   Indicator(PROCESS, "fixture", "primary", "process", "fixture"),
                   Indicator(APP, "fixture", "primary", "app-id", "fixture")], "fixture", None)


def run(root, kind="filesystem"):
    ctx = ScanContext(_iocs(), phone_path=str(root), ios_input=kind, backup_password="",
                      emit=lambda _m: None)
    return ios.run(ctx)


def db(tmp_path, schema, rows=()):
    work = Path(str(tmp_path)) / "build.sqlite"
    if work.exists():
        work.unlink()
    con = sqlite3.connect(str(work))
    con.executescript(schema)
    for sql, params in rows:
        con.execute(sql, params)
    con.commit()
    con.close()
    raw = work.read_bytes()
    work.unlink()
    return raw


def tree(tmp_path, files):
    root = Path(str(tmp_path)) / "extraction"
    for rel, data in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data if isinstance(data, bytes) else data.encode("utf-8"))
    root.mkdir(exist_ok=True)
    return root


def backup(tmp_path, items, apps=None):
    """An unencrypted Finder/iTunes backup folder with the given (domain,
    relativePath, bytes) files."""
    import hashlib
    root = Path(str(tmp_path)) / "backup"
    root.mkdir()
    con = sqlite3.connect(str(root / "Manifest.db"))
    con.execute("CREATE TABLE Files(fileID TEXT,domain TEXT,relativePath TEXT,flags INTEGER,file BLOB)")
    for domain, relative, raw in items:
        fid = hashlib.sha1((domain + "-" + relative).encode()).hexdigest()
        (root / fid[:2]).mkdir(exist_ok=True)
        (root / fid[:2] / fid).write_bytes(raw)
        con.execute("INSERT INTO Files VALUES(?,?,?,?,?)", (fid, domain, relative, 1, b""))
    con.commit()
    con.close()
    (root / "Manifest.plist").write_bytes(plistlib.dumps({"IsEncrypted": False}))
    info = {"Product Version": "17.0"}
    if apps is not None:
        info["Installed Applications"] = apps
    (root / "Info.plist").write_bytes(plistlib.dumps(info))
    return root


def sysdiagnose(tmp_path, files, gz=True):
    path = Path(str(tmp_path)) / "sysdiagnose.tar.gz"
    with tarfile.open(str(path), "w:gz" if gz else "w") as archive:
        for name, data in files.items():
            raw = data if isinstance(data, bytes) else data.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(raw)
            archive.addfile(info, io.BytesIO(raw))
    return path


def ips(meta, body):
    return (json.dumps(meta) + "\n" + (json.dumps(body) if isinstance(body, dict) else body)).encode()


GARBAGE = b"\x00\xff\x13not a usable file\xfe" * 7
UNRELATED_DB = "CREATE TABLE unrelated(x,y)"

# check name -> (path where a file-system extraction keeps it, bytes of a valid but
# unrelated or empty file of that kind, expectation key)
_FS = "var/mobile/"
FILES = {
    "ios:safari-bookmarks": _FS + "Library/Safari/Bookmarks.db",
    "ios:browser-state": _FS + "Library/Safari/BrowserState.db",
    "ios:webkit-statistics": _FS + "Library/WebKit/WebsiteData/ResourceLoadStatistics/observations.db",
    "ios:url-cache": _FS + "Library/Caches/com.apple.mobilesafari/Cache.db",
    "ios:favicons": _FS + "Library/Image Cache/Favicons/Favicons.db",
    "ios:brave-sites": _FS + "Containers/Data/Application/A/Library/Brave.sqlite",
    "ios:whatsapp": _FS + "Containers/Shared/AppGroup/B/ChatStorage.sqlite",
    "ios:permissions": _FS + "Library/TCC/TCC.db",
    "ios:calls": _FS + "Library/CallHistoryDB/CallHistory.storedata",
    "ios:calendar": _FS + "Library/Calendar/Calendar.sqlitedb",
    "ios:interactions": _FS + "Library/CoreDuet/People/interactionC.db",
    "ios:shortcuts": _FS + "Library/Shortcuts/Shortcuts.sqlite",
    "ios:keychain-analytics": _FS + "Library/Keychains/Analytics/events.db",
    "ios:browser-connections": _FS + "Containers/Data/Application/C/Library/Application Support/Chromium/Network Persistent State",
    "ios:analytics": _FS + "Library/com.apple.osanalytics.addaily.plist",
    "ios:location-clients": _FS + "Library/Caches/locationd/clients.plist",
    "ios:preferences": _FS + "Library/Preferences/.GlobalPreferences.plist",
    "ios:id-status-cache": _FS + "Library/Preferences/com.apple.identityservices.idstatuscache.plist",
    "ios:profiles": _FS + "Library/ConfigurationProfiles/profile-0001.stub",
    "ios:profile-events": _FS + "Library/ConfigurationProfiles/MCProfileEvents.plist",
    "ios:profile-settings": _FS + "Library/ConfigurationProfiles/UserSettings.plist",
    "ios:app-metadata": _FS + "Containers/Bundle/Application/D/iTunesMetadata.plist",
    "ios:webkit-origins": _FS + "Library/WebKit/WebsiteData/Default/hash/hash/origin",
    "ios:webkit-session": _FS + "Library/Safari/SafariResourceState.plist",
    "ios:lockdown": "var/root/Library/Lockdown/pair_records/x.plist",
    "ios:shutdown": "var/db/diagnostics/shutdown.log",
    "ios:installations": "var/installd/Library/Logs/MobileInstallation/mobile_installation.log.0",
    "ios:crashes": _FS + "Library/Logs/CrashReporter/Retired/a-2026.ips",
    "ios:message-handles": _FS + "Library/SMS/sms.db",
}

# Valid, recognised files of these kinds that hold nothing to match are still a
# complete read; everything else must not report ran when unusable.
UNUSABLE = {}
LEGIT_EMPTY = {}
NOT_FILE_BASED = {}
DYNAMIC = {
    ("modules/ios.py", "check"): "ios:messages ios:safari ios:processes ios:chrome-history "
                                 "ios:firefox-history: swept below, backup layouts",
    ("modules/ios.py", "frame"): "ios:manifest (backup) / ios:input (extraction, archive): ran only when "
                                 "the source listed at least one file; swept below",
    ("ios_artifacts.py", "check"): "every ios:<kind> in FILES above, plus the message-extra "
                                   "checks: swept below",
}


def _add(registry, name, case, factory):
    registry.setdefault(name, []).append((case, factory))


def _single(name, raw):
    def factory(tmp_path):
        return run(tree(tmp_path, {FILES[name]: raw}), "filesystem")
    return factory


# 1. Garbage bytes under the file's own name: nothing can be read.
for _name in FILES:
    _add(UNUSABLE, _name, "garbage", _single(_name, GARBAGE))
    _add(UNUSABLE, _name, "empty-file", _single(_name, b""))

# 2. A valid SQLite database with none of the tables the reader knows. For most
#    kinds the file's name says what it is, so unknown tables are a gap; a Cache.db
#    or keychain analytics file with no known store is, by design, not marked ran
#    and not a gap either (backups carry other stores with those names).
_DB_KINDS = ("ios:safari-bookmarks", "ios:browser-state", "ios:webkit-statistics", "ios:url-cache",
             "ios:favicons", "ios:brave-sites", "ios:whatsapp", "ios:permissions", "ios:calls",
             "ios:calendar", "ios:interactions", "ios:shortcuts", "ios:keychain-analytics")


def _unknown_db(name):
    def factory(tmp_path):
        return run(tree(tmp_path, {FILES[name]: db(tmp_path, UNRELATED_DB)}), "filesystem")
    return factory


for _name in _DB_KINDS:
    _add(UNUSABLE, _name, "unknown-layout", _unknown_db(_name))

# 3. A JSON file that is not a Network Persistent State; a plist that is not the
#    kind its name claims.
_add(UNUSABLE, "ios:browser-connections", "unknown-layout",
     _single("ios:browser-connections", json.dumps({"net": {"renamed": {}}}).encode()))
_add(UNUSABLE, "ios:browser-connections", "no-net",
     _single("ios:browser-connections", json.dumps({"other": 1}).encode()))
for _name in ("ios:analytics", "ios:id-status-cache", "ios:profiles",
              "ios:profile-events", "ios:app-metadata", "ios:webkit-session"):
    _add(UNUSABLE, _name, "unknown-layout",
         _single(_name, plistlib.dumps({"Unrelated": {"Key": "value"}})))
# clients.plist: a dict of dicts is read as client records (older iOS keys clients by
# bare bundle id), so the unknown layout is a root that is not a dictionary.
_add(UNUSABLE, "ios:location-clients", "list-root",
     _single("ios:location-clients", plistlib.dumps(["not", "a", "client", "dictionary"])))

# 4. Text logs with no recognised record.
_add(UNUSABLE, "ios:shutdown", "unknown-layout", _single("ios:shutdown", "nothing relevant\n"))
_add(UNUSABLE, "ios:lockdown", "empty-file", _single("ios:lockdown", b""))
# Crash reports: 298/288 with no identity, like 309 and 109.
for _case, _meta, _body in (
        ("298-renamed-field", {"bug_type": "298"}, {"processes": [{"proc": PROCESS}]}),
        ("298-processes-dict", {"bug_type": "298"}, {"processes": {"7": {"name": PROCESS}}}),
        ("298-empty-processes", {"bug_type": "298"}, {"processes": []}),
        ("288-renamed-key", {"bug_type": "288"}, {"procs": {"7": {"procname": PROCESS}}}),
        ("288-renamed-field", {"bug_type": "288"}, {"processByPid": {"7": {"proc": PROCESS}}}),
        ("309-no-identity", {"bug_type": "309"}, {"x": PROCESS}),
        ("109-no-identity", {"bug_type": "109"}, {"x": PROCESS})):
    _add(UNUSABLE, "ios:crashes", _case, _single("ios:crashes", ips(_meta, _body)))


# 5. The backup history readers (backup layout) and the message extras.
def _backup_case(domain, relative, raw):
    def factory(tmp_path):
        return run(backup(tmp_path, [(domain, relative, raw)]), "backup")
    return factory


_HISTORY = {
    "ios:messages": ("HomeDomain", "Library/SMS/sms.db"),
    "ios:safari": ("HomeDomain", "Library/Safari/History.db"),
    "ios:processes": ("WirelessDomain", "Library/Databases/DataUsage.sqlite"),
    "ios:chrome-history": ("AppDomain-com.google.chrome",
                           "Library/Application Support/Google/Chrome/Default/History"),
    "ios:firefox-history": ("AppDomainGroup-group.org.mozilla.ios.Firefox", "profile.profile/browser.db"),
}
for _name, (_domain, _relative) in _HISTORY.items():
    _add(UNUSABLE, _name, "garbage", _backup_case(_domain, _relative, GARBAGE))
    _add(UNUSABLE, _name, "empty-file", _backup_case(_domain, _relative, b""))


def _unrelated_backup_db(domain, relative):
    def factory(tmp_path):
        return run(backup(tmp_path, [(domain, relative, db(tmp_path, UNRELATED_DB))]), "backup")
    return factory


for _name, (_domain, _relative) in _HISTORY.items():
    _add(UNUSABLE, _name, "unknown-layout", _unrelated_backup_db(_domain, _relative))

# The message extras: only checks that find their table report ran.
def _handle_without_id(tmp_path):
    return run(tree(tmp_path, {FILES["ios:message-handles"]: db(tmp_path, "CREATE TABLE handle(service)")}),
               "filesystem")


def _attachment_without_filename(tmp_path):
    return run(tree(tmp_path, {FILES["ios:message-handles"]: db(tmp_path, "CREATE TABLE attachment(mime_type)")}),
               "filesystem")


_add(UNUSABLE, "ios:message-handles", "handle-without-id", _handle_without_id)
_add(UNUSABLE, "ios:message-attachments", "attachment-without-filename", _attachment_without_filename)
_add(UNUSABLE, "ios:message-attachments", "garbage", _single("ios:message-handles", GARBAGE))

# The source itself.
_add(UNUSABLE, "ios:manifest", "garbage-manifest-db", lambda t: _bad_backup(t, GARBAGE))
_add(UNUSABLE, "ios:manifest", "no-files-listed", lambda t: run(backup(t, [], apps=[]), "backup"))
_add(UNUSABLE, "ios:manifest", "no-files-table", lambda t: _bad_backup(t, db(t, UNRELATED_DB)))
_add(UNUSABLE, "ios:input", "empty-folder-filesystem", lambda t: run(tree(t, {}), "filesystem"))
_add(UNUSABLE, "ios:input", "empty-folder-sysdiagnose", lambda t: run(tree(t, {}), "sysdiagnose"))
_add(UNUSABLE, "ios:input", "corrupt-archive",
     lambda t: run(_corrupt_archive(t), "sysdiagnose"))
_add(UNUSABLE, "ios:applications", "no-installed-applications-key",
     lambda t: run(backup(t, []), "backup"))
_add(UNUSABLE, "ios:applications", "wrong-type",
     lambda t: run(_apps_backup(t, "not a list"), "backup"))


def _bad_backup(tmp_path, manifest_db):
    root = backup(tmp_path, [])
    (root / "Manifest.db").write_bytes(manifest_db)
    return run(root, "backup")


def _corrupt_archive(tmp_path):
    path = Path(str(tmp_path)) / "bad.tar.gz"
    path.write_bytes(b"\x1f\x8b\x08\x00" + GARBAGE)
    return path


def _apps_backup(tmp_path, apps):
    return backup(tmp_path, [], apps=apps)


# Recognised, valid, genuinely empty inputs that are a real clean read.
def _legit_backup_db(domain, relative, schema):
    def factory(tmp_path):
        return run(backup(tmp_path, [(domain, relative, db(tmp_path, schema))], apps=[]), "backup")
    return factory


LEGIT_EMPTY["ios:messages"] = (
    "sms.db with the message table and no rows: a phone that has no messages was fully read",
    _legit_backup_db("HomeDomain", "Library/SMS/sms.db", "CREATE TABLE message(text,date,is_from_me)"))
LEGIT_EMPTY["ios:safari"] = (
    "History.db with history_items/history_visits and no rows: a fresh or cleared Safari history",
    _legit_backup_db("HomeDomain", "Library/Safari/History.db",
                     "CREATE TABLE history_items(id INTEGER PRIMARY KEY,url TEXT);"
                     "CREATE TABLE history_visits(id INTEGER PRIMARY KEY,history_item INTEGER,visit_time REAL)"))
LEGIT_EMPTY["ios:processes"] = (
    "DataUsage.sqlite with an empty ZPROCESS table: no process has used the network yet",
    _legit_backup_db("WirelessDomain", "Library/Databases/DataUsage.sqlite", "CREATE TABLE ZPROCESS(ZPROCNAME)"))
LEGIT_EMPTY["ios:chrome-history"] = (
    "Chrome History with urls/visits and no rows: an unused or cleared browser",
    _legit_backup_db("AppDomain-com.google.chrome",
                     "Library/Application Support/Google/Chrome/Default/History",
                     "CREATE TABLE urls(id INTEGER PRIMARY KEY,url TEXT);"
                     "CREATE TABLE visits(id INTEGER PRIMARY KEY,url INTEGER,visit_time INTEGER)"))
LEGIT_EMPTY["ios:firefox-history"] = (
    "Firefox browser.db with history/visits and no rows: an unused or cleared browser",
    _legit_backup_db("AppDomainGroup-group.org.mozilla.ios.Firefox", "profile.profile/browser.db",
                     "CREATE TABLE history(id INTEGER PRIMARY KEY,url TEXT);"
                     "CREATE TABLE visits(id INTEGER PRIMARY KEY,siteID INTEGER,date INTEGER)"))
LEGIT_EMPTY["ios:applications"] = (
    "Info.plist lists user-installed apps only; a stock phone has an empty list (key present, list type valid)",
    lambda t: run(backup(t, [], apps=[]), "backup"))
LEGIT_EMPTY["ios:message-handles"] = (
    "a sms.db whose handle table has the id column and no rows",
    lambda t: run(tree(t, {FILES["ios:message-handles"]: db(
        t, "CREATE TABLE handle(id,service)")}), "filesystem"))
LEGIT_EMPTY["ios:message-attachments"] = (
    "a sms.db whose attachment table has the filename column and no rows",
    lambda t: run(tree(t, {FILES["ios:message-handles"]: db(
        t, "CREATE TABLE attachment(filename,mime_type,created_date)")}), "filesystem"))
LEGIT_EMPTY["ios:preferences"] = (
    ".GlobalPreferences.plist is recognised by name and every string in it is searched; "
    "a missing Lockdown Mode key means only that it was never configured",
    lambda t: run(tree(t, {FILES["ios:preferences"]: plistlib.dumps({"AppleLanguages": ["en"]})}), "filesystem"))
LEGIT_EMPTY["ios:profile-settings"] = (
    "a device-settings plist in the profiles folder has no typed field; every string is searched",
    lambda t: run(tree(t, {FILES["ios:profile-settings"]: plistlib.dumps({"k": "v"})}), "filesystem"))
LEGIT_EMPTY["ios:id-status-cache"] = (
    "an IDS lookup cache with no service records is a phone that looked nobody up",
    lambda t: run(tree(t, {FILES["ios:id-status-cache"]: plistlib.dumps({"CacheVersion": 1})}), "filesystem"))
LEGIT_EMPTY["ios:safari-bookmarks"] = (
    "Bookmarks.db with the bookmarks table (url column) and no rows",
    lambda t: run(tree(t, {FILES["ios:safari-bookmarks"]: db(t, "CREATE TABLE bookmarks(url)")}), "filesystem"))
LEGIT_EMPTY["ios:url-cache"] = (
    "a CFNetwork Cache.db (cfurl_cache_response table) with no cached responses",
    lambda t: run(tree(t, {FILES["ios:url-cache"]: db(
        t, "CREATE TABLE cfurl_cache_response(request_key,time_stamp)")}), "filesystem"))
LEGIT_EMPTY["ios:crashes"] = (
    "a crash report whose metadata line names no process and whose type (here a feedback report) "
    "legitimately carries no identity",
    lambda t: run(tree(t, {FILES["ios:crashes"]: ips({"bug_type": "313"}, {"session": "x"})}), "filesystem"))
LEGIT_EMPTY["ios:webkit-statistics"] = (
    "observations.db with the ObservedDomains table and no rows",
    lambda t: run(tree(t, {FILES["ios:webkit-statistics"]: db(
        t, "CREATE TABLE ObservedDomains(registrableDomain,lastSeen)")}), "filesystem"))

_add(UNUSABLE, "ios:process-list", "garbage",
     lambda t: run(sysdiagnose(t, {"ps.txt": GARBAGE}), "sysdiagnose"))
_add(UNUSABLE, "ios:process-list", "unknown-layout",
     lambda t: run(sysdiagnose(t, {"ps.txt": "nothing like a process list\n"}), "sysdiagnose"))
_add(UNUSABLE, "ios:webkit-origins", "garbage", _single("ios:webkit-origins", GARBAGE))
_add(UNUSABLE, "ios:installations", "garbage", _single("ios:installations", GARBAGE))
