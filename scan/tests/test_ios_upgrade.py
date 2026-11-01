"""Independent synthetic iPhone evidence; no host/device acquisition or indicators contacted."""
import contextlib
import datetime
import hashlib
import io
import json
import plistlib
import sqlite3
import struct
import tarfile
from pathlib import Path
from unittest.mock import patch

import pytest

from zbtriage import cli, ios_sources, report
from zbtriage.context import ScanContext
from zbtriage.iocs import IocSet, Indicator
from zbtriage.modules import ios
from zbtriage.ios_messages import ios_message_text
from zbtriage.readers import reader_select
from test_followup_fixes import bundle

DOMAIN = "fixture.invalid"
PROCESS = "fixtureproc"
APP = "com.fixture.app"
EMAIL = "person@fixture.invalid"
PATH = "/private/var/tmp/fixtureproc"
PROFILE = "11111111-2222-3333-4444-555555555555"


@pytest.fixture(params=("source", "bundle"))
def reader(request, bundle):
    return ios.run if request.param == "source" else bundle.run_ios


def ctx(root, kind="backup", password=""):
    indicators = [(DOMAIN, "domain"), (PROCESS, "process"), (APP, "app-id"),
                  (EMAIL, "email"), (PATH, "file-path"), (PROFILE, "profile-id")]
    return ScanContext(IocSet([Indicator(v, "fixture", "primary", t, "fixture") for v, t in indicators], "fixture", None),
                       phone_path=str(root), ios_input=kind, backup_password=password, emit=lambda _: None)


def db_bytes(tmp_path, schema, statements=(), wal=False):
    work = tmp_path / "builder.sqlite"
    con = sqlite3.connect(work)
    con.executescript(schema)
    con.commit()
    if wal:
        con.execute("PRAGMA journal_mode=WAL")
        con.execute("PRAGMA wal_autocheckpoint=0")
    for sql, params in statements:
        con.execute(sql, params)
    con.commit()
    raw = work.read_bytes()
    sidecar = Path(str(work) + "-wal").read_bytes() if wal else b""
    con.close()
    work.unlink()
    return raw, sidecar


def backup(root, items, encrypted=False, modern=False):
    root.mkdir()
    manifest = {"IsEncrypted": encrypted}
    class_key = b"c" * 32
    def enc(key, data):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        pad = 16 - len(data) % 16
        cipher = Cipher(algorithms.AES(key), modes.CBC(bytes(16))).encryptor()
        return cipher.update(data + bytes([pad]) * pad) + cipher.finalize()
    if encrypted:
        pytest.importorskip("cryptography")
        from cryptography.hazmat.primitives.keywrap import aes_key_wrap
        secret = b"owner-password"
        header = [(b"UUID", b"h" * 16)]
        if modern:
            header += [(b"DPSL", b"d" * 20), (b"DPIC", struct.pack(">I", 123))]
            secret = hashlib.pbkdf2_hmac("sha256", secret, b"d" * 20, 123, 32)
        header += [(b"SALT", b"s" * 20), (b"ITER", struct.pack(">I", 101))]
        secret = hashlib.pbkdf2_hmac("sha1", secret, b"s" * 20, 101, 32)
        header += [(b"UUID", b"g" * 16), (b"CLAS", struct.pack(">I", 4)),
                   (b"WRAP", struct.pack(">I", 2)), (b"WPKY", aes_key_wrap(secret, class_key))]
        manifest["BackupKeyBag"] = b"".join(k + struct.pack(">I", len(v)) + v for k, v in header)
        manifest["ManifestKey"] = struct.pack("<I", 4) + aes_key_wrap(class_key, b"m" * 32)
    con = sqlite3.connect(root / "Manifest.db")
    con.execute("CREATE TABLE Files(fileID TEXT,domain TEXT,relativePath TEXT,flags INTEGER,file BLOB)")
    for n, (domain, relative, raw) in enumerate(items):
        fid = hashlib.sha1((domain + "-" + relative).encode()).hexdigest()
        metadata, data = b"", raw
        if encrypted:
            key = hashlib.sha256(str(n).encode()).digest()
            obj = {"Size": len(raw), "EncryptionKey": struct.pack("<I", 4) + aes_key_wrap(class_key, key)}
            metadata = plistlib.dumps({"$objects": ["$null", obj], "$top": {"root": plistlib.UID(1)}}, fmt=plistlib.FMT_BINARY)
            data = enc(key, raw)
        (root / fid[:2]).mkdir(exist_ok=True)
        (root / fid[:2] / fid).write_bytes(data)
        con.execute("INSERT INTO Files VALUES(?,?,?,?,?)", (fid, domain, relative, 1, metadata))
    con.commit()
    con.close()
    if encrypted:
        path = root / "Manifest.db"
        path.write_bytes(enc(b"m" * 32, path.read_bytes()))
    (root / "Manifest.plist").write_bytes(plistlib.dumps(manifest))
    (root / "Info.plist").write_bytes(plistlib.dumps({"Product Version": "fixture-version", "Installed Applications": []}))


def tree_hashes(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in root.rglob("*") if p.is_file()}


@pytest.mark.parametrize("encryption", ("plain", "legacy", "modern"))
def test_wal_only_message_and_independent_encrypted_sidecar(tmp_path, reader, encryption):
    raw, wal = db_bytes(tmp_path, "CREATE TABLE message(text,date,is_from_me)",
                        [("INSERT INTO message VALUES(?,?,0)", (DOMAIN, 700000000000000000))], wal=True)
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/SMS/sms.db", raw),
                  ("HomeDomain", "Library/SMS/sms.db-wal", wal)], encryption != "plain", encryption == "modern")
    before = tree_hashes(root)
    result = reader(ctx(root, password="owner-password"))
    hits = [h for h in result.hits if h.indicator == DOMAIN]
    assert len(hits) == 1
    assert hits[0].evidence == "received"
    assert hits[0].provenance["wal_sha256"]
    assert hits[0].provenance["record_id"] == 1
    assert hits[0].provenance["encrypted_source"] == (encryption != "plain")
    assert not any(not c.ran and c.name == "ios:messages" for c in result.checks)
    assert tree_hashes(root) == before


def test_damaged_wal_preserves_base_and_reports_gap(tmp_path, reader):
    raw, _ = db_bytes(tmp_path, "CREATE TABLE message(text,date,is_from_me)", [("INSERT INTO message VALUES(?,0,0)", (DOMAIN,))])
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/SMS/sms.db", raw), ("HomeDomain", "Library/SMS/sms.db-wal", b"broken")])
    result = reader(ctx(root))
    assert any(h.indicator == DOMAIN for h in result.hits)
    assert any(not c.ran and "WAL" in c.reason for c in result.checks)


def test_wal_checksum_rejects_corruption(tmp_path):
    raw, wal = db_bytes(tmp_path, "CREATE TABLE value(data)", [("INSERT INTO value VALUES(?)", (DOMAIN,))], wal=True)
    prefix, issues = ios_sources._is_wal_prefix(wal, raw)
    assert prefix == wal and not issues
    altered = bytearray(wal)
    altered[-1] ^= 1
    assert "checksum" in " ".join(ios_sources._is_wal_prefix(bytes(altered), raw)[1])
    assert "truncated" in " ".join(ios_sources._is_wal_prefix(wal[:-1], raw)[1])


def test_wrong_password_and_missing_encrypted_payload(tmp_path, reader):
    raw, _ = db_bytes(tmp_path, "CREATE TABLE message(text,date,is_from_me)", [("INSERT INTO message VALUES(?,0,0)", (DOMAIN,))])
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/SMS/sms.db", raw)], True, True)
    result = reader(ctx(root, password="incorrect"))
    assert not result.hits and any("password" in c.reason for c in result.checks)
    fid = hashlib.sha1(b"HomeDomain-Library/SMS/sms.db").hexdigest()
    (root / fid[:2] / fid).unlink()
    result = reader(ctx(root, password="owner-password"))
    assert any("payload is missing" in c.reason for c in result.checks)


def keyed_text(text, extra=""):
    return plistlib.dumps({"$archiver": "NSKeyedArchiver", "$objects": ["$null",
        {"$class": plistlib.UID(2), "NS.string": plistlib.UID(3), "attributes": extra},
        {"$classname": "NSAttributedString"}, text], "$top": {"root": plistlib.UID(1)}}, fmt=plistlib.FMT_BINARY)


def typed_text(text):
    payload = text.encode()
    return (b"\x04\x0bstreamtyped\x81\xe8\x03\x84\x01@\x84\x84\x84\x12NSAttributedString\x00\x85"
            b"\x92\x84\x84\x84\x08NSString\x01\x85\x84\x01+" + bytes([len(payload)]) + payload + b"\x86")


@pytest.mark.parametrize("encoded", (keyed_text, typed_text))
def test_encoded_messages_preserve_direction_and_ignore_attributes(tmp_path, reader, encoded):
    raw, _ = db_bytes(tmp_path, "CREATE TABLE message(text,date,is_from_me,attributedBody)", [
        ("INSERT INTO message VALUES(NULL,0,0,?)", (encoded(DOMAIN),)),
        ("INSERT INTO message VALUES(NULL,0,1,?)", (encoded(DOMAIN),)),
        ("INSERT INTO message VALUES(NULL,0,0,?)", (keyed_text("ordinary", DOMAIN),)),
        ("INSERT INTO message VALUES(NULL,0,0,?)", (b"unknown " + DOMAIN.encode(),))])
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/SMS/sms.db", raw)])
    result = reader(ctx(root))
    assert [h.evidence for h in result.hits] == ["received", "referenced"]
    assert any("encoded or unsupported" in c.reason for c in result.checks)


def test_encoded_cycle_and_bad_lengths_refused():
    obj = plistlib.loads(keyed_text("safe"))
    obj["$objects"][1]["NS.string"] = plistlib.UID(1)
    with pytest.raises(ValueError):
        ios_message_text(plistlib.dumps(obj, fmt=plistlib.FMT_BINARY))
    for raw in (typed_text(DOMAIN)[:-2], typed_text(DOMAIN).replace(b"NSString", b"BadClass"), b"garbage"):
        with pytest.raises(ValueError):
            ios_message_text(raw)


@pytest.mark.parametrize("kind,path,schema,values,grade", [
    ("browser-state", "Library/Safari/BrowserState.db", "CREATE TABLE tabs(url,title)", (DOMAIN, "saved"), "referenced"),
    ("webkit-statistics", "Library/WebKit/observations.db", "CREATE TABLE observed_domains(registrableDomain,lastSeen)", (DOMAIN, 123), "referenced"),
    ("url-cache", "Library/Caches/Cache.db", "CREATE TABLE cfurl_cache_response(request_key,time_stamp)", (DOMAIN, 123), "referenced"),
    ("whatsapp", "Library/ChatStorage.sqlite", "CREATE TABLE ZWAMESSAGE(ZTEXT,ZISFROMME,ZMESSAGEDATE,ZFROMJID)", (DOMAIN, 0, 700000000, "safe"), "received"),
    ("permissions", "Library/TCC/TCC.db", "CREATE TABLE access(client,service,auth_value)", (APP, "kTCCServiceCamera", 2), "configured"),
    ("calls", "Library/CallHistoryDB/CallHistory.storedata", "CREATE TABLE ZCALLRECORD(ZADDRESS,ZDATE)", (EMAIL, 700000000), "device-log"),
    ("calendar", "Library/Calendar/Calendar.sqlitedb", "CREATE TABLE CalendarItem(title,notes,url)", ("entry", "note", DOMAIN), "referenced"),
    ("interactions", "Library/CoreDuet/interactionC.db", "CREATE TABLE ZINTERACTIONS(ZBUNDLEID,ZSTARTDATE)", (APP, 700000000), "device-log"),
    ("shortcuts", "Library/Shortcuts/Shortcuts.sqlite", "CREATE TABLE ZSHORTCUT(ZNAME,ZWORKFLOWACTIONS)", ("saved", plistlib.dumps({"URL": DOMAIN})), "referenced"),
])
def test_additional_sql_schemas(tmp_path, reader, kind, path, schema, values, grade):
    table = schema.split()[2].split("(")[0]
    raw, _ = db_bytes(tmp_path, schema, [("INSERT INTO " + table + " VALUES(" + ",".join("?" * len(values)) + ")", values)])
    root = tmp_path / "backup"
    backup(root, [("AppDomain-net.whatsapp.WhatsApp" if kind == "whatsapp" else "HomeDomain", path, raw)])
    result = reader(ctx(root))
    assert any(h.evidence == grade for h in result.hits), result.checks
    assert any(c.ran and c.name == "ios:" + kind for c in result.checks)
    assert all(h.provenance["sha256"] == hashlib.sha256(raw).hexdigest() for h in result.hits)


def test_safari_profiles_and_hostile_view(tmp_path, reader):
    raw, _ = db_bytes(tmp_path, "CREATE TABLE history_items(id,url); CREATE TABLE history_visits(history_item,visit_time,origin DEFAULT 0)",
                     [("INSERT INTO history_items VALUES(1,?)", ("https://" + DOMAIN,)), ("INSERT INTO history_visits(history_item,visit_time) VALUES(1,700000000)", ())])
    hostile, _ = db_bytes(tmp_path, "CREATE VIEW tabs AS WITH RECURSIVE x(n) AS (VALUES(1) UNION ALL SELECT n+1 FROM x) SELECT n AS url FROM x")
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/Safari/Profiles/fixture/History.db", raw),
                  ("HomeDomain", "Library/Safari/BrowserState.db", hostile)])
    result = reader(ctx(root))
    assert any(h.evidence == "contacted" for h in result.hits)
    assert not any(not c.ran and c.name == "ios:safari" for c in result.checks)
    assert any(not c.ran and c.name == "ios:browser-state" for c in result.checks)


def test_filesystem_and_sysdiagnose_archive(tmp_path, reader):
    root = tmp_path / "filesystem"
    folder = root / "private/var/mobile/Library/SMS"
    folder.mkdir(parents=True)
    raw, _ = db_bytes(tmp_path, "CREATE TABLE message(text,date,is_from_me)", [("INSERT INTO message VALUES(?,0,0)", (DOMAIN,))])
    (folder / "sms.db").write_bytes(raw)
    assert [s.name for s in reader_select(ctx(root, "filesystem"))] == ["ios"]
    assert any(h.evidence == "received" for h in reader(ctx(root, "filesystem")).hits)
    archive = tmp_path / "diagnostics.tar.gz"
    log = ("After 0.87s, these clients are still here:\n- remaining client pid: 123 (" + PATH
           + "/11111111-2222-3333-4444-555555555555)\nSIGTERM: [1700000000] All buffers flushed\n").encode()
    with tarfile.open(archive, "w:gz") as tar:
        for name, content in (("sys/system_logs.logarchive/Extra/shutdown.log.1", log),
                              ("../escape.plist", plistlib.dumps({"bundleID": APP})),
                              ("sys/crash.ips", json.dumps({"procName": PROCESS, "captureTime": "2026-01-01T00:00:00Z"}).encode())):
            entry = tarfile.TarInfo(name)
            entry.size = len(content)
            tar.addfile(entry, io.BytesIO(content))
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    result = reader(ctx(archive, "sysdiagnose"))
    assert any(h.indicator == PATH and h.observed.startswith("2023-") for h in result.hits)
    assert any(h.indicator == PROCESS and "crash.ips" in h.location for h in result.hits)
    assert result.leads
    assert any("unsafe evidence path" in c.reason for c in result.checks)
    assert not (tmp_path / "escape.plist").exists()
    assert digest == hashlib.sha256(archive.read_bytes()).hexdigest()
    assert all(h.provenance["source"] == str(archive) and h.provenance["member"] for h in result.hits)


def test_duplicate_archive_member_cannot_supply_ambiguous_evidence(tmp_path, reader):
    archive = tmp_path / "duplicate.tar"
    with tarfile.open(archive, "w") as tar:
        for value in (PROCESS, "ordinary"):
            raw = json.dumps({"procName": value}).encode()
            member = tarfile.TarInfo("crash.ips")
            member.size = len(raw)
            tar.addfile(member, io.BytesIO(raw))
    result = reader(ctx(archive, "sysdiagnose"))
    assert not result.hits
    assert any("duplicate" in c.reason for c in result.checks)


def test_cleanup_even_on_wrong_password(tmp_path, monkeypatch):
    root, temp = tmp_path / "backup", tmp_path / "temporary"
    temp.mkdir()
    backup(root, [], True)
    monkeypatch.setattr(ios_sources, "local_temp_dir", lambda: str(temp))
    ios.run(ctx(root, password="wrong"))
    assert not list(temp.iterdir())


def test_new_cli_formats_and_provenance_privacy(tmp_path, bundle):
    root = tmp_path / "diagnostics"
    root.mkdir()
    (root / "crash.ips").write_text(json.dumps({"procName": PROCESS}))
    feed = tmp_path / "indicators.stix2"
    feed.write_text(json.dumps({"objects": [{"type": "indicator", "pattern": "[process:name='" + PROCESS + "']"}]}))
    for api in (cli, bundle):
        full, share = tmp_path / "report.json", tmp_path / "share.json"
        argv = ["--phone", str(root), "--ios-input", "sysdiagnose", "--iocs", str(feed),
                "--json", str(full), "--share-json", str(share), "--no-banner"]
        if api is bundle:
            argv += ["--no-pause"]
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors), patch.object(api, "_force_utf8_io", lambda: None):
            code = api.main(argv)
        assert code == 2, errors.getvalue() + output.getvalue()
        doc = json.loads(full.read_text(encoding="utf-8"))
        assert sorted(doc["modules"]) == ["ios"]
        assert doc["scope"]["ios_input"] == "sysdiagnose"
        assert doc["modules"]["ios"]["hits"][0]["provenance"]["sha256"]
        assert "provenance" not in share.read_text(encoding="utf-8")


def test_plist_families_and_metadata(tmp_path, reader):
    root = tmp_path / "backup"
    documents = [
        ("Library/Preferences/com.apple.osanalytics.addaily.plist", {"netUsageBaseline": {PROCESS: [datetime.datetime(2026, 1, 1), 123]}}),
        # Real layouts: installed profiles are profile-<hash>.stub; install
        # history is MCProfileEvents.plist keyed by profile identifier.
        ("Library/ConfigurationProfiles/profile-0123abcd.stub", {"PayloadUUID": PROFILE}),
        ("Library/ConfigurationProfiles/MCProfileEvents.plist",
         {"ProfileEvents": [{PROFILE: {"operation": "install", "process": "/usr/libexec/mobileconfig",
                                      "timestamp": datetime.datetime(2026, 1, 2, 3, 4, 5)}}]}),
        # A device-settings file with no profile in it is searched, not a gap.
        ("Library/ConfigurationProfiles/MCSettingsEvents.plist", {"SystemSettings": {}}),
        ("Library/Caches/locationd/clients.plist", {APP: {"LocationTimeStopped": 700000000}}),
        ("iTunesMetadata.plist", {"softwareVersionBundleId": APP}),
        ("Library/Preferences/.GlobalPreferences.plist", {"LDMGlobalEnabled": True}),
        ("Library/WebKit/resource-log.plist", {"resourceURL": DOMAIN}),
    ]
    backup(root, [("HomeDomain", path, plistlib.dumps(doc)) for path, doc in documents])
    result = reader(ctx(root))
    assert any(h.indicator == PROCESS and h.observed.startswith("2026-") for h in result.hits)
    assert {(h.indicator, h.evidence) for h in result.hits} >= {(PROFILE, "configured"), (PROFILE, "device-log"), (APP, "device-log"), (DOMAIN, "referenced")}
    assert any("Lockdown Mode as enabled" in n for n in result.notes)
    assert not any(not c.ran and c.name in ("ios:analytics", "ios:profiles", "ios:profile-events", "ios:profile-settings",
                                            "ios:location-clients") for c in result.checks)


def test_message_metadata_and_malformed_cache_neighbours(tmp_path, reader):
    raw, _ = db_bytes(tmp_path, "CREATE TABLE message(text,date,is_from_me); CREATE TABLE handle(id,service); CREATE TABLE attachment(filename,mime_type,created_date)",
        [("INSERT INTO handle VALUES(?, 'iMessage')", (EMAIL,)), ("INSERT INTO attachment VALUES(?, 'image/gif', 700000000)", (PATH,))])
    cache, _ = db_bytes(tmp_path, "CREATE TABLE tabs(url)", [("INSERT INTO tabs VALUES(?)", (b"binary " + DOMAIN.encode(),)), ("INSERT INTO tabs VALUES(?)", (DOMAIN,))])
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/SMS/sms.db", raw), ("HomeDomain", "Library/Safari/BrowserState.db", cache)])
    result = reader(ctx(root))
    assert any(h.indicator == EMAIL and h.evidence == "device-log" for h in result.hits)
    assert any(h.indicator == PATH and h.evidence == "referenced" for h in result.hits)
    assert any(h.indicator == DOMAIN and "BrowserState" in h.location for h in result.hits)
    assert any(not c.ran and c.name == "ios:browser-state" for c in result.checks)


def _uncommit_last_transaction(wal):
    """Return `wal` with its final commit frame turned into an ordinary frame, so
    the last transaction is a valid but UNCOMMITTED tail. Built from the published
    WAL format rather than from how a live SQLite engine happens to spill pages,
    which differs between SQLite versions (Apple's Python 3.9 ships 3.43.2, where
    a small transaction is one committed frame and nothing is left over)."""
    magic, _version, page = struct.unpack_from(">3I", wal)
    order = "<II" if magic == 0x377f0682 else ">II"

    def checksum(data, a, b):
        for x, y in struct.iter_unpack(order, data):
            a = (a + x + b) & 0xffffffff
            b = (b + y + a) & 0xffffffff
        return a, b

    out = bytearray(wal)
    frame = 24 + page
    starts = list(range(32, len(wal) - frame + 1, frame))
    commits = [i for i in starts if struct.unpack_from(">I", wal, i + 4)[0]]
    assert len(commits) >= 2, "need two committed transactions to leave one uncommitted"
    cut = commits[-1]
    struct.pack_into(">I", out, cut + 4, 0)
    c0, c1 = struct.unpack_from(">2I", wal, 24)
    for i in starts:
        c0, c1 = checksum(bytes(out[i:i + 8]), c0, c1)
        c0, c1 = checksum(bytes(out[i + 24:i + frame]), c0, c1)
        if i >= cut:
            struct.pack_into(">2I", out, i + 16, c0, c1)
    return bytes(out)


def test_native_uncommitted_wal_tail_not_promoted(tmp_path, reader):
    work = tmp_path / "source.db"
    con = sqlite3.connect(work)
    con.execute("CREATE TABLE message(text,date,is_from_me)")
    con.commit()
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute("INSERT INTO message VALUES('ordinary',0,0)")
    con.commit()
    con.execute("INSERT INTO message VALUES(?,0,0)", (DOMAIN,))
    con.commit()
    raw, wal = work.read_bytes(), Path(str(work) + "-wal").read_bytes()
    con.close()
    wal = _uncommit_last_transaction(wal)
    prefix, issues = ios_sources._is_wal_prefix(wal, raw)
    assert prefix and len(prefix) < len(wal) and not issues
    assert DOMAIN.encode() in wal[len(prefix):] and DOMAIN.encode() not in prefix
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/SMS/sms.db", raw), ("HomeDomain", "Library/SMS/sms.db-wal", wal)])
    result = reader(ctx(root))
    assert not result.hits
    assert any(c.ran and c.name == "ios:messages" for c in result.checks)


def test_manifest_wal_and_cleanup(tmp_path, reader):
    raw, _ = db_bytes(tmp_path, "CREATE TABLE message(text,date,is_from_me)", [("INSERT INTO message VALUES(?,0,0)", (DOMAIN,))])
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/SMS/sms.db", raw)])
    con = sqlite3.connect(root / "Manifest.db")
    row = con.execute("SELECT * FROM Files").fetchone()
    con.execute("DELETE FROM Files")
    con.commit()
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA wal_autocheckpoint=0")
    con.execute("INSERT INTO Files VALUES(?,?,?,?,?)", row)
    con.commit()
    try:
        before = tree_hashes(root)
        result = reader(ctx(root))
        assert any(h.evidence == "received" for h in result.hits)
        assert before == tree_hashes(root)
    finally:
        con.close()


def test_bad_crash_tail_preserves_prior_identity_and_blank_tail_is_valid(tmp_path, reader):
    root = tmp_path / "diagnostics"
    root.mkdir()
    (root / "good.ips").write_text(json.dumps({"procName": PROCESS}) + "\n{}\n\n")
    (root / "bad.ips").write_text(json.dumps({"procName": PROCESS}) + '\n{"unfinished":')
    result = reader(ctx(root, "sysdiagnose"))
    assert len(result.hits) == 2
    assert any(c.ran and c.name == "ios:crashes" for c in result.checks)
    assert any(not c.ran and c.name == "ios:crashes" for c in result.checks)


def test_process_case_preserved_through_stix(tmp_path, reader):
    from zbtriage.stix import load_stix
    feed = tmp_path / "feed.stix2"
    feed.write_text(json.dumps({"objects": [{"type": "indicator", "pattern": "[process:name='FixtureProc']"}]}))
    root = tmp_path / "diagnostics"
    root.mkdir()
    (root / "case.ips").write_text(json.dumps({"procName": "FixtureProc"}))
    (root / "different.ips").write_text(json.dumps({"procName": "fixtureproc"}))
    context = ctx(root, "sysdiagnose")
    context.iocs = IocSet(load_stix(str(feed)).indicators, "fixture", None)
    result = reader(context)
    assert len(result.hits) == 1 and "case.ips" in result.hits[0].location


def test_malformed_metadata_is_a_gap_not_a_crash(tmp_path, reader):
    root = tmp_path / "backup"
    raw, _ = db_bytes(tmp_path, "CREATE TABLE message(text,date,is_from_me)")
    backup(root, [("HomeDomain", "Library/SMS/sms.db", raw)], True)
    # Exercise the inert metadata reader independently; encrypted manifest tests
    # already cover end-to-end per-file metadata consumption.
    for doc in ({"$top": []}, {"$objects": [], "$top": {"root": "bad"}}, {"$objects": "bad"}):
        with pytest.raises(ValueError):
            ios._ios_unarchive(plistlib.dumps(doc))


def test_archive_link_and_expansion_limit(tmp_path, monkeypatch):
    archive = tmp_path / "links.tar"
    with tarfile.open(archive, "w") as tar:
        member = tarfile.TarInfo("crash.ips")
        member.type, member.linkname = tarfile.SYMTYPE, "outside.ips"
        tar.addfile(member)
    result = ios.run(ctx(archive, "sysdiagnose"))
    assert not result.hits and any("links" in c.reason for c in result.checks)
    monkeypatch.setattr(ios_sources, "_IS_ARCHIVE_LIMIT", 10)
    with pytest.raises(ValueError, match="expansion"):
        ios_sources._IsLimitedStream(io.BytesIO(b"a" * 100)).read(100)


def test_property_list_limit_applies_before_decoding(monkeypatch):
    monkeypatch.setattr(ios_sources, "_IS_PLIST_LIMIT", 10)
    with patch.object(ios_sources.plistlib, "loads", side_effect=AssertionError("decoded oversized input")):
        with pytest.raises(ValueError, match="byte limit"):
            ios_sources._is_plist(b"a" * 11)


def test_malformed_xml_metadata_does_not_hide_readable_artifacts(tmp_path, reader):
    raw, _ = db_bytes(tmp_path, "CREATE TABLE message(text,date,is_from_me)", [("INSERT INTO message VALUES(?,0,0)", (DOMAIN,))])
    malformed = b'<?xml version="1.0"?><plist><dict><key>unfinished</key>'
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/SMS/sms.db", raw),
                  ("HomeDomain", "Library/ConfigurationProfiles/profile-first.stub", malformed),
                  ("HomeDomain", "iTunesMetadata.plist", plistlib.dumps({"softwareVersionBundleId": APP}))])
    (root / "Info.plist").write_bytes(malformed)
    result = reader(ctx(root))
    assert {(h.indicator, h.evidence) for h in result.hits} >= {(DOMAIN, "received"), (APP, "device-log")}
    assert any(not c.ran and c.name == "ios:profiles" for c in result.checks)
    assert any(not c.ran and c.name == "ios:applications" for c in result.checks)


def test_new_menu_choices_and_preview_are_scope_only(tmp_path, bundle):
    from zbtriage import menu
    for api in (menu, bundle):
        for choice, kind in (("3", "filesystem"), ("4", "sysdiagnose")):
            args = cli._parse([])
            session = api._MnSession(args, lambda: None, io.StringIO(choice + "\n" + str(tmp_path) + "\n"), io.StringIO(), True)
            assert api._mn_phone(session) == "scan"
            assert args.phone == str(tmp_path) and args.ios_input == kind
    for api in (cli, bundle):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), patch.object(api, "_force_utf8_io", lambda: None):
            assert api.main(["--phone", str(tmp_path), "--ios-input", "sysdiagnose", "--preview"]) == 0
        assert json.loads(out.getvalue())["collection_type"] == "ios-sysdiagnose"
