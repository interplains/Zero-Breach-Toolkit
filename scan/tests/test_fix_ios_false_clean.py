"""iPhone readers: unusable input is a gap, never a clean read (2.0.3).

Reproduces the findings of private-notes/REVIEW-30-ITEMS-VERIFIED.md (item 3,
R5 and the 'source opened is not proof' flaw behind R1) for the iPhone readers.
Each test fails on the 2.0.2 code. Fixture layouts and their sources are cited
at the top of sweep_ios.py (MVT parsers, Apple documentation, Chromium and
WebKit source); values are synthetic .invalid names and are never contacted.
"""
import plistlib

import pytest

import sweep_ios as s


def _checks(result, name):
    return [c for c in result.checks if c.name == name]


def _ran(result, name):
    return any(c.ran for c in _checks(result, name))


def _gap(result, name):
    return any(not c.ran for c in _checks(result, name))


# --- .ips types 288 and 298 need an identity, like 109 and 309 -----------------------
@pytest.mark.parametrize("case,meta,body", [
    ("298 renamed name field", {"bug_type": "298"}, {"processes": [{"proc": s.PROCESS}]}),
    ("298 processes is a dict", {"bug_type": "298"}, {"processes": {"7": {"name": s.PROCESS}}}),
    ("298 empty process list", {"bug_type": "298"}, {"processes": []}),
    ("288 renamed key", {"bug_type": "288"}, {"procs": {"7": {"procname": s.PROCESS}}}),
    ("288 renamed field", {"bug_type": "288"}, {"processByPid": {"7": {"proc": s.PROCESS}}}),
])
def test_stackshot_and_jetsam_reports_without_an_identity_are_a_gap(tmp_path, case, meta, body):
    result = s.run(s.tree(tmp_path, {s.FILES["ios:crashes"]: s.ips(meta, body)}))
    assert _gap(result, "ios:crashes"), case
    assert not _ran(result, "ios:crashes"), case


@pytest.mark.parametrize("meta,body", [
    ({"bug_type": "298"}, {"processes": [{"name": s.PROCESS}]}),
    ({"bug_type": "288"}, {"processByPid": {"7": {"procname": s.PROCESS}}}),
    ({"bug_type": "313"}, {"session": "a feedback report names no process"}),
])
def test_recognised_reports_and_feedback_reports_stay_clean_reads(tmp_path, meta, body):
    result = s.run(s.tree(tmp_path, {s.FILES["ios:crashes"]: s.ips(meta, body)}))
    assert _ran(result, "ios:crashes")
    assert not _gap(result, "ios:crashes")


# --- stores that only share a file name are not marked ran, and are not a gap ---------
@pytest.mark.parametrize("name", ["ios:url-cache", "ios:keychain-analytics"])
def test_an_unrelated_store_with_a_shared_name_is_neither_ran_nor_a_gap(tmp_path, name):
    result = s.run(s.tree(tmp_path, {s.FILES[name]: s.db(tmp_path, s.UNRELATED_DB)}))
    assert not _ran(result, name)
    assert not _gap(result, name)       # a gap here would fire on every backup


def test_a_cache_with_a_recognised_table_is_still_read(tmp_path):
    raw = s.db(tmp_path, "CREATE TABLE cfurl_cache_response(request_key,time_stamp)",
               [("INSERT INTO cfurl_cache_response VALUES(?,0)", ("https://" + s.DOMAIN + "/x",))])
    result = s.run(s.tree(tmp_path, {s.FILES["ios:url-cache"]: raw}))
    assert _ran(result, "ios:url-cache")
    assert any(h.indicator == s.DOMAIN for h in result.hits)


# --- a property list of a layout nobody documented is a gap, not a clean read ---------
@pytest.mark.parametrize("name", ["ios:analytics", "ios:app-metadata", "ios:id-status-cache",
                                  "ios:location-clients", "ios:profile-events", "ios:profiles",
                                  "ios:webkit-session"])
def test_an_unrecognised_property_list_layout_is_a_gap(tmp_path, name):
    doc = {"Unrelated": {"Key": "value"}}
    if name == "ios:location-clients":
        # A dict of dicts is read as client records (older iOS keys clients by bare
        # bundle id, so it cannot be told apart); a list root is not any layout.
        doc = ["not", "a", "client", "dictionary"]
    result = s.run(s.tree(tmp_path, {s.FILES[name]: plistlib.dumps(doc)}))
    assert _gap(result, name)
    assert not _ran(result, name)


def test_strings_in_an_unrecognised_property_list_are_still_searched(tmp_path):
    doc = {"Unrelated": {"Key": "see https://" + s.DOMAIN + "/"}}
    result = s.run(s.tree(tmp_path, {s.FILES["ios:analytics"]: plistlib.dumps(doc)}))
    assert any(h.indicator == s.DOMAIN for h in result.hits)
    assert _gap(result, "ios:analytics")


# --- files with no content ---------------------------------------------------------------
@pytest.mark.parametrize("name", ["ios:lockdown", "ios:webkit-origins", "ios:installations"])
@pytest.mark.parametrize("raw", [b"", s.GARBAGE], ids=["empty", "garbage"])
def test_empty_or_garbage_files_are_not_a_clean_read(tmp_path, name, raw):
    result = s.run(s.tree(tmp_path, {s.FILES[name]: raw}))
    assert _gap(result, name)
    assert not _ran(result, name)


def test_a_real_lockdown_property_list_is_still_read(tmp_path):
    result = s.run(s.tree(tmp_path, {s.FILES["ios:lockdown"]: plistlib.dumps({"HostID": "ABC", "SystemBUID": "DEF"})}))
    assert _ran(result, "ios:lockdown")


# --- the source being open is not proof anything was read ----------------------------------
def test_an_empty_extraction_folder_does_not_mark_the_input_ran(tmp_path):
    for kind in ("filesystem", "sysdiagnose"):
        sub = tmp_path / kind
        sub.mkdir()
        result = s.run(s.tree(sub, {}), kind)
        assert not _ran(result, "ios:input"), kind
        assert _gap(result, "ios:input"), kind
        assert result.submetrics.get("phone_records_read", 0) == 0, kind


def test_a_corrupt_sysdiagnose_archive_reads_nothing(tmp_path):
    result = s.run(s._corrupt_archive(tmp_path), "sysdiagnose")
    assert not _ran(result, "ios:input")
    assert result.submetrics.get("phone_records_read", 0) == 0


def test_a_manifest_that_lists_no_files_is_not_a_read_backup(tmp_path):
    result = s.run(s.backup(tmp_path, [], apps=[]), "backup")
    assert not _ran(result, "ios:manifest")
    assert result.submetrics.get("phone_records_read", 0) == 0


def test_an_unreadable_manifest_reads_nothing(tmp_path):
    result = s._bad_backup(tmp_path, s.GARBAGE)
    assert result.submetrics.get("phone_records_read", 0) == 0


def test_a_normal_backup_and_extraction_count_what_they_read(tmp_path):
    sms = s.db(tmp_path, "CREATE TABLE message(text,date,is_from_me)",
               [("INSERT INTO message VALUES('hello',700000000,0)", ())])
    backup = s.backup(tmp_path, [("HomeDomain", "Library/SMS/sms.db", sms)], apps=[])
    result = s.run(backup, "backup")
    assert result.submetrics["phone_records_read"] >= 2          # the manifest entry and the message
    assert _ran(result, "ios:manifest")
    sub = tmp_path / "fs"
    sub.mkdir()
    result = s.run(s.tree(sub, {s.FILES["ios:message-handles"]: sms}), "filesystem")
    assert result.submetrics["phone_records_read"] >= 1
    assert _ran(result, "ios:input")


# --- normal input must not gain gap lines ------------------------------------------------------
def test_a_normal_backup_gains_no_gap_lines(tmp_path):
    sms = s.db(tmp_path, "CREATE TABLE message(text,date,is_from_me)",
               [("INSERT INTO message VALUES('hello',700000000,0)", ())])
    cache = s.db(tmp_path, "CREATE TABLE admin(k,v);CREATE TABLE event_cache(e)")
    usage = s.db(tmp_path, "CREATE TABLE ZPROCESS(ZPROCNAME)", [("INSERT INTO ZPROCESS VALUES('launchd')", ())])
    safari = s.db(tmp_path, "CREATE TABLE history_items(id INTEGER PRIMARY KEY,url TEXT);"
                            "CREATE TABLE history_visits(id INTEGER PRIMARY KEY,history_item INTEGER,visit_time REAL)",
                  [("INSERT INTO history_items VALUES(1,'https://example.invalid/')", ()),
                   ("INSERT INTO history_visits VALUES(1,1,700000000)", ())])
    backup = s.backup(tmp_path, [
        ("HomeDomain", "Library/SMS/sms.db", sms),
        ("HomeDomain", "Library/Safari/History.db", safari),
        ("WirelessDomain", "Library/Databases/DataUsage.sqlite", usage),
        ("HomeDomain", "Library/Caches/com.apple.rtcreporting/eventcache/Cache.db", cache)], apps=["com.example.app"])
    result = s.run(backup, "backup")
    unexpected = [(c.name, c.reason) for c in result.checks if not c.ran and "unreadable" in c.reason]
    assert not unexpected, unexpected
