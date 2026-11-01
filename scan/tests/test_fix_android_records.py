"""2.0.3 Android readers: crash records, the app list and the battery history.

Every fixture layout comes from a cited source, not from this project's own idea
of the format:

  * Tombstone protobuf: AOSP system/core debuggerd/proto/tombstone.proto
    (android13-release): `string timestamp = 4;`, `repeated string command_line = 9;`,
    `repeated LogBuffer log_buffers = 18;`, `repeated FD open_fds = 19;`;
    `message LogBuffer { string name = 1; repeated LogMessage logs = 2; }`,
    `message LogMessage { string timestamp = 1; ... string message = 6; }`,
    `message FD { int32 fd = 1; string path = 2; ... }`. Wire format: protobuf
    encoding documentation (tag = field << 3 | wire type; 2 = length-delimited).
  * Text tombstone, Android 11 and older: android11-release
    libdebuggerd/tombstone.cpp prints `Timestamp: %s` and
    `pid: %d, tid: %d, name: %s  >>> %s <<<` and no `Cmdline:` line.
    Android 12+ text (tombstone_proto_to_text.cpp, android13-release) prints
    `Cmdline: %s` (the command_line list joined by spaces) and the same pid line.
  * Battery history: AOSP frameworks/base BatteryStats.java (android13-release)
    dumpDailyPackageChanges prints `<prefix>Package changes:` then
    `<prefix>  Update <pkg> vers=<n>` or `<prefix>  Uninstall <pkg>` (an
    Uninstall row has NO vers=, and there is no Install row); the day header is
    `  Daily from yyyy-MM-dd-HH-mm-ss to yyyy-MM-dd-HH-mm-ss:` and the package
    changes are printed with prefix "    " under it.
  * AndroidQF packages.json record layout: mvt-project/androidqf collector
    (name, installer, uid, disabled, system, third_party, files[path, sha256,
    certificate{Sha1, Sha256}]), as already used by test_android.collection.
"""
import json
import os
import struct
import sys
import zipfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_android import check, collection  # noqa: E402
from test_android_deep import add_dumpsys  # noqa: E402
from zbtriage.result import EV_DEVICE_LOG  # noqa: E402

SPY = "com.spy.app"


# --- protobuf wire helpers (encoding documentation) -----------------------------

def varint(n):
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def field(number, value):
    if isinstance(value, int):
        return varint(number << 3) + varint(value)
    if isinstance(value, str):
        value = value.encode()
    return varint(number << 3 | 2) + varint(len(value)) + value


def tombstone_pb(command_line, timestamp="2026-09-20 12:33:31.7+0300", logs="", fds=""):
    """A Tombstone message with the fields in field-number order, as the C++
    serializer writes them: 2 build_fingerprint, 4 timestamp, 5 pid, 9 command_line*,
    then (large, after the head) 18 log_buffers and 19 open_fds."""
    body = field(2, "google/fixture/fixture:14/AAA/1:user/release-keys")
    body += field(4, timestamp) + field(5, 4242) + field(8, "u:r:untrusted_app:s0")
    for part in command_line:
        body += field(9, part)
    if logs:
        body += field(18, field(1, "main") + field(2, field(1, "09-20 12:33:31.700") + field(6, logs)))
    if fds:
        body += field(19, field(1, 3) + field(2, fds))
    return body


def bugreport(folder, members):
    with zipfile.ZipFile(os.path.join(folder, "bugreport.zip"), "w") as z:
        for name, data in members.items():
            z.writestr("FS/data/tombstones/" + name, data)


def text_tombstone_android11(name):
    return ("*** *** *** *** *** *** *** *** *** *** *** *** *** *** *** ***\n"
            "Timestamp: 2026-09-20 12:33:31.7+0300\n"
            "pid: 4242, tid: 4242, name: {0}  >>> {0} <<<\n"
            "uid: 10099\nsignal 11 (SIGSEGV), code 1 (SEGV_MAPERR)\n").format(name)


def crash_hits(r):
    return [h for h in r.hits if h.indicator == SPY]


def crash_check(r):
    return [c for c in r.checks if c.name == "android:crashes"]


# --- item 1: tombstones ----------------------------------------------------------

def test_protobuf_only_tombstone_names_the_app():
    d = collection(spy=False)
    bugreport(d, {"tombstone_00.pb": tombstone_pb([SPY])})
    r = check(d)
    hits = crash_hits(r)
    assert [(h.evidence, h.observed) for h in hits] == [(EV_DEVICE_LOG, "2026-09-20T12:33:31")]
    assert r.submetrics["android_crash_records"] == 1
    assert all(c.ran for c in crash_check(r))


def test_protobuf_words_in_log_buffer_and_open_files_are_not_an_identity():
    # A crash of a harmless app whose log (field 18) and open files (field 19)
    # mention the indicator is not a crash of the indicator's app.
    d = collection(spy=False)
    bugreport(d, {"tombstone_00.pb": tombstone_pb(["com.legit.app"], logs="started " + SPY,
                                                  fds="/data/data/" + SPY + "/db")})
    r = check(d)
    assert crash_hits(r) == []
    assert r.submetrics["android_crash_records"] == 1
    assert all(c.ran for c in crash_check(r))


def test_protobuf_command_line_is_a_repeated_field_joined_with_spaces():
    d = collection(spy=False)
    bugreport(d, {"tombstone_01.pb": tombstone_pb(["/data/local/tmp/spyd", "--arg"])})
    r = check(d)
    assert [h.indicator for h in r.hits if h.indicator == "/data/local/tmp/spyd"] == ["/data/local/tmp/spyd"]


def test_android11_text_tombstone_has_no_cmdline_line():
    d = collection(spy=False)
    bugreport(d, {"tombstone_02": text_tombstone_android11(SPY)})
    r = check(d)
    assert len(crash_hits(r)) == 1
    assert crash_hits(r)[0].evidence == EV_DEVICE_LOG


def test_text_and_protobuf_twin_is_one_record_and_one_hit():
    d = collection(spy=False)
    bugreport(d, {"tombstone_03": "Timestamp: 2026-09-20 12:33:31.7+0300\nCmdline: %s\n" % SPY,
                  "tombstone_03.pb": tombstone_pb([SPY])})
    r = check(d)
    assert len(crash_hits(r)) == 1
    assert r.submetrics["android_crash_records"] == 1


def test_a_record_without_an_identity_is_a_gap_not_a_clean_read():
    d = collection(spy=False)
    bugreport(d, {"tombstone_04": "Timestamp: 2026-09-20 12:33:31.7+0300\nsome unrecognised layout\n"})
    r = check(d)
    checks = crash_check(r)
    assert checks and not any(c.ran for c in checks)
    assert any("command line" in c.reason for c in checks)


def test_a_truncated_or_garbage_protobuf_is_a_gap():
    d = collection(spy=False)
    good = tombstone_pb([SPY])
    bugreport(d, {"tombstone_05.pb": good[:20], "tombstone_06.pb": b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff"})
    r = check(d)
    assert crash_hits(r) == []
    assert not any(c.ran for c in crash_check(r))


def test_one_readable_and_one_unreadable_record_gives_a_hit_and_a_gap():
    d = collection(spy=False)
    bugreport(d, {"tombstone_07.pb": tombstone_pb([SPY]), "tombstone_08.pb": b"\x00\x01"})
    r = check(d)
    assert len(crash_hits(r)) == 1
    assert any(not c.ran for c in crash_check(r))


def test_a_bug_report_without_tombstones_is_still_a_clean_read():
    d = collection(spy=False)
    with zipfile.ZipFile(os.path.join(d, "bugreport.zip"), "w") as z:
        z.writestr("main_entry.txt", "bugreport-fixture.txt")
    r = check(d)
    assert [c.ran for c in crash_check(r)] == [True]
    assert r.submetrics["android_crash_records"] == 0


# --- item 2: the app list --------------------------------------------------------

def _packages(d, value):
    with open(os.path.join(d, "packages.json"), "w") as fh:
        json.dump(value, fh)


def test_an_empty_app_list_is_not_checked():
    d = collection(spy=False)
    _packages(d, [])
    r = check(d)
    packages = [c for c in r.checks if c.name == "android:packages"]
    assert packages and not any(c.ran for c in packages)


def test_records_without_a_name_are_not_a_read_app_list():
    d = collection(spy=False)
    _packages(d, [{}, {"name": ""}, 7])
    r = check(d)
    assert not any(c.ran for c in r.checks if c.name == "android:packages")
    assert not any(c.ran for c in r.checks if c.name in ("android:app-fingerprints", "android:app-certificates"))


def test_a_normal_app_list_is_read_and_counted():
    d = collection(spy=False)
    r = check(d)
    assert any(c.ran for c in r.checks if c.name == "android:packages")
    assert r.submetrics["phone_records_read"] >= 3


# --- item 4: battery history -----------------------------------------------------

def _battery(rows):
    return ("  Daily from 2026-10-01-00-00-00 to 2026-10-02-00-00-00:\n"
            "    Package changes:\n" + "".join("      %s\n" % row for row in rows))


def test_uninstall_row_has_no_version_and_still_reads_as_removed():
    d = collection(spy=False)
    add_dumpsys(d, batterystats=_battery(["Uninstall " + SPY]))
    r = check(d)
    hit = [h for h in r.hits if h.indicator == SPY]
    assert len(hit) == 1 and "REMOVED" in hit[0].detail
    assert hit[0].location == "battery history (package changes)"
    assert hit[0].observed == "2026-10-02T00:00:00"
    assert r.submetrics["android_package_changes"] == 1


def test_update_row_with_version_is_read_and_no_install_verb_exists():
    d = collection(spy=False)
    add_dumpsys(d, batterystats=_battery(["Update %s vers=12" % SPY]))
    r = check(d)
    hit = [h for h in r.hits if h.indicator == SPY]
    assert len(hit) == 1 and "updated" in hit[0].detail
    assert r.submetrics["android_package_changes"] == 1


def test_an_empty_battery_section_is_a_gap_and_a_day_without_changes_is_a_clean_read():
    d = collection(spy=False)
    add_dumpsys(d, batterystats="")
    assert not any(c.ran for c in check(d).checks if c.name == "android:history")
    d = collection(spy=False)
    add_dumpsys(d, batterystats="  Daily from 2026-10-01-00-00-00 to 2026-10-02-00-00-00:\n")
    r = check(d)
    assert [c.ran for c in r.checks if c.name == "android:history"] == [True]
    assert r.submetrics["android_package_changes"] == 0


# --- item 7: where in the log a match is -----------------------------------------

def test_a_log_match_says_which_line_and_keeps_its_source_file():
    # No format source is needed for the log body: logcat/dumpsys are free text and
    # the location format is this project's own ("phone log <file>, line <n>").
    d = collection(spy=False)
    with open(os.path.join(d, "logcat.txt"), "w", encoding="utf-8") as fh:
        fh.write("11-01 10:00:00.000 I tag: ordinary line\n"
                 "11-01 10:00:01.000 I tag: another line\n"
                 "11-01 10:00:02.000 I tag: contacting Spy-C2.example now\n"
                 "11-01 10:00:03.000 I tag: started com.spy.app\n"
                 "11-01 10:00:04.000 I tag: wrote /data/local/tmp/spyd\n")
    r = check(d)
    where = {h.indicator: h for h in r.hits}
    assert where["spy-c2.example"].location == "phone log logcat.txt, line 3"
    assert where["com.spy.app"].location == "phone log logcat.txt, line 4"
    assert where["/data/local/tmp/spyd"].location == "phone log logcat.txt, line 5"
    for hit in where.values():
        assert os.path.basename(hit.artifact) == "logcat.txt"


# --- the count the report uses to decide whether anything was read ----------------

def test_a_collection_with_nothing_usable_counts_no_records_read():
    d = collection(spy=False)
    _packages(d, [])
    for name in ("files.json", "processes.txt", "getprop.txt", "settings_global.txt"):
        os.remove(os.path.join(d, name))
    with open(os.path.join(d, "dumpsys.txt"), "w") as fh:
        fh.write("")
    r = check(d)
    assert r.submetrics.get("phone_records_read", 0) == 0


def test_a_valid_empty_root_list_is_not_counted_as_a_record():
    d = collection(spy=False)
    _packages(d, [])
    for name in ("files.json", "processes.txt", "getprop.txt", "settings_global.txt", "dumpsys.txt"):
        os.remove(os.path.join(d, name))
    r = check(d)           # root_binaries.json = [] is the only readable file left
    assert any(c.ran and c.name == "android:root" for c in r.checks)
    assert r.submetrics.get("phone_records_read", 0) == 0
