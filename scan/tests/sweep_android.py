"""Sweep registry for the Android reader (see test_unusable_input_sweep.py).

Each factory builds an AndroidQF collection folder (layout as in
test_android.collection, i.e. the mvt-project/androidqf collector's file names
and record layouts), damages exactly one artifact, runs android.run and returns
the ModuleResult. Where a layout comes from a source other than that collector:

  * dumpsys batterystats rows: AOSP BatteryStats.java (android13-release),
    dumpDailyPackageChanges / "  Daily from <start> to <end>:".
  * Android backup (.ab) header "ANDROID BACKUP\\n<version>\\n<compressed>\\n<enc>\\n":
    AOSP frameworks/base BackupManagerService / adb backup format (also read by
    MVT's parse_ab_header).
  * bugreport.zip tombstones: AOSP dumpstate puts /data/tombstones/tombstone_NN
    (+ .pb) under FS/data/tombstones/.
  * getprop "[key]: [value]" lines: Android `getprop` output.
"""
import json
import os
import zipfile

from test_android import check, collection
from test_android_deep import add_dumpsys, sms_backup


def _write(folder, name, data):
    mode = "wb" if isinstance(data, bytes) else "w"
    with open(os.path.join(folder, name), mode) as fh:
        fh.write(data)


def _remove(folder, name):
    try:
        os.remove(os.path.join(folder, name))
    except FileNotFoundError:
        pass


def _case(name, data, remove=()):
    def factory(tmp_path):
        d = collection(spy=False)
        for gone in remove:
            _remove(d, gone)
        _write(d, name, data)
        return check(d)
    return factory


def _packages(value):
    return _case("packages.json", value if isinstance(value, (str, bytes)) else json.dumps(value))


def _dumpsys(**sections):
    def factory(tmp_path):
        d = collection(spy=False)
        add_dumpsys(d, **sections)
        return check(d)
    return factory


def _bugreport(members=None, raw=None):
    def factory(tmp_path):
        d = collection(spy=False)
        if raw is not None:
            _write(d, "bugreport.zip", raw)
        else:
            with zipfile.ZipFile(os.path.join(d, "bugreport.zip"), "w") as z:
                for name, data in members.items():
                    z.writestr(name, data)
        return check(d)
    return factory


SYSTEM_ONLY = [{"name": "android", "installer": "", "third_party": False, "system": True,
                "disabled": False, "uid": 1000, "files": []}]
BINARY = b"\x00\x01\x02" * 400

UNUSABLE = {
    "android:packages": [
        ("empty list", _packages([])),
        ("records without a name", _packages([{}, {"name": ""}, 7])),
        ("not JSON", _packages("this is not json")),
        ("truncated JSON", _packages('[{"name": "com.x')),
        ("a JSON object, not a list", _packages({"packages": []})),
    ],
    # A third-party app with no recorded app file is already a gap; these are
    # collections where NO app file record exists at all. (Built-in app files that only
    # lack a fingerprint or certificate stay a note, pinned in test_discovery_and_fingerprint_gaps.)
    "android:app-fingerprints": [
        ("system apps only, no app files", _packages(SYSTEM_ONLY)),
        ("empty list", _packages([])),
    ],
    "android:app-certificates": [
        ("system apps only, no app files", _packages(SYSTEM_ONLY)),
        ("empty list", _packages([])),
    ],
    "android:processes": [
        ("empty processes.txt", _case("processes.txt", "")),
        ("header only", _case("processes.txt", "USER PID PPID VSZ RSS WCHAN ADDR S NAME\n")),
        ("no header", _case("processes.txt", "system 900 1 1 1 0 0 S zygote\n")),
        ("binary", _case("processes.txt", BINARY)),
        ("JSON object", _case("processes.json", "{}", remove=("processes.txt",))),
        ("JSON records without command lines", _case("processes.json", json.dumps(
            [{"pid": 1, "command_line": None}, {"pid": 2}]), remove=("processes.txt",))),
        ("missing", _case("unrelated.txt", "x", remove=("processes.txt",))),
    ],
    "android:properties": [
        ("empty getprop", _case("getprop.txt", "")),
        ("not getprop lines", _case("getprop.txt", "ro.build.version.sdk=34\nplain text\n")),
        ("binary", _case("getprop.txt", BINARY)),
    ],
    "android:settings": [
        ("empty settings", _case("settings_global.txt", "")),
        ("JSON, not key=value", _case("settings_global.txt", '{"adb_enabled": "1=1"}\n')),
        ("binary", _case("settings_global.txt", BINARY)),
    ],
    "android:device-security": [
        ("no properties, SELinux or mounts", _case("getprop.txt", "")),
        ("garbage everywhere", _case("getprop.txt", "plain text\n")),
    ],
    "android:files": [
        ("empty list", _case("files.json", "[]")),
        ("not JSON", _case("files.json", "not json")),
        ("records without a path", _case("files.json", json.dumps([{}, 1, "x"]))),
        ("JSON object", _case("files.json", "{}")),
        ("truncated", _case("files.json", '[{"path": "/a"')),
    ],
    "android:file-hashes": [
        ("empty list", _case("files.json", "[]")),
        ("records without any fingerprint", _case("files.json", json.dumps([{"path": "/data/local/tmp/ok"}]))),
        ("not JSON", _case("files.json", "not json")),
    ],
    "android:root": [
        ("JSON object", _case("root_binaries.json", "{}")),
        ("not JSON", _case("root_binaries.json", "not json")),
        ("missing", _case("unrelated.txt", "x", remove=("root_binaries.json",))),
    ],
    "android:history": [
        ("no dumpsys", _case("unrelated.txt", "x", remove=("dumpsys.txt",))),
        ("empty dumpsys", _case("dumpsys.txt", "")),
        ("no battery section", _dumpsys(package="x")),
        ("blank battery section", _dumpsys(batterystats="")),
    ],
    "android:device-logs": [
        ("no dumpsys or logcat", _case("unrelated.txt", "x", remove=("dumpsys.txt",))),
        ("empty dumpsys", _case("dumpsys.txt", b"", remove=())),
        ("binary dumpsys", _case("dumpsys.txt", BINARY)),
    ],
    "android:crashes": [
        ("no bug report", _case("unrelated.txt", "x")),
        ("not a zip", _bugreport(raw=b"this is not a zip file")),
        ("empty file", _bugreport(raw=b"")),
        ("text tombstone in an unrecognised layout", _bugreport({
            "FS/data/tombstones/tombstone_00": "Timestamp: 2026-09-20 12:33:31.7+0300\nunrecognised\n"})),
        ("garbage protobuf tombstone", _bugreport({
            "FS/data/tombstones/tombstone_00.pb": b"\xff" * 16})),
        ("protobuf with no command line", _bugreport({
            "FS/data/tombstones/tombstone_00.pb": b"\x22\x05hello"})),
    ],
    "android:messages": [
        ("no SMS backup", _case("unrelated.txt", "x")),
        ("empty file", _case("backup.ab", b"")),
        ("not an Android backup", _case("backup.ab", b"garbage garbage garbage garbage\n")),
        ("header only", _case("backup.ab", b"ANDROID BACKUP\n5\n1\nnone\n")),
        ("encrypted without a password", _case("backup.ab", sms_backup([], encrypted=True))),
        ("backup without SMS data", _case("backup.ab", b"ANDROID BACKUP\n5\n0\nnone\n")),
    ],
}


def _history_without_changes(tmp_path):
    d = collection(spy=False)
    add_dumpsys(d, batterystats="  Daily from 2026-10-01-00-00-00 to 2026-10-02-00-00-00:\n")
    return check(d)


def _no_tombstones(tmp_path):
    return _bugreport({"main_entry.txt": "bugreport-fixture.txt"})(tmp_path)


LEGIT_EMPTY = {
    "android:root": ("root_binaries.json = [] is AndroidQF's normal output when no root tool was found",
                     _case("root_binaries.json", "[]")),
    "android:history": ("a battery history with a day and no package changes: nothing was installed or "
                        "removed that day", _history_without_changes),
    "android:crashes": ("a bug report that lists no tombstones: the phone recorded no native crash",
                        _no_tombstones),
    "android:messages": ("an SMS backup whose SMS member is [] is a valid backup of a phone with no SMS",
                         _case("backup.ab", sms_backup([]))),
}

NOT_FILE_BASED = {}

# call sites that build the check name at run time, and where each name is swept
DYNAMIC = {
    ("modules/android.py", "check"): (
        "_an_fingerprint_coverage emits android:app-fingerprints and android:app-certificates; "
        "both are swept above under UNUSABLE"),
}
