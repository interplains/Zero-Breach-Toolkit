"""An Android bug report made on the phone, read as a phone collection. Every bug report here is built in the
test; the layout follows what Android's dumpstate writes."""
import json
import os
import tempfile
import zipfile

import pytest

from zbtriage import bugreport as br
from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import android, intrusion

SEP = "-" * 79


def _main_text(packages=True, settings=True):
    parts = ["=" * 56, "== dumpstate: 2026-11-13 10:00:00", "=" * 56, "", "Build: UP1A.231005.007", "",
             "------ SYSTEM PROPERTIES (getprop) ------",
             "[ro.build.version.security_patch]: [2026-10-01]",
             "[ro.debuggable]: [0]",
             "[ro.boot.verifiedbootstate]: [green]",
             "------ 0.012s was the duration of 'SYSTEM PROPERTIES' ------",
             "------ SYSTEM LOG (logcat -v threadtime -v printable -v uid -d *:v) ------",
             "11-13 09:59:00.000  1000  1234  1250 I NetworkMonitor: probe to https://spy-c2.example/beacon",
             "------ 0.200s was the duration of 'SYSTEM LOG' ------",
             "------ DUMPSYS (/system/bin/dumpsys) ------", SEP]
    if packages:
        parts += ["DUMP OF SERVICE package:",
                  "Database versions:", "  Internal:", "",
                  "Packages:",
                  "  Package [com.android.settings] (1a2b3c):",
                  "    codePath=/system/priv-app/Settings",
                  "    pkgFlags=[ SYSTEM HAS_CODE PERSISTENT ]",
                  "    firstInstallTime=2009-01-01 00:00:00",
                  "  Package [com.whatsapp] (4d5e6f):",
                  "    codePath=/data/app/~~abc==/com.whatsapp-xyz==",
                  "    installerPackageName=com.android.vending",
                  "    firstInstallTime=2025-03-02 12:00:00",
                  "  Package [com.spy.app] (7a8b9c):",
                  "    codePath=/data/app/~~def==/com.spy.app-uvw==",
                  "    installerPackageName=null",
                  "    initiatingPackageName=com.google.android.packageinstaller",
                  "    firstInstallTime=2026-11-01 09:00:00",
                  "    pkgFlags=[ HAS_CODE ALLOW_CLEAR_USER_DATA ]",
                  "",
                  "Hidden system packages:",
                  "  Package [com.android.old] (999):",
                  "    codePath=/system/app/Old",
                  "--------- 0.050s was the duration of dumpsys package, ending at: 2026-11-13 10:00:05", SEP]
    parts += ["DUMP OF SERVICE batterystats:",
              "Daily stats:",
              "  Current start time: 2026-11-13-00-00-00",
              "  Daily from 2026-11-02-00-00-00 to 2026-11-03-00-00-00:",
              "    Package changes:",
              "      Update com.whatsapp vers=231000",
              "      Uninstall com.removed.spy",
              "--------- 0.030s was the duration of dumpsys batterystats, ending at: 2026-11-13 10:00:04", SEP]
    if settings:
        parts += ["DUMP OF SERVICE settings:",
                  "GLOBAL SETTINGS (user 0)",
                  "_id:36 name:adb_enabled pkg:android value:1 default:1 defaultSystemSet:true",
                  "_id:40 name:package_verifier_enable pkg:android value:0 default:1 defaultSystemSet:true",
                  "SECURE SETTINGS (user 0)",
                  "_id:61 name:enabled_accessibility_services pkg:com.spy.app value:com.spy.app/.Svc "
                  "default:null defaultSystemSet:true",
                  "SECURE SETTINGS (user 10)",
                  "_id:62 name:enabled_accessibility_services pkg:x value:com.other/.Svc default:null",
                  "SYSTEM SETTINGS (user 0)",
                  "_id:70 name:screen_brightness pkg:android value:120 default:120",
                  "--------- 0.010s was the duration of dumpsys settings, ending at: 2026-11-13 10:00:06", SEP]
    parts += ["------ 1.0s was the duration of 'DUMPSYS' ------", ""]
    return "\n".join(parts)


def _bugreport(tmp_path, name="bugreport-phone-UP1A-2026-11-13-10-00-00.zip", **kw):
    path = tmp_path / name
    main = "bugreport-phone-UP1A-2026-11-13-10-00-00.txt"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("main_entry.txt", main)
        z.writestr("version.txt", "2.0")
        z.writestr(main, _main_text(**kw))
    return str(path)


def _iocs():
    return IocSet([Indicator("com.spy.app", "artifact", "primary", "app-id", "t", "Spyfam"),
                   Indicator("com.removed.spy", "artifact", "primary", "app-id", "t", "Spyfam"),
                   Indicator("spy-c2.example", "cc", "primary", "domain", "t", "Spyfam"),
                   Indicator("a" * 64, "sample", "primary", "sha256", "t", "Spyfam"),
                   Indicator("b" * 64, "artifact", "primary", "app-cert", "t", "Spyfam")], "t.txt", None)


def _run(path):
    return android.run(ScanContext(iocs=_iocs(), emit=lambda _m: None, phone_path=path))


# --- recognising a bug report -----------------------------------------------------------------------------------

def test_a_bug_report_zip_and_an_old_text_report_are_recognised(tmp_path):
    assert br.br_is_bugreport(_bugreport(tmp_path))
    txt = tmp_path / "bugreport.txt"
    txt.write_text(_main_text(), encoding="utf-8")
    assert br.br_is_bugreport(str(txt))


def test_other_files_are_not_bug_reports(tmp_path):
    plain = tmp_path / "photos.zip"
    with zipfile.ZipFile(plain, "w") as z:
        z.writestr("a.jpg", b"x")
    named = tmp_path / "bugreport-fake.zip"
    with zipfile.ZipFile(named, "w") as z:
        z.writestr("bugreport-fake.txt", "no dumpstate header here")
    notes = tmp_path / "notes.txt"
    notes.write_text("hello", encoding="utf-8")
    for path in (plain, named, notes, tmp_path):
        assert not br.br_is_bugreport(str(path))


def test_the_main_text_is_found_without_main_entry(tmp_path):
    path = tmp_path / "br.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("dumpstate_board.txt", "board")
        z.writestr("bugreport-x.txt", _main_text())
    assert br.br_is_bugreport(str(path))


# --- turning it into a collection -------------------------------------------------------------------------------

def test_the_parts_a_bug_report_holds_are_written_in_collection_shape(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    found = br.br_to_collection(_bugreport(tmp_path), str(out))
    assert found["made"] == "2026-11-13T10:00:00" and found["apps"] == 3 and found["properties"] == 3
    apps = {a["name"]: a for a in json.load(open(out / "packages.json", encoding="utf-8"))}
    assert set(apps) == {"com.android.settings", "com.whatsapp", "com.spy.app"}   # hidden system list left out
    assert apps["com.android.settings"]["system"] and not apps["com.android.settings"]["third_party"]
    assert apps["com.whatsapp"]["installer"] == "com.android.vending"
    assert apps["com.spy.app"]["installer"] == "com.google.android.packageinstaller"   # installer was null
    assert all(a["files"] == [] for a in apps.values())                               # not in a bug report
    secure = (out / "settings_secure.txt").read_text(encoding="utf-8")
    assert "enabled_accessibility_services=com.spy.app/.Svc" in secure and "com.other" not in secure
    assert "package_verifier_enable=0" in (out / "settings_global.txt").read_text(encoding="utf-8")
    assert "[ro.debuggable]: [0]" in (out / "getprop.txt").read_text(encoding="utf-8")
    assert "spy-c2.example" in (out / "logcat.txt").read_text(encoding="utf-8")
    dumpsys = (out / "dumpsys.txt").read_text(encoding="utf-8")
    assert dumpsys.startswith("DUMP OF SERVICE package:") and "was the duration" not in dumpsys
    assert (out / "bugreport.zip").exists()


# --- the checks on a bug report ---------------------------------------------------------------------------------

def test_a_bug_report_is_checked_like_a_collection(tmp_path):
    path = _bugreport(tmp_path)
    r = _run(path)
    indicators = {h.indicator for h in r.hits}
    assert "com.spy.app" in indicators and "spy-c2.example" in indicators
    assert all(h.artifact.startswith(path) for h in r.hits)                 # evidence points at the bug report
    assert any("bug report made on the phone on 2026-11-13 10:00" in n for n in r.notes)
    ran = {c.name for c in r.checks if c.ran}
    assert {"android:packages", "android:settings", "android:history"} <= ran
    # an app deleted from the phone still shows in the battery history a bug report carries
    assert any(h.indicator == "com.removed.spy" and "REMOVED" in h.detail for h in r.hits)


def test_what_a_bug_report_cannot_hold_is_not_checked_never_clean(tmp_path):
    r = _run(_bugreport(tmp_path))
    gaps = {c.name: c.reason for c in r.checks if not c.ran}
    for check in ("android:processes", "android:files", "android:root", "android:messages",
                  "android:app-fingerprints", "android:app-certificates"):
        assert check in gaps, check
        assert gaps[check] == br.BR_NOT_IN_A_BUG_REPORT[check]
        assert "json" not in gaps[check] and "AndroidQF" not in gaps[check]


def test_the_report_never_talks_about_a_collection_or_androidqf(tmp_path):
    r = _run(_bugreport(tmp_path))
    gaps = [c.name for c in r.checks if not c.ran]
    assert len(gaps) == len(set(gaps))                                       # one gap per check
    text = " ".join(r.notes + [c.reason for c in r.checks if not c.ran] + [d.why for d in r.doors])
    for word in ("collection needs it", "not in the collection", "AndroidQF", "no SMS backup in the collection",
                 "The collection needed it"):
        assert word not in text, word
    assert any("A bug report does not need it" in n for n in r.notes)        # USB debugging was on in the report


def test_the_temporary_folder_is_removed(tmp_path, monkeypatch):
    made = []
    real = tempfile.mkdtemp
    monkeypatch.setattr(tempfile, "mkdtemp", lambda *a, **k: made.append(real(*a, **k)) or made[-1])
    _run(_bugreport(tmp_path))
    assert made and not os.path.exists(made[0])


def test_a_bug_report_without_an_app_list_says_so(tmp_path):
    r = _run(_bugreport(tmp_path, packages=False))
    assert any(c.name == "android:packages" and not c.ran and "no app list" in c.reason for c in r.checks)


def test_a_damaged_bug_report_is_a_gap_not_a_crash(tmp_path):
    path = tmp_path / "bugreport.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("main_entry.txt", "missing.txt")
        z.writestr("bugreport-a.txt", "== dumpstate: 2026-11-13 10:00:00\n")
    data = bytearray(path.read_bytes())
    data[-30:] = b"\0" * 30                                                   # break the ZIP directory
    path.write_bytes(bytes(data))
    r = _run(str(path))
    assert not r.hits and any(not c.ran for c in r.checks)


def test_the_intrusion_reader_says_a_bug_report_has_no_intrusion_logs(tmp_path):
    r = intrusion.run(ScanContext(iocs=_iocs(), emit=lambda _m: None, phone_path=_bugreport(tmp_path)))
    assert "does not contain Intrusion Logging" in (r.inapplicable_reason or "")
    assert not [c for c in r.checks if not c.ran]


def test_a_bug_report_is_sent_to_the_android_reader(tmp_path):
    from zbtriage.readers import reader_select
    ctx = ScanContext(iocs=_iocs(), emit=lambda _m: None, phone_path=_bugreport(tmp_path))
    names = [spec.name for spec in reader_select(ctx)]
    assert "android" in names and "ios" not in names


# --- running apps: a bug report names them in the activity manager's part ----------------------------------------

def _with_activity(tmp_path):
    text = _main_text().replace("------ 1.0s was the duration of 'DUMPSYS' ------",
                                "DUMP OF SERVICE activity:\n"
                                "ACTIVITY MANAGER RUNNING PROCESSES (dumpsys activity processes)\n"
                                "  *APP* UID 10234 ProcessRecord{1a2b3c 4321:com.spy.app:remote/u0a234}\n"
                                "  Process LRU list (sorted by oom_adj, 3 total):\n"
                                "    #0: fg     TOP  LCMN 1287:com.whatsapp/u0a123 act:activities\n"
                                "    #1: vis    BFGS ---- 2210:com.android.systemui/1000\n"
                                "--------- 0.020s was the duration of dumpsys activity, ending at: 2026-11-13\n"
                                + SEP + "\n------ 1.0s was the duration of 'DUMPSYS' ------")
    path = tmp_path / "bugreport-phone-UP1A-2026-11-13-10-00-00.zip"
    main = "bugreport-phone-UP1A-2026-11-13-10-00-00.txt"
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("main_entry.txt", main)
        z.writestr(main, text)
    return str(path)


def test_running_apps_in_a_bug_report_are_checked(tmp_path):
    r = _run(_with_activity(tmp_path))
    processes = [c for c in r.checks if c.name == "android:processes"]
    assert processes and all(c.ran for c in processes)
    assert any("running process com.spy.app:remote" in h.location or "running process" in h.detail
               for h in r.hits if h.indicator == "com.spy.app")


def test_running_apps_are_read_only_from_the_activity_manager_part():
    dumpsys = ("DUMP OF SERVICE alarm:\n  12:com.not.this/u0a1\n"
               "DUMP OF SERVICE activity:\n  ProcessRecord{1 99:com.example.app/u0a9}\n  99:com.example.app/u0a9\n")
    assert br.br_processes(dumpsys) == [(99, "com.example.app")]
