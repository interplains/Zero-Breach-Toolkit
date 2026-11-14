"""Remote-access, download-folder, driver and option findings checked before release (2026-11-14)."""
import os
from unittest.mock import patch

import pytest

from zbtriage.modules import doors
from zbtriage.result import ModuleResult


@pytest.mark.parametrize("name", ["ScreenConnect Client (5a2b9c)", "ConnectWise Control Client (1234)",
                                  "Bomgar Jump Client", "NetSupport Manager Client", "Comodo One Client"])
def test_agents_named_client_are_found(name):
    assert doors.dr_match_programs([name])


@pytest.mark.parametrize("name", ["RealVNC Viewer", "com.logmein.GoToMeeting.G2MUpdate", "com.logmein.gotoopener",
                                  "LogMeIn Hamachi Tunneling Engine", "SpyShelter Anti-Keylogger",
                                  "Zemana AntiKeylogger"])
def test_viewers_meeting_apps_and_anti_keyloggers_are_not_flagged(name):
    assert not doors.dr_match_programs([name])


def test_real_remote_tools_and_keyloggers_still_are():
    assert doors.dr_match_programs(["LogMeIn Rescue"]) and doors.dr_match_programs(["Revealer Keylogger Free"])


@pytest.mark.parametrize("name", ["UltraViewer_setup_6.6_en.exe", "AnyViewerSetup.exe", "LogMeInRescue.exe",
                                  "GoToAssist_Customer.exe", "GoToResolve.exe", "AteraAgentSetup.msi",
                                  "NinjaOne-Agent.msi", "dwagent.exe", "ToDesk_Lite.exe"])
def test_common_scam_downloads_are_recognised(name):
    assert doors.dr_match_download(name)


def test_the_real_windows_folders_and_any_onedrive_are_included(tmp_path):
    (tmp_path / "OneDrive - Contoso").mkdir()
    folders = [f for f, _ in doors.dr_download_folders(str(tmp_path), shell=[(r"D:\Downloads", 2)])]
    assert r"D:\Downloads" in folders
    assert str(tmp_path / "OneDrive - Contoso" / "Desktop") in folders


def test_32_bit_python_on_64_bit_windows_says_so(monkeypatch):
    monkeypatch.setattr(doors, "_dr_wow64", lambda: True)
    r = ModuleResult("doors")
    doors._check_programs(r)
    assert any(c.name == "remote-access-software" and not c.ran for c in r.checks)
    assert all(d.state == "unknown" for d in r.doors)


@pytest.mark.parametrize("extra", [["--describe"], ["--undo-fix", "x.json"], ["--phone-guide", "android"]])
def test_separate_checks_refuse_every_other_operation(extra):
    from zbtriage.cli import _parse
    with pytest.raises(SystemExit):
        _parse(["--threat-warning"] + extra)


def test_the_public_dns_lists_are_not_known_good():
    from zbtriage.feeds import FEED_FILE_SHA256, KNOWN_GOOD_SOURCES
    ids = {s["id"] for s in KNOWN_GOOD_SOURCES}
    assert not [i for i in ids if "public-dns" in i]
    assert not [i for i in FEED_FILE_SHA256 if "public-dns" in i]
