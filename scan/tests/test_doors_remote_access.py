"""Remote-access programs: the additions taken from LOLRMM, and copies downloaded but never installed.
No real system is read: program names are given, folders are built in a temporary directory."""
import fnmatch
import os
import re

import pytest

from zbtriage.accessdata import ACCESS_FILES, ACCESS_PROGRAMS, OWN_ACCESS_PROGRAMS
from zbtriage.modules import doors
from zbtriage.result import ModuleResult
from zbtriage.rmmdata import RMM_PROGRAMS


def test_added_remote_access_programs_are_recognised():
    found = {p: k for p, k, _m in doors.dr_match_programs(
        ["UltraViewer 6.6", "ToDesk", "Sunlogin Remote Control", "HopToDesk 1.4", "NetSupport Manager (client)",
         "Veyon 4.8", "Pulseway Agent", "RDP Wrapper Library"])}
    assert found["UltraViewer"] == "remote" and found["ToDesk"] == "remote"
    assert found["Sunlogin (Oray)"] == "remote" and found["HopToDesk"] == "remote"
    assert found["Veyon (classroom monitoring)"] == "monitoring"
    assert "Pulseway" in found and "RDP Wrapper (unofficial multi-user Remote Desktop)" in found
    # NetSupport's "Client" is the side being controlled (client32.exe, which criminals deliver): it is a way in.
    assert any(p.startswith("NetSupport") for p in found)


EVERYDAY_PROGRAMS = [
    # the traps found while choosing what to take from LOLRMM: none of these is a way into the computer
    "NVDA", "NVDA (Non-Visual Desktop Access)", "GoTo Meeting", "GoTo Opener", "Cisco Webex Meetings", "Webex",
    "QQ", "WeChat", "NateOn", "PuTTY release 0.81", "WinSCP 6.3", "MobaXterm", "mRemoteNG", "Remmina",
    "Remote Desktop Connection Manager", "Microsoft Remote Desktop", "Quick Assist", "Tailscale", "ZeroTier One",
    "cloudflared", "ngrok", "MEGAsync", "Syncthing", "Duplicati 2", "Yandex.Disk", "IDrive", "Insync",
    "Synergy", "Mouse without Borders", "Duet Display", "ESET Security", "Sophos Endpoint Agent",
    "SentinelOne Agent", "Rapid7 Insight Agent", "Tanium Client", "Zabbix Agent 2", "Absolute Persistence",
    "Faronics Deep Freeze", "Ninite", "Iperius Backup", "Wonderware InTouch", "HyperSnap 9", "Git",
    "Visual Studio Code", "Level", "Roster Manager", "Acronis True Image", "Laplink PCmover", "Adobe Connect",
    "Basecamp 3",
    # everyday software
    "Zoom Workplace", "Microsoft Teams", "Slack", "Discord", "Signal", "Telegram Desktop", "WhatsApp", "Skype",
    "Steam", "Epic Games Launcher", "Battle.net", "GOG GALAXY", "Mozilla Firefox", "Google Chrome",
    "Microsoft Edge", "Brave", "Opera GX", "Tor Browser", "7-Zip 24.08", "WinRAR", "VLC media player",
    "OBS Studio", "Audacity", "GIMP", "LibreOffice", "Adobe Acrobat", "Notepad++", "Python 3.12", "Node.js",
    "Docker Desktop", "Oracle VirtualBox", "VMware Workstation", "Wireshark", "Npcap", "KeePassXC", "Bitwarden",
    "1Password", "VeraCrypt", "Proton VPN", "Mullvad VPN", "NordVPN", "WireGuard", "OpenVPN Connect",
    "Malwarebytes", "Avast Free Antivirus", "Bitdefender Total Security", "Norton 360", "Kaspersky Plus",
    "Dropbox", "Google Drive", "Microsoft OneDrive", "iCloud", "iTunes", "Apple Devices", "Phone Link",
    "Samsung DeX", "Samsung Smart Switch", "Dell SupportAssist", "HP Support Assistant", "Lenovo Vantage",
    "NVIDIA GeForce Experience", "Logitech Options+", "Razer Synapse", "HWiNFO64", "CPU-Z", "CrystalDiskInfo",
    "Rufus", "Ventoy", "qBittorrent", "FileZilla Client", "Postman", "JetBrains Toolbox",
    "PyCharm Community Edition", "Android Studio", "Visual Studio Community 2022", "SQL Server Management Studio",
    "Parallels Desktop", "Macrium Reflect", "Garmin Express", "Spotify", "Netflix",
]


def test_everyday_programs_are_never_called_remote_access():
    assert doors.dr_match_programs(EVERYDAY_PROGRAMS) == []


@pytest.mark.parametrize("name, program", [
    ("AnyDesk.exe", "AnyDesk"), ("AnyDesk (1).exe", "AnyDesk"), ("anydesk-ab12.exe", "AnyDesk"),
    ("TeamViewerQS_x64.exe", "TeamViewer"), ("RustDesk-1.3.2-x86_64.exe", "RustDesk"),
    ("UltraViewer_Desktop.exe", "UltraViewer"), ("todesk_setup.exe", "ToDesk"),
    ("Support-LogMeInRescue.exe", "LogMeIn"), ("ScreenConnect.ClientSetup.msi", "ConnectWise ScreenConnect / Control"),
    ("AnyDesk.app", "AnyDesk"), ("AnyDesk.dmg", "AnyDesk"),
])
def test_downloaded_remote_access_program_names(name, program):
    assert doors.dr_match_download(name)[0] == program


@pytest.mark.parametrize("name", [
    "invoice.pdf", "AnyDesk.exe.txt", "AnyDesk-manual.pdf", "svchost.exe", "explorer.exe", "GoTo Opener.exe",
    "winpty-agent.exe", "zohomeeting.exe", "iperius.exe", "Git-2.47.0-64-bit.exe", "VSCodeUserSetup-x64.exe",
    "ZoomInstaller.exe", "vlc-3.0.21-win64.exe", "putty.exe", "WinSCP-6.3-Setup.exe", "tvnviewer.exe",
])
def test_ordinary_downloads_are_not_remote_access(name):
    assert doors.dr_match_download(name) is None


def test_no_file_pattern_can_match_a_windows_program():
    system = ["svchost.exe", "explorer.exe", "lsass.exe", "csrss.exe", "winlogon.exe", "services.exe",
              "rundll32.exe", "dllhost.exe", "conhost.exe", "taskhostw.exe", "msiexec.exe", "cmd.exe",
              "powershell.exe", "mstsc.exe", "msra.exe", "quickassist.exe"]
    assert not [(p, s) for _n, _k, p in ACCESS_FILES for s in system if fnmatch.fnmatchcase(s, p)]


def test_added_data_is_consistent_with_our_own_list():
    names = [n for n, _k, _rx in ACCESS_PROGRAMS]
    assert len(names) == len(set(names))
    for _n, kind, rx in ACCESS_PROGRAMS:
        assert kind in ("remote", "monitoring")
        re.compile(rx)
    own = [re.compile(rx, re.I) for _n, _k, rx in OWN_ACCESS_PROGRAMS]
    assert not [n for n, _k, _rx in RMM_PROGRAMS if any(o.search(n) for o in own)]   # our entry always wins
    assert {n for n, _k, _p in ACCESS_FILES} <= set(names)
    assert all(p == p.lower() and p.endswith(doors._DR_DL_EXT) for _n, _k, p in ACCESS_FILES)


def _tree(root, files, dirs=()):
    for rel in dirs:
        (root / rel).mkdir(parents=True, exist_ok=True)
    for rel in files:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(b"MZ")


def test_downloads_are_read_to_the_stated_depth(tmp_path):
    _tree(tmp_path, ["Downloads/AnyDesk.exe", "Downloads/unzipped/RustDesk-1.3.exe", "Downloads/a/b/ToDesk.exe",
                     "Desktop/UltraViewer_Desktop.exe", "Desktop/sub/HopToDesk.exe", "Documents/report.pdf"],
          dirs=["Downloads/AnyDesk.exe.d", "Desktop/AnyDesk.exe"])
    found, seen, capped, opened, _refused = doors.dr_scan_downloads(doors.dr_download_folders(str(tmp_path)))
    assert sorted(p for p, _k, _path in found) == ["AnyDesk", "RustDesk", "UltraViewer"]
    assert not capped and seen > 0 and opened == 3
    # a folder named like a program is not a program
    assert not any(path == str(tmp_path / "Desktop" / "AnyDesk.exe") for _p, _k, path in found)


def test_a_mac_app_bundle_in_downloads_is_recognised(tmp_path):
    _tree(tmp_path, ["Downloads/AnyDesk.app/Contents/Info.plist"])
    found, _seen, _capped, _opened, _refused = doors.dr_scan_downloads(doors.dr_download_folders(str(tmp_path)))
    assert [p for p, _k, _path in found] == ["AnyDesk"]


def test_links_are_not_followed(tmp_path):
    outside = tmp_path / "outside"
    _tree(outside, ["AnyDesk.exe"])
    (tmp_path / "home" / "Downloads").mkdir(parents=True)
    try:
        os.symlink(str(outside), str(tmp_path / "home" / "Downloads" / "linked"), target_is_directory=True)
        os.symlink(str(outside / "AnyDesk.exe"), str(tmp_path / "home" / "Downloads" / "AnyDesk.exe"))
    except (OSError, NotImplementedError):
        pytest.skip("this system does not allow creating links")
    found, _seen, _capped, _opened, _refused = doors.dr_scan_downloads(doors.dr_download_folders(str(tmp_path / "home")))
    assert found == []


def test_a_huge_downloads_folder_is_read_in_part_and_says_so(tmp_path, monkeypatch):
    _tree(tmp_path, ["Downloads/f{}.txt".format(i) for i in range(10)])
    monkeypatch.setattr(doors, "_DR_DL_ENTRIES", 3)
    _found, seen, capped, opened, _refused = doors.dr_scan_downloads(doors.dr_download_folders(str(tmp_path)))
    assert capped and seen == 3


def test_downloaded_program_door_and_closed_door(tmp_path, monkeypatch):
    _tree(tmp_path, ["Downloads/AnyDesk (2).exe", "Downloads/Sorillus Launcher.exe"])
    monkeypatch.setattr(doors, "dr_download_folders", lambda home: [(str(tmp_path / "Downloads"), 2)])
    r = ModuleResult("doors")
    doors._check_downloads(r)
    by_title = {d.title: d for d in r.doors}
    remote = by_title["A remote-access program is waiting in your files: AnyDesk"]
    assert remote.state == "open" and remote.severity == "medium" and "AnyDesk (2).exe" in remote.observed
    assert by_title["A monitoring program is waiting in your files: Sorillus"].severity == "high"
    assert any(c.name == "remote-access-downloads" and c.ran for c in r.checks)
    empty = tmp_path / "empty"
    empty.mkdir()
    monkeypatch.setattr(doors, "dr_download_folders", lambda home: [(str(empty), 2)])
    r2 = ModuleResult("doors")
    doors._check_downloads(r2)
    assert [d.state for d in r2.doors] == ["closed"]


def test_goto_meeting_launcher_is_not_remote_access():
    assert doors.dr_match_programs(["GoTo Opener", "GoTo Meeting 10.19"]) == []
    assert doors.dr_match_programs(["GoTo Resolve Unattended"])[0][0] == "GoTo Resolve / GoTo Assist"
