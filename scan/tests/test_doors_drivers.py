"""Windows drivers: known vulnerable or malicious drivers, the vulnerable driver blocklist and memory integrity.
Decisions only: no real driver, registry or Windows report is read."""
import hashlib
import os
import re

import pytest

from zbtriage import driverdata
from zbtriage.modules import doors
from zbtriage.result import ModuleResult


@pytest.mark.parametrize("raw, expected", [
    (r"\SystemRoot\System32\drivers\acpi.sys", r"C:\Windows\System32\drivers\acpi.sys"),
    (r"System32\drivers\disk.sys", r"C:\Windows\System32\drivers\disk.sys"),
    (r"\??\C:\ProgramData\tool\rtcore64.sys", r"C:\ProgramData\tool\rtcore64.sys"),
    (r'"C:\Program Files\Vendor\drv.sys"', r"C:\Program Files\Vendor\drv.sys"),
    (r"%SystemRoot%\System32\drivers\x.sys", r"C:\Windows\System32\drivers\x.sys"),
    (r"\\server\share\evil.sys", ""),                 # a network path is never opened
    (r"\Device\HarddiskVolume3\x.sys", ""),
    ("x.sys", ""), ("", ""), (None, ""),
])
def test_driver_service_paths_are_resolved_or_refused(raw, expected):
    got = doors.dr_resolve_image_path(raw, r"C:\Windows")
    assert got.replace("/", "\\") == expected.replace("/", "\\") if expected else got == ""


def test_the_shipped_driver_list_is_well_formed():
    assert len(driverdata.DRIVER_SHA256) > 1500
    for table, size in ((driverdata.DRIVER_SHA256, 64), (driverdata.DRIVER_SHA1, 40)):
        for h, (kind, name) in table.items():
            assert re.fullmatch(r"[0-9a-f]{%d}" % size, h)
            assert kind in ("v", "m") and name.lower().endswith(".sys")
    kinds = {k for k, _n in driverdata.DRIVER_SHA256.values()}
    assert kinds == {"v", "m"}


def _write(path, data):
    path.write_bytes(data)
    return str(path)


def test_a_listed_fingerprint_is_found_and_others_are_not(tmp_path, monkeypatch):
    bad = _write(tmp_path / "rtcore64.sys", b"pretend vulnerable driver")
    good = _write(tmp_path / "ordinary.sys", b"an ordinary driver")
    monkeypatch.setattr(doors, "DRIVER_SHA256",
                        {hashlib.sha256(b"pretend vulnerable driver").hexdigest(): ("v", "RTCore64.sys")})
    matches, done, unread = doors.dr_fingerprint_files([bad, good, bad], problem=lambda p: "")
    assert matches == [(bad, "v", "RTCore64.sys")] and done == 2 and unread == 0   # the duplicate is read once


def test_sha1_is_used_when_a_sample_has_no_sha256(tmp_path, monkeypatch):
    path = _write(tmp_path / "old.sys", b"old sample")
    monkeypatch.setattr(doors, "DRIVER_SHA256", {})
    monkeypatch.setattr(doors, "DRIVER_SHA1", {hashlib.sha1(b"old sample").hexdigest(): ("m", "old.sys")})
    assert doors.dr_fingerprint_files([path], problem=lambda p: "")[0] == [(path, "m", "old.sys")]


def test_refused_missing_and_oversized_files_are_not_read(tmp_path, monkeypatch):
    big = _write(tmp_path / "big.sys", b"x" * 100)
    ok = _write(tmp_path / "ok.sys", b"y")
    monkeypatch.setattr(doors, "_DR_DRV_MAX_FILE", 50)
    _m, done, unread = doors.dr_fingerprint_files(
        [big, ok, str(tmp_path / "missing.sys"), str(tmp_path / "linked.sys")],
        problem=lambda p: "refused" if p.endswith("linked.sys") else "")
    assert done == 1 and unread == 2       # big + refused; a file that no longer exists is not "unread"


def test_driver_doors(monkeypatch):
    r = ModuleResult("doors")
    doors.dr_driver_doors(r, [(r"C:\Windows\System32\drivers\evil.sys", "m", "evil.sys"),
                              (r"C:\Windows\System32\drivers\RTCore64.sys", "v", "RTCore64.sys")], 500, 2, True)
    by_title = {d.title: d for d in r.doors}
    assert by_title["A driver known to be malicious is installed: evil.sys"].severity == "high"
    vuln = by_title["A driver with a known security hole is installed: RTCore64.sys"]
    assert vuln.severity == "medium" and vuln.setting == "windowsdefender://coreisolation"
    assert any(c.name == "windows-drivers" and c.ran for c in r.checks)
    assert any("2 could not be read" in n for n in r.notes)


def test_a_registered_driver_in_a_program_folder_is_installed():
    # Paths outside System32\drivers come from a registered driver service: the driver IS installed.
    r = ModuleResult("doors")
    doors.dr_driver_doors(r, [(r"C:\Program Files\GIGABYTE\Lib\MyPortIO_x64.sys", "v", "myportio_x64.sys")],
                          10, 0, True)
    titles = [d.title for d in r.doors]
    assert "A driver with a known security hole is installed: MyPortIO_x64.sys" in titles


def test_the_blocklist_is_enforced_whenever_memory_integrity_runs():
    door = doors.dr_blocklist_door(0, 22631, True)
    assert door.state == "closed" and "enforced" in door.title
    off = doors.dr_blocklist_door(0, 22631, False)
    assert off.state == "open" and "someone turned it off" not in off.why


def test_downloads_on_linux_and_localised_folders(tmp_path):
    assert doors.dr_match_download("anydesk_6.3.0-1_amd64.deb") == ("AnyDesk", "remote")
    assert doors.dr_match_download("rustdesk-1.3.2-x86_64 (1).AppImage") == ("RustDesk", "remote")
    cfg = tmp_path / ".config"
    cfg.mkdir()
    (cfg / "user-dirs.dirs").write_text('XDG_DOWNLOAD_DIR="$HOME/Descargas"\n', encoding="utf-8")
    folders = [f for f, _ in doors.dr_download_folders(str(tmp_path))]
    assert str(tmp_path / "Descargas") in folders


def test_no_listed_driver_is_a_closed_door_only_when_drivers_were_read():
    r = ModuleResult("doors")
    doors.dr_driver_doors(r, [], 480, 0, True)
    assert [d.state for d in r.doors] == ["closed"]
    for folder_read in (True, False):
        r2 = ModuleResult("doors")
        doors.dr_driver_doors(r2, [], 0, 7, folder_read)
        assert [d.state for d in r2.doors] == ["unknown"]
        assert any(c.name == "windows-drivers" and not c.ran for c in r2.checks)


@pytest.mark.parametrize("value, build, hvci, state", [
    (0, 26200, True, "closed"),          # memory integrity running enforces the list whatever the setting says
    (0, 26200, False, "open"),           # switched off, nothing else enforcing it
    (1, 19045, False, "closed"),
    (None, 26200, False, "closed"),      # on by default from Windows 11 22H2
    (None, 22621, False, "closed"),
    (None, 19045, False, "open"),        # Windows 10: only with memory integrity
    (None, 19045, True, "closed"),
    (None, 0, False, "unknown"),
])
def test_vulnerable_driver_blocklist(value, build, hvci, state):
    assert doors.dr_blocklist_door(value, build, hvci).state == state


@pytest.mark.parametrize("running, configured, registry, state, title_part", [
    (True, True, 1, "closed", "is on"),
    (False, True, 1, "open", "set to on but is not running"),   # an incompatible driver, or a pending restart
    (False, False, 1, "open", "set to on but is not running"),
    (False, False, 0, "open", "is off"),
    (False, False, None, "open", "is off"),
    (None, None, 0, "open", "is off"),
    (None, None, 1, "unknown", "whether it is running could not be read"),
    (None, None, None, "unknown", "could not be read"),
])
def test_memory_integrity(running, configured, registry, state, title_part):
    door = doors.dr_memory_integrity_door(running, configured, registry)
    assert door.state == state and title_part in door.title


def test_memory_integrity_names_the_drivers_that_may_block_it():
    door = doors.dr_memory_integrity_door(False, True, 1, ["MsIo64.sys", "AmdTools64.sys", "MsIo64.sys"])
    assert "AmdTools64.sys, MsIo64.sys" in door.fix
    assert "known holes" not in doors.dr_memory_integrity_door(False, True, 1).fix
    assert doors.dr_memory_integrity_door(True, True, 1, ["MsIo64.sys"]).state == "closed"


@pytest.mark.parametrize("text, expected", [
    ("Running=0;Configured=2", (False, True)),
    ("Running=1,2;Configured=1,2", (True, True)),
    ("Running=;Configured=", (False, False)),
    ("Get-CimInstance : Invalid namespace", (None, None)),
    ("", (None, None)),
])
def test_device_guard_report(text, expected):
    assert doors.dr_device_guard(text) == expected


def test_driver_check_runs_only_on_windows(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(doors.sys, "platform", "linux")
    called = []
    monkeypatch.setattr(doors, "_check_windows_drivers", lambda r: called.append(1))
    for name in ("_check_programs", "_check_downloads", "_check_linux", "_check_browsers"):
        monkeypatch.setattr(doors, name, lambda r: None)
    doors.run(SimpleNamespace(partial=None))
    assert called == []
