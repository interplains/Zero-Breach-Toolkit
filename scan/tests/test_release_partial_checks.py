"""Partly-done checks must never read as clean, and a ZIP's real list size bounds the work (found before release,
2026-11-14)."""
import os
import struct
import time
import zipfile
from unittest.mock import patch

import pytest

from zbtriage import bugreport, filecheck as fc, localpaths
from zbtriage.modules import doors
from zbtriage.result import ModuleResult


# 1. a refused folder next to a readable empty one is not "nothing waiting"
def test_a_refused_download_folder_is_not_a_clean_result(tmp_path):
    (tmp_path / "Downloads").mkdir()
    (tmp_path / "Desktop").mkdir()
    real = os.scandir

    def scandir(path):
        if os.path.basename(str(path)) == "Downloads":
            raise PermissionError("refused")
        return real(path)
    folders = [(str(tmp_path / "Downloads"), 2), (str(tmp_path / "Desktop"), 1)]
    r = ModuleResult("doors")
    with patch.object(doors, "dr_download_folders", lambda home: folders), patch("os.scandir", scandir):
        doors._check_downloads(r)
    door = [d for d in r.doors if d.door == "computer:remote-access-download"][0]
    assert door.state == "unknown" and "could not be opened" in door.title
    assert any(c.name == "remote-access-downloads-complete" and not c.ran for c in r.checks)


def test_a_capped_folder_is_not_a_clean_result(tmp_path, monkeypatch):
    d = tmp_path / "Downloads"
    d.mkdir()
    for i in range(12):
        (d / "f{}.txt".format(i)).write_bytes(b"")
    monkeypatch.setattr(doors, "_DR_DL_ENTRIES", 5)
    r = ModuleResult("doors")
    with patch.object(doors, "dr_download_folders", lambda home: [(str(d), 2)]):
        doors._check_downloads(r)
    door = [x for x in r.doors if x.door == "computer:remote-access-download"][0]
    assert door.state == "unknown"


# 2. unread drivers or an unreadable services list: not "none is on the list"
def test_unread_drivers_are_not_a_clean_result():
    r = ModuleResult("doors")
    doors.dr_driver_doors(r, [], 100, 2, True)
    door = [d for d in r.doors if d.door == "windows:known-bad-drivers"][0]
    assert door.state == "unknown" and "not all were checked" in door.title
    assert any(c.name == "windows-drivers-complete" and not c.ran for c in r.checks)
    r2 = ModuleResult("doors")
    doors.dr_driver_doors(r2, [], 100, 0, True, services_read=False)
    assert [d for d in r2.doors if d.door == "windows:known-bad-drivers"][0].state == "unknown"


def test_a_driver_file_that_no_longer_exists_is_not_a_gap(tmp_path):
    ok = tmp_path / "ok.sys"
    ok.write_bytes(b"x")
    _m, done, unread = doors.dr_fingerprint_files([str(ok), str(tmp_path / "gone.sys")], problem=lambda p: "")
    assert done == 1 and unread == 0
    r = ModuleResult("doors")
    doors.dr_driver_doors(r, [], done, unread, True)
    assert [d for d in r.doors if d.door == "windows:known-bad-drivers"][0].state == "closed"


# 3. a ZIP that declares 0 entries but carries a huge list of contents is refused
def test_a_zip_lying_about_its_entry_count_is_still_bounded(tmp_path, monkeypatch):
    path = tmp_path / "liar.zip"
    with zipfile.ZipFile(path, "w") as z:
        for i in range(50):
            z.writestr("f{}.txt".format(i), "x")
    data = bytearray(path.read_bytes())
    at = data.rfind(b"PK\x05\x06")
    struct.pack_into("<HH", data, at + 8, 0, 0)                   # declared entries: 0
    path.write_bytes(bytes(data))
    count, cd_size = bugreport.zip_directory(str(path))
    assert count == 0 and cd_size > 0
    monkeypatch.setattr(bugreport, "ZIP_MAX_DIRECTORY", 100)
    with pytest.raises(ValueError):
        bugreport.zip_open(str(path))


# 4. when the lists cannot be loaded, the file check says so
def test_a_file_check_without_its_lists_says_incomplete(tmp_path):
    path = tmp_path / "photo.jpg"
    path.write_bytes(b"\xff\xd8\xff" + b"\x00" * 100)
    rec = fc.fc_examine(str(path), None, lists_error="OSError: broken")
    assert rec["level"] == fc.FC_INCOMPLETE
    text = fc.fc_render(rec)
    assert "Incomplete" in text and "NOT compared" in text and "Nothing known was found" not in text


# 7. an interrupted bug report check is cleaned up by the stale-temp sweep
def test_bug_report_temp_folders_are_swept(tmp_path):
    old = tmp_path / "zb-bugreport-abc"
    old.mkdir()
    past = time.time() - 2 * localpaths.STALE_TEMP_AGE
    os.utime(old, (past, past))
    localpaths.sweep_stale_temp(base=str(tmp_path))
    assert not old.exists()
