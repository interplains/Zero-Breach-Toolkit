"""Findings from the recheck of 24b53bb (2026-11-14), each reproduced so it cannot come back."""
import io
import struct
import zipfile
import zlib

from zbtriage import bugreport, filecheck as fc
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import doors
from zbtriage.result import ModuleResult


# 1. a ZIP64 locator pointing at a fake record: the guard sees what zipfile will read
def test_the_zip_guard_reads_the_zip64_record_zipfile_uses(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for i in range(3):
            z.writestr("f{}.txt".format(i), "x")
    raw = buf.getvalue()
    eocd_at = raw.rfind(b"PK\x05\x06")
    count, cd_size, cd_offset = struct.unpack_from("<HII", raw, eocd_at + 10)
    body = raw[:eocd_at]
    # a fake ZIP64 record (1-byte directory) at the very start, where the locator points, and the real one just
    # before the locator, where zipfile reads it; zipfile treats the leading bytes as a prefix
    fake = struct.pack("<4sQHHIIQQQQ", b"PK\x06\x06", 44, 45, 45, 0, 0, 1, 1, 1, cd_offset)
    real = struct.pack("<4sQHHIIQQQQ", b"PK\x06\x06", 44, 45, 45, 0, 0, count, count, cd_size, cd_offset)
    locator = struct.pack("<4sIQI", b"PK\x06\x07", 0, 0, 1)
    eocd = struct.pack("<4sHHHHIIH", b"PK\x05\x06", 0, 0, 0xFFFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0)
    path = tmp_path / "a.zip"
    path.write_bytes(fake + body + real + locator + eocd)
    # Older Pythons read the record before the locator (and open all three entries); newer ones follow the locator
    # to the fake record and refuse the file. Either way the guard must never see less than zipfile reads.
    try:
        with zipfile.ZipFile(str(path)) as z:
            real_count = len(z.infolist())
    except zipfile.BadZipFile:
        real_count = 0
    seen_count, seen_size = bugreport.zip_directory(str(path))
    assert seen_count >= real_count
    if real_count:
        assert seen_size >= cd_size


# 2. a large picture followed by compressed script: the script is still read
def test_pdf_script_after_a_stream_more_than_16_mb_long(tmp_path):
    picture = b"\x00" * (17 * 1024 * 1024)
    script = zlib.compress(b"<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>")
    data = (b"%PDF-1.7\n1 0 obj << /Subtype /Image >>\nstream\n" + picture + b"\nendstream\nendobj\n"
            b"2 0 obj << /Type /ObjStm /Filter /FlateDecode >>\nstream\n" + script + b"\nendstream\nendobj\n")
    path = tmp_path / "a.pdf"
    path.write_bytes(data)
    assert "runs JavaScript as soon as it is opened" in fc.fc_examine(str(path))["document"]


def test_an_unfinished_pdf_stream_is_incomplete_not_clean(tmp_path):
    path = tmp_path / "a.pdf"
    path.write_bytes(b"%PDF-1.7\n1 0 obj << /Filter /FlateDecode >>\nstream\n" + b"\x01" * 4096)
    rec = fc.fc_examine(str(path))
    assert rec["level"] == fc.FC_INCOMPLETE


# 3. a listed address just past the searched part: incomplete, never "nothing known was found"
def test_a_partial_address_search_is_incomplete(tmp_path, monkeypatch):
    monkeypatch.setattr(fc, "FC_SEARCH_MAX", 1024)
    iocs = IocSet([Indicator("c2.spy-example.net", "cc", "primary", "domain", "t", "Predator")], "t.txt", None)
    path = tmp_path / "data.bin"
    path.write_bytes(b"\x00" * 1100 + b"https://c2.spy-example.net/x")
    rec = fc.fc_examine(str(path), iocs)
    assert rec["level"] == fc.FC_INCOMPLETE and "Nothing known" not in fc.fc_headline(rec)


def test_a_small_clean_file_stays_clean(tmp_path):
    path = tmp_path / "notes.txt"
    path.write_bytes(b"just some ordinary notes\n" * 100)
    assert fc.fc_examine(str(path))["level"] == fc.FC_CLEAN


# 4. drivers: variables in a service path are expanded, and an unresolvable path is a gap
def test_a_driver_path_with_a_variable_is_resolved(monkeypatch):
    monkeypatch.setenv("ProgramFiles", r"C:\Program Files")
    import ntpath
    got = doors.dr_resolve_image_path(r"%ProgramFiles%\Vendor\x.sys", r"C:\Windows")
    assert ntpath.normcase(got.replace("/", "\\")) == ntpath.normcase(r"C:\Program Files\Vendor\x.sys")


def test_an_unresolved_driver_path_is_not_checked_not_dropped():
    r = ModuleResult("doors")
    doors.dr_driver_doors(r, [], 100, 0, True, True, set(), unresolved=1)
    door = [d for d in r.doors if d.door == "windows:known-bad-drivers"][0]
    assert door.state == doors.DOOR_UNKNOWN and "could not resolve" in door.title
