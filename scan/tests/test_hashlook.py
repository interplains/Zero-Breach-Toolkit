"""Hash look-up: fingerprints, file kinds, imphash as pefile computes it, signer names, offline matches, and the
online services through a fake transport - only fingerprints leave, only after consent, only to allowed hosts."""
import hashlib
import json
import os
import struct
import sys

import pytest

from zbtriage import hashlook as hl
from zbtriage.iocs import Indicator, IocSet


def tiny_pe(imports):
    """A minimal PE32 with one section holding an import table. imports: [(dll, [name or ordinal int])]."""
    va, raw = 0x1000, 0x200
    blob = bytearray(0x800)
    desc_at = 0
    pos = 20 * (len(imports) + 1)
    descs = []
    for dll, funcs in imports:
        name_at = pos
        blob[pos:pos + len(dll) + 1] = dll.encode() + b"\x00"
        pos += len(dll) + 2
        thunk_at = pos
        pos += 4 * (len(funcs) + 1)
        thunks = []
        for f in funcs:
            if isinstance(f, int):
                thunks.append(0x80000000 | f)
            else:
                thunks.append(va + pos)
                blob[pos:pos + 2 + len(f) + 1] = b"\x00\x00" + f.encode("latin-1") + b"\x00"
                pos += 2 + len(f) + 2
        for i, t in enumerate(thunks):
            struct.pack_into("<I", blob, thunk_at + 4 * i, t)
        descs.append((va + thunk_at, va + name_at))
    for i, (thunk, name) in enumerate(descs):
        struct.pack_into("<IIIII", blob, desc_at + 20 * i, thunk, 0, 0, name, thunk)
    head = bytearray(raw)
    head[0:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, 0x40)
    head[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", head, 0x44, 0x14C, 1, 1700000000, 0, 0, 224, 0x102)
    opt = 0x58
    struct.pack_into("<H", head, opt, 0x10B)
    struct.pack_into("<I", head, opt + 92, 16)
    struct.pack_into("<II", head, opt + 96 + 8, va + desc_at, 20 * len(imports))
    struct.pack_into("<8sIIII", head, opt + 224, b".idata", len(blob), va, len(blob), raw)
    return bytes(head) + bytes(blob)


def test_imphash_matches_the_pefile_definition():
    pe = tiny_pe([("KERNEL32.dll", ["LoadLibraryA", "GetProcAddress"]), ("WS2_32.dll", [115, 9999]),
                  ("custom.drv", [7, "Bad Name!"])])
    expected = hashlib.md5(b"kernel32.loadlibrarya,kernel32.getprocaddress,ws2_32.wsastartup,ws2_32.ord9999,"
                           b"custom.drv.ord7,custom.drv.*invalid*").hexdigest()
    info = hl.hl_pe(pe)
    assert info["imphash"] == expected
    assert info["compiled_utc"] == "2023-11-14"


def test_not_a_pe_and_broken_pe_are_harmless():
    assert hl.hl_pe(b"hello") == {}
    assert hl.hl_pe(b"MZ" + b"\xff" * 100) == {}
    assert isinstance(hl.hl_pe(tiny_pe([("a.dll", ["f"])])[:300]), dict)


def test_kinds_come_from_content_not_names():
    assert hl.hl_kind(b"MZ\x90", "invoice.pdf") == "windows-program"
    assert hl.hl_kind(b"%PDF-1.7", "x") == "document"
    assert hl.hl_kind(b"PK\x03\x04", "app.apk") == "android-app"
    assert hl.hl_kind(b"\x7fELF", "") == "linux-program"
    assert hl.hl_kind(b"#!/bin/sh", "") == "script"
    assert hl.hl_kind(b"\x89PNG", "photo.png") == "other"


def test_hashes_are_right(tmp_path):
    f = tmp_path / "a.bin"
    data = os.urandom(3 * 1024 * 1024 + 7)
    f.write_bytes(data)
    r = hl.hl_hashes(str(f))
    assert r["sha256"] == hashlib.sha256(data).hexdigest() and r["md5"] == hashlib.md5(data).hexdigest()
    assert r["sha1"] == hashlib.sha1(data).hexdigest() and r["size"] == len(data)


@pytest.mark.skipif(sys.platform != "win32", reason="reads a signed Windows program")
def test_signer_name_of_a_real_signed_program():
    r = hl.hl_examine(sys.executable)
    assert r["signature"] == "signed" and "Python Software Foundation" in r.get("signer", "")


def test_offline_match_is_known_threat(tmp_path):
    f = tmp_path / "spy.exe"
    f.write_bytes(b"MZ" + os.urandom(100))
    digest = hashlib.sha256(f.read_bytes()).hexdigest()
    iocs = IocSet([Indicator(digest, "file", "primary", "sha256", "amnesty-test", "Pegasus")], "t", 0)
    result = hl.hl_run([str(tmp_path)], iocs)
    assert result["level"] == hl.HL_KNOWN and "Pegasus" in result["files"][0]["verdict"]


class FakeHttp:
    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        for prefix, reply in self.answers.items():
            if url.startswith(prefix):
                return reply(body) if callable(reply) else reply
        return 404, b""


def _files(tmp_path, n=3):
    out = []
    for i in range(n):
        f = tmp_path / "f{}.exe".format(i)
        f.write_bytes(b"MZ" + bytes([i]) * 50)
        out.append(str(f))
    return out


def _records(paths):
    return [hl.hl_examine(p, None, sign=lambda p: "not-signed") for p in paths]


def test_only_fingerprints_are_sent_and_answers_are_read(tmp_path):
    recs = _records(_files(tmp_path))
    bad, good = recs[0], recs[1]

    def circl(body):
        asked = json.loads(body)["hashes"]
        assert all(len(h) == 40 for h in asked)
        return 200, json.dumps([{"SHA-1": good["sha1"].upper(), "ProductName": "Notepad",
                                 "hashlookup:trust": 90}]).encode()

    def bazaar(body):
        if bad["sha256"].encode() in body:
            return 200, json.dumps({"query_status": "ok", "data": [{"signature": "AgentTesla",
                                                                    "first_seen": "2024-01-02 03:04:05"}]}).encode()
        return 200, b'{"query_status": "hash_not_found"}'
    http = FakeHttp({"https://hashlookup.circl.lu/": circl, "https://mb-api.abuse.ch/": bazaar})
    hl.hl_online(recs, ["circl", "malwarebazaar"], {"abusech": "K"}, http)
    for _m, url, headers, body in http.calls:
        text = (url + json.dumps(headers) + (body or b"").decode()).lower()
        assert str(tmp_path).lower() not in text and "f0.exe" not in text
    report = hl.hl_report(recs)
    assert report["level"] == hl.HL_KNOWN
    assert "AgentTesla" in recs[0]["verdict"] and "first seen 2024" in recs[0]["verdict"]
    assert recs[1]["verdict"].startswith("known good") and "Notepad" in recs[1]["verdict"]
    assert "not the same as safe" in recs[2]["verdict"]


def test_virustotal_counts_and_hybrid_verdicts(tmp_path):
    recs = _records(_files(tmp_path, 2))
    vt = json.dumps({"data": {"attributes": {"last_analysis_stats": {"malicious": 2, "suspicious": 0,
                                                                     "undetected": 60},
                                             "first_submission_date": 1700000000}}}).encode()
    http = FakeHttp({"https://www.virustotal.com/api/v3/files/" + recs[0]["sha256"]: (200, vt),
                     "https://hybrid-analysis.com/": lambda b: (200, json.dumps(
                         [{"verdict": "malicious", "threat_score": 100, "vx_family": "Pegasus"}]).encode())
                     if recs[1]["sha256"].encode() in b else (200, b"[]")})
    hl.hl_online(recs, ["virustotal", "hybrid"], {"virustotal": "V", "hybrid": "H"}, http, sleep=lambda s: None)
    hl.hl_report(recs)
    assert recs[0]["level"] == hl.HL_LOOK and "2 of 62 engines" in recs[0]["verdict"]
    assert recs[1]["level"] == hl.HL_KNOWN and "Pegasus" in recs[1]["verdict"]
    hybrid_call = [c for c in http.calls if "hybrid" in c[1]][0]
    assert hybrid_call[2]["User-Agent"] == "Falcon Sandbox" and hybrid_call[2]["api-key"] == "H"


def test_missing_keys_are_explained_and_skipped(tmp_path):
    recs = _records(_files(tmp_path, 1))
    http = FakeHttp({})
    notes = hl.hl_online(recs, ["virustotal", "threatfox"], {}, http)
    assert not http.calls and any("virustotal.com" in n for n in notes) and any("auth.abuse.ch" in n for n in notes)


def test_signed_files_and_photos_are_not_sent(tmp_path):
    exe = tmp_path / "signed.exe"
    exe.write_bytes(b"MZ" + b"\x01" * 40)
    photo = tmp_path / "me.jpg"
    photo.write_bytes(b"\xff\xd8\xff" + b"\x02" * 40)
    recs = [hl.hl_examine(str(exe), None, sign=lambda p: "signed"), hl.hl_examine(str(photo))]
    http = FakeHttp({})
    hl.hl_online(recs, ["circl"], {}, http)
    assert http.calls == []


def test_cache_answers_the_second_time(tmp_path):
    recs = _records(_files(tmp_path, 1))
    cache = hl.HlCache(str(tmp_path / "cfg"))
    http = FakeHttp({"https://mb-api.abuse.ch/": (200, b'{"query_status": "hash_not_found"}')})
    hl.hl_online(recs, ["malwarebazaar"], {"abusech": "K"}, http, cache=cache)
    again = hl.HlCache(str(tmp_path / "cfg"))
    http2 = FakeHttp({})
    hl.hl_online(_records([recs[0]["path"]]), ["malwarebazaar"], {"abusech": "K"}, http2, cache=again)
    assert len(http.calls) == 1 and http2.calls == []


def test_virustotal_free_key_limit(tmp_path):
    recs = _records(_files(tmp_path, 25))
    http = FakeHttp({"https://www.virustotal.com/": (404, b"")})
    waits = []
    notes = hl.hl_online(recs, ["virustotal"], {"virustotal": "V"}, http, sleep=waits.append)
    assert len(http.calls) == hl.HL_VT_FREE_LIMIT and len(waits) == hl.HL_VT_FREE_LIMIT - 1
    assert any("4 a minute" in n for n in notes)


def test_declining_consent_sends_nothing(tmp_path, monkeypatch):
    _files(tmp_path, 2)
    http = FakeHttp({})
    result = hl.hl_run([str(tmp_path)], None, ["circl"], keys={}, http=http, config_dir=str(tmp_path / "c"),
                       confirm=lambda text: False)
    assert http.calls == [] and "nothing was looked up online" in result["notes"]


def test_transport_refuses_other_hosts():
    with pytest.raises(hl.HlError):
        hl.hl_http("GET", "https://evil.example/files/x", {}, None)
    with pytest.raises(hl.HlError):
        hl.hl_http("GET", "http://hashlookup.circl.lu/lookup/sha1/x", {}, None)


def test_keys_are_saved_privately_and_env_wins(tmp_path, monkeypatch):
    path = hl.hl_save_key("virustotal", "abc", str(tmp_path))
    assert hl.hl_keys(str(tmp_path)) == {"virustotal": "abc"}
    monkeypatch.setenv("ZB_VIRUSTOTAL_KEY", "fromenv")
    assert hl.hl_keys(str(tmp_path))["virustotal"] == "fromenv"
    if sys.platform != "win32":
        assert oct(os.stat(path).st_mode & 0o777) == "0o600"


def test_services_parse():
    assert hl.hl_parse_services("all") == list(hl.HL_SERVICES)
    assert hl.hl_parse_services("circl, virustotal") == ["circl", "virustotal"]
    with pytest.raises(hl.HlError):
        hl.hl_parse_services("google")


def test_render_says_what_left_the_computer(tmp_path):
    result = hl.hl_run(_files(tmp_path, 1), None)
    assert "nothing was sent anywhere" in hl.hl_render(result)


# --- entry points --------------------------------------------------------------------------------------------
from test_followup_fixes import bundle  # noqa: E402,F401  (pytest fixture)


def test_bundle_runs_the_hash_lookup_offline(bundle, capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(bundle, "reader_run", lambda *a, **k: pytest.fail("a computer scan must not start"),
                        raising=False)
    f = _files(tmp_path, 1)[0]
    assert bundle._bundle_main(["--no-menu", "--no-banner", "--no-feeds", "--hash-lookup", f]) == 0
    assert "HASH LOOK-UP" in capsys.readouterr().out


def test_online_needs_a_hash_lookup():
    from zbtriage import cli
    with pytest.raises(SystemExit):
        cli._parse(["--online", "circl"])
