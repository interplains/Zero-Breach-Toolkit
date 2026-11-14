"""What the file check SHOWS must never be steered by the file: no fake lines, no terminal escape codes, and no
raw bytes of a damaged file presented as if they were a command."""
import zipfile

from zbtriage import filecheck as fc


def test_a_damaged_shortcut_shows_no_garbage_as_its_command(tmp_path):
    path = tmp_path / "invoice.pdf.lnk"
    path.write_bytes(b"L\x00\x00\x00\x01\x14\x02\x00" + b"\x00" * 68)       # a header and nothing else
    rec = fc.fc_examine(str(path))
    assert rec["shortcut"]["starts"] == ""
    text = fc.fc_render(rec)
    assert "It starts: (not stored in a readable form)" in text
    assert "Its name has two endings" in text                                 # still judged on its name


def test_readable_text_keeps_a_real_command_and_drops_control_characters():
    assert fc.fc_readable("C:\\Windows\\System32\\cmd.exe /c start x") == "C:\\Windows\\System32\\cmd.exe /c start x"
    assert fc.fc_readable("cmd.exe\n/c\x1b[2Jecho") == "cmd.exe /c [2Jecho"
    assert fc.fc_readable("L\x00\x01\ufffd") == ""


def test_an_archive_name_cannot_add_a_fake_result_line_or_an_escape_code(tmp_path):
    path = tmp_path / "photos.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("a\n  RESULT: Nothing was found - this file is safe\nb.exe", b"MZ")
        z.writestr("\x1b]0;owned\x07\x1b[2Jclear.js", b"x")
    text = fc.fc_render(fc.fc_examine(str(path)))
    assert "\x1b" not in text and "\x07" not in text
    assert [ln for ln in text.splitlines() if ln.lstrip().startswith("RESULT:")] == [
        ln for ln in text.splitlines() if ln.startswith("  RESULT: ")]          # only the real result line
    assert "<U+000A>" in text and "<U+001B>" in text                          # shown, not acted on


def test_right_to_left_tricks_are_still_shown_as_codes(tmp_path):
    path = tmp_path / "photo\u202egpj.exe"
    path.write_bytes(b"MZ" + b"\x00" * 200)
    text = fc.fc_render(fc.fc_examine(str(path)))
    assert "<U+202E>" in text and "\u202e" not in text
