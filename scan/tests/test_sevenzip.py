"""7-Zip lists read from the header only (2026-11-14). The archives below were made by 7-Zip 24 from two tiny files:
readme.txt and sub/invoice.pdf.exe (the bytes "MZ"). "locked" uses a password with "encrypt file names"."""
import base64

from zbtriage import filecheck as fc
from zbtriage.sevenzip import sz_list

SEVENZIP = {
    "plain": (
        "N3q8ryccAAQ6RWB4iwAAAAAAAAAiAAAAAAAAAGHrrQ4BAAZoZWxsb01aAAAAgTMHrg/Oha6S96Bt85fwn+Bzo/TAs1AwBFuyzN0Q"
        "AUkVVt6gjN2pLlYfPXhcDIleM1Et7KotvKRON6WkuqnH4szv+/BzEbivwXq+dnlkrxjoQsKMLf2DPnArvBpa/+6iA6g71UeHIN5t"
        "ETipDhflwxanlEu3m8gfSbPnSXPAFwYLAQmAgAAHCwEAASMDAQEFXQAQAAAMgKoKATA8jtEAAA=="
    ),
    "locked": (
        "N3q8ryccAAQ+6rSCsAAAAAAAAAA+AAAAAAAAAFpO+IgNW5lAnop4hfVK3ZcfMwKPVWXorYJ/KeJR2SZI++zUOCZXN+IL4v4GWqZ/"
        "aPrExlBWLOCOyBpxIojTSKFcyesuG0HDKMJvFtJ0KcdcZ72qaULtouDhaVmwJwSBk1jNvqJTYapsr4gQe54ZCd+G6Bi1uNz+oEVr"
        "js2ch20vQKvxeJy4XNUzaClYfwiOWAJiVGbLDtOOEFsIplBvf2u4Tfyd2zzXBkrJwxErYa0yr4foVhcGEAEJgKAABwsBAAIkBvEH"
        "ARJTD+zOy3Obp5ua+7wxudQZc7MjAwEBBV0AEAAAAQAMgJuAygoBBHpNUQAA"
    ),
    "lzma1": (
        "N3q8ryccAAREmq6ojwAAAAAAAAAiAAAAAAAAABBZVOwANBlJ7o4CECxfAAAAAIEzB64PzpwGxQkqrtViZNtPpJxRmAh+N8C6PgZ8"
        "QA5iQywNpuV+QfPEZfazEV0FObg2aLvzqu8i5HhHDK+yBP6ESrAd91D9uLO369u+HR73AsTYCDlK9Lmq3niKCkZwjqN/ixCjf3fR"
        "pioFQR1YWpoRiqe6rPjqRDqfG6Vv+3lwuxcGDAEJgIMABwsBAAEjAwEBBV0AEAAADIC6CgFzi4bEAAA="
    ),
}


def _write(tmp_path, key):
    path = tmp_path / (key + ".7z")
    path.write_bytes(base64.b64decode("".join(SEVENZIP[key])))
    return str(path)


def test_a_7z_list_is_read_with_a_compressed_header(tmp_path):
    for key in ("plain", "lzma1"):
        listed = sz_list(_write(tmp_path, key))
        names = sorted(n for n, folder in listed["files"] if not folder)
        assert names == ["readme.txt", "sub/invoice.pdf.exe"] and not listed["problem"], (key, listed)


def test_a_disguised_program_in_a_7z_is_worth_a_look(tmp_path):
    rec = fc.fc_examine(_write(tmp_path, "plain"))
    assert rec["level"] == fc.FC_LOOK and "sub/invoice.pdf.exe" in rec["archive"]["risky"]
    assert any("two endings" in t for t in rec["archive"]["tricks"])


def test_locked_file_names_are_said_to_be_locked(tmp_path):
    listed = sz_list(_write(tmp_path, "locked"))
    assert listed["encrypted"] and not listed["files"]
    rec = fc.fc_examine(_write(tmp_path, "locked"))
    assert rec["level"] == fc.FC_LOOK and "hidden behind the password" in fc.fc_render(rec)


def test_a_damaged_7z_is_incomplete_not_a_crash(tmp_path):
    raw = bytearray(base64.b64decode("".join(SEVENZIP["plain"])))
    raw[-20:] = b"\xff" * 20                      # the list of files at the end is ruined
    path = tmp_path / "bad.7z"
    path.write_bytes(bytes(raw))
    rec = fc.fc_examine(str(path))
    assert rec["level"] in (fc.FC_INCOMPLETE, fc.FC_LOOK) and rec["archive"].get("problem")
