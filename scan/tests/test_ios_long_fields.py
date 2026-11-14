"""Long iPhone text fields (issue #47: three Shortcuts definitions over 64 KB were skipped whole).

A field up to _IA_FIELD_MAX is searched in overlapping windows, so a match beyond the old
64 KB limit, or straddling a window boundary, is still found. Only a larger field is a gap.
"""
from zbtriage import ios_artifacts

from test_followup_fixes import bundle  # noqa: F401  (fixture used by `reader`)
from test_ios_upgrade import DOMAIN, EMAIL, backup, ctx, db_bytes, reader  # noqa: F401

SCHEMA = ("CREATE TABLE ZSHORTCUT(Z_PK INTEGER PRIMARY KEY, ZNAME, ZWORKFLOWACTIONS, ZCREATIONDATE);"
          "CREATE TABLE ZSHORTCUTACTIONS(Z_PK INTEGER PRIMARY KEY, ZDATA, ZSHORTCUT)")


def _shortcut_backup(tmp_path, name):
    raw, _ = db_bytes(tmp_path, SCHEMA, [("INSERT INTO ZSHORTCUT VALUES(1, ?, '', 0)", (name,))])
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/Shortcuts/Shortcuts.sqlite", raw)])
    return root


def _gaps(result):
    return {c.name: c.reason for c in result.checks if not c.ran}


def _place(text, at, value):
    return text[:at] + value + text[at + len(value):]


def test_match_beyond_the_old_64kb_limit_is_found(tmp_path, reader):
    name = _place("x " * 100000, 150000, " " + DOMAIN + " ")
    result = reader(ctx(_shortcut_backup(tmp_path, name)))
    assert any(h.indicator == DOMAIN for h in result.hits)
    assert "ios:shortcuts" not in _gaps(result)


def test_match_straddling_a_window_boundary_is_found(tmp_path, reader):
    at = ios_artifacts._IA_FIELD_WINDOW - 5          # starts in window one, ends in window two
    name = _place("x " * 100000, at, " " + DOMAIN + " ")
    result = reader(ctx(_shortcut_backup(tmp_path, name)))
    assert any(h.indicator == DOMAIN for h in result.hits)


def test_email_in_a_long_field_is_found_once(tmp_path, reader):
    name = _place("x " * 100000, 120000, " " + EMAIL + " ")
    result = reader(ctx(_shortcut_backup(tmp_path, name)))
    assert len([h for h in result.hits if h.indicator == EMAIL]) == 1


def test_a_field_too_big_to_read_is_still_a_gap(tmp_path, reader):
    # Over the 8 MB text cap. On Python 3.11+ SQLite itself refuses anything over 2 MB first
    # (localpaths sets SQLITE_LIMIT_LENGTH); Python 3.8-3.10 have no setlimit, so the text cap is
    # what stops it. Either way: not run, no false match. (A 3 MB field passed on 3.11+ only.)
    name = "x" * (ios_artifacts._IA_FIELD_MAX + 1024) + " " + DOMAIN
    result = reader(ctx(_shortcut_backup(tmp_path, name)))
    assert "ios:shortcuts" in _gaps(result)
    assert not any(h.indicator == DOMAIN for h in result.hits)
