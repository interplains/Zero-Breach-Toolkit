"""Choosing from the terminal menu with the arrow keys - and still by typing (2026-11-14)."""
import io

import pytest

from zbtriage import menu, menukeys as mk

LABELS = ["First", "Second", "Third"]


def _pick(keys, start=1):
    out = io.StringIO()
    return mk.mk_select(LABELS, out.write, iter(keys), start=start), out.getvalue()


def test_arrows_move_and_enter_chooses():
    assert _pick(["down", "down", "enter"])[0] == "3"
    assert _pick(["up", "enter"])[0] == "3"                  # wraps round from the top
    assert _pick(["down", "down", "down", "enter"])[0] == "1"  # and from the bottom
    assert _pick(["enter"])[0] == "1"                        # Enter alone keeps the old default, 1


def test_typing_still_works():
    assert _pick(["2", "enter"])[0] == "2"
    assert _pick(["1", "2", "enter"])[0] == "12"             # out of range: the menu says so, as before
    assert _pick(["3", "backspace", "1", "enter"])[0] == "1"
    assert _pick(["?"])[0] == "?"
    assert _pick(["0"])[0] == "0"
    assert _pick(["q"])[0] == "0"


def test_end_of_input_and_ctrl_c():
    assert _pick(["down", "end"])[0] is None
    with pytest.raises(KeyboardInterrupt):
        _pick(["interrupt"])


def test_only_one_line_is_redrawn_with_no_terminal_codes():
    _choice, shown = _pick(["down", "down", "enter"])
    assert "\x1b" not in shown and shown.count("\n") == 1 and "Third" in shown


def test_off_where_keys_cannot_be_read(monkeypatch):
    assert not mk.mk_supported(io.StringIO(), io.StringIO())          # not a terminal
    monkeypatch.setenv("ZB_PLAIN_MENU", "1")
    import sys
    assert not mk.mk_supported(sys.stdin, sys.stderr)


def test_the_menu_falls_back_to_typing_when_keys_are_off():
    from zbtriage.cli import _parse
    args = _parse(["--no-banner"])
    out = io.StringIO()
    assert menu.choose_scan(args, lambda: None, stdin=io.StringIO("1\n"), stderr=out, stdout_visible=True)
    assert "up/down" not in out.getvalue()
