"""Every separate tool's text goes through contract.safe_render: names from the network, a sender, a file in an
archive or a startup entry cannot put terminal escape codes or direction-changing characters on the screen."""
import importlib
import inspect
import os
import re

from zbtriage import mailcheck
from zbtriage.safetext import safe_render

PKG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "zbtriage")


def test_every_renderer_is_wrapped():
    missing = []
    for name in sorted(os.listdir(PKG)):
        if not name.endswith(".py") or name.startswith("_"):
            continue
        source = open(os.path.join(PKG, name), encoding="utf-8").read()
        for fn in re.findall(r"^def ([a-z]+_render(?:_[a-z]+)?)\(", source, re.M):
            if fn == "safe_render":                     # the wrapper itself
                continue
            module = importlib.import_module("zbtriage." + name[:-3])
            if not hasattr(getattr(module, fn), "__wrapped__"):
                missing.append("{}.{}".format(name, fn))
    assert not missing, "renderers without @safe_render: {}".format(missing)


def test_escape_codes_and_direction_marks_are_removed_but_lines_stay():
    @safe_render
    def render():
        return "a\x1b[2Jb\x07\n\tc‮d​e"
    assert render() == "a�[2Jb�\n\tc�de"


def test_a_crafted_sender_name_cannot_reach_the_terminal():
    raw = (b"From: \"Bank\x1b]0;owned\x07\x1b[2J\" <a@b.example>\r\nTo: you@example.org\r\nSubject: hi\r\n"
           b"Date: Thu, 12 Nov 2026 10:00:00 +0000\r\nMessage-ID: <x@b.example>\r\n\r\nhello\r\n")
    text = mailcheck.mc_render(mailcheck.mc_check(raw, None))
    assert "\x1b" not in text and "\x07" not in text
    assert "Bank" in text


def test_the_wrapper_keeps_the_renderer_signature():
    from zbtriage import linkcheck
    assert list(inspect.signature(linkcheck.lc_render).parameters) == ["result"]
