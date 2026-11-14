"""Text from outside (a scanned file, a network name, an email sender) made safe to show on a screen.

Kept in its own small module with no package imports so that every other module - including the separate tools
that come before contract.py in the single-file build - can use it.
"""
import functools
import re

# Control and direction-changing characters: terminal escape codes, and text that displays differently from what
# it is. Line feed (\x0a) and tab (\x09) are deliberately NOT in this set.
ST_CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f  ‪-‮⁦-⁩]")
# Invisible formatting characters, removed outright.
ST_INVISIBLE = re.compile("[\xad᠎​-‏⁠-⁤﻿]")


def st_line(text) -> str:
    """One value from outside, kept on ONE line: every control, invisible or direction-changing character -
    line breaks included - shown as <U+XXXX>. For a name taken from a file (a signer, a path on Linux) that is
    printed inside a line of a result, where a line break could add a forged line."""
    import unicodedata
    return "".join("<U+{:04X}>".format(ord(c)) if unicodedata.category(c)[0] == "C" or unicodedata.category(c)
                   in ("Zl", "Zp") else c for c in str(text))


ST_WIDTH = 78


def st_wrap_lines(lines, width: int = ST_WIDTH):
    """Report lines kept within `width`, broken between words (a terminal breaks them mid-word otherwise). A
    continuation lines up under the text it continues: after "- " for a list item, after "open: " for a device's
    ports, else under the line's own indent."""
    import textwrap
    out = []
    for line in lines:
        if len(line) <= width or not line.strip():
            out.append(line)
            continue
        lead = len(line) - len(line.lstrip(" "))
        body = line.lstrip(" ")
        hang = lead + 2 if body.startswith("- ") else lead + 6 if body.startswith("open: ") else lead
        out += textwrap.wrap(line, width=width, subsequent_indent=" " * hang, break_long_words=False,
                             break_on_hyphens=False) or [line]
    return out


def safe_render(render):
    """For every separate tool's renderer: whatever text the tool shows (names from the network, a sender, a
    file inside an archive, a startup entry) cannot carry terminal escape codes or direction-changing characters
    to the screen. Line feeds and tabs stay, as in contract.sanitize_untrusted, but nothing is cut short.
    Not re-wrapped here on purpose: re-wrapping text a tool already broke at ~100 columns leaves ragged fragments,
    and it would split codes that must stay on one line (the helper package's read-aloud numbers). Tools that
    need it call st_wrap_lines themselves."""
    @functools.wraps(render)
    def wrapped(*args, **kwargs):
        text = render(*args, **kwargs)
        return ST_CONTROL.sub("�", ST_INVISIBLE.sub("", text)) if isinstance(text, str) else text
    return wrapped
