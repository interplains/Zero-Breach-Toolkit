"""Right-to-left text for the window.

On Windows and macOS, Tk hands each line to the system, which lays out an
Arabic, Persian or Hebrew line correctly (words right to left, letters joined).
What it gets wrong is the edges: every line is treated as left-to-right overall,
so a full stop, colon or number at the end of a line lands on the wrong side. So
the window wraps right-to-left text itself and puts a right-to-left mark at both
ends of every displayed line ("native" mode, measured on Windows 11 / Tk 8.6).

Tk on Linux (X11) draws text with no right-to-left support: letters come out
unjoined and in typing order. There the words and letters are put in display
order here, and Arabic letters are given their joined forms ("manual" mode).

Only the window uses this. Reports saved to a file keep the ordinary (logical)
order, which every text editor lays out by itself.
"""

_MARKS = "‎‏‪‫‬‭‮⁦⁧⁨⁩"
_RLM = "‏"
_bidi_state = {"mode": "native"}


def bidi_mode(windowing_system):
    """Set from Tk's windowing system: 'x11' needs the manual layout."""
    _bidi_state["mode"] = "manual" if windowing_system == "x11" else "native"
    return _bidi_state["mode"]


def bidi_rtl_char(c):
    return "֐" <= c <= "ࣿ" or "יִ" <= c <= "﷿" or "ﹰ" <= c <= "﻾"


def _direction(token):
    """R for a word with right-to-left letters, L for one with other letters or
    digits (numbers read left to right in every script), R for right-to-left
    punctuation alone, "" for anything else. An English word with an Arabic
    comma ("Cellebrite،") is an English word: counting the comma made it R, and
    on Linux it was shown backwards."""
    for c in token:
        if bidi_rtl_char(c) and c.isalpha():
            return "R"
    for c in token:
        if c.isalnum():
            return "L"
    for c in token:
        if bidi_rtl_char(c):
            return "R"
    return ""


def _rtl_punctuation(c):
    return bidi_rtl_char(c) and not c.isalnum()


_SENTENCE_END = ".,:;!?"


def _left_word(word):
    """A left-to-right word inside right-to-left text, with right-to-left
    punctuation that belongs to the sentence (an Arabic comma, question mark)
    moved to the side the sentence reads it on. A plain full stop, comma or
    colon straight after a Latin word ("Android.") belongs to the sentence too;
    it is moved unless it is part of the word (an address, "e.g.", a number)."""
    core = word.rstrip("".join(c for c in word if _rtl_punctuation(c)))
    last = core.rsplit(" ", 1)[-1]
    if (core == word and len(last) > 1 and last[-1] in _SENTENCE_END and last[-2].isascii()
            and last[-2].isalpha() and not any(c in last[:-1] for c in ".@/:\\")):
        core = core[:-1]
    trail = word[len(core):]
    body = core.lstrip("".join(c for c in core if _rtl_punctuation(c)))
    lead = core[:len(core) - len(body)]
    return trail + body + lead


# --- manual mode (X11): Arabic joining and visual order --------------------
# letter: (isolated, final, initial, medial); a letter with only two forms
# joins to the letter before it but never to the one after.
_FORMS = {
    "ء": ("ﺀ",), "آ": ("ﺁ", "ﺂ"), "أ": ("ﺃ", "ﺄ"),
    "ؤ": ("ﺅ", "ﺆ"), "إ": ("ﺇ", "ﺈ"), "ئ": ("ﺉ", "ﺊ", "ﺋ", "ﺌ"),
    "ا": ("ﺍ", "ﺎ"), "ب": ("ﺏ", "ﺐ", "ﺑ", "ﺒ"), "ة": ("ﺓ", "ﺔ"),
    "ت": ("ﺕ", "ﺖ", "ﺗ", "ﺘ"), "ث": ("ﺙ", "ﺚ", "ﺛ", "ﺜ"),
    "ج": ("ﺝ", "ﺞ", "ﺟ", "ﺠ"), "ح": ("ﺡ", "ﺢ", "ﺣ", "ﺤ"),
    "خ": ("ﺥ", "ﺦ", "ﺧ", "ﺨ"), "د": ("ﺩ", "ﺪ"), "ذ": ("ﺫ", "ﺬ"),
    "ر": ("ﺭ", "ﺮ"), "ز": ("ﺯ", "ﺰ"), "س": ("ﺱ", "ﺲ", "ﺳ", "ﺴ"),
    "ش": ("ﺵ", "ﺶ", "ﺷ", "ﺸ"), "ص": ("ﺹ", "ﺺ", "ﺻ", "ﺼ"),
    "ض": ("ﺽ", "ﺾ", "ﺿ", "ﻀ"), "ط": ("ﻁ", "ﻂ", "ﻃ", "ﻄ"),
    "ظ": ("ﻅ", "ﻆ", "ﻇ", "ﻈ"), "ع": ("ﻉ", "ﻊ", "ﻋ", "ﻌ"),
    "غ": ("ﻍ", "ﻎ", "ﻏ", "ﻐ"), "ف": ("ﻑ", "ﻒ", "ﻓ", "ﻔ"),
    "ق": ("ﻕ", "ﻖ", "ﻗ", "ﻘ"), "ك": ("ﻙ", "ﻚ", "ﻛ", "ﻜ"),
    "ل": ("ﻝ", "ﻞ", "ﻟ", "ﻠ"), "م": ("ﻡ", "ﻢ", "ﻣ", "ﻤ"),
    "ن": ("ﻥ", "ﻦ", "ﻧ", "ﻨ"), "ه": ("ﻩ", "ﻪ", "ﻫ", "ﻬ"),
    "و": ("ﻭ", "ﻮ"), "ى": ("ﻯ", "ﻰ"), "ي": ("ﻱ", "ﻲ", "ﻳ", "ﻴ"),
    # Persian and Urdu letters
    "پ": ("ﭖ", "ﭗ", "ﭘ", "ﭙ"), "چ": ("ﭺ", "ﭻ", "ﭼ", "ﭽ"),
    "ژ": ("ﮊ", "ﮋ"), "ک": ("ﮎ", "ﮏ", "ﮐ", "ﮑ"),
    "گ": ("ﮒ", "ﮓ", "ﮔ", "ﮕ"), "ی": ("ﯼ", "ﯽ", "ﯾ", "ﯿ"),
}
_LAM_ALEF = {"آ": ("ﻵ", "ﻶ"), "أ": ("ﻷ", "ﻸ"),
             "إ": ("ﻹ", "ﻺ"), "ا": ("ﻻ", "ﻼ")}
_TRANSPARENT = set("ًٌٍَُِّْٰ")
_MIRROR = {"(": ")", ")": "(", "[": "]", "]": "[", "{": "}", "}": "{", "<": ">", ">": "<",
           "«": "»", "»": "«"}


def _joins_after(c):
    return len(_FORMS.get(c, ())) == 4


def bidi_shape(word):
    """Arabic letters in their joined presentation forms (manual mode only)."""
    out = []
    letters = [c for c in word]
    i = 0
    while i < len(letters):
        c = letters[i]
        if c not in _FORMS:
            out.append(c)
            i += 1
            continue
        prev = next((p for p in reversed(letters[:i]) if p not in _TRANSPARENT), None)
        joined_before = prev is not None and _joins_after(prev) and prev in _FORMS
        if c == "ل" and i + 1 < len(letters) and letters[i + 1] in _LAM_ALEF:
            out.append(_LAM_ALEF[letters[i + 1]][1 if joined_before else 0])
            i += 2
            continue
        nxt = next((n for n in letters[i + 1:] if n not in _TRANSPARENT), None)
        joins_next = _joins_after(c) and nxt in _FORMS
        forms = _FORMS[c]
        if len(forms) == 1:
            out.append(forms[0])
        elif joined_before and joins_next:
            out.append(forms[3])
        elif joined_before:
            out.append(forms[1])
        elif joins_next:
            out.append(forms[2])
        else:
            out.append(forms[0])
        i += 1
    return "".join(out)


def _manual_line(line):
    tokens = line.split(" ")
    runs = []
    for token in tokens:
        d = _direction(token)
        if runs and (d == "" or d == runs[-1][0]):
            runs[-1][1].append(token)
        else:
            runs.append([d or "R", [token]])
    out = []
    for d, words in reversed(runs):
        if d == "R":
            out.extend("".join(_MIRROR.get(c, c) for c in reversed(bidi_shape(w))) for w in reversed(words))
        else:
            # A run of English words reads left to right as a whole; only
            # sentence punctuation at its ends moves ("Apple Devices،").
            out.append(_left_word(" ".join(words)))
    return " ".join(out)


# --- both modes ---------------------------------------------------------------
def bidi_line(line):
    """One displayed line of right-to-left text, ready for a Tk widget."""
    line = "".join(c for c in line if c not in _MARKS)
    if not any(bidi_rtl_char(c) for c in line):
        return line
    if _bidi_state["mode"] == "manual":
        return _manual_line(line)
    return _RLM + line + _RLM


# Tk 8.6 on Windows draws a right-to-left line longer than about 200 UTF-8 bytes
# in two swapped pieces (measured: 204 bytes fine, 211 split). Native lines are
# therefore kept under 180 bytes, however wide the window is.
_NATIVE_LINE_BYTES = 180


def _too_long(line):
    return _bidi_state["mode"] == "native" and len(line.encode("utf-8")) > _NATIVE_LINE_BYTES


def bidi_wrap(text, measure, width):
    """Wrap text to `width` pixels (measure(str) -> pixels) and return the
    displayed lines, each made ready by bidi_line. Leading indentation becomes
    trailing, since the text is aligned to the right."""
    lines = []
    for paragraph in str(text).split("\n"):
        stripped = paragraph.lstrip(" ")
        indent = paragraph[:len(paragraph) - len(stripped)]
        if not stripped:
            lines.append("")
            continue
        current = ""
        for word in stripped.split(" "):
            candidate = (current + " " + word) if current else word
            if current and (measure(candidate + indent) > width or _too_long(candidate)):
                lines.append(bidi_line(current) + indent)
                current = word
            else:
                current = candidate
        lines.append(bidi_line(current) + indent)
    return "\n".join(lines)
