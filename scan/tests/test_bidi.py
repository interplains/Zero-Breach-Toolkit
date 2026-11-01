"""Right-to-left layout for the window: Windows/macOS only need the line edges
marked; Linux (X11) needs words, letters and joined forms done here."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import bidi  # noqa: E402

RLM = "‏"


@pytest.fixture(autouse=True)
def native_after():
    yield
    bidi.bidi_mode("win32")


def test_left_to_right_text_is_never_touched():
    for mode in ("win32", "x11"):
        bidi.bidi_mode(mode)
        assert bidi.bidi_line("Step 1 of 4: Browsers") == "Step 1 of 4: Browsers"


def test_native_mode_marks_both_ends_and_keeps_typing_order():
    bidi.bidi_mode("win32")
    line = "يفحص هذا الجهاز."
    assert bidi.bidi_line(line) == RLM + line + RLM
    assert bidi.bidi_line(RLM + line + RLM) == RLM + line + RLM   # never doubled


def test_manual_mode_orders_words_right_to_left_and_keeps_english_runs():
    bidi.bidi_mode("x11")
    out = bidi.bidi_line("يفحص Zero Breach الجهاز")
    words = out.split(" ")
    # The English name keeps its own order, between the two Arabic words, which swap sides.
    assert words[1:3] == ["Zero", "Breach"]
    assert bidi.bidi_shape("الجهاز")[::-1] == words[0]
    assert bidi.bidi_shape("يفحص")[::-1] == words[3]


def test_manual_mode_joins_arabic_letters():
    shaped = bidi.bidi_shape("بحث")          # initial, medial, final forms
    assert shaped == "ﺑﺤﺚ"
    assert bidi.bidi_shape("لا") == "ﻻ"   # lam-alef ligature
    # Dal, alef and reh never join to the letter after them: all three stand alone.
    assert bidi.bidi_shape("دار") == "\ufea9\ufe8d\ufead"


def test_hebrew_needs_no_joining_only_order():
    bidi.bidi_mode("x11")
    assert bidi.bidi_line("שלום עולם") == "םלוע םולש"


def test_wrapping_keeps_every_word_and_moves_indent_to_the_right():
    bidi.bidi_mode("win32")
    text = "    " + " ".join(["كلمة"] * 30)
    lines = bidi.bidi_wrap(text, len, 40).split("\n")
    assert len(lines) > 1
    assert all(line.endswith("    ") for line in lines)
    assert sum(line.count("كلمة") for line in lines) == 30


def test_manual_mode_keeps_an_english_word_with_an_arabic_comma_forwards():
    # "Cellebrite" followed by an Arabic comma came out as "etirbelleC".
    bidi.bidi_mode("x11")
    out = bidi.bidi_line("آثار Cellebrite، الأداة")
    assert "Cellebrite" in out and "etirbelleC" not in out
    # The comma belongs to the sentence, which reads right to left: it sits on
    # the word's left, between it and the next Arabic word.
    assert "،Cellebrite" in out
    assert "،Apple Devices" in bidi.bidi_line("Finder أو Apple Devices، أو")


def test_manual_mode_keeps_numbers_in_reading_order():
    bidi.bidi_mode("x11")
    assert "٢٠٢٦" in bidi.bidi_line("في عام ٢٠٢٦ تم")
    assert "15" in bidi.bidi_line("من 15 إلى 20")


def test_a_line_of_english_with_only_arabic_punctuation_is_still_right_to_left():
    bidi.bidi_mode("win32")
    assert bidi.bidi_line("Cellebrite، Pegasus").startswith(RLM)
