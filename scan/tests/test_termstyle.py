"""Colour and the in-place progress line in the terminal (2026-11-14)."""
import io

from zbtriage import termstyle as ts
from zbtriage.report import render_summary


def _doc(hits=(), gaps=()):
    return {"verdict": {"status": "INDICATORS_FOUND" if hits else "NO_INDICATORS", "gaps": list(gaps)},
            "modules": {"m": {"hits": list(hits), "checks": []}}, "doors": [], "worth_a_look": []}


def test_the_level_follows_the_evidence():
    assert ts.ts_level(_doc([{"tier": "primary", "evidence": "on-disk"}])) == "red"
    assert ts.ts_level(_doc([{"tier": "forensic", "evidence": "device-log"}])) == "red"
    assert ts.ts_level(_doc([{"tier": "delivery", "evidence": "contacted"}])) == "amber"
    assert ts.ts_level(_doc(gaps=["browser: locked"])) == "amber"


def test_only_the_result_line_and_headings_are_coloured():
    doc = _doc([{"tier": "primary", "evidence": "on-disk", "indicator": "x", "location": "y", "detail": "z"}])
    try:
        text = render_summary(doc)
    except Exception:                                   # a minimal document; the colouring is what is tested
        text = "\n".join(["=" * 72, "  IN PLAIN WORDS", "=" * 72, "  Result:        Spyware was found",
                          "                 on this device.", "  What it means: strongest", "", "  SUMMARY"])
    coloured = ts.ts_colour_report(text, doc)
    result_lines = [l for l in coloured.split("\n") if "Result:" in l]
    assert result_lines and result_lines[0].startswith(ts._RED)
    meaning = [l for l in coloured.split("\n") if "What it means" in l]
    assert meaning and "\x1b" not in meaning[0]
    assert ts.ts_colour_report(text, doc).replace(ts._RED, "").replace(ts._BOLD, "").replace(ts._RESET, "") == text


def test_off_where_it_does_not_belong(monkeypatch):
    assert not ts.ts_enabled(io.StringIO())             # piped or saved: never
    monkeypatch.setenv("NO_COLOR", "1")
    import sys
    assert not ts.ts_enabled(sys.stdout)


def test_progress_is_one_line_and_warnings_stay():
    out = io.StringIO()
    p = ts.TsProgress(out)
    p("[*] running check: browser")
    p("[browser]   still working: chrome (1,200 records checked so far)")
    p("WARNING: something went wrong")
    p("[*] running check: hash")
    p.finish()
    text = out.getvalue()
    assert "WARNING: something went wrong\n" in text
    assert text.count("\n") == 1                        # only the warning took its own line
    assert "Checking your browsers" in text and "Checking program files" in text
