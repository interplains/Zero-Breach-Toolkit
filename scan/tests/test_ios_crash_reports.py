"""Diagnostic (.ips) reports that do not start with Apple's JSON header line (issue #47).

On an iOS 27 backup seven reports failed with "Expecting value: line 1 column 1 (char 0)" and
the crash check was reported as not run. A byte-order mark in front of the JSON, and an
older plain-text report saved under an .ips name, are both readable and must be read; only a
report with nothing in it is a gap, and it must say so in plain words.
"""
from test_followup_fixes import bundle  # noqa: F401  (fixture used by `reader`)
from test_ios_real_world_layouts import PROCESS, _ips, _sysdiagnose, ctx, gaps, reader  # noqa: F401


def _jetsam():
    return _ips({"bug_type": "298", "timestamp": "2026-01-02 03:04:05.00 +0000"},
                {"processes": [{"name": PROCESS}]})


def test_byte_order_mark_before_the_json_header_is_read(tmp_path, reader):
    archive = _sysdiagnose(tmp_path, [("crashes_and_spins/JetsamEvent-1.ips", b"\xef\xbb\xbf" + _jetsam())])
    result = reader(ctx(archive, "sysdiagnose"))
    assert any(h.indicator == PROCESS for h in result.hits)
    assert gaps(result) == {}


def test_plain_text_report_with_an_ips_name_is_read(tmp_path, reader):
    text = ("Incident Identifier: 00000000-0000-0000-0000-000000000000\n"
            "Process:         " + PROCESS + " [123]\n"
            "Path:            /usr/libexec/" + PROCESS + "\n").encode()
    archive = _sysdiagnose(tmp_path, [("crashes_and_spins/" + PROCESS + "-2026-01-02.ips", text)])
    result = reader(ctx(archive, "sysdiagnose"))
    assert any(h.indicator == PROCESS for h in result.hits)
    assert gaps(result) == {}


def test_an_empty_report_is_a_gap_in_plain_words(tmp_path, reader):
    archive = _sysdiagnose(tmp_path, [("crashes_and_spins/JetsamEvent-2.ips", b"   \n")])
    result = reader(ctx(archive, "sysdiagnose"))
    reasons = " ".join(gaps(result).values())
    assert "diagnostic report is empty" in reasons
    assert "Expecting value" not in reasons


def test_ordinary_json_reports_are_unchanged(tmp_path, reader):
    archive = _sysdiagnose(tmp_path, [("crashes_and_spins/JetsamEvent-3.ips", _jetsam())])
    result = reader(ctx(archive, "sysdiagnose"))
    assert any(h.indicator == PROCESS for h in result.hits)
    assert gaps(result) == {}
