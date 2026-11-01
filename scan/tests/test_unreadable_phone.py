"""A phone that could not be opened is never shown as clean (2.0.1, BUG 6).

An encrypted iPhone backup that cannot be decrypted (cryptography missing, or no
password) must show the amber "could not be checked" result, never the green
"No known spyware traces found". A readable backup stays green.
"""
import datetime
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zbtriage import gui, report
from zbtriage.modules import ios
from test_evidence_safety import _ctx
from test_ios_upgrade import backup, db_bytes

UNREAD_TITLE = "This phone could not be checked"


def _sms(tmp_path, text):
    raw, _ = db_bytes(tmp_path, "CREATE TABLE message(text,date,is_from_me)",
                      [("INSERT INTO message VALUES(?,700000000,0)", (text,))])
    return raw


def _document(ctx, result):
    doc = report.build_document(ctx.iocs, [result], datetime.datetime(2026, 11, 1, 12, 0, 0))
    doc["scope"] = {"phone": True, "scan_type": "phone"}
    return doc


@pytest.mark.parametrize("password", ["owner-password", ""])
def test_encrypted_backup_without_cryptography_is_not_green(tmp_path, monkeypatch, password):
    root = tmp_path / "backup"
    # Built while cryptography is available; the scan below runs as if it were not.
    backup(root, [("HomeDomain", "Library/SMS/sms.db", _sms(tmp_path, "fixture.invalid"))],
           encrypted=True, modern=True)
    # Hide the package and every submodule already imported: a cached submodule
    # would otherwise still import, and the test would prove nothing.
    for name in [m for m in sys.modules if m == "cryptography" or m.startswith("cryptography.")]:
        monkeypatch.setitem(sys.modules, name, None)
    ctx = _ctx(root, backup_password=password)
    doc = _document(ctx, ios.run(ctx))

    assert report.phone_source_unread(doc)
    colour, title, subtitle = gui.gui_headline(doc)
    assert colour == gui.GUI_WARN
    assert title == UNREAD_TITLE
    assert "not a clean result" in subtitle
    assert "No known spyware traces found" not in " ".join(gui.gui_next_steps(doc))
    summary = " ".join(report.render_summary(doc).split())
    assert "could not be opened" in summary
    assert "no known indicator was found" not in summary


def test_readable_backup_with_gaps_is_neutral_not_green(tmp_path):
    # 2.0.3: this test used to pin GREEN for a readable backup. An ordinary
    # backup always has parts that could not be checked (artifacts it does not
    # hold), and green with gaps contradicted "a gap, never a clean result".
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/SMS/sms.db", _sms(tmp_path, "nothing to see here"))])
    ctx = _ctx(root)
    doc = _document(ctx, ios.run(ctx))

    assert not report.phone_source_unread(doc)
    assert doc["verdict"]["gaps"]
    colour, title, subtitle = gui.gui_headline(doc)
    assert colour == gui.GUI_NEUTRAL and colour != gui.GUI_GOOD
    assert title == "Nothing found in what could be checked"
    assert "could not run" in subtitle
    assert UNREAD_TITLE not in report.render_summary(doc)


def test_unreadable_android_collection_is_not_green():
    doc = {"scope": {"phone": True},
           "modules": {"android": {"checks": [{"name": "android", "ran": False,
                                               "reason": "not an AndroidQF collection folder"}]}},
           "verdict": {"status": report.V_NONE_WITH_GAPS, "gaps": []}}
    assert report.phone_source_unread(doc)
    assert gui.gui_headline(doc)[1] == UNREAD_TITLE


def test_a_computer_scan_with_the_same_check_is_unaffected():
    # 2.0.3: still never "unread" (only phone scans can be); with gaps the
    # headline is the neutral one, no longer green.
    doc = {"scope": {"phone": False},
           "modules": {"android": {"checks": [{"name": "android", "ran": False, "reason": "x"}]}},
           "verdict": {"status": report.V_NONE_WITH_GAPS, "gaps": []}}
    assert not report.phone_source_unread(doc)
    assert gui.gui_headline(doc)[1] == "Nothing found in what could be checked"


def test_a_platform_that_read_something_is_not_unread():
    # 2.0.3: "read" is evidence that records were parsed, not a check name.
    doc = {"scope": {"phone": True},
           "modules": {"android": {"checks": [{"name": "android", "ran": False, "reason": "x"},
                                               {"name": "android:packages", "ran": True}],
                                   "submetrics": {"phone_records_read": 4}}},
           "verdict": {"status": report.V_NONE_WITH_GAPS, "gaps": []}}
    assert not report.phone_source_unread(doc)


def test_checks_that_ran_without_reading_anything_are_still_unread():
    doc = {"scope": {"phone": True},
           "modules": {"ios": {"checks": [{"name": "ios:input", "ran": True},
                                          {"name": "ios:manifest", "ran": True}],
                               "submetrics": {"phone_records_read": 0}}},
           "verdict": {"status": report.V_NONE_WITH_GAPS, "gaps": ["ios/ios:messages: x"]}}
    assert report.phone_source_unread(doc)
    assert gui.gui_headline(doc)[1] == UNREAD_TITLE
