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


def test_clean_readable_backup_stays_green(tmp_path):
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/SMS/sms.db", _sms(tmp_path, "nothing to see here"))])
    ctx = _ctx(root)
    doc = _document(ctx, ios.run(ctx))

    assert not report.phone_source_unread(doc)
    colour, title, _ = gui.gui_headline(doc)
    assert colour == gui.GUI_GOOD
    assert title == "No known spyware traces found"
    assert UNREAD_TITLE not in report.render_summary(doc)


def test_unreadable_android_collection_is_not_green():
    doc = {"scope": {"phone": True},
           "modules": {"android": {"checks": [{"name": "android", "ran": False,
                                               "reason": "not an AndroidQF collection folder"}]}},
           "verdict": {"status": report.V_NONE_WITH_GAPS, "gaps": []}}
    assert report.phone_source_unread(doc)
    assert gui.gui_headline(doc)[1] == UNREAD_TITLE


def test_a_computer_scan_with_the_same_check_is_unaffected():
    doc = {"scope": {"phone": False},
           "modules": {"android": {"checks": [{"name": "android", "ran": False, "reason": "x"}]}},
           "verdict": {"status": report.V_NONE_WITH_GAPS, "gaps": []}}
    assert not report.phone_source_unread(doc)
    assert gui.gui_headline(doc)[1] == "No known spyware traces found"


def test_a_platform_that_did_run_is_not_unread():
    doc = {"scope": {"phone": True},
           "modules": {"android": {"checks": [{"name": "android", "ran": False, "reason": "x"},
                                               {"name": "android:packages", "ran": True}]}},
           "verdict": {"status": report.V_NONE_WITH_GAPS, "gaps": []}}
    assert not report.phone_source_unread(doc)
