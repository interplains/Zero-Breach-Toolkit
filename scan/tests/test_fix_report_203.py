"""2.0.3: results that must not read as clean, and the report/window fixes that
came with them. Each test here fails on the 2.0.2 code.

Format sources for the fixtures: none of these tests invents a data format. The
phone readers' real input (AndroidQF packages.json, iPhone backups, sysdiagnose
archives) is built with the helpers the existing reader tests use; an empty
folder and a file of arbitrary bytes are the unusable inputs themselves.
"""
import datetime
import os
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import gui, report
from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import android, ios
from zbtriage.result import EV_CONTACTED, EV_DEVICE_LOG, Hit, ModuleResult

UNREAD_TITLE = "This phone could not be checked"
NOW = datetime.datetime(2026, 11, 2, 12, 0, 0)
IOCS = IocSet([Indicator("spy-c2.test", "cc", "primary", "domain", "fixture", "Fixturefam")], "fixture", None)


def _phone_doc(result):
    doc = report.build_document(IOCS, [result], NOW)
    doc["scope"] = {"phone": True, "scan_type": "phone"}
    return doc


def _ctx(folder, **kw):
    return ScanContext(iocs=IOCS, emit=lambda _m: None, phone_path=str(folder), **kw)


def _assert_not_green(doc):
    assert report.phone_source_unread(doc), doc["modules"]
    colour, title, subtitle = gui.gui_headline(doc)
    assert title == UNREAD_TITLE and colour == gui.GUI_WARN and colour != gui.GUI_GOOD
    summary = " ".join(report.render_summary(doc).split())
    assert "RESULT: the phone could not be checked" in summary
    assert "no known indicator was found" not in summary
    assert doc["exit_code"] == 3


# --- A: nothing read must never be green ----------------------------------------

@pytest.mark.parametrize("kind", ("filesystem", "sysdiagnose"))
def test_an_empty_folder_with_an_iphone_type_chosen_is_not_green(tmp_path, kind):
    # ios:input is marked ran before anything is read: it must not count as read.
    result = ios.run(_ctx(tmp_path, ios_input=kind))
    _assert_not_green(_phone_doc(result))


def test_a_corrupt_sysdiagnose_archive_is_not_green(tmp_path):
    archive = tmp_path / "sysdiagnose_2026.tar.gz"
    archive.write_bytes(b"this is not an archive")       # bytes that are not any archive
    _assert_not_green(_phone_doc(ios.run(_ctx(archive, ios_input="sysdiagnose"))))


def test_an_empty_android_package_list_is_not_green(tmp_path):
    # AOSP: a phone always has system packages, so an empty list is a damaged
    # collection, never "no apps to check".
    (tmp_path / "packages.json").write_text("[]")
    result = android.run(_ctx(tmp_path))
    assert not any(c.name == "android:packages" and c.ran for c in result.checks)
    _assert_not_green(_phone_doc(result))


def test_android_records_that_are_not_package_records_are_not_green(tmp_path):
    (tmp_path / "packages.json").write_text("[{}, 5, null]")
    _assert_not_green(_phone_doc(android.run(_ctx(tmp_path))))


def test_a_normal_android_collection_is_read_not_unread():
    from test_android import collection
    doc = _phone_doc(android.run(_ctx(collection(spy=False))))
    assert not report.phone_source_unread(doc)
    assert gui.gui_headline(doc)[1] in ("No known spyware traces found",
                                        "Nothing found in what could be checked")


def test_a_normal_iphone_backup_is_read_not_unread(tmp_path):
    from test_ios_upgrade import backup, db_bytes
    raw, _ = db_bytes(tmp_path, "CREATE TABLE message(text,date,is_from_me)",
                      [("INSERT INTO message VALUES(?,700000000,0)", ("nothing to see here",))])
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/SMS/sms.db", raw)])
    doc = _phone_doc(ios.run(_ctx(root)))
    assert not report.phone_source_unread(doc)
    assert gui.gui_headline(doc)[1] == "Nothing found in what could be checked"   # the backup has gaps


def test_a_finding_always_counts_as_something_read():
    module = ModuleResult("android")
    module.add_hit(Hit(indicator="spy-c2.test", location="x", detail="d", evidence=EV_CONTACTED))
    doc = _phone_doc(module)
    assert not report.phone_source_unread(doc)


def test_unread_does_not_depend_on_check_names():
    # The old test looked for a ran check starting "ios:" and was defeated by the
    # frame check. Whatever the check is called, no records read means unread.
    for names in (("ios:input",), ("ios:manifest", "ios:messages", "ios:safari"), ("android:packages",)):
        module = ModuleResult("ios")
        for name in names:
            module.ran(name)
        assert report.phone_source_unread(_phone_doc(module)), names
    module = ModuleResult("ios")
    module.ran("ios:input")
    module.submetrics["phone_records_read"] = 3
    assert not report.phone_source_unread(_phone_doc(module))


# --- B / 11: green only for a complete check; withdrawn has its own wording -------

def test_gaps_are_never_green():
    module = ModuleResult("browser")
    module.ran("history")
    module.could_not_run("app:chrome:cookies", "Cookies file was running and locked")
    doc = report.build_document(IOCS, [module], NOW)
    colour, title, subtitle = gui.gui_headline(doc)
    assert colour == gui.GUI_NEUTRAL and colour not in (gui.GUI_GOOD, gui.GUI_RED, gui.GUI_WARN)
    assert title == "Nothing found in what could be checked"
    assert "1 check could not run" in subtitle
    assert any("could not run" in step for step in gui.gui_next_steps(doc))
    assert "Nothing matched known spyware. Keep" not in " ".join(gui.gui_next_steps(doc))


def test_green_is_for_a_complete_check_only():
    module = ModuleResult("browser")
    module.ran("history")
    doc = report.build_document(IOCS, [module], NOW)
    assert not doc["verdict"]["gaps"]
    assert gui.gui_headline(doc)[:2] == (gui.GUI_GOOD, "No known spyware traces found")


def test_a_withdrawn_match_is_not_called_a_page_you_read():
    module = ModuleResult("browser")
    module.ran("connection-records")
    module.add_hit(Hit(indicator="spy-c2.test", location="Network Persistent State", detail="d",
                       tier="cc", confidence="primary", source="fixture", evidence=EV_CONTACTED))

    def enrich(modules, _iocs):
        for md in modules.values():
            for h in md.get("hits", []):
                h["withdrawn_only"] = True
                h["withdrawal_present"] = True
    with patch("zbtriage.evidence.evidence_enrich", enrich):
        doc = report.build_document(IOCS, [module], NOW)
    assert doc["verdict"]["status"] == report.V_WITHDRAWN
    colour, title, subtitle = gui.gui_headline(doc)
    assert title == "Only a withdrawn indicator matched"
    assert "withdrawn" in subtitle and "web pages you read" not in subtitle
    steps = " ".join(gui.gui_next_steps(doc))
    assert "withdrawn" in steps and "a name in a page you read" not in steps
    assert "WITHDRAWN" in report.render_summary(doc)          # report.py's own wording


# --- 15: the closing list of gaps -------------------------------------------------

def _doc_with_gaps(hit):
    module = ModuleResult("browser")
    module.ran("history")
    for i in range(2):
        module.could_not_run("app:edge:history%d" % i, "History file %d was running and locked" % i)
    module.could_not_run("alpha-check", "reason for alpha-check")
    if hit:
        module.add_hit(Hit(indicator="spy-c2.test", location="x", detail="d", tier="cc",
                           confidence="primary", source="fixture", evidence=EV_CONTACTED))
    return report.build_document(IOCS, [module], NOW)


@pytest.mark.parametrize("hit", (True, False))
def test_the_gap_list_is_at_the_end_of_the_full_report_with_or_without_a_finding(hit):
    full = report.render_human(_doc_with_gaps(hit))
    tail = full[full.rfind("VERDICT"):]
    assert "Checks that could NOT run" in tail
    assert "reason for alpha-check" in tail


def test_the_summary_does_not_promise_more_than_the_report_holds():
    summary = report.render_summary(_doc_with_gaps(True))
    assert "listed in full" not in " ".join(summary.split())


# --- 7: a log string in the summary says what it is ------------------------------

def test_a_phone_log_match_carries_its_caveat_in_the_summary():
    module = ModuleResult("android")
    module.ran("android:device-logs")
    module.submetrics["phone_records_read"] = 1
    module.add_hit(Hit(indicator="spy-c2.test", location="phone log logcat.txt line 12", detail="d",
                       tier="cc", confidence="primary", source="fixture", evidence=EV_DEVICE_LOG))
    doc = _phone_doc(module)
    summary = " ".join(report.render_summary(doc).split())
    assert "only text an app wrote to the log" in summary
    assert "line 12" in summary
    # A grade that is not a log string does not get the log caveat.
    other = ModuleResult("browser")
    other.ran("history")
    other.add_hit(Hit(indicator="spy-c2.test", location="History", detail="d", tier="cc",
                      confidence="primary", source="fixture", evidence=EV_CONTACTED))
    assert "only text an app wrote" not in " ".join(
        report.render_summary(report.build_document(IOCS, [other], NOW)).split())


# --- 13 and 22: the window ---------------------------------------------------------

def _need_tk():
    try:
        import tkinter.messagebox  # noqa: F401
    except ImportError:
        pytest.skip("tkinter is not installed")


def test_the_backup_list_says_how_many_are_not_shown():
    _need_tk()
    shown = []
    backups = [("2026-10-%02d  /backups/%d" % (n, n), "/backups/%d" % n) for n in range(12)]
    fake = SimpleNamespace(root=None, phone_kind=SimpleNamespace(set=lambda v: None),
                           phone_kinds=["iPhone backup"], phone_folder=SimpleNamespace(set=lambda v: None))
    with patch.object(gui, "gui_backup_folders", lambda: backups), \
            patch("tkinter.messagebox.showinfo", lambda title, text, **kw: shown.append(text)):
        gui.GuiApp.find_backups(fake)
    assert len(shown) == 1
    text = shown[0]
    assert "All backups found" not in text
    assert "4 more" in text                       # 12 found, 8 listed
    assert text.count("/backups/") == 8


def test_a_few_backups_are_all_listed_without_a_count():
    _need_tk()
    shown = []
    backups = [("x  /backups/%d" % n, "/backups/%d" % n) for n in range(3)]
    fake = SimpleNamespace(root=None, phone_kind=SimpleNamespace(set=lambda v: None),
                           phone_kinds=["iPhone backup"], phone_folder=SimpleNamespace(set=lambda v: None))
    with patch.object(gui, "gui_backup_folders", lambda: backups), \
            patch("tkinter.messagebox.showinfo", lambda title, text, **kw: shown.append(text)):
        gui.GuiApp.find_backups(fake)
    assert "more" not in shown[0] and shown[0].count("/backups/") == 3


def test_a_network_folder_is_refused_before_it_is_looked_at():
    _need_tk()
    folder = "\\\\files.invalid\\share\\backup"
    errors, looked_at = [], []
    fake = SimpleNamespace(busy=False, root=None, check=SimpleNamespace(get=lambda: "phone"),
                           phone_folder=SimpleNamespace(get=lambda: folder))
    with patch.object(gui, "path_problem", lambda path: "UNC or device path was not opened"), \
            patch("os.path.isdir", lambda path: looked_at.append(path) or True), \
            patch("tkinter.messagebox.showerror", lambda title, text, **kw: errors.append(text)):
        gui.GuiApp.start_check(fake)
    assert not looked_at, "the typed folder was asked about before it was checked: %r" % looked_at
    assert len(errors) == 1 and "UNC" in errors[0] and "own drive" in errors[0]
