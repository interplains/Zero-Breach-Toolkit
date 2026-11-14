"""The window and the command-line summary work out their headline separately.
They must agree on the meaning, and neither may read as clean when the other
says incomplete or not checked (2.0.3; see private-notes/LESSONS-FALSE-CLEAN-
20261102.md, "we trusted two outputs to agree").

The same documents go through both: findings, a withdrawn match, references
only, nothing found, nothing found with gaps, and a phone nothing was read from.
Documents are built by the real build_document(); a phone's "read" evidence is
the phone_records_read counter the Android and iPhone readers keep.
"""
import datetime
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import gui, report
from zbtriage.contract import contract_exit_code
from zbtriage.iocs import Indicator, IocSet
from zbtriage.result import EV_CONTACTED, EV_REFERENCED, Hit, ModuleResult

NOW = datetime.datetime(2026, 11, 2, 12, 0, 0)
IOCS = IocSet([Indicator("spy-c2.test", "cc", "primary", "domain", "fixture", "Fixturefam")], "fixture", None)

UNREAD_TITLE = "This phone could not be checked"
TITLES = {
    "Something needs a closer look": "found",
    "Spyware found on this device": "found",
    "A phone-monitoring (stalkerware) app was found": "found",
    "Contact with a spyware address - not proof of infection": "found",
    "This phone was unlocked with a phone-forensics tool": "found",
    "Advertising-network traces found": "found",
    "Only a withdrawn indicator matched": "withdrawn",
    "Only references found": "references",
    UNREAD_TITLE: "unread",
    "No known spyware traces found": "clean",
    "Nothing found in what could be checked": "incomplete",
}


def _hit(evidence):
    return Hit(indicator="spy-c2.test", location="fixture", detail="d", tier="cc", confidence="primary",
               source="fixture", evidence=evidence)


def _module(name="browser", hit=None, gap=False, read=None):
    r = ModuleResult(name)
    r.ran("fixture-check")
    if gap:
        r.could_not_run("fixture-gap", "a part of the fixture could not be read")
    if hit:
        r.add_hit(_hit(hit))
    if read is not None:
        r.submetrics["phone_records_read"] = read
    return r


def _document(kind):
    phone = kind.startswith("phone")
    withdrawn = kind == "withdrawn"
    hit = {"found": EV_CONTACTED, "withdrawn": EV_CONTACTED, "references": EV_REFERENCED}.get(kind)
    module = _module("android" if phone else "browser", hit=hit, gap=kind in ("none_with_gaps", "phone_gaps"),
                     read={"phone_nothing_read": 0, "phone_read": 7, "phone_gaps": 7}.get(kind))
    if kind == "phone_nothing_read":
        module.checks = []
        module.could_not_run("android:packages", "app list: not in the collection")
        module.checks.append(type(module.checks[0])("ios:input", True))   # a frame check marked ran
    if withdrawn:
        def enrich(modules, _iocs):
            for md in modules.values():
                for h in md.get("hits", []):
                    h["withdrawn_only"] = True
                    h["withdrawal_present"] = True
        with patch("zbtriage.evidence.evidence_enrich", enrich):
            doc = report.build_document(IOCS, [module], NOW)
    else:
        doc = report.build_document(IOCS, [module], NOW)
    doc["scope"] = {"phone": phone, "scan_type": "phone" if phone else "default"}
    return doc


def _window_kind(doc):
    title = gui.gui_headline(doc)[1]
    assert title in TITLES, "the window shows a headline this test does not know: " + title
    return TITLES[title]


def _cli_kind(doc):
    text = " ".join(report.render_summary(doc).split())
    if "RESULT: the phone could not be checked" in text:
        return "unread"
    if "a match to an indicator its publisher has WITHDRAWN" in text:
        return "withdrawn"
    if "RESULT: no known indicator was found" in text:
        return "nothing"
    if "all of them reference-only" in text:
        return "references"
    if "FINDING" in text or "finding to review" in text or "findings to review" in text or "indicator to review" in text \
            or "indicators to review" in text or "potentially SERIOUS" in text:
        return "found"
    raise AssertionError("the summary says something this test does not know: " + text[:300])


KINDS = ("found", "withdrawn", "references", "none", "none_with_gaps",
         "phone_nothing_read", "phone_read", "phone_gaps")
EXPECTED = {
    #  kind                window         command-line
    "found":              ("found",       "found"),
    "withdrawn":          ("withdrawn",   "withdrawn"),
    "references":         ("references",  "references"),
    "none":               ("clean",       "nothing"),
    "none_with_gaps":     ("incomplete",  "nothing"),
    "phone_nothing_read": ("unread",      "unread"),
    "phone_read":         ("clean",       "nothing"),
    "phone_gaps":         ("incomplete",  "nothing"),
}


@pytest.mark.parametrize("kind", KINDS)
def test_window_and_command_line_agree(kind):
    doc = _document(kind)
    window, cli = _window_kind(doc), _cli_kind(doc)
    assert (window, cli) == EXPECTED[kind], (kind, window, cli)
    # Neither may read as clean while the other says incomplete or not checked.
    gaps = bool(doc["verdict"]["gaps"])
    summary = report.render_summary(doc)
    if window == "clean":
        assert not gaps and cli == "nothing" and "COULD NOT BE CHECKED" not in summary
        assert contract_exit_code(doc) == 0
    if cli == "unread":
        assert window == "unread"
    if window == "unread":
        assert cli == "unread" and contract_exit_code(doc) == 3
    if gaps and window in ("clean",):
        raise AssertionError("green with gaps")
    if kind in ("none_with_gaps", "phone_gaps", "phone_nothing_read"):
        assert contract_exit_code(doc) == 3


@pytest.mark.parametrize("kind", KINDS)
def test_one_shared_function_names_the_result(kind):
    doc = _document(kind)
    shared = report.result_kind(doc)
    assert shared == {"found": "found", "withdrawn": "withdrawn", "references": "references",
                      "none": "none", "none_with_gaps": "none_with_gaps",
                      "phone_nothing_read": "unread", "phone_read": "none",
                      "phone_gaps": "none_with_gaps"}[kind]
