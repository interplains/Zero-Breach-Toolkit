"""--combine: the household report. Built from small hand-made reports; reads files only."""
import datetime
import json
from types import SimpleNamespace

import pytest

from zbtriage import household as hh


def _report(status="NO_KNOWN_INDICATORS", phone=False, dns_logs=0, modules=None, gaps=(), when=None, **extra):
    when = when or datetime.datetime.now().astimezone().replace(microsecond=0).isoformat()
    doc = {"schema_version": 1, "tool": {"name": "zero-breach-toolkit", "version": "3.0.0"}, "timestamp": when,
           "platform": {"system": "Windows", "release": "11"}, "modules": modules or {},
           "worth_a_look": [], "verdict": {"status": status, "gaps": list(gaps)},
           "scope": {"phone": phone, "dns_logs": dns_logs, "cancelled": False}, "scan_state": "completed",
           "ioc_set": {"age_days": 2, "stale": False}}
    doc.update(extra)
    return doc


def _home(findings=(), gaps=()):
    return {"tool": "zero-breach-toolkit home-network check", "subnet": "192.168.1.0/24", "devices": [{}, {}],
            "findings": [list(f) for f in findings], "gaps": list(gaps), "timestamp": "2026-11-08T18:00:00+03:00"}


def _write(tmp_path, name, doc, bom=False):
    path = tmp_path / name
    path.write_text(("\ufeff" if bom else "") + json.dumps(doc), encoding="utf-8")
    return str(path)


IOS_HIT = {"ios": {"status": "HITS", "notes": ["iOS version recorded by backup: 18.6"],
                   "hits": [{"indicator": "bad.example", "family": "Paragon Graphite", "evidence": "contacted"}]}}


@pytest.mark.parametrize("doc,kind", [
    (_report(), "computer"),
    (_report(phone=True, modules={"ios": {"status": "CLEAN"}}), "iphone"),
    (_report(phone=True, modules={"ios": {"status": "NOT_APPLICABLE"}, "android": {"status": "CLEAN"}}), "android"),
    (_report(dns_logs=1, modules={"dns-logs": {"status": "CLEAN"}}), "dns-log"),
    (_home(), "home-network"),
    ({"report_type": "sharing-summary", "tool": {"name": "zero-breach-toolkit"}, "scope": {"phone": True},
      "verdict": {"status": "NO_KNOWN_INDICATORS"}}, "phone"),
])
def test_kind_of_each_report(doc, kind):
    assert hh.hh_kind(doc) == kind


@pytest.mark.parametrize("doc", [{"tool": {"name": "something else"}}, {"verdict": {}}, ["a list"]])
def test_reports_from_other_tools_are_refused_not_guessed(tmp_path, doc):
    combined = hh.hh_combine([_write(tmp_path, "other.json", doc)])
    assert combined["entries"] == [] and combined["unreadable"]


def test_worst_device_first_and_red_overall(tmp_path):
    files = [_write(tmp_path, "pc.json", _report()),
             _write(tmp_path, "phone.json", _report("INDICATORS_FOUND", phone=True, modules=IOS_HIT)),
             _write(tmp_path, "home.json", _home(findings=[("Open door: Telnet on 192.168.1.9", "d", "w")]))]
    doc = hh.hh_combine(files)
    assert doc["overall"] == hh.RED
    assert [e["colour"] for e in doc["entries"]] == [hh.RED, hh.AMBER, hh.GREEN]
    assert doc["entries"][0]["label"] == "iPhone (iOS 18.6)"
    assert doc["entries"][0]["findings"] == ["Paragon Graphite: bad.example (ios, contacted)"]


def test_exit_codes(tmp_path):
    assert hh.combine_command(SimpleNamespace(combine=[_write(tmp_path, "a.json", _report())]), out=lambda _l: None) == 0
    gaps = _write(tmp_path, "b.json", _report("NO_KNOWN_INDICATORS_WITH_GAPS", gaps=["host/dns-cache: not readable"]))
    assert hh.combine_command(SimpleNamespace(combine=[gaps]), out=lambda _l: None) == 3
    hit = _write(tmp_path, "c.json", _report("INDICATORS_FOUND", phone=True, modules=IOS_HIT))
    assert hh.combine_command(SimpleNamespace(combine=[gaps, hit]), out=lambda _l: None) == 2


def test_report_resaved_with_a_bom_still_reads(tmp_path):
    doc = hh.hh_combine([_write(tmp_path, "bom.json", _report(), bom=True)])
    assert len(doc["entries"]) == 1 and not doc["unreadable"]


def test_unreadable_file_is_listed_and_spoils_an_all_clear(tmp_path):
    bad = tmp_path / "broken.json"
    bad.write_text("not json", encoding="utf-8")
    doc = hh.hh_combine([_write(tmp_path, "pc.json", _report()), str(bad), str(tmp_path / "missing.json")])
    assert doc["overall"] == hh.AMBER
    assert [u["source"] for u in doc["unreadable"]] == ["broken.json", "missing.json"]
    assert "COULD NOT BE INCLUDED" in hh.hh_render(doc)


def test_missing_kinds_of_check_are_named(tmp_path):
    doc = hh.hh_combine([_write(tmp_path, "pc.json", _report())])
    text = " ".join(doc["missing"])
    assert "No phone was checked" in text and "--home-network" in text and "--dns-log" in text
    assert "No computer" not in text


def test_label_syntax(tmp_path):
    path = _write(tmp_path, "pc.json", _report())
    assert hh.hh_parse_arg("Mum's laptop=" + path) == ("Mum's laptop", path)
    assert hh.hh_parse_arg(path) == ("", path)
    assert hh.hh_parse_arg("C:\\odd=name.json") == ("", "C:\\odd=name.json")
    assert hh.hh_combine(["Mum's laptop=" + path])["entries"][0]["label"] == "Mum's laptop"


def test_old_reports_are_flagged(tmp_path):
    old = (datetime.datetime.now().astimezone() - datetime.timedelta(days=45)).replace(microsecond=0).isoformat()
    doc = hh.hh_combine([_write(tmp_path, "pc.json", _report(when=old))])
    assert doc["old"] == ["Computer (Windows 11)"]


def test_gap_prefixes_are_dropped(tmp_path):
    doc = hh.hh_combine([_write(tmp_path, "a.json", _report(
        "NO_KNOWN_INDICATORS_WITH_GAPS", phone=True, modules={"android": {"status": "PARTIAL"}},
        gaps=["android/android:history: no battery history in the collection"]))])
    assert doc["entries"][0]["gaps"] == ["no battery history in the collection"]


def test_evidence_text_is_escaped_in_the_page(tmp_path):
    hostile = dict(IOS_HIT)
    hostile["ios"] = dict(IOS_HIT["ios"], hits=[{"indicator": "<script>alert(1)</script>", "evidence": "contacted"}])
    doc = hh.hh_combine(["<b>x=" + _write(tmp_path, "p.json", _report("INDICATORS_FOUND", phone=True, modules=hostile))])
    assert doc["entries"], doc["unreadable"]
    page = hh.hh_html(doc)
    assert "<script>" not in page and "&lt;script&gt;" in page
    assert "<b>x" not in page and "&lt;b&gt;x" in page


def test_never_replaces_an_existing_file(tmp_path):
    src = _write(tmp_path, "pc.json", _report())
    target = tmp_path / "house.html"
    target.write_text("keep me", encoding="utf-8")
    lines = []
    code = hh.combine_command(SimpleNamespace(combine=[src], html=str(target), json=None), out=lines.append)
    assert code == 1 and target.read_text(encoding="utf-8") == "keep me"
    assert any("already exists" in l for l in lines)


def test_sharing_summary_is_marked_as_details_missing(tmp_path):
    summary = {"report_type": "sharing-summary", "tool": {"name": "zero-breach-toolkit", "version": "3"},
               "scope": {"phone": True}, "verdict": {"status": "NO_KNOWN_INDICATORS_WITH_GAPS"},
               "coverage": {"gap_count": 2}}
    entry = hh.hh_combine([_write(tmp_path, "s.json", summary)])["entries"][0]
    assert entry["summary_only"] and entry["gaps"] == ["2 parts could not be checked"]


def test_cli_options(tmp_path):
    from zbtriage.cli import _parse
    with pytest.raises(SystemExit):
        _parse(["--html", str(tmp_path / "x.html")])
    with pytest.raises(SystemExit):
        _parse(["--combine", "a.json", "--home-network"])
    args = _parse(["--combine", "a.json", "b.json", "--html", str(tmp_path / "x.html")])
    assert args.combine == ["a.json", "b.json"]


@pytest.mark.parametrize("bad", [{"modules": [1, 2]}, {"modules": {"ios": None}}, {"worth_a_look": ["x"]},
                                 {"modules": {"ios": {"hits": ["not a dict"]}}}, {"verdict": {"status": 7, "gaps": 3}}])
def test_malformed_report_is_listed_not_fatal(tmp_path, bad):
    doc = _report(phone=True, **{k: v for k, v in bad.items() if k != "verdict"})
    if "verdict" in bad:
        doc["verdict"] = bad["verdict"]
    combined = hh.hh_combine([_write(tmp_path, "good.json", _report()), _write(tmp_path, "bad.json", doc)])
    assert any(e["label"].startswith("Computer") for e in combined["entries"])
    assert combined["unreadable"] == [] or combined["unreadable"][0]["source"] == "bad.json"
