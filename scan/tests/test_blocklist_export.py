"""--export-blocklist: the website names a scan matched, as a DNS block list."""
import contextlib
import datetime
import io
from pathlib import Path

import pytest

from zbtriage import cli, export, report
from zbtriage.result import (ModuleResult, Hit, EV_CONTACTED, EV_DNS, EV_CONFIGURED,
                             EV_REFERENCED, EV_ON_DISK)
from test_expanded_capabilities import context, BAD
from test_followup_fixes import bundle


def hit(value, evidence=EV_CONTACTED, kind="domain", tier="infrastructure", family="Fixture"):
    return {"indicator": value, "evidence": evidence, "kind": kind, "tier": tier, "family": family}


def document(*hits):
    return {"modules": {"browser": {"hits": list(hits)}}, "completed_at": "2026-11-16T09:00:00+00:00"}


def test_matched_names_are_listed_once_with_the_most_telling_grade():
    entries, left_out = export.bl_collect(document(
        hit("Evil.Example."), hit("evil.example", evidence=EV_CONFIGURED),
        hit("other.example", evidence=EV_DNS)))
    assert [name for name, _ in entries] == ["evil.example", "other.example"]
    assert entries[0][1].startswith("contacted")
    assert left_out == {"ip": 0, "reclaimable": 0, "other": 0}


def test_references_are_never_listed():
    # A saved news page naming a server is not contact; blocking the site
    # that published the article would be a false positive.
    entries, _ = export.bl_collect(document(hit("news.example", evidence=EV_REFERENCED)))
    assert entries == []


def test_ip_addresses_are_left_out_and_counted():
    entries, left_out = export.bl_collect(document(
        hit("203.0.113.7", kind="ip"), hit("2001:db8::1", kind=""), hit("203.0.113.7", kind="ip")))
    assert entries == []
    assert left_out["ip"] == 2


def test_names_that_may_have_changed_owner_are_left_out():
    entries, left_out = export.bl_collect(document(hit("old.example", tier="reclaimable")))
    assert entries == [] and left_out["reclaimable"] == 1
    # Matched as an ordinary indicator too: listed, and not counted as left out.
    entries, left_out = export.bl_collect(document(hit("old.example", tier="reclaimable"),
                                                   hit("old.example", tier="cc")))
    assert [name for name, _ in entries] == ["old.example"] and left_out["reclaimable"] == 0


@pytest.mark.parametrize("value", ["evil.example\n0.0.0.0 good.example", "*.evil.example",
                                   "evil .example", "http://evil.example/", "-evil.example", "evil"])
def test_a_value_that_is_not_a_plain_host_name_never_becomes_a_line(value):
    entries, left_out = export.bl_collect(document(hit(value)))
    assert entries == [] and left_out["other"] == 1


def test_hits_without_a_kind_count_only_when_graded_as_network_contact():
    entries, left_out = export.bl_collect(document(
        hit("visited.example", kind=""),
        hit("a" * 64, kind="", evidence=EV_ON_DISK),
        hit("yara:Fixture_Rule", kind="", evidence="file-pattern"),
        hit("com.fixture.app", kind="app-id", evidence="on-device")))
    assert [name for name, _ in entries] == ["visited.example"]
    assert left_out == {"ip": 0, "reclaimable": 0, "other": 0}


def test_both_formats_put_comments_on_their_own_lines():
    entries = [("evil.example", "contacted / Fixture / cc")]
    hosts = export.bl_render(entries, "hosts", "3.0.2", "2026-11-16T09:00:00+00:00").splitlines()
    domains = export.bl_render(entries, "domains", "3.0.2", "2026-11-16T09:00:00+00:00").splitlines()
    assert "0.0.0.0 evil.example" in hosts and "evil.example" in domains
    for lines in (hosts, domains):
        assert all(line.startswith("#") or not line or " #" not in line for line in lines)
        assert lines[0].startswith("# Zero Breach Toolkit 3.0.2")
        assert lines[1].startswith("# Made 2026-11-16T09:00:00+00:00 ")


def test_feed_text_in_a_comment_cannot_start_a_new_line():
    entries, _ = export.bl_collect(document(hit("evil.example", family="Fixture\n0.0.0.0 good.example")))
    text = export.bl_render(entries, "hosts", "3.0.2", "2026-11-16T09:00:00+00:00")
    assert "0.0.0.0 good.example" not in text.splitlines()


def test_an_empty_list_is_still_a_valid_file():
    text = export.bl_render([], "domains", "3.0.2", "2026-11-16T09:00:00+00:00")
    assert all(not line or line.startswith("#") for line in text.splitlines())
    assert "No matched website names" in text


def test_the_list_is_written_with_unix_line_endings(tmp_path):
    out = tmp_path / "block.txt"
    written, _ = export.bl_write(document(hit("evil.example")), str(out), "hosts", "3.0.2")
    data = out.read_bytes()
    assert written == 1 and b"\r\n" not in data and b"0.0.0.0 evil.example\n" in data


def test_a_report_without_a_completion_time_is_refused(tmp_path):
    doc = document(hit("evil.example"))
    del doc["completed_at"]
    with pytest.raises(ValueError):
        export.bl_write(doc, str(tmp_path / "block.txt"), "hosts", "3.0.2")
    assert not (tmp_path / "block.txt").exists()


def test_summary_says_what_was_left_out():
    line = export.bl_summary("block.txt", 1, {"ip": 2, "reclaimable": 1, "other": 0})
    assert "1 website name)" in line and "2 IP addresses left out" in line
    assert "may belong to someone else" in line


@pytest.mark.parametrize("extra", [
    ["--blocklist-format", "domains"],
    ["--export-blocklist", "same", "--json", "same"],
    ["--export-blocklist", "same", "--report", "same"],
    ["--export-blocklist", "block.txt", "--update"],
])
def test_option_mistakes_are_refused(extra):
    with contextlib.redirect_stderr(io.StringIO()), pytest.raises(SystemExit):
        cli._parse(["--no-menu"] + extra)


def test_hosts_is_the_default_format():
    assert cli._parse(["--no-menu", "--export-blocklist", "block.txt"]).blocklist_format == "hosts"


def test_the_single_file_takes_and_checks_the_options_too(bundle):
    assert bundle._bundle_parse(["--no-menu", "--export-blocklist", "b.txt"]).blocklist_format == "hosts"
    for extra in (["--blocklist-format", "domains"], ["--export-blocklist", "same", "--json", "same"]):
        with contextlib.redirect_stderr(io.StringIO()), pytest.raises(SystemExit):
            bundle._bundle_parse(["--no-menu"] + extra)


def test_a_scan_writes_the_list_in_the_package_and_the_single_file(tmp_path, bundle):
    for n, api in enumerate((report, bundle)):
        result = ModuleResult("browser")
        result.ran("history")
        result.add_hit(Hit(BAD, "fixture History", "recorded visit", evidence=EV_CONTACTED))
        out = tmp_path / "block{}.txt".format(n)
        parse = cli._parse if api is report else bundle._bundle_parse
        args = parse(["--no-menu", "--export-blocklist", str(out), "--blocklist-format", "domains"])
        err = io.StringIO()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
            api.finalize_report(context().iocs, [result], datetime.datetime.now(), args)
        assert BAD in out.read_text(encoding="utf-8").splitlines()
        assert "wrote DNS block list (1 website name)" in err.getvalue()


def test_a_failed_write_is_reported_and_sets_the_exit_code(tmp_path):
    result = ModuleResult("browser")
    result.ran("history")
    args = cli._parse(["--no-menu", "--export-blocklist", str(tmp_path / "missing" / "block.txt")])
    err = io.StringIO()
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
        code = report.finalize_report(context().iocs, [result], datetime.datetime.now(), args)
    assert code == 1 and "could not write DNS block list" in err.getvalue()
