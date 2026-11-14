"""The window's pure logic and the live-connections reader, without a display."""
import sys
from types import SimpleNamespace

from zbtriage import gui, netconns, workflow
from zbtriage.iocs import Indicator, IocSet
from zbtriage.report import V_HITS, V_NONE, V_NONE_WITH_GAPS, V_REFERENCES


def _doc(status, gaps=()):
    return {"verdict": {"status": status, "gaps": list(gaps)}}


def test_headline_follows_the_verdict():
    assert gui.gui_headline(_doc(V_HITS))[1] == "Something needs a closer look"
    assert gui.gui_headline(_doc(V_NONE))[1] == "No known spyware traces found"
    assert "not a guarantee" in gui.gui_headline(_doc(V_NONE))[2]
    assert "2 checks could not run" in gui.gui_headline(_doc(V_NONE_WITH_GAPS, ["a", "b"]))[2]
    assert gui.gui_headline(_doc(V_REFERENCES))[1] == "Only references found"
    doc = _doc(V_NONE)
    doc["modules"] = {"ios": {"leads": [{"check": "x"}]}}
    colour, title, subtitle = gui.gui_headline(doc)
    # leads with nothing known: an amber card that says so (team test F1), never the grey "nothing found" one
    assert title == "1 thing worth a look" and colour == gui.GUI_WARN and "not proof" in subtitle
    doc["verdict"]["gaps"] = ["a"]
    doc["verdict"]["status"] = V_NONE_WITH_GAPS
    assert "1 check could not run" in gui.gui_headline(doc)[2]
    doc["verdict"]["status"] = V_REFERENCES      # references still say "references", leads in the small print
    assert "1 thing worth a look is listed" in gui.gui_headline(doc)[2]


def test_finds_iphone_backups_newest_first(tmp_path, monkeypatch):
    base = tmp_path / "Library" / "Application Support" / "MobileSync" / "Backup"
    for name, when in (("old", 1000), ("new", 2000)):
        (base / name).mkdir(parents=True)
        (base / name / "Manifest.plist").write_bytes(b"x")
        import os
        os.utime(base / name, (when, when))
    (base / "notabackup").mkdir()
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.delenv("APPDATA", raising=False)
    found = gui.gui_backup_folders()
    assert [p.rsplit(chr(92), 1)[-1].rsplit("/", 1)[-1] for _l, p in found] == ["new", "old"]


def test_window_opens_only_when_asked_or_double_clicked(monkeypatch):
    args = SimpleNamespace(gui=False, no_gui=False)
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert not workflow.gui_wanted([], args)
    assert workflow.gui_wanted(["--gui"], SimpleNamespace(gui=True, no_gui=False))
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert workflow.gui_wanted([], args)
    assert not workflow.gui_wanted(["--no-banner"], args)
    assert not workflow.gui_wanted([], SimpleNamespace(gui=False, no_gui=True))


def test_linux_proc_table_and_matching(tmp_path, monkeypatch):
    # 93.184.216.34:443 ESTABLISHED and a loopback listener, in /proc/net/tcp layout.
    (tmp_path / "tcp").write_text(
        "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111\n"
        "   1: 0A00020F:C350 22D8B85D:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 222\n")
    monkeypatch.setattr(netconns, "_nc_linux_owners", lambda: {"222": (42, "/usr/bin/fixture")})
    rows = netconns._nc_linux(str(tmp_path))
    by_state = {r["state"]: r for r in rows}
    assert by_state["LISTEN"]["local"] == "127.0.0.1" and by_state["LISTEN"]["local_port"] == 8080
    est = by_state["ESTABLISHED"]
    assert (est["remote"], est["remote_port"], est["pid"]) == ("93.184.216.34", 443, 42)
    iocs = IocSet([Indicator("93.184.216.34", "infrastructure-ip", "primary", "ip", "fixture")], "x", None)
    matches = netconns.nc_match(rows, iocs)
    assert [m["remote"] for m in matches] == ["93.184.216.34"]
    assert est["remote_public"] and not by_state["LISTEN"]["remote_public"]


def test_lsof_endpoint_split():
    assert netconns._nc_lsof_split("[2001:db8::1]:443") == ("2001:db8::1", 443)
    assert netconns._nc_lsof_split("10.0.0.2:51234") == ("10.0.0.2", 51234)


def test_window_offers_every_training_example():
    from zbtriage.training import TRAINING_SCENARIOS
    assert "training" in [key for key, _label, _note in gui.GUI_CHECKS]
    assert sorted(k for _label, k in gui.GUI_TRAINING_LABELS) == sorted(TRAINING_SCENARIOS)


def test_training_is_stamped_in_what_the_window_saves(tmp_path):
    # The window builds its report with prepare_document, not finalize_report,
    # so the training marker has to be added there or a saved report from the
    # window would look like a real check.
    import datetime
    from zbtriage import cli, report, training
    args = cli._parse(["--training", "spyware", "--no-menu", "--no-banner"])
    training.training_prepare(args)
    try:
        doc = report.prepare_document(IocSet([], "", 0), [], datetime.datetime.now(), args)
    finally:
        training.training_cleanup()
    assert doc["training"]["synthetic"] is True
    text = report.render_human(doc)
    summary = text.index("SUMMARY")
    assert text.index("TRAINING EXAMPLE: a made-up phone", summary) < text.index("RESULT:", summary)


def test_a_real_check_carries_no_training_stamp():
    import datetime
    from zbtriage import cli, report
    args = cli._parse(["--scan-type", "browser", "--no-menu", "--no-banner"])
    doc = report.prepare_document(IocSet([], "", 0), [], datetime.datetime.now(), args)
    assert "training" not in doc
    assert "TRAINING" not in report.render_human(doc)


def test_progress_follows_the_steps_of_the_check():
    state = {"steps": ["browser", "hash", "host"]}
    assert gui.gui_progress("[*] loading indicators", state) == ("[*] loading indicators", None)
    text, percent = gui.gui_progress("[*] running check: browser", state)
    assert text == "Checking your browsers... (step 1 of 3)" and percent == 0
    text, _ = gui.gui_progress("[browser]   still working: app:steam (1,200 records checked so far)", state)
    assert text == "Checking your browsers... (step 1 of 3) - Steam: 1,200 records checked"
    assert not state["measured"]
    _, percent = gui.gui_progress("[*]   browser finished in 600s", state)
    assert round(percent) == 33
    gui.gui_progress("[*] running check: hash", state)
    text, percent = gui.gui_progress("[hash] fingerprinted 5,000 / 10,000 candidates", state)
    assert text == "Checking program files... (step 2 of 3) - 5,000 of 10,000 files"
    assert state["measured"] and round(percent) == 50


def test_stop_raises_once_like_ctrl_c():
    import threading
    stop, seen = threading.Event(), []
    emit = gui.gui_stoppable_emit(stop, seen.append)
    emit("first")
    stop.set()
    try:
        emit("second")
        raise AssertionError("Stop did not interrupt the check")
    except KeyboardInterrupt:
        pass
    emit("third")  # winding down after the stop is reported, not interrupted again
    assert seen == [("status", "first"), ("status", "third")]


def _hit_doc(tier, **extra):
    doc = {"verdict": {"status": V_HITS, "gaps": []},
           "modules": {"browser": {"hits": [{"tier": tier, "indicator": "x.invalid"}], "leads": []}}}
    doc.update(extra)
    return doc


def test_an_advertising_network_trace_is_not_treated_as_spyware():
    doc = _hit_doc("delivery")
    assert gui.gui_headline(doc)[1] == "Advertising-network traces found"
    advice = " ".join(gui.gui_next_steps(doc))
    assert "usually an ordinary ad, not spyware" in advice and "Keep this device as it is" not in advice
    assert "uBlock Origin" in advice and "dnsmasq" in advice and "archivegenocide.com/scan" in advice
    assert "Usually nothing to do" not in advice


def test_a_real_finding_gets_the_preserve_and_get_help_steps():
    doc = _hit_doc("primary")
    assert gui.gui_headline(doc)[1] == "Something needs a closer look"
    advice = gui.gui_next_steps(doc)
    assert advice[0].startswith("Keep this device as it is")
    assert any(gui.HELPLINE in step for step in advice)


def test_next_steps_follow_the_gaps_leads_and_stop():
    doc = {"verdict": {"status": V_NONE_WITH_GAPS,
                       "gaps": ["indicators/indicator-sources: indicator source missing",
                                "browser/edge:cookies: Edge was running, so one of its databases was locked"]},
           "modules": {"exploited-software": {"leads": [{"check": "chrome"}]}},
           "scope": {"cancelled": True}}
    advice = " ".join(gui.gui_next_steps(doc))
    for words in ("out-of-date programs", "stopped before it finished", "Update indicator lists",
                  "Close your browsers"):
        assert words in advice
    assert gui.gui_headline(doc)[1] == "Check stopped before it finished"


def test_practice_shows_the_real_steps_labelled_as_practice():
    doc = _hit_doc("primary", training={"scenario": "spyware"})
    advice = gui.gui_next_steps(doc)
    assert advice[0].startswith("Practice example")
    assert any(step.startswith("Keep this device as it is") for step in advice)
