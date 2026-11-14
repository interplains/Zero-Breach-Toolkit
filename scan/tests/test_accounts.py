"""The account checklist and the threat-warning guide. Nothing here signs in, opens or contacts anything."""
import io
import json

import pytest

from zbtriage import accounts as ac
from zbtriage import menu


def _answers(*replies):
    it = iter(replies)
    return lambda _prompt: next(it, None)


def test_unanswered_steps_are_not_checked_never_fine():
    r = ac.ac_result({})
    assert r["counts"][ac.AC_SKIPPED] == len(ac.AC_STEPS) and r["level"] == "incomplete"
    text = ac.ac_render(r)
    assert "NOT CHECKED" in text and "CHECKED - FINE" not in text


def test_every_step_checked_is_clean():
    r = ac.ac_result({sid: ac.AC_CHECKED for sid, *_ in ac.AC_STEPS})
    assert r["level"] == "clean" and "nothing you didn't recognise" in ac.ac_headline(r)
    assert "NOT CHECKED" not in ac.ac_render(r)


def test_a_found_step_says_what_to_do_and_warns_before_removing():
    r = ac.ac_result({"whatsapp": ac.AC_FOUND, "signal": ac.AC_CHECKED})
    assert r["level"] == "worth-a-look"
    text = ac.ac_render(r)
    assert "WhatsApp: linked devices" in text and "Log out" in text
    assert "can alert them" in text and "accessnow.org/help" in text


def test_an_unknown_answer_counts_as_skipped():
    r = ac.ac_result({"whatsapp": "maybe"})
    assert next(s for s in r["steps"] if s["id"] == "whatsapp")["state"] == ac.AC_SKIPPED


def test_the_terminal_walk_records_answers_and_stops_on_q():
    said = []
    r = ac.ac_terminal(_answers("y", "huh", "n", "s", "q"), said.append)
    states = {s["id"]: s["state"] for s in r["steps"]}
    assert states["apple-devices"] == ac.AC_CHECKED
    assert states["apple-safety-check"] == ac.AC_FOUND          # "huh" was asked again
    assert states["google-devices"] == ac.AC_SKIPPED
    assert all(states[sid] == ac.AC_SKIPPED for sid, *_ in ac.AC_STEPS[3:])
    assert any("Where:" in t for t in said)


def test_closing_the_window_mid_way_stops_cleanly():
    r = ac.ac_terminal(_answers(), lambda _t: None)               # end of input at once
    assert r["counts"][ac.AC_SKIPPED] == len(ac.AC_STEPS)


def test_the_result_is_saved_and_never_overwrites(tmp_path):
    r = ac.ac_result({"telegram": ac.AC_FOUND})
    path = ac.ac_save(r, str(tmp_path))
    assert json.load(open(path, encoding="utf-8"))["counts"][ac.AC_FOUND] == 1
    with pytest.raises(FileExistsError):
        ac.ac_save(r, path)


def test_step_ids_are_unique_and_every_step_says_where_and_what_to_do():
    ids = [s[0] for s in ac.AC_STEPS]
    assert len(ids) == len(set(ids))
    for sid, account, where, look, fix in ac.AC_STEPS:
        assert account and where and look and fix, sid


def test_the_threat_warning_guide_keeps_evidence_before_updating():
    g = ac.AC_THREAT_WARNING
    assert g.index("DO NOT ERASE") < g.index("SAVE A COPY") < g.index("Install the latest updates")
    assert "accessnow.org/help" in g and "Lockdown Mode" in g
    assert "never ask you to click links" in g


def test_the_command_line_options(monkeypatch, capsys):
    from zbtriage.cli import _parse
    assert ac.ac_command(_parse(["--threat-warning"])) == 0
    assert "IF YOU GOT A THREAT WARNING" in capsys.readouterr().out
    monkeypatch.setattr("sys.stdin", io.StringIO("n\nq\n"))
    assert ac.ac_command(_parse(["--accounts"])) == 0            # a checklist never exits as a scan would
    assert "TO FIX - WHAT TO DO" in capsys.readouterr().out


def test_both_are_in_the_terminal_menu():
    labels = {item.label for item in menu._MN_ITEMS}
    assert {"Your online accounts", "I got a threat warning"} <= labels
