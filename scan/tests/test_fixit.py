"""Fix it for me. Every test uses a fake runner: no test ever changes this computer. What is checked is the
promises - nothing without a yes, an undo record written before the change, the change verified afterwards, a
managed computer left alone, and dangerous doors explained rather than touched."""
import json
import os
import socket
import sys

import pytest

from zbtriage import fixit as fx


@pytest.fixture(autouse=True)
def never_touch_this_computer(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("a test tried to run a real command")
    monkeypatch.setattr(fx, "fx_run", refuse)
    monkeypatch.setattr(fx, "fx_powershell", refuse)
    monkeypatch.setattr(fx, "fx_elevated", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)


class Runner:
    """Stands in for PowerShell: records what it was asked to run."""

    def __init__(self, works=True):
        self.commands = []
        self.works = works

    def __call__(self, script, timeout=0):
        self.commands.append(script)
        return (0, "ok") if self.works else (1, "Access is denied")


def door(name, state="open", title="Something is open", fix=""):
    return {"door": name, "state": state, "title": title, "why": "", "fix": fix, "setting": "",
            "severity": "medium", "observed": ""}


def _patch_fix(monkeypatch, name="windows:remote-desktop", before=None, after_ok=True):
    """Make one fix readable and verifiable without touching the registry."""
    state = {"found": True, "value": "0"} if before is None else before
    seen = {}
    monkeypatch.setitem(fx.FX_FIXES, name, dict(
        fx.FX_FIXES[name], platform=sys.platform,
        read=lambda: dict(state),
        apply=lambda s: "APPLY " + json.dumps(s, sort_keys=True),
        undo=lambda s: "UNDO " + json.dumps(s, sort_keys=True),
        verify=lambda: seen.get("ok", after_ok)))
    return seen


# --- the plan ------------------------------------------------------------------------------------------------

def test_an_open_door_with_a_safe_fix_is_offered(monkeypatch, tmp_path):
    _patch_fix(monkeypatch)
    plan = fx.fx_plan(doors=[door("windows:remote-desktop", title="Remote Desktop is switched on")],
                      managed=(False, ""), config_dir=str(tmp_path))
    assert [o["door"] for o in plan["offers"]] == ["windows:remote-desktop"]
    offer = plan["offers"][0]
    assert offer["warn"] and offer["does"] and offer["was"] == "Remote Desktop is switched on"
    text = fx.fx_render(plan)
    assert "--fix-it windows:remote-desktop" in text and "Nothing has been changed" in text
    assert offer["warn"][:20] in text


def test_closed_doors_are_not_offered(monkeypatch, tmp_path):
    _patch_fix(monkeypatch)
    plan = fx.fx_plan(doors=[door("windows:remote-desktop", state="closed"),
                             door("windows:firewall", state="unknown")],
                      managed=(False, ""), config_dir=str(tmp_path))
    assert plan["offers"] == [] and plan["guidance"] == []
    assert "Nothing is open that needs closing" in fx.fx_render(plan)


@pytest.mark.parametrize("name", ["windows:disk-encryption", "windows:secure-boot", "windows:administrators",
                                  "macos:filevault", "linux:disk-encryption"])
def test_dangerous_doors_are_explained_never_done(monkeypatch, tmp_path, name):
    plan = fx.fx_plan(doors=[door(name)], managed=(False, ""), config_dir=str(tmp_path))
    assert plan["offers"] == [], name + " must never be automated"
    assert plan["guidance"] and len(plan["guidance"][0]["text"]) > 60
    assert name not in fx.FX_FIXES
    assert "BETTER DONE BY YOU" in fx.fx_render(plan)


def test_a_door_with_no_advice_still_says_something(tmp_path):
    plan = fx.fx_plan(doors=[door("odd:thing", fix="Open Settings and look.")], managed=(False, ""),
                      config_dir=str(tmp_path))
    assert plan["guidance"][0]["text"] == "Open Settings and look."


def test_a_managed_computer_is_left_alone(monkeypatch, tmp_path):
    _patch_fix(monkeypatch)
    plan = fx.fx_plan(doors=[door("windows:remote-desktop")], managed=(True, "your organisation"),
                      config_dir=str(tmp_path))
    assert plan["offers"] == []
    assert "your organisation" in plan["guidance"][0]["text"]
    assert "managed by your organisation" in fx.fx_render(plan)


def test_a_managed_computer_refuses_to_apply(monkeypatch, tmp_path):
    _patch_fix(monkeypatch)
    monkeypatch.setattr(fx, "fx_managed", lambda: (True, "a company domain"))
    runner = Runner()
    result = fx.fx_apply("windows:remote-desktop", confirm=lambda q: True, config_dir=str(tmp_path),
                         runner=runner)
    assert not result["done"] and "a company domain" in result["why"] and runner.commands == []


# --- applying ------------------------------------------------------------------------------------------------

def test_nothing_happens_without_a_yes(monkeypatch, tmp_path):
    _patch_fix(monkeypatch)
    monkeypatch.setattr(fx, "fx_managed", lambda: (False, ""))
    runner = Runner()
    result = fx.fx_apply("windows:remote-desktop", confirm=lambda q: False, config_dir=str(tmp_path),
                         runner=runner)
    assert not result["done"] and runner.commands == []
    assert not os.path.isdir(fx.fx_records_dir(str(tmp_path))) or not os.listdir(fx.fx_records_dir(str(tmp_path)))


def test_the_question_says_what_will_happen_and_that_there_is_a_way_back(monkeypatch, tmp_path):
    _patch_fix(monkeypatch)
    monkeypatch.setattr(fx, "fx_managed", lambda: (False, ""))
    asked = []
    fx.fx_apply("windows:remote-desktop", confirm=lambda q: asked.append(q) or False,
                config_dir=str(tmp_path), runner=Runner())
    assert "What it does:" in asked[0] and "Before you say yes:" in asked[0] and "--undo-fix" in asked[0]


def test_the_undo_record_is_written_before_the_change(monkeypatch, tmp_path):
    _patch_fix(monkeypatch, before={"found": True, "value": "0"})
    monkeypatch.setattr(fx, "fx_managed", lambda: (False, ""))
    order = []

    class Watcher(Runner):
        def __call__(self, script, timeout=0):
            order.append("ran")
            assert os.listdir(fx.fx_records_dir(str(tmp_path))), "the record must exist before the command runs"
            return super().__call__(script, timeout)
    result = fx.fx_apply("windows:remote-desktop", confirm=lambda q: True, config_dir=str(tmp_path),
                         runner=Watcher())
    assert result["done"] and order == ["ran"]
    with open(result["record"], encoding="utf-8") as fh:
        record = json.load(fh)
    assert record["before"] == {"found": True, "value": "0"}
    assert record["undo"].startswith("UNDO") and record["applied"].startswith("APPLY")
    assert record["result"] == "done"


def test_a_fix_that_did_not_work_says_so(monkeypatch, tmp_path):
    _patch_fix(monkeypatch, after_ok=False)
    monkeypatch.setattr(fx, "fx_managed", lambda: (False, ""))
    result = fx.fx_apply("windows:remote-desktop", confirm=lambda q: True, config_dir=str(tmp_path),
                         runner=Runner(works=False))
    assert not result["done"] and "did not change" in result["why"]
    with open(result["record"], encoding="utf-8") as fh:
        assert json.load(fh)["result"] == "did not take effect"


def test_a_fix_whose_previous_setting_cannot_be_recorded_is_not_offered(monkeypatch, tmp_path):
    name = "windows:firewall"

    def no_record(state):
        raise fx.FxError("the firewall's previous setting was not recorded")
    monkeypatch.setitem(fx.FX_FIXES, name, dict(fx.FX_FIXES[name], platform=sys.platform,
                                                read=lambda: {"profiles": ""}, undo=no_record))
    monkeypatch.setattr(fx, "fx_managed", lambda: (False, ""))
    runner = Runner()
    result = fx.fx_apply(name, confirm=lambda q: True, config_dir=str(tmp_path), runner=runner)
    assert not result["done"] and "not recorded" in result["why"] and runner.commands == []


def test_an_unknown_fix_is_refused(tmp_path):
    with pytest.raises(fx.FxError):
        fx.fx_apply("windows:make-tea", confirm=lambda q: True, config_dir=str(tmp_path), runner=Runner())


# --- undoing -------------------------------------------------------------------------------------------------

def test_undo_runs_the_recorded_command(monkeypatch, tmp_path):
    _patch_fix(monkeypatch, before={"found": False, "value": None})
    monkeypatch.setattr(fx, "fx_managed", lambda: (False, ""))
    applied = fx.fx_apply("windows:remote-desktop", confirm=lambda q: True, config_dir=str(tmp_path),
                          runner=Runner())
    name = os.path.basename(applied["record"])[:-5]
    runner = Runner()
    result = fx.fx_undo(name, confirm=lambda q: True, config_dir=str(tmp_path), runner=runner)
    assert result["done"] and runner.commands == ['UNDO {"found": false, "value": null}']
    with open(applied["record"], encoding="utf-8") as fh:
        assert json.load(fh)["result"] == "undone"


def test_undo_needs_a_yes_and_a_record(monkeypatch, tmp_path):
    _patch_fix(monkeypatch)
    monkeypatch.setattr(fx, "fx_managed", lambda: (False, ""))
    applied = fx.fx_apply("windows:remote-desktop", confirm=lambda q: True, config_dir=str(tmp_path),
                          runner=Runner())
    runner = Runner()
    result = fx.fx_undo(os.path.basename(applied["record"])[:-5], confirm=lambda q: False,
                        config_dir=str(tmp_path), runner=runner)
    assert not result["done"] and runner.commands == []
    with pytest.raises(fx.FxError):
        fx.fx_undo("nothing-like-this", confirm=lambda q: True, config_dir=str(tmp_path), runner=runner)


def test_past_changes_are_listed_with_how_to_put_them_back(monkeypatch, tmp_path):
    _patch_fix(monkeypatch)
    monkeypatch.setattr(fx, "fx_managed", lambda: (False, ""))
    fx.fx_apply("windows:remote-desktop", confirm=lambda q: True, config_dir=str(tmp_path), runner=Runner())
    plan = fx.fx_plan(doors=[], managed=(False, ""), config_dir=str(tmp_path))
    text = fx.fx_render(plan)
    assert "WHAT HAS BEEN CHANGED BEFORE" in text and "--undo-fix" in text


# --- the commands themselves (built, never run) --------------------------------------------------------------

def test_the_real_commands_look_right():
    assert fx._fx_rdp_apply({}) == ("New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' "
                                    "-Force | Out-Null; Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet"
                                    "\\Control\\Terminal Server' -Name 'fDenyTSConnections' -Value 1 -Type DWord "
                                    "-Force")
    assert "Remove-ItemProperty" in fx._fx_rdp_undo({"found": False})
    assert "-Value 0 -Type DWord" in fx._fx_rdp_undo({"found": True, "value": "0"})
    assert fx._fx_firewall_undo({"profiles": "Domain=True;Public=False;Private=True"}) == (
        "Set-NetFirewallProfile -Profile Domain -Enabled True; "
        "Set-NetFirewallProfile -Profile Public -Enabled False; "
        "Set-NetFirewallProfile -Profile Private -Enabled True")
    with pytest.raises(fx.FxError):
        fx._fx_firewall_undo({"profiles": ""})
    assert "-NoRestart" in fx._fx_smb1_apply({}) and "Enable-WindowsOptionalFeature" in fx._fx_smb1_undo({})


def test_every_fix_is_complete_and_warns():
    for name, fix in fx.FX_FIXES.items():
        assert fix["platform"] in ("win32", "darwin", "linux")
        assert len(fix["does"]) > 30 and len(fix["warn"]) > 40, name + " does not explain itself"
        assert fix["title"] and not fix["title"].endswith(".")
        for key in ("read", "apply", "undo", "verify"):
            assert callable(fix[key]), "{} has no {}".format(name, key)


def test_no_fix_ever_touches_a_password_or_encryption():
    for name, fix in fx.FX_FIXES.items():
        built = fix["apply"]({"found": True, "value": "0", "profiles": "Domain=True", "state": "Enabled"})
        low = (built + fix["does"]).lower()
        for banned in ("defaultpassword", "bitlocker", "manage-bde", "filevault", "-password", "net user"):
            assert banned not in low, "{} touches {}".format(name, banned)


# --- entry points --------------------------------------------------------------------------------------------
from test_followup_fixes import bundle  # noqa: E402,F401  (pytest fixture)


def test_bundle_lists_fixes_without_changing_anything(bundle, capsys, monkeypatch):
    monkeypatch.setattr(bundle, "reader_run", lambda *a, **k: pytest.fail("a computer scan must not start"),
                        raising=False)
    monkeypatch.setattr(bundle, "fx_plan", lambda *a, **k: {"managed": False, "managed_by": "", "offers": [],
                                                            "guidance": [], "records": [], "admin": False},
                        raising=False)
    assert bundle._bundle_main(["--no-menu", "--no-banner", "--no-feeds", "--fix-it", "list"]) == 0
    assert "CLOSE THE DOORS FOUND OPEN" in capsys.readouterr().out
