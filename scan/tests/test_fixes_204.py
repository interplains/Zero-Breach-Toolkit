"""2.0.4: findings from real Mac and Windows runs."""
import subprocess
import sys
from unittest.mock import patch

from zbtriage import gui, localpaths
from zbtriage.kevdata import kev_affected
from zbtriage.modules import hashscan


# --- a year in a CVE record is not a version ---------------------------------------------

def test_a_year_bound_does_not_make_a_current_release_look_old():
    assert kev_affected("27.2", [{"product": "macOS", "version": "unspecified", "lessThan": "2021"}], "macOS") is None
    assert kev_affected("27.2", [{"product": "macOS", "version": "0", "lessThanOrEqual": "2022"}], "macOS") is None


def test_real_version_bounds_still_compare():
    assert kev_affected("15.1", [{"product": "macOS", "version": "0", "lessThan": "15.2"}], "macOS") is True
    assert kev_affected("15.3", [{"product": "macOS", "version": "0", "lessThan": "15.2"}], "macOS") is False


def test_a_product_numbered_by_year_still_compares():
    assert kev_affected("2019", [{"product": "Office", "version": "0", "lessThan": "2021"}], "Office") is True


def test_a_year_bound_beside_a_real_range_keeps_the_real_range():
    ranges = [{"version": "0", "lessThan": "2021"}, {"version": "0", "lessThan": "15.2"}]
    assert kev_affected("15.1", ranges) is True
    assert kev_affected("27.2", ranges) is False


# --- Full Disk Access advice --------------------------------------------------------------

def test_advice_is_dropped_when_access_is_already_on():
    reasons = {"denied": 3, "large": 0, "unreadable": 0}
    with patch.object(sys, "platform", "darwin"), patch.object(hashscan, "mac_has_full_disk_access", lambda: True):
        text = hashscan._hs_reasons(reasons)
    assert "even with Full Disk Access" in text and "give " not in text


def test_advice_stays_when_access_is_off():
    reasons = {"denied": 3, "large": 0, "unreadable": 0}
    with patch.object(sys, "platform", "darwin"), patch.object(hashscan, "mac_has_full_disk_access", lambda: False):
        assert "give " in hashscan._hs_reasons(reasons)


def test_full_disk_access_is_only_detected_on_a_mac():
    with patch.object(sys, "platform", "win32"):
        assert localpaths.mac_has_full_disk_access() is False


# --- window ------------------------------------------------------------------------------

def test_a_stopped_check_does_not_say_nothing_matched():
    doc = {"verdict": {"status": "NO_KNOWN_INDICATORS_WITH_GAPS", "gaps": ["a/b: gap"]}, "modules": {},
           "scope": {"cancelled": True}}
    text = " ".join(gui.gui_next_steps(doc))
    assert "stopped" in text and "Nothing matched" not in text


def test_the_save_dialog_lists_file_types():
    assert gui.gui_save_types(".txt")[0][1] == "*.txt"
    assert gui.gui_save_types(".json")[0][1] == "*.json"
    assert gui.gui_save_types(".txt")[-1][1] == "*.*"


def test_fonts_are_chosen_for_the_writing_system_on_windows_only():
    with patch.object(sys, "platform", "win32"), patch.object(gui, "i18n_lang", lambda: "zh"):
        assert gui.gui_font_family("Segoe UI", ("Segoe UI", "Microsoft YaHei UI")) == "Microsoft YaHei UI"
        assert gui.gui_font_family("Segoe UI", ("Segoe UI",)) == "Segoe UI"
    with patch.object(sys, "platform", "linux"), patch.object(gui, "i18n_lang", lambda: "zh"):
        assert gui.gui_font_family("DejaVu", ("Microsoft YaHei UI",)) == "DejaVu"


# --- no terminal left in the taskbar ------------------------------------------------------

def _relaunch(frozen=True, clicked=True, platform="win32", env=None, popen=None):
    calls = []

    def fake(args, **kw):
        calls.append((args, kw))
        if popen:
            raise popen

    with patch.object(sys, "platform", platform), patch.object(sys, "frozen", frozen, create=True), \
            patch.object(gui, "gui_launched_by_double_click", lambda: clicked), \
            patch.object(subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True), \
            patch.dict("os.environ", env or {}, clear=False), patch.object(subprocess, "Popen", fake):
        return gui.gui_relaunch_without_console(), calls


def test_a_double_clicked_program_restarts_without_a_console():
    with patch.dict("os.environ", {}, clear=False):
        import os
        os.environ.pop("ZB_WINDOW_ONLY", None)
        done, calls = _relaunch()
    assert done is True
    assert calls[0][1]["env"]["ZB_WINDOW_ONLY"] == "1"
    assert calls[0][1]["env"]["PYINSTALLER_RESET_ENVIRONMENT"] == "1"


def test_it_never_restarts_twice():
    done, calls = _relaunch(env={"ZB_WINDOW_ONLY": "1"})
    assert done is False and not calls


def test_it_stays_put_from_a_terminal_or_as_a_script():
    import os
    with patch.dict("os.environ", {}, clear=False):
        os.environ.pop("ZB_WINDOW_ONLY", None)
        assert _relaunch(clicked=False) == (False, [])
        assert _relaunch(frozen=False) == (False, [])
        assert _relaunch(platform="darwin") == (False, [])


def test_a_failed_restart_carries_on_here():
    import os
    with patch.dict("os.environ", {}, clear=False):
        os.environ.pop("ZB_WINDOW_ONLY", None)
        done, _calls = _relaunch(popen=OSError("blocked"))
    assert done is False
