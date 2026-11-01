"""The packaged Mac app must not talk itself out of opening its window.

A double-clicked app has no terminal to fall back to, so a wrong "no window"
would look like an app that does nothing. Only a remote session can get a "no".
"""
import os
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from zbtriage import gui


def _without_ssh():
    return {k: v for k, v in os.environ.items() if k not in ("SSH_CONNECTION", "SSH_TTY")}


def test_a_local_session_never_asks_the_system_and_always_gets_a_window():
    with patch.dict(os.environ, _without_ssh(), clear=True), \
            patch("ctypes.CDLL", side_effect=AssertionError("must not be called")):
        assert gui._mac_has_window_server() is True


def test_a_remote_session_with_no_desktop_gets_no_window():
    env = dict(_without_ssh(), SSH_CONNECTION="192.0.2.1 1 192.0.2.2 22")
    with patch.dict(os.environ, env, clear=True), patch("ctypes.CDLL", side_effect=OSError("no framework")):
        assert gui._mac_has_window_server() is False


def test_the_probe_runs_plain_readable_code():
    assert gui._GUI_PROBE_CODE == "import tkinter; tkinter.Tk().destroy()"
