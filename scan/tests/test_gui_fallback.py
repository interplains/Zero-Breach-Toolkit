"""No window possible (no display, or a Tk that aborts): it is never created, the check falls back to the terminal."""
import io
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import gui  # noqa: E402
from zbtriage.i18n import i18n_set  # noqa: E402

MESSAGE = "The window could not be opened on this computer, so the check is running in the terminal instead."
HINT = "To get the window, install Python from python.org/downloads and start the check with that Python."


class FallbackCase(unittest.TestCase):
    def tearDown(self):
        i18n_set("en")

    def fresh(self):
        return patch.object(gui, "_gui_probe_cache", [])

    def need_tk(self):
        try:
            import tkinter  # noqa: F401
        except ImportError:
            self.skipTest("tkinter is not installed here")

    def test_no_window_means_gui_main_returns_none_without_tk(self):
        self.need_tk()
        err = io.StringIO()
        with patch.object(gui, "gui_available", return_value=False), \
                patch("tkinter.Tk", side_effect=AssertionError("Tk created")), \
                patch.object(sys, "stderr", err):
            self.assertIsNone(gui.gui_main({"lang": "en"}))
        self.assertIn(MESSAGE, err.getvalue())

    def test_tcl_error_is_still_a_clean_fallback(self):
        self.need_tk()
        import tkinter
        err = io.StringIO()
        with patch.object(gui, "gui_available", return_value=True), \
                patch("tkinter.Tk", side_effect=tkinter.TclError("no display")), \
                patch.object(sys, "stderr", err):
            self.assertIsNone(gui.gui_main({"lang": "en"}))
        self.assertIn(MESSAGE, err.getvalue())

    def test_linux_needs_a_display(self):
        for env, want in (({}, False), ({"DISPLAY": ":0"}, True), ({"WAYLAND_DISPLAY": "w0"}, True)):
            with self.fresh(), patch.object(sys, "platform", "linux"), \
                    patch.dict(os.environ, env, clear=True):
                self.assertIs(gui.gui_available(), want)

    def test_windows_is_assumed_available_and_result_is_cached(self):
        with self.fresh(), patch.object(sys, "platform", "win32"):
            self.assertTrue(gui.gui_available())
            with patch.object(sys, "platform", "linux"), patch.dict(os.environ, {}, clear=True):
                self.assertTrue(gui.gui_available())

    def test_mac_uses_the_subprocess_probe(self):
        with self.fresh(), patch.object(sys, "platform", "darwin"), \
                patch.object(sys, "frozen", False, create=True), \
                patch.object(gui, "gui_probe", return_value=False) as probe:
            self.assertFalse(gui.gui_available())
        self.assertEqual(probe.call_args[0][0][0], sys.executable)

    def test_probe_handles_crash_signal_timeout_and_missing_program(self):
        py = sys.executable
        self.assertTrue(gui.gui_probe([py, "-c", "pass"]))
        self.assertFalse(gui.gui_probe([py, "-c", "import sys; sys.exit(3)"]))
        self.assertFalse(gui.gui_probe([py, "-c", "import os; os.abort()"]))
        self.assertFalse(gui.gui_probe([py, "-c", "import time; time.sleep(30)"], timeout=1))
        self.assertFalse(gui.gui_probe(["/no/such/program-zb"]))

    @unittest.skipIf(sys.platform == "win32", "signals are a POSIX feature")
    def test_child_killed_by_sigabrt_means_no_window(self):
        # What Apple's Python 3.9 does: Tk calls abort() while the desktop IS there.
        import signal
        code = "import os, signal; os.kill(os.getpid(), signal.SIGABRT)"
        self.assertFalse(gui.gui_probe([sys.executable, "-c", code]))
        with self.fresh(), patch.object(sys, "platform", "darwin"), \
                patch.object(sys, "frozen", False, create=True), \
                patch.object(gui, "_GUI_PROBE_CODE", code):
            self.assertFalse(gui.gui_available())

    def test_apple_system_python_gets_the_python_org_hint(self):
        # base_prefix is patched too: run under Apple's own Python, the real value
        # points at Xcode and would mark every case as Apple's Python.
        for exe, prefix, want in (
                ("/Library/Developer/CommandLineTools/usr/bin/python3",
                 "/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9", True),
                ("/usr/bin/python3",
                 "/Applications/Xcode.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9", True),
                ("/Library/Frameworks/Python.framework/Versions/3.13/bin/python3",
                 "/Library/Frameworks/Python.framework/Versions/3.13", False)):
            err = io.StringIO()
            with patch.object(sys, "platform", "darwin"), patch.object(sys, "executable", exe), \
                    patch.object(sys, "base_prefix", prefix), \
                    patch.object(sys, "frozen", False, create=True), patch.object(sys, "stderr", err):
                gui.gui_fallback_notice()
            self.assertIn(MESSAGE, err.getvalue())
            self.assertIs(HINT in err.getvalue(), want, exe)

    def test_hint_is_not_shown_off_a_mac_or_in_the_packaged_app(self):
        for plat, frozen in (("linux", False), ("win32", False), ("darwin", True)):
            err = io.StringIO()
            with patch.object(sys, "platform", plat), patch.object(sys, "executable", "/usr/bin/python3"), \
                    patch.object(sys, "frozen", frozen, create=True), patch.object(sys, "stderr", err):
                gui.gui_fallback_notice()
            self.assertNotIn(HINT, err.getvalue())

    def test_message_is_translated_in_every_language(self):
        from zbtriage.i18n import I18N_CODES, T
        langs = [l for l in I18N_CODES if l != "en"]
        self.assertTrue(langs)
        for lang in langs:
            i18n_set(lang)
            self.assertNotEqual(T(MESSAGE), MESSAGE, lang)
            self.assertNotEqual(T(HINT), HINT, lang)


if __name__ == "__main__":
    unittest.main()
