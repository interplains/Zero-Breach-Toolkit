"""The window's layout: paragraphs fit the width they have, and switching the
language keeps what the person had chosen.

Most tests use a withdrawn window, which is never drawn on the screen. The
geometry test needs a drawn window and runs only on Linux with a display
(for example under Xvfb), so it never opens a window on a desktop.
"""
import os
import queue
import shutil
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import cli, gui  # noqa: E402
from zbtriage.bidi import _MARKS  # noqa: E402
from zbtriage.i18n import i18n_set  # noqa: E402


def _training_document(tmp, scenario="cellebrite"):
    fake = SimpleNamespace(hooks=cli._gui_hooks(), stop_requested=threading.Event(),
                           events=queue.Queue())
    with patch.dict(os.environ, {"TMPDIR": tmp, "TEMP": tmp, "TMP": tmp}):
        gui.GuiApp._run_check(fake, "training", None, scenario)
    kind, doc = None, None
    while not fake.events.empty():
        kind, doc = fake.events.get()
    assert kind == "done", doc
    return doc


class WindowCase(unittest.TestCase):
    mapped = False

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="gui_layout_")
        try:
            import tkinter as tk
            self.root = tk.Tk()
        except Exception as exc:  # noqa: BLE001 - no display here
            shutil.rmtree(self.tmp, ignore_errors=True)
            self.skipTest("no window available: {}".format(exc))
        if not self.mapped:
            self.root.withdraw()
        i18n_set("en")
        self.app = gui.GuiApp(self.root, cli._gui_hooks())

    def tearDown(self):
        try:
            self.root.destroy()
        finally:
            i18n_set("en")
            shutil.rmtree(self.tmp, ignore_errors=True)


class TestLanguageSwitch(WindowCase):
    def test_the_example_row_is_shown_again(self):
        self.app.check.set("training")
        self.app.training_choice.set(self.app.training_names[-1])
        self.app.set_language("ar")
        self.assertEqual(self.app.training_frame.winfo_manager(), "grid")
        self.assertEqual(self.app.training_choice.get(), self.app.training_names[-1])
        self.app.set_language("fr")
        self.assertEqual(self.app.training_frame.winfo_manager(), "grid")
        self.assertEqual(self.app.close_note.winfo_manager(), "")

    def test_the_phone_row_folder_and_tab_are_kept(self):
        self.app.check.set("phone")
        self.app.phone_kind.set(self.app.phone_kinds[1])
        self.app.phone_folder.set(self.tmp)
        self.app.tabs.select(self.app.tab_help)
        self.app.set_language("de")
        self.assertEqual(self.app.phone_frame.winfo_manager(), "grid")
        self.assertEqual(self.app.phone_folder.get(), self.tmp)
        self.assertEqual(self.app.phone_kind.get(), self.app.phone_kinds[1])
        self.assertEqual(self.app.tabs.index(self.app.tabs.select()), self.app.tabs.index(self.app.tab_help))

    def test_one_watcher_on_the_chosen_check(self):
        for code in ("ar", "ja", "en"):
            self.app.set_language(code)
        self.assertEqual(len(self.app.check.trace_info()), 1)

    def test_the_window_size_is_not_reset(self):
        self.root.geometry("900x700")
        self.root.update_idletasks()
        self.app.set_language("es")
        self.root.update_idletasks()
        self.assertTrue(self.root.geometry().startswith("900x700"), self.root.geometry())

    def test_the_result_is_kept(self):
        doc = _training_document(self.tmp)
        self.app._show_result(doc, select=False)
        self.app.set_language("ar")
        self.assertIs(self.app.document, doc)
        self.assertTrue(self.app.next_text.cget("text").strip())


class TestParagraphsFitTheirWidth(WindowCase):
    def _all_fit(self, width):
        for label in self.app._fitted:
            label._fit_available = lambda width=width: width
        self.app._refit_all()
        return self.app._fitted

    def test_wrap_follows_the_width_in_english(self):
        self.app._show_result(_training_document(self.tmp), select=False)
        for width in (800, 520):
            fitted = self._all_fit(width)
            self.assertIn(self.app.next_text, fitted)
            for label in fitted:
                self.assertEqual(int(str(label.cget("wraplength"))), width)

    def test_right_to_left_lines_are_wrapped_for_the_width_they_have(self):
        self.app._show_result(_training_document(self.tmp), select=False)
        self.app.set_language("ar")
        for width in (840, 500):
            fitted = self._all_fit(width)
            self.assertIn(self.app.next_text, fitted)
            for label in fitted:
                measure = self.app._measure_font(label).measure
                lines = str(label.cget("text")).split("\n")
                for line in lines:
                    bare = "".join(c for c in line if c not in _MARKS)
                    if " " in bare.strip():      # a single long word cannot be wrapped
                        self.assertLessEqual(measure(bare), width + 2, (label, line))
                # Wrapped for this width, not a fixed one: the lines are long
                # enough to fill it (every line but a paragraph's last).
                self.assertEqual(int(str(label.cget("wraplength"))), 0)


@unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("DISPLAY"),
                     "draws a window: runs on Linux with a display (Xvfb) only")
class TestDrawnWindowGeometry(WindowCase):
    """At the narrowest planned widths no paragraph runs past its box."""
    mapped = True

    def _check_inside(self, label):
        parent = self.root.nametowidget(label.winfo_parent())
        right = label.winfo_x() + label.winfo_reqwidth()
        self.assertLessEqual(right, parent.winfo_width(), (str(label), label.cget("text")[:60]))

    def test_nothing_is_cut_off(self):
        doc = _training_document(self.tmp, "spyware")
        for code in ("en", "ar"):
            self.app.set_language(code)
            self.app._show_result(doc, select=False)
            for size in ("940x820", "780x640"):
                self.root.geometry(size)
                for tab in (self.app.tab_check, self.app.tab_result):
                    self.app.tabs.select(tab)
                    for _ in range(5):
                        self.root.update()
                    for label in self.app._fitted:
                        if label.winfo_ismapped():
                            self._check_inside(label)


if __name__ == "__main__":
    unittest.main()
