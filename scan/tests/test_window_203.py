"""Window fixes of 2.0.3: the phone guides, saving a report, Help that names the
buttons by their real labels, right-to-left lines, the indicator-update lines,
the fresh-profile note and the choice list that no longer shifts."""

import json
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

from zbtriage import bidi, gui, report, scope  # noqa: E402
from zbtriage import i18n  # noqa: E402
from zbtriage.i18n import T, i18n_set  # noqa: E402

from test_gui_layout import WindowCase  # noqa: E402

def _have_tk():
    try:
        import tkinter  # noqa: F401
        return True
    except ImportError:
        return False


HEADLINES = ("No known spyware traces found", "Only references found", "Something needs a closer look")
BUTTONS = ("A phone", "Find iPhone backups", "Practise")


class TestPhoneGuides(unittest.TestCase):
    def tearDown(self):
        i18n_set("en")

    def _packaged(self, platform):
        with patch.object(sys, "frozen", True, create=True):
            return gui.gui_guide_text(platform)

    def test_the_packaged_program_gets_the_windows_own_steps(self):
        for platform in ("ios", "android"):
            text = self._packaged(platform)
            for word in ("python", "scan/", "--phone", "--collect-android", "--backup-password",
                         "inside the Zero-Breach-Toolkit folder", "run the tool with no options", "menu"):
                self.assertNotIn(word, text, (platform, word))
            for label in ("A phone", "Choose...", "Start check"):
                self.assertIn(label, text, (platform, label))
        self.assertIn("Find iPhone backups", self._packaged("ios"))
        self.assertIn("Backup password", self._packaged("ios"))
        self.assertIn("Collect from an Android phone...", self._packaged("android"))

    def test_a_script_user_keeps_the_command_line_form(self):
        with patch.object(sys, "frozen", False, create=True):
            for platform in ("ios", "android"):
                text = gui.gui_guide_text(platform)
                self.assertIn("python -X utf8 scan/zero-breach-toolkit.py --phone", text)
        self.assertIn("--backup-password", scope.scope_guide("ios"))

    def test_the_guide_names_the_buttons_in_the_chosen_language(self):
        catalog = {"A phone": "Un teléfono", "Start check": "Iniciar comprobación",
                   "Find iPhone backups": "Buscar copias del iPhone", "Choose...": "Elegir...",
                   "Backup password": "Contraseña de la copia", "What is it?": "¿Qué es?",
                   "Collect from an Android phone...": "Recopilar de un teléfono Android..."}
        i18n_set("es")
        with patch.dict(i18n._i18n_state, {"catalog": catalog}):
            for platform in ("ios", "android"):
                text = self._packaged(platform)
                self.assertIn("Un teléfono", text)
                self.assertIn("Iniciar comprobación", text)
                self.assertNotIn("\"A phone\"", text)
                self.assertNotIn("Start check", text)

    def test_the_android_answers_are_not_aligned_with_spaces(self):
        # Columns made of spaces only line up in a fixed-width font.
        for text in (scope.scope_guide("android"), self._packaged("android")):
            for line in text.splitlines():
                self.assertNotRegex(line, r"\S {2,}(->|Only|No\b)", line)
        self.assertIn("Backup? -> Only SMS", scope.scope_guide("android"))


class TestGuideWindow(WindowCase):
    def test_the_guide_scrolls_and_keeps_its_close_button(self):
        with patch.object(sys, "frozen", True, create=True):
            self.app.show_guide("android")
        guide = [w for w in self.root.winfo_children() if w.winfo_class() == "Toplevel"][-1]
        classes = []

        def walk(widget):
            classes.append(widget.winfo_class())
            for child in widget.winfo_children():
                walk(child)
        walk(guide)
        # Apple's Tk 8.5 (Aqua) reports a ttk.Scrollbar as "Scrollbar".
        self.assertTrue({"TScrollbar", "Scrollbar"} & set(classes), classes)
        self.assertIn("TButton", classes)
        button = [w for w in guide.winfo_children() if w.winfo_class() == "TButton"][0]
        self.assertEqual(button.pack_info()["side"], "bottom")
        guide.destroy()


class TestSaving(unittest.TestCase):
    def test_the_save_dialog_opens_in_downloads(self):
        with tempfile.TemporaryDirectory() as home:
            for name in ("Documents", "Downloads"):
                os.mkdir(os.path.join(home, name))
            with patch.dict(os.environ, {"USERPROFILE": home, "HOME": home}):
                self.assertEqual(gui.gui_save_folder(), os.path.join(home, "Downloads"))
            os.rmdir(os.path.join(home, "Downloads"))
            with patch.dict(os.environ, {"USERPROFILE": home, "HOME": home}):
                self.assertEqual(gui.gui_save_folder(), os.path.join(home, "Documents"))
            os.rmdir(os.path.join(home, "Documents"))
            with patch.dict(os.environ, {"USERPROFILE": home, "HOME": home}):
                self.assertEqual(gui.gui_save_folder(), home)

    def test_the_failure_says_what_happened_and_what_to_do(self):
        text = gui.gui_save_failure(PermissionError(13, "Access is denied"))
        self.assertIn("ransomware protection", text)
        self.assertIn("Downloads", text)
        self.assertIn("Access is denied", text)
        self.assertNotIn("Documents or Desktop folder instead", text)
        # The program's own refusal is already plain and is shown as it is.
        self.assertEqual(gui.gui_save_failure(OSError("report output path refused: network")),
                         "report output path refused: network")

    @unittest.skipUnless(_have_tk(), "tkinter is not installed")
    def test_a_blocked_write_shows_that_message(self):
        shown = []
        fake = SimpleNamespace(document={"x": 1}, args=None, root=None, status=SimpleNamespace(set=lambda t: None),
                               _ask_path=lambda *a: "C:/blocked/report.txt")

        def blocked(path):
            raise PermissionError(13, "Access is denied")
        with patch("tkinter.messagebox.showerror", lambda title, text, **kw: shown.append((title, text))), \
                patch.object(gui, "workflow_output_guard", lambda *a: None):
            gui.GuiApp._save(fake, blocked, "Save", "r", ".txt")
        self.assertEqual(len(shown), 1)
        self.assertEqual(shown[0][0], "Not saved")
        self.assertIn("Downloads", shown[0][1])


class TestHelpNamesTheButtons(unittest.TestCase):
    def tearDown(self):
        i18n_set("en")

    def test_help_quotes_the_translated_labels(self):
        catalog = {"A phone": "Un teléfono", "Find iPhone backups": "Buscar copias del iPhone",
                   "Practise": "Practicar", HEADLINES[0]: "No se encontró ningún rastro",
                   HEADLINES[1]: "Solo referencias", HEADLINES[2]: "Algo requiere atención"}
        i18n_set("es")
        with patch.dict(i18n._i18n_state, {"catalog": catalog}):
            text = gui.gui_help_text()
        for name in catalog.values():
            self.assertIn(name, text)
        for english in BUTTONS + HEADLINES:
            self.assertNotIn("\"" + english + "\"", text)

    def test_in_every_language_help_matches_the_buttons(self):
        for code in i18n.i18n_available():
            i18n_set(code)
            text = gui.gui_help_text()
            for english in BUTTONS + HEADLINES:
                self.assertIn(T(english), text, (code, english))
            self.assertNotIn("{", text, code)


class TestRightToLeft(unittest.TestCase):
    def tearDown(self):
        bidi.bidi_mode("win32")

    def test_native_lines_stay_under_the_length_tk_can_draw(self):
        bidi.bidi_mode("win32")
        text = " ".join(["كلمة"] * 60)          # one long Arabic paragraph, 4 characters a word
        lines = bidi.bidi_wrap(text, len, 5000).split("\n")     # a very wide window
        self.assertGreater(len(lines), 1)
        for line in lines:
            bare = "".join(c for c in line if c not in bidi._MARKS)
            self.assertLessEqual(len(bare.encode("utf-8")), 180, line)
        self.assertEqual(" ".join("".join(c for c in l if c not in bidi._MARKS) for l in lines), text)

    def test_the_other_layout_is_not_cut_by_bytes(self):
        bidi.bidi_mode("x11")
        text = " ".join(["كلمة"] * 60)
        self.assertEqual(len(bidi.bidi_wrap(text, len, 5000).split("\n")), 1)

    def test_a_full_stop_after_a_latin_word_goes_to_the_reading_end(self):
        bidi.bidi_mode("x11")
        self.assertTrue(bidi.bidi_line("افتح Android.").startswith(".Android "))
        self.assertTrue(bidi.bidi_line("اكتب Enter:").startswith(":Enter "))
        # Not part of a sentence: an address, an abbreviation, a number.
        self.assertTrue(bidi.bidi_line("افتح example.com.").startswith("example.com."))
        self.assertTrue(bidi.bidi_line("افتح v2.0.").startswith("v2.0."))


class TestUpdateLines(unittest.TestCase):
    RAW = ["[=] Intellexa Predator: 583 indicators, unchanged (sha256 0123456789abcdef)",
           "[+] NSO Pegasus: 1,204 indicators (sha256 fedcba9876543210)",
           "[!] Some Source failed: HTTP Error 404: Not Found",
           "Indicator sets in C:\\x\\indicators: 29 up to date, 1 failed; 13,131 indicators. Full SHA-256 "
           "and download times are in manifest.json there.",
           "Exploited-vulnerability list: 1,500 entries; reading 12 records for the checked programs...",
           "Actively exploited software list (2026.10.30): 1,500 entries for the checked programs."]

    def test_lines_are_plain_words(self):
        shown = [gui.gui_update_line(line) for line in self.RAW]
        self.assertEqual(shown[0], "Intellexa Predator: already up to date")
        self.assertEqual(shown[1], "NSO Pegasus: updated")
        self.assertEqual(shown[2], "Some Source: could not be updated")
        self.assertEqual(shown[3], "29 lists up to date, 1 could not be updated")
        for text in shown:
            self.assertNotIn("sha256", text.lower())
            self.assertNotIn("indicators,", text)
        self.assertEqual(gui.gui_update_line("Version 9.9.9 is available: https://x.invalid"),
                         "Version 9.9.9 is available: https://x.invalid")

    def test_the_window_shows_the_plain_line_and_keeps_the_exact_one(self):
        fake = SimpleNamespace(events=queue.Queue(), hooks={})

        def update():
            for line in self.RAW[:2]:
                print(line, file=sys.stderr)
            return 0
        fake.hooks["update"] = update
        gui.GuiApp._run_update(fake)
        statuses = []
        while not fake.events.empty():
            kind, payload = fake.events.get()
            if kind == "status":
                statuses.append(payload)
        self.assertEqual(statuses, ["Intellexa Predator: already up to date", "NSO Pegasus: updated"])
        self.assertEqual(fake.update_details, self.RAW[:2])


class TestFreshProfile(unittest.TestCase):
    def test_missing_until_a_list_is_downloaded(self):
        with tempfile.TemporaryDirectory() as cache:
            with patch("zbtriage.feeds.default_cache_dir", lambda: cache):
                self.assertTrue(gui.gui_lists_missing())
                with open(os.path.join(cache, "manifest.json"), "w", encoding="utf-8") as fh:
                    json.dump({"sources": {"a": {"file": "a.txt"}}}, fh)
                self.assertFalse(gui.gui_lists_missing())

    def test_a_damaged_manifest_says_nothing(self):
        with tempfile.TemporaryDirectory() as cache:
            with open(os.path.join(cache, "manifest.json"), "w", encoding="utf-8") as fh:
                fh.write("{broken")
            with patch("zbtriage.feeds.default_cache_dir", lambda: cache):
                self.assertFalse(gui.gui_lists_missing())


class TestFreshProfileNote(WindowCase):
    def test_the_note_shows_on_a_fresh_profile_and_goes_after_an_update(self):
        with patch.object(gui, "gui_lists_missing", lambda: True):
            self.app._lists_note_visibility()
            self.assertEqual(self.app.lists_note.winfo_manager(), "grid")
        self.assertIn("built-in", self.app.lists_note.cget("text"))
        self.assertIn("Update indicator lists", self.app.lists_note.cget("text"))
        with patch.object(gui, "gui_lists_missing", lambda: False):
            self.app.events.put(("updated", "Indicator lists updated."))
            self.app._begin_busy("x")
            self.app._drain()
            self.assertEqual(self.app.lists_note.winfo_manager(), "")


class TestPrivacyNote(unittest.TestCase):
    def test_windows_is_named_only_on_windows(self):
        self.assertIn("Windows", report._PRIVACY_NOTE)
        self.assertNotIn("Windows", report._PRIVACY_NOTE_OTHER)
        self.assertIn("your username", report._PRIVACY_NOTE_OTHER)


@unittest.skipUnless(sys.platform.startswith("linux") and os.environ.get("DISPLAY"),
                     "draws a window: runs on Linux with a display (Xvfb) only")
class TestDrawnChoices(WindowCase):
    mapped = True

    def test_descriptions_do_not_move_when_a_row_appears(self):
        first = self.app.check.get()
        label = [w for w in self.app._fitted if w.winfo_manager() == "grid"][0]
        positions = {}
        for choice in ("default", "phone", "training", "browser"):
            self.app.check.set(choice)
            for _ in range(5):
                self.root.update()
            positions[choice] = label.winfo_rootx()
        self.assertEqual(len(set(positions.values())), 1, positions)
        self.app.check.set(first)

    def test_the_guide_close_button_stays_inside_the_guide(self):
        with patch.object(sys, "frozen", True, create=True):
            self.app.show_guide("android")
        guide = [w for w in self.root.winfo_children() if w.winfo_class() == "Toplevel"][-1]
        for _ in range(5):
            self.root.update()
        button = [w for w in guide.winfo_children() if w.winfo_class() == "TButton"][0]
        self.assertLessEqual(button.winfo_y() + button.winfo_height(), guide.winfo_height())
        guide.destroy()


if __name__ == "__main__":
    unittest.main()
