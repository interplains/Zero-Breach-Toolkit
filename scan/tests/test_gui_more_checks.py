"""Window: More checks (home network, trackers, household report, DNS log) and the doors dialog."""
import json
import os
from unittest.mock import patch

from zbtriage import gui, homenet

from test_gui_layout import WindowCase


class TestMoreChecks(WindowCase):
    def _toplevels(self):
        import tkinter as tk
        return [w for w in self.root.winfo_children() if isinstance(w, tk.Toplevel)]

    def test_more_checks_lists_every_tool(self):
        before = len(self._toplevels())
        self.app.more_checks()                  # the button opens the More checks tab, not a pop-up
        self.assertEqual(len(self._toplevels()), before)
        self.assertEqual(self.app.tabs.index("current"), self.app.tabs.index(self.app.tab_more))
        win = self.app.tab_more
        labels = []

        def walk(w):                       # the list sits inside a scrolling frame
            for child in w.winfo_children():
                if child.winfo_class() == "TButton" and child.cget("text") != "Close":
                    labels.append(child.cget("text"))
                walk(child)
        walk(win)
        self.assertIn('Check a link or message...', labels)
        self.assertIn('Check a network recording...', labels)
        self.assertIn('What starts automatically...', labels)
        self.assertIn('Send evidence to a helper...', labels)
        self.assertIn("Look up a file's fingerprint...", labels)
        self.assertIn("Look through Windows' own records...", labels)
        self.assertIn('Close the doors found open...', labels)
        self.assertIn('Check a suspicious email...', labels)
        self.assertIn('Check a QR code...', labels)
        self.assertIn('Was a phone copied by a forensics tool?...', labels)
        self.assertIn('Check a suspicious file...', labels)
        self.assertIn('Check my online accounts...', labels)
        self.assertIn('I got a threat warning...', labels)
        self.assertEqual(len(labels), 20, labels)

    def test_account_checklist_blank_steps_are_not_checked(self):
        import tkinter as tk
        self.app.account_checklist()
        win = self._toplevels()[-1]
        self.assertEqual(win.title(), "Check my online accounts")
        radios, buttons = [], {}

        def walk(w):
            for child in w.winfo_children():
                if child.winfo_class() == "TRadiobutton":
                    radios.append(child)
                elif child.winfo_class() == "TButton":
                    buttons[child.cget("text")] = child
                walk(child)
        walk(win)
        from zbtriage.accounts import AC_STEPS
        self.assertEqual(len(radios), 3 * len(AC_STEPS))
        radios[1].invoke()                          # first step: something I don't recognise
        buttons["Show the result"].invoke()
        result = self._toplevels()[-1]
        self.assertEqual(result.title(), "Your online accounts")
        text = [c for c in result.winfo_children() if isinstance(c, tk.Label)][0].cget("text")
        self.assertIn("1 thing(s) to fix", text)

    def test_link_check_window_opens_with_a_paste_box(self):
        self.app.link_check()
        win = self._toplevels()[-1]
        self.assertEqual(win.title(), "Check a link or message")

    def test_home_network_contacts_nothing_without_yes(self):
        target = ("192.168.1.37", homenet.hn_subnet("192.168.1.37"), "192.168.1.1", "")
        with patch.object(homenet, "hn_target", return_value=target), \
                patch.object(homenet, "hn_check", side_effect=AssertionError("must not run")), \
                patch("tkinter.messagebox.askyesno", return_value=False) as ask:
            self.app.home_network()
        self.assertIn("192.168.1.0/24", ask.call_args[0][1])
        self.assertIn("without any password", ask.call_args[0][1])

    def test_check_file_opens_a_result_with_a_sealed_copy_button(self):
        path = os.path.join(self.tmp, "invoice.pdf")
        with open(path, "wb") as fh:
            fh.write(b"%PDF-1.7 /OpenAction /JS (x)")
        with patch.object(self.app, "_in_background", lambda title, work, show: show(work())):
            self.app.check_file(path)
        win = self._toplevels()[-1]
        self.assertEqual(win.title(), "Check a suspicious file")
        texts = []

        def walk(w):
            for child in w.winfo_children():
                try:
                    texts.append(child.cget("text"))
                except Exception:
                    pass
                walk(child)
        walk(win)
        self.assertIn("Save a sealed copy...", texts)
        self.assertTrue(any("worth an expert" in str(t) for t in texts), texts)

    def test_household_report_window(self):
        report = os.path.join(self.tmp, "pc.json")
        with open(report, "w", encoding="utf-8") as fh:
            json.dump({"tool": {"name": "zero-breach-toolkit"}, "verdict": {"status": "NO_KNOWN_INDICATORS",
                                                                             "gaps": []},
                       "scope": {}, "modules": {}, "platform": {"system": "Windows"}}, fh)
        with patch("tkinter.messagebox.askokcancel", return_value=True) as explain, \
                patch("tkinter.filedialog.askopenfilenames", return_value=(report,)):
            self.app.household()
        self.assertIn(".json", explain.call_args[0][1])          # says what to pick before the picker opens
        win = self._toplevels()[-1]
        self.assertEqual(win.title(), "Household report")

    def test_household_cancel_stops_before_the_file_picker(self):
        with patch("tkinter.messagebox.askokcancel", return_value=False), \
                patch("tkinter.filedialog.askopenfilenames", side_effect=AssertionError("must not open")):
            self.app.household()

    def test_tracker_start_screen_offers_three_plain_choices(self):
        import sys
        import types
        before = len(self._toplevels())
        with patch.dict(sys.modules, {"bleak": types.ModuleType("bleak")}), \
                patch.object(self.app, "_listen_for_trackers") as listen:
            self.app.trackers()
            win = self._toplevels()[-1]
            self.assertEqual(len(self._toplevels()), before + 1)
            texts = []

            def walk(w):
                for child in w.winfo_children():
                    try:
                        texts.append(child.cget("text"))
                    except Exception:
                        pass
                    walk(child)
            walk(win)
            self.assertIn("3 minutes - recommended", texts)
            self.assertIn("Start listening", texts)
            start = [b for b in win.winfo_children()[0].winfo_children() if b.cget("text") == "Start listening"][0]
            start.invoke()
        listen.assert_called_once_with(3)

    def test_dns_log_starts_a_normal_check(self):
        log = os.path.join(self.tmp, "dns.log")
        with open(log, "w", encoding="utf-8") as fh:
            fh.write("Nov  8 10:00:01 dnsmasq[1]: query[A] example.org from 192.168.1.20\n")
        started = []
        with patch("tkinter.filedialog.askopenfilename", return_value=log), \
                patch("threading.Thread") as thread:
            thread.return_value.start = lambda: started.append(True)
            self.app.dns_log()
        self.assertEqual(started, [True])
        self.assertEqual(thread.call_args.kwargs["kwargs"]["argv_override"][:2], ["--dns-log", log])

    def test_doors_button_counts_open_doors(self):
        self.app.document = {"doors": [{"door": "a", "state": "open", "title": "x", "severity": "high"},
                                       {"door": "b", "state": "closed", "title": "y", "severity": "low"}]}
        self.app._doors_label(self.app.document)
        self.assertEqual(self.app.doors_button.cget("text"), "1 door to close...")
        self.app.show_doors()
        self.assertEqual(self._toplevels()[-1].title(), "Doors to close")


def test_admin_button_only_when_it_would_help(monkeypatch):
    monkeypatch.setattr(gui.sys, "platform", "win32")
    monkeypatch.setattr(gui, "gui_is_admin", lambda: False)
    needs = {"verdict": {"gaps": ["windows-execution/windows-prefetch: ... (Windows lets only administrators read "
                                  "this; run the check as administrator to include it)"]}}
    assert gui.gui_admin_would_help(needs)
    assert not gui.gui_admin_would_help({"verdict": {"gaps": ["browser: locked file"]}})
    monkeypatch.setattr(gui, "gui_is_admin", lambda: True)
    assert not gui.gui_admin_would_help(needs)
    monkeypatch.setattr(gui.sys, "platform", "linux")
    assert not gui.gui_admin_would_help(needs)


def test_source_runs_are_told_how_rather_than_elevated(monkeypatch):
    monkeypatch.setattr(gui.sys, "frozen", False, raising=False)
    assert "administrator terminal" in gui.gui_restart_elevated()
