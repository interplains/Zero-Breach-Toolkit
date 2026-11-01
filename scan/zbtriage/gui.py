"""A simple window for people who would rather not use a terminal.

It runs exactly the same check as the terminal version, through hooks the
entry point supplies (how to read options, load indicators, run the readers
and update the lists), so the two can never disagree. The window adds one view
of its own: live network connections, read from the system and compared with
the indicators' addresses, without contacting anything.

tkinter ships with Python, so the window adds no download and no dependency.
It is imported only when the window opens: scripts and servers never need it.
"""
import datetime
import os
import queue
import sys
import threading

from .context import ScanContext, scan_recovery
from .bidi import bidi_line, bidi_mode, bidi_wrap
from .i18n import I18N_LANGUAGES, T, TN, i18n_as, i18n_available, i18n_default, i18n_lang, i18n_rtl, i18n_set
from .readers import reader_select
from .iocs import IocError
from .netconns import nc_is_remote, nc_list, nc_match
from .scope import scope_guide
from .training import TRAINING_SCENARIOS, training_cleanup, training_prepare
from .report import (V_HITS, V_NONE, V_NONE_WITH_GAPS, _defang_report, phone_source_unread,
                     prepare_document, render_human, render_summary, share_summary, write_json)
from .workflow import workflow_before_scan, workflow_output_guard, workflow_write_text

GUI_RED = "#c4161c"
GUI_INK = "#1d1d1f"
GUI_MUTED = "#5f6368"
GUI_BG = "#f6f6f7"
GUI_CARD = "#ffffff"
GUI_GOOD = "#1e7e34"
GUI_WARN = "#9a6700"

GUI_CHECKS = (
    ("browser", "Quick check", "Browsers only, where ad-delivered spyware leaves its traces. Usually 5 to 10 minutes."),
    ("default", "Standard check", "Recommended. Browsers, apps, startup items, program files and out-of-date "
                                  "programs. Usually 15 to 20 minutes."),
    ("full", "Full check", "Everything in Standard, plus web caches and more file types. Usually 30 minutes or more."),
    ("phone", "A phone", "An iPhone backup made with Finder or Apple Devices, or an Android collection. "
                         "Usually a few minutes."),
    ("training", "Practise", "A made-up phone with made-up spyware, for learning to read a report. Checks nothing real."),
)

GUI_TRAINING_LABELS = (
    ("Spyware found", "spyware"),
    ("Things worth a look", "worth-a-look"),
    ("Nothing found", "clean"),
    ("Phone seized (Cellebrite)", "cellebrite"),
)
assert {k for _l, k in GUI_TRAINING_LABELS} == set(TRAINING_SCENARIOS)

# Each step of a check as people would say it, for the progress line.
GUI_STEP_NAMES = {
    "browser": "Browsers", "hash": "Program files", "host": "System settings",
    "traces": "Apps and startup items", "windows-execution": "Programs that have run",
    "exploited-software": "Out-of-date programs", "unix-host": "System settings",
    "android-intrusion": "Phone settings", "android": "Android phone", "ios": "iPhone",
    "patterns": "Extra patterns",
}
HELPLINE = "https://www.accessnow.org/help/"
BLOCKLIST_URL = "https://github.com/interplains/Zero-Breach-Toolkit#blocking-advertising-domains"


def gui_progress(message, state):
    """Read one progress line from the check and return (text, percent).

    `state` is the caller's dict for one check: "steps" holds the step names
    the check will run (from reader_select) and the rest is kept here. The
    percentage counts finished steps, plus the share of the current step when
    the step says how far it has got (the program-file step does); it is None
    until the first step starts."""
    import re
    steps = state.setdefault("steps", [])
    message = str(message)
    started = re.match(r"\[\*\] running check: (\S+)", message)
    finished = re.match(r"\[\*\]\s+(\S+) finished in", message)
    counted = re.match(r"\[hash\] fingerprinted ([\d,]+) / ([\d,]+) candidates", message)
    working = re.match(r"\[browser\]\s+still working: (.+?) \(([\d,]+) records checked", message)
    if started:
        name = started.group(1)
        state["index"] = steps.index(name) if name in steps else state.get("index", -1) + 1
        state.update(current=name, fraction=0.0, detail="", measured=False)
    elif finished:
        state["fraction"] = 1.0
    elif counted:
        done, total = (int(x.replace(",", "")) for x in counted.groups())
        state["fraction"] = min(1.0, done / total) if total else 0.0
        state["measured"] = True
        state["detail"] = T("{done} of {total} files", done="{:,}".format(done), total="{:,}".format(total))
    elif working:
        label, records = working.groups()
        label = label[4:] if label.startswith("app:") else label
        state["detail"] = T("{name}: {records} records checked", name=label[:1].upper() + label[1:],
                            records=records)
    if "current" not in state:
        return message[:160], None
    index = max(0, state.get("index", 0))
    total = max(len(steps), index + 1)
    name = state["current"]
    text = T("Step {n} of {total}: {name}", n=index + 1, total=total,
             name=T(GUI_STEP_NAMES[name]) if name in GUI_STEP_NAMES else name)
    if state.get("detail"):
        text += " - " + state["detail"]
    percent = 100.0 * (index + state.get("fraction", 0.0)) / total
    return text, max(0.0, min(100.0, percent))


def gui_next_steps(document):
    """What the person should do now, in a few plain lines, from the result."""
    verdict = document.get("verdict", {})
    status = verdict.get("status", "")
    gaps = [str(g).lower() for g in verdict.get("gaps", [])]
    modules = document.get("modules", {})
    steps = []
    if document.get("training"):
        real = dict(document)
        real.pop("training")
        return ([T("Practice example: nothing real was checked. If this were a real result, "
                   "these would be the next steps:")] + gui_next_steps(real))
    if status == V_HITS and gui_ad_network_only(document):
        steps.append(T("This is usually an ordinary ad, not spyware, and it does not show that you were "
                       "targeted or infected. But some spyware has been delivered through advertising "
                       "networks, so it is a good idea to block them:"))
        steps.append(T("Install a reputable ad blocker in your browser, for example uBlock Origin."))
        steps.append(T("Or use a DNS resolver that blocks ads and known spyware domains, on your computer, "
                       "phone or router. The page https://archivegenocide.com/scan has a test and setup steps."))
        steps.append(T("This project publishes its own blocklists of these advertising domains (adblock, "
                       "hosts and dnsmasq formats): {url}", url=BLOCKLIST_URL))
        steps.append(T("Keep the report. If you have another reason to think you are being targeted, "
                       "such as a threat warning from Apple or Google, get expert help: {url}", url=HELPLINE))
        steps.append(T("Do not open or look up the address in the report."))
    elif status == V_HITS and gui_forensic(document):
        steps.append(T("Assume what was on the phone when it was taken was copied: messages, photos, "
                       "contacts and the accounts signed in."))
        steps.append(T("From another device, change the passwords of important accounts and sign out "
                       "other sessions. Tell the people whose conversations were on the phone."))
        steps.append(T("In documented cases spyware was installed after such an unlock: check the apps "
                       "installed around that time, and get expert help: {url}", url=HELPLINE))
        steps.append(T("Save the report (Save report... below) and keep it somewhere safe."))
    elif status == V_HITS:
        hits = [h for m in modules.values() for h in m.get("hits", [])]
        steps.append(T("Keep this device as it is: do not delete, reset or 'clean' anything yet. "
                       "What was found is the evidence."))
        steps.append(T("Save the report (Save report... below) and keep it somewhere safe."))
        if any(h.get("tier") == "stalkerware" for h in hits):
            steps.append(T("If this is a monitoring app and you could be in danger, talk to a support "
                           "service before changing anything: {url}", url="https://stopstalkerware.org/"))
        steps.append(T("Get expert help. Journalists, activists and other civil society members can "
                       "contact Access Now's free Digital Security Helpline: {url}", url=HELPLINE))
        steps.append(T("Do not open or look up the addresses in the report."))
    elif status in (V_NONE, V_NONE_WITH_GAPS) and phone_source_unread(document):
        steps.append(T("The phone's backup or collection could not be opened, so nothing in it was "
                       "checked. Check the folder you chose. For an encrypted iPhone backup, enter its "
                       "backup password and run the check again."))
    elif status in (V_NONE, V_NONE_WITH_GAPS):
        steps.append(T("Nothing matched known spyware. Keep your system and apps updated, and run the "
                       "check again now and then."))
    else:
        steps.append(T("Usually nothing to do: a name in a page you read or saved is not an infection. "
                       "If you have another reason to worry, a helpline can advise: {url}", url=HELPLINE))
    if modules.get("exploited-software", {}).get("leads"):
        steps.append(T("Update the out-of-date programs named in the summary: attackers are using "
                       "flaws in those versions right now."))
    other_leads = sum(len(m.get("leads", [])) for n, m in modules.items() if n != "exploited-software")
    if other_leads:
        steps.append(T("Read the 'worth a look' items in the summary. Each has an ordinary explanation; "
                       "if you don't recognise one, ask whoever set up the device."))
    if document.get("scope", {}).get("cancelled"):
        steps.append(T("The check was stopped before it finished. Run it again to cover the remaining steps."))
    if any(g.startswith("indicators/indicator-sources:") and "indicator source missing" in g for g in gaps):
        steps.append(T("Press 'Update indicator lists' on the Check tab, then run the check again: "
                       "this time only the built-in lists were used."))
    if any("was running" in g or "locked" in g for g in gaps):
        steps.append(T("Some open apps kept their records locked. Close your browsers and chat apps, "
                       "then run the check again to include them."))
    return steps


# What the phone folder holds, and the --ios-input value it needs ("" lets the
# reader tell an iPhone backup from an Android collection by itself).
GUI_PHONE_KINDS = (
    ("iPhone backup (Finder, Apple Devices or iTunes)", ""),
    ("Android collection (made with AndroidQF)", ""),
    ("iPhone sysdiagnose archive or folder", "sysdiagnose"),
    ("Extracted iPhone file system", "filesystem"),
)


def gui_backup_folders():
    """Local iPhone backups, newest first: [(label, path)]."""
    home = os.path.expanduser("~")
    roots = [os.path.join(home, "Library", "Application Support", "MobileSync", "Backup"),
             os.path.join(home, "Apple", "MobileSync", "Backup")]
    if os.environ.get("APPDATA"):
        roots.append(os.path.join(os.environ["APPDATA"], "Apple Computer", "MobileSync", "Backup"))
    found = []
    for root in roots:
        try:
            names = os.listdir(root)
        except OSError:
            continue
        for name in names:
            path = os.path.join(root, name)
            if os.path.isfile(os.path.join(path, "Manifest.plist")):
                try:
                    when = os.path.getmtime(path)
                except OSError:
                    when = 0
                found.append((when, path))
    found.sort(reverse=True)
    return [(datetime.datetime.fromtimestamp(when).strftime("%Y-%m-%d %H:%M") + "  " + path, path)
            for when, path in found]


def gui_self_command():
    """How to run this same program again (packaged, single file or source)."""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, os.path.abspath(sys.argv[0])]


def gui_launched_by_double_click():
    """True when nothing else shares this program's console window (Windows),
    i.e. it was opened from Explorer rather than typed into a terminal."""
    if sys.platform != "win32":
        return not sys.stdin or not sys.stdin.isatty()
    try:
        import ctypes
        ids = (ctypes.c_uint * 8)()
        count = ctypes.windll.kernel32.GetConsoleProcessList(ids, 8)
    except (AttributeError, OSError):
        return False
    # A packaged program runs as a small launcher plus Python: two processes.
    return 0 < count <= (2 if getattr(sys, "frozen", False) else 1)


def gui_hide_console():
    if sys.platform != "win32":
        return
    try:
        import ctypes
        window = ctypes.windll.kernel32.GetConsoleWindow()
        if window:
            ctypes.windll.user32.ShowWindow(window, 0)
    except (AttributeError, OSError):
        pass


def gui_forensic(document):
    """True when a finding is a trace of a phone-forensics tool (Cellebrite)."""
    return any(h.get("tier") == "forensic" for m in document.get("modules", {}).values()
               for h in m.get("hits", []))


def gui_ad_network_only(document):
    """True when every finding is advertising-network infrastructure: what an
    ordinary ad can leave behind, which the report itself says is not on its
    own a sign of being targeted or infected."""
    hits = [h for m in document.get("modules", {}).values() for h in m.get("hits", [])]
    return bool(hits) and all(h.get("tier") == "delivery" for h in hits)


def gui_stoppable_emit(stop, put):
    """The progress callback for a check run from the window. Every check
    reports progress all the time, so once `stop` is set the next report
    raises the same interruption as Ctrl+C in the terminal: what was already
    checked is kept and the rest is reported as not run. It raises once; after
    that the check winds down on its own."""
    raised = []

    def emit(message):
        if stop.is_set() and not raised:
            raised.append(True)
            raise KeyboardInterrupt
        put(("status", message))
    return emit


def gui_headline(document):
    """(colour, title, subtitle) for the result card."""
    verdict = document["verdict"]
    status = verdict.get("status", "")
    gaps = len(verdict.get("gaps", []))
    gap_note = (" " + TN("{n} check could not run; see below.", "{n} checks could not run; see below.", gaps)
                if gaps else "")
    leads = sum(len(m.get("leads", [])) for m in document.get("modules", {}).values())
    if leads:
        gap_note = " " + TN("{n} thing worth a look is listed in the summary.",
                            "{n} things worth a look are listed in the summary.", leads) + gap_note
    if document.get("scope", {}).get("cancelled") and status != V_HITS:
        return (GUI_WARN, T("Check stopped before it finished"),
                T("Nothing matched in the steps that ran, but the remaining steps were not checked.")
                + gap_note)
    if status == V_HITS and gui_forensic(document):
        return (GUI_RED, T("This phone was unlocked with a phone-forensics tool"),
                T("Traces of Cellebrite, the tool police and security services use to copy seized "
                  "phones, were found. Read the steps below.") + gap_note)
    if status == V_HITS and gui_ad_network_only(document):
        return (GUI_WARN, T("Advertising-network traces found"),
                T("A browser loaded something from an advertising network that researchers have "
                  "seen used to deliver spyware. Ordinary ads leave the same traces, so on its own "
                  "this is not a sign of infection.") + gap_note)
    if status == V_HITS:
        return (GUI_RED, T("Something needs a closer look"),
                T("Traces matching known spyware were found. Read the summary below before acting, "
                  "and keep this device as it is.") + gap_note)
    if status in (V_NONE, V_NONE_WITH_GAPS) and phone_source_unread(document):
        # Never green: a phone that could not be opened was not checked at all.
        return (GUI_WARN, T("This phone could not be checked"),
                T("Its backup or collection could not be opened, so nothing in it was checked. "
                  "This is not a clean result.") + gap_note)
    if status in (V_NONE, V_NONE_WITH_GAPS):
        return (GUI_GOOD, T("No known spyware traces found"),
                T("Nothing matched the indicators in what could be checked. That is not a guarantee.")
                + gap_note)
    return (GUI_WARN, T("Only references found"),
            T("Indicator names appeared in saved content such as web pages you read. That alone is "
              "not a sign of infection.") + gap_note)


def gui_dir(text):
    """Short text (no wrapping) for a right-to-left language, in display order:
    Tk lays words out left to right, so the order is set here (see bidi.py).
    Other languages are returned unchanged."""
    if not i18n_rtl() or not text:
        return text
    return "\n".join(bidi_line(line) for line in str(text).split("\n"))


# Scripts the fixed-width report font cannot draw joined or at all; their
# report is shown in the ordinary text font instead.
GUI_PROPORTIONAL = frozenset(("ar", "fa", "he", "pa", "ta", "te", "ja", "ko", "zh", "el"))


class GuiApp:
    def __init__(self, root, hooks):
        import tkinter as tk
        from tkinter import ttk
        self.tk, self.ttk = tk, ttk
        self.root, self.hooks = root, hooks
        bidi_mode(str(root.tk.call("tk", "windowingsystem")))
        self.events = queue.Queue()
        self.document = None
        self.args = None
        self.iocs = None
        self.busy = False
        self.stop_requested = threading.Event()
        self.progress_state = {}
        self.started_at = None
        self.check = tk.StringVar(value="default")

        class DirectedVar(tk.StringVar):
            def set(self, value):
                super().set(gui_dir(value))
        self.status = DirectedVar(value=gui_dir(T("Ready.")))
        self.conn_status = DirectedVar(value="")
        self.only_internet = tk.BooleanVar(value=True)
        self.auto_refresh = tk.BooleanVar(value=True)
        self._fitted = []
        self._refit_pending = False
        self._check_trace = None
        self._net_tick = 0
        self._style()
        self.root.geometry("1000x820")
        self._layout()
        self.root.bind("<Configure>", self._on_configure, add="+")
        self.root.after(100, self._drain)

    # --- look -------------------------------------------------------------
    def _style(self):
        tk, ttk = self.tk, self.ttk
        from tkinter import font
        base = font.nametofont("TkDefaultFont")
        base.configure(size=10)
        self.font_title = font.Font(family=base.cget("family"), size=18, weight="bold")
        self.font_head = font.Font(family=base.cget("family"), size=13, weight="bold")
        self.font_body = font.Font(family=base.cget("family"), size=10)
        self.font_bold = font.Font(family=base.cget("family"), size=10, weight="bold")
        self.font_mono = font.nametofont("TkFixedFont")
        self.root.configure(bg=GUI_BG)
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure(".", background=GUI_BG, foreground=GUI_INK)
        style.configure("Card.TFrame", background=GUI_CARD)
        style.configure("Card.TLabel", background=GUI_CARD, foreground=GUI_INK)
        style.configure("Muted.TLabel", background=GUI_CARD, foreground=GUI_MUTED)
        style.configure("Card.TRadiobutton", background=GUI_CARD, foreground=GUI_INK)
        style.configure("Card.TCheckbutton", background=GUI_CARD, foreground=GUI_INK)
        style.configure("TNotebook", background=GUI_BG, borderwidth=0, tabmargins=(16, 8, 16, 0))
        style.configure("TNotebook.Tab", padding=(18, 8), background="#e4e4e7", foreground=GUI_MUTED,
                        borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", GUI_CARD)],
                  foreground=[("selected", GUI_INK)], expand=[("selected", (0, 0, 0, 0))])
        style.configure("Horizontal.TProgressbar", troughcolor="#ececee", background=GUI_RED,
                        bordercolor="#ececee", lightcolor=GUI_RED, darkcolor=GUI_RED, thickness=8)
        style.configure("Accent.TButton", background=GUI_RED, foreground="white", padding=(18, 10),
                        font=self.font_head, borderwidth=0)
        style.map("Accent.TButton", background=[("disabled", "#d9a3a5"), ("active", "#a51217")])
        style.configure("TButton", padding=(12, 6))
        style.configure("Treeview", rowheight=24)
        style.configure("Treeview.Heading", font=self.font_body)

    def _just(self):
        """(justify, anchor) for paragraphs in the current language's direction."""
        return ("right", "e") if i18n_rtl() else ("left", "w")

    def _text_direction(self, widget):
        widget.tag_configure("dir", justify="right" if i18n_rtl() else "left")
        widget.tag_add("dir", "1.0", "end")

    def set_language(self, code):
        """Switch every visible word to another language, keeping the result."""
        if self.busy or code == i18n_lang():
            return
        # What the person had chosen survives the switch: the open tab, the
        # phone folder and kind, the practice example.
        kept = self._choices()
        i18n_set(code)
        for child in self.root.winfo_children():
            child.destroy()
        self._fitted = []
        self.status.set(T("Ready."))
        self._layout()
        if self.document is not None:
            self._show_result(self.document, select=False)
        self._restore(kept)

    def _choices(self):
        def index(value, values):
            return values.index(value) if value in values else 0
        return {"tab": self.tabs.index(self.tabs.select()) if self.tabs.select() else 0,
                "kind": index(self.phone_kind.get(), self.phone_kinds),
                "folder": self.phone_folder.get(), "password": self.phone_password.get(),
                "example": index(self.training_choice.get(), self.training_names)}

    def _restore(self, kept):
        self.phone_kind.set(self.phone_kinds[kept["kind"]])
        self.phone_folder.set(kept["folder"])
        self.phone_password.set(kept["password"])
        self.training_choice.set(self.training_names[kept["example"]])
        self._phone_visibility()
        self.tabs.select(kept["tab"])

    # --- paragraphs that wrap to the window --------------------------------
    def _fit(self, label, text, fallback, available=None):
        """Show a paragraph in a label that wraps to the width it really has.
        A fixed wrap width cut lines off whenever the window was narrower than
        planned, and right-to-left text (wrapped here, not by Tk) was wrapped
        for a width the label did not have. The text is wrapped again whenever
        the window changes size. `available` gives the width in pixels when the
        label's own width follows its text (a grid cell); otherwise the label's
        width is used. `fallback` is used before the window is laid out."""
        label._fit_text = text
        label._fit_fallback = fallback
        label._fit_available = available
        label._fit_width = None
        if label not in self._fitted:
            self._fitted.append(label)
        self._refit(label)

    def _fit_width(self, label):
        try:
            width = label._fit_available() if label._fit_available else label.winfo_width() - 8
        except Exception:  # noqa: BLE001 - a widget not laid out yet
            width = 0
        return int(width) if width >= 120 else label._fit_fallback

    def _refit(self, label):
        width = self._fit_width(label)
        if width != label._fit_width:
            label._fit_width = width
            self._set_label(label, label._fit_text, width)

    def _on_configure(self, _event):
        if not self._refit_pending:
            self._refit_pending = True
            self.root.after_idle(self._refit_all)

    def _refit_all(self):
        self._refit_pending = False
        alive = []
        for label in self._fitted:
            try:
                if not label.winfo_exists():
                    continue
            except Exception:  # noqa: BLE001 - destroyed with its window
                continue
            alive.append(label)
            self._refit(label)
        self._fitted = alive

    def _card(self, parent, **pack):
        frame = self.ttk.Frame(parent, style="Card.TFrame", padding=16)
        frame.pack(fill="x", padx=16, pady=(12, 0), **pack)
        return frame

    def _layout(self):
        tk, ttk = self.tk, self.ttk
        self.root.title("Zero Breach Toolkit")
        self.root.minsize(780, 640)
        header = tk.Frame(self.root, bg="#111111")
        header.pack(fill="x")
        top = tk.Frame(header, bg="#111111")
        top.pack(fill="x", padx=16, pady=(10, 0))
        tk.Label(top, text="ZERO BREACH", fg=GUI_RED, bg="#111111", font=self.font_title).pack(side="left")
        tk.Label(top, text="v" + self.hooks["version"].split(" ")[0], fg="#8a8a8a",
                 bg="#111111", font=self.font_body).pack(side="right")
        # Each language's own name, laid out for its own direction (Arabic,
        # Farsi and Hebrew names came out backwards on Linux, in every language).
        shown = {code: bidi_line(name) for code, name in I18N_LANGUAGES}
        names = [shown[code] for code, _name in I18N_LANGUAGES if code in i18n_available()]
        self.language = tk.StringVar(value=shown[i18n_lang()])
        self.language_box = ttk.Combobox(top, textvariable=self.language, state="readonly", width=16,
                                         values=names)
        self.language_box.pack(side="right", padx=(0, 12))
        codes = {name: code for code, name in shown.items()}
        self.language_box.bind("<<ComboboxSelected>>", lambda _e: self.set_language(codes[self.language.get()]))
        justify, anchor = self._just()
        subtitle = tk.Label(header, fg="#d0d0d0", bg="#111111", font=self.font_body, anchor=anchor,
                            justify=justify)
        subtitle.pack(fill="x", padx=16, pady=(0, 10))
        self._fit(subtitle, T("Checks this device for traces of known mercenary spyware. "
                              "Read-only: nothing is changed, and nothing leaves this device."), 940)
        tabs = ttk.Notebook(self.root)
        tabs.pack(fill="both", expand=True, pady=(8, 0))
        self.tabs = tabs
        self.tab_check = ttk.Frame(tabs)
        self.tab_result = ttk.Frame(tabs)
        self.tab_net = ttk.Frame(tabs)
        self.tab_help = ttk.Frame(tabs)
        tabs.add(self.tab_check, text=T("Check"))
        tabs.add(self.tab_result, text=T("Result"))
        tabs.add(self.tab_net, text=T("Live connections"))
        tabs.add(self.tab_help, text=T("Help"))
        tabs.bind("<<NotebookTabChanged>>", lambda _e: self._tab_changed(tabs))
        self._layout_check()
        self._layout_net()
        self._layout_help()
        if i18n_rtl():
            self._direct(self.root)
            for tab in tabs.tabs():
                tabs.tab(tab, text=gui_dir(tabs.tab(tab, "text")))

    def _direct(self, widget):
        """Lay out every fixed label, button and option right to left."""
        for child in widget.winfo_children():
            if child.winfo_class() in ("TCombobox", "TEntry", "Entry", "Text", "Treeview"):
                continue
            if getattr(child, "_fit_text", None) is not None:
                continue    # already laid out by _fit, for the width it has
            try:
                text = child.cget("text")
            except Exception:  # noqa: BLE001 - widgets without text
                text = None
            if isinstance(text, str) and text:
                try:
                    wrap = int(str(child.cget("wraplength")) or 0)
                except Exception:  # noqa: BLE001 - no wraplength option
                    wrap = 0
                try:
                    if wrap > 0:
                        child.configure(text=self._rtl_wrap(text, wrap, child), wraplength=0)
                    else:
                        child.configure(text=gui_dir(text))
                except Exception:  # noqa: BLE001
                    pass
            self._direct(child)

    def _measure_font(self, widget=None):
        from tkinter import font
        try:
            return font.Font(font=widget.cget("font")) if widget is not None and widget.cget("font") else self.font_body
        except Exception:  # noqa: BLE001 - ttk widgets take the default font
            return self.font_body

    def _rtl_wrap(self, text, width, widget=None):
        if not i18n_rtl():
            return text
        return bidi_wrap(text, self._measure_font(widget).measure, width)

    def _set_label(self, label, text, width):
        """Set a wrapping label's text in either direction."""
        if i18n_rtl():
            label.configure(text=self._rtl_wrap(text, width, label), wraplength=0)
        else:
            label.configure(text=text, wraplength=width)

    def _fill(self, widget, text):
        """Put text into a text box. Right-to-left text is laid out for the box's
        current width, and again whenever the box is resized."""
        widget._logical = text
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        if i18n_rtl():
            widget.configure(wrap="none")
            width = widget.winfo_width() - 40
            if width < 200:
                width = 860
            widget._laid_width = widget.winfo_width()
            widget.insert("end", bidi_wrap(text, self.font_body.measure, width))
            if not getattr(widget, "_relayout", False):
                widget._relayout = True

                def again(_event, w=widget):
                    if abs(w.winfo_width() - getattr(w, "_laid_width", 0)) > 20:
                        state = str(w.cget("state"))
                        self._fill(w, w._logical)
                        w.configure(state=state)
                widget.bind("<Configure>", again, add="+")
        else:
            widget.insert("end", text)
        self._text_direction(widget)

    def _layout_check(self):
        tk, ttk = self.tk, self.ttk
        top = self._card(self.tab_check)
        ttk.Label(top, text=T("Choose a check"), style="Card.TLabel", font=self.font_head).grid(
            row=0, column=0, sticky="w", columnspan=2)
        justify = self._just()[0]

        def beside_choices(top=top):
            # The note column: the card's width less its padding and the
            # column of choices.
            return top.winfo_width() - 32 - top.grid_bbox(0, 1, 0, len(GUI_CHECKS))[2] - 12 - 8

        for i, (value, label, note) in enumerate(GUI_CHECKS, 1):
            ttk.Radiobutton(top, text=T(label), value=value, variable=self.check,
                            style="Card.TRadiobutton").grid(row=i, column=0, sticky="w", pady=2)
            note_label = ttk.Label(top, style="Muted.TLabel", justify=justify)
            note_label.grid(row=i, column=1, sticky="w", padx=12)
            self._fit(note_label, T(note), 640, beside_choices)
        self.phone_frame = ttk.Frame(top, style="Card.TFrame")
        self._layout_phone(self.phone_frame)
        self.training_frame = ttk.Frame(top, style="Card.TFrame")
        self.training_names = [gui_dir(T(label)) for label, _k in GUI_TRAINING_LABELS]
        self.training_choice = tk.StringVar(value=self.training_names[0])
        ttk.Label(self.training_frame, text=T("Example"), style="Card.TLabel").pack(side="left")
        ttk.Combobox(self.training_frame, textvariable=self.training_choice, state="readonly", width=28,
                     values=self.training_names).pack(side="left", padx=8)
        ttk.Label(self.training_frame, text=T("Nothing on this computer or any phone is read."),
                  style="Muted.TLabel").pack(side="left")
        # The phone or example row goes below the last choice, never over it.
        self.options_row = len(GUI_CHECKS) + 1
        if self._check_trace is not None:
            # A language switch lays the window out again: one watcher only.
            self.check.trace_remove("write", self._check_trace)
        self._check_trace = self.check.trace_add("write", lambda *_a: self._phone_visibility())
        buttons = ttk.Frame(top, style="Card.TFrame")
        buttons.grid(row=self.options_row + 1, column=0, columnspan=2, sticky="w", pady=(12, 0))
        self.start_button = ttk.Button(buttons, text=T("Start check"), style="Accent.TButton",
                                       command=self.start_check)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(buttons, text=T("Stop"), command=self.stop_check, state="disabled")
        self.stop_button.pack(side="left", padx=(8, 0))
        ttk.Label(buttons, text=T("Times depend on how much is on the computer."),
                  style="Muted.TLabel").pack(side="right")
        self.update_button = ttk.Button(buttons, text=T("Update indicator lists"), command=self.update_lists)
        self.update_button.pack(side="left", padx=12)
        self.close_note = ttk.Label(top, style="Muted.TLabel", justify=justify)
        self.close_note.grid(row=self.options_row + 2, column=0, columnspan=2, sticky="w", pady=(10, 0))
        self._fit(self.close_note, T("Close your browsers and chat apps first: open apps lock some "
                                     "of their records. Updating the lists is the only step that "
                                     "uses the internet."), 860, lambda: top.winfo_width() - 32 - 8)
        # After a language switch the chosen check is kept, so its phone or
        # example row must be shown again.
        self._phone_visibility()

        progress = self._card(self.tab_check)
        self.progress = ttk.Progressbar(progress, mode="determinate", value=0)
        self.progress.pack(fill="x")
        ttk.Label(progress, textvariable=self.status, style="Muted.TLabel").pack(anchor="w", pady=(6, 0))
        self.elapsed = type(self.status)(value="")
        ttk.Label(progress, textvariable=self.elapsed, style="Muted.TLabel").pack(anchor="w")

        result = self.ttk.Frame(self.tab_result, style="Card.TFrame", padding=16)
        result.pack(fill="both", expand=True, padx=16, pady=12)
        self.training_bar = tk.Label(result, text=T("TRAINING EXAMPLE - a made-up phone, not a real check"),
                                     bg="#f59e0b", fg="#1d1d1f", font=self.font_head, anchor="w", padx=10, pady=6)
        justify, anchor = self._just()
        self.result_title = tk.Label(result, text=T("No check run yet."), bg=GUI_CARD, fg=GUI_INK,
                                     font=self.font_head, anchor=anchor)
        self.result_title.pack(fill="x")
        self.result_note = tk.Label(result, text="", bg=GUI_CARD, fg=GUI_MUTED, font=self.font_body,
                                    anchor=anchor, justify=justify, wraplength=880)
        self.result_note.pack(fill="x", pady=(2, 8))
        self.next_frame = tk.Frame(result, bg="#f3f4f6", padx=12, pady=8)
        tk.Label(self.next_frame, text=T("What should I do now?"), bg="#f3f4f6", fg=GUI_INK,
                 font=self.font_bold,
                 anchor=anchor).pack(fill="x")
        self.next_text = tk.Label(self.next_frame, text="", bg="#f3f4f6", fg=GUI_INK, font=self.font_body,
                                  anchor=anchor, justify=justify, wraplength=860)
        self.next_text.pack(fill="x", pady=(4, 0))
        self.helpline_button = ttk.Button(self.next_frame, text=T("Copy the helpline address"),
                                          command=self.copy_helpline)
        actions = ttk.Frame(result, style="Card.TFrame")
        actions.pack(fill="x", pady=(0, 8))
        self.view_button = ttk.Button(actions, text=T("Show full report"), command=self.toggle_view,
                                      state="disabled")
        self.view_button.pack(side="left")
        self.save_button = ttk.Button(actions, text=T("Save report..."), command=self.save_report,
                                      state="disabled")
        self.save_button.pack(side="left", padx=8)
        self.share_button = ttk.Button(actions, text=T("Save sharing summary..."),
                                       command=self.save_summary, state="disabled")
        self.share_button.pack(side="left")
        frame = ttk.Frame(result, style="Card.TFrame")
        frame.pack(fill="both", expand=True)
        self.text = tk.Text(frame, wrap="word",
                            font=self.font_body if i18n_lang() in GUI_PROPORTIONAL else self.font_mono,
                            relief="flat", bg="#fbfbfb",
                            fg=GUI_INK, padx=10, pady=8, height=24)
        scroll = ttk.Scrollbar(frame, command=self.text.yview)
        self.text.configure(yscrollcommand=scroll.set, state="disabled")
        scroll.pack(side="right", fill="y")
        self.text.pack(side="left", fill="both", expand=True)
        self.showing_full = False

    def _layout_phone(self, frame):
        tk, ttk = self.tk, self.ttk
        self.phone_kinds = [gui_dir(T(label)) for label, _kind in GUI_PHONE_KINDS]
        self.phone_kind = tk.StringVar(value=self.phone_kinds[0])
        self.phone_folder = tk.StringVar(value="")
        self.phone_password = tk.StringVar(value="")
        ttk.Label(frame, text=T("What is it?"), style="Card.TLabel").grid(row=0, column=0, sticky="w", pady=2)
        ttk.Combobox(frame, textvariable=self.phone_kind, state="readonly", width=48,
                     values=self.phone_kinds).grid(row=0, column=1, sticky="w", padx=8)
        ttk.Label(frame, text=T("Folder"), style="Card.TLabel").grid(row=1, column=0, sticky="w", pady=2)
        ttk.Entry(frame, textvariable=self.phone_folder, width=60).grid(row=1, column=1, sticky="w", padx=8)
        row = ttk.Frame(frame, style="Card.TFrame")
        row.grid(row=1, column=2, sticky="w")
        ttk.Button(row, text=T("Choose..."), command=self.choose_phone_folder).pack(side="left")
        ttk.Button(row, text=T("Find iPhone backups"), command=self.find_backups).pack(side="left", padx=6)
        ttk.Label(frame, text=T("Backup password"), style="Card.TLabel").grid(row=2, column=0, sticky="w", pady=2)
        ttk.Entry(frame, textvariable=self.phone_password, show="*", width=30).grid(row=2, column=1, sticky="w", padx=8)
        ttk.Label(frame, text=T("Only for an encrypted iPhone backup. It is used for this check and then forgotten."),
                  style="Muted.TLabel").grid(row=3, column=1, columnspan=2, sticky="w", padx=8)
        help_row = ttk.Frame(frame, style="Card.TFrame")
        help_row.grid(row=4, column=1, columnspan=2, sticky="w", padx=8, pady=(6, 0))
        ttk.Button(help_row, text=T("How do I make an iPhone backup?"),
                   command=lambda: self.show_guide("ios")).pack(side="left")
        ttk.Button(help_row, text=T("How do I check an Android phone?"),
                   command=lambda: self.show_guide("android")).pack(side="left", padx=6)
        ttk.Button(help_row, text=T("Collect from an Android phone..."),
                   command=self.collect_android).pack(side="left")

    def _phone_visibility(self):
        choice = self.check.get()
        self.phone_frame.grid_remove()
        self.training_frame.grid_remove()
        if choice == "phone":
            self.phone_frame.grid(row=self.options_row, column=0, columnspan=2, sticky="w", pady=(8, 0))
        elif choice == "training":
            self.training_frame.grid(row=self.options_row, column=0, columnspan=2, sticky="w", pady=(8, 0))
        if choice in ("phone", "training"):
            self.close_note.grid_remove()
        else:
            self.close_note.grid()

    def choose_phone_folder(self):
        from tkinter import filedialog
        path = filedialog.askdirectory(parent=self.root, title=T("Choose the phone backup or collection folder"),
                                       mustexist=True)
        if path:
            self.phone_folder.set(os.path.normpath(path))

    def find_backups(self):
        from tkinter import messagebox
        backups = gui_backup_folders()
        if not backups:
            messagebox.showinfo(T("No iPhone backups found"),
                                T("No iPhone backup was found in the usual places on this computer. Make one "
                                  "with Finder (Mac) or Apple Devices / iTunes (Windows): see \"How do I make an "
                                  "iPhone backup?\"."), parent=self.root)
            return
        self.phone_kind.set(self.phone_kinds[0])
        self.phone_folder.set(backups[0][1])
        if len(backups) > 1:
            messagebox.showinfo(T("iPhone backups found"),
                                T("The newest backup was chosen. All backups found:") + "\n\n" +
                                "\n".join(label for label, _path in backups[:8]), parent=self.root)

    def show_guide(self, platform):
        tk, ttk = self.tk, self.ttk
        win = tk.Toplevel(self.root)
        win.title(T("Checking an iPhone") if platform == "ios" else T("Checking an Android phone"))
        win.geometry("760x560")
        text = tk.Text(win, wrap="word", font=self.font_body, padx=12, pady=10)
        win.update_idletasks()
        self._fill(text, T(scope_guide(platform)))
        text.configure(state="disabled")
        text.pack(fill="both", expand=True)
        ttk.Button(win, text=T("Close"), command=win.destroy).pack(pady=8)

    def collect_android(self):
        from tkinter import filedialog, messagebox
        folder = filedialog.askdirectory(parent=self.root, title=T("Choose an EMPTY folder for the Android collection"))
        if not folder:
            return
        folder = os.path.normpath(folder)
        command = gui_self_command() + ["--collect-android", folder, "--no-gui"]
        if sys.platform == "win32":
            import subprocess
            subprocess.Popen(command, creationflags=getattr(subprocess, "CREATE_NEW_CONSOLE", 0))
            messagebox.showinfo(T("Collecting from the Android phone"),
                                T("The guided collection opened in its own window. Follow its steps; when it "
                                  "finishes, this folder will be filled in here so you can start the check."),
                                parent=self.root)
        else:
            import shlex
            messagebox.showinfo(T("Collecting from the Android phone"),
                                T("The guided collection runs in a terminal. Open Terminal and run:") + "\n\n" +
                                " ".join(shlex.quote(c) for c in command) +
                                "\n\n" + T("When it finishes, start the check here."), parent=self.root)
        self.phone_kind.set(self.phone_kinds[1])
        self.phone_folder.set(folder)

    def _layout_net(self):
        tk, ttk = self.tk, self.ttk
        top = self._card(self.tab_net)
        justify, anchor = self._just()
        ttk.Label(top, text=T("Connections right now"), style="Card.TLabel", font=self.font_head).pack(anchor=anchor)
        about = ttk.Label(top, style="Muted.TLabel", justify=justify, anchor=anchor)
        about.pack(fill="x", pady=(4, 8))
        self._fit(about, T("Which programs on this device are connected to which addresses at this "
                           "moment. Addresses known to belong to spyware servers are shown in red. Nothing is "
                           "looked up or contacted. Servers change hands, so a match is a reason to look "
                           "closer, not proof of infection; website names are checked by the full scan, "
                           "not here."), 880)
        controls = ttk.Frame(top, style="Card.TFrame")
        controls.pack(fill="x")
        ttk.Button(controls, text=T("Refresh now"), command=self.refresh_connections).pack(side="left")
        ttk.Checkbutton(controls, text=T("Only connections to the internet"), variable=self.only_internet,
                        style="Card.TCheckbutton", command=self.refresh_connections).pack(side="left", padx=12)
        ttk.Checkbutton(controls, text=T("Refresh every 5 seconds"), variable=self.auto_refresh,
                        style="Card.TCheckbutton").pack(side="left")
        ttk.Label(top, textvariable=self.conn_status, style="Card.TLabel").pack(anchor="w", pady=(8, 0))
        table = ttk.Frame(self.tab_net, style="Card.TFrame", padding=8)
        table.pack(fill="both", expand=True, padx=16, pady=12)
        columns = ("program", "remote", "port", "state", "match")
        self.tree = ttk.Treeview(table, columns=columns, show="headings")
        for name, title, width in (("program", "Program", 260), ("remote", "Remote address", 260),
                                   ("port", "Port", 70), ("state", "State", 120),
                                   ("match", "Known spyware address?", 220)):
            self.tree.heading(name, text=T(title))
            self.tree.column(name, width=width, anchor="w")
        self.tree.tag_configure("hit", background="#fde2e2", foreground=GUI_RED)
        scroll = ttk.Scrollbar(table, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)
        self.net_visible = False

    def _layout_help(self):
        tk = self.tk
        card = self._card(self.tab_help, expand=True)
        text = tk.Text(card, wrap="word", relief="flat", bg=GUI_CARD, fg=GUI_INK, font=self.font_body,
                       padx=4, pady=4, height=24)
        self._fill(text, T(GUI_HELP))
        text.configure(state="disabled")
        text.pack(fill="both", expand=True)

    # --- events from worker threads ----------------------------------------
    def _drain(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "status":
                    text, percent = gui_progress(payload, self.progress_state)
                    if self.stop_requested.is_set():
                        text = T("Stopping after the current step. What was already checked is kept.")
                    self.status.set(text[:160])
                    if percent is not None and self.progress_state.get("measured"):
                        # The step says how far it has got: show the real share.
                        if str(self.progress.cget("mode")) != "determinate":
                            self.progress.stop()
                            self.progress.configure(mode="determinate")
                        self.progress.configure(value=percent)
                    elif str(self.progress.cget("mode")) != "indeterminate":
                        # A step that cannot be counted: keep the bar moving so
                        # it is clearly still working; the text gives the step.
                        self.progress.configure(mode="indeterminate", value=0)
                        self.progress.start(12)
                elif kind == "steps":
                    self.progress_state = {"steps": list(payload)}
                elif kind == "done":
                    self._show_result(payload)
                elif kind == "failed":
                    self._finish_busy()
                    self.status.set(str(payload))
                    self._set_text(str(payload))
                elif kind == "updated":
                    self._finish_busy()
                    self.status.set(payload)
                    self.iocs = None
        except queue.Empty:
            pass
        if self.busy and self.started_at is not None:
            minutes = int((datetime.datetime.now() - self.started_at).total_seconds() // 60)
            self.elapsed.set(TN("Running for {n} minute.", "Running for {n} minutes.", minutes)
                             if minutes else T("Running for less than a minute."))
        self.root.after(100, self._drain)

    def _begin_busy(self, message, stoppable=False):
        self.busy = True
        self.started_at = datetime.datetime.now()
        self.stop_requested.clear()
        self.progress_state = {}
        if stoppable:
            self.stop_button.state(["!disabled"])
        self.start_button.state(["disabled"])
        self.update_button.state(["disabled"])
        self.language_box.state(["disabled"])
        self.progress.configure(mode="indeterminate")
        self.progress.start(12)
        self.status.set(message)

    def _finish_busy(self):
        self.busy = False
        self.started_at = None
        self.elapsed.set("")
        self.stop_button.state(["disabled"])
        self.progress.stop()
        self.progress.configure(mode="determinate", value=0)
        self.start_button.state(["!disabled"])
        self.update_button.state(["!disabled"])
        self.language_box.state(["!disabled"])

    def _set_text(self, text):
        self._fill(self.text, text)
        self.text.configure(state="disabled")

    # --- the check ----------------------------------------------------------
    def start_check(self):
        from tkinter import messagebox
        if self.busy:
            return
        if self.check.get() == "phone":
            folder = self.phone_folder.get().strip()
            if not folder or not os.path.isdir(folder):
                messagebox.showerror(T("Choose the phone folder"), T("Choose the folder that holds the iPhone "
                                                                     "backup or the Android collection first."),
                                     parent=self.root)
                return
        self.document = None
        for b in (self.view_button, self.save_button, self.share_button):
            b.state(["disabled"])
        self.result_title.configure(text=gui_dir(T("Checking...")), fg=GUI_INK)
        self._set_label(self.result_note, T("This can take a while. You can keep using the computer."), 880)
        self._set_text("")
        self._begin_busy(T("Starting the check..."), stoppable=True)
        phone = None
        if self.check.get() == "phone":
            choice = self.phone_kinds.index(self.phone_kind.get()) if self.phone_kind.get() in self.phone_kinds else 0
            kind = GUI_PHONE_KINDS[choice][1]
            phone = (self.phone_folder.get().strip(), kind, self.phone_password.get())
            self.phone_password.set("")
        training = None
        if self.check.get() == "training":
            choice = self.training_choice.get()
            training = (GUI_TRAINING_LABELS[self.training_names.index(choice)][1]
                        if choice in self.training_names else "spyware")
        threading.Thread(target=self._run_check, args=(self.check.get(), phone, training), daemon=True).start()

    def _run_check(self, scan_type, phone=None, training=None):
        try:
            password = ""
            if phone:
                folder, kind, password = phone
                argv = ["--phone", folder, "--no-menu", "--no-banner"] + (["--ios-input", kind] if kind else [])
            elif training:
                argv = ["--training", training, "--no-menu", "--no-banner"]
            else:
                argv = ["--scan-type", scan_type, "--no-menu", "--no-banner"]
            args = self.hooks["parse"](argv)
            # Training swaps in its made-up phone and indicators (and removes them after).
            training_prepare(args)
            iocs = self.hooks["load_iocs"](args)
            workflow_before_scan(args, iocs)
            emit = gui_stoppable_emit(self.stop_requested, self.events.put)
            ctx = ScanContext(iocs=iocs, full=scan_type == "full", browser_only=scan_type == "browser",
                              phone_path=args.phone or "", ios_input=getattr(args, "ios_input", "") or "",
                              backup_password=password, emit=emit)
            self.events.put(("steps", [spec.name for spec in reader_select(ctx)]))
            password = ""
            started = datetime.datetime.now()
            with scan_recovery(ctx):
                self.hooks["run_readers"](ctx)
            document = prepare_document(iocs, ctx.completed, started, args, ctx.cancelled)
            # The live-connections view keeps the real indicators, never the made-up ones.
            self.args, self.iocs = args, (None if getattr(args, "training", None) else iocs)
            self.events.put(("done", document))
        except IocError as exc:
            self.events.put(("failed", T("The indicator lists could not be loaded: {error}", error=exc)))
        except BaseException as exc:  # noqa: BLE001 - shown to the person, never swallowed
            # BaseException, not Exception: an option error raises SystemExit,
            # which would otherwise end this thread silently and leave the
            # window saying "Starting the check..." for ever.
            self.events.put(("failed", T("The check stopped with an error: {error}",
                                         error="{}: {}".format(type(exc).__name__, exc))))
        finally:
            training_cleanup()

    def _show_result(self, document, select=True):
        self._finish_busy()
        self.document = document
        colour, title, note = gui_headline(document)
        if document.get("training"):
            self.training_bar.pack(fill="x", before=self.result_title, pady=(0, 8))
        else:
            self.training_bar.pack_forget()
        self.result_title.configure(text=gui_dir(title), fg=colour)
        self._fit(self.result_note, note, 880)
        steps = gui_next_steps(document)
        # A no-break space keeps each bullet with its first word: with an
        # ordinary space a step in Chinese or Japanese (no spaces to wrap at)
        # left the bullet alone on a line of its own.
        self._fit(self.next_text, "\n".join("\u2022\u00a0" + s for s in steps), 860)
        self.next_frame.pack(fill="x", pady=(0, 10), before=self.view_button.master)
        if any(HELPLINE in s for s in steps):
            self.helpline_button.pack(anchor="w", pady=(6, 0))
        else:
            self.helpline_button.pack_forget()
        self.showing_full = False
        self.view_button.configure(text=gui_dir(T("Show full report")))
        self._set_text(_defang_report(render_summary(document), document))
        if select:
            self.tabs.select(self.tab_result)
        for b in (self.view_button, self.save_button, self.share_button):
            b.state(["!disabled"])
        if document.get("training"):
            # A sharing summary exists to be sent to someone; a training example never is.
            self.share_button.state(["disabled"])
        stopped = document.get("scope", {}).get("cancelled")
        if select:
            at = datetime.datetime.now().strftime("%H:%M")
            self.status.set(T("Check stopped at {time}.", time=at) if stopped
                            else T("Check finished at {time}.", time=at))

    def stop_check(self):
        if self.busy and not self.stop_requested.is_set():
            self.stop_requested.set()
            self.stop_button.state(["disabled"])
            self.status.set(T("Stopping after the current step. What was already checked is kept."))

    def copy_helpline(self):
        # Copied, not opened: the check never contacts anything, and the person
        # decides where and when to open it.
        self.root.clipboard_clear()
        self.root.clipboard_append(HELPLINE)
        self.status.set(T("Copied: {url}", url=HELPLINE))

    def toggle_view(self):
        if not self.document:
            return
        self.showing_full = not self.showing_full
        text = render_human(self.document) if self.showing_full else render_summary(self.document)
        self._set_text(_defang_report(text, self.document))
        self.view_button.configure(text=gui_dir(T("Show summary") if self.showing_full else T("Show full report")))

    def _ask_path(self, title, name, extension):
        from tkinter import filedialog
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        return filedialog.asksaveasfilename(
            parent=self.root, title=title, defaultextension=extension,
            initialfile="{}-{}{}".format(name, stamp, extension),
            initialdir=os.path.join(os.path.expanduser("~"), "Documents")
            if os.path.isdir(os.path.join(os.path.expanduser("~"), "Documents")) else os.path.expanduser("~"))

    def _save(self, writer, title, name, extension):
        from tkinter import messagebox
        if not self.document:
            return
        path = self._ask_path(title, name, extension)
        if not path:
            return
        try:
            workflow_output_guard(self.args, path, self.document)
            writer(path)
            self.status.set(T("Saved: {path}", path=path))
        except PermissionError:
            messagebox.showerror(T("Not saved"), T("This location cannot be written to. Choose your "
                                                   "Documents or Desktop folder instead."), parent=self.root)
        except (OSError, ValueError, TypeError) as exc:
            messagebox.showerror(T("Not saved"), str(exc), parent=self.root)

    def save_report(self):
        self._save(lambda path: workflow_write_text(gui_report_text(self.document), path),
                   T("Save the report"), "zero-breach-report", ".txt")

    def save_summary(self):
        self._save(lambda path: write_json(share_summary(self.document), path),
                   T("Save a sharing summary"), "zero-breach-summary", ".json")

    def update_lists(self):
        from tkinter import messagebox
        if self.busy:
            return
        if not messagebox.askokcancel(
                T("Update indicator lists"),
                T("This downloads the latest published indicator lists from GitHub (about 30 "
                  "sources). It is the only step that uses the internet. Continue?"), parent=self.root):
            return
        self._begin_busy(T("Downloading the indicator lists..."))
        threading.Thread(target=self._run_update, daemon=True).start()

    def _run_update(self):
        import contextlib
        events = self.events

        class Lines:
            def write(self, text):
                for line in text.splitlines():
                    if line.strip():
                        events.put(("status", line.strip()))
                return len(text)

            def flush(self):
                pass
        try:
            with contextlib.redirect_stdout(Lines()), contextlib.redirect_stderr(Lines()):
                code = self.hooks["update"]()
            from . import feeds
            note = feeds.LAST_VERSION_NOTICE
            message = (T("Indicator lists updated.") if code == 0 else
                       T("Some indicator lists could not be updated; the others are ready."))
            self.events.put(("updated", message + ("  " + note if note else "")))
        except BaseException as exc:  # noqa: BLE001 - see _run_check
            self.events.put(("failed", T("The update stopped with an error: {error}", error=exc)))

    # --- live connections ----------------------------------------------------
    def _tab_changed(self, tabs):
        self.net_visible = tabs.index("current") == tabs.index(self.tab_net)
        if self.net_visible:
            self.refresh_connections()
            self._schedule_refresh()

    def _schedule_refresh(self):
        # One refresh timer at a time: leaving and reopening the tab used to
        # start a second one, and the table then refreshed twice as often.
        self._net_tick += 1
        token = self._net_tick

        def tick():
            if token != self._net_tick or not self.net_visible:
                return
            if self.auto_refresh.get():
                self.refresh_connections()
            self.root.after(5000, tick)
        self.root.after(5000, tick)

    def _indicators(self):
        if self.iocs is None:
            try:
                args = self.hooks["parse"](["--no-menu", "--no-banner"])
                self.iocs = self.hooks["load_iocs"](args)
            except BaseException:  # noqa: BLE001 - the table still shows connections
                self.iocs = None
        return self.iocs

    def refresh_connections(self):
        rows, problem = nc_list()
        iocs = self._indicators()
        matches = nc_match(rows, iocs) if iocs is not None else []
        shown = [r for r in rows if r.get("remote_public") or not self.only_internet.get()]
        shown.sort(key=lambda r: (r.get("match") is None, os.path.basename(r.get("program") or "~")))
        self.tree.delete(*self.tree.get_children())
        for r in shown:
            program = os.path.basename(r.get("program") or "") or (
                T("unknown (pid {pid})", pid=r["pid"]) if r.get("pid") else T("unknown"))
            match = r.get("match")
            label = T("YES: {name} ({tier})", name=match.family or match.source, tier=match.tier) if match else ""
            self.tree.insert("", "end", values=(program, r["remote"], r["remote_port"], r["state"], label),
                             tags=("hit",) if match else ())
        if problem:
            self.conn_status.set(problem)
        elif iocs is None:
            self.conn_status.set(T("{n} connections shown. The indicator lists could not be loaded, so "
                                   "nothing was compared.", n=len(shown)))
        elif matches:
            self.conn_status.set(T("{n} connection(s) go to an address on a spyware list. Do not close "
                                   "anything; save a report and get expert help (Help tab).", n=len(matches)))
        else:
            self.conn_status.set(T("{n} connections shown. None goes to an address on the spyware lists "
                                   "({ips} addresses checked).", n=len(shown),
                                   ips=sum(1 for i in iocs.indicators if i.type == "ip")))


GUI_HELP = """What this does
Zero Breach looks for traces that known mercenary spyware (Pegasus, Predator, Candiru, Paragon Graphite and others) leaves on a device: records in browsers and apps, startup items, and fingerprints of program files. It only reads; it never changes, deletes or uploads anything.

Reading the result
- "No known spyware traces found" means nothing matched in what could be checked. It is not a guarantee: new spyware is unknown until researchers publish it, and some checks may not have run (they are listed).
- "Only references found" means an indicator name appeared in saved content, for example an article about Pegasus that you read. That alone is not a sign of infection.
- "Something needs a closer look" means a trace matched. Do not reset or wipe the device: that destroys the evidence. Save the report and contact one of the helplines below.

Checking a phone
Choose "A phone", then the folder of an iPhone backup (Finder or Apple Devices / iTunes makes one; "Find iPhone backups" looks in the usual places) or an Android collection. The guides under the folder box explain how to make either. An encrypted iPhone backup needs its password, which is used for that check only.

Practise
"Practise" checks a made-up phone with made-up spyware, so you can learn to read a report (spyware found, things worth a look, or nothing found). Nothing real is read, and every result is marked as a training example.

Live connections
Shows what is connected right now and marks addresses on the spyware lists. Servers change hands over time, so a match is a reason to look closer, not proof.

Getting help
If you might be targeted (for example as a journalist, activist or lawyer), you can ask for help whatever this check says:
- Access Now Digital Security Helpline: https://www.accessnow.org/help/
- Amnesty International Security Lab: https://securitylab.amnesty.org/
- The Citizen Lab: https://citizenlab.ca/

More: https://github.com/interplains/Zero-Breach-Toolkit#readme
"""


def gui_report_text(document):
    """The report as saved from the window: in the chosen language, followed by
    the English original, which stays the record a helpline works from."""
    text = _defang_report(render_human(document), document)
    if i18n_lang() == "en":
        return text
    with i18n_as("en"):
        original = _defang_report(render_human(document), document)
    return (text + "\n\n" + "=" * 72 + "\n" +
            T("The English original follows. It is the authoritative record: share it with "
              "anyone helping you.") + "\n" + "=" * 72 + "\n\n" + original)


_GUI_PROBE_CODE = "import tkinter; tkinter.Tk().destroy()"
_gui_probe_cache = []


def gui_probe(command, timeout=15):
    """Run `command` (a list) in a child process and say whether it exited 0.
    A crash, a signal, a missing program or a timeout all count as "no"; the
    child's output is thrown away. Used because on a Mac creating the window can
    abort the whole process instead of raising: with no window server, or on
    Apple's own Python whose Tk refuses this macOS version even on a normal
    desktop."""
    import subprocess
    try:
        done = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL, timeout=timeout)
    except Exception:  # noqa: BLE001 - timeout, missing program, anything
        return False
    return done.returncode == 0


def _mac_has_window_server():
    """For a packaged program, which cannot re-run itself as a plain interpreter.
    A double-clicked app has no terminal to fall back to, so a wrong "no" would
    look like an app that does nothing: only a remote (SSH) session can get a
    "no" here, and only if it also has no CoreGraphics desktop session."""
    if not (os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY")):
        return True
    try:
        import ctypes
        lib = ctypes.CDLL("/System/Library/Frameworks/ApplicationServices.framework/ApplicationServices")
        lib.CGSessionCopyCurrentDictionary.restype = ctypes.c_void_p
        return bool(lib.CGSessionCopyCurrentDictionary())
    except Exception:  # noqa: BLE001
        return False


def gui_available():
    """Can a window be opened here? Decided before any Tk root is created and
    cached for the process. Never raises. "No" covers a missing display AND a Tk
    that cannot start on this computer even with a desktop present (Apple's own
    Python 3.9 aborts the process on some macOS versions)."""
    if _gui_probe_cache:
        return _gui_probe_cache[0]
    try:
        if sys.platform.startswith("win"):
            ok = True
        elif sys.platform == "darwin":
            if getattr(sys, "frozen", False):
                ok = _mac_has_window_server()
            else:
                ok = gui_probe([sys.executable, "-c", _GUI_PROBE_CODE])
        else:
            ok = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    except Exception:  # noqa: BLE001
        ok = False
    _gui_probe_cache.append(ok)
    return ok


def _apple_system_python():
    """True for the Python that ships with macOS / the Command Line Tools. Its Tk
    can refuse to start on some macOS versions even on a normal desktop (it quits
    the whole process), so the window is unavailable there while python.org's
    Python works."""
    if sys.platform != "darwin" or getattr(sys, "frozen", False):
        return False
    where = (sys.executable or "") + " " + (getattr(sys, "base_prefix", "") or "")
    return ("/CommandLineTools/" in where or "/Xcode.app/" in where
            or (sys.executable or "").startswith("/usr/bin/"))


def gui_fallback_notice():
    print(T("The window could not be opened on this computer, so the check is running in the terminal instead."),
          file=sys.stderr)
    if _apple_system_python():
        print(T("To get the window, install Python from python.org/downloads and start the check with that Python."),
              file=sys.stderr)


def gui_main(hooks):
    """Open the window. Returns an exit code, or None if no window can be shown
    here (no display, a Tk that refuses to start, a desktop session that is not
    available), so the caller can fall back to the terminal."""
    i18n_set(hooks.get("lang") or i18n_default())
    if not gui_available():
        gui_fallback_notice()
        return None
    try:
        import tkinter as tk
    except ImportError:
        gui_fallback_notice()
        return None
    try:
        root = tk.Tk()
    except tk.TclError:
        gui_fallback_notice()
        return None
    if gui_launched_by_double_click():
        gui_hide_console()
    try:
        GuiApp(root, hooks)
    except Exception:
        # Anything that goes wrong while the window is being built (a font that
        # cannot be loaded, a display that disappears): leave it and let the
        # caller continue in the terminal.
        try:
            root.destroy()
        except Exception:
            pass
        gui_fallback_notice()
        return None
    root.mainloop()
    return 0
