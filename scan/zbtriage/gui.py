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
import re
import sys
import threading
import time

from .context import ScanContext, scan_recovery
from .bidi import bidi_line, bidi_mode, bidi_wrap
from .i18n import I18N_LANGUAGES, T, TN, i18n_as, i18n_available, i18n_default, i18n_lang, i18n_rtl, i18n_set
from .readers import reader_select
from .iocs import IocError
from .localpaths import path_problem
from .netconns import nc_is_remote, nc_list, nc_match
from .scope import SCOPE_BUGREPORT_GUIDE, scope_bugreport_window_guide, scope_guide, scope_window_guide
from .accounts import AC_THREAT_WARNING
from .training import TRAINING_SCENARIOS, training_cleanup, training_prepare
from .report import (V_HITS, _defang_report, prepare_document, render_human, render_summary,
                     result_kind, share_summary, write_json)
from .workflow import workflow_before_scan, workflow_output_guard, workflow_write_text

GUI_RED = "#c4161c"
GUI_INK = "#1d1d1f"
GUI_MUTED = "#5f6368"
GUI_BG = "#f6f6f7"
GUI_CARD = "#ffffff"
GUI_GOOD = "#1e7e34"
GUI_WARN = "#9a6700"
# Nothing found, but not everything could be checked: neither the green of a
# complete check nor the amber of a warning.
GUI_NEUTRAL = "#3c4858"

GUI_CHECKS = (
    ("browser", "Quick check", "Browsers only, where ad-delivered spyware leaves its traces. Usually 5 to 15 minutes."),
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
    "browser": "Checking your browsers", "hash": "Checking program files", "host": "Checking system settings",
    "traces": "Checking apps and programs that start by themselves",
    "windows-execution": "Checking programs that have run", "exploited-software": "Looking for out-of-date programs",
    "unix-host": "Checking system settings", "android-intrusion": "Checking the phone's settings",
    "android": "Checking the Android phone", "ios": "Checking the iPhone backup",
    "patterns": "Running the extra pattern check", "wifi-settings": "Checking saved Wi-Fi networks",
    "trust-settings": "Checking certificates and network settings",
    "doors": "Looking for ways in that are left open", "dns-logs": "Reading the DNS log",
}
# How long each check usually takes, said before it starts (the same estimates as on the choice of check).
GUI_DURATIONS = {
    "browser": "This check usually takes 5 to 15 minutes.",
    "default": "This check usually takes 15 to 20 minutes.",
    "full": "This check usually takes 30 minutes or more.",
    "phone": "This check usually takes a few minutes.",
    "training": "This takes a few seconds.",
}
# After this long on one step with nothing new to say, the window says it is still working.
GUI_SLOW_STEP_SECONDS = 120
HELPLINE = "https://www.accessnow.org/help/"
STALKERWARE_HELP = "https://stopstalkerware.org/"
PROJECT_TELEGRAM = "https://t.me/+t9gq13mSKcE4NGI0"
# Who to send a result to, in the "Send this to someone who can help" window: (name, who it is for, address).
GUI_HELPERS = (
    ("Access Now Digital Security Helpline", "Free, for journalists, activists, lawyers and human rights defenders",
     HELPLINE),
    ("Coalition Against Stalkerware", "If you think a partner or someone close is watching your phone",
     STALKERWARE_HELP),
    ("Zero Breach on Telegram", "Join the group and ask in the MOD channel for someone to contact you privately. "
     "Never post files, reports or personal details in the group itself.", PROJECT_TELEGRAM),
)
BLOCKLIST_URL = "https://github.com/interplains/Zero-Breach-Toolkit#blocking-advertising-domains"


# Roughly how long each step takes on an ordinary computer, in seconds (team test, 15.5-minute Standard check:
# browsers 691 s, program files 185 s, traces 35 s, doors 13 s, the rest a few seconds). Only the bar's pace
# comes from these: the text always says which step is running.
GUI_STEP_SECONDS = {"browser": 600, "hash": 200, "traces": 35, "windows-execution": 20, "exploited-software": 15,
                    "doors": 13, "host": 6, "unix-host": 6, "trust-settings": 4, "wifi-settings": 3,
                    "android": 60, "android-intrusion": 10, "ios": 90, "patterns": 120, "dns-logs": 30}


def gui_background_priority(on: bool) -> bool:
    """While a check runs, let everything else on the computer go first: Windows' background mode lowers this
    program's CPU, disk and memory priority (and lifts it again afterwards); macOS and Linux get a lower nice
    value for the rest of the session (it cannot be raised back without administrator rights). The check takes
    longer only when the computer is busy with something else. True when the change was made."""
    try:
        if sys.platform == "win32":
            import ctypes
            kernel32 = ctypes.windll.kernel32
            mode = 0x00100000 if on else 0x00200000          # PROCESS_MODE_BACKGROUND_BEGIN / _END
            return bool(kernel32.SetPriorityClass(kernel32.GetCurrentProcess(), mode))
        if on and hasattr(os, "nice"):
            if os.nice(0) < 10:
                os.nice(10 - os.nice(0))
            return True
    except (OSError, AttributeError, ValueError):
        pass
    return False


def gui_progress_smooth(state, now=None):
    """The bar's position (0-100) for a running check: finished steps by their usual length, plus the share of
    the current one - its own count when it gives one (program files), otherwise an estimate from how long it
    has been running that slows down as it nears the end and never reaches it. None before the first step."""
    if "current" not in state:
        return None
    steps = state.get("steps") or [state["current"]]
    index = max(0, state.get("index", 0))
    weights = [GUI_STEP_SECONDS.get(n, 10) for n in steps]
    while len(weights) <= index:
        weights.append(10)
    total = float(sum(weights))
    done = sum(weights[:index])
    if state.get("measured") or state.get("fraction", 0.0) >= 1.0:
        part = state.get("fraction", 0.0)
    else:
        import math
        elapsed = max(0.0, (now if now is not None else time.monotonic()) - state.get("since", 0.0))
        usual = weights[index]
        # steady up to 90% over the step's usual length, then creeping towards 95% if it takes longer
        part = 0.9 * elapsed / usual if elapsed < usual else 0.9 + 0.05 * (1.0 - math.exp(-(elapsed - usual) / usual))
    percent = 100.0 * (done + weights[index] * part) / total
    percent = max(state.get("shown", 0.0), min(99.0, percent))      # never backwards, full only when done
    state["shown"] = percent
    return percent


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
        state.update(current=name, fraction=0.0, detail="", measured=False, since=time.monotonic())
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
    text = T("{name}... (step {n} of {total})", n=index + 1, total=total,
             name=T(GUI_STEP_NAMES[name]) if name in GUI_STEP_NAMES else name)
    if state.get("detail"):
        text += " - " + state["detail"]
    percent = 100.0 * (index + state.get("fraction", 0.0)) / total
    return text, max(0.0, min(100.0, percent))


def gui_next_steps(document):
    """What the person should do now, in a few plain lines, from the result."""
    verdict = document.get("verdict", {})
    status = verdict.get("status", "")
    kind = result_kind(document)
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
    elif kind == "unread":
        steps.append(T("The phone's backup or collection could not be opened, so nothing in it was "
                       "checked. Check the folder you chose. For an encrypted iPhone backup, enter its "
                       "backup password and run the check again."))
    elif kind == "none":
        steps.append(T("Nothing matched known spyware. Keep your system and apps updated, and run the "
                       "check again now and then."))
    elif kind == "none_with_gaps" and not document.get("scope", {}).get("cancelled"):
        steps.append(T("Nothing matched known spyware in what could be checked, but some checks could "
                       "not run, so this is not a full all-clear. They are listed in the summary: fix "
                       "what you can and run the check again."))
    elif kind == "withdrawn":
        steps.append(T("The publisher of the matched indicator has withdrawn it, so this is not an "
                       "actionable finding on its own. Read the match and the withdrawal note in the "
                       "summary; it does not clear the device either."))
    else:
        steps.append(T("Usually nothing to do: a name in a page you read or saved is not an infection. "
                       "If you have another reason to worry, a helpline can advise: {url}", url=HELPLINE))
    if modules.get("exploited-software", {}).get("leads"):
        steps.append(T("Update the out-of-date programs named in the summary: attackers are using "
                       "flaws in those versions right now."))
    phone_update = [l for l in modules.get("ios", {}).get("leads", []) if l.get("check") == "ios:software-version"]
    if phone_update:
        steps.append(T("Update the iPhone (Settings > General > Software Update): its iOS is older than the fix "
                       "for flaws attackers are using right now, which is how spyware usually gets onto phones."))
    other_leads = sum(len(m.get("leads", [])) for n, m in modules.items()
                      if n != "exploited-software") - len(phone_update)
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
    # Kept last so a saved choice keeps its place. "" = no --ios-input: the Android reader recognises the file.
    ("Android bug report (made on the phone, no USB debugging needed)", ""),
)
GUI_BUGREPORT_KIND = len(GUI_PHONE_KINDS) - 1


_GUI_SETTING_URI = re.compile(r"^(ms-settings:[A-Za-z0-9-]+|windowsdefender://[A-Za-z]+|"
                              r"x-apple\.systempreferences:[A-Za-z0-9.\-]+(\?[A-Za-z0-9_]+)?)$")


def gui_setting_allowed(uri):
    """Only the system-settings links the doors check writes; anything else is never opened."""
    return bool(_GUI_SETTING_URI.match(str(uri or "")))


def gui_open_setting(uri):
    """Open a system settings page (never a web address). Returns a sentence for the status line."""
    if not gui_setting_allowed(uri):
        return "That setting cannot be opened from here."
    try:
        if sys.platform == "win32":
            os.startfile(uri)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            import subprocess
            subprocess.run(["open", uri], check=False, timeout=20)
        else:
            return "Open your system settings to change this."
    except OSError as exc:
        return "The setting could not be opened: {}".format(str(exc)[:120])
    return "Opened the setting."


def gui_is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    except (AttributeError, OSError):
        return False


def gui_admin_would_help(document):
    """True on Windows, not elevated, when a gap says a record is readable only by administrators."""
    if sys.platform != "win32" or gui_is_admin():
        return False
    gaps = " ".join(str(g) for g in (document.get("verdict") or {}).get("gaps", []))
    return "only administrators" in gaps or "run the check as administrator" in gaps


def gui_restart_elevated():
    """Start this program again as administrator (Windows asks the person). "" on success, else why not."""
    if not getattr(sys, "frozen", False):
        return ("Start the program from an administrator terminal instead (right-click Terminal > Run as "
                "administrator), then run it again.")
    try:
        import ctypes
        code = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, None, None, 1)  # type: ignore
    except (AttributeError, OSError) as exc:
        return "Windows could not start it as administrator: {}".format(str(exc)[:120])
    return "" if code > 32 else "Not restarted: Windows did not allow it (or you chose No)."


def gui_doors_recheck():
    """Run only the doors check again (a few seconds) and return its doors, labelled as in a report."""
    import importlib
    from types import SimpleNamespace
    run = globals().get("run_doors")                  # the single-file build has it in scope
    if run is None:
        run = importlib.import_module("zbtriage.modules.doors").run
    result = run(SimpleNamespace(partial=None)).to_dict()
    return [dict(d, module="doors") for d in result.get("doors", [])]


def _report_doors_sort(doors):
    order = {"open": 0, "unknown": 1, "closed": 2}
    severity = {"high": 0, "medium": 1, "low": 2}
    return sorted(doors, key=lambda d: (order.get(d.get("state"), 3), severity.get(d.get("severity"), 3),
                                        d.get("door", "")))


def gui_backup_folders():
    """Local iPhone backups, newest first: [(label, path)]."""
    from .iphonebackup import ib_backup_roots
    found = []
    for root in ib_backup_roots():
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


def gui_update_line(line):
    """One progress line of the indicator update in plain words. The update
    prints technical lines ("[=] Name: 583 indicators, unchanged (sha256 ...)");
    people see "Name: already up to date". Lines it does not know are shown as
    they are."""
    import re
    m = re.match(r"\[=\] (.+?): [\d,]+ indicators, unchanged", line)
    if m:
        return T("{name}: already up to date", name=m.group(1))
    m = re.match(r"\[\+\] (.+?): [\d,]+ indicators", line)
    if m:
        return T("{name}: updated", name=m.group(1))
    m = re.match(r"\[!\] (.+?) failed: ", line)
    if m:
        return T("{name}: could not be updated", name=m.group(1))
    m = re.match(r"Indicator sets in .*?: (\d+) up to date, (\d+) failed", line)
    if m:
        return T("{ok} lists up to date, {failed} could not be updated", ok=m.group(1), failed=m.group(2))
    if line.startswith("FAILED "):
        m = re.match(r"FAILED (.+?): ", line)
        return T("{name}: could not be updated", name=m.group(1)) if m else line
    if line.startswith("Exploited-vulnerability list:"):
        return T("Updating the list of actively exploited software...")
    if line.startswith("Actively exploited software list not updated"):
        return T("The list of actively exploited software could not be updated.")
    if line.startswith("Actively exploited software list"):
        return T("The list of actively exploited software is up to date.")
    return line


def gui_lists_missing():
    """True while no indicator list has been downloaded to this computer, so
    only the lists built into the program are used."""
    try:
        from .feeds import default_cache_dir, read_manifest
        return not read_manifest(default_cache_dir())
    except Exception:  # noqa: BLE001 - an unreadable cache is not "missing"; say nothing
        return False


def gui_save_folder():
    """Where the save dialog opens. Downloads, not Documents: Windows ransomware
    protection (Controlled folder access) blocks an unsigned program from
    writing to Documents, Desktop and Pictures, and a person who has it turned
    on - a common setting for exactly this audience - could not save at all."""
    home = os.path.expanduser("~")
    for name in ("Downloads", "Documents"):
        folder = os.path.join(home, name)
        if os.path.isdir(folder):
            return folder
    return home


def gui_save_failure(exc):
    """What to tell the person when a report could not be written: what
    probably happened, and what to do, before the system's own wording."""
    if getattr(exc, "errno", None) is None:
        return str(exc)      # this program's own refusal (for example a network path), already plain
    detail = getattr(exc, "strerror", None) or str(exc)
    return (T("The file could not be saved in that folder. Your security software - for example "
              "Windows ransomware protection (Controlled folder access) - may stop this program "
              "from writing to folders such as Documents, Desktop and Pictures. Nothing was changed. "
              "Press Save again and choose your Downloads folder, or another folder you created "
              "yourself.") + "\n\n" + T("Details: {detail}", detail=detail))


def gui_guide_text(platform):
    """The phone guide for the window. The packaged program has no folder to
    run a script from and its people are not at a command line, so it gets the
    window's own steps; someone running the script keeps the command-line form."""
    if getattr(sys, "frozen", False):
        extra = ("\n\n" + scope_bugreport_window_guide()) if platform == "android" else ""
        return scope_window_guide(platform) + extra
    extra = ("\n\n" + T(SCOPE_BUGREPORT_GUIDE)) if platform == "android" else ""
    return T(scope_guide(platform)) + extra


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


def gui_font_family(default, available):
    """The Windows face for Chinese, Japanese or Korean, so characters are not
    drawn with another language's fallback font. Elsewhere the system default."""
    if sys.platform != "win32":
        return default
    wanted = {"zh": ("Microsoft YaHei UI", "Microsoft YaHei"), "ja": ("Yu Gothic UI", "Meiryo UI", "Meiryo"),
              "ko": ("Malgun Gothic",)}.get(i18n_lang(), ())
    return next((name for name in wanted if name in available), default)


def gui_save_types(extension):
    """The save dialog's file-type list."""
    kinds = {".txt": T("Text file"), ".json": T("Data file (JSON)")}
    return [(kinds.get(extension, extension), "*" + extension), (T("All files"), "*.*")]


def gui_relaunch_without_console():
    """Double-clicked on Windows, the program starts in a terminal window that
    stays in the taskbar, and closing it ends the check. Start again with no
    console and let this copy end, which closes the terminal. Returns True when
    the new copy started; on any failure the caller carries on here."""
    if sys.platform != "win32" or not getattr(sys, "frozen", False) or os.environ.get("ZB_WINDOW_ONLY"):
        return False
    if not gui_launched_by_double_click():
        return False
    try:
        import subprocess
        # The reset makes the copy unpack for itself: this one's folder goes when it ends.
        env = dict(os.environ, ZB_WINDOW_ONLY="1", PYINSTALLER_RESET_ENVIRONMENT="1")
        subprocess.Popen([sys.executable] + sys.argv[1:], env=env, close_fds=True,
                         creationflags=subprocess.CREATE_NO_WINDOW,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except (OSError, ValueError, AttributeError):
        return False
    return True


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


def gui_found_line(document):
    """"6 found - Predator: graph[.]example[.]com, app com.x.y, a file 3f2a9c1e... and 3 more." - what the checks
    matched, for the result card, so it says how many and which without opening the report. Addresses are
    defanged (never clickable), file fingerprints shortened, each family named once. Without matches, the first
    worth-a-look items."""
    import re
    groups, count = {}, 0
    for h in (h for m in document.get("modules", {}).values() for h in m.get("hits", [])):
        if h.get("withdrawn_only"):
            continue
        raw = str(h.get("indicator") or "")
        if not raw:
            continue
        if re.fullmatch(r"[0-9a-fA-F]{32,128}", raw):
            name = T("a file {fingerprint}...", fingerprint=raw[:10])
        elif re.search(r"[a-z0-9-]\.[a-z]{2,}$", raw, re.I) and " " not in raw:
            name = raw.replace(".", "[.]")
        else:
            name = raw[:60]
        family = str(h.get("family") or "").strip()
        names = groups.setdefault(family, [])
        if name not in names:
            names.append(name)
            count += 1
    if count:
        parts, shown = [], 0
        for family, names in groups.items():
            take = names[:max(0, 4 - shown)]
            shown += len(take)
            if take:
                parts.append((family + ": " if family else "") + ", ".join(take))
        more = count - shown
        text = TN("{n} found - {names}", "{n} found - {names}", count, names="; ".join(parts))
        return text + (" " + TN("and {n} more", "and {n} more", more) if more > 0 else "") + "."
    leads = []
    for m in document.get("modules", {}).values():
        for lead in m.get("leads", []):
            what = str(lead.get("what") or lead.get("check") or "").strip()
            if what and what not in leads:
                leads.append(what)
    if leads:
        text = T("Worth a look: {items}", items="; ".join(x[:80] for x in leads[:3]))
        return text + (" " + TN("and {n} more", "and {n} more", len(leads) - 3) if len(leads) > 3 else "") + "."
    return ""


def gui_headline(document):
    """(colour, title, subtitle) for the result card; the subtitle starts with what was found, by name."""
    colour, title, note = _gui_headline(document)
    found = gui_found_line(document)
    if found and found not in note:
        note = found + " " + note
    return colour, title, note


def _gui_headline(document):
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
        # The title says how strong the evidence is, in the same words as "IN PLAIN WORDS".
        from .report import PLAIN_CONTACT, PLAIN_STRONG
        hits = [h for m in document.get("modules", {}).values() for h in m.get("hits", [])
                if not h.get("withdrawn_only") and h.get("evidence") != "referenced"]
        strong = [h for h in hits if h.get("evidence") in PLAIN_STRONG]
        if strong and {h.get("tier") for h in strong} == {"stalkerware"}:
            return (GUI_RED, T("A phone-monitoring (stalkerware) app was found"),
                    T("If you did not install it, someone may be watching this phone. Removing it can alert them: "
                      "read the steps below and talk to a helpline first.") + gap_note)
        if strong:
            return (GUI_RED, T("Spyware found on this device"),
                    T("A file or app matching known spyware is on this device. Keep it as it is - do not wipe or "
                      "reset it - and read the steps below.") + gap_note)
        if hits and all(h.get("evidence") in PLAIN_CONTACT for h in hits):
            return (GUI_WARN, T("Contact with a spyware address - not proof of infection"),
                    T("This device contacted or looked up an address on the spyware lists, but no spyware file or "
                      "app was found. Keep the report and read the steps below.") + gap_note)
        # A grade that is missing or unknown counts as serious, never as "only contact".
        return (GUI_RED, T("Something needs a closer look"),
                T("Traces matching known spyware were found. Read the summary below before acting, "
                  "and keep this device as it is.") + gap_note)
    kind = result_kind(document)
    if leads and kind in ("none", "none_with_gaps"):
        # Nothing known matched, but some things deserve a second look: say that in the title and colour, or the
        # card reads exactly like a clean result (found by the team test: the "worth a look" practice example).
        gaps_only = (" " + TN("{n} check could not run; see below.", "{n} checks could not run; see below.", gaps)
                     if gaps else "")
        return (GUI_WARN, TN("{n} thing worth a look", "{n} things worth a look", leads),
                T("No known spyware matched, but some things deserve a second look. They are listed in the "
                  "summary below; they are not proof of anything on their own.") + gaps_only)
    if kind == "unread":
        # Never green: a phone nothing was read from was not checked at all.
        return (GUI_WARN, T("This phone could not be checked"),
                T("Nothing in its backup or collection could be read, so nothing in it was checked. "
                  "This is not a clean result.") + gap_note)
    if kind == "none":
        return (GUI_GOOD, T("No known spyware traces found"),
                T("Nothing matched the indicators in what could be checked. That is not a guarantee.")
                + gap_note)
    if kind == "none_with_gaps":
        # Green is for a check that ran in full. With gaps the honest headline
        # is what was searched, in a colour that does not say "all clear".
        return (GUI_NEUTRAL, T("Nothing found in what could be checked"),
                T("Nothing matched the indicators in what could be checked, but some checks could not "
                  "run, so this is not a full all-clear. That is not a guarantee.") + gap_note)
    if kind == "withdrawn":
        return (GUI_WARN, T("Only a withdrawn indicator matched"),
                T("A match was found to an indicator its publisher has withdrawn. That is not an "
                  "actionable finding on its own; review the source context in the summary.")
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
        self.root.after(900, self._welcome_back)
        if hooks.get("open_file"):           # a file dropped onto the program: check it straight away
            self.root.after(400, lambda: self.check_file(hooks["open_file"]))
        if sys.platform == "darwin":
            # macOS hands a file dropped on the app icon (at launch or while open) to Tk's open-document event.
            try:
                self.root.createcommand("::tk::mac::OpenDocument",
                                        lambda *paths: paths and self.root.after(300, lambda: self.check_file(paths[0])))
            except Exception:  # noqa: BLE001 - an older Tk without the event: the button still works
                pass

    # --- look -------------------------------------------------------------
    def _style(self):
        tk, ttk = self.tk, self.ttk
        from tkinter import font
        base = font.nametofont("TkDefaultFont")
        base.configure(size=10)
        family = gui_font_family(base.cget("family"), font.families())
        base.configure(family=family)
        self.font_title = font.Font(family=family, size=18, weight="bold")
        self.font_head = font.Font(family=family, size=13, weight="bold")
        self.font_body = font.Font(family=family, size=10)
        self.font_bold = font.Font(family=family, size=10, weight="bold")
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
            if i18n_rtl():
                width -= 24     # drawn right-to-left text can be wider than Tk measures it
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
        self.tab_more = ttk.Frame(tabs)
        self.tab_result = ttk.Frame(tabs)
        self.tab_net = ttk.Frame(tabs)
        self.tab_help = ttk.Frame(tabs)
        tabs.add(self.tab_check, text=T("Check"))
        tabs.add(self.tab_more, text=T("More checks"))
        tabs.add(self.tab_result, text=T("Result"))
        tabs.add(self.tab_net, text=T("Live connections"))
        tabs.add(self.tab_help, text=T("Help"))
        tabs.bind("<<NotebookTabChanged>>", lambda _e: self._tab_changed(tabs))
        self._layout_check()
        self._layout_more()
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
        # The phone and example rows span both columns. Without a weight on the
        # notes column, their width was shared out to the column of choices and
        # pushed every description to the right whenever one of them was shown.
        top.columnconfigure(1, weight=1)
        ttk.Label(top, text=T("Choose a check"), style="Card.TLabel", font=self.font_head).grid(
            row=0, column=0, sticky="w", columnspan=2)
        justify = self._just()[0]

        def beside_choices(top=top):
            # The note column: the card's width less its padding, the
            # column of choices and the label's padding on both sides.
            return top.winfo_width() - 32 - top.grid_bbox(0, 1, 0, len(GUI_CHECKS))[2] - 24 - 8

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
        self.update_button = ttk.Button(buttons, text=T("Update indicator lists"), command=self.update_lists)
        self.update_button.pack(side="left", padx=12)
        self.more_button = ttk.Button(buttons, text=T("More checks..."), command=self.more_checks)
        self.more_button.pack(side="left")
        self.intake_button = ttk.Button(buttons, text=T("Not sure where to start?"), command=self.what_happened)
        self.intake_button.pack(side="left", padx=(8, 0))
        self.close_note = ttk.Label(top, style="Muted.TLabel", justify=justify)
        self.close_note.grid(row=self.options_row + 2, column=0, columnspan=2, sticky="w", pady=(10, 0))
        self._fit(self.close_note, T("Close your browsers and chat apps first: open apps lock some "
                                     "of their records. Updating the lists is the only step that "
                                     "uses the internet."), 860, lambda: top.winfo_width() - 32 - 8)
        # A fresh profile has only the built-in indicators until the lists are
        # downloaded; say so before a check, not only in its result.
        self.lists_note = ttk.Label(top, style="Muted.TLabel", justify=justify, foreground=GUI_WARN)
        self.lists_note.grid(row=self.options_row + 3, column=0, columnspan=2, sticky="w", pady=(6, 0))
        self._fit(self.lists_note,
                  T("Only the built-in indicators are in use: the full lists have not been downloaded "
                    "yet. Press \"{update}\" to download them.", update=T("Update indicator lists")),
                  860, lambda: top.winfo_width() - 32 - 8)
        self._lists_note_visibility()
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
        self.share_button = ttk.Button(actions, text=T("Send this to someone who can help..."),
                                       command=self.send_for_help, state="disabled")
        self.share_button.pack(side="left")
        self.doors_button = ttk.Button(actions, text=T("Doors to close..."), command=self.show_doors,
                                       state="disabled")
        self.doors_button.pack(side="left", padx=(6, 0))
        # Shown only on Windows, when the result says some records need administrator rights.
        self.admin_button = ttk.Button(actions, text=T("Restart as administrator for the full check"),
                                       command=self.restart_as_admin)
        self.saved_note = tk.Label(result, text="", bg=GUI_CARD, fg=GUI_MUTED, font=self.font_body,
                                   anchor=anchor, justify=justify, wraplength=860)
        self.saved_note.pack(fill="x", pady=(0, 6))
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
        ttk.Button(help_row, text=T("Make an iPhone backup..."),
                   command=self.make_backup).pack(side="left", padx=(0, 6))
        ttk.Button(help_row, text=T("How do I make an iPhone backup?"),
                   command=lambda: self.show_guide("ios")).pack(side="left")
        ttk.Button(help_row, text=T("How do I check an Android phone?"),
                   command=lambda: self.show_guide("android")).pack(side="left", padx=6)
        ttk.Button(help_row, text=T("Collect from an Android phone..."),
                   command=self.collect_android).pack(side="left")

    def _lists_note_visibility(self):
        """Show the built-in-indicators note while no list has been downloaded."""
        if gui_lists_missing():
            self.lists_note.grid()
        else:
            self.lists_note.grid_remove()

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
        if self.phone_kind.get() == self.phone_kinds[GUI_BUGREPORT_KIND]:
            # A bug report is one file the phone made (Developer options > Take bug report), not a folder.
            path = filedialog.askopenfilename(parent=self.root, title=T("Choose the bug report the phone made"),
                                              filetypes=[(T("Bug report"), "*.zip *.txt"), (T("All files"), "*")])
        else:
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
            listed = backups[:8]
            if len(backups) > len(listed):
                text = (T("The newest backup was chosen. The newest backups found:") + "\n\n" +
                        "\n".join(label for label, _path in listed) + "\n\n" +
                        T("...and {n} more not shown.", n=len(backups) - len(listed)))
            else:
                text = (T("The newest backup was chosen. All backups found:") + "\n\n" +
                        "\n".join(label for label, _path in listed))
            messagebox.showinfo(T("iPhone backups found"), text, parent=self.root)

    # --- More checks: home network, trackers, household report, DNS log -------------------------------

    def more_checks(self):
        """The "More checks..." button: open the More checks tab."""
        self.tabs.select(self.tab_more)

    def _layout_more(self):
        """The More checks tab: every separate check, in the same sections and names as the terminal menu."""
        tk, ttk = self.tk, self.ttk

        class _InTab:                                   # the entries once closed a pop-up; in a tab there is none
            def destroy(self):
                pass
        win = _InTab()
        page = self.tab_more
        # Same sections and names as the terminal menu (menu.py), so both read the same way.
        sections = (
            (T("Check something you received"), (
                (T("Check a suspicious file..."),
                 T("An attachment, download or app you don't trust. Says what it really is and whether it matches "
                   "known spyware, and seals a copy to send to an expert. It is never opened or run. Tip: you can "
                   "also drop a file onto the Zero Breach program."),
                 lambda: (win.destroy(), self.check_file())),
                (T("Check a link or message..."),
                 T("Paste a text, WhatsApp or Signal message, email or link. Finds spyware links and account-takeover "
                   "tricks. Nothing is opened."),
                 lambda: (win.destroy(), self.link_check())),
                (T("Check a suspicious email..."),
                 T("A saved email (.eml or \"Show original\"). Who really sent it, what the receiving server "
                   "decided, and its links and attachments. Nothing is opened."),
                 lambda: (win.destroy(), self.email_check())),
                (T("Check a QR code..."),
                 T("A picture of a QR code. Reads what it says without following it - including the links that "
                   "add someone else's device to your messaging account."),
                 lambda: (win.destroy(), self.qr_check_window())),
                (T("Look up a file's fingerprint..."),
                 T("Fingerprints a file or folder and compares it with the spyware lists; then, only if you say yes, "
                   "asks online services about the fingerprints (never the files)."),
                 lambda: (win.destroy(), self.hash_lookup())),
                (T("Keys for online look-ups..."),
                 T("Your own free keys for MalwareBazaar / ThreatFox, VirusTotal and Hybrid Analysis."),
                 lambda: (win.destroy(), self.lookup_keys())),
            )),
            (T("Around you"), (
                (T("Check my home network..."),
                 T("Who is on your Wi-Fi, which doors their devices leave open, whether cameras show video without a "
                   "password, and whether your router's lookups are being changed. Asks first; looks only."),
                 lambda: (win.destroy(), self.home_network())),
                (T("Hidden Wi-Fi networks nearby..."),
                 T("The networks this computer hears, and what a hidden one probably is: who made it, whether it is "
                   "part of your own router, how close it is. Joins nothing."),
                 lambda: (win.destroy(), self.wifi_nearby())),
                (T("Look for Bluetooth trackers..."),
                 T("Listens for AirTags, SmartTags, Tiles and Find Hub tags near you. Receives only."),
                 lambda: (win.destroy(), self.trackers())),
                (T("Check a network recording..."),
                 T("A recording of a phone's internet traffic (the free PCAPdroid app on Android makes one without "
                   "root): which servers were contacted, and by which app. Offline."),
                 lambda: (win.destroy(), self.traffic_check())),
                (T("Check a router or Pi-hole DNS log..."),
                 T("Checks every device that used that DNS server, from its log file. Contacts nothing."),
                 lambda: (win.destroy(), self.dns_log())),
            )),
            (T("Look closer"), (
                (T("Was a phone copied by a forensics tool?..."),
                 T("For a phone that was taken from you: reads a phone collection or an iPhone backup for signs "
                   "it was plugged into a Cellebrite-style machine. Finding nothing is not proof."),
                 lambda: (win.destroy(), self.extraction_check())),
                (T("Check my online accounts..."),
                 T("A guided list: devices linked to your WhatsApp, Signal, Apple or Google account, email "
                   "forwarding, location sharing. You look and tick; nothing is signed in to or sent."),
                 lambda: (win.destroy(), self.account_checklist())),
                (T("I got a threat warning..."),
                 T("Apple, Google, WhatsApp or another service warned you may be targeted: how to check it is "
                   "real, keep the evidence and get free help."),
                 lambda: (win.destroy(), self._text_window(T("If you got a threat warning"),
                                                           T(AC_THREAT_WARNING)))),
                (T("Close the doors found open..."),
                 T("Switch off Remote Desktop, automatic sign-in or old file sharing, and switch the firewall "
                   "on. Asks before each one and saves a way back."),
                 lambda: (win.destroy(), self.fix_it())),
                (T("What starts automatically..."),
                 T("Every program set to start with the computer: its signature, and anything worth a second look. "
                   "Read only; nothing is changed."),
                 lambda: (win.destroy(), self.startup_list())),
                (T("Look through Windows' own records..."),
                 T("Hidden commands, downloads that were run, protection switched off, cleared logs, remote "
                   "sessions. Takes a couple of minutes; reads only."),
                 lambda: (win.destroy(), self.hunt_records())),
                (T("Open a Windows log file (.evtx)..."),
                 T("Read records exported from another computer, on any system."),
                 lambda: (win.destroy(), self.hunt_file())),
            )),
            (T("Put it together"), (
                (T("Household report..."),
                 T("Put the saved reports of every computer, phone and the home network on one page."),
                 lambda: (win.destroy(), self.household())),
                (T("Send evidence to a helper..."),
                 T("Put reports, a phone collection or files into one package only your helper can open, signed so "
                   "they know it is from you. Nothing is uploaded."),
                 lambda: (win.destroy(), self.helper_package())),
            )),
        )
        outer = ttk.Frame(page, style="Card.TFrame")
        outer.pack(fill="both", expand=True, padx=16, pady=12)
        canvas = tk.Canvas(outer, bg=GUI_CARD, highlightthickness=0, borderwidth=0)
        bar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = ttk.Frame(canvas, style="Card.TFrame")
        item = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(item, width=e.width))

        def wheel(event):
            if event.num == 4 or event.delta > 0:
                canvas.yview_scroll(-1 if sys.platform == "darwin" else -3, "units")
            elif event.num == 5 or event.delta < 0:
                canvas.yview_scroll(1 if sys.platform == "darwin" else 3, "units")
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            outer.bind(seq, wheel)
            canvas.bind(seq, wheel)
        for heading, items in sections:
            ttk.Label(inner, text=heading.upper(), style="Muted.TLabel").pack(anchor="w", padx=14, pady=(12, 0))
            for label, note, command in items:
                row = ttk.Frame(inner, style="Card.TFrame")
                row.pack(fill="x", padx=14, pady=5)
                button = ttk.Button(row, text=label, command=command)
                button.pack(anchor="w")
                text = ttk.Label(row, text=note, wraplength=860, style="Muted.TLabel")
                text.pack(anchor="w", pady=(2, 0))
                for w in (row, button, text):             # the wheel scrolls wherever the pointer is
                    for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
                        w.bind(seq, wheel)

    def _file_check_window(self, title, filetypes, how_to, check, render, headline):
        """Shared shape for the checks that read one file: explain, choose, read in the background, show."""
        from tkinter import filedialog, messagebox
        if not messagebox.askokcancel(T(title), T(how_to) + "\n\n" + T("Choose the file now?"),
                                      parent=self.root):
            return
        path = filedialog.askopenfilename(parent=self.root, title=T(title), filetypes=filetypes)
        if not path:
            return

        def work():
            with open(path, "rb") as fh:
                data = fh.read(64 * 1024 * 1024)
            try:
                return {"ok": check(data, self._iocs_or_none())}
            except Exception as exc:  # noqa: BLE001 - the reason is shown to the person
                return {"error": str(exc)}

        def show(result):
            if "error" in result:
                messagebox.showerror(T(title), T(str(result["error"])) + "\n\n" + T(how_to), parent=self.root)
                return
            self._text_window(T(title), render(result["ok"]),
                              verdict=(T(headline(result["ok"])), result["ok"]["level"]))
        self._in_background(T("Reading it..."), work, show)

    def extraction_check(self):
        from tkinter import filedialog, messagebox
        from .extracted import EX_HOW_TO, ExError, ex_check, ex_headline, ex_render
        if not messagebox.askokcancel(T("Was a phone copied?"), T(EX_HOW_TO) + "\n\n" +
                                      T("Choose the folder now?"), parent=self.root):
            return
        folder = filedialog.askdirectory(parent=self.root, title=T("Choose the collection or backup folder"))
        if not folder:
            return

        def work():
            try:
                return {"ok": ex_check(folder, self._iocs_or_none())}
            except (ExError, OSError) as exc:
                return {"error": str(exc)}

        def show(result):
            if "error" in result:
                messagebox.showerror(T("Was a phone copied?"), T(str(result["error"])) + "\n\n" + T(EX_HOW_TO),
                                     parent=self.root)
                return
            self._text_window(T("Was a phone copied?"), ex_render(result["ok"]),
                              verdict=(T(ex_headline(result["ok"])), result["ok"]["level"]))
        self._in_background(T("Reading it..."), work, show)

    def email_check(self):
        from .mailcheck import MC_HOW_TO, mc_check, mc_headline, mc_render
        self._file_check_window(T("Check a suspicious email"),
                                [(T("Saved emails"), "*.eml *.msg *.txt"), (T("All files"), "*.*")],
                                MC_HOW_TO, mc_check, mc_render, mc_headline)

    def qr_check_window(self):
        from .qrcheck import QR_HOW_TO, qr_check, qr_headline, qr_render
        self._file_check_window(T("Check a QR code"),
                                [(T("Pictures"), "*.png *.gif *.bmp *.ppm *.pgm"), (T("All files"), "*.*")],
                                QR_HOW_TO, qr_check, qr_render, qr_headline)

    def check_file(self, path=None):
        """A first look at one suspicious file (chosen here, or dropped onto the program), without running it,
        with a button that saves a sealed copy (password 'infected') to send to an expert."""
        from tkinter import filedialog, messagebox
        from .filecheck import fc_examine, fc_headline, fc_render, fc_seal, fc_sealed_name
        if not path:
            path = filedialog.askopenfilename(parent=self.root,
                                              title=T("Choose the suspicious file (it will not be opened or run)"))
            if not path:
                return
        from .localpaths import path_problem
        problem = path_problem(os.path.abspath(path))
        if problem:
            messagebox.showerror(T("Check a suspicious file"),
                                 T("Only files on this computer are checked: {why}", why=problem), parent=self.root)
            return
        if not os.path.isfile(path):
            messagebox.showerror(T("Check a suspicious file"), T("That is not a file: {path}", path=path),
                                 parent=self.root)
            return

        def examine():
            try:
                lists, error = self.hooks["load_iocs"](self.hooks["parse"](["--no-menu", "--no-banner"])), ""
            except Exception as exc:  # noqa: BLE001 - checked without the lists, and the result says so
                lists, error = None, "{}: {}".format(type(exc).__name__, exc)
            return fc_examine(path, lists, lists_error=error)

        def seal(out):
            # Off the window thread: sealing a large file takes minutes in pure Python, and the window must not
            # freeze ("Not responding") meanwhile. Errors are shown by _in_background.
            def done(_result):
                messagebox.showinfo(T("Sealed copy saved"),
                                    T("Saved: {path}\n\nThe password to open it is: infected\n\nThe original file was "
                                      "not touched. Send the sealed copy to an expert, or to us on Telegram.", path=out),
                                    parent=self.root)
            self._in_background(T("Sealing a copy..."), lambda: fc_seal(path, out), done)
            return "background"

        def online(rec):
            """The fingerprint look-up online, for this one file - only after saying what is sent."""
            from .hashlook import (HL_SERVICES, HlCache, hl_consent_text, hl_headline, hl_keys, hl_online,
                                   hl_render, hl_report)
            keys = hl_keys()
            services = [n for n, (_n, _c, need) in HL_SERVICES.items() if not need or keys.get(need)]
            if not messagebox.askyesno(T("Ask online services?"), T(hl_consent_text(services, 1)) + "\n\n" +
                                       T("Send the fingerprint?"), parent=self.root):
                return

            def ask():
                notes = hl_online([rec], services, keys, cache=HlCache())
                return hl_report([rec], notes, [])

            def shown(result):
                self._text_window(T("Online look-up"), hl_render(result),
                                  verdict=(T(hl_headline(result)), result["level"]))
            self._in_background(T("Asking online services..."), ask, shown)

        def show(rec):
            extra = [(T("Also look it up online..."), lambda: online(rec))] if rec.get("sha256") and \
                rec.get("level") != "known-threat" else None
            self._text_window(T("Check a suspicious file"), fc_render(rec),
                              (T("Save a sealed copy..."), fc_sealed_name(path), seal),
                              verdict=(T(fc_headline(rec)), rec.get("level")), extra=extra)
        self._in_background(T("Checking the file (it is not opened or run)..."), examine,
                            show)

    def hash_lookup(self):
        from tkinter import filedialog, messagebox
        from .hashlook import (HL_SERVICES, HlCache, hl_consent_text, hl_headline, hl_keys, hl_online, hl_render,
                               hl_report, hl_run, hl_should_ask)
        paths = list(filedialog.askopenfilenames(parent=self.root, title=T("Choose the file(s) to look up")) or ())
        if not paths:
            return

        def iocs():
            try:
                return self.hooks["load_iocs"](self.hooks["parse"](["--no-menu", "--no-banner"]))
            except Exception:  # noqa: BLE001
                return None

        def show(result):
            self._text_window(T("Hash look-up"), hl_render(result), verdict=(T(hl_headline(result)), result["level"]))
            keys = hl_keys()
            services = [n for n, (_n, _c, need) in HL_SERVICES.items() if not need or keys.get(need)]
            count = len({r["sha256"] for r in result["files"] if hl_should_ask(r)})
            if not count or result.get("asked") or result["level"] == "known-threat":
                return
            if messagebox.askyesno(T("Ask online services?"), T(hl_consent_text(services, count)) + "\n\n" +
                                   T("Send the fingerprints?"), parent=self.root):
                def online():
                    notes = hl_online(result["files"], services, keys, cache=HlCache())
                    return dict(hl_report(result["files"], notes, result["skipped"]), asked=True)
                self._in_background(T("Asking online services..."), online, show)
        self._in_background(T("Fingerprinting..."), lambda: hl_run(paths, iocs()), show)

    def lookup_keys(self):
        from tkinter import messagebox
        from .hashlook import HL_KEY_WHERE, hl_keys, hl_save_key
        tk, ttk = self.tk, self.ttk
        win = tk.Toplevel(self.root)
        win.title(T("Keys for online look-ups"))
        win.geometry("620x360")
        win.configure(bg=GUI_CARD)
        have = hl_keys()
        entries = {}
        for name, where in HL_KEY_WHERE.items():
            ttk.Label(win, text="{} ({})".format(name, T("saved") if have.get(name) else T("not set")),
                      style="Muted.TLabel").pack(anchor="w", padx=14, pady=(10, 0))
            ttk.Label(win, text=T("Get one: ") + where, wraplength=590).pack(anchor="w", padx=14)
            var = tk.StringVar()
            ttk.Entry(win, textvariable=var, show="*", width=70).pack(fill="x", padx=14)
            entries[name] = var

        def save():
            for name, var in entries.items():
                if var.get().strip():
                    hl_save_key(name, var.get().strip())
            messagebox.showinfo(T("Keys for online look-ups"), T("Saved on this computer only."), parent=win)
            win.destroy()
        row = ttk.Frame(win)
        row.pack(side="bottom", fill="x", padx=14, pady=10)
        ttk.Button(row, text=T("Save"), command=save).pack(side="right")
        ttk.Button(row, text=T("Cancel"), command=win.destroy).pack(side="right", padx=6)

    def helper_package(self):
        from tkinter import filedialog, messagebox
        from .ageseal import AgError, ag_parse_recipient
        from .helperpack import HP_HOW, HpError, hp_build, hp_render
        tk, ttk = self.tk, self.ttk
        win = tk.Toplevel(self.root)
        win.title(T("Send evidence to a helper"))
        win.geometry("640x520")
        win.configure(bg=GUI_CARD)
        ttk.Label(win, text=T(HP_HOW.strip()), wraplength=600, justify="left").pack(anchor="w", padx=14, pady=(12, 6))
        ttk.Label(win, text=T("Helper's key (age1...):")).pack(anchor="w", padx=14)
        key = tk.StringVar()
        ttk.Entry(win, textvariable=key, width=80).pack(fill="x", padx=14)
        plain = tk.BooleanVar(value=False)
        ttk.Checkbutton(win, text=T("No key: make an unencrypted package (only if the helper asked)"),
                        variable=plain).pack(anchor="w", padx=14, pady=(4, 8))
        ttk.Label(win, text=T("What to include:")).pack(anchor="w", padx=14)
        chosen = tk.Listbox(win, height=9)
        chosen.pack(fill="both", expand=True, padx=14)
        row = ttk.Frame(win)
        row.pack(fill="x", padx=14, pady=6)

        def add_files():
            for p in filedialog.askopenfilenames(parent=win, title=T("Choose files")) or ():
                chosen.insert("end", p)

        def add_folder():
            p = filedialog.askdirectory(parent=win, title=T("Choose a folder"))
            if p:
                chosen.insert("end", p)

        def remove():
            for i in reversed(chosen.curselection()):
                chosen.delete(i)
        ttk.Button(row, text=T("Add files..."), command=add_files).pack(side="left")
        ttk.Button(row, text=T("Add a folder..."), command=add_folder).pack(side="left", padx=6)
        ttk.Button(row, text=T("Remove"), command=remove).pack(side="left")

        def make():
            paths = list(chosen.get(0, "end"))
            recipient = None if plain.get() else key.get().strip()
            if not paths:
                messagebox.showinfo(T("Send evidence to a helper"), T("Add at least one file or folder."), parent=win)
                return
            if recipient is not None:
                try:
                    ag_parse_recipient(recipient)
                except AgError as exc:
                    messagebox.showerror(T("Send evidence to a helper"), T(str(exc)), parent=win)
                    return
            out = filedialog.askdirectory(parent=win, title=T("Where should the package be saved?"))
            if not out:
                return
            win.destroy()

            def work():
                try:
                    return hp_build(paths, out, recipient)
                except (AgError, HpError, OSError) as exc:
                    return {"error": str(exc)}

            def show(result):
                if "error" in result:
                    messagebox.showerror(T("Send evidence to a helper"),
                                         T("The package was not made: {why}", why=result["error"]), parent=self.root)
                    return
                self._text_window(T("Package for a helper"), hp_render(result),
                                  verdict=(T("Sealed - only your helper can open it") if result["encrypted"] else
                                           T("Not encrypted - send it only by the route your helper agreed"),
                                           "nothing-known" if result["encrypted"] else "worth-a-look"))
            self._in_background(T("Sealing the package..."), work, show)
        bottom = ttk.Frame(win)
        bottom.pack(fill="x", padx=14, pady=(0, 12))
        ttk.Button(bottom, text=T("Make the package..."), command=make).pack(side="right")
        ttk.Button(bottom, text=T("Cancel"), command=win.destroy).pack(side="right", padx=6)

    def fix_it(self):
        from tkinter import messagebox
        from .fixit import FxError, fx_apply, fx_open_doors, fx_plan, fx_render, fx_undo
        tk, ttk = self.tk, self.ttk

        def plan():
            # The quick doors check sees only part of what a full check counts (the browser and trust steps
            # find doors too, and take minutes). Add the open doors of this computer's last full check, so the
            # two screens agree (team test F3); the fresh state wins where both have the same door.
            live = fx_open_doors()
            seen = {d.get("door") for d in live}
            doc = self.document or {}
            earlier = [] if (doc.get("scope") or {}).get("phone") else [
                d for d in doc.get("doors") or [] if d.get("state") == "open" and d.get("door") not in seen]
            result = fx_plan(doors=live + earlier)
            if not doc.get("doors") or (doc.get("scope") or {}).get("phone"):
                from .fixit import FX_GUIDANCE
                result["guidance"].append({
                    "door": "", "title": "A full check finds more doors", "state": FX_GUIDANCE,
                    "text": "Doors in your browsers (extensions, no ad blocker) and in Windows' protection settings "
                            "are found by the Standard check on the Check tab, which takes longer. Run it, then "
                            "open this again to see every door."})
            return result

        def show(plan):
            win = tk.Toplevel(self.root)
            win.title(T("Close the doors found open"))
            win.geometry("720x620")
            win.configure(bg=GUI_CARD)
            box = tk.Text(win, wrap="word", height=18, bg=GUI_CARD, fg=GUI_INK, relief="flat")
            box.insert("1.0", fx_render(plan))
            box.configure(state="disabled")
            box.pack(fill="both", expand=True, padx=14, pady=12)
            row = ttk.Frame(win)
            row.pack(fill="x", padx=14, pady=(0, 12))

            def do(offer):
                def go():
                    if not messagebox.askyesno(T("Close this door?"),
                                               "{}\n\n{}\n\n{}\n\n{}".format(
                                                   T(offer["title"]), T(offer["does"]), T(offer["warn"]),
                                                   T("A way back is saved first. Go ahead?")), parent=win):
                        return
                    win.destroy()

                    def work():
                        try:
                            return fx_apply(offer["door"], confirm=lambda q: True)
                        except (FxError, OSError) as exc:
                            return {"done": False, "why": str(exc)}

                    def done(result):
                        messagebox.showinfo(T("Close the doors found open"),
                                            T("Done. You can put it back from this screen.") if result["done"]
                                            else T("Nothing was changed: {why}", why=result["why"]),
                                            parent=self.root)
                        self._in_background(T("Checking again..."), plan, show)
                    self._in_background(T("Closing it..."), work, done)
                return go
            for offer in plan["offers"]:
                ttk.Button(row, text=T(offer["title"]), command=do(offer)).pack(side="left", padx=(0, 6))
            if plan["records"]:
                def put_back():
                    record = plan["records"][-1]
                    if not messagebox.askyesno(T("Put it back?"), T(record.get("title", "")), parent=win):
                        return
                    win.destroy()
                    self._in_background(T("Putting it back..."),
                                        lambda: fx_undo(record["name"], confirm=lambda q: True),
                                        lambda r: self._in_background(T("Checking again..."), plan, show))
                ttk.Button(row, text=T("Put the last change back"), command=put_back).pack(side="right")
            ttk.Button(row, text=T("Close"), command=win.destroy).pack(side="right", padx=6)
        self._in_background(T("Looking at what is open..."), plan, show)

    def hunt_records(self):
        from .huntwin import hw_from_this_computer, hw_headline, hw_render
        if sys.platform != "win32":
            from tkinter import messagebox
            messagebox.showinfo(T("Windows' own records"),
                                T("This reads a Windows computer's records. Use \"Open a Windows log file\" for "
                                  "records exported from one."), parent=self.root)
            return
        self._in_background(T("Reading Windows' own records..."),
                            lambda: hw_from_this_computer(self._iocs_or_none()),
                            lambda result: self._text_window(T("Windows' own records"), hw_render(result),
                                                             verdict=(T(hw_headline(result)), result["level"])))

    def hunt_file(self):
        from tkinter import filedialog
        from .huntwin import hw_from_files, hw_headline, hw_render
        paths = list(filedialog.askopenfilenames(parent=self.root, title=T("Choose Windows log file(s)"),
                                                 filetypes=[(T("Windows log files"), "*.evtx"),
                                                            (T("All files"), "*.*")]) or ())
        if not paths:
            return
        self._in_background(T("Reading the records..."),
                            lambda: hw_from_files(paths, self._iocs_or_none()),
                            lambda result: self._text_window(T("Windows' own records"), hw_render(result),
                                                             verdict=(T(hw_headline(result)), result["level"])))

    def _iocs_or_none(self):
        try:
            return self.hooks["load_iocs"](self.hooks["parse"](["--no-menu", "--no-banner"]))
        except Exception:  # noqa: BLE001 - the behaviour rules work without the lists
            return None

    def startup_list(self):
        from .startup import su_headline, su_inventory, su_render, su_save

        def work():
            try:
                iocs = self.hooks["load_iocs"](self.hooks["parse"](["--no-menu", "--no-banner"]))
            except Exception:  # noqa: BLE001
                iocs = None
            return su_inventory(iocs)

        def show(result):
            self._text_window(T("What starts automatically"), su_render(result),
                              (T("Save the result..."), "startup-items.json", lambda p: su_save(result, p)),
                              verdict=(T(su_headline(result)), result["level"]))
        self._in_background(T("Listing what starts automatically..."), work, show)

    def traffic_check(self):
        from tkinter import filedialog, messagebox
        from .netcapture import NC_HOW_TO, NcError, nc_analyse, nc_headline, nc_render
        if not messagebox.askokcancel(T("Check a network recording"),
                                      T(NC_HOW_TO.strip()) + "\n\n" + T("Choose the recording now?"), parent=self.root):
            return
        path = filedialog.askopenfilename(parent=self.root, title=T("Choose the recording"),
                                          filetypes=[(T("Network recordings"), "*.pcap *.pcapng *.cap"),
                                                     (T("All files"), "*.*")])
        if not path:
            return

        def work():
            with open(path, "rb") as fh:
                data = fh.read(2 * 1024 * 1024 * 1024)
            try:
                iocs = self.hooks["load_iocs"](self.hooks["parse"](["--no-menu", "--no-banner"]))
            except Exception:  # noqa: BLE001
                iocs = None
            try:
                return nc_analyse(data, iocs)
            except NcError as exc:
                return {"error": str(exc)}

        def show(result):
            if "error" in result:
                messagebox.showerror(T("Check a network recording"), T("That file could not be read: {why}",
                                                                       why=result["error"]), parent=self.root)
                return
            self._text_window(T("Network recording check"), nc_render(result),
                              verdict=(T(nc_headline(result)), result["level"]))
        self._in_background(T("Reading the recording..."), work, show)

    def link_check(self):
        """Paste a message or link; judged offline against the indicator lists and known tricks."""
        tk, ttk = self.tk, self.ttk
        win = tk.Toplevel(self.root)
        win.title(T("Check a link or message"))
        win.geometry("720x460")
        win.configure(bg=GUI_CARD)
        ttk.Label(win, text=T("Paste the message or the link below. Nothing is opened, looked up or sent anywhere."),
                  wraplength=680).pack(anchor="w", padx=14, pady=(12, 6))
        box = tk.Text(win, wrap="word", height=12, font=self.font_body, padx=8, pady=6)
        box.pack(fill="both", expand=True, padx=14)
        box.focus_set()
        bottom = ttk.Frame(win)
        bottom.pack(fill="x", padx=14, pady=10)

        def paste():
            try:
                box.insert("insert", self.root.clipboard_get())
            except tk.TclError:
                pass

        def check():
            text = box.get("1.0", "end").strip()
            if not text:
                return
            win.destroy()
            from .linkcheck import lc_check_text, lc_headline, lc_render

            def work():
                try:
                    iocs = self.hooks["load_iocs"](self.hooks["parse"](["--no-menu", "--no-banner"]))
                except Exception:  # noqa: BLE001 - the patterns still work without the lists
                    iocs = None
                return lc_check_text(text, iocs)
            self._in_background(T("Checking..."), work,
                                lambda result: self._text_window(T("Link and message check"), lc_render(result),
                                                                 verdict=(T(lc_headline(result)), result["level"])))
        ttk.Button(bottom, text=T("Paste"), command=paste).pack(side="left")
        ttk.Button(bottom, text=T("Check"), command=check, style="Accent.TButton").pack(side="right")
        ttk.Button(bottom, text=T("Cancel"), command=win.destroy).pack(side="right", padx=6)

    def account_checklist(self):
        """The account checklist: every step with where to look, and three answers. Unanswered = not checked."""
        from .accounts import (AC_CHECKED, AC_FOUND, AC_KEY_ADVICE, AC_LINKS, AC_SKIPPED, ac_headline,
                               ac_load_answers, ac_render, ac_result, ac_save, ac_save_answers)
        import webbrowser
        tk, ttk = self.tk, self.ttk
        win = tk.Toplevel(self.root)
        win.title(T("Check my online accounts"))
        win.geometry("760x{}".format(max(420, min(1000, self.root.winfo_screenheight() - 120))))
        win.configure(bg=GUI_CARD)
        answers = {}
        remembered = ac_load_answers()

        def keep(*_a):
            ac_save_answers({sid: var.get() for sid, var in answers.items() if var.get()})

        def start_over():
            for var in answers.values():
                var.set("")
            ac_save_answers({})

        def finish():
            result = ac_result({sid: var.get() for sid, var in answers.items() if var.get()})
            win.destroy()
            self._text_window(T("Your online accounts"), ac_render(result),
                              save=(T("Save the result..."), "account-checklist.json",
                                    lambda path: ac_save(result, path)),
                              verdict=(T(ac_headline(result)), result["level"]))
        bottom = ttk.Frame(win)
        bottom.pack(side="bottom", fill="x", padx=14, pady=10)
        ttk.Button(bottom, text=T("Show the result"), command=finish, style="Accent.TButton").pack(side="right")
        ttk.Button(bottom, text=T("Close"), command=win.destroy).pack(side="right", padx=6)
        ttk.Button(bottom, text=T("Start over"), command=start_over).pack(side="left")
        tk.Label(win, text=gui_dir(T(AC_KEY_ADVICE)), bg="#fff4d6", fg=GUI_INK, font=self.font_body,
                 wraplength=720, justify="left", padx=12, pady=10).pack(fill="x", padx=14, pady=(12, 6))
        ttk.Label(win, text=T("No program can see inside your accounts without signing in, and this one never "
                              "does. Look where each step says, then choose an answer. Your answers are kept, so "
                              "you can close this and finish later."), wraplength=720).pack(anchor="w", padx=14,
                                                                                           pady=(0, 6))
        outer = ttk.Frame(win, style="Card.TFrame")
        outer.pack(fill="both", expand=True)
        canvas = tk.Canvas(outer, bg=GUI_CARD, highlightthickness=0, borderwidth=0)
        bar = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=bar.set)
        bar.pack(side="right", fill="y")
        canvas.pack(side="left", fill="both", expand=True)
        inner = ttk.Frame(canvas, style="Card.TFrame")
        item = canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind("<Configure>", lambda _e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.bind("<Configure>", lambda e: canvas.itemconfigure(item, width=e.width))

        def wheel(event):
            if event.num == 4 or event.delta > 0:
                canvas.yview_scroll(-1 if sys.platform == "darwin" else -3, "units")
            elif event.num == 5 or event.delta < 0:
                canvas.yview_scroll(1 if sys.platform == "darwin" else 3, "units")
        for seq in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            win.bind(seq, wheel)
            canvas.bind(seq, wheel)
        from .accounts import AC_STEPS
        for sid, account, where, look, _fix in AC_STEPS:
            row = ttk.Frame(inner, style="Card.TFrame")
            row.pack(fill="x", padx=14, pady=8)
            ttk.Label(row, text=T(account), style="Card.TLabel",
                      font=(self.font_body.actual("family"), 11, "bold")).pack(anchor="w")
            ttk.Label(row, text=T("Where: ") + T(where), wraplength=680, style="Card.TLabel").pack(anchor="w")
            ttk.Label(row, text=T("Check: ") + T(look), wraplength=680, style="Card.TLabel").pack(anchor="w")
            if sid in AC_LINKS:
                ttk.Button(row, text=T("Open this page"),
                           command=lambda u=AC_LINKS[sid]: webbrowser.open(u)).pack(anchor="w", pady=(2, 0))
            var = tk.StringVar(value=remembered.get(sid, ""))
            var.trace_add("write", keep)
            answers[sid] = var
            choices = ttk.Frame(row, style="Card.TFrame")
            choices.pack(anchor="w", pady=(2, 0))
            for value, words in ((AC_CHECKED, T("Checked - fine")), (AC_FOUND, T("Something is wrong or missing")),
                                 (AC_SKIPPED, T("Skip"))):
                ttk.Radiobutton(choices, text=words, value=value, variable=var,
                                style="Card.TRadiobutton").pack(side="left", padx=(0, 12))

    def _text_window(self, title, text, save=None, verdict=None, extra=None):
        """A window showing a text result, with an optional (label, filename, writer) save button and an optional
        coloured verdict bar (text, level) - the same three levels every tool uses."""
        tk, ttk = self.tk, self.ttk
        win = tk.Toplevel(self.root)
        win.title(title)
        win.geometry("860x620")
        if verdict:
            words, level = verdict
            colour = {"known-threat": GUI_RED, "dangerous": GUI_RED, "worth-a-look": GUI_WARN,
                      "incomplete": GUI_WARN}.get(level, GUI_GOOD)
            tk.Label(win, text=words, bg=colour, fg="white", anchor="w", padx=16, pady=12,
                     font=(self.font_body.actual("family"), 14, "bold")).pack(side="top", fill="x")
        bottom = ttk.Frame(win)
        bottom.pack(side="bottom", fill="x", pady=8, padx=12)
        status = tk.StringVar(value="")
        ttk.Label(bottom, textvariable=status).pack(side="right")
        if save:
            label, name, writer = save

            def do_save():
                from tkinter import filedialog
                path = filedialog.asksaveasfilename(parent=win, initialfile=name, defaultextension=os.path.splitext(
                    name)[1], title=label)
                if path:
                    try:
                        if os.path.exists(path):
                            raise OSError("{} already exists - choose a new name".format(path))
                        if writer(path) == "background":       # finishes later and says so itself
                            status.set(T("Saving..."))
                        else:
                            status.set(T("Saved: {path}", path=path))
                    except OSError as exc:
                        status.set(T("Not saved: {why}", why=str(exc)[:120]))
            ttk.Button(bottom, text=label, command=do_save).pack(side="left")
        for label, command in extra or ():
            ttk.Button(bottom, text=label, command=command).pack(side="left", padx=(6, 0))
        ttk.Button(bottom, text=T("Close"), command=win.destroy).pack(side="left", padx=6)
        body = ttk.Frame(win)
        body.pack(fill="both", expand=True)
        box = tk.Text(body, wrap="word", font=self.font_mono if hasattr(self, "font_mono") else self.font_body,
                      padx=12, pady=10)
        scroll = ttk.Scrollbar(body, command=box.yview)
        box.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        box.pack(side="left", fill="both", expand=True)
        box.insert("end", text)
        box.configure(state="disabled")
        return win

    def _in_background(self, title, work, show):
        """Run work() off the window thread; then show(result) - or the error - on it."""
        holder = {}
        self._begin_busy(title, stoppable=False)
        # The status bar lives on the Check tab; from any other tab nothing would seem to happen. A small window
        # in the middle of the screen says what is going on until the result is ready.
        tk, ttk = self.tk, self.ttk
        wait = tk.Toplevel(self.root)
        wait.withdraw()
        wait.title(T("Working..."))
        wait.configure(bg=GUI_CARD)
        wait.resizable(False, False)
        wait.transient(self.root)
        box = tk.Frame(wait, bg=GUI_CARD, padx=24, pady=18)
        box.pack(fill="both", expand=True)
        tk.Label(box, text=gui_dir(title), bg=GUI_CARD, fg=GUI_INK, font=self.font_bold, wraplength=420,
                 justify="left").pack(anchor="w")
        tk.Label(box, text=gui_dir(T("This can take a little while. The result opens by itself.")), bg=GUI_CARD,
                 fg=GUI_MUTED, font=self.font_body, wraplength=420, justify="left").pack(anchor="w", pady=(4, 10))
        bar = ttk.Progressbar(box, mode="indeterminate", length=380)
        bar.pack(fill="x")
        bar.start(12)
        self._centre(wait)
        try:
            wait.grab_set()            # an impatient second click must not start the same check again
        except tk.TclError:            # another window holds the grab (a dialog): fine, it is only a guard
            pass

        def run():
            try:
                holder["result"] = work()
            except BaseException as exc:  # noqa: BLE001 - shown to the person
                holder["error"] = "{}: {}".format(type(exc).__name__, str(exc)[:300])

        thread = threading.Thread(target=run, daemon=True)
        thread.start()

        def poll():
            if thread.is_alive():
                self.root.after(500, poll)
                return
            self._finish_busy()
            try:
                bar.stop()
                wait.destroy()
            except tk.TclError:
                pass
            if "error" in holder:
                from tkinter import messagebox
                messagebox.showerror(title, T("This check stopped with an error: {error}", error=holder["error"]),
                                     parent=self.root)
            else:
                show(holder["result"])
        self.root.after(500, poll)

    def home_network(self):
        from tkinter import messagebox
        from .homenet import HN_CONSENT, HN_FIXED_NAMES, HN_WHOAMI, hn_check, hn_render, hn_target
        try:
            _local, subnet, _gateway, note = hn_target()
        except Exception as exc:  # noqa: BLE001 - HomeNetError and friends: explain, never crash
            messagebox.showinfo(T("Home network check"), T("Not started: {why}", why=str(exc)), parent=self.root)
            return
        consent = T(HN_CONSENT, subnet=subnet, names=len(HN_FIXED_NAMES) + 1 + len(HN_WHOAMI),
                    examples=", ".join(n for n, _ in HN_FIXED_NAMES + HN_WHOAMI))
        if not messagebox.askyesno(T("Home network check"), consent.strip() + ("\n\n" + note if note else "")
                                   + "\n\n" + T("Check this network now?"), parent=self.root):
            return

        def show(result):
            import json
            text = hn_render(result)
            self._text_window(T("Home network check"), text,
                              (T("Save as JSON..."), "home-network.json",
                               lambda path: open(path, "x", encoding="utf-8").write(json.dumps(dict(
                                   result, tool="zero-breach-toolkit home-network check",
                                   timestamp=datetime.datetime.now().astimezone().replace(
                                       microsecond=0).isoformat()), indent=2, ensure_ascii=False))))
        self._in_background(T("Checking the home network..."), lambda: hn_check(), show)

    def wifi_nearby(self):
        from .wifinearby import wn_can_find, wn_render, wn_report, wn_save, wn_scan
        report = wn_report(wn_scan())
        self._text_window(T("Wi-Fi networks nearby"), wn_render(report),
                          (T("Save the result..."), "wifi-nearby.json", lambda p: wn_save(report, p)))
        hidden = [n for n in report.get("hidden") or [] if n.get("bssid")]
        if hidden and wn_can_find():
            self._wifi_find(hidden)

    def _wifi_find(self, hidden):
        """Find it: choose a hidden network, then a live signal meter, refreshed every few seconds."""
        from .wifinearby import wn_meter, wn_rescan, wn_signal_of
        tk, ttk = self.tk, self.ttk
        win = tk.Toplevel(self.root)
        win.withdraw()
        win.title(T("Find a hidden network"))
        win.configure(bg=GUI_CARD)
        body = tk.Frame(win, bg=GUI_CARD, padx=18, pady=14)
        body.pack(fill="both", expand=True)
        tk.Label(body, text=T("Walk slowly around with this computer: the signal is strongest near the device."),
                 bg=GUI_CARD, fg=GUI_INK, font=self.font_body, wraplength=520, justify="left").pack(anchor="w")
        names = ["{}  {}".format(n["bssid"], n.get("vendor") or "") for n in hidden]
        choice = tk.StringVar(value=names[0])
        ttk.Combobox(body, values=names, textvariable=choice, state="readonly", width=48).pack(anchor="w", pady=8)
        meter = tk.StringVar(value=T("Starting..."))
        tk.Label(body, textvariable=meter, bg=GUI_CARD, fg=GUI_INK, font=("Consolas", 14)).pack(anchor="w", pady=6)
        state = {"previous": None, "running": True, "bssid": hidden[0]["bssid"]}

        def chosen(*_a):
            state["bssid"] = hidden[names.index(choice.get())]["bssid"]
            state["previous"] = None
        choice.trace_add("write", chosen)

        def tick():
            if not state["running"]:
                return

            def work():
                wn_rescan()
                time.sleep(3)
                signal = wn_signal_of(state["bssid"])
                self.root.after(0, lambda: show(signal))
            threading.Thread(target=work, daemon=True).start()

        def show(signal):
            if not state["running"]:
                return
            meter.set(T(wn_meter(signal, state["previous"])) if signal is None else wn_meter(signal, state["previous"]))
            if signal is not None:
                state["previous"] = signal
            win.after(500, tick)

        def close():
            state["running"] = False
            win.destroy()
        ttk.Button(body, text=T("Close"), command=close).pack(anchor="e", pady=(10, 0))
        win.protocol("WM_DELETE_WINDOW", close)
        self._centre(win)
        tick()

    def trackers(self):
        from tkinter import messagebox
        try:
            import bleak  # noqa: F401
        except ImportError:
            from .trackers import TK_BLEAK, tk_install_bleak
            if not messagebox.askyesno(
                    T("Bluetooth trackers"),
                    T("This check needs the Bluetooth library 'bleak', which this Python does not have yet (the "
                      "downloadable programs include it). Install it now? {package} from the official Python package "
                      "index, about 1 MB; nothing else is changed.", package=TK_BLEAK), parent=self.root):
                return
            self.status.set(T("Installing the Bluetooth library..."))
            notes = []

            def install():
                ok = tk_install_bleak(notes.append)
                self.root.after(0, lambda: done(ok))

            def done(ok):
                self.status.set(T(notes[-1]) if notes else "")
                if ok:
                    self.trackers()
                else:
                    messagebox.showinfo(T("Bluetooth trackers"), "\n".join(T(n) for n in notes[1:]) or
                                        T("It could not be installed."), parent=self.root)
            threading.Thread(target=install, daemon=True).start()
            return
        # A short start screen: what will happen, what to do, and three plain choices instead of a number box.
        tk, ttk = self.tk, self.ttk
        win = tk.Toplevel(self.root)
        win.title(T("Bluetooth trackers"))
        win.geometry("660x420")
        win.transient(self.root)
        choice = tk.IntVar(value=3)
        buttons = ttk.Frame(win, padding=(16, 0, 16, 16))
        buttons.pack(side="bottom", fill="x")
        body = ttk.Frame(win, padding=16)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text=T("Is a tracker following you?"), font=self.font_bold).pack(anchor="w")
        for line in (T("This listens for AirTags, SmartTags, Tiles and Find Hub tags near this computer. It only "
                       "receives: nothing is sent, and nothing leaves this computer."),
                     T("Keep the computer with you while it listens. Checking in a few different places - at home, "
                       "at work, on the move - gives the clearest answer: a tracker heard every time is travelling "
                       "with you.")):
            ttk.Label(body, text=line, wraplength=620, justify="left").pack(anchor="w", pady=(8, 0))
        if sys.platform == "darwin":
            ttk.Label(body, text=T("If macOS asks whether Zero Breach may use Bluetooth, choose Allow."),
                      wraplength=620, justify="left").pack(anchor="w", pady=(8, 0))
        ttk.Label(body, text=T("How long should it listen?"), font=self.font_bold).pack(anchor="w", pady=(16, 4))
        for minutes, label in ((1, T("1 minute - quick")), (3, T("3 minutes - recommended")),
                               (10, T("10 minutes - most thorough"))):
            ttk.Radiobutton(body, text=label, value=minutes, variable=choice).pack(anchor="w", pady=2)

        def start():
            minutes = choice.get()
            win.destroy()
            self._listen_for_trackers(minutes)
        ttk.Button(buttons, text=T("Start listening"), style="Accent.TButton", command=start).pack(side="left")
        ttk.Button(buttons, text=T("Cancel"), command=win.destroy).pack(side="left", padx=6)

    def _listen_for_trackers(self, minutes):
        """Listen in the background with a countdown, then show the answer first (coloured bar) and the details."""
        import asyncio
        import re as _re
        import time as _time
        from tkinter import messagebox
        from .trackers import _tk_history_io, _tk_listen, tk_headline, tk_plain_error, tk_render, tk_summarise
        heard = {"signals": 0}
        started = _time.time()

        def emit(message):
            found = _re.search(r"(\d+) tracker signals", message)
            if found:
                heard["signals"] = int(found.group(1))

        def listen():
            try:
                sightings = asyncio.run(_tk_listen(minutes, emit))
            except Exception as exc:  # noqa: BLE001 - Bluetooth off, no adapter, permission refused
                return {"error": tk_plain_error(exc)}
            summary = tk_summarise(sightings, minutes)
            _tk_history_io(summary)          # same tracker in 3+ separate checks over a day -> IMPORTANT
            return {"summary": summary}

        def tick():
            if not self.busy:
                return
            left = max(0, int(minutes * 60 - (_time.time() - started)))
            self.status.set(T("Listening for Bluetooth trackers: {time} left, {count} tracker signals heard so far. "
                              "Keep the computer with you.", time="%d:%02d" % divmod(left, 60),
                              count=heard["signals"]))
            self.root.after(1000, tick)

        def show(result):
            if "error" in result:
                messagebox.showinfo(T("Bluetooth trackers"), result["error"], parent=self.root)
                return
            summary = result["summary"]
            words, level = tk_headline(summary)
            self._text_window(T("Bluetooth trackers"), tk_render(summary, minutes), verdict=(T(words), level))
        self._in_background(T("Listening for Bluetooth trackers..."), listen, show)
        self.root.after(1000, tick)

    def household(self):
        from tkinter import filedialog, messagebox
        from .household import HH_HEADLINE, hh_combine, hh_html, hh_render
        # Say what to pick before the file picker opens: people do not know these are the saved .json reports.
        several = T("Cmd") if sys.platform == "darwin" else T("Ctrl")
        if not messagebox.askokcancel(
                T("Household report"),
                T("This puts every device's result on one page, worst first, and says what you have not "
                  "checked yet.\n\nNext, choose the reports you saved from each check: the .json files from "
                  "each computer and phone, the phone check page's \"Save JSON\", the home network check, and "
                  "any smaller check you saved (hidden Wi-Fi, live connections, startup items and others). "
                  "For a computer or phone checked in this window: Result tab > \"{send}\" > \"{short}\". "
                  "Hold {key} to choose several at once.", key=several,
                  send=T("Send this to someone who can help..."), short=T("Save the short summary...")),
                parent=self.root):
            return
        paths = filedialog.askopenfilenames(parent=self.root,
                                            title=T("Choose the saved reports (.json) - hold {key} to choose several",
                                                    key=several),
                                            filetypes=[(T("Reports"), "*.json"), (T("All files"), "*.*")])
        if not paths:
            return
        doc = hh_combine(list(paths))
        level = {"red": "dangerous", "amber": "worth-a-look", "grey": "worth-a-look"}.get(doc["overall"], "clean")
        self._text_window(T("Household report"), hh_render(doc),
                          (T("Save as a page..."), "household-report.html",
                           lambda path: open(path, "x", encoding="utf-8").write(hh_html(doc))),
                          verdict=(T(HH_HEADLINE[doc["overall"]]), level))

    def dns_log(self):
        from tkinter import filedialog, messagebox
        path = filedialog.askopenfilename(parent=self.root, title=T("Choose the DNS log"))
        if not path or self.busy:
            return
        problem = path_problem(os.path.abspath(path))
        if problem:
            messagebox.showerror(T("Choose the DNS log"), T("That file cannot be used: {problem}.", problem=problem),
                                 parent=self.root)
            return
        self.document = None
        for b in (self.view_button, self.save_button, self.share_button):
            b.state(["disabled"])
        self.result_title.configure(text=gui_dir(T("Checking...")), fg=GUI_INK)
        self._set_text("")
        self._begin_busy(T("Starting the check..."), stoppable=True)
        self.tabs.select(self.tab_check)          # the progress bar is on the Check tab; from More checks it was hidden
        threading.Thread(target=self._run_check, args=("default",),
                         kwargs={"argv_override": ["--dns-log", path, "--no-menu", "--no-banner"]},
                         daemon=True).start()

    def restart_as_admin(self):
        from tkinter import messagebox
        if not messagebox.askyesno(T("Restart as administrator"),
                                   T("Windows keeps some records of which programs have run (Prefetch, Amcache) "
                                     "readable only by administrators. Restart this program as administrator to "
                                     "include them? Windows will ask you to confirm."), parent=self.root):
            return
        message = gui_restart_elevated()
        if message:
            messagebox.showinfo(T("Restart as administrator"), T(message), parent=self.root)
        else:
            self.root.destroy()

    def _doors_label(self, document):
        doors = document.get("doors") or []
        n = sum(1 for d in doors if d.get("state") == "open")
        self.doors_button.configure(text=gui_dir(TN("{n} door to close...", "{n} doors to close...", n) if n
                                                 else T("Doors to close...")))
        self.doors_button.state(["!disabled"] if doors else ["disabled"])

    def show_doors(self):
        """Doors to close: each open door with why, how, an 'Open this setting' button, and 'Check again'."""
        if not self.document:
            return
        tk, ttk = self.tk, self.ttk
        win = tk.Toplevel(self.root)
        win.title(T("Doors to close"))
        win.geometry("820x600")
        status = tk.StringVar(value=T("Ways in that are left open. They are not signs of spyware; closing them "
                                      "makes spying harder."))
        bottom = ttk.Frame(win)
        bottom.pack(side="bottom", fill="x", pady=8, padx=12)
        ttk.Label(bottom, textvariable=status, wraplength=780).pack(side="top", anchor="w")
        buttons = ttk.Frame(bottom)
        buttons.pack(side="top", anchor="w", pady=(6, 0))
        body = ttk.Frame(win)
        body.pack(fill="both", expand=True)
        text = tk.Text(body, wrap="word", font=self.font_body, padx=12, pady=10)
        scroll = ttk.Scrollbar(body, command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)
        text.tag_configure("title", font=self.font_bold)
        text.tag_configure("muted", foreground=GUI_MUTED)

        def fill():
            text.configure(state="normal")
            text.delete("1.0", "end")
            doors = self.document.get("doors") or []
            open_ = [d for d in doors if d.get("state") == "open"]
            if not open_:
                text.insert("end", T("No open doors were found in what this check could read.") + "\n", "title")
            for d in open_:
                text.insert("end", "• " + gui_dir(T(d.get("title", ""))) + "\n", "title")
                if d.get("observed"):
                    text.insert("end", "   " + d["observed"] + "\n", "muted")
                for key in ("why", "fix"):
                    if d.get(key):
                        text.insert("end", "   " + gui_dir(T(d[key])) + "\n")
                if d.get("setting") and gui_setting_allowed(d["setting"]):
                    text.insert("end", "   ")
                    text.window_create("end", window=ttk.Button(
                        text, text=T("Open this setting"),
                        command=lambda uri=d["setting"]: status.set(T(gui_open_setting(uri)))))
                    text.insert("end", "\n")
                text.insert("end", "\n")
            closed = [d for d in doors if d.get("state") == "closed"]
            unknown = [d for d in doors if d.get("state") == "unknown"]
            if closed:
                text.insert("end", T("Already closed:") + " " + "; ".join(T(d["title"]) for d in closed) + "\n",
                            "muted")
            if unknown:
                text.insert("end", T("Could not check:") + " " + "; ".join(T(d["title"]) for d in unknown) + "\n",
                            "muted")
            from .report import ACCOUNT_CHECKLIST
            text.insert("end", "\n" + T("Accounts to check yourself (no tool can see these without signing in):")
                        + "\n", "title")
            for name, how in ACCOUNT_CHECKLIST:
                text.insert("end", "☐ " + gui_dir(T(name)) + ": ", "title")
                text.insert("end", gui_dir(T(how)) + "\n")
            text.configure(state="disabled")

        def again():
            status.set(T("Checking this computer's doors again..."))
            win.update_idletasks()
            try:
                fresh = gui_doors_recheck()
            except Exception as exc:  # noqa: BLE001 - shown, never fatal
                status.set(T("Could not check again: {why}", why=str(exc)[:160]))
                return
            keep = [d for d in self.document.get("doors") or [] if d.get("module") != "doors"]
            from_report = _report_doors_sort(keep + fresh)
            self.document["doors"] = from_report
            fill()
            self._doors_label(self.document)
            status.set(T("Checked again at {time}.", time=datetime.datetime.now().strftime("%H:%M")))

        ttk.Button(buttons, text=T("Check again"), command=again).pack(side="left")
        ttk.Button(buttons, text=T("Close"), command=win.destroy).pack(side="left", padx=6)
        fill()

    def make_backup(self):
        """Open Apple's backup app with the steps, then watch for the new backup and offer to check it."""
        from tkinter import messagebox
        from .iphonebackup import (IB_STEPS, IB_WARNINGS, ib_device_name, ib_new_finished, ib_open_backup_app,
                                   ib_snapshot)
        tk, ttk = self.tk, self.ttk
        win = tk.Toplevel(self.root)
        win.title(T("Make an iPhone backup"))
        win.geometry("780x480")
        baseline = ib_snapshot()
        from .resume import resume_save
        resume_save("iphone-backup", {"baseline": baseline})   # so a backup finished after closing is offered later
        found = []
        status = tk.StringVar(value=T("Waiting for a new backup to finish..."))
        # Buttons and status first, so the text can never push them out of the window.
        bottom = ttk.Frame(win)
        bottom.pack(side="bottom", fill="x", pady=8, padx=12)
        ttk.Label(bottom, textvariable=status, wraplength=740, font=self.font_bold).pack(side="top", anchor="w")
        buttons = ttk.Frame(bottom)
        buttons.pack(side="top", anchor="w", pady=(6, 0))
        steps = IB_STEPS.get(sys.platform)

        def use_backup():
            if not found:
                return
            from .resume import resume_clear
            resume_clear()
            self.phone_kind.set(self.phone_kinds[0])
            self.phone_folder.set(found[0])
            win.destroy()
            messagebox.showinfo(T("Backup ready to check"),
                                T("The new backup was chosen. If you made it encrypted, type its password in "
                                  "\"Backup password\", then press \"Start check\"."), parent=self.root)

        if steps:
            ttk.Button(buttons, text=T("Open Apple Devices") if sys.platform == "win32" else T("Open Finder"),
                       style="Accent.TButton",
                       command=lambda: status.set(T(ib_open_backup_app()))).pack(side="left")
        check_button = ttk.Button(buttons, text=T("Check this backup"), state="disabled", command=use_backup)
        check_button.pack(side="left", padx=6)
        ttk.Button(buttons, text=T("Close"), command=win.destroy).pack(side="left")
        body = ttk.Frame(win)
        body.pack(fill="both", expand=True)
        text = tk.Text(body, wrap="word", font=self.font_body, padx=12, pady=10)
        scroll = ttk.Scrollbar(body, command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)
        if steps:
            lines = [T("Apple's own app makes the backup; this program then checks it. Nothing is uploaded."), ""]
            lines += ["{}. {}".format(i, T(step)) for i, step in enumerate(steps, 1)]
        else:
            lines = [T("Linux has no Apple app for iPhone backups. In a terminal, run:"), "",
                     "    zero-breach-toolkit --make-iphone-backup FOLDER", "",
                     T("It asks first, downloads a verified backup helper, makes an encrypted backup into FOLDER "
                       "and then checks it. To check it again later from this window, choose that FOLDER's "
                       "backup with \"Choose...\".")]
        lines += ["", T("Before you start:")] + ["- " + T(w) for w in IB_WARNINGS]
        text.insert("end", "\n".join(lines))
        text.configure(state="disabled")

        def poll():
            try:
                if not win.winfo_exists():
                    return
            except tk.TclError:
                return
            new = ib_new_finished(baseline)
            if new:
                found[:] = new[:1]
                status.set(T("A new backup has finished: {name}. Press \"Check this backup\".",
                             name=ib_device_name(new[0]) or os.path.basename(new[0])))
                check_button.configure(state="normal")
                return
            win.after(3000, poll)
        win.after(3000, poll)

    def what_happened(self):
        """What happened? - each answer opens the check that answers it. "I know what I want" closes it."""
        from tkinter import messagebox
        from .intake import INTAKE, INTAKE_PARTNER_NOTE
        tk, ttk = self.tk, self.ttk
        win = tk.Toplevel(self.root)
        win.withdraw()                                  # shown once placed over the main window
        win.title(T("What happened?"))
        win.configure(bg=GUI_CARD)
        win.transient(self.root)
        justify, anchor = self._just()
        body = tk.Frame(win, bg=GUI_CARD, padx=18, pady=14)
        body.pack(fill="both", expand=True)
        top = tk.Frame(body, bg=GUI_CARD)
        top.pack(fill="x")
        tk.Label(top, text=gui_dir(T("What happened?")), bg=GUI_CARD, fg=GUI_INK, font=self.font_head,
                 anchor=anchor).pack(side="left")
        ttk.Button(top, text=T("I know what I want"), command=win.destroy).pack(side="right")
        tk.Label(body, text=gui_dir(T("Choose what fits best. Each choice opens the right check; nothing starts "
                                      "until you say so.")),
                 bg=GUI_CARD, fg=GUI_MUTED, font=self.font_body, anchor=anchor, justify=justify,
                 wraplength=560).pack(fill="x", pady=(4, 10))
        actions = {
            "file": self.check_file,
            "link": self.link_check,
            "warning": lambda: self._text_window(T("If you got a threat warning"), T(AC_THREAT_WARNING)),
            "taken": self.extraction_check,
            "partner": lambda: (messagebox.showinfo(T("Before you change anything"), T(INTAKE_PARTNER_NOTE),
                                                    parent=self.root), self._choose_check("phone"),
                                self.account_checklist()),
            "network": self.wifi_nearby,
            "checkup": lambda: self._choose_check("default"),
        }

        def go(key):
            win.destroy()
            actions[key]()

        for key, said, next_, _menu in INTAKE:
            row = tk.Frame(body, bg=GUI_CARD)
            row.pack(fill="x", pady=3)
            ttk.Button(row, text=T(said), command=lambda k=key: go(k)).pack(fill="x")
            tk.Label(row, text=gui_dir(T(next_)), bg=GUI_CARD, fg=GUI_MUTED, font=self.font_body, anchor=anchor,
                     justify=justify, wraplength=560).pack(fill="x")
        tk.Label(body, text=gui_dir(T("You can open this again with \"Not sure where to start?\".")), bg=GUI_CARD,
                 fg=GUI_MUTED, font=self.font_body, anchor=anchor).pack(fill="x", pady=(10, 0))
        self._centre(win)

    def _choose_check(self, kind):
        """Select a check on the first tab, ready for Start (nothing starts by itself)."""
        self.check.set(kind)
        self._phone_visibility()
        self.tabs.select(self.tab_check)

    def _welcome_back(self):
        """An iPhone backup started last time and never checked: offer it now if it has finished."""
        from tkinter import messagebox
        from .iphonebackup import ib_device_name, ib_new_finished
        from .resume import resume_clear, resume_load
        step = resume_load()
        if step.get("kind") != "iphone-backup" or self.busy:
            return
        baseline = step["data"].get("baseline")
        new = ib_new_finished(baseline) if isinstance(baseline, dict) else []
        if not new:
            if time.time() - step["started"] < 86400:
                self.status.set(T("Welcome back. The iPhone backup you started has not finished yet - keep the "
                                  "iPhone connected, then choose \"Make an iPhone backup\" again to check it."))
            return
        name = ib_device_name(new[0]) or os.path.basename(new[0])
        if messagebox.askyesno(T("Welcome back"), T("The iPhone backup you were making has finished: {name}. "
                                                   "Check it now?", name=name), parent=self.root):
            self.phone_kind.set(self.phone_kinds[0])
            self.phone_folder.set(new[0])
            self.check.set("phone")
            self._phone_visibility()
            self.tabs.select(self.tab_check)
            self.status.set(T("The backup was chosen. If you made it encrypted, type its password in "
                              "\"Backup password\", then press \"Start check\"."))
        resume_clear()

    def show_guide(self, platform):
        tk, ttk = self.tk, self.ttk
        win = tk.Toplevel(self.root)
        win.title(T("Checking an iPhone") if platform == "ios" else T("Checking an Android phone"))
        win.geometry("760x560")
        # Buttons first, so the text can never push the Close button out of the window.
        ttk.Button(win, text=T("Close"), command=win.destroy).pack(side="bottom", pady=8)
        body = ttk.Frame(win)
        body.pack(fill="both", expand=True)
        text = tk.Text(body, wrap="word", font=self.font_body, padx=12, pady=10)
        scroll = ttk.Scrollbar(body, command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)
        win.update_idletasks()
        self._fill(text, gui_guide_text(platform))
        text.configure(state="disabled")

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
        ttk.Button(controls, text=T("Save this list..."), command=self.save_connections).pack(side="left",
                                                                                            padx=(6, 0))
        ttk.Checkbutton(controls, text=T("Only connections to the internet"), variable=self.only_internet,
                        style="Card.TCheckbutton", command=self.refresh_connections).pack(side="left", padx=12)
        ttk.Checkbutton(controls, text=T("Refresh every 5 seconds"), variable=self.auto_refresh,
                        style="Card.TCheckbutton").pack(side="left")
        ttk.Label(top, textvariable=self.conn_status, style="Card.TLabel").pack(anchor="w", pady=(8, 0))
        table = ttk.Frame(self.tab_net, style="Card.TFrame", padding=8)
        table.pack(fill="both", expand=True, padx=16, pady=12)
        columns = ("program", "remote", "who", "port", "state", "match")
        self.tree = ttk.Treeview(table, columns=columns, show="headings")
        for name, title, width in (("program", "Program", 220), ("remote", "Remote address", 200),
                                   ("who", "Who runs it", 170), ("port", "Port", 60), ("state", "State", 110),
                                   ("match", "Known spyware address?", 200)):
            self.tree.heading(name, text=T(title))
            self.tree.column(name, width=width, anchor="w")
        self.tree.tag_configure("hit", background="#fde2e2", foreground=GUI_RED)
        scroll = ttk.Scrollbar(table, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        self.tree.pack(fill="both", expand=True)
        self.net_rows = {}
        menu = tk.Menu(self.tree, tearoff=0)
        menu.add_command(label=T("Details..."), command=self.connection_details)
        menu.add_command(label=T("Look up who owns this address..."), command=self.connection_owner)
        menu.add_command(label=T("Copy address"), command=self.connection_copy)

        def popup(event):
            item = self.tree.identify_row(event.y)
            if item:
                self.tree.selection_set(item)
                menu.tk_popup(event.x_root, event.y_root)
        for seq in ("<Button-3>", "<Button-2>" if sys.platform == "darwin" else "<Control-Button-1>"):
            self.tree.bind(seq, popup)
        self.tree.bind("<Double-1>", lambda e: self.tree.identify_row(e.y) and self.connection_details())
        ttk.Label(top, text=T("Right-click (or double-click) a connection for details."),
                  style="Muted.TLabel").pack(anchor="w")
        self.net_visible = False

    def _layout_help(self):
        tk = self.tk
        card = self.ttk.Frame(self.tab_help, style="Card.TFrame", padding=16)
        card.pack(fill="both", expand=True, padx=16, pady=12)
        # Japanese and Chinese have no spaces, so wrapping by word moved whole
        # sentences to the next line and left their bullets alone.
        text = tk.Text(card, wrap="char" if i18n_lang() in ("ja", "zh") else "word", relief="flat",
                       bg=GUI_CARD, fg=GUI_INK, font=self.font_body, padx=4, pady=4, height=24)
        self._fill(text, gui_help_text())
        text.configure(state="disabled")
        scroll = self.ttk.Scrollbar(card, command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        scroll.pack(side="right", fill="y")
        text.pack(side="left", fill="both", expand=True)

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
                    self._lists_note_visibility()
        except queue.Empty:
            pass
        if self.busy:
            # One bar for the whole check, moved by the clock every tenth of a second rather than only when a
            # step reports: it no longer jumps between a percentage and a bouncing bar, and a busy scan cannot
            # make it stutter (team test: "the bar is a bit choppy").
            smooth = gui_progress_smooth(self.progress_state)
            if smooth is not None:
                if str(self.progress.cget("mode")) != "determinate":
                    self.progress.stop()
                    self.progress.configure(mode="determinate")
                self.progress.configure(value=smooth)
            elif str(self.progress.cget("mode")) != "indeterminate":
                self.progress.configure(mode="indeterminate", value=0)
                self.progress.start(12)
        if self.busy and self.started_at is not None:
            minutes = int((datetime.datetime.now() - self.started_at).total_seconds() // 60)
            line = (TN("Running for {n} minute.", "Running for {n} minutes.", minutes)
                    if minutes else T("Running for less than a minute."))
            since = self.progress_state.get("since")
            if since is not None and not self.progress_state.get("measured") and \
                    time.monotonic() - since > GUI_SLOW_STEP_SECONDS:
                line += " " + T("This step can take a while on a computer with many files - it is still working.")
            self.elapsed.set(line)
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
            # Ask whether the typed folder is safe to look at BEFORE looking at it:
            # the box takes pasted text, and asking Windows whether a network path
            # exists contacts that server.
            problem = path_problem(os.path.abspath(folder)) if folder else ""
            if problem:
                messagebox.showerror(T("Choose the phone folder"),
                                     T("That folder cannot be used: {problem}. Choose a folder on this "
                                       "computer's own drive.", problem=problem), parent=self.root)
                return
            if not folder or not os.path.isdir(folder):
                messagebox.showerror(T("Choose the phone folder"), T("Choose the folder that holds the iPhone "
                                                                     "backup or the Android collection first."),
                                     parent=self.root)
                return
        self.document = None
        for b in (self.view_button, self.save_button, self.share_button):
            b.state(["disabled"])
        self.result_title.configure(text=gui_dir(T("Checking...")), fg=GUI_INK)
        expected = GUI_DURATIONS.get(self.check.get(), "This can take a while.")
        self._set_label(self.result_note, T(expected) + " " + T("You can keep using the computer."), 880)
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

    def _run_check(self, scan_type, phone=None, training=None, argv_override=None):
        lowered = gui_background_priority(True)
        try:
            password = ""
            if argv_override:
                argv = list(argv_override)
            elif phone:
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
                              backup_password=password, emit=emit,
                              dns_logs=tuple(os.path.abspath(p) for p in (getattr(args, "dns_log", None) or [])))
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
            if lowered:
                gui_background_priority(False)

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
        self._doors_label(document)
        if gui_admin_would_help(document):
            self.admin_button.pack(side="left", padx=(6, 0))
        else:
            self.admin_button.pack_forget()
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
        """The full report in a window of its own: in the Result tab's box it was out of sight on a small screen
        (the box is what is left under the advice, one line on a 1000x680 window), so the button seemed to do
        nothing."""
        if not self.document:
            return
        document = self.document
        # Off the window thread: a real result can take a while to write out, and the window froze meanwhile
        # (hourglass, nothing happening).
        self._in_background(T("Preparing the full report..."),
                            lambda: _defang_report(render_human(document), document),
                            lambda text: self._text_window(T("Full report"), text))

    def _ask_path(self, title, name, extension):
        from tkinter import filedialog
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        return filedialog.asksaveasfilename(
            parent=self.root, title=title, defaultextension=extension,
            filetypes=gui_save_types(extension),
            initialfile="{}-{}{}".format(name, stamp, extension), initialdir=gui_save_folder())

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
            shown = T("Saved: {path}", path=os.path.normpath(path))
            self.status.set(shown)
            self.saved_note.configure(text=shown)
        except OSError as exc:
            self.status.set(T("Not saved."))
            messagebox.showerror(T("Not saved"), gui_save_failure(exc), parent=self.root)
        except (ValueError, TypeError) as exc:
            messagebox.showerror(T("Not saved"), str(exc), parent=self.root)

    def save_report(self):
        self._save(lambda path: workflow_write_text(gui_report_text(self.document), path),
                   T("Save the report"), "zero-breach-report", ".txt")

    def send_for_help(self):
        """The two ways to share a result, what each holds, and who can help - in one place."""
        tk, ttk = self.tk, self.ttk
        win = tk.Toplevel(self.root)
        win.withdraw()
        win.title(T("Send this to someone who can help"))
        win.configure(bg=GUI_CARD)
        win.transient(self.root)
        justify, anchor = self._just()
        body = tk.Frame(win, bg=GUI_CARD, padx=18, pady=14)
        body.pack(fill="both", expand=True)

        def para(text, font=None, fg=GUI_INK, pad=(0, 6)):
            tk.Label(body, text=gui_dir(text), bg=GUI_CARD, fg=fg, font=font or self.font_body, anchor=anchor,
                     justify=justify, wraplength=560).pack(fill="x", pady=pad)

        para(T("Nothing is sent automatically. You choose what to share, and who gets it."), self.font_bold)
        para(T("1. The short summary"), self.font_bold, pad=(8, 2))
        para(T("What was found and what could not be checked. No personal files, messages or photos."), fg=GUI_MUTED)
        ttk.Button(body, text=T("Save the short summary..."),
                   command=lambda: (win.destroy(), self.save_summary())).pack(anchor=anchor, pady=(0, 6))
        para(T("2. A locked package for an expert"), self.font_bold, pad=(8, 2))
        para(T("The full report and any files you choose to add, locked so that only the person you send it to "
               "can open it."), fg=GUI_MUTED)
        ttk.Button(body, text=T("Make a locked package..."),
                   command=lambda: (win.destroy(), self.helper_package())).pack(anchor=anchor, pady=(0, 6))
        para(T("Who can help"), self.font_bold, pad=(10, 2))
        for name, who, url in GUI_HELPERS:
            row = tk.Frame(body, bg=GUI_CARD)
            row.pack(fill="x", pady=(2, 2))
            tk.Label(row, text=gui_dir(T(name)), bg=GUI_CARD, fg=GUI_INK, font=self.font_bold, anchor=anchor,
                     justify=justify).pack(fill="x")
            tk.Label(row, text=gui_dir(T(who)), bg=GUI_CARD, fg=GUI_MUTED, font=self.font_body, anchor=anchor,
                     justify=justify, wraplength=560).pack(fill="x")
            line = tk.Frame(row, bg=GUI_CARD)
            line.pack(fill="x")
            tk.Label(line, text=url, bg=GUI_CARD, fg=GUI_INK, font=self.font_body).pack(side="left")
            ttk.Button(line, text=T("Copy"), command=lambda u=url: self._copy(u)).pack(side="left", padx=8)
        ttk.Button(body, text=T("Close"), command=win.destroy).pack(anchor="e", pady=(12, 0))
        self._centre(win)

    def _centre(self, win):
        """Place a small window over the middle of the main one, then show it."""
        win.update_idletasks()
        w, h = win.winfo_reqwidth(), win.winfo_reqheight()
        x = self.root.winfo_rootx() + max(0, (self.root.winfo_width() - w) // 2)
        y = self.root.winfo_rooty() + max(0, (self.root.winfo_height() - h) // 3)
        win.geometry("+{}+{}".format(x, y))
        win.deiconify()
        win.lift()

    def _copy(self, text):
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.status.set(T("Copied: {url}", url=text))

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
        details = self.update_details = []

        class Lines:
            def write(self, text):
                for line in text.splitlines():
                    if line.strip():
                        # The window shows plain words; the exact line (hashes,
                        # counts, error text) is kept in `details`.
                        details.append(line.strip())
                        events.put(("status", gui_update_line(line.strip())))
                return len(text)

            def flush(self):
                pass
        try:
            with contextlib.redirect_stdout(Lines()), contextlib.redirect_stderr(Lines()):
                code = self.hooks["update"]()
            from .feeds import LAST_VERSION_NOTICE
            note = LAST_VERSION_NOTICE
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

    def _selected_connection(self):
        sel = self.tree.selection()
        return self.net_rows.get(sel[0]) if sel else None

    def connection_details(self):
        row = self._selected_connection()
        if row:
            self._text_window(T("Connection details"), gui_connection_text(row))

    def connection_copy(self):
        row = self._selected_connection()
        if row:
            self._copy(row.get("remote", ""))

    def connection_owner(self):
        """Ask the internet registry who owns the address - only after saying exactly what is sent."""
        from tkinter import messagebox
        from .ncinfo import nc_kind, nc_rdap
        row = self._selected_connection()
        if not row:
            return
        address = row.get("remote", "")
        if nc_kind(address) != "the internet":
            messagebox.showinfo(T("Who owns this address"), T("This address is not on the internet, so there is "
                                                             "nothing to look up: it is {kind}.",
                                                             kind=T(nc_kind(address))), parent=self.root)
            return
        if not messagebox.askyesno(T("Who owns this address"),
                                   T("This asks the internet registry (rdap.org) who owns {address}. Only the "
                                     "address is sent - nothing about you or this computer. Continue?",
                                     address=address), parent=self.root):
            return
        self.conn_status.set(T("Asking the internet registry..."))

        def ask():
            try:
                answer = nc_rdap(address) or T("the registry does not name an owner")
            except Exception as exc:  # noqa: BLE001 - offline, blocked, a slow registry
                answer = T("the registry could not be reached ({error})", error=type(exc).__name__)
            self.root.after(0, lambda: (self.conn_status.set(""), messagebox.showinfo(
                T("Who owns this address"), "{}\n\n{}".format(address, answer), parent=self.root)))
        threading.Thread(target=ask, daemon=True).start()

    def save_connections(self):
        import json
        from tkinter import filedialog
        rows = list(getattr(self, "net_rows", {}).values())
        if not rows:
            self.conn_status.set(T("Nothing to save yet: press Refresh now first."))
            return
        path = filedialog.asksaveasfilename(parent=self.root, initialfile="live-connections.json",
                                            defaultextension=".json", title=T("Save this list..."))
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(gui_connections_saved(rows), fh, indent=2, ensure_ascii=False)
            self.conn_status.set(T("Saved: {path}", path=path))
        except OSError as exc:
            self.conn_status.set(T("Not saved: {why}", why=str(exc)[:120]))

    def refresh_connections(self):
        rows, problem = nc_list()
        iocs = self._indicators()
        matches = nc_match(rows, iocs) if iocs is not None else []
        shown = [r for r in rows if r.get("remote_public") or not self.only_internet.get()]
        shown.sort(key=lambda r: (r.get("match") is None, os.path.basename(r.get("program") or "~")))
        from .ncinfo import nc_who
        self.tree.delete(*self.tree.get_children())
        self.net_rows = {}
        # One row per program, address and port: a browser's six connections to the same server are one line
        # ("6 connections"), so the list shows what is talking to what instead of repeating it.
        groups = {}
        for r in shown:
            key = (r.get("pid"), r.get("program"), r.get("remote"), r.get("remote_port"))
            groups.setdefault(key, []).append(r)
        for rows in groups.values():
            r = dict(rows[0], count=len(rows), states=sorted({x.get("state", "") for x in rows}))
            program = os.path.basename(r.get("program") or "") or (
                T("unknown (pid {pid})", pid=r["pid"]) if r.get("pid") else T("unknown"))
            if len(rows) > 1:
                program = T("{program} ({n} connections)", program=program, n=len(rows))
            match = r.get("match")
            label = T("YES: {name} ({tier})", name=match.family or match.source, tier=match.tier) if match else ""
            item = self.tree.insert("", "end", values=(program, r["remote"], T(nc_who(r["remote"])) if
                                                       nc_who(r["remote"]) else "", r["remote_port"],
                                                       ", ".join(s for s in r["states"] if s), label),
                                    tags=("hit",) if match else ())
            self.net_rows[item] = r
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


def gui_connections_saved(rows) -> dict:
    """The live-connections list as a saved result (also read by the household report)."""
    import datetime
    from .ncinfo import nc_who
    hits = [r for r in rows if r.get("match")]
    return {"tool": "zero-breach-toolkit live connections",
            "made": datetime.datetime.now().astimezone().replace(microsecond=0).isoformat(),
            "level": "known-threat" if hits else "nothing-known",
            "summary": "{} connections listed, {} to an address on a spyware list".format(len(rows), len(hits)),
            "findings": ["{} -> {} ({})".format(os.path.basename(r.get("program") or "") or "unknown", r["remote"],
                                                r["match"].family or r["match"].source) for r in hits],
            "connections": [{"program": r.get("program") or "", "address": r.get("remote"),
                             "port": r.get("remote_port"), "who": nc_who(r.get("remote") or ""),
                             "count": r.get("count", 1)} for r in rows]}


def gui_connection_text(row):
    """The Details window's text for one connection."""
    from .ncinfo import nc_details
    lines = []
    for label, text in nc_details(row):
        lines.append("{}: {}".format(T(label), T(text) if "{}" not in text else text))
    match = row.get("match")
    if match:
        lines.append("")
        lines.append(T("This address is on a spyware list ({name}). Do not close anything; save a report and get "
                       "expert help.", name=match.family or match.source))
    return "\n".join(lines)


def gui_help_text():
    """The Help tab, put together from sentences that quote the window's own
    words (its buttons, its result headlines) as they are written in the chosen
    language. One translated block named the buttons in whatever words the
    translation happened to use, often the English ones."""
    bullet = "• "
    names = {"phone": T("A phone"), "find": T("Find iPhone backups"), "practise": T("Practise"),
             "none": T("No known spyware traces found"), "refs": T("Only references found"),
             "hit": T("Something needs a closer look"),
             "partial": T("Nothing found in what could be checked"),
             "withdrawn": T("Only a withdrawn indicator matched")}
    sections = [
        (T("What this does"), [
            T("Zero Breach looks for traces that known mercenary spyware (Pegasus, Predator, Candiru, "
              "Paragon Graphite and others) leaves on a device: records in browsers and apps, startup "
              "items, and fingerprints of program files. It only reads; it never changes, deletes or "
              "uploads anything.")]),
        (T("Reading the result"), [
            bullet + T("\"{none}\" means nothing matched and every check ran. It is not a "
                       "guarantee: new spyware is unknown until researchers publish it.", **names),
            bullet + T("\"{partial}\" means nothing matched in what could be checked, but some "
                       "checks could not run. They are listed; what they cover is not cleared.",
                       **names),
            bullet + T("\"{withdrawn}\" means the match is to an indicator its publisher has "
                       "withdrawn. That is not an actionable finding on its own, and it does not clear "
                       "the device.", **names),
            bullet + T("\"{refs}\" means an indicator name appeared in saved content, for example an "
                       "article about Pegasus that you read. That alone is not a sign of infection.",
                       **names),
            bullet + T("\"{hit}\" means a trace matched. Do not reset or wipe the device: that destroys "
                       "the evidence. Save the report and contact one of the helplines below.",
                       **names)]),
        (T("Checking a phone"), [
            T("Choose \"{phone}\", then the folder of an iPhone backup (Finder or Apple Devices / "
              "iTunes makes one; \"{find}\" looks in the usual places) or an Android collection. The "
              "guides under the folder box explain how to make either. An encrypted iPhone backup "
              "needs its password, which is used for that check only.", **names)]),
        (T("Practise"), [
            T("\"{practise}\" checks a made-up phone with made-up spyware, so you can learn to read a "
              "report (spyware found, things worth a look, or nothing found). Nothing real is read, "
              "and every result is marked as a training example.", **names)]),
        (T("Live connections"), [
            T("Shows what is connected right now and marks addresses on the spyware lists. Servers "
              "change hands over time, so a match is a reason to look closer, not proof."),
            T("The \"Who runs it\" column names the company behind an address (Google, Microsoft, Telegram and "
              "others) from a list built into the program, so nothing is looked up. Right-click or double-click a "
              "row for its details: the program's file, when it started, and what started it. \"{save}\" keeps the "
              "list for the household report.", save=T("Save this list..."))]),
        (T("More checks"), [
            T("The More checks tab has smaller tools, each with a line saying what it does. In short:"),
            bullet + T("\"{a}\", \"{b}\", \"{c}\" and \"{d}\": something you were sent. Nothing is opened, run or "
                       "followed. A file check can also be looked up online, but only after you say yes.",
                       a=T("Check a suspicious file..."), b=T("Check a link or message..."),
                       c=T("Check a suspicious email..."), d=T("Check a QR code...")),
            bullet + T("\"{a}\": who is on your Wi-Fi and which doors their devices leave open.",
                       a=T("Check my home network...")),
            bullet + T("\"{a}\": networks that hide their name, and what each probably is. On Windows and Linux "
                       "it can then follow one network's signal while you walk, to find the device.",
                       a=T("Hidden Wi-Fi networks nearby...")),
            bullet + T("\"{a}\": AirTags and other tags near you. If a part it needs is missing, it offers to add "
                       "it.", a=T("Look for Bluetooth trackers...")),
            bullet + T("\"{a}\" and \"{b}\": what a phone or a whole home talked to, and which companies run "
                       "those names.", a=T("Check a network recording..."),
                       b=T("Check a router or Pi-hole DNS log...")),
            bullet + T("\"{a}\": the single best step first (a physical security key), then where to look in "
                       "each account. Your answers are kept until you finish.", a=T("Check my online accounts...")),
            bullet + T("\"{a}\" and \"{b}\": what starts with the computer, with a plain line for each, and "
                       "Windows' own records of what ran.", a=T("What starts automatically..."),
                       b=T("Look through Windows' own records...")),
            bullet + T("\"{a}\": switches off risky settings one at a time, after asking, and keeps a way back.",
                       a=T("Close the doors found open...")),
            bullet + T("\"{a}\": the saved results of every device and check on one page, worst first.",
                       a=T("Household report...")),
            T("Not sure which to use? On the Check tab, \"{a}\" asks what happened and points you to the right "
              "check.", a=T("Not sure where to start?"))]),
        (T("Getting help"), [
            T("If you might be targeted (for example as a journalist, activist or lawyer), you can ask "
              "for help whatever this check says:"),
            bullet + T("Access Now Digital Security Helpline: {url}", url=HELPLINE),
            bullet + T("Amnesty International Security Lab: {url}", url="https://securitylab.amnesty.org/"),
            bullet + T("The Citizen Lab: {url}", url="https://citizenlab.ca/")]),
    ]
    parts = [heading + "\n" + "\n".join(lines) for heading, lines in sections]
    parts.append(T("More: {url}", url="https://github.com/interplains/Zero-Breach-Toolkit#readme"))
    return "\n\n".join(parts) + "\n"


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
    if gui_relaunch_without_console():
        return 0
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
