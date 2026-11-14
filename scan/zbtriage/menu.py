"""The start menu shown to a person who opens the tool without choosing a check.

Someone who double-clicks the tool should be asked what to check, not dropped
straight into the standard computer scan with no visible way to choose a full
scan, a USB stick or a phone. Scripts and AI assistants are unaffected: the menu
appears only when both stdin and stderr are a real terminal and nothing on the
command line already says what to check, and --no-menu turns it off. It writes
to stderr, so a report redirected to a file (the Windows launcher does this)
still contains only the report.

The menu only sets the options a command line would. It never scans or reads
evidence itself. The two steps that reach the internet both ask first: the
indicator update (this tool downloads) and the ad-blocking test (the person's
own browser opens a web page; this tool sends nothing).

Layout. Entries live in sections, numbered in the order shown:
  Check for spyware traces   computer (standard / full), browsers only,
                             drive-folder-file, phone, was a phone copied
  Check something you received   a link or message, an email, a QR code, a file's
                             fingerprint
  Around you                 home network, Bluetooth trackers, a phone's network
                             recording, a router / Pi-hole DNS log
  Look closer                read-only views a person can investigate themselves:
                             what starts automatically, Windows' own records
  Put it together            household report, send evidence to a helper
  Help and settings          helplines, phone preparation, look-up keys, indicator update,
                             training
New features add one _MnItem; nothing else here changes. An item that cannot
work in the current window (for example a step whose prompts would be hidden)
is left out rather than shown and then failing.
"""

import os
import sys

# Options that already say what to check. If any is present the person (or a
# script) has chosen, so the menu stays out of the way.
_MN_CHOSEN = ("--scan-type", "--wifi-nearby", "--target", "--phone", "--collect-android", "--update",
              "--quick", "--deep", "--patterns", "--pattern-path", "--backup-password",
              "--extended-windows", "--ios-input", "--no-menu", "--preview", "--describe", "--phone-guide",
              "--training")

_MN_SECTIONS = ("Check for spyware traces", "Check something you received", "Around you", "Look closer",
                "Put it together", "Help and settings")

_MN_HELP = """
  If you think you are being targeted right now, contact a helpline first.
  You do not need to run this tool before asking for help.

    Access Now Digital Security Helpline - free, 24/7, many languages
      https://www.accessnow.org/help/
    Amnesty International Security Lab - for journalists, activists and
    human-rights defenders
      https://securitylab.amnesty.org/get-help/

  If a check finds something: do not panic, do not visit the address it names,
  and keep the report. Send the sharing summary first; it leaves out your file
  paths, messages and the indicator values."""


class _MnItem(object):
    """One menu entry. `run(session)` returns "scan", "quit" or "back"."""

    def __init__(self, section, label, hint, run, available=None):
        self.section, self.label, self.hint, self.run = section, label, hint, run
        self.available = available or (lambda session: True)


class _MnSession(object):
    def __init__(self, args, update, stdin, stderr, stdout_visible):
        self.args, self.update = args, update
        self.stdin, self.stderr = stdin, stderr
        # Whether ordinary output reaches the person. The Windows launcher sends
        # it to the report file, so steps that prompt on stdout must be hidden.
        self.stdout_visible = stdout_visible

    def say(self, text=""):
        from .report import _report_console, _safe_text
        _report_console("\n".join(_safe_text(line) for line in text.split("\n")), self.stderr)

    def ask(self, prompt):
        """One line from the person; None at end of input (closed window, Ctrl+Z)."""
        self.stderr.write(prompt)
        self.stderr.flush()
        line = self.stdin.readline()
        return line.strip() if line else None

    def yes(self, prompt):
        answer = self.ask(prompt)
        return bool(answer) and answer.lower() in ("y", "yes")

    def pause(self):
        self.ask("\n  Press Enter to go back to the menu...")

    def local_path(self, prompt, allow_blank=False, want_dir=False):
        """Ask until the person gives an existing local path.

        Returns the absolute path, "" when blank is allowed and given, or None
        to go back to the menu."""
        from .localpaths import path_problem
        while True:
            raw = self.ask(prompt)
            if raw is None:
                return None
            path = _mn_clean_path(raw)
            if not path:
                if allow_blank:
                    return ""
                self.say("  Nothing entered. Type 0 to go back to the menu.")
                continue
            if path == "0":
                return None
            full = os.path.abspath(path)
            problem = path_problem(full)
            if problem:
                # Opening a network share makes Windows send this account's
                # credentials to another computer, so only local paths are used.
                self.say("  That path cannot be used: {}. Use a drive or folder on this "
                         "computer.".format(problem))
                continue
            if not os.path.exists(full):
                self.say("  Nothing found at that path. Check it and try again, or type 0 "
                         "to go back.")
                continue
            if want_dir and not os.path.isdir(full):
                self.say("  That is a file, not a folder. If it is a .zip from AndroidQF, "
                         "unzip it first, then drag in the unzipped folder.")
                continue
            return full


def _mn_clean_path(text):
    """A path typed or dragged into the window. Explorer wraps paths that contain
    spaces in double quotes when they are dragged in; macOS Terminal escapes
    spaces with a backslash."""
    text = (text or "").strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        return text[1:-1].strip()
    if os.sep == "/" and "\\ " in text:
        text = text.replace("\\ ", " ")
    return text


# ----------------------------------------------------------------- the checks

def _mn_standard(s):
    s.args.scan_type = "default"
    return "scan"


def _mn_full(s):
    s.args.scan_type = "full"
    return "scan"


# The ad-blocking test only works inside a browser: it measures what that
# browser lets through. The mirror is for when the main domain is unreachable.
_MN_ADBLOCK_URL = "https://archivegenocide.com/scan/"
_MN_ADBLOCK_MIRROR = "https://archivegenocide.org/scan/index.html"


def _mn_browser(s):
    s.say("\n  1  Check this computer's browsers for the ad campaign and other"
          "\n     spyware traces (offline: history, cookies, caches)"
          "\n  2  Test whether your browser blocks ads (opens a web page)")
    which = s.ask("  Choose, or press Enter to go back: ")
    if which == "1":
        s.say("\n  Close your browsers first if you can. An open browser can keep part"
              "\n  of its history locked, and anything locked is listed as not checked.")
        s.args.scan_type = "browser"
        return "scan"
    if which == "2":
        _mn_adblock(s)
    return "back"


def _mn_adblock(s):
    s.say("\n  This opens a test page from archivegenocide in your web browser. It"
          "\n  checks, inside that browser, whether ads and ad trackers are blocked,"
          "\n  and shows how to turn blocking on. Your browser goes online for this;"
          "\n  this tool does not, and it sends nothing about this computer."
          "\n  It tests the browser it opens in. For another browser, paste the"
          "\n  address into that one."
          "\n\n    " + _MN_ADBLOCK_URL +
          "\n    if that does not load: " + _MN_ADBLOCK_MIRROR)
    if s.yes("  Open it in your default browser now? [y/N]: "):
        if not _mn_open_page(_MN_ADBLOCK_URL):
            s.say("  No browser could be opened from here. Copy the address above into one.")
    s.pause()


def _mn_open_page(url):
    """Hand the address to the desktop's browser. Never fetches anything itself."""
    # Without a desktop session, Python's webbrowser falls back to a text browser
    # inside this terminal, which would take over the window mid-menu.
    if sys.platform.startswith("linux") and not (os.environ.get("DISPLAY")
                                                 or os.environ.get("WAYLAND_DISPLAY")):
        return False
    try:
        import webbrowser
        return bool(webbrowser.open(url, new=2))
    except Exception:
        return False


def _mn_targeted(s):
    s.say("\n  Drag the drive, folder or file into this window (or type its path),"
          "\n  then press Enter. Type 0 to go back.")
    first = s.local_path("  > ")
    if first is None:
        return "back"
    targets = [first]
    while True:
        more = s.local_path("  Add another, or press Enter to start: ", allow_blank=True)
        if more is None:
            return "back"
        if more == "":
            break
        if more not in targets:
            targets.append(more)
    s.args.scan_type = "targeted"
    s.args.target = targets
    if getattr(s.args, "patterns", False) and not getattr(s.args, "pattern_path", None):
        s.args.pattern_path = list(targets)
    return "scan"


def _mn_phone(s):
    choices = ["  1  I already have a collection folder or an iPhone backup"]
    if s.stdout_visible:
        choices.append("  2  Collect from an Android phone connected by USB now (guided)")
    choices.extend(["  3  Check an already acquired iPhone filesystem folder",
                    "  4  Check an already acquired iPhone sysdiagnose (folder or TAR/TAR.GZ)"])
    s.say("\n" + "\n".join(choices))
    which = s.ask("  Choose, or press Enter to go back: ")
    if which == "2" and s.stdout_visible:
        return _mn_collect(s)
    if which in ("3", "4"):
        s.say("  Drag the local evidence path here, or type it. Type 0 to go back.")
        evidence = s.local_path("  > ", want_dir=which == "3")
        if evidence is None:
            return "back"
        s.args.phone = evidence
        s.args.ios_input = "filesystem" if which == "3" else "sysdiagnose"
        return "scan"
    if which != "1":
        return "back"
    s.say("\n  Drag the folder into this window (or type its path), then press Enter."
          "\n  Android: the unzipped AndroidQF folder with packages.json in it."
          "\n  iPhone: the backup folder with Manifest.plist in it."
          "\n  Type 0 to go back. Not sure how to make one? See 'How to prepare a phone'.")
    folder = s.local_path("  > ", want_dir=True)
    if folder is None:
        return "back"
    iphone = _mn_local_marker(folder, "Manifest.plist")
    android = _mn_local_marker(folder, "packages.json")
    if not (iphone or android):
        s.say("  This folder has neither packages.json nor Manifest.plist, so it does not"
              "\n  look like an AndroidQF collection or an iPhone backup.")
        if not s.yes("  Check it anyway? [y/N]: "):
            return "back"
    s.args.phone = folder
    if iphone:
        s.args.backup_password = s.yes(
            "  Is this iPhone backup password-protected (encrypted)? [y/N]: ")
    elif _mn_local_marker(folder, "backup.ab"):
        s.args.backup_password = s.yes(
            "  Did you set a password for the message backup (backup.ab)? [y/N]: ")
    return "scan"


def _mn_local_marker(folder, name):
    from .localpaths import path_problem
    path = os.path.join(folder, name)
    return not path_problem(path) and os.path.isfile(path)


def _mn_collect(s):
    s.say("\n  This downloads the official AndroidQF collector, checks it against its"
          "\n  published fingerprint, and runs it to copy records from the phone. It needs"
          "\n  the internet for the download, USB debugging on the phone, and the phone"
          "\n  owner's consent. The collected records are private: keep the folder safe."
          "\n\n  Press Enter to save the collection on your Desktop, or drag in another"
          "\n  folder (or type its path). Type 0 to go back.")
    folder = s.local_path("  > ", allow_blank=True, want_dir=True)
    if folder is None:
        return "back"
    if folder == "":
        home = os.path.expanduser("~")
        desktop = os.path.join(home, "Desktop")
        folder = desktop if os.path.isdir(desktop) else home
    s.args.collect_android = os.path.join(folder, "zero-breach-android-collection")
    s.say("  The collection will be saved in " + s.args.collect_android)
    return "scan"


# ------------------------------------------------------------ help and settings

def _mn_help(s):
    s.say(_MN_HELP)
    s.pause()
    return "back"


def _mn_guide(s):
    from .scope import scope_guide
    which = s.ask("\n  1  Android    2  iPhone    (Enter to go back): ")
    if which in ("1", "2"):
        s.say()
        s.say(scope_guide("android" if which == "1" else "ios"))
        s.pause()
    return "back"


def _mn_training(s):
    s.say("\n  Practise reading a report on a made-up phone. Nothing on this computer"
          "\n  or any real phone is read, and the example is deleted afterwards. Useful"
          "\n  for trainers and for anyone who wants to see a result before a real check."
          "\n"
          "\n  1  A phone with spyware traces (findings and their evidence grades)"
          "\n  2  A phone with things 'worth a look' but no findings"
          "\n  3  A phone where nothing is found (what 'clean' does and does not mean)"
          "\n  4  A phone seized and unlocked with Cellebrite (a phone-forensics tool)")
    which = s.ask("  Choose, or press Enter to go back: ")
    scenario = {"1": "spyware", "2": "worth-a-look", "3": "clean", "4": "cellebrite"}.get(which)
    if not scenario:
        return "back"
    s.args.training = scenario
    return "scan"


def _mn_read_pasted(s, prompt):
    """Lines the person pastes or types, until an empty line. None to go back."""
    s.say(prompt)
    lines = []
    while True:
        line = s.ask("  " if lines else "  > ")
        if line is None:
            return None
        if line == "":
            break
        if line == "0" and not lines:
            return None
        lines.append(line)
    return "\n".join(lines)


def _mn_iocs(s):
    """The indicator lists a scan would use; None (patterns only) if they cannot be loaded."""
    loader = getattr(s, "load_iocs", None)
    if loader is None:
        s.say("  (Indicator lists are not available here. Checking the patterns only.)")
        return None
    try:
        return loader(s.args)
    except Exception as exc:  # noqa: BLE001
        s.say("  (Indicator lists could not be loaded: {}. Checking the patterns only.)".format(str(exc)[:120]))
        return None


def _mn_link(s):
    from .linkcheck import lc_check_text, lc_render
    text = _mn_read_pasted(s, "\n  Paste the message or the link (a text, a WhatsApp or Signal message, an email body),"
                              "\n  then press Enter on an empty line. Nothing is opened or looked up. Type 0 to go back.")
    if text is None or not text.strip():
        return "back"
    s.say("\n" + lc_render(lc_check_text(text, _mn_iocs(s))))
    s.pause()
    return "back"


def _mn_extracted(s):
    from .extracted import EX_HOW_TO, ExError, ex_check, ex_render
    s.say("\n" + EX_HOW_TO + "\n\n  Drag the folder into this window (or type its path) and press Enter."
          "\n  0 goes back.")
    path = s.local_path("  > ", want_dir=True)
    if path is None:
        return "back"
    try:
        s.say("\n" + ex_render(ex_check(path, _mn_iocs(s))))
    except (ExError, OSError) as exc:
        s.say("  That could not be checked: {}".format(exc))
    s.pause()
    return "back"


def _mn_email(s):
    from .mailcheck import MC_HOW_TO, McError, mc_check, mc_render
    s.say("\n" + MC_HOW_TO + "\n\n  Drag the saved message into this window (or type its path) and press Enter."
          "\n  0 goes back.")
    path = s.local_path("  > ")
    if path is None or os.path.isdir(path):
        return "back"
    try:
        with open(path, "rb") as fh:
            s.say("\n" + mc_render(mc_check(fh.read(64 * 1024 * 1024), _mn_iocs(s))))
    except (McError, OSError) as exc:
        s.say("  That message could not be checked: {}".format(exc))
    s.pause()
    return "back"


def _mn_qr(s):
    from .qrcheck import QR_HOW_TO, QrError, qr_check, qr_render
    s.say("\n" + QR_HOW_TO + "\n\n  Drag the picture into this window (or type its path) and press Enter."
          "\n  0 goes back.")
    path = s.local_path("  > ")
    if path is None or os.path.isdir(path):
        return "back"
    try:
        with open(path, "rb") as fh:
            s.say("\n" + qr_render(qr_check(fh.read(64 * 1024 * 1024), _mn_iocs(s))))
    except (QrError, OSError) as exc:
        s.say("  That picture could not be checked: {}".format(exc))
    s.pause()
    return "back"


def _mn_choose(s, labels, prompt):
    """A choice from a numbered list: with the arrow keys where the terminal allows it (menukeys), always also by
    typing the number; the plain typed prompt everywhere else."""
    from .menukeys import mk_keys, mk_select, mk_supported
    if not mk_supported(s.stdin, s.stderr):
        return s.ask(prompt)

    def write(text):
        s.stderr.write(text)
        s.stderr.flush()
    write("  Use the up/down arrows and Enter, or type the number.\n")
    return mk_select(labels, write, mk_keys(s.stdin), hint="(arrows + Enter, or type the number)")


def _mn_check_file(s):
    from .filecheck import fc_examine, fc_render
    s.say("\n  Drag the file into this window (or type its path) and press Enter. 0 goes back.")
    path = s.local_path("  > ")
    if path is None:
        return "back"
    s.say("  Looking at the file (it is not opened or run)...")
    s.say("\n" + fc_render(fc_examine(path, _mn_iocs(s))))
    s.pause()
    return "back"


def _mn_intake(s, items):
    """'?': what happened, in the person's words, leading to the entry that answers it."""
    from .intake import INTAKE, INTAKE_PARTNER_NOTE
    by_label = {i.label: i for i in items}
    choices = [(key, said, next_, by_label[label]) for key, said, next_, label in INTAKE if label in by_label]
    s.say("\n  WHAT HAPPENED?")
    for n, (_key, said, next_, _item) in enumerate(choices, 1):
        s.say("    {:>2}  {}\n        {}".format(n, said, next_))
    s.say("     0  Back to the full list")
    choice = _mn_choose(s, [said for _k, said, _n, _i in choices], "  Type a number and press Enter: ")
    if not choice or not choice.isdigit() or not 1 <= int(choice) <= len(choices):
        return "back"
    key, _said, _next, item = choices[int(choice) - 1]
    if key == "partner":
        s.say("\n  " + INTAKE_PARTNER_NOTE)
        s.say("  After the phone check, look at your accounts too: \"Your online accounts\" in the list.")
    return item.run(s)


def _mn_hash(s):
    from .hashlook import (HL_SERVICES, HlCache, hl_consent_text, hl_keys, hl_online, hl_render, hl_report,
                           hl_run, hl_should_ask)
    s.say("\n  Drag a file or folder into this window (or type its path) and press Enter. 0 goes back.")
    path = s.local_path("  > ")
    if path is None:
        return "back"
    s.say("  Fingerprinting (offline)...")
    result = hl_run([path], _mn_iocs(s), progress=s.say)
    s.say("\n" + hl_render(result))
    keys = hl_keys()
    services = [n for n, (_name, _c, need) in HL_SERVICES.items() if not need or keys.get(need)]
    count = len({r["sha256"] for r in result["files"] if hl_should_ask(r)})
    if count and result["level"] != "known-threat":
        s.say("\n  Ask online services as well?\n" + hl_consent_text(services, count))
        if len(services) == 1:
            s.say("  (Only CIRCL is available: add free keys for more under Help and settings > Keys for online"
                  " look-ups.)")
        if s.yes("  Send the fingerprints? (y/N) "):
            notes = hl_online(result["files"], services, keys, cache=HlCache(), progress=s.say)
            s.say("\n" + hl_render(hl_report(result["files"], notes, result["skipped"])))
    s.pause()
    return "back"


def _mn_lookup_keys(s):
    from .hashlook import HL_KEY_WHERE, hl_keys, hl_save_key
    have = hl_keys()
    for name, where in HL_KEY_WHERE.items():
        s.say("\n  {}: {}\n    get one: {}".format(name, "saved" if have.get(name) else "not set", where))
        value = s.ask("    paste the key and press Enter (Enter keeps it, - removes it): ")
        if value is None:
            return "back"
        if value == "-":
            hl_save_key(name, "")
        elif value:
            hl_save_key(name, value)
    s.say("\n  Keys are kept in your user settings folder on this computer only.")
    s.pause()
    return "back"


def _mn_helper(s):
    from .ageseal import AgError
    from .helperpack import HP_HOW, HpError, hp_build, hp_render
    s.say("\n  Send evidence to a helper\n\n" + HP_HOW + "\n\n  Paste the helper's key and press Enter (0 to go back,"
          " or type none\n  for an unencrypted package if the helper asked for that):")
    key = (s.ask("  > ") or "").strip()
    if key in ("", "0"):
        return "back"
    paths = []
    s.say("\n  Now the files and folders to include: drag each one into this window (or type its path) and press"
          "\n  Enter. An empty line when you are done.")
    while True:
        path = s.local_path("  + ", allow_blank=True)
        if path is None:
            return "back"
        if not path:
            break
        paths.append(path)
    if not paths:
        return "back"
    s.say("\n  Where should the package be saved? Drag a folder here, or press Enter for the findings folder.")
    out = s.local_path("  > ", allow_blank=True, want_dir=True)
    if out is None:
        return "back"
    out = out or os.path.join(os.getcwd(), "findings")
    try:
        result = hp_build(paths, out, None if key.lower() == "none" else key, progress=s.say)
        s.say("\n" + hp_render(result))
    except (AgError, HpError, OSError) as exc:
        s.say("  The package was not made: {}".format(exc))
    s.pause()
    return "back"


def _mn_fixit(s):
    from .fixit import FxError, fx_apply, fx_plan, fx_render, fx_undo
    while True:
        plan = fx_plan()
        s.say("\n" + fx_render(plan))
        choices = [o["door"] for o in plan["offers"]]
        if not choices and not plan["records"]:
            s.pause()
            return "back"
        if choices:
            s.say("  Type the number of a fix to do it, u to put the last one back, or 0 to go back:")
            for n, offer in enumerate(choices, 1):
                s.say("    {}  {}".format(n, plan["offers"][n - 1]["title"]))
        else:
            s.say("  Type u to put the last change back, or 0 to go back:")
        answer = (s.ask("  > ") or "").strip().lower()
        if answer in ("", "0"):
            return "back"
        if answer == "u" and plan["records"]:
            try:
                result = fx_undo(plan["records"][-1]["name"], confirm=lambda q: s.yes("  " + q + " (y/N) "))
                s.say("  Put back." if result["done"] else "  Not put back: " + result["why"])
            except (FxError, OSError) as exc:
                s.say("  Nothing was changed: {}".format(exc))
            s.pause()
            continue
        if answer.isdigit() and 1 <= int(answer) <= len(choices):
            try:
                result = fx_apply(choices[int(answer) - 1],
                                  confirm=lambda q: s.yes("\n  " + q + "\n  Go ahead? (y/N) "))
            except (FxError, OSError) as exc:
                s.say("  Nothing was changed: {}".format(exc))
                s.pause()
                continue
            if result["done"]:
                s.say("  Done. To put it back later: the Close-the-doors screen offers it as u.")
                if result.get("needs_restart"):
                    s.say("  This one finishes after you restart the computer.")
            else:
                s.say("  Nothing was changed: " + result["why"])
            s.pause()


def _mn_hunt(s):
    from .huntwin import hw_from_this_computer, hw_render
    s.say("\n  Reading Windows' own records (read only). This takes a couple of minutes...")
    result = hw_from_this_computer(_mn_iocs(s), progress=s.say)
    s.say("\n" + hw_render(result))
    s.pause()
    return "back"


def _mn_hunt_file(s):
    from .huntwin import hw_from_files, hw_render
    s.say("\n  Windows saves its records as .evtx files. On the computer they came from:"
          "\n     wevtutil epl \"Microsoft-Windows-PowerShell/Operational\" ps.evtx"
          "\n\n  Drag the file (or a folder of them) into this window and press Enter. 0 goes back.")
    path = s.local_path("  > ")
    if path is None:
        return "back"
    paths = [path]
    if os.path.isdir(path):
        paths = sorted(os.path.join(path, n) for n in os.listdir(path) if n.lower().endswith(".evtx"))
        if not paths:
            s.say("  That folder holds no .evtx files.")
            s.pause()
            return "back"
    result = hw_from_files(paths, _mn_iocs(s), progress=s.say)
    s.say("\n" + hw_render(result))
    s.pause()
    return "back"


def _mn_startup(s):
    from .startup import su_inventory, su_render
    s.say("\n  Listing everything set to start automatically (read only; this takes a few seconds)...")
    s.say("\n" + su_render(su_inventory(_mn_iocs(s))))
    s.pause()
    return "back"


def _mn_traffic(s):
    from .netcapture import NC_HOW_TO, NcError, nc_analyse, nc_render
    s.say("\n" + NC_HOW_TO + "\n\n  Drag the recording (.pcap / .pcapng) into this window, or type its path, then press"
          "\n  Enter. Type 0 to go back.")
    path = s.local_path("  > ")
    if path is None or os.path.isdir(path):
        return "back"
    try:
        with open(path, "rb") as fh:
            data = fh.read(2 * 1024 * 1024 * 1024)
        s.say("\n" + nc_render(nc_analyse(data, _mn_iocs(s))))
    except (NcError, OSError) as exc:
        s.say("  That file could not be read: {}".format(exc))
    s.pause()
    return "back"


def _mn_homenet(s):
    from .homenet import homenet_command
    homenet_command(s.args)
    s.pause()
    return "back"


def _mn_wifi_nearby(s):
    from .wifinearby import wifi_nearby_command
    s.say("")
    wifi_nearby_command(out=s.say)
    s.pause()
    return "back"


def _mn_trackers(s):
    from .trackers import trackers_command
    raw = s.ask("\n  Listen for how many minutes? (1 to 30, Enter for 3; longer is clearer): ")
    if raw is None:
        return "back"
    s.args.trackers = max(1, min(30, int(raw))) if raw.isdigit() else 3
    trackers_command(s.args)
    s.args.trackers = None
    s.pause()
    return "back"


def _mn_dnslog(s):
    s.say("\n  Drag the DNS log from your router, Pi-hole, AdGuard Home or DNS server into this"
          "\n  window (or type its path), then press Enter. Type 0 to go back.")
    path = s.local_path("  > ")
    if path is None or os.path.isdir(path):
        return "back"
    s.args.dns_log = [path]
    return "scan"


def _mn_household(s):
    from .household import combine_command
    s.say("\n  Drag in the saved JSON reports (computers, phones, the home network), one at a time,"
          "\n  then press Enter on an empty line. Type 0 to go back.")
    paths = []
    while True:
        p = s.local_path("  > " if not paths else "  Another, or Enter to finish: ", allow_blank=bool(paths))
        if p is None:
            return "back"
        if p == "":
            break
        paths.append(p)
    s.args.combine = paths
    combine_command(s.args)
    s.args.combine = None
    s.pause()
    return "back"


def _mn_update(s):
    s.say("\n  This downloads the published indicator lists (Amnesty, the MVT project,"
          "\n  Echap and others). This uses the internet, as does guided Android"
          "\n  acquisition. The checks themselves run offline.")
    if s.yes("  Download them now? [y/N]: "):
        s.update()
        s.pause()
    return "back"


def _mn_accounts(s):
    from .accounts import ac_render, ac_terminal
    result = ac_terminal(s.ask, s.say)
    s.say("\n" + ac_render(result))
    s.pause()
    return "back"


def _mn_threat_warning(s):
    from .accounts import AC_THREAT_WARNING
    s.say("\n" + AC_THREAT_WARNING)
    s.pause()
    return "back"


_MN_ITEMS = [
    _MnItem(_MN_SECTIONS[0], "This computer - standard check",
            "the usual places; recommended to start", _mn_standard),
    _MnItem(_MN_SECTIONS[0], "This computer - full check",
            "adds caches and all file types; slower", _mn_full),
    _MnItem(_MN_SECTIONS[0], "This computer - browsers only",
            "ad campaign check; ad-blocking test", _mn_browser),
    _MnItem(_MN_SECTIONS[0], "A drive, folder or single file",
            "a USB stick, a download, an attachment", _mn_targeted),
    _MnItem(_MN_SECTIONS[0], "A phone",
            "Android (AndroidQF) or an iPhone backup", _mn_phone),
    _MnItem(_MN_SECTIONS[0], "Was a phone copied?",
            "a seized phone; Cellebrite traces", _mn_extracted),
    _MnItem(_MN_SECTIONS[1], "A link or message",
            "paste it; nothing is opened", _mn_link),
    _MnItem(_MN_SECTIONS[1], "A suspicious email",
            "who really sent it; nothing opened", _mn_email),
    _MnItem(_MN_SECTIONS[1], "A QR code in a picture",
            "reads it without following it", _mn_qr),
    _MnItem(_MN_SECTIONS[1], "A suspicious file",
            "what it really is; never opened or run", _mn_check_file),
    _MnItem(_MN_SECTIONS[1], "A file's fingerprint",
            "offline first; online asks", _mn_hash),
    _MnItem(_MN_SECTIONS[2], "Your home network",
            "devices, doors, cameras; asks first", _mn_homenet, lambda s: s.stdout_visible),
    _MnItem(_MN_SECTIONS[2], "Bluetooth trackers nearby",
            "AirTags, Tiles and more; listens only", _mn_trackers, lambda s: s.stdout_visible),
    _MnItem(_MN_SECTIONS[2], "Hidden Wi-Fi networks nearby",
            "who made them, how close; joins nothing", _mn_wifi_nearby),
    _MnItem(_MN_SECTIONS[2], "A phone's network recording",
            "PCAPdroid / Wireshark file; offline", _mn_traffic),
    _MnItem(_MN_SECTIONS[2], "A router or Pi-hole DNS log",
            "every device that used that DNS server", _mn_dnslog),
    _MnItem(_MN_SECTIONS[3], "Your online accounts",
            "linked devices, forwarding; you look", _mn_accounts),
    _MnItem(_MN_SECTIONS[3], "Close the doors found open",
            "asks first; saves a way back", _mn_fixit),
    _MnItem(_MN_SECTIONS[3], "What starts automatically",
            "every program set to start; read only", _mn_startup),
    _MnItem(_MN_SECTIONS[3], "Windows' own records",
            "hidden commands, cleared logs", _mn_hunt,
            lambda s: sys.platform == "win32"),
    _MnItem(_MN_SECTIONS[3], "A Windows log file (.evtx)",
            "records from another machine", _mn_hunt_file),
    _MnItem(_MN_SECTIONS[4], "Household report",
            "several saved reports on one page", _mn_household, lambda s: s.stdout_visible),
    _MnItem(_MN_SECTIONS[4], "Send evidence to a helper",
            "sealed and signed; nothing is sent", _mn_helper),
    _MnItem(_MN_SECTIONS[5], "Where to get help",
            "helplines if you may be targeted", _mn_help),
    _MnItem(_MN_SECTIONS[5], "I got a threat warning",
            "what to do, in order", _mn_threat_warning),
    _MnItem(_MN_SECTIONS[5], "How to prepare a phone",
            "step by step; nothing is run", _mn_guide),
    _MnItem(_MN_SECTIONS[5], "Keys for online look-ups",
            "your own free keys; kept here", _mn_lookup_keys),
    _MnItem(_MN_SECTIONS[5], "Update the indicator lists",
            "uses the internet; the checks never do", _mn_update),
    _MnItem(_MN_SECTIONS[5], "Practise with a training example",
            "a made-up phone; reads nothing real", _mn_training),
]


def _mn_render(items, s):
    lines = ["", "  What would you like to do?  (Not sure? Type ? and press Enter.)"]
    number = 0
    for section in _MN_SECTIONS:
        entries = [i for i in items if i.section == section]
        if not entries:
            continue
        lines.append("")
        lines.append("  " + section.upper())
        for item in entries:
            number += 1
            lines.append("    {:>2}  {:<32} {}".format(number, item.label, item.hint))
    lines += ["", "     ?  Not sure where to start? Tell me what happened", "     0  Quit", "",
              "  Checks read local evidence. Updates download indicator lists;",
              "  guided acquisition collects private phone records after consent;",
              "  the ad-blocking test opens a page in your own browser."]
    s.say("\n".join(lines))


def menu_wanted(argv, args, stdin=None, stderr=None):
    """True when a person is at the terminal and has not chosen a check yet."""
    stdin = stdin or sys.stdin
    stderr = stderr or sys.stderr
    if getattr(args, "no_menu", False):
        return False
    for token in argv or ():
        if any(token == opt or token.startswith(opt + "=") for opt in _MN_CHOSEN):
            return False
    try:
        return bool(stdin.isatty() and stderr.isatty())
    except (AttributeError, ValueError):
        return False


def choose_scan(args, update, stdin=None, stderr=None, stdout_visible=None, load_iocs=None):
    """Show the menu until the person picks a check or quits.

    Sets the same args a command line would. `update` is called with no
    arguments if the person confirms the indicator update. Returns True to run
    the chosen check, False to quit."""
    stdin = stdin or sys.stdin
    stderr = stderr or sys.stderr
    if stdout_visible is None:
        try:
            stdout_visible = bool(sys.stdout.isatty())
        except (AttributeError, ValueError):
            stdout_visible = False
    s = _MnSession(args, update, stdin, stderr, stdout_visible)
    s.load_iocs = load_iocs
    while True:
        items = [i for i in _MN_ITEMS if i.available(s)]
        _mn_render(items, s)
        choice = _mn_choose(s, [i.label for i in items],
                            "  Type a number (or ? if you are not sure) and press Enter [1]: ")
        if choice is None or choice.lower() in ("0", "q", "quit", "exit"):
            s.say("\n  Nothing was checked.")
            return False
        if choice == "?":
            outcome = _mn_intake(s, items)
            if outcome == "scan":
                args._interactive_workflow = True
                return True
            if outcome == "quit":
                s.say("\n  Nothing was checked.")
                return False
            continue
        if choice == "":
            choice = "1"
        if not choice.isdigit() or not 1 <= int(choice) <= len(items):
            s.say("  Please type a number from 0 to {}.".format(len(items)))
            continue
        outcome = items[int(choice) - 1].run(s)
        if outcome == "scan":
            args._interactive_workflow = True
            return True
        if outcome == "quit":
            s.say("\n  Nothing was checked.")
            return False
