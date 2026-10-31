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
                             drive-folder-file, phone
  Look closer                read-only views a person can investigate themselves
                             (planned: network connections, trusted certificates,
                             browser extensions)
  Help and settings          helplines, phone preparation, indicator update
New features add one _MnItem; nothing else here changes. An item that cannot
work in the current window (for example a step whose prompts would be hidden)
is left out rather than shown and then failing.
"""

import os
import sys

# Options that already say what to check. If any is present the person (or a
# script) has chosen, so the menu stays out of the way.
_MN_CHOSEN = ("--scan-type", "--target", "--phone", "--collect-android", "--update",
              "--quick", "--deep", "--patterns", "--pattern-path", "--backup-password",
              "--extended-windows", "--ios-input", "--no-menu", "--preview", "--describe", "--phone-guide",
              "--training")

_MN_SECTIONS = ("Check for spyware traces", "Look closer", "Help and settings")

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
          "\n  3  A phone where nothing is found (what 'clean' does and does not mean)")
    which = s.ask("  Choose, or press Enter to go back: ")
    scenario = {"1": "spyware", "2": "worth-a-look", "3": "clean"}.get(which)
    if not scenario:
        return "back"
    s.args.training = scenario
    return "scan"


def _mn_update(s):
    s.say("\n  This downloads the published indicator lists (Amnesty, the MVT project,"
          "\n  Echap and others). This uses the internet, as does guided Android"
          "\n  acquisition. The checks themselves run offline.")
    if s.yes("  Download them now? [y/N]: "):
        s.update()
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
    _MnItem(_MN_SECTIONS[2], "Where to get help",
            "helplines if you may be targeted", _mn_help),
    _MnItem(_MN_SECTIONS[2], "How to prepare a phone",
            "step by step; nothing is run", _mn_guide),
    _MnItem(_MN_SECTIONS[2], "Update the indicator lists",
            "uses the internet; the checks never do", _mn_update),
    _MnItem(_MN_SECTIONS[2], "Practise with a training example",
            "a made-up phone; reads nothing real", _mn_training),
]


def _mn_render(items, s):
    lines = ["", "  What would you like to do?"]
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
    lines += ["", "     0  Quit", "",
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


def choose_scan(args, update, stdin=None, stderr=None, stdout_visible=None):
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
    while True:
        items = [i for i in _MN_ITEMS if i.available(s)]
        _mn_render(items, s)
        choice = s.ask("  Type a number and press Enter [1]: ")
        if choice is None or choice.lower() in ("0", "q", "quit", "exit"):
            s.say("\n  Nothing was checked.")
            return False
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
