"""Doors to close: ways into this computer that are left open.

Prevention advice, never findings: an open door does not mean anyone used it. Each check reads a setting
(registry, a system command's output, a configuration file) and reports the door as open, closed, or could
not be checked, with why it matters for someone who could be targeted and how to close it - plus a link that
opens the exact system setting where one exists.

Reads only. Changes nothing. Contacts nothing (scan modules may not use the network). Never reads a
password: for automatic sign-in it notes only whether a password is stored, never the password.
"""
from __future__ import annotations

import fnmatch
import hashlib
import itertools
import json
import ntpath
import os
import re
import subprocess
import sys

from ..accessdata import ACCESS_FILES, ACCESS_PROGRAMS
from ..driverdata import DRIVER_SHA1, DRIVER_SHA256
from ..contract import sanitize_untrusted
from ..localpaths import path_problem
from ..result import DOOR_CLOSED, DOOR_OPEN, DOOR_UNKNOWN, Door, Lead, ModuleResult

NAME = "doors"
_DR_TIMEOUT = 40
_DR_ACCESS = tuple((name, kind, re.compile(rx, re.I)) for name, kind, rx in ACCESS_PROGRAMS)


def _dr_run(argv, timeout=_DR_TIMEOUT):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    done = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, creationflags=flags, stdin=subprocess.DEVNULL)
    return done.returncode, done.stdout or ""


def _dr_ps(script):
    return _dr_run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script])


def _reg(root, path, value):
    """A registry value, or None when the key or value is absent."""
    import winreg  # type: ignore
    try:
        with winreg.OpenKey(root, path) as key:
            return winreg.QueryValueEx(key, value)[0]
    except OSError:
        return None


def _dr_clean(text, limit=200):
    return sanitize_untrusted(str(text))[:limit]


# --- remote access and monitoring programs (all platforms) ---------------------------------------------

def dr_match_programs(names):
    """[(program, kind, matched name)] for installed names that match the list; one entry per program."""
    found, seen = [], set()
    for raw in names:
        name = _dr_clean(raw, 160)
        # A viewer only lets this computer control OTHER computers: not a way in. (TeamViewer is one word.)
        # "Client" is NOT exempt: in ScreenConnect, Bomgar, NetSupport and others the "Client" is the agent
        # that lets someone else in ("ScreenConnect Client (...)" is the support-scam favourite).
        viewer = bool(re.search(r"\bviewer\b", name, re.I))
        for program, kind, rx in _DR_ACCESS:
            m = rx.search(name) if program not in seen else None
            if not m:
                continue
            # ...unless the list entry itself names the client, as for an agent that runs on the managed machine
            # ("Comodo One Client").
            if kind == "remote" and viewer and not re.search(r"viewer", m.group(0), re.I):
                continue
            if program not in seen:
                seen.add(program)
                found.append((program, kind, name))
    return found


def _dr_windows_program_names():
    import winreg  # type: ignore
    names = []
    roots = ((winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
             (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
             (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"))
    for root, path in roots:
        try:
            with winreg.OpenKey(root, path) as key:
                for i in range(20000):
                    try:
                        sub = winreg.EnumKey(key, i)
                    except OSError:
                        break
                    name = _reg(root, path + "\\" + sub, "DisplayName")
                    if name:
                        names.append(str(name))
        except OSError:
            continue
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services") as key:
            for i in range(20000):
                try:
                    sub = winreg.EnumKey(key, i)
                except OSError:
                    break
                display = _reg(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services" + "\\" + sub,
                               "DisplayName")
                names.append(sub)
                if isinstance(display, str) and not display.startswith("@"):
                    names.append(display)
    except OSError:
        pass
    return names


def _dr_listdir(path):
    try:
        return os.listdir(path)
    except OSError:
        return []


def _dr_posix_program_names():
    names = []
    if sys.platform == "darwin":
        for folder in ("/Applications", os.path.expanduser("~/Applications"), "/Library/LaunchDaemons",
                       "/Library/LaunchAgents", os.path.expanduser("~/Library/LaunchAgents")):
            names += [n.replace(".app", "").replace(".plist", "") for n in _dr_listdir(folder)]
    else:
        for folder in ("/usr/share/applications", os.path.expanduser("~/.local/share/applications"),
                       "/etc/systemd/system", "/lib/systemd/system", "/usr/lib/systemd/system", "/opt",
                       os.path.expanduser("~/.config/autostart"), "/etc/xdg/autostart"):
            names += [n.replace(".desktop", "").replace(".service", "") for n in _dr_listdir(folder)]
    return names


def _dr_wow64():
    """True for 32-bit Python on 64-bit Windows: System32 and parts of the registry are redirected for it."""
    return sys.platform == "win32" and bool(os.environ.get("PROCESSOR_ARCHITEW6432"))


def _check_programs(r):
    if _dr_wow64():
        r.add_door(Door("computer:remote-access-software", DOOR_UNKNOWN,
                        "Installed programs were not checked: 32-bit Python cannot see all of them on 64-bit Windows"))
        r.could_not_run("remote-access-software", "32-bit Python on 64-bit Windows sees only part of the installed "
                                                  "programs - use 64-bit Python or the downloadable program")
        return
    names = _dr_windows_program_names() if sys.platform == "win32" else _dr_posix_program_names()
    found = dr_match_programs(names)
    for program, kind, matched in found:
        if kind == "monitoring":
            r.add_door(Door("computer:monitoring-software", DOOR_OPEN,
                            "Monitoring software is installed: {}".format(program),
                            "Monitoring programs record what is done on this computer - screens, typing, sites, "
                            "messages - and send it to whoever set them up. Sold to employers and parents, they "
                            "are also how a partner or ex keeps watch.",
                            "If you did not install it, or no longer agree to it: write down what you see first "
                            "(it can be evidence), then uninstall it and change your passwords from another "
                            "device. On a work computer, ask your employer what is monitored.",
                            "ms-settings:appsfeatures" if sys.platform == "win32" else "", "high", matched))
        else:
            r.add_door(Door("computer:remote-access", DOOR_OPEN,
                            "Remote-access software is installed: {}".format(program),
                            "Remote-access tools let someone see and control this computer from elsewhere. IT "
                            "support uses them every day; so do scammers and abusive partners.",
                            "If you, your family or your IT support installed it and still use it, keep it and "
                            "protect it with a strong password. Otherwise uninstall it.",
                            "ms-settings:appsfeatures" if sys.platform == "win32" else "", "medium", matched))
    if not found:
        r.add_door(Door("computer:remote-access", DOOR_CLOSED,
                        "No known remote-access or monitoring software installed"))
    r.note("Remote-access and monitoring software: {} installed names compared with {} known programs.".format(
        len(names), len(_DR_ACCESS)))
    r.ran("remote-access-software")


# --- a remote-access program downloaded but never installed ---------------------------------------------
# The "download AnyDesk and read me the code" scam: the program runs straight from Downloads, so it is never in
# the installed-programs list. Only file NAMES are compared; nothing is opened or run. Links are not followed.

_DR_DL_SUFFIX = re.compile(r" ?\(\d{1,3}\)(?=\.[a-z0-9]{2,8}$)")
_DR_DL_EXT = (".exe", ".app", ".dmg", ".msi", ".pkg", ".deb", ".rpm", ".appimage")
_DR_DL_ENTRIES = 5000          # per folder, so a huge Downloads folder cannot stall the check


def dr_match_download(name):
    """(program, kind) when a file name is one a remote-access program uses, else None."""
    low = _DR_DL_SUFFIX.sub("", str(name).strip().lower())
    if not low.endswith(_DR_DL_EXT):
        return None
    for program, kind, pattern in ACCESS_FILES:
        if fnmatch.fnmatchcase(low, pattern):
            return program, kind
    return None


def dr_download_folders(home, shell=None):
    """[(folder, depth)]: Downloads two levels deep (programs unpacked from a ZIP), Desktop and Documents one.
    Includes the names a Linux desktop gives them in its own language (XDG user-dirs: Descargas, Escritorio...)
    and the OneDrive copies Windows' folder backup moves Desktop and Documents into. Each folder once."""
    out, seen = [], set()

    def add(folder, depth):
        key = os.path.normcase(os.path.abspath(folder))
        if key not in seen:
            seen.add(key)
            out.append((folder, depth))
    add(os.path.join(home, "Downloads"), 2)
    add(os.path.join(home, "Desktop"), 1)
    add(os.path.join(home, "Documents"), 1)
    for name, depth in (("DOWNLOAD", 2), ("DESKTOP", 1), ("DOCUMENTS", 1)):
        folder = dr_xdg_dir(home, name)
        if folder:
            add(folder, depth)
    # Where Windows really keeps them belongs to the current user: only for the current user's own home.
    if shell is None:
        same_home = os.path.normcase(os.path.abspath(home)) == os.path.normcase(os.path.expanduser("~"))
        shell = dr_windows_shell_folders() if same_home else []
    for folder, depth in shell:
        add(folder, depth)
    try:
        onedrives = [n for n in os.listdir(home) if n == "OneDrive" or n.startswith("OneDrive - ")]
    except OSError:
        onedrives = []
    for drive in sorted(onedrives):
        for name in ("Desktop", "Documents"):
            add(os.path.join(home, drive, name), 1)
    return out


def dr_windows_shell_folders():
    """[(folder, depth)] for where Windows really keeps this user's Downloads, Desktop and Documents (they are
    often moved to another drive or into OneDrive). Empty off Windows or when the setting cannot be read."""
    if sys.platform != "win32":
        return []
    import winreg  # type: ignore
    out = []
    for value, depth in (("{374DE290-123F-4565-9164-39C4925E467B}", 2), ("Desktop", 1), ("Personal", 1)):
        raw = _reg(winreg.HKEY_CURRENT_USER,
                   r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", value)
        if isinstance(raw, str) and raw.strip():
            out.append((os.path.normpath(os.path.expandvars(raw.strip())), depth))
    return out


def dr_xdg_dir(home, name):
    """A folder from ~/.config/user-dirs.dirs (XDG_<NAME>_DIR="$HOME/..."), or None."""
    try:
        with open(os.path.join(home, ".config", "user-dirs.dirs"), encoding="utf-8", errors="replace") as fh:
            text = fh.read(64 * 1024)
    except OSError:
        return None
    m = re.search(r'(?m)^XDG_{}_DIR="([^"\n]{{1,500}})"'.format(name), text)
    if not m:
        return None
    value = os.path.normpath(m.group(1).replace("$HOME", home))
    return value if os.path.isabs(value) else None


def dr_scan_downloads(folders):
    """([(program, kind, path)], entries_seen, capped, folders_read, folders_refused) - names only; links and
    junctions are not followed. folders_read counts the top folders that could actually be opened (none means
    nothing was checked); folders_refused counts folders and subfolders that exist but could not be opened."""
    found, seen, capped, opened, refused = [], 0, False, 0, 0
    for top, depth in folders:
        pending = [(top, 1)]
        count = 0
        while pending and count <= _DR_DL_ENTRIES:
            folder, level = pending.pop()
            # Local, and no link or junction anywhere in the path (path_problem knows junctions on every Python
            # version; DirEntry.is_junction only exists from 3.12). A top folder refused here was not checked; a
            # link inside is simply not followed, as promised.
            problem = path_problem(folder)
            if problem:
                if level == 1 and os.path.lexists(folder):
                    refused += 1
                continue
            try:
                with os.scandir(folder) as it:
                    # Never more names than the cap allows: a folder of millions is not listed whole first.
                    entries = list(itertools.islice(it, _DR_DL_ENTRIES - count + 1))
            except FileNotFoundError:
                continue
            except OSError:
                refused += 1
                continue
            if level == 1:
                opened += 1
            for entry in entries:
                count += 1
                if count > _DR_DL_ENTRIES:
                    capped = True
                    break
                try:
                    if entry.is_symlink() or (hasattr(entry, "is_junction") and entry.is_junction()):
                        continue
                    is_dir = entry.is_dir(follow_symlinks=False)
                except OSError:
                    continue
                bundle = entry.name.lower().endswith(".app")
                hit = dr_match_download(entry.name) if (not is_dir or bundle) else None
                if hit:
                    found.append((hit[0], hit[1], entry.path))
                elif is_dir and not bundle and level < depth:
                    pending.append((entry.path, level + 1))
        seen += min(count, _DR_DL_ENTRIES)
    return found, seen, capped, opened, refused


def _check_downloads(r):
    folders = [f for f in dr_download_folders(os.path.expanduser("~")) if os.path.isdir(f[0])]
    if not folders:
        # A computer with no such folders (a server, another layout) has nothing waiting there: not a gap.
        r.note("Downloaded remote-access programs: no Downloads, Desktop or Documents folder on this computer.")
        return
    found, seen, capped, opened, refused = dr_scan_downloads(folders)
    if not opened:
        # No folder could be read: that is not "nothing waiting" - say it was not checked.
        r.add_door(Door("computer:remote-access-download", DOOR_UNKNOWN,
                        "Downloads, Desktop and Documents could not be read, so downloaded remote-access programs "
                        "were not checked"))
        r.could_not_run("remote-access-downloads", "none of Downloads, Desktop or Documents could be read")
        return
    by_program = {}
    for program, kind, path in found:
        by_program.setdefault((program, kind), []).append(path)
    for (program, kind), paths in sorted(by_program.items()):
        shown = "; ".join(_dr_clean(p, 160) for p in paths[:3]) + (" ..." if len(paths) > 3 else "")
        r.add_door(Door("computer:remote-access-download", DOOR_OPEN,
                        "A {} program is waiting in your files: {}".format(
                            "monitoring" if kind == "monitoring" else "remote-access", program),
                        "It was downloaded but is not installed, so it does not appear in the list of programs. "
                        "Scammers and abusers often ask people to download one of these and read out a code - "
                        "running it once is enough for them to see and control the computer.",
                        "If someone asked you to download it: do not open it again and do not read out any code. If "
                        "you already let someone connect, restart the computer, change your passwords from another "
                        "device, and call your bank if they could have seen it. If you downloaded it yourself for a "
                        "reason you know, you can delete it or keep it.",
                        "", "high" if kind == "monitoring" else "medium", shown))
    # Read only in part (a folder or subfolder refused, or a huge folder capped): nothing found in the part that was
    # read is not "nothing waiting".
    partly = []
    if refused:
        partly.append("{} folder(s) could not be opened".format(refused))
    if capped:
        partly.append("very large folders were read only in part")
    if not by_program and not partly:
        r.add_door(Door("computer:remote-access-download", DOOR_CLOSED,
                        "No remote-access programs waiting in Downloads, Desktop or Documents"))
    elif not by_program:
        r.add_door(Door("computer:remote-access-download", DOOR_UNKNOWN,
                        "No remote-access program found in the part of Downloads, Desktop and Documents that could "
                        "be read ({})".format("; ".join(partly))))
    if partly:
        r.could_not_run("remote-access-downloads-complete",
                        "Downloads, Desktop and Documents were read only in part: " + "; ".join(partly))
    r.note("Downloaded programs: {} file names in Downloads, Desktop and Documents compared with {} known "
           "remote-access program files.".format(seen, len(ACCESS_FILES)))
    r.ran("remote-access-downloads")


# --- Windows drivers: known vulnerable or malicious, and the two protections against them ---------------------
# A signed driver with a known hole lets someone who already has a foothold switch off antivirus from inside
# Windows ("bring your own vulnerable driver"). Every .sys file directly in System32\drivers, and the file of every
# kernel-driver service wherever it is, is fingerprinted (read only) and compared with LOLDrivers' verified list.
# Paths from the registry go through path_problem first: a network or linked path is never opened.

_DR_DRV_MAX_FILE = 256 * 1024 * 1024     # graphics and anti-cheat drivers are 70-110 MB; read in pieces
_DR_DRV_MAX_TOTAL = 2 * 1024 * 1024 * 1024
_DR_DRV_MAX_FILES = 4000


def dr_resolve_image_path(raw, system_root):
    """A driver service's ImagePath as a local absolute path, or "" when it cannot be resolved."""
    path = str(raw or "").strip().strip('"').strip()
    if not path:
        return ""
    low = path.lower()
    if low.startswith("\\??\\"):
        path = path[4:]
    elif low.startswith("\\systemroot\\"):
        path = os.path.join(system_root, path[len("\\systemroot\\"):])
    elif low.startswith("system32\\") or low.startswith("syswow64\\"):
        path = os.path.join(system_root, path)
    elif low.startswith("%systemroot%\\"):
        path = os.path.join(system_root, path[len("%systemroot%\\"):])
    if "%" in path:
        path = ntpath.expandvars(path)                  # a REG_EXPAND_SZ path, e.g. %ProgramFiles%\Vendor\x.sys
    if not (len(path) > 2 and path[1] == ":" and path[2] in "\\/"):
        return ""                               # anything else (UNC, device, relative) is not opened
    return os.path.normpath(path)


def dr_match_driver(sha256, sha1):
    """(kind 'v'|'m', listed file name) for a known fingerprint, else None."""
    return DRIVER_SHA256.get((sha256 or "").lower()) or DRIVER_SHA1.get((sha1 or "").lower())


def dr_fingerprint_files(paths, problem=None):
    """([(path, kind, listed name)], files_fingerprinted, files_not_read) - each file read once, in pieces."""
    problem = problem or path_problem
    matches, done, unread, total = [], 0, 0, 0
    seen = set()
    for path in paths:
        key = os.path.normcase(path)
        if key in seen:
            continue
        seen.add(key)
        if done >= _DR_DRV_MAX_FILES or total >= _DR_DRV_MAX_TOTAL:
            unread += 1
            continue
        if problem(path):
            unread += 1
            continue
        try:
            size = os.path.getsize(path)
        except FileNotFoundError:
            continue                    # a service left behind by an uninstalled driver: nothing there to load
        except OSError:
            unread += 1
            continue
        try:
            if size > _DR_DRV_MAX_FILE:
                unread += 1
                continue
            h256, h1 = hashlib.sha256(), hashlib.sha1()
            with open(path, "rb") as fh:
                for block in iter(lambda: fh.read(1024 * 1024), b""):
                    h256.update(block)
                    h1.update(block)
        except OSError:
            unread += 1
            continue
        done += 1
        total += size
        hit = dr_match_driver(h256.hexdigest(), h1.hexdigest())
        if hit:
            matches.append((path, hit[0], hit[1]))
    return matches, done, unread


def _dr_driver_service_paths(system_root):
    """([driver file paths from registered kernel/file-system driver services], how many such services name a path
    that could not be resolved). Raises OSError when the services list itself cannot be read, so the caller can say
    the check was incomplete instead of judging on less."""
    import winreg  # type: ignore
    out, unresolved = [], 0
    base = r"SYSTEM\CurrentControlSet\Services"
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base) as key:
        for i in range(20000):
            try:
                sub = winreg.EnumKey(key, i)
            except OSError:
                break
            kind = _reg(winreg.HKEY_LOCAL_MACHINE, base + "\\" + sub, "Type")
            if kind not in (1, 2):              # kernel and file-system drivers only
                continue
            image = _reg(winreg.HKEY_LOCAL_MACHINE, base + "\\" + sub, "ImagePath")
            if not image:
                image = "\\SystemRoot\\System32\\drivers\\{}.sys".format(sub)   # what Windows loads then
            path = dr_resolve_image_path(image, system_root) if isinstance(image, str) else ""
            if path:
                out.append(path)
            else:
                unresolved += 1
    return out, unresolved


def dr_driver_paths(system_root, service_paths):
    folder = os.path.join(system_root, "System32", "drivers")
    try:
        names = sorted(n for n in os.listdir(folder) if n.lower().endswith(".sys"))
    except OSError:
        names = None
    listed = [os.path.join(folder, n) for n in names] if names is not None else []
    return listed + list(service_paths), names is not None


def dr_driver_doors(r, matches, done, unread, folder_read, services_read=True, registered=None, unresolved=0):
    """registered: the driver paths a registered driver service points at (normcased), or None when unknown. Windows
    loads a driver only through such a service, so a file in the drivers folder that no service names is present,
    not installed."""
    if not done:
        # Nothing fingerprinted (folder unreadable, or every file refused): not checked, never "none found".
        r.add_door(Door("windows:known-bad-drivers", DOOR_UNKNOWN,
                        "Installed drivers could not be read, so they were not compared with the list of known "
                        "vulnerable and malicious drivers"))
        r.could_not_run("windows-drivers", "no driver file could be read" if folder_read
                        else "the System32\\drivers folder could not be read")
        return
    for path, kind, listed in matches:
        shown = _dr_clean(path, 200)
        # Installed = a registered driver service points at it (Windows loads drivers only that way). A file in the
        # drivers folder that no service names is present but not set to load.
        installed = registered is None or os.path.normcase(path) in registered
        where = "is installed" if installed else "is in Windows' drivers folder"
        if kind == "m":
            r.add_door(Door("windows:known-bad-drivers", DOOR_OPEN,
                            "A driver known to be malicious {}: {}".format(where, ntpath.basename(shown)),
                            "Drivers run inside Windows itself. A malicious one can hide other programs and switch "
                            "off security software, and it is a sign that someone had full control of this computer."
                            if installed else
                            "No driver service is set to load it, but only an administrator can put a file in Windows' "
                            "drivers folder - so someone had full control of this computer at some point.",
                            "Do not try to remove it yourself and do not keep using this computer for anything "
                            "sensitive. Save the report, and get expert help: the Access Now Digital Security "
                            "Helpline (accessnow.org/help) helps journalists and activists for free.",
                            "", "high", "{} (listed as {})".format(shown, listed)))
        else:
            r.add_door(Door("windows:known-bad-drivers", DOOR_OPEN,
                            "A driver with a known security hole {}: {}".format(where, ntpath.basename(shown)),
                            "Someone who already has a foothold can load a driver like this to switch off antivirus "
                            "from inside Windows. It usually came with a hardware, graphics-card, motherboard or "
                            "overclocking tool, and on its own it does not mean anyone used it.",
                            "Update or uninstall the program it came with, and keep Microsoft's vulnerable driver "
                            "blocklist switched on (Windows Security > Device security > Core isolation).",
                            "windowsdefender://coreisolation", "medium", "{} (listed as {})".format(shown, listed)))
    # What was left out. A driver file that no longer exists (left behind by an uninstall) is not counted: there is
    # nothing there to load. A file that exists but could not be read, an unreadable drivers folder or services
    # list, all mean some installed drivers were not compared - never "none is on the list".
    missed = []
    if unread:
        missed.append("{} driver file(s) could not be read".format(unread))
    if not folder_read:
        missed.append("the System32\\drivers folder could not be listed")
    if not services_read:
        missed.append("the list of registered driver services could not be read")
    if unresolved:
        missed.append("{} registered driver(s) name a file location this check could not resolve".format(unresolved))
    if not matches and not missed:
        r.add_door(Door("windows:known-bad-drivers", DOOR_CLOSED,
                        "No installed driver is on the list of known vulnerable or malicious drivers"))
    elif not matches:
        r.add_door(Door("windows:known-bad-drivers", DOOR_UNKNOWN,
                        "None of the {} drivers that could be read is on the list of known vulnerable or malicious "
                        "drivers, but not all were checked ({})".format(done, "; ".join(missed))))
    if missed:
        r.could_not_run("windows-drivers-complete", "not every installed driver was compared: " + "; ".join(missed))
    r.note("Drivers: {} driver files fingerprinted and compared with {} known vulnerable or malicious drivers "
           "(LOLDrivers){}.".format(done, len(DRIVER_SHA256) + len(DRIVER_SHA1),
                                    "; {} could not be read".format(unread) if unread else ""))
    r.ran("windows-drivers")


def dr_blocklist_door(value, build, hvci_running):
    """Microsoft's vulnerable driver blocklist: on by default from Windows 11 22H2 (build 22621); before that it is
    enforced only together with memory integrity - and with memory integrity running it is enforced whatever the
    setting says. An explicit 0 without memory integrity: it was switched off, by a person or a program."""
    if hvci_running:
        return Door("windows:driver-blocklist", DOOR_CLOSED,
                    "Microsoft's vulnerable driver blocklist is enforced (memory integrity is running)")
    if value == 0:
        return Door("windows:driver-blocklist", DOOR_OPEN, "Microsoft's vulnerable driver blocklist is switched off",
                    "The blocklist stops Windows loading drivers with known holes - the ones used to switch off "
                    "antivirus. On current Windows 11 it is on by default, so it was switched off at some point - "
                    "some games' anti-cheat and hardware tools ask for that.",
                    "Windows Security > Device security > Core isolation details > switch on 'Microsoft Vulnerable "
                    "Driver Blocklist'.", "windowsdefender://coreisolation", "medium", "VulnerableDriverBlocklistEnable=0")
    if value == 1 or (value is None and build >= 22621):
        return Door("windows:driver-blocklist", DOOR_CLOSED, "Microsoft's vulnerable driver blocklist is on")
    if value is None and build:
        return Door("windows:driver-blocklist", DOOR_OPEN, "Microsoft's vulnerable driver blocklist is not switched on",
                    "On this version of Windows the blocklist is on only together with memory integrity. It stops "
                    "Windows loading drivers with known holes - the ones used to switch off antivirus.",
                    "Windows Security > Device security > Core isolation details > switch on 'Microsoft Vulnerable "
                    "Driver Blocklist' (or memory integrity).", "windowsdefender://coreisolation", "low",
                    "build {}, no blocklist setting".format(build))
    return Door("windows:driver-blocklist", DOOR_UNKNOWN, "Microsoft's vulnerable driver blocklist could not be read")


def dr_memory_integrity_door(running, configured, registry_enabled, holed_drivers=()):
    """Memory integrity (HVCI). `running`/`configured` come from Windows' Device Guard report (None when it could
    not be read); the registry value is only a fallback, because a setting can be on and still not running.
    `holed_drivers`: names of drivers with known holes found on this computer - a common reason it will not run."""
    if running is True:
        return Door("windows:memory-integrity", DOOR_CLOSED, "Memory integrity is on")
    why = ("Memory integrity keeps unsigned and tampered code out of the core of Windows, where spyware is hardest "
           "to find and remove.")
    fix = ("Windows Security > Device security > Core isolation details > Memory integrity. If Windows will not "
           "switch it on, that page lists the driver that blocks it - usually an old hardware or game tool.")
    if holed_drivers:
        fix += (" The drivers with known holes found on this computer ({}) are a common reason; updating or "
                "removing the program each came with often lets it switch on.".format(
                    ", ".join(sorted(set(holed_drivers))[:4])))
    if running is False and (configured or registry_enabled == 1):
        return Door("windows:memory-integrity", DOOR_OPEN, "Memory integrity is set to on but is not running",
                    why + " It is set to on, but Windows is not running it - often an incompatible driver, or a "
                    "restart that has not happened yet.", fix, "windowsdefender://coreisolation", "medium",
                    "configured, not running")
    if running is False or (running is None and registry_enabled == 0):
        return Door("windows:memory-integrity", DOOR_OPEN, "Memory integrity is off", why, fix,
                    "windowsdefender://coreisolation", "low")
    if running is None and registry_enabled == 1:
        return Door("windows:memory-integrity", DOOR_UNKNOWN,
                    "Memory integrity is set to on, but whether it is running could not be read")
    return Door("windows:memory-integrity", DOOR_UNKNOWN, "Memory integrity could not be read")


def dr_device_guard(text):
    """(running_hvci, configured_hvci) from 'Running=<n,..>;Configured=<n,..>', or (None, None)."""
    m = re.search(r"Running=([0-9, ]*);Configured=([0-9, ]*)", text or "")
    if not m:
        return None, None
    running = {p.strip() for p in m.group(1).split(",") if p.strip()}
    configured = {p.strip() for p in m.group(2).split(",") if p.strip()}
    return "2" in running, "2" in configured


def _check_windows_drivers(r):
    import winreg  # type: ignore
    if _dr_wow64():
        r.add_door(Door("windows:known-bad-drivers", DOOR_UNKNOWN,
                        "Installed drivers were not checked: 32-bit Python cannot see them on 64-bit Windows"))
        r.could_not_run("windows-drivers", "32-bit Python on 64-bit Windows is shown a different drivers folder - "
                                           "use 64-bit Python or the downloadable program")
        return
    system_root = os.environ.get("SystemRoot") or r"C:\Windows"
    if path_problem(system_root):
        system_root = r"C:\Windows"
    try:
        (service_paths, unresolved), services_read = _dr_driver_service_paths(system_root), True
    except OSError:
        service_paths, unresolved, services_read = [], 0, False
    paths, folder_read = dr_driver_paths(system_root, service_paths)
    matches, done, unread = dr_fingerprint_files(paths)
    dr_driver_doors(r, matches, done, unread, folder_read, services_read,
                    {os.path.normcase(p) for p in service_paths} if services_read else None, unresolved)
    hklm = winreg.HKEY_LOCAL_MACHINE
    try:
        code, out = _dr_ps("$g = Get-CimInstance -Namespace root\\Microsoft\\Windows\\DeviceGuard -ClassName "
                        "Win32_DeviceGuard -ErrorAction Stop; 'Running=' + ($g.SecurityServicesRunning -join ',') + "
                        "';Configured=' + ($g.SecurityServicesConfigured -join ',')")
        running, configured = dr_device_guard(out) if code == 0 else (None, None)
    except (OSError, subprocess.SubprocessError):
        running, configured = None, None
    registry = _reg(hklm, r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity",
                    "Enabled")
    r.add_door(dr_memory_integrity_door(running, configured, registry if isinstance(registry, int) else None,
                                        [os.path.basename(p) for p, _k, _n in matches]))
    value = _reg(hklm, r"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable")
    try:
        build = int(sys.getwindowsversion().build)
    except (AttributeError, ValueError):
        build = 0
    r.add_door(dr_blocklist_door(value if isinstance(value, int) else None, build, running is True))


# --- Windows settings -----------------------------------------------------------------------------------

def dr_firewall_state(text):
    """{profile: enabled} from 'Name Enabled' lines."""
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[1] in ("True", "False"):
            out[parts[0]] = parts[1] == "True"
    return out


_BITLOCKER = {1: "on", 2: "off", 3: "encrypting", 4: "decrypting", 5: "suspended", 6: "locked"}


def _check_windows(r):
    import winreg  # type: ignore
    hklm, hkcu = winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER
    # Remote Desktop
    deny = _reg(hklm, r"SYSTEM\CurrentControlSet\Control\Terminal Server", "fDenyTSConnections")
    if deny is None:
        r.add_door(Door("windows:remote-desktop", DOOR_UNKNOWN, "Remote Desktop setting could not be read"))
    elif int(deny) == 0:
        r.add_door(Door("windows:remote-desktop", DOOR_OPEN, "Remote Desktop is switched on",
                        "Anyone who knows or guesses a password on this computer can sign in to it remotely.",
                        "Turn it off unless you use it: Settings > System > Remote Desktop.",
                        "ms-settings:remotedesktop", "medium"))
    else:
        r.add_door(Door("windows:remote-desktop", DOOR_CLOSED, "Remote Desktop is off"))
    # Automatic sign-in (a password may sit in the registry in plain text) - the password itself is never read
    auto = _reg(hklm, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon")
    stored = _reg(hklm, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword") is not None
    if str(auto or "0").strip() == "1":
        r.add_door(Door("windows:automatic-sign-in", DOOR_OPEN,
                        "This computer signs in automatically" + (", with the password stored in the registry"
                                                                    if stored else ""),
                        "Anyone who switches it on is signed in as you - no password needed."
                        + (" The stored password can be read by any program running as administrator." if stored
                           else ""),
                        "Press Win+R, type netplwiz, tick 'Users must enter a user name and password to use this "
                        "computer', and press OK. Then change your Windows password.",
                        "", "high"))
    else:
        r.add_door(Door("windows:automatic-sign-in", DOOR_CLOSED, "Automatic sign-in is off"))
    # Sign-in required after sleep (power setting CONSOLELOCK); 1 = required
    # /qh includes hidden settings; the two 0x........ values are the AC and DC indexes (labels are translated
    # on non-English Windows, the hex values are not)
    rc, text = _dr_run(["powercfg", "/qh", "SCHEME_CURRENT", "SUB_NONE", "CONSOLELOCK"])
    values = re.findall(r":\s*0x([0-9a-f]{8})\b", text, re.I)[-2:]
    if rc == 0 and values:
        if any(int(v, 16) == 0 for v in values):
            r.add_door(Door("windows:sign-in-on-wake", DOOR_OPEN, "No password is asked when the computer wakes up",
                            "Someone who opens the lid while you are away gets straight in.",
                            "Settings > Accounts > Sign-in options > 'If you've been away, when should Windows "
                            "require you to sign in again?' > 'When PC wakes up from sleep'.",
                            "ms-settings:signinoptions", "medium"))
        else:
            r.add_door(Door("windows:sign-in-on-wake", DOOR_CLOSED, "A password is asked when the computer wakes up"))
    else:
        r.add_door(Door("windows:sign-in-on-wake", DOOR_UNKNOWN, "Sign-in after sleep could not be checked"))
    # Firewall
    rc, text = _dr_ps("Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { $_.Name + ' ' + $_.Enabled }")
    profiles = dr_firewall_state(text) if rc == 0 else {}
    off = sorted(p for p, on in profiles.items() if not on)
    if not profiles:
        r.add_door(Door("windows:firewall", DOOR_UNKNOWN, "Firewall state could not be read"))
    elif off:
        r.add_door(Door("windows:firewall", DOOR_OPEN, "The firewall is off for: {}".format(", ".join(off)),
                        "Programs listening on this computer can be reached by others on the same network.",
                        "Windows Security > Firewall & network protection > turn each network type on (or check "
                        "your antivirus, which may manage the firewall).",
                        "windowsdefender://network", "medium", ", ".join(off)))
    else:
        r.add_door(Door("windows:firewall", DOOR_CLOSED, "The firewall is on"))
    # Disk encryption (works without administrator rights through the shell's own property)
    rc, text = _dr_ps("(New-Object -ComObject Shell.Application).NameSpace($env:SystemDrive + '\\').Self."
                   "ExtendedProperty('System.Volume.BitLockerProtection')")
    state = _BITLOCKER.get(int(text.strip())) if rc == 0 and text.strip().isdigit() else None
    if state in ("on", "encrypting"):
        r.add_door(Door("windows:disk-encryption", DOOR_CLOSED, "The system drive is encrypted (BitLocker / "
                                                              "device encryption)"))
    elif state in ("off", "suspended", "decrypting"):
        r.add_door(Door("windows:disk-encryption", DOOR_OPEN, "The system drive is not encrypted",
                        "If the computer is taken, seized or left in a hotel, everything on it can be read by "
                        "removing the drive.",
                        "Settings > Privacy & security > Device encryption (Windows Home), or BitLocker Drive "
                        "Encryption (Pro). Save the recovery key somewhere safe - not only on this computer.",
                        "ms-settings:deviceencryption", "high", state))
    else:
        r.add_door(Door("windows:disk-encryption", DOOR_UNKNOWN, "Disk encryption could not be checked"))
    # Secure Boot
    sb = _reg(hklm, r"SYSTEM\CurrentControlSet\Control\SecureBoot\State", "UEFISecureBootEnabled")
    if sb is None:
        r.add_door(Door("windows:secure-boot", DOOR_UNKNOWN, "Secure Boot could not be checked"))
    elif int(sb) == 1:
        r.add_door(Door("windows:secure-boot", DOOR_CLOSED, "Secure Boot is on"))
    else:
        r.add_door(Door("windows:secure-boot", DOOR_OPEN, "Secure Boot is off",
                        "Secure Boot stops tampered start-up code from loading before Windows - the place the most "
                        "persistent spyware hides.",
                        "Turn it on in the computer's firmware (UEFI/BIOS) settings. Look up your computer model's "
                        "instructions first: some systems need settings changed in a specific order.",
                        "", "low"))
    # SMB1 (old file sharing with known worm-able flaws)
    smb1 = _reg(hklm, r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start")
    if smb1 is not None and int(smb1) != 4:
        r.add_door(Door("windows:smb1", DOOR_OPEN, "Old file sharing (SMB1) is installed",
                        "SMB1 has well-known flaws that let malware spread between computers on a network.",
                        "Control Panel > Programs > Turn Windows features on or off > untick 'SMB 1.0/CIFS File "
                        "Sharing Support'.", "ms-settings:optionalfeatures", "low"))
    else:
        r.add_door(Door("windows:smb1", DOOR_CLOSED, "Old file sharing (SMB1) is not installed"))
    # Administrators
    rc, text = _dr_ps("Get-LocalGroupMember -SID S-1-5-32-544 -ErrorAction Stop | Where-Object PrincipalSource -eq "
                   "'Local' | ForEach-Object { $_.Name }")
    admins = [a.strip() for a in text.splitlines() if a.strip()] if rc == 0 else None
    if admins is None:
        r.add_door(Door("windows:administrators", DOOR_UNKNOWN, "Administrator accounts could not be listed"))
    else:
        enabled = []
        rc2, users = _dr_ps("Get-LocalUser -ErrorAction Stop | Where-Object Enabled | ForEach-Object { $_.Name }")
        on = {u.strip().lower() for u in users.splitlines()} if rc2 == 0 else None
        for a in admins:
            short = a.split("\\")[-1]
            if on is None or short.lower() in on:
                enabled.append(_dr_clean(short, 60))
        if len(enabled) > 1:
            r.add_door(Door("windows:administrators", DOOR_OPEN,
                            "{} accounts can change everything on this computer".format(len(enabled)),
                            "Every administrator account can install hidden software and read other accounts' files. "
                            "An account you don't recognise is a way in.",
                            "Settings > Accounts > Other users: remove accounts you don't use, and make others "
                            "'Standard user'.", "ms-settings:otherusers", "low", ", ".join(enabled)))
        else:
            r.add_door(Door("windows:administrators", DOOR_CLOSED, "Only one administrator account"))
    r.ran("windows-settings")


# --- macOS settings -------------------------------------------------------------------------------------

def _listening(port):
    rc, text = _dr_run(["netstat", "-an"]) if sys.platform != "win32" else (1, "")
    return bool(re.search(r"[.:]{}\s+\S*\s*(\*[.:]\*|0\.0\.0\.0[.:]\*|\[::\]:\*)?\s*LISTEN".format(port), text))


def _check_macos(r):
    rc, text = _dr_run(["fdesetup", "status"])
    if rc == 0 and "FileVault is On" in text:
        r.add_door(Door("macos:disk-encryption", DOOR_CLOSED, "FileVault disk encryption is on"))
    elif rc == 0 and "FileVault is Off" in text:
        r.add_door(Door("macos:disk-encryption", DOOR_OPEN, "FileVault disk encryption is off",
                        "If the Mac is taken or seized, everything on it can be read.",
                        "System Settings > Privacy & Security > FileVault > Turn On. Keep the recovery key safe.",
                        "x-apple.systempreferences:com.apple.preference.security?FileVault", "high"))
    else:
        r.add_door(Door("macos:disk-encryption", DOOR_UNKNOWN, "FileVault could not be checked"))
    rc, text = _dr_run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    if rc == 0 and "enabled" in text.lower():
        r.add_door(Door("macos:firewall", DOOR_CLOSED, "The firewall is on"))
    elif rc == 0 and "disabled" in text.lower():
        r.add_door(Door("macos:firewall", DOOR_OPEN, "The firewall is off",
                        "Programs listening on this Mac can be reached by others on the same network.",
                        "System Settings > Network > Firewall > turn it on.",
                        "x-apple.systempreferences:com.apple.Network-Settings.extension", "medium"))
    else:
        r.add_door(Door("macos:firewall", DOOR_UNKNOWN, "Firewall state could not be read"))
    rc, text = _dr_run(["csrutil", "status"])
    if rc == 0 and "disabled" in text.lower():
        r.add_door(Door("macos:system-integrity", DOOR_OPEN, "System Integrity Protection is off",
                        "It stops programs - including spyware - from changing macOS itself.",
                        "Restart into Recovery, open Terminal, run 'csrutil enable', restart.", "", "high"))
    elif rc == 0 and "enabled" in text.lower():
        r.add_door(Door("macos:system-integrity", DOOR_CLOSED, "System Integrity Protection is on"))
    rc, text = _dr_run(["spctl", "--status"])
    if rc in (0, 1) and "disabled" in text.lower():
        r.add_door(Door("macos:gatekeeper", DOOR_OPEN, "Gatekeeper app checking is off",
                        "Any app, from anywhere, can run without macOS checking who made it.",
                        "Run 'sudo spctl --master-enable' in Terminal, then System Settings > Privacy & Security > "
                        "allow apps from 'App Store and identified developers'.",
                        "x-apple.systempreferences:com.apple.preference.security", "medium"))
    elif "enabled" in text.lower():
        r.add_door(Door("macos:gatekeeper", DOOR_CLOSED, "Gatekeeper app checking is on"))
    if _listening(22):
        r.add_door(Door("macos:remote-login", DOOR_OPEN, "Remote Login (SSH) is on",
                        "Anyone who knows or guesses a password on this Mac can sign in to it remotely.",
                        "System Settings > General > Sharing > turn off Remote Login.",
                        "x-apple.systempreferences:com.apple.Sharing-Settings.extension", "medium"))
    if _listening(5900):
        r.add_door(Door("macos:screen-sharing", DOOR_OPEN, "Screen Sharing or Remote Management is on",
                        "Someone on the network can see and control this screen.",
                        "System Settings > General > Sharing > turn off Screen Sharing and Remote Management.",
                        "x-apple.systempreferences:com.apple.Sharing-Settings.extension", "medium"))
    rc, text = _dr_run(["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"])
    if rc == 0 and text.strip():
        r.add_door(Door("macos:automatic-sign-in", DOOR_OPEN, "This Mac signs in automatically",
                        "Anyone who switches it on is signed in - no password needed.",
                        "System Settings > Users & Groups > 'Automatically log in as' > Off.",
                        "x-apple.systempreferences:com.apple.preferences.users", "high"))
    r.ran("macos-settings")


# --- Linux settings -------------------------------------------------------------------------------------

def dr_linux_root_encrypted(lsblk_json):
    """True / False / None from `lsblk -J -o NAME,TYPE,MOUNTPOINT,MOUNTPOINTS`: is / on a crypt device?"""
    try:
        devices = json.loads(lsblk_json).get("blockdevices", [])
    except (ValueError, AttributeError):
        return None

    def walk(nodes, crypt):
        for node in nodes or []:
            here = crypt or node.get("type") == "crypt"
            points = node.get("mountpoints") or [node.get("mountpoint")]
            if "/" in points:
                return here
            found = walk(node.get("children"), here)
            if found is not None:
                return found
        return None
    return walk(devices, False)


def _check_linux(r):
    rc, text = _dr_run(["lsblk", "-J", "-o", "NAME,TYPE,MOUNTPOINT"])
    enc = dr_linux_root_encrypted(text) if rc == 0 else None
    if enc is True:
        r.add_door(Door("linux:disk-encryption", DOOR_CLOSED, "The system disk is encrypted"))
    elif enc is False:
        r.add_door(Door("linux:disk-encryption", DOOR_OPEN, "The system disk is not encrypted",
                        "If the computer is taken or seized, everything on it can be read.",
                        "Encryption is chosen when Linux is installed (LUKS). Back up, then reinstall with "
                        "'Encrypt the new installation' ticked; meanwhile keep sensitive files in an encrypted "
                        "folder or volume.", "", "high"))
    else:
        r.add_door(Door("linux:disk-encryption", DOOR_UNKNOWN, "Disk encryption could not be checked"))
    rc, text = _dr_run(["ss", "-ltn"])
    if rc == 0 and re.search(r"LISTEN\s+\S+\s+\S+\s+(0\.0\.0\.0|\*|\[::\]):22\b", text):
        r.add_door(Door("linux:ssh-server", DOOR_OPEN, "An SSH server is accepting connections",
                        "Anyone on the network who knows or guesses a password can sign in remotely.",
                        "If you don't use it: sudo systemctl disable --now ssh (or sshd).", "", "medium"))
    elif rc == 0:
        r.add_door(Door("linux:ssh-server", DOOR_CLOSED, "No SSH server is accepting connections"))
    for path, rx in (("/etc/gdm3/custom.conf", r"^\s*AutomaticLoginEnable\s*=\s*true"),
                     ("/etc/gdm/custom.conf", r"^\s*AutomaticLoginEnable\s*=\s*true"),
                     ("/etc/lightdm/lightdm.conf", r"^\s*autologin-user\s*=\s*\S")):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                if re.search(rx, fh.read(65536), re.M | re.I):
                    r.add_door(Door("linux:automatic-sign-in", DOOR_OPEN, "This computer signs in automatically",
                                    "Anyone who switches it on is signed in - no password needed.",
                                    "Turn off automatic login in Settings > Users (or remove the setting from "
                                    + path + ").", "", "high"))
                    break
        except OSError:
            continue
    r.ran("linux-settings")


# --- browser extensions and signed-in accounts (all platforms) -----------------------------------------

_ALL_SITES = re.compile(r"^(<all_urls>|\*://\*/\*|https?://\*/\*|\*://\*\.?[^/]*/\*)$")


def dr_extension_info(manifest, messages=None):
    """(name, can_read_all_sites) from a Chromium extension manifest dict."""
    name = str(manifest.get("name", ""))
    m = re.fullmatch(r"__MSG_(\w+)__", name)
    if m and messages:
        name = str((messages.get(m.group(1)) or messages.get(m.group(1).lower()) or {}).get("message", name))
    hosts = list(manifest.get("host_permissions") or []) + [p for p in manifest.get("permissions") or []
                                                            if isinstance(p, str)]
    for cs in manifest.get("content_scripts") or []:
        hosts += cs.get("matches") or []
    broad = any(isinstance(h, str) and h in ("<all_urls>", "*://*/*", "http://*/*", "https://*/*") for h in hosts)
    return _dr_clean(name, 100), broad


def mask_email(address):
    """'sara@gmail.com' -> 's***@gmail.com'. Enough to recognise your own account, not to identify you."""
    address = str(address or "").strip()
    if "@" not in address:
        return ""
    user, domain = address.split("@", 1)
    return "{}***@{}".format(user[:1], _dr_clean(domain, 60))


def _read_json(path, limit=8 * 1024 * 1024):
    if path_problem(path):
        return None
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, encoding="utf-8-sig", errors="replace") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _bad_extension_ids():
    try:
        from ..extensiondata import BAD_EXTENSIONS
        return BAD_EXTENSIONS
    except ImportError:
        return {}


# Ad blockers that stop ad-delivered attacks well: uBlock Origin (and its Lite version) and AdGuard, by their store ids
# (Chrome/Edge and Firefox), and by name for copies from other stores. Brave blocks ads by itself.
DR_AD_BLOCKER_IDS = {
    "cjpalhdlnbpafiamejdnhcphjbkeiagm": "uBlock Origin", "ddkjiahejlhfcafbddmgiahcphecmpfh": "uBlock Origin Lite",
    "odfafepnkmbhccpbejgmiehpchacaeak": "uBlock Origin", "bgnkhhnnamicmpeenaelnjfhikgbkllg": "AdGuard",
    "uBlock0@raymondhill.net": "uBlock Origin", "adguardadblocker@adguard.com": "AdGuard",
}
_DR_AD_BLOCKER_NAMES = re.compile(r"(?i)\bublock origin\b|\badguard adblocker\b")


def dr_ad_blocker_door(r, seen, blockers, brave):
    """The browsers' ad blocking as a door: closed when a good blocker (or Brave) is there, open when browsers were
    read and none was found. Nothing is said when no browser could be read."""
    if blockers or brave:
        names = sorted(set(blockers)) + (["the Brave browser's own blocking"] if brave else [])
        r.add_door(Door("browser:ad-blocker", DOOR_CLOSED, "Ads are blocked in a browser here ({})".format(
            ", ".join(names)[:120])))
    elif seen or brave is False:
        r.add_door(Door("browser:ad-blocker", DOOR_OPEN, "No ad blocker was found in your browsers",
                        "Some spyware has been delivered through ordinary-looking ads. A good ad blocker stops "
                        "most of them from loading at all.",
                        "Install uBlock Origin from your browser's own extension store (on Chrome, uBlock Origin "
                        "Lite), or use the Brave browser, which blocks ads by itself.", "", "low"))


def _check_browsers(r):
    from .browser import CHROMIUM_ROOTS, _firefox_roots
    bad = _bad_extension_ids()
    broad_list, malicious, accounts, seen = [], [], [], 0
    blockers, brave = [], None
    for label, user_data in CHROMIUM_ROOTS:
        if not os.path.isdir(user_data):
            continue
        if label.startswith("brave"):
            brave = True
        state = _read_json(os.path.join(user_data, "Local State")) or {}
        cache = ((state.get("profile") or {}).get("info_cache") or {})
        for folder, info in cache.items():
            email = mask_email((info or {}).get("user_name", ""))
            if email:
                accounts.append("{} ({}): {}".format(label, _dr_clean((info or {}).get("name", folder), 40), email))
        for profile in _dr_listdir(user_data):
            ext_root = os.path.join(user_data, profile, "Extensions")
            for ext_id in _dr_listdir(ext_root):
                if not re.fullmatch(r"[a-p]{32}", ext_id):
                    continue
                versions = sorted(_dr_listdir(os.path.join(ext_root, ext_id)))
                if not versions:
                    continue
                base = os.path.join(ext_root, ext_id, versions[-1])
                manifest = _read_json(os.path.join(base, "manifest.json"), 2 * 1024 * 1024) or {}
                messages = (_read_json(os.path.join(base, "_locales", manifest.get("default_locale", "en"),
                                                    "messages.json"), 2 * 1024 * 1024) or {})
                name, broad = dr_extension_info(manifest, messages)
                seen += 1
                if ext_id in DR_AD_BLOCKER_IDS or _DR_AD_BLOCKER_NAMES.search(name or ""):
                    blockers.append(DR_AD_BLOCKER_IDS.get(ext_id) or _dr_clean(name, 40))
                where = "{} {}".format(label, profile)
                if ext_id in bad:
                    malicious.append("{} [{}] in {} - {}".format(name or ext_id, ext_id, where, bad[ext_id]))
                elif broad:
                    broad_list.append("{} ({})".format(name or ext_id, where))
    for label, profile_dir in _ff_profiles(_firefox_roots):
        data = _read_json(os.path.join(profile_dir, "extensions.json")) or {}
        for addon in data.get("addons") or []:
            if addon.get("location") != "app-profile" or not addon.get("active"):
                continue
            seen += 1
            name = _dr_clean((addon.get("defaultLocale") or {}).get("name") or addon.get("id", ""), 100)
            if addon.get("id") in DR_AD_BLOCKER_IDS or _DR_AD_BLOCKER_NAMES.search(name or ""):
                blockers.append(DR_AD_BLOCKER_IDS.get(addon.get("id")) or name[:40])
            perms = ((addon.get("userPermissions") or {}).get("origins") or [])
            if any(p in ("<all_urls>", "*://*/*") for p in perms):
                broad_list.append("{} ({})".format(name, label))
        signed = _read_json(os.path.join(profile_dir, "signedInUser.json")) or {}
        email = mask_email((signed.get("accountData") or {}).get("email", ""))
        if email:
            accounts.append("{}: {}".format(label, email))
    for item in malicious:
        r.add_door(Door("browser:malicious-extension", DOOR_OPEN, "A browser extension known to be malicious is "
                                                                   "installed",
                        "It was reported as stealing data or spying on browsing.",
                        "Remove it now (browser menu > Extensions), then change the passwords you used in that "
                        "browser - from another device if you can.", "", "high", _dr_clean(item, 300)))
    if broad_list:
        r.add_door(Door("browser:all-sites-extensions", DOOR_OPEN,
                        "{} browser extension(s) can read and change every website you visit".format(len(broad_list)),
                        "Such an extension sees your passwords, messages and banking as you type them. Many are "
                        "fine (password managers, ad blockers); one you don't recognise is a way in.",
                        "Open the browser's extensions page and remove any you don't know or no longer use.",
                        "", "low", _dr_clean("; ".join(broad_list[:12]) + (" ..." if len(broad_list) > 12 else ""),
                                             600)))
    elif seen:
        r.add_door(Door("browser:all-sites-extensions", DOOR_CLOSED, "No browser extension can read every website"))
    for item in accounts:
        r.add_lead(Lead("browser-accounts", _dr_clean(item, 200),
                        "A browser here is signed in and syncing to this account. Is it yours?",
                        "Usually your own account. A browser signed in to someone else's account sends them "
                        "your history, saved passwords and open tabs - a common way partners keep watch. Sign "
                        "out of any account that is not yours."))
    dr_ad_blocker_door(r, seen, blockers, brave)
    r.note("Browser extensions: {} checked{}.".format(
        seen, ", against {} known malicious ones".format(len(bad)) if bad else ""))
    r.ran("browser-extensions")


def _ff_profiles(firefox_roots):
    out = []
    try:
        roots = firefox_roots() if callable(firefox_roots) else firefox_roots
    except OSError:
        return out
    for item in roots or []:
        label, path = (item[0], item[-1]) if isinstance(item, (list, tuple)) else ("firefox", item)
        if os.path.isdir(path):
            for name in _dr_listdir(path):
                full = os.path.join(path, name)
                if os.path.isfile(os.path.join(full, "prefs.js")):
                    out.append(("{} {}".format(label, name), full))
            if os.path.isfile(os.path.join(path, "prefs.js")):
                out.append((label, path))
    return out


def run(ctx) -> ModuleResult:
    r = ModuleResult(NAME)
    ctx.partial = r
    r.note("Doors to close: settings and programs that make spying easier. Read only; nothing is changed.")
    platform_check = {"win32": _check_windows, "darwin": _check_macos}.get(sys.platform,
                                                                            _check_linux if sys.platform.startswith(
                                                                                "linux") else None)
    for check_name, check in (("remote-access-software", _check_programs),
                              ("remote-access-downloads", _check_downloads), ("system-settings", platform_check),
                              ("windows-drivers", _check_windows_drivers if sys.platform == "win32" else None),
                              ("browser-extensions", _check_browsers)):
        if check is None:
            continue
        try:
            check(r)
        except Exception as exc:  # noqa: BLE001 - one check failing must not hide the others
            r.could_not_run(check_name, "module error: {}".format(str(exc)[:160]))
    return r
