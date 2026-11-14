"""What starts automatically (--startup): every program set to start with the computer or at sign-in, offline.

Spyware has to start again after a restart, so it has to register somewhere. This check lists those places in
plain words and marks what deserves a second look; it changes nothing.

  Windows: Run / RunOnce keys (per user, machine-wide, 32-bit view, policy), whether Windows has them switched off
           (StartupApproved), Startup folders (shortcuts resolved), scheduled tasks, auto-start services and drivers,
           Winlogon shell/userinit, debugger hijacks (Image File Execution Options), AppInit DLLs.
           Each program's signature is checked with Windows' own verifier, offline.
  macOS:   LaunchAgents and LaunchDaemons outside /System, login and background items (BTM), and which apps were
           allowed to record the screen, use the camera or microphone, see key presses, control the computer or
           read all files (TCC). The last two need Full Disk Access or sudo; otherwise reported as not readable.
  Linux:   desktop autostart entries, enabled systemd units, cron.

Each program is fingerprinted (SHA-256) and compared with the indicator lists, and its name with the list of
remote-access and monitoring programs. Levels: known-threat, worth-a-look, nothing-known.
"""
from __future__ import annotations

import glob
import hashlib
import ntpath
import os
import plistlib
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
from typing import Dict, List, Tuple

SU_KNOWN, SU_LOOK, SU_NOTHING = "known-threat", "worth-a-look", "nothing-known"
SU_HASH_LIMIT = 200 * 1024 * 1024
SU_TASK_LIMIT = 4000

_SU_SCRIPT_HOSTS = ("powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                    "rundll32.exe", "regsvr32.exe", "conhost.exe")
_SU_ENCODED = re.compile(r"(?i)(?:^|\s)-e(?:nc(?:odedcommand)?|c)?\s+[A-Za-z0-9+/=]{40,}")
_SU_DOWNLOADER = re.compile(r"(?i)(downloadstring|downloadfile|invoke-webrequest|\biwr\b|\birm\b|"
                            r"invoke-restmethod|bitsadmin|certutil\s+-urlcache|https?://)")

_SU_TCC = {"kTCCServiceScreenCapture": "record the screen",
           "kTCCServiceListenEvent": "see every key pressed (Input Monitoring)",
           "kTCCServiceAccessibility": "control the computer (Accessibility)",
           "kTCCServicePostEvent": "send key presses and clicks",
           "kTCCServiceMicrophone": "use the microphone",
           "kTCCServiceCamera": "use the camera",
           "kTCCServiceSystemPolicyAllFiles": "read all files (Full Disk Access)",
           "kTCCServiceAddressBook": "read contacts",
           "kTCCServiceCalendar": "read the calendar",
           "kTCCServicePhotos": "read photos",
           "kTCCServiceAppleEvents": "control other apps"}
_SU_TCC_WATCH = {"kTCCServiceScreenCapture", "kTCCServiceListenEvent", "kTCCServiceAccessibility",
                 "kTCCServicePostEvent"}


def su_entry(where, name, command, enabled=True, kind="program", note=""):
    return {"where": where, "name": str(name)[:200], "command": str(command or "")[:2000], "enabled": enabled,
            "kind": kind, "note": note}


# --- the program a command runs ---------------------------------------------------------------------------------

def su_program(command: str) -> Tuple[str, str]:
    """(program path, file it is given) for a command line; Windows environment variables expanded."""
    cmd = os.path.expandvars(command.strip()).replace("\\??\\", "")
    if cmd.lower().startswith("\\systemroot\\"):
        cmd = os.environ.get("SystemRoot", r"C:\Windows") + cmd[11:]
    elif cmd.lower().startswith("system32\\"):
        cmd = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), cmd)
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        prog, rest = (cmd[1:end], cmd[end + 1:]) if end > 0 else (cmd[1:], "")
    else:
        m = re.match(r"(?i)^(.+?\.(?:exe|com|bat|cmd|scr|dll|ps1|vbs|js|lnk|sys|app))(?:\s|$)(.*)", cmd)
        if m:
            prog, rest = m.group(1), m.group(2)
        else:
            prog, _sep, rest = cmd.partition(" ")
    prog, rest = prog.strip(), rest.strip()
    given = ""
    base = os.path.basename(prog).lower()
    if base in ("rundll32.exe", "rundll32") and rest:
        given = rest.split(",")[0].strip().strip('"')
    elif base in ("wscript.exe", "cscript.exe", "regsvr32.exe", "mshta.exe") and rest:
        parts = [p for p in re.findall(r'"[^"]+"|\S+', rest) if not p.startswith(("/", "-"))]
        given = parts[0].strip('"') if parts else ""
    elif base in ("powershell.exe", "pwsh.exe", "powershell", "pwsh"):
        m = re.search(r'(?i)-f(?:ile)?\s+("[^"]+"|\S+)', rest)
        given = m.group(1).strip('"') if m else ""
    elif base in ("cmd.exe", "cmd"):
        m = re.search(r'(?i)/[ck]\s+("[^"]+"|\S+)', rest)
        given = m.group(1).strip('"') if m else ""
    if prog and not os.path.isabs(prog) and sys.platform == "win32" and "\\" not in prog:
        found = shutil.which(prog)
        prog = found or prog
    if given and not os.path.isabs(given) and sys.platform == "win32" and "\\" not in given:
        given = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", given)
    return prog, given


_SU_SCRIPT_EXT = (".ps1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".py", ".sh")


def su_unquoted(command: str, exists=os.path.exists) -> Tuple[str, bool]:
    """(intended program, whether it exists) for a command whose path has a space but no quotes; ('', False) if the
    command is not like that."""
    cmd = command.strip()
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        if end < 0:
            return "", False
        head, rest = cmd[1:end], cmd[end + 1:].split()
    else:
        parts = cmd.split()
        head, rest = (parts[0], parts[1:]) if parts else ("", [])
    # A Windows path is absolute whatever system this runs on: os.path alone follows the host's rules, so on
    # Linux or macOS "C:\..." never counted and the check silently found nothing (found running the suite on Linux).
    if not head or not (os.path.isabs(head) or ntpath.isabs(head)) or exists(head):
        return "", False
    for k in range(1, min(len(rest), 6) + 1):
        candidate = " ".join([head] + rest[:k])
        if exists(candidate):
            return candidate, True
    if rest and not rest[0].startswith(("-", "/")) and ("\\" in rest[0] or "/" in rest[0]):
        return " ".join([head, rest[0]]), False
    return "", False


def _su_user_writable(path: str) -> bool:
    if not path:
        return False
    low = os.path.normcase(os.path.abspath(path))
    roots = [os.path.expanduser("~"), tempfile.gettempdir(), os.environ.get("PUBLIC", ""), "/tmp", "/var/tmp",
             "/dev/shm", "/Users/Shared"]
    for root in roots:
        if root and (low + os.sep).startswith(os.path.normcase(os.path.abspath(root)) + os.sep):
            return True
    return False


def _su_hashes(path: str) -> Tuple[str, str]:
    """(SHA-256, SHA-1) of a program, or ('', '') if unreadable or larger than the limit."""
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > SU_HASH_LIMIT:
            return "", ""
        h256, h1 = hashlib.sha256(), hashlib.sha1()  # noqa: S324 - SHA-1 only to match published indicators
        with open(path, "rb") as fh:
            for block in iter(lambda: fh.read(1 << 20), b""):
                h256.update(block)
                h1.update(block)
        return h256.hexdigest(), h1.hexdigest()
    except OSError:
        return "", ""


def _su_sign(path: str) -> str:
    if sys.platform == "win32":
        from .winsign import ws_status
        return ws_status(path)
    if sys.platform == "darwin":
        return _su_mac_sign(path)
    return ""


def _su_mac_sign(path: str) -> str:
    """'signed (Team ID ...)' / 'Apple' / 'not-signed' using codesign (offline: no notarization lookup)."""
    target = path
    m = re.match(r"(.+?\.app)(/|$)", path)
    if m:
        target = m.group(1)
    if not os.path.exists(target):
        return "missing"
    try:
        done = subprocess.run(["/usr/bin/codesign", "-dv", "--verbose=2", target], capture_output=True, text=True,
                              timeout=20, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    text = done.stderr or ""
    if "not signed" in text:
        return "not-signed"
    if "Authority=Software Signing" in text or "Authority=Apple Code Signing" in text:
        return "signed (Apple)"
    team = re.search(r"TeamIdentifier=(\S+)", text)
    if team and team.group(1) != "not":
        return "signed (Team ID {})".format(team.group(1))
    if "adhoc" in text.lower():
        return "not-signed"
    return "unknown"


# --- Windows -----------------------------------------------------------------------------------------------------

def su_approved_on(value: bytes) -> bool:
    """Task Manager's Startup switch from a StartupApproved value: on when the first byte is even (2 or 6)."""
    return bool(value) and value[0] % 2 == 0


def _su_reg_values(root, path, view=0):
    import winreg  # type: ignore
    out = []
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as key:
            i = 0
            while True:
                try:
                    name, value, _t = winreg.EnumValue(key, i)
                except OSError:
                    break
                out.append((name, value))
                i += 1
    except OSError:
        return None
    return out


def _su_reg_subkeys(root, path, view=0):
    import winreg  # type: ignore
    out = []
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ | view) as key:
            i = 0
            while True:
                try:
                    out.append(winreg.EnumKey(key, i))
                except OSError:
                    break
                i += 1
    except OSError:
        return None
    return out


def _su_windows(gaps: List[str]) -> List[dict]:
    import winreg  # type: ignore
    HKCU, HKLM = winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE
    W32 = getattr(winreg, "KEY_WOW64_32KEY", 0)
    entries = []
    approved = {}       # Task Manager's on/off switch: first byte 2 (or 6) = on, 1 / 3 / 7 = off
    for root, scope in ((HKCU, "HKCU"), (HKLM, "HKLM")):
        for sub in ("Run", "Run32", "StartupFolder"):
            for name, value in _su_reg_values(root, "Software\\Microsoft\\Windows\\CurrentVersion\\Explorer"
                                              "\\StartupApproved\\" + sub) or []:
                if isinstance(value, bytes) and value:
                    approved[(scope, sub, name.lower())] = su_approved_on(value)
    scopes = {"Run key (this user)": ("HKCU", "Run"), "Run key (all users)": ("HKLM", "Run"),
              "Run key (all users, 32-bit)": ("HKLM", "Run32"), "Startup folder (this user)": ("HKCU", "StartupFolder"),
              "Startup folder (all users)": ("HKLM", "StartupFolder")}

    def switched_on(where, name):
        scope = scopes.get(where)
        return approved.get(scope + (name.lower(),), True) if scope else True
    run_keys = [(HKCU, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, "Run key (this user)"),
                (HKCU, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0, "RunOnce key (this user)"),
                (HKCU, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", 0,
                 "policy Run key (this user)"),
                (HKLM, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, "Run key (all users)"),
                (HKLM, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", W32, "Run key (all users, 32-bit)"),
                (HKLM, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", 0, "RunOnce key (all users)"),
                (HKLM, "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", W32, "RunOnce key (all users, 32-bit)"),
                (HKLM, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run", 0,
                 "policy Run key (all users)")]
    seen = set()
    for root, path, view, where in run_keys:
        for name, value in _su_reg_values(root, path, view) or []:
            key = (where.split(",")[0], name.lower(), str(value).lower())
            if key in seen or not value:
                continue
            seen.add(key)
            entries.append(su_entry(where, name, value, switched_on(where, name)))
    folders = [(os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
                "Startup folder (this user)"),
               (os.path.join(os.environ.get("PROGRAMDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
                "Startup folder (all users)")]
    from .shelllinks import shelllink_content
    for folder, where in folders:
        for path in sorted(glob.glob(os.path.join(folder, "*"))):
            name = os.path.basename(path)
            if name.lower() == "desktop.ini":
                continue
            command = path
            try:
                with open(path, "rb") as fh:
                    raw = fh.read(1024 * 1024)
            except OSError:
                raw = b""
            if name.lower().endswith(".lnk"):
                active, _ref, _ok = shelllink_content(raw)
                command = active or su_lnk_fallback(raw) or path
            elif name.lower().endswith((".cmd", ".bat")):
                command = su_batch_command(raw) or path
            entries.append(su_entry(where, name, command, switched_on(where, name)))
    winlogon = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    for value_name, default in (("Shell", "explorer.exe"), ("Userinit", r"C:\Windows\system32\userinit.exe,")):
        for root in (HKLM, HKCU):
            vals = dict(_su_reg_values(root, winlogon) or [])
            v = vals.get(value_name)
            if v and v.strip().lower().rstrip(",") != default.lower().rstrip(","):
                entries.append(su_entry("Winlogon " + value_name, value_name, v, kind="hijack",
                                        note="the program Windows starts at sign-in was changed from the normal {}"
                                        .format(default)))
    ifeo = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
    for sub in _su_reg_subkeys(HKLM, ifeo) or []:
        vals = dict(_su_reg_values(HKLM, ifeo + "\\" + sub) or [])
        if vals.get("Debugger"):
            entries.append(su_entry("debugger hijack (IFEO)", sub, vals["Debugger"], kind="hijack",
                                    note="whenever {} is started, Windows starts this instead".format(sub)))
    for view in (0, W32):
        vals = dict(_su_reg_values(HKLM, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows", view) or [])
        if vals.get("AppInit_DLLs") and vals.get("LoadAppInit_DLLs") == 1:
            entries.append(su_entry("AppInit DLLs", "AppInit_DLLs", vals["AppInit_DLLs"], kind="hijack",
                                    note="loaded into every program that shows a window"))
    services = r"SYSTEM\CurrentControlSet\Services"
    for sub in _su_reg_subkeys(HKLM, services) or []:
        vals = dict(_su_reg_values(HKLM, services + "\\" + sub) or [])
        start, stype, image = vals.get("Start"), vals.get("Type", 0), vals.get("ImagePath")
        if not image or start not in (0, 1, 2) or not isinstance(stype, int):
            continue
        is_driver = bool(stype & 0x3)
        if is_driver and start not in (0, 1, 2):
            continue
        dll = ""
        if not is_driver:
            params = dict(_su_reg_values(HKLM, services + "\\" + sub + "\\Parameters") or [])
            dll = params.get("ServiceDll", "") if "svchost" in str(image).lower() else ""
        entries.append(su_entry("driver" if is_driver else "service", vals.get("DisplayName", sub) if
                                not str(vals.get("DisplayName", "")).startswith("@") else sub,
                                dll or image, kind="driver" if is_driver else "service"))
    entries += _su_tasks(gaps)
    return entries


def su_lnk_fallback(raw: bytes) -> str:
    """The program path in a shortcut the strict parser refused: the longest drive-letter path to a program
    or script found inside it."""
    found = []
    for text in (raw.decode("utf-16-le", "ignore"), raw.decode("latin-1")):
        found += re.findall(r"[A-Za-z]:\\[^\x00-\x1f\"<>|?*]{1,400}?\.(?:exe|bat|cmd|com|vbs|ps1)\b", text)
    return max(found, key=len) if found else ""


def su_batch_command(raw: bytes) -> str:
    """The first real command of a .cmd / .bat file (comments, echo off and labels skipped)."""
    text = raw[:65536].decode("utf-8", "replace")
    for line in text.splitlines():
        s = line.strip().lstrip("@")
        low = s.lower()
        if not s or low.startswith(("rem", "::", "echo off", "echo on", ":", "setlocal", "endlocal", "title ",
                                    "chcp ", "cls")):
            continue
        return s[:2000]
    return ""


def su_tasks_from_xml(blob: str) -> List[Tuple[str, str, bool]]:
    """[(task name, command, enabled)] from `schtasks /query /xml ONE` output or one task's XML."""
    import xml.etree.ElementTree as ET
    out = []
    parts = re.split(r"<!--\s*(\\[^>]*?)\s*-->", blob)
    pairs = list(zip(parts[1::2], parts[2::2])) if len(parts) > 1 else [("", blob)]
    for name, chunk in pairs:
        start, end = chunk.find("<Task"), chunk.find("</Task>")
        if start < 0 or end < 0 or "<!DOCTYPE" in chunk.upper():
            continue
        try:
            tree = ET.fromstring(chunk[start:end + 7])
        except ET.ParseError:
            continue
        enabled = _su_task_settings_enabled(tree) is not False
        for el in tree.iter():
            if el.tag.rsplit("}", 1)[-1] != "Exec":
                continue
            cmd = arg = ""
            for child in el:
                ctag = child.tag.rsplit("}", 1)[-1]
                if ctag == "Command":
                    cmd = (child.text or "").strip()
                elif ctag == "Arguments":
                    arg = (child.text or "").strip()
            if cmd:
                out.append((name.strip().lstrip("\\"), ('"{}" {}'.format(cmd.strip('"'), arg)).strip(), enabled))
    return out


def _su_tasks(gaps):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    system32 = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
    try:
        done = subprocess.run([os.path.join(system32, "schtasks.exe"), "/query", "/xml", "ONE"], capture_output=True,
                              timeout=120, creationflags=flags, stdin=subprocess.DEVNULL)
        blob = done.stdout.decode("utf-16") if done.stdout[:2] in (b"\xff\xfe", b"\xfe\xff") else \
            done.stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError, UnicodeError) as exc:
        gaps.append("scheduled tasks could not be listed ({})".format(str(exc)[:80]))
        return []
    tasks = su_tasks_from_xml(blob)
    if not tasks:
        gaps.append("scheduled tasks could not be listed")
    if len(tasks) > SU_TASK_LIMIT:
        gaps.append("more than {} scheduled task actions; the rest were not listed".format(SU_TASK_LIMIT))
    return [su_entry("scheduled task", name, command, enabled, kind="task")
            for name, command, enabled in tasks[:SU_TASK_LIMIT]]


def _su_task_settings_enabled(tree):
    """The task-level Settings/Enabled flag (False = switched off), ignoring trigger-level flags."""
    for el in tree:
        if el.tag.rsplit("}", 1)[-1] == "Settings":
            for child in el:
                if child.tag.rsplit("}", 1)[-1] == "Enabled":
                    return (child.text or "").strip().lower() != "false"
    return None


# --- macOS -------------------------------------------------------------------------------------------------------

def _su_plist(path):
    try:
        with open(path, "rb") as fh:
            return plistlib.load(fh)
    except Exception:  # noqa: BLE001 - malformed property lists are simply skipped
        return None


def _su_mac(gaps: List[str]) -> List[dict]:
    entries = []
    home = os.path.expanduser("~")
    for folder, where in ((os.path.join(home, "Library/LaunchAgents"), "LaunchAgent (this user)"),
                          ("/Library/LaunchAgents", "LaunchAgent (all users)"),
                          ("/Library/LaunchDaemons", "LaunchDaemon (system)")):
        for path in sorted(glob.glob(os.path.join(folder, "*.plist"))):
            data = _su_plist(path)
            if not isinstance(data, dict):
                gaps.append("could not read {}".format(path))
                continue
            args = data.get("ProgramArguments") or []
            prog = data.get("Program") or (args[0] if args else "")
            command = " ".join('"{}"'.format(a) if " " in str(a) else str(a) for a in ([prog] + list(args[1:])))
            enabled = not data.get("Disabled", False)
            entries.append(su_entry(where, data.get("Label") or os.path.basename(path), command, enabled,
                                    kind="launchd", note="" if data.get("RunAtLoad") or data.get("KeepAlive")
                                    else "starts on a schedule or when asked"))
    btm = sorted(glob.glob("/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm"))
    btm += glob.glob(os.path.join(home, "Library/Application Support/com.apple.backgroundtaskmanagementagent/"
                                        "backgrounditems.btm"))
    read_any = False
    for path in btm[-2:]:
        data = _su_plist(path)
        if data is None:
            continue
        read_any = True
        for item in su_btm_items(data):
            entries.append(su_entry("login / background item", os.path.basename(item.rstrip("/")), item,
                                    kind="btm"))
    if not read_any:
        gaps.append("login and background items (BTM) need sudo to read on this macOS; System Settings > General > "
                    "Login Items shows them")
    return entries


def su_btm_items(data) -> List[str]:
    """Application and program paths named in a BTM store (an NSKeyedArchiver property list)."""
    objects = data.get("$objects", []) if isinstance(data, dict) else []
    found = []
    for obj in objects:
        if isinstance(obj, str):
            s = obj[7:] if obj.startswith("file://") else obj
            if s.startswith("/") and (".app" in s or "/bin/" in s or s.endswith((".sh", ".py"))) and \
                    not s.startswith("/System/") and s not in found:
                found.append(s)
    return found[:500]


def su_tcc(paths=None) -> Tuple[List[dict], List[str]]:
    """[{service, meaning, client}] allowed in TCC databases, and gaps."""
    home = os.path.expanduser("~")
    paths = paths or [os.path.join(home, "Library/Application Support/com.apple.TCC/TCC.db"),
                      "/Library/Application Support/com.apple.TCC/TCC.db"]
    grants, gaps = [], []
    for path in paths:
        if not os.path.exists(path):
            continue
        tmp = tempfile.mkdtemp(prefix="zb-tcc-")
        con = None
        try:
            copy = os.path.join(tmp, "TCC.db")
            shutil.copyfile(path, copy)
            for suffix in ("-wal", "-shm"):
                if os.path.exists(path + suffix):
                    shutil.copyfile(path + suffix, copy + suffix)
            from .localpaths import open_evidence_db
            con = open_evidence_db(copy)
            cols = {row[1] for row in con.execute("PRAGMA table_info(access)")}
            allowed = "auth_value = 2" if "auth_value" in cols else "allowed = 1"
            for service, client in con.execute("SELECT service, client FROM access WHERE " + allowed):
                if service in _SU_TCC:
                    grants.append({"service": service, "meaning": _SU_TCC[service], "client": str(client)[:300]})
        except PermissionError:
            gaps.append("app permissions (TCC) at {} need Full Disk Access for this terminal or app".format(path))
        except (OSError, sqlite3.Error) as exc:
            gaps.append("app permissions at {} could not be read ({})".format(path, str(exc)[:80]))
        finally:
            if con is not None:
                con.close()
            shutil.rmtree(tmp, ignore_errors=True)
    return grants, gaps


# --- Linux -------------------------------------------------------------------------------------------------------

def _su_linux(gaps: List[str]) -> List[dict]:
    import configparser
    entries = []
    home = os.path.expanduser("~")
    cfg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    for folder, where in ((os.path.join(cfg, "autostart"), "autostart (this user)"),
                          ("/etc/xdg/autostart", "autostart (all users)")):
        for path in sorted(glob.glob(os.path.join(folder, "*.desktop"))):
            parser = configparser.RawConfigParser(strict=False, interpolation=None)
            try:
                parser.read(path, encoding="utf-8")
                sec = parser["Desktop Entry"]
            except (configparser.Error, KeyError, OSError, UnicodeError):
                continue
            hidden = sec.get("Hidden", "false").lower() == "true" or \
                sec.get("X-GNOME-Autostart-enabled", "true").lower() == "false"
            entries.append(su_entry(where, sec.get("Name", os.path.basename(path)), sec.get("Exec", ""), not hidden,
                                    kind="autostart"))
    for folder, where in ((os.path.join(cfg, "systemd/user"), "systemd unit (this user)"),
                          ("/etc/systemd/system", "systemd unit (system)"),
                          ("/etc/systemd/user", "systemd unit (all users)")):
        for link in sorted(glob.glob(os.path.join(folder, "*.wants", "*"))):
            unit = os.path.realpath(link)
            command = ""
            try:
                with open(unit, encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        if line.strip().startswith("ExecStart="):
                            command = line.split("=", 1)[1].strip().lstrip("-@+!:")
                            break
            except OSError:
                pass
            if command:
                entries.append(su_entry(where, os.path.basename(link), command, kind="systemd"))
    for path in sorted(glob.glob("/etc/cron.d/*")) + ["/etc/crontab"]:
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    s = line.strip()
                    if s and not s.startswith("#") and not re.match(r"^\w+=", s):
                        parts = s.split(None, 6)
                        if len(parts) == 7:
                            entries.append(su_entry("cron (system)", os.path.basename(path), parts[6], kind="cron"))
        except OSError:
            continue
    try:
        done = subprocess.run(["crontab", "-l"], capture_output=True, text=True, timeout=10, stdin=subprocess.DEVNULL)
        for line in (done.stdout or "").splitlines():
            s = line.strip()
            if s and not s.startswith("#") and not re.match(r"^\w+=", s):
                parts = s.split(None, 5)
                if len(parts) == 6:
                    entries.append(su_entry("cron (this user)", "crontab", parts[5], kind="cron"))
                elif s.startswith("@") and len(s.split(None, 1)) == 2:
                    entries.append(su_entry("cron (this user)", "crontab", s.split(None, 1)[1], kind="cron"))
    except (OSError, subprocess.SubprocessError):
        pass
    return entries


# --- judging -----------------------------------------------------------------------------------------------------

def _su_vendor_system(path: str) -> bool:
    low = os.path.normcase(path)
    if sys.platform == "win32":
        win = os.path.normcase(os.environ.get("SystemRoot", r"C:\Windows"))
        return low.startswith(win + os.sep)
    return low.startswith(("/system/", "/usr/libexec/", "/usr/sbin/", "/usr/bin/", "/bin/", "/sbin/",
                           "/usr/lib/", "/lib/"))


def su_judge(entries, iocs=None, sign=None, hashes=None, exists=None):
    """Add program, signature, fingerprints and reasons to each entry; return (level, entries)."""
    from .accessdata import ACCESS_PROGRAMS
    sign = sign or _su_sign
    hashes = hashes or _su_hashes
    exists = exists or os.path.exists
    access = [(n, k, re.compile(rx, re.I)) for n, k, rx in ACCESS_PROGRAMS]
    level = SU_NOTHING
    cache: Dict[str, tuple] = {}
    for e in entries:
        prog, given = su_program(e["command"]) if e["command"] else ("", "")
        e["program"], e["given"] = prog, given
        reasons, known = [], None
        target = given if given and os.path.basename(prog).lower() in _SU_SCRIPT_HOSTS else prog
        e["target"] = target
        on_disk = bool(target) and exists(target)
        e["exists"] = on_disk
        if on_disk:
            if target not in cache:
                cache[target] = (sign(target),) + tuple(hashes(target))
            e["signature"], e["sha256"], e["sha1"] = cache[target]
        else:
            e["signature"], e["sha256"], e["sha1"] = ("missing" if target else ""), "", ""
        if iocs is not None:
            for value in (e["sha256"], e["sha1"]):
                ind = iocs.lookup(value) if value else None
                if ind is not None and ind.type in ("sha256", "sha1"):
                    known = ind
                    break
        if known:
            e["indicator"] = {"value": known.value, "family": known.family or "spyware", "source": known.source}
        text = " ".join((e["name"], e["command"]))
        for program, kind, rx in access:
            if rx.search(text):
                reasons.append("{} is a {} program: fine if you installed it, a way in if you did not".format(
                    program, kind))
                break
        if e["kind"] == "hijack":
            reasons.append(e["note"])
        if _SU_ENCODED.search(e["command"]):
            reasons.append("runs a hidden (encoded) PowerShell command")
        elif os.path.basename(prog).lower() in _SU_SCRIPT_HOSTS and _SU_DOWNLOADER.search(e["command"]):
            reasons.append("downloads something from the internet each time it starts")
        sig = e["signature"]
        what = "script" if target.lower().endswith(_SU_SCRIPT_EXT) else "program"
        unquoted, unquoted_there = ("", False) if on_disk or not target else su_unquoted(e["command"], exists)
        if unquoted and not unquoted_there:
            reasons.append("points to {}, which is not there (left over from something removed); its path also lacks "
                           "quotes around a space, so as set up it could never have run".format(unquoted))
        elif unquoted:
            reasons.append("BROKEN: the path has a space but no quotes, so Windows tries to start {} - which does not "
                           "exist - instead of {}. It never runs, and a file put at that name would run in its place. "
                           "Re-create it with the path in quotes".format(target, unquoted))
        if on_disk and _su_user_writable(target) and sig in ("not-signed", "bad-signature"):
            reasons.append("an unsigned {} in a folder any program you run can change ({}) - check you know what it "
                           "is".format(what, os.path.dirname(target)))
        elif on_disk and sig == "bad-signature":
            reasons.append("its signature does not match the file or comes from an untrusted publisher")
        elif on_disk and _su_vendor_system(target) and sig == "not-signed" and e["kind"] in ("service", "driver"):
            reasons.append("an unsigned {} inside the Windows folder".format(e["kind"]))
        if target and not on_disk and not unquoted and os.path.isabs(target) and e["kind"] != "btm" and \
                _su_user_writable(target):
            reasons.append("points to a program that is not there (left over, or deleted after it ran)")
        e["reasons"] = reasons
        if known:
            level = SU_KNOWN
        elif reasons and level == SU_NOTHING and e.get("enabled", True):
            level = SU_LOOK
    return level, entries


def su_inventory(iocs=None) -> Dict[str, object]:
    gaps: List[str] = []
    grants: List[dict] = []
    if sys.platform == "win32":
        entries = _su_windows(gaps)
    elif sys.platform == "darwin":
        entries = _su_mac(gaps)
        grants, tcc_gaps = su_tcc()
        gaps += tcc_gaps
    elif sys.platform.startswith("linux"):
        entries = _su_linux(gaps)
    else:
        entries = []
        gaps.append("this system is not supported")
    level, entries = su_judge(entries, iocs)
    level = _su_grants_level(grants, level)
    return {"level": level, "entries": entries, "grants": grants, "gaps": gaps, "platform": sys.platform}


def _su_grants_level(grants, level):
    from .accessdata import ACCESS_PROGRAMS
    access = [(n, re.compile(rx, re.I)) for n, _k, rx in ACCESS_PROGRAMS]
    for g in grants:
        g["reasons"] = []
        if g["service"] in _SU_TCC_WATCH:
            for program, rx in access:
                if rx.search(g["client"]):
                    g["reasons"].append("{} (remote access / monitoring) may {}".format(program, g["meaning"]))
                    break
        if g["reasons"] and level == SU_NOTHING:
            level = SU_LOOK
    return level


# --- report ------------------------------------------------------------------------------------------------------

_SU_HEAD = {SU_KNOWN: "KNOWN SPYWARE is set to start automatically", SU_LOOK: "WORTH A LOOK",
            SU_NOTHING: "NOTHING KNOWN starts automatically"}
_SU_SIGN_WORDS = {"signed": "signed", "not-signed": "NOT SIGNED", "bad-signature": "BAD SIGNATURE",
                  "expired-signature": "signed (certificate expired)", "missing": "file missing", "unknown": "",
                  "": ""}
_SU_HOW_OFF = {"win32": "To switch something off: Task Manager > Startup apps (Run keys and Startup folder), Task "
                        "Scheduler (tasks) or Services. Uninstall from Settings > Apps if you do not recognise it.",
               "darwin": "To switch something off: System Settings > General > Login Items; to remove an app's "
                         "permission: System Settings > Privacy & Security.",
               "linux": "To switch something off: your desktop's Startup Applications, or systemctl disable."}


def su_headline(result) -> str:
    return T(_SU_HEAD[result["level"]])


from .safetext import safe_render  # noqa: E402
from .i18n import T, TX  # noqa: E402


# What each kind of startup entry is, for someone who is not technical.
SU_KIND_MEANING = {
    "program": "It opens by itself when you sign in.",
    "autostart": "It opens by itself when you sign in.",
    "service": "Windows runs it in the background by itself, for every user, even before anyone signs in.",
    "driver": "It becomes part of Windows itself once loaded - the most powerful kind of program.",
    "task": "A scheduled task: Windows runs it at set times or when something happens.",
    "hijack": "It changes how Windows starts other programs - used by some legitimate tools, and by spyware to "
              "hide itself.",
    "launchd": "macOS starts it by itself, at login or when the Mac starts.",
    "btm": "macOS lists it as allowed to run in the background.",
    "systemd": "Linux starts it by itself, at boot or when you log in.",
    "cron": "A scheduled job: the system runs it at set times.",
}


def su_file_date(path: str) -> str:
    """The program file's date ("2026-11-02"), a hint of when it arrived - or "" when it cannot be read."""
    import datetime
    try:
        if path and os.path.isfile(path):
            return datetime.datetime.fromtimestamp(os.path.getmtime(path)).strftime("%Y-%m-%d")
    except (OSError, ValueError, OverflowError):
        pass
    return ""


@safe_render
def su_render(result, show_all=False) -> str:
    entries = result["entries"]
    lines = ["=" * 72, "  " + T("WHAT STARTS AUTOMATICALLY") + "  -  " + T(_SU_HEAD[result["level"]]),
             "  " + T("Read only: nothing was changed, nothing was contacted."), "=" * 72, ""]
    flagged = [e for e in entries if e.get("indicator") or e["reasons"]]
    if any(e.get("indicator") for e in entries):
        lines.append("  " + T("KNOWN SPYWARE"))
        for e in entries:
            if e.get("indicator"):
                lines.append("    - " + T("{name} ({where}): {target} - listed as {family} ({source})",
                                          name=e["name"], where=TX(e["where"]), target=e["target"],
                                          family=e["indicator"]["family"], source=e["indicator"]["source"]))
        lines += ["", "    " + T("Do not delete it yet - it is evidence. Get expert help: Access Now Helpline "
                                 "https://www.accessnow.org/help/ (24/7)."), ""]
    looks = [e for e in flagged if e["reasons"] and not e.get("indicator")]
    if looks:
        lines.append("  " + T("WORTH A LOOK"))
        for e in looks:
            state = "" if e.get("enabled", True) else " [" + T("switched off") + "]"
            lines.append("    - {}{} ({})".format(e["name"], state, TX(e["where"])))
            lines.append("        " + T("runs: {command}", command=e["command"][:200]))
            if SU_KIND_MEANING.get(e.get("kind")):
                lines.append("        " + T("means: {meaning}", meaning=T(SU_KIND_MEANING[e["kind"]])))
            dated = su_file_date(e.get("target", ""))
            if dated:
                lines.append("        " + T("dated: {date} (the program file's date - a hint of when it arrived)",
                                            date=dated))
            for reason in e["reasons"]:
                lines.append("        " + T("why: {reason}", reason=TX(reason)))
        lines.append("")
    grant_looks = [g for g in result["grants"] if g.get("reasons")]
    if grant_looks:
        lines.append("  " + T("APP PERMISSIONS WORTH A LOOK"))
        for g in grant_looks:
            lines.append("    - " + "; ".join(TX(r) for r in g["reasons"]) + " ({})".format(g["client"]))
        lines.append("")
    groups: Dict[str, List[dict]] = {}
    for e in entries:
        if not show_all and e["kind"] in ("service", "driver", "task") and _su_vendor_system(e.get("target", "")) \
                and not e["reasons"] and e.get("signature") in ("signed", "signed (Apple)"):
            continue
        groups.setdefault(e["where"], []).append(e)
    lines.append("  " + T("EVERYTHING THAT STARTS") + ("" if show_all else " " + T(
        "(signed Windows / system components hidden; --startup-all shows them)")))
    for where, items in groups.items():
        lines.append("    " + TX(where))
        for e in items[:300]:
            sig = _SU_SIGN_WORDS.get(e.get("signature", ""), e.get("signature", ""))
            sig = T(sig) if sig else ""
            state = "" if e.get("enabled", True) else ", " + T("switched off")
            lines.append("      {}  -  {}{}{}".format(e["name"][:60], (e.get("target") or e["command"])[:110],
                                                    "  [" + sig + state + "]" if sig or state else "", ""))
    if not entries:
        lines.append("    " + T("nothing found"))
    if result["grants"]:
        lines += ["", "  " + T("APPS ALLOWED TO...")]
        by_service: Dict[str, List[str]] = {}
        for g in result["grants"]:
            by_service.setdefault(g["meaning"], []).append(g["client"])
        for meaning, clients in by_service.items():
            lines.append("    {}: {}".format(TX(meaning), ", ".join(sorted(set(clients))[:30])))
    if result["gaps"]:
        lines += ["", "  " + T("NOT READ")]
        lines += ["    - " + TX(g) for g in result["gaps"]]
    how_off = _SU_HOW_OFF.get("linux" if result["platform"].startswith("linux") else result["platform"], "")
    lines += ["", "  " + (T(how_off) if how_off else ""),
              "  " + T("Not recognising something is not proof of spyware: look the name up, or ask someone you "
                       "trust.")]
    from .safetext import st_wrap_lines
    return "\n".join(st_wrap_lines(lines))


def su_saved(result) -> dict:
    """The saved result (also read by the household report)."""
    import datetime
    looks = [e for e in result["entries"] if e.get("indicator") or e["reasons"]]
    return dict(result, tool="zero-breach-toolkit startup inventory",
                made=datetime.datetime.now().astimezone().replace(microsecond=0).isoformat(),
                summary="{} things start automatically, {} worth a look".format(len(result["entries"]), len(looks)),
                findings=["{} ({}): {}".format(e["name"], e["where"], "; ".join(e["reasons"]) or "known spyware")
                          for e in looks])


def su_save(result, path) -> None:
    import json
    with open(path, "x", encoding="utf-8") as fh:
        json.dump(su_saved(result), fh, indent=2, ensure_ascii=False)


def su_command(args, load_iocs, out=print) -> int:
    import json
    try:
        iocs = load_iocs(args)
    except Exception as exc:  # noqa: BLE001
        out("(" + T("Indicator lists could not be loaded: {why}. Listing without them.", why=str(exc)[:160]) + ")")
        iocs = None
    result = su_inventory(iocs)
    out(su_render(result, show_all=bool(getattr(args, "startup_all", False))))
    if getattr(args, "json", None):
        with open(args.json, "x", encoding="utf-8") as fh:
            json.dump(su_saved(result), fh, indent=2, ensure_ascii=False)
        out("\n" + T("Saved: {path}", path=args.json))
    return {SU_KNOWN: 3, SU_LOOK: 1, SU_NOTHING: 0}[result["level"]]
