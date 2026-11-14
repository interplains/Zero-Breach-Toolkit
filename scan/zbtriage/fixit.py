"""Fix it for me (--fix-it): close the doors the scan found open, one at a time, with a way back.

Rules this follows, because a tool that changes a person's computer has to be trusted:
  * Nothing is changed unless the person names the fix and says yes to what it will do.
  * The current setting is read and written to an undo record FIRST. Without a record, the fix is not offered.
  * One change, one command. No batching, no silent elevation: on Windows the person sees Windows' own
    permission prompt for that single command.
  * Afterwards the setting is read back. The record says whether it took effect, so "done" is never assumed.
  * Anything that could lock a person out of their own computer, lose their data, or that a tool should not
    touch - disk encryption, Secure Boot, removing accounts, a computer an employer manages - is explained
    instead of done.
  * A password is never asked for, read or passed on. On macOS and Linux the exact command is printed for the
    person to run themselves with sudo.

Undo records live beside the toolkit's settings (one JSON file each) and `--undo-fix` puts a setting back.
"""
from __future__ import annotations

import datetime
import json
import os
import re
import subprocess
import sys
from typing import Callable, Dict, List, Optional, Tuple

FX_READY, FX_GUIDANCE, FX_NOT_OPEN, FX_MANAGED = "ready", "guidance", "not-open", "managed"
FX_TIMEOUT = 180


class FxError(ValueError):
    pass


# --- running things ------------------------------------------------------------------------------------------

def fx_run(argv, timeout=FX_TIMEOUT) -> Tuple[int, str]:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    try:
        done = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=timeout, creationflags=flags, stdin=subprocess.DEVNULL)
        return done.returncode, ((done.stdout or "") + "\n" + (done.stderr or "")).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, "{}: {}".format(exc.__class__.__name__, str(exc)[:200])


def _fx_ps_exe():
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0",
                       "powershell.exe")
    return exe if os.path.isfile(exe) else "powershell.exe"


def fx_powershell(script: str, timeout=FX_TIMEOUT) -> Tuple[int, str]:
    return fx_run([_fx_ps_exe(), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script],
                  timeout)


def fx_is_admin() -> bool:
    if sys.platform != "win32":
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def fx_elevated(script: str, timeout=FX_TIMEOUT) -> Tuple[int, str]:
    """Run ONE command with administrator rights. The person sees Windows' own permission prompt."""
    if sys.platform != "win32":
        raise FxError("elevation is only done on Windows")
    if fx_is_admin():
        return fx_powershell(script, timeout)
    import tempfile
    handle, out_path = tempfile.mkstemp(prefix="zb-fix-", suffix=".txt")
    os.close(handle)
    try:
        inner = ("$ErrorActionPreference='Continue'; try {{ & {{{script}}} *>&1 | Out-File -Encoding utf8 "
                 "-FilePath '{out}'; exit $LASTEXITCODE }} catch {{ $_ | Out-File -Encoding utf8 -FilePath "
                 "'{out}'; exit 1 }}").format(script=script.replace("'", "''"), out=out_path.replace("'", "''"))
        encoded = __import__("base64").b64encode(inner.encode("utf-16-le")).decode("ascii")
        launcher = ("$p = Start-Process -FilePath '{exe}' -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass',"
                    "'-EncodedCommand','{enc}' -Verb RunAs -Wait -WindowStyle Hidden -PassThru; "
                    "exit $p.ExitCode").format(exe=_fx_ps_exe(), enc=encoded)
        code, text = fx_powershell(launcher, timeout)
        try:
            with open(out_path, encoding="utf-8-sig", errors="replace") as fh:
                output = fh.read().strip()
        except OSError:
            output = ""
        if "canceled by the user" in text or "cancelled by the user" in text.lower():
            return 1, "you said no to the permission prompt; nothing was changed"
        return code, output or text
    finally:
        try:
            os.remove(out_path)
        except OSError:
            pass


# --- is this computer managed by someone else? ---------------------------------------------------------------

def fx_managed() -> Tuple[bool, str]:
    """(managed, who) - a work or school computer, where these settings belong to whoever runs it."""
    if sys.platform == "win32":
        code, text = fx_run([os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32",
                                          "dsregcmd.exe"), "/status"])
        if code == 0 and text:
            joined = {}
            for line in text.splitlines():
                if ":" in line:
                    key, _sep, value = line.partition(":")
                    joined[key.strip()] = value.strip().upper()
            for key, word in (("AzureAdJoined", "your organisation (Microsoft Entra / Azure AD)"),
                              ("DomainJoined", "a company or school domain"),
                              ("EnterpriseJoined", "your organisation")):
                if joined.get(key) == "YES":
                    return True, word
        code, text = fx_powershell("(Get-CimInstance -Namespace root/cimv2/mdm/dmmap -ClassName "
                                   "MDM_DevDetail_Ext01 -ErrorAction SilentlyContinue).DeviceHardwareData "
                                   "-ne $null")
        if code == 0 and text.strip().lower() == "true":
            return True, "a device-management service (MDM)"
        return False, ""
    if sys.platform == "darwin":
        code, text = fx_run(["/usr/bin/profiles", "status", "-type", "enrollment"])
        if code == 0 and "Enrolled via DEP: Yes" in text or "MDM enrollment: Yes" in text:
            return True, "a device-management service (MDM)"
        return False, ""
    return False, ""


# --- the fixes ------------------------------------------------------------------------------------------------

def _fx_reg_read(path: str, name: str) -> Tuple[bool, object]:
    """(exists, value) for a registry value, read with Windows' own tools."""
    code, text = fx_powershell("$v = Get-ItemProperty -Path '{p}' -Name '{n}' -ErrorAction SilentlyContinue; "
                               "if ($null -eq $v) {{ 'ABSENT' }} else {{ 'VALUE=' + $v.'{n}' }}".format(
                                   p=path, n=name))
    text = (text or "").strip()
    if code or not text or text == "ABSENT":
        return False, None
    if text.startswith("VALUE="):
        return True, text[6:].strip()
    return False, None


def _fx_reg_write(path: str, name: str, value, kind="DWord") -> str:
    return ("New-Item -Path '{p}' -Force | Out-Null; "
            "Set-ItemProperty -Path '{p}' -Name '{n}' -Value {v} -Type {t} -Force".format(
                p=path, n=name, v=value if kind == "DWord" else "'{}'".format(value), t=kind))


def _fx_reg_delete(path: str, name: str) -> str:
    return "Remove-ItemProperty -Path '{p}' -Name '{n}' -ErrorAction SilentlyContinue".format(p=path, n=name)


_FX_TS = r"HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
_FX_WINLOGON = r"HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"


def _fx_rdp_state():
    found, value = _fx_reg_read(_FX_TS, "fDenyTSConnections")
    return {"found": found, "value": value}


def _fx_rdp_apply(state):
    return _fx_reg_write(_FX_TS, "fDenyTSConnections", 1)


def _fx_rdp_undo(state):
    if not state.get("found"):
        return _fx_reg_delete(_FX_TS, "fDenyTSConnections")
    return _fx_reg_write(_FX_TS, "fDenyTSConnections", int(str(state["value"]).strip() or 0))


def _fx_rdp_ok():
    found, value = _fx_reg_read(_FX_TS, "fDenyTSConnections")
    return found and str(value).strip() == "1"


def _fx_autologon_state():
    found, value = _fx_reg_read(_FX_WINLOGON, "AutoAdminLogon")
    return {"found": found, "value": value}


def _fx_autologon_apply(state):
    return _fx_reg_write(_FX_WINLOGON, "AutoAdminLogon", 0, kind="String")


def _fx_autologon_undo(state):
    if not state.get("found"):
        return _fx_reg_delete(_FX_WINLOGON, "AutoAdminLogon")
    return _fx_reg_write(_FX_WINLOGON, "AutoAdminLogon", str(state["value"]).strip(), kind="String")


def _fx_autologon_ok():
    found, value = _fx_reg_read(_FX_WINLOGON, "AutoAdminLogon")
    return (not found) or str(value).strip() in ("0", "")


def _fx_firewall_state():
    code, text = fx_powershell("(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object { $_.Name + '=' + "
                               "$_.Enabled }) -join ';'")
    return {"profiles": (text or "").strip() if code == 0 else ""}


def _fx_firewall_apply(state):
    return "Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True"


def _fx_firewall_undo(state):
    parts = [p for p in (state.get("profiles") or "").split(";") if "=" in p]
    if not parts:
        raise FxError("the firewall's previous setting was not recorded")
    commands = []
    for part in parts:
        name, _sep, enabled = part.partition("=")
        if name.strip() in ("Domain", "Public", "Private"):
            commands.append("Set-NetFirewallProfile -Profile {} -Enabled {}".format(
                name.strip(), "True" if enabled.strip().lower() in ("true", "1") else "False"))
    return "; ".join(commands)


def _fx_firewall_ok():
    code, text = fx_powershell("((Get-NetFirewallProfile).Enabled -contains $false)")
    return code == 0 and text.strip().lower() == "false"


def _fx_smb1_state():
    code, text = fx_powershell("(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol "
                               "-ErrorAction SilentlyContinue).State")
    return {"state": (text or "").strip() if code == 0 else ""}


def _fx_smb1_apply(state):
    return "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"


def _fx_smb1_undo(state):
    return "Enable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"


def _fx_smb1_ok():
    code, text = fx_powershell("(Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol "
                               "-ErrorAction SilentlyContinue).State")
    return code == 0 and "disabl" in (text or "").lower()


FX_FIXES = {
    "windows:remote-desktop": {
        "platform": "win32", "title": "Switch Remote Desktop off",
        "does": "Tells Windows to refuse Remote Desktop connections (the fDenyTSConnections setting).",
        "warn": "If you or someone you trust connects to this computer remotely - a work support desk, your own "
                "laptop from elsewhere - that will stop working until you switch it back on.",
        "read": _fx_rdp_state, "apply": _fx_rdp_apply, "undo": _fx_rdp_undo, "verify": _fx_rdp_ok,
        "admin": True},
    "windows:automatic-sign-in": {
        "platform": "win32", "title": "Stop signing in automatically",
        "does": "Switches off automatic sign-in, so the computer asks for your password when it starts.",
        "warn": "Windows may still have your password stored from when automatic sign-in was set up. This fix "
                "stops it being used; to remove the stored password itself, open netplwiz and tick \"Users must "
                "enter a user name and password\". This tool never reads or touches the password.",
        "read": _fx_autologon_state, "apply": _fx_autologon_apply, "undo": _fx_autologon_undo,
        "verify": _fx_autologon_ok, "admin": True},
    "windows:firewall": {
        "platform": "win32", "title": "Switch the firewall on",
        "does": "Switches Windows' firewall on for all three profiles (Domain, Private, Public).",
        "warn": "If another security program manages your firewall, it may switch it back, or you may end up "
                "with both. Programs that accept connections may ask for permission again.",
        "read": _fx_firewall_state, "apply": _fx_firewall_apply, "undo": _fx_firewall_undo,
        "verify": _fx_firewall_ok, "admin": True},
    "windows:smb1": {
        "platform": "win32", "title": "Remove old file sharing (SMB1)",
        "does": "Removes the SMB1 feature, a 1980s file-sharing protocol with known, unfixable weaknesses.",
        "warn": "Needs a restart to finish. Very old network drives, printers and scanners can stop being "
                "reachable; if something does, the undo puts it back.",
        "read": _fx_smb1_state, "apply": _fx_smb1_apply, "undo": _fx_smb1_undo, "verify": _fx_smb1_ok,
        "admin": True},
}

# Doors a tool must not close by itself, with what to do instead.
FX_GUIDANCE_TEXT = {
    "windows:disk-encryption": (
        "Turning on BitLocker is not something this tool should do for you: it needs somewhere safe to keep the "
        "recovery key, and if that key is lost the data is gone for good.\n"
        "    Do it yourself: Settings > Privacy & security > Device encryption, or search for \"BitLocker\".\n"
        "    Save the recovery key somewhere away from this computer (printed, or in your password manager)."),
    "windows:secure-boot": (
        "Secure Boot lives in the computer's firmware, not in Windows, so it can only be switched on there.\n"
        "    Restart, open the firmware settings (usually F2, F10, DEL or ESC during start-up), find Secure "
        "Boot and enable it. The disk may need to be in UEFI/GPT mode first.\n"
        "    If you are not sure, this one is safe to leave: it matters most against someone who has the "
        "computer in their hands."),
    "windows:administrators": (
        "Removing an administrator account is left to you: done wrongly it can lock you out of your own "
        "computer.\n"
        "    Look at Settings > Accounts > Other users. An account you do not recognise, or one someone else "
        "set up, should be removed - but make sure you can still sign in as an administrator yourself first."),
    "macos:filevault": (
        "FileVault is best switched on through System Settings so macOS can help you keep the recovery key.\n"
        "    System Settings > Privacy & Security > FileVault > Turn On. Keep the recovery key somewhere away "
        "from this computer."),
    "macos:remote-login": (
        "Run this yourself, so you are the one approving it:\n"
        "    sudo systemsetup -setremotelogin off"),
    "macos:screen-sharing": (
        "Run this yourself:\n"
        "    sudo launchctl disable system/com.apple.screensharing"),
    "macos:firewall": (
        "Run this yourself:\n"
        "    sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on"),
    "linux:ssh-server": (
        "Run this yourself, if nothing you rely on connects to this computer:\n"
        "    sudo systemctl disable --now ssh    (or sshd, depending on the distribution)"),
    "linux:disk-encryption": (
        "Encrypting a disk that already holds your files cannot be done safely in place. It is set up when the "
        "system is installed, so this one means a reinstall - worth planning rather than rushing."),
    "linux:automatic-login": (
        "Switch this off in your desktop's own settings (Users / Login screen), or in the display manager's "
        "configuration (for example /etc/gdm3/custom.conf, AutomaticLoginEnable=false)."),
}


# --- undo records ---------------------------------------------------------------------------------------------

def fx_records_dir(config_dir=None) -> str:
    from .helperpack import hp_config_dir
    return os.path.join(config_dir or hp_config_dir(), "fixes")


def fx_write_record(door, state, commands, config_dir=None) -> str:
    folder = fx_records_dir(config_dir)
    os.makedirs(folder, exist_ok=True)
    when = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(folder, "{}-{}.json".format(when, re.sub(r"[^a-z0-9]+", "-", door.lower())))
    record = {"door": door, "title": FX_FIXES[door]["title"], "when_utc": when, "before": state,
              "applied": commands["apply"], "undo": commands["undo"], "result": "not run yet"}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(record, fh, indent=2)
    return path


def fx_update_record(path, **fields):
    try:
        with open(path, encoding="utf-8") as fh:
            record = json.load(fh)
    except (OSError, ValueError):
        return
    record.update(fields)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2)
    except OSError:
        pass


def fx_records(config_dir=None) -> List[dict]:
    folder = fx_records_dir(config_dir)
    out = []
    try:
        names = sorted(os.listdir(folder))
    except OSError:
        return out
    for name in names:
        if not name.endswith(".json"):
            continue
        try:
            with open(os.path.join(folder, name), encoding="utf-8") as fh:
                record = json.load(fh)
            record["path"] = os.path.join(folder, name)
            record["name"] = name[:-5]
            out.append(record)
        except (OSError, ValueError):
            continue
    return out


# --- what can be done ----------------------------------------------------------------------------------------

def _fx_door_checker():
    """(the doors check for this system, the result class) - found the same way in the package and in the
    single-file build, where the modules are all one namespace and there is nothing to import."""
    name = {"win32": "_check_windows", "darwin": "_check_macos"}.get(sys.platform)
    if name is None:
        name = "_check_linux" if sys.platform.startswith("linux") else None
    if name is None:
        return None, None
    here = globals()                     # the single-file build: every module is one namespace already
    if name in here and "ModuleResult" in here:
        return here[name], here["ModuleResult"]
    try:                                 # the package: import by name, so the single-file build keeps no
        from importlib import import_module      # dangling reference to a stripped relative import
        where = __package__ or "zbtriage"
        doors_module = import_module(where + ".modules.doors")
        result_module = import_module(where + ".result")
        return getattr(doors_module, name, None), result_module.ModuleResult
    except Exception:  # noqa: BLE001 - without the doors check there is nothing to offer
        return None, None


def fx_open_doors(doors=None) -> List[dict]:
    """The doors the scan finds open on this computer, as plain dicts."""
    if doors is None:
        checker, make_result = _fx_door_checker()
        if checker is None or make_result is None:
            return []
        result = make_result("doors")
        try:
            checker(result)
        except Exception:  # noqa: BLE001 - a door that cannot be read is simply not offered
            pass
        doors = [d.to_dict() for d in result.doors]
    return [d for d in doors if d.get("state") == "open"]


def fx_plan(doors=None, managed=None, config_dir=None) -> Dict[str, object]:
    is_managed, who = fx_managed() if managed is None else managed
    open_doors = fx_open_doors(doors)
    offers, guidance = [], []
    for door in open_doors:
        name = door.get("door", "")
        fix = FX_FIXES.get(name)
        if fix and fix["platform"] == sys.platform:
            if is_managed:
                guidance.append({"door": name, "title": door.get("title", name),
                                 "text": "This computer is managed by {}. These settings are theirs to change, "
                                         "and a change here is likely to be undone or to break something. Ask "
                                         "whoever supports it.".format(who), "state": FX_MANAGED})
            else:
                offers.append({"door": name, "title": fix["title"], "was": door.get("title", name),
                               "does": fix["does"], "warn": fix["warn"], "admin": fix["admin"],
                               "state": FX_READY})
        elif name in FX_GUIDANCE_TEXT:
            guidance.append({"door": name, "title": door.get("title", name), "text": FX_GUIDANCE_TEXT[name],
                             "state": FX_GUIDANCE})
        else:
            guidance.append({"door": name, "title": door.get("title", name),
                             "text": door.get("fix") or "There is no safe automatic fix for this one.",
                             "state": FX_GUIDANCE})
    return {"managed": is_managed, "managed_by": who, "offers": offers, "guidance": guidance,
            "records": fx_records(config_dir), "admin": fx_is_admin()}


def fx_apply(door: str, confirm: Optional[Callable[[str], bool]] = None, config_dir=None,
             runner=None) -> Dict[str, object]:
    """Apply one fix. Returns what happened; nothing is changed unless confirm() says yes."""
    fix = FX_FIXES.get(door)
    if not fix:
        raise FxError("there is no automatic fix for " + door)
    if fix["platform"] != sys.platform:
        raise FxError("that fix is for a different kind of computer")
    is_managed, who = fx_managed()
    if is_managed:
        return {"door": door, "done": False, "why": "this computer is managed by {}; ask whoever supports "
                                                    "it".format(who)}
    state = fix["read"]()
    try:
        commands = {"apply": fix["apply"](state), "undo": fix["undo"](state)}
    except FxError as exc:
        return {"door": door, "done": False, "why": "the current setting could not be recorded, so the fix was "
                                                    "not offered ({})".format(exc)}
    question = ("{}\n  What it does: {}\n  Before you say yes: {}\n  A way back is saved first, and "
                "--undo-fix puts it back.".format(fix["title"], fix["does"], fix["warn"]))
    if confirm is not None and not confirm(question):
        return {"door": door, "done": False, "why": "you did not say yes; nothing was changed"}
    record = fx_write_record(door, state, commands, config_dir)
    run = runner or (fx_elevated if fix["admin"] else fx_powershell)
    code, output = run(commands["apply"])
    worked = fix["verify"]()
    fx_update_record(record, result="done" if worked else "did not take effect",
                     output=(output or "")[:2000], exit_code=code)
    return {"door": door, "done": bool(worked), "record": record, "output": (output or "")[:1000],
            "why": "" if worked else "the command ran but the setting did not change ({})".format(
                (output or "no output").splitlines()[0][:160] if output else "no output"),
            "needs_restart": door == "windows:smb1" and worked}


def fx_undo(name: str, confirm: Optional[Callable[[str], bool]] = None, config_dir=None,
            runner=None) -> Dict[str, object]:
    matches = [r for r in fx_records(config_dir) if r.get("name") == name or r.get("path") == name
               or r.get("door") == name]
    if not matches:
        raise FxError("no undo record called " + name)
    record = matches[-1]
    command = record.get("undo")
    if not command:
        raise FxError("that record has nothing to undo")
    if confirm is not None and not confirm("Put '{}' back as it was ({})?".format(record.get("title", ""),
                                                                                 record.get("when_utc", ""))):
        return {"done": False, "why": "you did not say yes; nothing was changed"}
    fix = FX_FIXES.get(record.get("door")) or {}
    run = runner or (fx_elevated if fix.get("admin", True) else fx_powershell)
    code, output = run(command)
    fx_update_record(record["path"], result="undone" if code == 0 else "undo failed",
                     undo_output=(output or "")[:2000])
    return {"done": code == 0, "record": record["path"], "output": (output or "")[:1000],
            "why": "" if code == 0 else (output or "the command failed").splitlines()[0][:160]}


# --- words ---------------------------------------------------------------------------------------------------

from .safetext import safe_render  # noqa: E402
from .i18n import T, TX  # noqa: E402


# Sentences the English report splits over two lines; another language gets the whole sentence on one line
# (st_wrap_lines then wraps it), so translators never see half a sentence.
_FX_MANAGED_SENTENCE = ("Settings like these belong to whoever supports it: a change made here is likely to be put "
                        "back automatically, or to break something they rely on. Ask them instead.")
_FX_ADMIN_SENTENCE = ("These need administrator rights. You will see Windows' own permission prompt for each single "
                      "command, so you can see exactly what is being run.")


def _fx_sentence(full, english_lines, indent):
    translated = T(full)
    if translated == full:
        return list(english_lines)
    return [indent + translated]


@safe_render
def fx_render(plan) -> str:
    lines = ["=" * 72, "  " + T("CLOSE THE DOORS FOUND OPEN"),
             "  " + T("Nothing has been changed. Each fix is applied only when you ask for it by name."), "=" * 72, ""]
    if plan["managed"]:
        lines += ["  " + T("This computer is managed by {who}.", who=plan["managed_by"])]
        lines += _fx_sentence(_FX_MANAGED_SENTENCE,
                              ["  Settings like these belong to whoever supports it: a change made here is likely to "
                               "be put",
                               "  back automatically, or to break something they rely on. Ask them instead."], "  ")
        lines += [""]
    if plan["offers"]:
        lines.append("  " + T("CAN BE DONE FOR YOU"))
        for offer in plan["offers"]:
            lines += ["    {}  ({})".format(T(offer["title"]), offer["door"]),
                      "      " + T("now: {state}", state=TX(offer["was"])),
                      "      " + T("what it does: {does}", does=T(offer["does"])),
                      "      " + T("before you say yes: {warn}", warn=T(offer["warn"])),
                      "      " + T("to do it: {command}", command="zero-breach-toolkit --fix-it " + offer["door"]),
                      ""]
        if not plan["admin"] and sys.platform == "win32":
            lines += _fx_sentence(_FX_ADMIN_SENTENCE,
                                  ["    These need administrator rights. You will see Windows' own permission prompt "
                                   "for each",
                                   "    single command, so you can see exactly what is being run."], "    ")
            lines += [""]
    if plan["guidance"]:
        lines.append("  " + T("BETTER DONE BY YOU"))
        for item in plan["guidance"]:
            lines.append("    {}".format(TX(item["title"])))
            for line in TX(item["text"]).splitlines():
                lines.append("      " + line.strip())
            lines.append("")
    if not plan["offers"] and not plan["guidance"]:
        lines += ["  " + T("Nothing is open that needs closing."), ""]
    if plan["records"]:
        lines.append("  " + T("WHAT HAS BEEN CHANGED BEFORE (each can be put back)"))
        for record in plan["records"][-12:]:
            lines.append("    {}  {}  - {}".format(record.get("when_utc", ""), T(record.get("title", "")) if
                                                   record.get("title") else "", TX(record.get("result", ""))))
        lines += ["    " + T("to put one back: {command}", command="zero-breach-toolkit --undo-fix {}".format(
            plan["records"][-1].get("name", ""))), ""]
    from .safetext import st_wrap_lines
    return "\n".join(st_wrap_lines(lines))


def fx_command(args, out=print, ask=None) -> int:
    door = getattr(args, "fix_it", None)
    undo = getattr(args, "undo_fix", None)
    if undo:
        try:
            result = fx_undo(undo, confirm=ask, runner=None)
        except FxError as exc:
            out(T("Nothing was changed: {why}", why=TX(str(exc))))
            return 2
        out(T("Put back.") if result["done"] else T("Not put back: {why}", why=TX(result["why"])))
        return 0 if result["done"] else 2
    if door and door != "list":
        try:
            result = fx_apply(door, confirm=ask)
        except FxError as exc:
            out(T("Nothing was changed: {why}", why=TX(str(exc))))
            return 2
        if result["done"]:
            out(T("Done. A way back is saved; put it back with:") + "\n  zero-breach-toolkit --undo-fix " +
                os.path.basename(result["record"])[:-5])
            if result.get("needs_restart"):
                out(T("This one finishes after you restart the computer."))
            return 0
        out(T("Nothing was changed: {why}", why=TX(result["why"])))
        return 2
    out(fx_render(fx_plan()))
    return 0


def fx_ask_terminal(question: str) -> bool:
    """Ask on the terminal, printing exactly what will happen. Anything but a clear yes means no."""
    import sys as _sys
    _sys.stderr.write("\n  " + question + "\n  " + T("Go ahead? (type yes)") + " ")
    _sys.stderr.flush()
    line = _sys.stdin.readline()
    return bool(line) and line.strip().lower() in ("yes", "y")
