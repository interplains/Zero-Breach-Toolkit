"""Host module — per-user COM persistence, DNS cache, DNS history, hosts file.

Ported from scripts/scan_host.ps1. Four checks, and the reason each one exists:

  1. com-persistence. Citizen Lab's write-up of this Candiru chain says it
     persists via a COM hijack. The technique registers a CLSID under HKCU,
     and Windows resolves HKCU\\Software\\Classes before the machine-wide HKLM
     registration — so a *per-user* InprocServer32 pointing at a DLL in a
     user-writable directory gets loaded into every process that instantiates
     that class, with no admin rights and no service or Run key to find.
     That is the whole appeal of the technique, and it is why this check looks
     at HKCU and not HKLM.
     Legitimate per-user COM registrations absolutely do exist (the reference
     machine had 37 of them), so this check LISTS them for review; it does not
     call them malicious. Per D4 (precision over coverage) an unsigned DLL in
     %LOCALAPPDATA% is not a finding on its own — plenty of honest software
     ships exactly that — so a Hit is emitted only when a registered path
     contains an actual indicator string.

  2. dns-cache. The local resolver cache, which is a record of what this boot
     has already looked up. Reading it resolves nothing: the entries are
     answers the OS kept from queries that already happened (D2).

  3. dns-log. This is the check that matters most in the whole project, and it
     usually FAILS. Microsoft-Windows-DNS-Client/Operational is disabled by
     default on Windows, so on a typical machine there is no DNS history to
     query at all — meaning past contact with a C&C domain cannot be ruled out
     retrospectively, only *future* contact can. Reporting that gap out loud is
     the point; silently reporting "clean" here would be a lie (D3). The report
     prints the one manual command that turns the log on for next time.

  4. hosts-file. Cheap. An indicator pointed at a sink address is a deliberate
     *block* (protective, not reported as a hit); only a mapping to a real
     address is a finding.

Read-only throughout: this module never writes the registry, never enables the
log, and needs no administrator (D7).
"""

from __future__ import annotations

import io
import ipaddress
import json
import os
from ..localpaths import path_problem
import platform
import sys
import re
import subprocess

from ..result import (Hit, Lead, ModuleResult, EV_DNS, EV_ATTEMPTED,
                      EV_PERSISTENCE, EV_CONFIGURED, EV_REFERENCED, EV_ON_DISK)

NAME = "host"

# winreg is Windows-only; a non-Windows import must not break the package.
try:
    import winreg  # type: ignore
except ImportError:  # pragma: no cover - non-Windows
    winreg = None  # type: ignore

# Resolve PowerShell by its absolute path, never the bare name. Invoked as
# "powershell", Windows resolves it through the executable search order - which
# includes the CURRENT DIRECTORY before System32. The tool tells users to run it
# from their Downloads folder, a user-writable location, so a planted
# powershell.exe there would be executed in its place (issue #7). An absolute
# path is never resolved through that search, so only the real interpreter at
# the System32 location can run; if it is not there, the call fails to a gap
# rather than ever executing a same-named file from elsewhere.
_PS_EXE = os.path.join(os.environ.get("SystemRoot") or r"C:\Windows",
                       "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
# A directory the scanner does not control, used as the child's working
# directory so it cannot inherit a hostile CWD either.
_PS_CWD = os.environ.get("SystemRoot") or r"C:\Windows"
def powershell_env():
    """Environment for PowerShell: modules load only from Windows' own folder, so
    a module installed in the user's profile cannot stand in for a built-in
    command and forge results."""
    env = dict(os.environ)
    env["PSModulePath"] = os.path.join(os.environ.get("SystemRoot") or r"C:\Windows",
                                       "System32", "WindowsPowerShell", "v1.0", "Modules")
    return env


_PS = [_PS_EXE, "-NoProfile", "-NonInteractive",
       "-ExecutionPolicy", "Bypass", "-Command"]

_DNS_LOG = "Microsoft-Windows-DNS-Client/Operational"
_DNS_EVENT_CAP = 50000

# Addresses that mean "this name was deliberately pointed nowhere". Shared by the
# hosts-file check and the resolver-cache check, because the two have to make the
# SAME judgement about the same address: a name answered with one of these was
# blocked by a filter, not reached. This project publishes hosts-file blocklists
# that map these very indicators to 0.0.0.0, so anyone who took our own advice
# will have exactly these entries - and telling them their device "communicated
# with" israeli spyware infrastructure would be a false alarm aimed at precisely
# the people the tool is for.
_SINK_ADDRESSES = {"0.0.0.0", "127.0.0.1", "::1", "::", "0:0:0:0:0:0:0:1"}


def _dns_answer_blocked(message: str) -> bool:
    """True when a DNS-Client event's results hold addresses and every one is a
    block address (the form a hosts-file or DNS blocklist answers with)."""
    low = (message or "").lower()
    at = low.rfind("results")
    if at < 0:
        return False
    addresses = []
    for part in low[at + len("results"):].split(";"):
        token = part.strip().strip(",.").strip()
        try:
            ipaddress.ip_address(token)
        except ValueError:
            continue
        addresses.append(token)
    return bool(addresses) and all(_is_sink(a) for a in addresses)


def _is_sink(address: str) -> bool:
    """True for an address that cannot be a remote destination: any loopback or
    unspecified address, in any spelling.

    The literal set above missed 127.0.0.2, ::ffff:127.0.0.1 and the fully
    written-out forms, so a blocklist using one of them was reported as a DNS
    record, which is a finding with exit 2, for someone who had protected
    themselves. 0.0.0.0/8 beyond 0.0.0.0 itself is deliberately not included:
    some current Linux kernels accept parts of it as real addresses.
    """
    text = (address or "").strip().lower()
    if text in _SINK_ADDRESSES:
        return True
    try:
        ip = ipaddress.ip_address(text.split("%", 1)[0])
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    if mapped is not None:
        ip = mapped
    return ip.is_loopback or ip.is_unspecified

# The sub-keys under a CLSID that name a server binary, in the order the PoC
# checks them. InprocHandler32 is included because it is loaded the same way
# and is the quieter of the three.
_SERVER_KINDS = ("InprocServer32", "LocalServer32", "InprocHandler32")
_COM_PATTERN_CANDIDATE_CAP = 128

# HKCU CLSID. Both the 64-bit and 32-bit registry views must be read, and the
# right way is explicit KEY_WOW64_*KEY flags on the ONE logical path - not two
# literal paths. Opening the literal "...\WOW6432Node\CLSID" works only from a
# 64-bit interpreter; from a 32-bit one the plain path is itself redirected into
# WOW6432Node and the literal WOW6432Node path becomes a doubly-nested key that
# does not exist, so the native view - where a hijack lives on a 64-bit box - goes
# unread. winreg may lack the flags on a 32-bit-only build, hence the getattr.
_CLSID_PATH = r"Software\Classes\CLSID"
_REG_VIEWS = [("native", getattr(winreg, "KEY_WOW64_64KEY", 0)),
              ("wow6432", getattr(winreg, "KEY_WOW64_32KEY", 0))]
# ERROR_NO_MORE_ITEMS: the only winerror that means "enumeration finished" rather
# than "enumeration failed". Anything else mid-walk is a truncation, not an end.
_ERROR_NO_MORE_ITEMS = 259

# Exact text required when there is no DNS history to query. Do not reword:
# this gap is the single most important finding the tool can report.
_DNS_LOG_GAP = (
    "DNS-Client/Operational log is disabled (the Windows default) — there is "
    "no queryable DNS history, so past activity cannot be checked "
    "retrospectively from this host")

_ARM_HINT = ("dns-log: Windows is not recording DNS history on this machine. See "
             "\"HOW TO TURN ON DNS HISTORY\" in this report to start a record a future scan "
             "can search. It cannot answer the question for the past.")

# Spelled out, because "enable DNS logging" is not an instruction most people can
# act on, and this is the single highest-value thing a reader can actually do.
# One manual command only: the tool deliberately does not write to the system in
# this release, so there is nothing here that could get the step wrong or need an
# undo. Turn it off again with the same command and /e:false.
_HOW_TO_ENABLE = [
    "HOW TO TURN ON DNS HISTORY (so a future scan can answer this):",
    "  One command, in an Administrator PowerShell:",
    "    1. Click Start, type \"PowerShell\", right-click it, \"Run as administrator\".",
    "    2. Paste this line and press Enter:",
    "         wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true /ms:67108864",
    "  (/e:true turns the log on; /ms sets it to 64 MB so it holds months, not",
    "   hours. To turn it back off later, run the same line with /e:false.)",
    "  This does NOT protect you and tells you nothing about the past. It means that",
    "  next time, there is a record to search instead of an empty attic.",
]


# --- PowerShell plumbing ----------------------------------------------------

def _ps(cmd: str, timeout: int = 60):
    """Run one PowerShell command. Returns (returncode, stdout, stderr).
    Never raises for a non-zero exit; callers decide what a failure means.

    errors="replace" is load-bearing, not defensive dressing. PowerShell writes
    in the console's code page, not UTF-8, and a certificate subject with an
    accented character in it (Proton AG's, for one) emits a byte that is not
    valid UTF-8. With strict decoding that raises inside subprocess's own reader
    thread, the whole check degrades to could_not_run, and the tool reports a gap
    it does not actually have. A mangled character in a signer name is a far
    better outcome than a phantom gap.
    """
    # Ask PowerShell to actually write UTF-8, so the decode above usually has
    # nothing to repair in the first place.
    cmd = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + cmd
    proc = subprocess.run(_PS + [cmd], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout,
                          cwd=_PS_CWD, env=powershell_env())
    return proc.returncode, (proc.stdout or ""), (proc.stderr or "")


def _ps_json(cmd: str, timeout: int = 60):
    """Run a PowerShell command whose output is ConvertTo-Json.

    Returns (rows, error). `rows` is always a list: ConvertTo-Json emits a bare
    object (not an array) for a single result and nothing at all for an empty
    one, so both shapes are normalised here. `error` is "" on success.
    """
    try:
        rc, out, err = _ps(cmd, timeout=timeout)
    except subprocess.TimeoutExpired:
        return [], "PowerShell timed out after {}s".format(timeout)
    except OSError as exc:
        return [], "PowerShell could not be launched: {}".format(exc)

    text = out.strip()
    if rc != 0:
        reason = err.strip().splitlines()
        return [], (reason[0] if reason else
                    "PowerShell exited {}".format(rc))
    if not text or text == "null":
        return [], ""
    try:
        data = json.loads(text)
    except ValueError as exc:
        return [], "unparseable JSON from PowerShell: {}".format(exc)
    if isinstance(data, dict):      # single object, not a list
        return [data], ""
    if isinstance(data, list):
        return data, ""
    return [], "unexpected JSON shape from PowerShell: {}".format(type(data))


def _str(row, *names) -> str:
    """Pull the first present, non-null field from a ConvertTo-Json row."""
    if not isinstance(row, dict):
        return "" if row is None else str(row)
    for name in names:
        val = row.get(name)
        if val not in (None, ""):
            return val if isinstance(val, str) else str(val)
    return ""


# --- shared matching --------------------------------------------------------

def _match(r: ModuleResult, ctx, haystack: str, location: str,
           detail_fmt: str, evidence: str = EV_REFERENCED,
           observed: str = "") -> int:
    """Case-insensitive substring match of every network IOC against one blob
    of local text. Each hit carries its own tier/confidence provenance.

    `detail_fmt` is substituted with a plain replace rather than str.format so
    that artifact text containing braces can never break the detail line."""
    found = 0
    low = (haystack or "").lower()
    if not low:
        return 0
    for ind in ctx.iocs.search(low):
        r.add_hit(Hit(indicator=ind.value, location=location,
                      detail=detail_fmt.replace("{ioc}", ind.value),
                      tier=ind.tier, confidence=ind.confidence,
                      source=ind.source, evidence=evidence, observed=observed,
                      family=ind.family))
        found += 1
    return found


# --- 1. per-user COM registrations -----------------------------------------

def _boot_time():
    """Last boot time, which is the entire window the DNS resolver cache covers.
    Returns (iso_string_or_None, error)."""
    rows, err = _ps_json(
        "Get-CimInstance Win32_OperatingSystem"
        " | Select-Object @{n='Boot';e={$_.LastBootUpTime.ToString('o')}}"
        " | ConvertTo-Json -Depth 2 -Compress", timeout=60)
    if err or not rows:
        return None, err or "no result"
    boot = _str(rows[0], "Boot")
    return (boot or None), ""


def _user_writable_dirs():
    """Directories a normal user can drop a DLL into without elevation. A COM
    server living under one of these is the shape the Candiru hijack takes."""
    home = os.path.expanduser("~")
    candidates = [
        os.environ.get("APPDATA"),
        os.environ.get("LOCALAPPDATA"),
        os.environ.get("TEMP"),
        os.environ.get("PROGRAMDATA"),
        os.path.join(home, "Downloads") if home else None,
    ]
    return [d.rstrip("\\/").lower() for d in candidates if d]


def _enum_com_registrations(r: ModuleResult):
    """Walk HKCU CLSID (both views) and collect every registered server path.

    Uses winreg rather than PowerShell: this is thousands of key opens and
    spawning a shell for it would dominate the module's runtime.
    """
    entries = []
    partial = []  # views where the walk could not be completed
    for view_name, view_flag in _REG_VIEWS:
        access = winreg.KEY_READ | view_flag
        try:
            base = winreg.OpenKey(winreg.HKEY_CURRENT_USER, _CLSID_PATH, 0, access)
        except FileNotFoundError:
            continue  # this view genuinely has no CLSID key - not a failure
        except OSError as exc:
            partial.append("{} view could not be opened ({})".format(
                view_name, exc))
            continue
        try:
            index = 0
            while True:
                try:
                    clsid = winreg.EnumKey(base, index)
                except OSError as exc:
                    if getattr(exc, "winerror", None) not in (None, _ERROR_NO_MORE_ITEMS):
                        # ACCESS_DENIED / KEY_DELETED / transient: the list was
                        # ABORTED, not exhausted. Record how far we got so the
                        # check cannot pass off a truncated walk as complete.
                        partial.append("{} view enumeration stopped after {} "
                                       "keys ({})".format(view_name, index, exc))
                    break
                index += 1
                for kind in _SERVER_KINDS:
                    sub = "{}\\{}".format(clsid, kind)
                    try:
                        with winreg.OpenKey(base, sub, 0, access) as key:
                            value, _type = winreg.QueryValueEx(key, "")
                    except FileNotFoundError:
                        continue  # no such sub-key, or no default value
                    except OSError as exc:
                        partial.append("{} {} could not be read ({})".format(
                            view_name, sub, exc))
                        continue
                    if not isinstance(value, str) or not value.strip():
                        continue
                    entries.append({
                        "clsid": clsid,
                        "kind": kind,
                        "raw": value,
                        "view": view_name,
                    })
        finally:
            base.Close()
    return entries, partial


def _server_path(raw: str, kind: str) -> str:
    """Turn a registered server value into the path of the binary it names.

    InprocServer32/InprocHandler32 hold a bare DLL path. LocalServer32 holds a
    COMMAND LINE: `"C:\\...\\App.exe" -Embedding`. The PoC only trimmed outer
    quotes, which leaves the switches attached and makes every such entry test
    as "not on disk" — three false review entries on the reference machine. The
    binary is extracted properly here so the on-disk and signature answers are
    about the real file.
    """
    s = os.path.expandvars(raw).strip()
    if s.startswith('"'):
        end = s.find('"', 1)
        if end > 1:
            return s[1:end].strip()
    s = s.strip('"').strip()
    if kind == "LocalServer32" and s:
        # Parse only text here. Even an existence check would contact a UNC
        # server before _check_com has had a chance to reject the path.
        # An extension inside a directory (tool.exe\payload.bat) or a
        # longer filename (tool.exe.backup\app.exe) is not the binary's end.
        # Match extensions in command order, not by extension preference:
        # arguments may themselves contain a later .exe path.
        end = re.search(r"\.(?:exe|com|bat|cmd)(?=\s|$)", s, re.IGNORECASE)
        if end is not None:
            return s[:end.end()].strip()
    return s


# --- "it never connects" enforced for FILESYSTEM paths ---------------------
#
# netguard.py makes network contact impossible through Python's socket module.
# A registered COM path escapes that guard completely: the value comes out of
# the registry, which is attacker-controllable on a compromised machine, and a
# UNC value such as \\attacker-host\share\payload.dll makes WINDOWS open an SMB
# session the instant anything stats the path. The connection is made by the OS,
# not by Python, so the socket guard never sees it and records nothing - and on
# Windows that handshake can hand the remote host this account's NetNTLM
# credentials. A drive letter mapped to a remote share does the same thing with
# none of the visual warning a UNC path gives.
#
# So the question "is this path local?" is answered from the STRING and from the
# OS's own mount table, before anything opens, stats or hashes it.
#
# Residual, stated rather than hidden: a reparse point or symlink sitting under a
# local drive letter can still redirect to a remote location, and there is no way
# to find that out without following it - which is the very act we are avoiding.
# That case needs an attacker who can already create reparse points locally.

# DRIVE_REMOTE from winbase.h: GetDriveTypeW's answer for a letter bound to a
# network share. The call reads the mount table the OS already holds and opens
# nothing itself, which is what makes it safe to ask first.
_DRIVE_REMOTE = 4


def _network_drive_letters():
    """Drive letters currently bound to a remote share.

    Returns (letters, known). `known` is False when the question could not be
    asked at all; per D3 that is reported as a gap, never assumed to mean
    "local".
    """
    letters = set()
    try:
        import ctypes
        get_drive_type = ctypes.windll.kernel32.GetDriveTypeW  # type: ignore
    except (ImportError, AttributeError, OSError):  # pragma: no cover - non-Windows
        return letters, False
    for code in range(ord("A"), ord("Z") + 1):
        letter = chr(code)
        try:
            if get_drive_type("{}:\\".format(letter)) == _DRIVE_REMOTE:
                letters.add(letter)
        except OSError:  # pragma: no cover - defensive
            return letters, False
    return letters, True


def _remote_path_reason(path: str, remote_letters, drives_known: bool) -> str:
    """Why this registered path must NOT be touched, or "" if it is local.

    Asked BEFORE os.path.exists(), because on a UNC path the existence test IS
    the connection; there is no safe way to ask afterwards.
    """
    if not path:
        return ""
    s = path.replace("/", "\\")
    low = s.lower()
    rest = s
    if low.startswith("\\\\?\\") or low.startswith("\\\\.\\"):
        # Extended-length prefix. "\\?\UNC\server\share" is the long spelling of
        # "\\server\share", while "\\?\C:\..." wearing the same prefix is an
        # ordinary local path - so the prefix alone settles nothing and the part
        # after it has to be read.
        if low[4:].startswith("unc\\"):
            return "it is a UNC path to a remote share (\\\\?\\UNC\\...)"
        rest = s[4:]
    elif s.startswith("\\\\"):
        return "it is a UNC path to a remote share (\\\\server\\share)"
    if len(rest) >= 2 and rest[0].isalpha() and rest[1] == ":":
        letter = rest[0].upper()
        if letter in remote_letters:
            return "drive {}: is mapped to a remote share".format(letter)
        if not drives_known:
            return ("drive {}: could not be classified as a local disk or a "
                    "network mapping on this host".format(letter))
    return ""


def _signature_status(paths, timeout: int = 180):
    """Leave signatures unverified: the OS verifier may retrieve network data.

    Signature inventory is optional context, never an indicator match. Until a
    strictly offline verifier is available, no verification subprocess is run.
    """
    if not paths:
        return {}, ""
    return ({p.lower(): ("NotChecked", "") for p in paths},
            "signature verification was not performed because the OS verifier "
            "may contact the network; signature status is unknown")


def _check_com(r: ModuleResult, ctx) -> None:
    ctx.emit("[host] enumerating per-user COM registrations (HKCU CLSID)")
    entries, partial = _enum_com_registrations(r)

    # Expand, de-quote and test each registered path before asking about
    # signatures, so the batched call only covers files that exist on disk.
    writable = [os.path.normcase(os.path.normpath(d)).casefold()
                for d in _user_writable_dirs()]
    remote_letters, drives_known = _network_drive_letters()
    on_disk = []
    for e in entries:
        expanded = _server_path(e["raw"], e["kind"])
        e["path"] = expanded
        low = os.path.normcase(os.path.normpath(expanded)).casefold() if expanded else ""
        # Decided before the path is touched: os.path.exists() on a remote path
        # is itself the network contact this tool promises never to make, and it
        # happens inside Windows where netguard cannot see it.
        e["remote_reason"] = _remote_path_reason(expanded, remote_letters,
                                                 drives_known)
        if not e["remote_reason"] and expanded:
            e["remote_reason"] = path_problem(expanded)
        if e["remote_reason"]:
            e["exists"] = False
            e["user_writable"] = False
            continue
        try:
            e["exists"] = bool(expanded) and os.path.exists(expanded)
        except OSError:
            e["exists"] = False
        e["user_writable"] = any(low == d or low.startswith(d + os.sep)
                                 for d in writable)
        if e["exists"]:
            on_disk.append(expanded)

    sigs, sig_err = _signature_status(on_disk)
    if sig_err:
        r.could_not_run("com-signatures", sig_err)

    # The existing general file roots miss a registered server in an unusual
    # local directory. Pass only bounded, local, user-writable file paths to
    # the opt-in pattern module; the latter rechecks each path before reading.
    # A user's explicit --pattern-path retains its documented limited scope.
    if getattr(ctx, "patterns", False) and not getattr(ctx, "pattern_paths", ()):
        unique = {}
        for e in entries:
            if not (e.get("exists") and e.get("user_writable")) or e.get("remote_reason"):
                continue
            try:
                if not os.path.isfile(e["path"]):
                    continue
            except OSError:
                continue
            key = os.path.normcase(os.path.normpath(e["path"]))
            unique.setdefault(key, e["path"])
        candidates = [unique[key] for key in sorted(unique)]
        ctx.pattern_candidate_paths = tuple(candidates[:_COM_PATTERN_CANDIDATE_CAP])
        ctx.pattern_candidate_omitted = max(0, len(candidates) - _COM_PATTERN_CANDIDATE_CAP)

    user_writable = 0
    reviewable = []
    unreachable = []
    for e in entries:
        if e.get("remote_reason"):
            # NOT "not on disk": nobody looked. Rendering a refusal to look as a
            # measurement is exactly the collapse D3 forbids.
            status, signer = "not checked (path is not on a local disk)", ""
        elif e["exists"]:
            status, signer = sigs.get(e["path"].lower(), ("Unknown", ""))
        else:
            status, signer = "n/a (not on disk)", ""
        e["sig"] = status
        e["signer"] = signer
        if e["user_writable"]:
            user_writable += 1

        location = "HKCU\\{}\\{}\\{}".format(
            "Software\\Classes\\WOW6432Node\\CLSID" if e["view"] == "wow6432"
            else "Software\\Classes\\CLSID", e["clsid"], e["kind"])

        # D4: the only COM finding worth calling a Hit is a registered path
        # that actually contains an indicator. "Unsigned DLL in AppData" is a
        # description of a lot of legitimate software, not of this implant.
        _match(r, ctx, "{} {}".format(e["raw"], e["path"]), location,
               "per-user COM server registration references indicator "
               "{ioc} — a COM hijack is this chain's documented persistence; "
               "investigate the registration and the binary",
               EV_PERSISTENCE)

        # The string match above is pure text and costs nothing, so a remote
        # registration is still matched against the indicator set - it is only
        # the FILE behind it that is left alone. Collected here, where the
        # registry location has been formatted, so the report can name it.
        if e.get("remote_reason"):
            unreachable.append((location, e))

        # Reviewable inventory, deliberately narrowed: an entry is only worth a
        # human's attention if it is BOTH in a user-writable directory AND not
        # validly signed. Collected rather than noted inline, so the list can be
        # capped - 8 full-width "not validly signed" lines in the DETAIL channel
        # read as 8 alarms next to the real hits.
        if e["user_writable"] and status not in ("Valid", "Unknown", "NotChecked"):
            reviewable.append((location, e))

    if reviewable:
        r.note("com-persistence: {} per-user COM registration(s) are in a folder "
               "you can write to and are not validly signed. Legitimate software "
               "does this too - these are pointers for a reviewer, NOT findings, "
               "and none of them matched an indicator.".format(len(reviewable)))
        for location, e in reviewable[:3]:
            r.note("    - {} -> {} [on disk: {}; signature: {}{}]".format(
                location, e["path"] or "(empty)",
                "yes" if e["exists"] else "no", e["sig"],
                "; signer: " + e["signer"] if e["signer"] else ""))
        if len(reviewable) > 3:
            r.note("    - ... and {} more, listed in full in the JSON report."
                   .format(len(reviewable) - 3))

    if unreachable:
        # Refusing to touch the path is the right call, but a refusal is a GAP,
        # not a clean entry, and the user is owed both facts: what was skipped
        # and why skipping it was the safe thing to do.
        r.note("com-persistence: {} per-user COM registration(s) name a path "
               "that is not on a local disk. The scanner did NOT open them. "
               "Merely testing whether such a path exists makes Windows open a "
               "connection to the remote host - and can hand that host this "
               "account's network credentials - which is the one thing this "
               "tool promises never to do. These entries are UNVERIFIED: their "
               "file was not fingerprinted and its signature was not checked."
               .format(len(unreachable)))
        for location, e in unreachable[:3]:
            r.note("    - {} -> {} [not checked: {}]".format(
                location, e["path"] or "(empty)", e["remote_reason"]))
        if len(unreachable) > 3:
            r.note("    - ... and {} more, listed in full in the JSON report."
                   .format(len(unreachable) - 3))

    r.checked += len(entries)
    r.submetrics["com_registrations"] = len(entries)
    r.submetrics["com_user_writable"] = user_writable
    if unreachable:
        r.submetrics["com_remote_paths"] = len(unreachable)

    # A truncated enumeration must not pass as a complete one (D3). If a registry
    # view could not be fully walked, the COM surface was only partly checked.
    if partial:
        r.could_not_run("com-persistence",
                        "the registry could not be fully enumerated, so an "
                        "auto-start entry may have been missed: {}".format(
                            "; ".join(partial)))
    elif unreachable:
        # Same doctrine, different cause: the registry was read in full, but
        # some of what it named was deliberately not opened.
        r.could_not_run("com-persistence",
                        "{} registered path(s) are not on a local disk and were "
                        "deliberately not opened (contacting them is what this "
                        "tool promises not to do), so those entries were not "
                        "verified: {}".format(
                            len(unreachable),
                            "; ".join(sorted(set(
                                e["remote_reason"] for _loc, e in unreachable)))))
    else:
        r.ran("com-persistence")
    ctx.emit("[host] COM registrations: {} ({} in user-writable dirs)"
             .format(len(entries), user_writable))


# --- 2. DNS resolver cache --------------------------------------------------

def _check_dns_cache(r: ModuleResult, ctx) -> None:
    ctx.emit("[host] reading local DNS resolver cache")
    # Reads the cache the OS already holds. It issues no query and resolves
    # nothing, which is exactly why D2 permits it.
    rows, err = _ps_json(
        "Get-DnsClientCache -ErrorAction Stop"
        " | Select-Object Entry,Name,Data,Type"
        " | ConvertTo-Json -Depth 3 -Compress", timeout=60)
    if err:
        r.could_not_run("dns-cache", "Get-DnsClientCache unavailable: {}".format(err))
        return

    hits = 0
    blocked = 0
    for row in rows:
        entry = _str(row, "Entry")
        name = _str(row, "Name")
        data = _str(row, "Data")
        # Windows preloads hosts-file mappings into the resolver cache when
        # the DNS Client starts, even if no application looked up that name.
        # A sink entry is therefore protective state, not proof of an attempted
        # connection. Installing our blocklist must not create findings.
        # https://learn.microsoft.com/en-us/windows-server/networking/dns/queries-lookups
        was_blocked = _is_sink(data)
        haystack = " ".join((entry, name, data))
        if was_blocked:
            blocked += sum(1 for _ind in ctx.iocs.search(haystack.lower()))
            continue
        where = ("(Entry=" + (entry or "-") + " Name=" + (name or "-") +
                 " Data=" + (data or "-") + ")")
        detail = ("indicator {ioc} appears as a name or address in this "
                  "boot's DNS resolver cache " + where + " — this is a "
                  "resolver record; endpoint contact is unverified")
        found = _match(r, ctx, haystack, "DNS resolver cache", detail, EV_DNS)
        hits += found

    r.checked += len(rows)
    r.submetrics["dns_cache_entries"] = len(rows)
    if blocked:
        r.submetrics["dns_cache_blocked_indicators"] = blocked
        r.note("dns-cache: {} indicator entry/entries point to a sink address. "
               "This is protective state, not a finding. Windows can preload "
               "these entries from the hosts file without any lookup; no "
               "attempt or contact is established.".format(blocked))

    # The resolver cache is wiped by a reboot, so its whole window is "since last
    # boot". Stating that plainly stops a clean cache being read as a clean history.
    boot, boot_err = _boot_time()
    r.reach["dns-cache"] = {
        "earliest": boot,
        "days": None,
        "basis": "the resolver cache holds only this boot session"
                 + ("" if boot else " (boot time unavailable: {})".format(boot_err)),
        "note": "The cache includes hosts-file mappings loaded at startup and "
                "records obtained during this boot. An entry alone does not "
                "establish that an application looked it up or connected.",
    }
    r.ran("dns-cache")
    ctx.emit("[host] DNS cache entries: {} ({} DNS findings, {} protective "
             "sink entries)".format(len(rows), hits, blocked))


# --- 3. retrospective DNS history ------------------------------------------

def _check_dns_log(r: ModuleResult, ctx) -> None:
    ctx.emit("[host] checking whether DNS-Client/Operational history exists")
    rows, err = _ps_json(
        "Get-WinEvent -ListLog '{}' -ErrorAction Stop"
        " | Select-Object @{{n='IsEnabled';e={{[bool]$_.IsEnabled}}}},"
        " @{{n='RecordCount';e={{[int]$_.RecordCount}}}}"
        " | ConvertTo-Json -Depth 3 -Compress".format(_DNS_LOG), timeout=60)

    if err or not rows:
        # Log absent or unreadable: the consequence for the user is identical
        # to it being disabled, so it is reported as the same gap, not as an
        # incidental error.
        r.submetrics["dns_log_enabled"] = 0
        r.submetrics["dns_log_records"] = 0
        r.could_not_run("dns-log", _DNS_LOG_GAP)
        r.note("dns-log: {} could not be queried ({})".format(
            _DNS_LOG, err or "log not present on this host"))
        r.note(_ARM_HINT)
        r.reach["dns-log"] = {
            "earliest": None,
            "days": 0,
            "basis": "DNS log metadata could not be read",
            "note": "No historical window could be established. Older or "
                    "unread records may still exist.",
            "how_to_enable": _HOW_TO_ENABLE,
        }
        return

    row = rows[0]
    enabled = bool(row.get("IsEnabled"))
    try:
        records = int(row.get("RecordCount") or 0)
    except (TypeError, ValueError):
        records = 0
    r.submetrics["dns_log_enabled"] = 1 if enabled else 0
    r.submetrics["dns_log_records"] = records

    if records <= 0:
        # The important branch, and the common one. This must never read clean.
        r.could_not_run("dns-log", _DNS_LOG_GAP)
        r.note("dns-log: {} enabled={} records={} — forward-looking checks are "
               "possible, retrospective ones are not.".format(
                   _DNS_LOG, enabled, records))
        r.note(_ARM_HINT)
        r.reach["dns-log"] = {
            "earliest": None,
            "days": 0,
            "basis": "DNS logging is {} and holds {} records".format(
                "enabled" if enabled else "disabled", records),
            "note": "No saved DNS events were available for this scan. "
                    "This does not establish whether older events existed or were cleared.",
            "how_to_enable": _HOW_TO_ENABLE,
        }
        return

    # IsEnabled controls current collection, not whether retained events can
    # be read. Disabling logging must not hide existing historical evidence.
    if not enabled:
        r.could_not_run("dns-log-recording",
                        "DNS logging is currently off; queries made while "
                        "logging was off may be missing")
        r.note("dns-log: logging is off; the log reports {} saved event(s). "
               "Checking them does not enable logging."
               .format(records))
    ctx.emit("[host] DNS-Client/Operational logging is {} ({} retained records); "
             "scanning messages".format("on" if enabled else "off", records))
    # -ErrorAction Stop, not SilentlyContinue: with SilentlyContinue a failure to
    # read the channel (ACL, corrupt .evtx, Event Log service degraded) exits 0
    # with no output, so `events` is [] and `ev_err` is "" - and the log, which is
    # ENABLED and holds records, gets reported as a check that ran and found
    # nothing. That rolls up to CLEAN: the one check the whole tool exists for,
    # silently certifying an unread log as clean history. ToString('o') gives ISO
    # 8601 so min()/max() sort chronologically rather than by locale date string.
    events, ev_err = _ps_json(
        "Get-WinEvent -LogName '{}' -MaxEvents {}"
        " -ErrorAction Stop"
        " | Select-Object @{{n='Time';e={{$_.TimeCreated.ToString('o')}}}},"
        " @{{n='Message';e={{[string]$_.Message}}}}"
        " | ConvertTo-Json -Depth 3 -Compress".format(
            _DNS_LOG, _DNS_EVENT_CAP), timeout=300)
    if (ev_err and not events) or (records > 0 and not events):
        reason = ("log has {} retained records but none could be read{} - this "
                  "machine's DNS history was NOT searched, so nothing here is "
                  "cleared".format(records, ": " + ev_err if ev_err else ""))
        r.could_not_run("dns-log", reason)
        return

    hits = 0
    times = [t for t in (_str(ev, "Time") for ev in events) if t]
    if times:
        # Retained records have dates even when logging is currently disabled.
        r.reach["dns-log"] = {
            "earliest": min(times),
            "days": None,
            "basis": "oldest of {:,} DNS events read (cap {:,})".format(
                len(times), _DNS_EVENT_CAP),
            "note": "Queries before this are either rotated out of the log or "
                    "beyond the bounded event read.",
        }
        if not enabled:
            r.reach["dns-log"]["note"] += " Logging is currently off; queries during unrecorded periods may be missing."
            r.reach["dns-log"]["how_to_enable"] = _HOW_TO_ENABLE
    for ev in events:
        when = _str(ev, "Time")
        message = _str(ev, "Message")
        # Same judgement as the resolver cache: a query answered only with
        # block addresses was stopped by a filter, so it is an attempt.
        if _dns_answer_blocked(message):
            hits += _match(
                r, ctx, message,
                "{} @ {}".format(_DNS_LOG, when or "unknown time"),
                "indicator {ioc} was looked up" + (" at " + when if when else "") +
                " and answered with a block address, so a filter stopped it",
                EV_ATTEMPTED, when)
            continue
        hits += _match(
            r, ctx, message,
            "{} @ {}".format(_DNS_LOG, when or "unknown time"),
            "indicator {ioc} appears as a name or address in a "
            "DNS-Client/Operational event" +
            (" at " + when if when else "") +
            " — the event alone does not establish successful resolution or "
            "endpoint contact",
            EV_DNS, when)

    r.checked += len(events)
    r.submetrics["dns_log_events_scanned"] = len(events)
    r.ran("dns-log")
    if records > len(events):
        # A note alone let the overall check appear complete and clean even
        # though older retained DNS records were never examined.
        r.could_not_run("dns-log-older-events",
                        "examined the most recent {} of {} retained records "
                        "(read cap {:,}); older entries were not checked".format(
                            len(events), records, _DNS_EVENT_CAP))
    ctx.emit("[host] DNS log events scanned: {} ({} indicator matches)"
             .format(len(events), hits))


# --- 4. hosts file ----------------------------------------------------------

def _hosts_path():
    """The hosts file on this platform. macOS's /etc is a link to /private/etc,
    and links are never followed, so the real location is used there."""
    if sys.platform == "win32":
        return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
    if sys.platform == "darwin":
        return "/private/etc/hosts"
    return "/etc/hosts"


def _check_hosts(r: ModuleResult, ctx) -> None:
    path = _hosts_path()
    ctx.emit("[host] reading {}".format(path))
    problem = path_problem(path)
    if problem:
        r.could_not_run("hosts-file", problem)
        return
    if not os.path.exists(path):
        r.could_not_run("hosts-file", "no hosts file at {}".format(path))
        return
    try:
        # Big ad-blocking lists reach tens of MB; anything far beyond that is not
        # read into memory whole, and saying so is a gap, not a clean result.
        if os.path.getsize(path) > 64 * 1024 * 1024:
            r.could_not_run("hosts-file", "the hosts file is over 64 MB, so it was not read")
            return
        with io.open(path, encoding="utf-8", errors="replace") as fh:
            raw = fh.readlines()
    except OSError as exc:
        r.could_not_run("hosts-file", "could not read {}: {}".format(path, exc))
        return

    active = [ln.strip() for ln in raw
              if ln.strip() and not ln.strip().startswith("#")]
    # A hosts line is "<address> <hostname...>". Pointing an indicator at one of
    # these sink addresses is a deliberate BLOCK - protective, the OPPOSITE of a
    # compromise - so it is not reported as a hit at all, only counted. Only a
    # mapping to a REAL address is a finding (EV_CONFIGURED).
    hits = 0
    blocked = 0
    for line in active:
        parts = line.split()
        addr = parts[0] if parts else ""
        if _is_sink(addr):
            # Still check it DOES contain an indicator, for the block count, but
            # never raise a hit on a protective entry.
            if ctx.iocs.search(line.lower()):
                blocked += 1
            continue
        hits += _match(
            r, ctx, line, path,
            "indicator {ioc} is mapped in the hosts file to " + addr +
            " (line: " + line + "). This is NOT a sink/block address, so the "
            "name has been pointed at a real host on this machine - unusual, "
            "and worth checking who added it.",
            EV_CONFIGURED)

    r.checked += 1
    r.submetrics["hosts_entries"] = len(active)
    if blocked:
        r.submetrics["hosts_blocked_indicators"] = blocked
        r.note("hosts-file: {} indicator(s) are BLOCKED in the hosts file "
               "(pointed at a sink address). That is protective, not a finding."
               .format(blocked))
    r.ran("hosts-file")
    ctx.emit("[host] active hosts entries: {} ({} indicator matches, {} blocked)"
             .format(len(active), hits, blocked))


# --- 5. known fixed-path file drops -----------------------------------------

# Files this campaign and its tooling drop at a FIXED path, where the path itself
# is the lead. HW.sys is the signed-but-vulnerable kernel driver Candiru brings to
# disable protections (bring-your-own-vulnerable-driver); Avast documented its
# path and the exact hash. The path is a generic name, so presence alone is only a
# pointer - the check hashes the file and says whether it is the KNOWN-BAD build
# (hash in the IOC set) or merely a same-named file to look at.
# Path parts, not a backslash string: os.path.join builds the right separator on
# every OS. A literal "System32\\drivers\\HW.sys" would be one filename with
# embedded backslashes on POSIX, so the check (and its test) only worked on Windows.
_KNOWN_DROPS = [
    (("System32", "drivers", "HW.sys"),
     "the signed-but-vulnerable driver Candiru uses to disable protections "
     "(bring-your-own-vulnerable-driver); documented by Avast, CVE-2022-2294"),
]


def _check_known_paths(r: ModuleResult, ctx) -> None:
    import hashlib
    root = os.environ.get("SystemRoot", r"C:\Windows")
    known_hashes = {h.value for h in ctx.iocs.hashes}
    found = 0
    unavailable = 0
    for parts, why in _KNOWN_DROPS:
        path = os.path.join(root, *parts)
        try:
            problem = path_problem(path)
            if problem:
                raise PermissionError(13, problem, path)
            os.stat(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            unavailable += 1
            r.skipped += 1
            r.could_not_run("known-path:" + path,
                            "could not inspect this path: {}".format(exc))
            continue
        found += 1
        digest = ""
        try:
            h = hashlib.sha256()
            with io.open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    h.update(chunk)
            digest = h.hexdigest()
        except OSError as exc:
            unavailable += 1
            r.skipped += 1
            r.could_not_run("known-path:" + path,
                            "file exists but its fingerprint is unavailable: {}"
                            .format(exc))
            continue
        if digest and digest in known_hashes:
            ind = ctx.iocs.lookup(digest)
            tier = ind.tier if ind else "sample"
            # A `vuln-driver` match is legitimate signed software this actor
            # abuses - present on clean machines too. Calling that "KNOWN-BAD"
            # would tell an innocent owner they are infected, so the wording is
            # chosen from the tier (see NOT_MALWARE_TIERS in report.py).
            if tier == "vuln-driver":
                detail = ("the file at {} matches a published indicator for {}. "
                          "This file is LEGITIMATE, signed software that is also "
                          "installed for honest reasons - its presence is NOT "
                          "proof of spyware. Worth establishing how and when it "
                          "was installed. Do not delete it.".format(path, why))
            else:
                detail = ("the file at {} is the KNOWN-BAD build - {}. Its "
                          "SHA-256 matches a published indicator. Do not delete "
                          "it; it is evidence.".format(path, why))
            r.add_hit(Hit(
                indicator=digest, location=path, detail=detail,
                tier=tier,
                confidence=ind.confidence if ind else "secondary",
                source=ind.source if ind else "", evidence=EV_ON_DISK,
                family=ind.family if ind else ""))
        else:
            # Present, but not the known-bad hash. A legitimate
            # driver of the same name exists, so this is a POINTER, not a hit:
            # recorded as a note, graded nowhere, so it never alarms on its own.
            r.note("known-paths: a file exists at {} ({}). This path is {}. "
                   "Its fingerprint does NOT match the known-bad build{}, so it "
                   "is most likely a legitimate same-named file - but given the "
                   "path it is worth a look.".format(
                       path, "SHA-256 " + digest[:16] + "..." if digest else
                       "unreadable", why,
                       "" if digest else " (could not read it)"))
    r.checked += len(_KNOWN_DROPS) - unavailable
    r.submetrics["known_paths_checked"] = len(_KNOWN_DROPS) - unavailable
    if found:
        r.submetrics["known_paths_present"] = found
    if unavailable < len(_KNOWN_DROPS):
        r.ran("known-paths")
    ctx.emit("[host] known fixed-path drops: {} checked, {} present".format(
        len(_KNOWN_DROPS), found))


# --- 6. Candiru DevilsTongue traces ------------------------------------------

# Where DevilsTongue puts its files and which COM classes it hijacks to start
# with Windows. Sources: Microsoft Threat Intelligence, "Protecting customers
# from a private-sector offensive actor using 0-day exploits and DevilsTongue
# malware" (2021-07-15), and Avast/Gen, "The Return of Candiru" (2022-07-21,
# github.com/avast/ioc/tree/master/Candiru). None of these files ships with
# Windows, but several names imitate Windows input-method (IME) or WMI files, so
# a file here is a lead to check, never a finding by itself: its fingerprint is
# what the hash check compares. Path parts, so the join is right on every OS.
_DT_PATHS = (
    ("System32", "IME", "IMEJP", "imjpueact.dll"), ("System32", "IME", "IMEJP", "imjpuexp.dll"),
    ("System32", "IME", "IMETC", "IMTCPROT.DLL"), ("System32", "IME", "SHARED", "imecpmeid.dll"),
    ("System32", "IME", "SHARED", "imccphd.dll"), ("System32", "IME", "SHARED", "imebrokev.dll"),
    ("System32", "IME", "SHARED", "imepadsvd.dll"),
    ("System32", "IME", "SHARED", "WimBootConfigurations.ini"),
    ("System32", "IME", "IMEJP", "WimBootConfigurations.ini"),
    ("System32", "IME", "IMETC", "WimBootConfigurations.ini"),
    ("System32", "config", "spp", "ServiceState", "Recovery", "pac.dat"),
    ("System32", "config", "cy-GB", "Setup", "SKB", "InputMethod", "TupTask.dat"),
    ("System32", "config", "config", "startwus.dat"),
    ("System32", "drivers", "physmem.sys"), ("System32", "drivers", "HW.sys.dat"),
    ("System32", "migration", "netiopmig.dll"), ("System32", "migration", "netiopmig.dll.inf"),
    ("System32", "migration", "sppvmig.dll"), ("System32", "migration", "spvmig.dll"),
    ("System32", "migration", "imjprmig.dll"),
    ("System32", "wbem", "dmwmibridgeprov132.dll"), ("System32", "wbem", "esscli32.dll"),
    ("System32", "wbem", "netdacim32.dll"), ("System32", "wbem", "netpeerdistcim32.dll"),
    ("System32", "wbem", "viewprov32.dll"), ("System32", "wbem", "vsswmi32.dll"),
    ("System32", "wbem", "wbemcore32.dll"), ("System32", "wbem", "wbemdisp32.dll"),
    ("System32", "wbem", "wbemsvc32.dll"), ("System32", "wbem", "wfascim32.dll"),
    ("System32", "wbem", "win32_encryptablevolume32.dll"), ("System32", "wbem", "wmiaprpl32.dll"),
)

# The COM classes DevilsTongue re-points at its own DLL, and the Windows file
# each normally loads. Anything else, or a per-user copy of the class, is the
# hijack Microsoft and Avast describe.
_DT_CLASSES = {
    "{4590F811-1D3A-11D0-891F-00AA004B2E24}": "wbemprox.dll",
    "{4FA18276-912A-11D1-AD9B-00C04FD8FDFF}": "wbemcore.dll",
    "{7C857801-7381-11CF-884D-00AA004B2E24}": "wbemsvc.dll",
    "{CF4CC405-E2C5-4DDD-B3CE-5E7582D8C9FA}": "wmiutils.dll",
}

_DT_USUAL_FILE = ("These names do not ship with Windows, but some imitate its input-method "
                  "or WMI files. Check the file's digital signature (right-click > Properties > "
                  "Digital Signatures). If it is not signed by Microsoft, keep the computer as it "
                  "is and get expert help.")
_DT_USUAL_CLASS = ("Some legitimate software re-registers Windows components, but rarely these. "
                   "If you did not install system tools recently, get expert help.")


def _dt_class_server(hive, clsid):
    """The InprocServer32 file a COM class loads in `hive` ("HKLM" or "HKCU"),
    or None if absent."""
    root = winreg.HKEY_LOCAL_MACHINE if hive == "HKLM" else winreg.HKEY_CURRENT_USER
    try:
        with winreg.OpenKey(root, r"Software\Classes\CLSID\{}\InprocServer32".format(clsid)) as key:
            value, _kind = winreg.QueryValueEx(key, "")
    except FileNotFoundError:
        return None
    return os.path.expandvars(str(value))


def _check_devilstongue(r: ModuleResult, ctx) -> None:
    root = os.environ.get("SystemRoot", r"C:\Windows")
    present = 0
    for parts in _DT_PATHS:
        path = os.path.join(root, *parts)
        try:
            problem = path_problem(path)
            if problem:
                raise PermissionError(13, problem, path)
            exists = os.path.lexists(path)
        except OSError as exc:
            r.could_not_run("devilstongue-traces", "could not inspect {}: {}".format(path, exc))
            return
        if exists:
            present += 1
            r.add_lead(Lead("devilstongue-traces", path,
                            "A file exists where Candiru's DevilsTongue spyware was documented "
                            "putting its files (Microsoft 2021, Avast 2022).", _DT_USUAL_FILE))
    changed = 0
    for clsid, normal in _DT_CLASSES.items():
        machine = _dt_class_server("HKLM", clsid)
        user = _dt_class_server("HKCU", clsid)
        if machine and os.path.basename(machine).lower() != normal:
            changed += 1
            r.add_lead(Lead("devilstongue-traces", "HKLM\\Software\\Classes\\CLSID\\" + clsid,
                            "A Windows component that DevilsTongue is documented hijacking loads "
                            "{} instead of {}.".format(machine, normal), _DT_USUAL_CLASS))
        if user:
            changed += 1
            r.add_lead(Lead("devilstongue-traces", "HKCU\\Software\\Classes\\CLSID\\" + clsid,
                            "A per-user copy of a Windows component that DevilsTongue is documented "
                            "hijacking loads {}.".format(user), _DT_USUAL_CLASS))
    r.checked += len(_DT_PATHS) + len(_DT_CLASSES)
    r.submetrics["devilstongue_paths_checked"] = len(_DT_PATHS)
    r.ran("devilstongue-traces")
    ctx.emit("[host] DevilsTongue traces: {} paths and {} components checked, {} to look at".format(
        len(_DT_PATHS), len(_DT_CLASSES), present + changed))


# --- module entry point -----------------------------------------------------

def run(ctx) -> ModuleResult:
    r = ModuleResult(NAME)
    # Publish the result straight away so that if anything below raises, the CLI
    # can still recover whatever was found before the failure instead of
    # discarding it (see ScanContext.partial).
    ctx.partial = r

    system = platform.system()
    if system in ("Darwin", "Linux"):
        # The hosts file is the one check here that exists on every platform;
        # the others (COM registrations, the Windows DNS cache and its event log,
        # Windows known paths) do not exist on macOS or Linux, so they are not
        # gaps there.
        try:
            _check_hosts(r, ctx)
        except Exception as exc:
            r.skipped += 1
            r.could_not_run("hosts-file", "{}: {}".format(type(exc).__name__, exc))
        return r
    if system != "Windows" or winreg is None:
        # Never a fake CLEAN on a platform where nothing was observed.
        reason = "not supported on {}".format(system or "unknown platform")
        for name in ("com-persistence", "dns-cache", "dns-log", "hosts-file",
                     "known-paths", "devilstongue-traces"):
            r.could_not_run(name, reason)
        return r

    # Each check is isolated: one failure must not cost the others.
    for name, fn in (("com-persistence", _check_com),
                     ("dns-cache", _check_dns_cache),
                     ("dns-log", _check_dns_log),
                     ("hosts-file", _check_hosts),
                     ("known-paths", _check_known_paths),
                     ("devilstongue-traces", _check_devilstongue)):
        try:
            fn(r, ctx)
        except Exception as exc:
            r.skipped += 1
            r.could_not_run(name, "{}: {}".format(type(exc).__name__, exc))

    return r
