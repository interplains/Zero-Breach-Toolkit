"""Traces module - Windows records, plus opt-in extended event queries.

The original five checks read sources an ordinary account can read:

  1. mark-of-the-web. Browsers stamp every downloaded file with a hidden
     "Zone.Identifier" stream naming the page it came from (HostUrl) and the
     page you were on (ReferrerUrl). It survives after history is cleared, for
     as long as the file exists. An indicator there = this computer downloaded
     from that host (grade: contacted).

  2. run-history. Windows keeps the last commands typed into the Win+R box
     (RunMRU). That is exactly where a fake "verify you are human" page tells
     people to paste a command (ClickFix). An indicator inside a stored command
     = grade ran-command. A command that runs PowerShell, mshta or a download tool against
     a web address is a 'worth a look' lead.

  3. defender-history. Microsoft Defender's own log: detections (1116/1117),
     real-time protection turned off (5001), settings changed (5007 - this is
     where an added EXCLUSION shows up, while the exclusion list itself is
     unreadable without admin). These are leads, never findings: Defender
     catches plenty of everyday junk. An indicator inside a Defender record is
     a finding (grade attempted - Defender saw it and acted).

  4. powershell-history. PowerShell's script-block log (event 4104), when it is
     on. An indicator inside a logged script = grade ran-command. A
     download-and-run pattern is a lead.

  5. ran-programs. Windows' shim cache and (Windows 11) program-launch list
     list file paths; ShimCache alone does not prove execution. Each existing file is
     fingerprinted and compared with published sample fingerprints, wherever
     on the disk it lives (grade on-disk).

Read-only, no network (D2). The PowerShell commands this module runs contain
no indicator values and no download pattern, so its own footprint in the
PowerShell log can never be reported by a later scan.

Names here are prefixed _tr_ because the single-file build places every
module's code in one namespace.
"""

from __future__ import annotations

import datetime
import errno
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
from urllib.parse import urlsplit

from ..heuristics import CRADLE_GET, CRADLE_RUN, REMOTE, RUNNER
from ..iocs import TYPE_SHA256
from ..localpaths import (path_problem, walk_local, WALK_LINK_REFUSED, WALK_SPECIAL_REFUSED,
                          WALK_CLOUD_SKIPPED)
from ..result import (EV_ATTEMPTED, EV_COMMAND, EV_CONTACTED, EV_ON_DISK, Hit, Lead,
                      ModuleResult)

NAME = "traces"

# PowerShell by its ABSOLUTE path, from a working folder the tool does not
# control - never the bare name, which Windows would first look up in the
# tool's own folder and the current folder (e.g. Downloads), so a planted
# powershell.exe there would run instead. The same fix as host.py.
_TR_PS_EXE = os.path.join(os.environ.get("SystemRoot") or r"C:\Windows",
                          "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
_TR_PS_CWD = os.environ.get("SystemRoot") or r"C:\Windows"
_TR_PS = [_TR_PS_EXE, "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
          "Bypass", "-Command"]
_TR_MAX_FILES = 300000          # Mark-of-the-Web: files examined before stopping
_TR_MAX_DEPTH = 16
_TR_SKIP_DIRS = {"node_modules", ".git", "__pycache__", ".venv", "venv"}
_TR_MAX_LEADS = 25              # per kind; the rest are counted in a note
_TR_PS_EVENTS = 20000           # newest PowerShell script blocks examined

# Lead patterns are data in zbtriage/heuristics.py (see its docstring for why).
_TR_RUNNER, _TR_REMOTE = RUNNER, REMOTE
_TR_CRADLE_RUN, _TR_CRADLE_GET = CRADLE_RUN, CRADLE_GET

_TR_WHY_RUNBOX = ("IT staff and some setup guides ask people to run commands like this. "
                  "It is also exactly what fake 'verify you are human' pages ask for. "
                  "If you do not remember typing it, ask for help.")
_TR_WHY_CRADLE = ("Installers such as Scoop and Chocolatey, and many setup guides, "
                  "download and run scripts this way. Malware does too.")
_TR_WHY_DETECT = ("Defender detects and removes many everyday threats (adware, cracked "
                  "software, browser junk). This shows what it saw and what it did; "
                  "check the action succeeded.")
_TR_WHY_RTP = ("People turn protection off briefly to install software, and other "
               "antivirus products switch it off. Attackers also do it.")
# Windows Security Center's own name for Defender ("Windows Defender" on older
# Windows, "Microsoft Defender Antivirus" now).
_TR_DEFENDER_NAME = re.compile(r"\b(?:windows|microsoft) defender\b", re.I)
_TR_WHY_EXCL = ("Developers, gamers and some programs add exclusions for speed or to "
                "stop false alarms. Attackers add them to hide their files.")


# --- helpers ----------------------------------------------------------------

def _tr_ps_json(cmd, timeout=180):
    """Run PowerShell, parse its JSON. Returns (rows, error)."""
    cmd = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " + cmd
    try:
        from .host import powershell_env
        proc = subprocess.run(_TR_PS + [cmd], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=timeout,
                              cwd=_TR_PS_CWD, env=powershell_env())
    except subprocess.TimeoutExpired:
        return [], "PowerShell timed out after {}s".format(timeout)
    except OSError as exc:
        return [], "PowerShell could not be launched: {}".format(exc)
    if proc.returncode != 0:
        lines = (proc.stderr or "").strip().splitlines()
        return [], lines[0] if lines else "PowerShell exited {}".format(proc.returncode)
    text = (proc.stdout or "").strip()
    if not text or text == "null":
        return [], ""
    try:
        data = json.loads(text)
    except ValueError as exc:
        return [], "unparseable JSON from PowerShell: {}".format(exc)
    return (data if isinstance(data, list) else [data]), ""


def _tr_events(log, ids, max_events, fields):
    """Newest events of the given ids, as dicts {Id, Time, Data:{...}}.

    `fields` is "named" (EventData by name, via XML) or a list of property
    indexes. 'No matching events' is an empty list, not an error; that error is
    told apart by its id, not its (translated) message."""
    id_list = ",".join(str(i) for i in ids)
    if fields == "named":
        shape = ("$x=[xml]$_.ToXml(); $d=@{}; foreach($n in $x.Event.EventData.Data)"
                 "{ $d[[string]$n.Name]=[string]$n.'#text' }; ")
    else:
        shape = "$d=@{}; " + "".join(
            "$d['p{0}']=[string]$_.Properties[{0}].Value; ".format(i) for i in fields)
    cmd = ("try {{ $ev = Get-WinEvent -FilterHashtable @{{LogName='{log}'; Id={ids}}} "
           "-MaxEvents {n} -ErrorAction Stop }} catch {{ if ($_.FullyQualifiedErrorId "
           "-like 'NoMatchingEventsFound*') {{ '[]'; exit 0 }} else {{ throw }} }}; "
           "@($ev | ForEach-Object {{ {shape}[pscustomobject]@{{Id=$_.Id; "
           "Time=$_.TimeCreated.ToString('s'); Data=$d}} }}) | ConvertTo-Json -Depth 4 "
           "-Compress").format(log=log, ids=id_list, n=int(max_events), shape=shape)
    return _tr_ps_json(cmd)


def _tr_hit(r, ctx, text, location, detail, evidence, observed=""):
    found = 0
    for ind in ctx.iocs.search((text or "").lower()):
        r.add_hit(Hit(indicator=ind.value, location=location,
                      detail=detail.replace("{ioc}", ind.value), tier=ind.tier,
                      confidence=ind.confidence, source=ind.source, evidence=evidence,
                      observed=observed, family=ind.family))
        found += 1
    return found


class _TrLeads:
    """Adds leads up to a per-kind cap and counts the rest."""

    def __init__(self, r):
        self.r, self.counts = r, {}

    def add(self, kind, lead):
        n = self.counts.get(kind, 0) + 1
        self.counts[kind] = n
        if n <= _TR_MAX_LEADS:
            self.r.add_lead(lead)

    def finish(self):
        for kind, n in self.counts.items():
            if n > _TR_MAX_LEADS:
                self.r.note("{}: {} further item(s) worth a look were not listed".format(
                    kind, n - _TR_MAX_LEADS))


# --- 1. Mark of the Web -----------------------------------------------------

def _tr_motw_roots():
    roots, seen = [], set()
    bases = [os.environ.get("USERPROFILE", "")]
    for var in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial"):
        bases.append(os.environ.get(var, ""))
    for base in bases:
        if not base:
            continue
        for sub in ("Downloads", "Desktop", "Documents"):
            p = os.path.join(base, sub)
            key = os.path.normcase(p)
            if key not in seen and os.path.isdir(p) and not path_problem(p):
                seen.add(key)
                roots.append(p)
    return roots


_TR_ZONE_LIMIT = 1024 * 1024


def _tr_read_zone(path):
    """HostUrl / ReferrerUrl from a file's Zone.Identifier stream, or None.
    A stream over the limit returns {"_oversize": "1"}: reading only its start
    could miss a HostUrl further in, which would look like "no origin"."""
    try:
        with open(path + ":Zone.Identifier", "rb") as fh:
            raw = fh.read(_TR_ZONE_LIMIT + 1)
    except FileNotFoundError:
        return None  # no download-origin record
    except OSError as exc:
        if exc.errno == errno.EINVAL:
            return None  # a drive (FAT, exFAT...) that cannot hold one
        return {"_unreadable": "1"}
    if len(raw) > _TR_ZONE_LIMIT:
        return {"_oversize": "1"}
    text = (raw.decode("utf-16", "replace") if raw[:2] in (b"\xff\xfe", b"\xfe\xff")
            else raw.decode("utf-8", "replace"))
    found = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and key.strip().lower() in ("hosturl", "referrerurl"):
            found[key.strip().lower()] = value.strip()
    return found


def _tr_check_motw(r, ctx):
    roots = _tr_motw_roots()
    if not roots:
        r.could_not_run("mark-of-the-web", "no Downloads, Desktop or Documents folder found")
        return
    examined, stamped, stopped, oversize = 0, 0, False, 0
    unreadable = {"files": 0, "folders": 0, "deep": 0, "cloud": 0}

    def onerror(exc):
        if getattr(exc, "strerror", None) in (WALK_LINK_REFUSED, WALK_SPECIAL_REFUSED):
            return  # links and special entries are not followed on purpose
        r.skipped += 1
        if getattr(exc, "strerror", None) == WALK_CLOUD_SKIPPED:
            unreadable["cloud"] += 1     # a file, not an unreadable folder
            return
        unreadable["folders"] += 1

    for root in roots:
        base_depth = root.rstrip("\\/").count(os.sep)
        for dirpath, dirs, files in walk_local(root, onerror=onerror):
            kept = [d for d in dirs if d.lower() not in _TR_SKIP_DIRS]
            if dirpath.count(os.sep) - base_depth >= _TR_MAX_DEPTH:
                unreadable["deep"] += len(kept)
                kept = []
            dirs[:] = kept
            for name in files:
                if examined >= _TR_MAX_FILES:
                    stopped = True
                    break
                examined += 1
                path = os.path.join(dirpath, name)
                zone = _tr_read_zone(path)
                if not zone:
                    continue
                if zone.get("_oversize"):
                    r.skipped += 1
                    oversize += 1
                    continue
                if zone.get("_unreadable"):
                    r.skipped += 1
                    unreadable["files"] += 1
                    continue
                stamped += 1
                observed = ""
                try:
                    observed = datetime.datetime.fromtimestamp(
                        os.stat(path).st_ctime).isoformat(timespec="seconds")
                except OSError:
                    pass
                for key, label in (("hosturl", "downloaded from"),
                                   ("referrerurl", "while on the page")):
                    url = zone.get(key, "")
                    try:
                        host = (urlsplit(url).hostname or "") if url else ""
                    except ValueError:
                        # urlsplit raises on an unclosed "[" ("http://[::1"). This
                        # check runs first, so one such file used to end the whole
                        # traces module: Run history, Defender, PowerShell and
                        # startup were all lost. A browser never writes such a
                        # URL, so no host is guessed from it; it is counted.
                        host = ""
                        r.skipped += 1
                    if host:
                        _tr_hit(r, ctx, host, path,
                                "this file was {} {{ioc}} (Mark of the Web: {})".format(
                                    label, url[:300]), EV_CONTACTED, observed)
            if stopped:
                break
        if stopped:
            break
    if oversize:
        r.could_not_run("mark-of-the-web", "{} download record(s) were too large to read in full, "
                        "so where those files came from was not checked".format(oversize))
    if unreadable["files"] or unreadable["folders"]:
        r.could_not_run("mark-of-the-web: unreadable", "{} file(s) and {} folder(s) could not be read, so "
                        "where those files came from was not checked".format(
                            unreadable["files"], unreadable["folders"]))
    if unreadable["cloud"]:
        r.could_not_run("mark-of-the-web: not downloaded", "{} file(s) stored only in iCloud or OneDrive "
                        "and not downloaded, so where those files came from was not checked".format(
                            unreadable["cloud"]))
    if unreadable["deep"]:
        r.could_not_run("mark-of-the-web: deep folders", "{} folder(s) more than {} levels down were not "
                        "examined".format(unreadable["deep"], _TR_MAX_DEPTH))
    r.checked += examined
    r.submetrics["motw_files_examined"] = examined
    r.submetrics["motw_files_with_origin"] = stamped
    if examined or not (unreadable["files"] or unreadable["folders"]):
        r.ran("mark-of-the-web")
    if stopped:
        r.could_not_run("mark-of-the-web: remaining files",
                        "stopped after {:,} files; files beyond that were not "
                        "examined".format(_TR_MAX_FILES))


# --- 2. Win+R history --------------------------------------------------------

# Under HKEY_CURRENT_USER. A module constant so a test can read a separate key
# with the real registry code, never the person's history.
_TR_RUNMRU_KEY = r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"


def _tr_read_runmru():
    """The Win+R history key: (values, last-write local ISO time, error).

    A missing key is an empty history, not an error: nothing was ever typed."""
    try:
        import winreg
    except ImportError:
        return {}, "", "Windows registry not available"
    sub = _TR_RUNMRU_KEY
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, sub)
    except FileNotFoundError:
        return {}, "", ""
    except OSError as exc:
        return {}, "", "could not open the Win+R history: {}".format(exc)
    with key:
        values, i = {}, 0
        while True:
            try:
                name, data, _type = winreg.EnumValue(key, i)
            except OSError:
                break
            values[name] = data
            i += 1
        last_write = winreg.QueryInfoKey(key)[2]
    newest = ""
    if last_write:
        newest = (datetime.datetime(1601, 1, 1) + datetime.timedelta(
            microseconds=last_write // 10)).replace(tzinfo=datetime.timezone.utc
                                                    ).astimezone().replace(
            tzinfo=None).isoformat(timespec="seconds")
    return values, newest, ""


def _tr_check_runbox(r, ctx, leads):
    values, newest, err = _tr_read_runmru()
    if err:
        r.could_not_run("run-history", err)
        return
    order = str(values.get("MRUList", ""))
    entries = [(n, str(v)) for n, v in values.items()
               if len(n) == 1 and n.isalpha() and isinstance(v, str)]
    for name, command in entries:
        command = command[:-2] if command.endswith("\\1") else command
        observed = newest if order[:1] == name else ""
        location = "Win+R history (entry {})".format(name)
        _tr_hit(r, ctx, command, location,
                "a command naming {ioc} was run from the Win+R box: " + command[:300],
                EV_COMMAND, observed)
        if _TR_RUNNER.search(command) and _TR_REMOTE.search(command):
            leads.add("run-history", Lead("run-history", location,
                                          "Win+R command fetches or runs something from "
                                          "the web: " + command[:300],
                                          _TR_WHY_RUNBOX, observed))
    r.checked += len(entries)
    r.submetrics["run_history_entries"] = len(entries)
    r.ran("run-history")


# --- 3. Defender -------------------------------------------------------------

_TR_DEFENDER_LOG = "Microsoft-Windows-Windows Defender/Operational"


_TR_DEF_DETECT_CAP = 2000
# Event 5007 ('settings changed') is mostly Defender's own housekeeping, so it
# is read on its own,
# with a larger cap, by property position (0 product, 1 version, 2 old value,
# 3 new value), and only exclusion changes are kept. Sharing one cap with the
# detections let that noise push real detections out of the window.
_TR_DEF_SETTINGS_CAP = 20000


def _tr_antivirus_products():
    from ..security_products import antivirus_products
    return antivirus_products()


def _tr_check_antivirus(r, leads):
    from ..contract import sanitize_untrusted
    products, error = _tr_antivirus_products()
    active = []
    states = {0: "on", 1: "off", 2: "temporarily paused", 3: "expired"}
    for product in products:
        name = " ".join(sanitize_untrusted(product["name"]).split())[:160]
        state = states.get(product.get("state"), "unknown")
        signature = "up to date" if product.get("signature_status") == 1 else "out of date"
        r.note("Windows Security Center reports antivirus {}: {}; updates {}.".format(name, state, signature))
        if product.get("state") == 0:
            active.append(name)
            if product.get("signature_status") == 0:
                leads.add("antivirus-status", Lead("antivirus-status", "Windows Security Center",
                    name + " is on but reports outdated protection updates",
                    "Open the antivirus application and check its update status. This is not a spyware finding."))
    r.submetrics["antivirus_products_registered"] = len(products)
    r.submetrics["antivirus_products_on"] = len(active)
    if error:
        r.could_not_run("antivirus-status", error)
    else:
        r.ran("antivirus-status")
        if not active:
            leads.add("antivirus-status", Lead("antivirus-status", "Windows Security Center",
                "Windows Security Center did not report an antivirus product currently on",
                "Check Windows Security and your antivirus application. Some enterprise products do not register here; this does not establish infection or prove that no protection is installed."))
    r.note("Antivirus status is what Windows Security Center reports now, not an independent health test or a record of protection at earlier event times.")
    return {"active": active, "complete": not bool(error)}


def _tr_check_defender(r, ctx, leads, protection=None):
    detections, err = _tr_events(_TR_DEFENDER_LOG, (1116, 1117, 5001),
                                 _TR_DEF_DETECT_CAP, "named")
    settings, err2 = ([], "") if err else _tr_events(
        _TR_DEFENDER_LOG, (5007,), _TR_DEF_SETTINGS_CAP, [2, 3])
    if err or err2:
        reason = err or err2
        if "there is not an event log" in reason.lower():
            # Windows removes the log when another antivirus takes over, so
            # there is nothing to read; say that instead of PowerShell's text.
            reason = ("Microsoft Defender's log is not on this PC, which is usual when another "
                      "antivirus is in charge; check that antivirus's own history instead")
        r.could_not_run("defender-history", "Defender log not readable: {}".format(reason))
        return
    # One lead per threat name: a cracked-software tool detected nine times is
    # one thing to look at, not nine. Records arrive newest first.
    threats, protection_off = {}, []
    for ev in detections:
        data = ev.get("Data") or {}
        when, eid = str(ev.get("Time") or ""), int(ev.get("Id") or 0)
        location = "Microsoft Defender log (event {})".format(eid)
        _tr_hit(r, ctx, " ".join(str(v) for v in data.values()), location,
                "Microsoft Defender recorded {ioc} in a detection", EV_ATTEMPTED, when)
        if eid == 5001:
            protection_off.append(Lead(
                "defender-history", location, "Defender real-time protection was turned off",
                _TR_WHY_RTP, when))
            continue
        threat = str(data.get("Threat Name") or "unnamed threat")
        entry = threats.setdefault(threat, {"count": 0, "when": when, "action": "",
                                            "path": str(data.get("Path") or "")})
        entry["count"] += 1
        if not entry["action"] and data.get("Action Name"):
            entry["action"] = str(data.get("Action Name"))
    exclusions, seen_exclusions = [], set()
    for ev in settings:
        data = ev.get("Data") or {}
        new = str(data.get("p3") or "")
        # Counted when an exclusion exists after the change: an addition (no old
        # value) or a modification (old and new both name it). Skipping every
        # event with an old value also skipped modifications, so an exclusion
        # that was changed rather than created never appeared. A deletion leaves
        # no exclusion in the new value and is still skipped. Records arrive
        # newest first, so each exclusion is reported once, at its latest change.
        if "\\Exclusions\\" not in new:
            continue
        excluded = new.split("\\Exclusions\\", 1)[1].rsplit(" = ", 1)[0]
        if excluded in seen_exclusions:
            continue
        seen_exclusions.add(excluded)
        when = str(ev.get("Time") or "")
        exclusions.append((excluded, when))
        _tr_hit(r, ctx, excluded, "Microsoft Defender log (event 5007)",
                "a Defender exclusion naming {ioc} was added or changed", EV_ATTEMPTED, when)

    # At most THREE items, most telling first. A long list of separate Defender
    # items goes unread. Each
    # item keeps the time of its newest record (records arrive newest first).
    def listing(items, limit=12):
        more = len(items) - limit
        return "; ".join(items[:limit]) + (" ... and {} more".format(more) if more > 0 else "")

    log = "Microsoft Defender log"
    if exclusions:
        leads.add("defender-history", Lead(
            "defender-history", log + " (event 5007)",
            "{} Defender exclusion(s) added - Defender does not scan these: {}".format(
                len(exclusions), listing([e[:150] for e, _w in exclusions])),
            _TR_WHY_EXCL, exclusions[0][1]))
    if protection_off:
        r.submetrics["defender_protection_off_events"] = len(protection_off)
        active = (protection or {}).get("active", [])
        # Another antivirus taking over is the ordinary reason Defender switches
        # itself off. Defender being on again now explains nothing: malware that
        # disables it can switch it back on, so that case stays worth a look.
        others = [name for name in active if not _TR_DEFENDER_NAME.search(name)]
        if others:
            r.note("Defender history records {} protection-off event(s), latest {}. Windows Security Center now reports {} on. A different antivirus can make Defender inactive; the historical event does not describe current protection or establish what protected the device then.".format(
                len(protection_off), protection_off[0].observed or "date unavailable", "; ".join(others)))
        else:
            leads.add("defender-history", Lead(
                "defender-history", log + " (event 5001)",
                "Defender history records {} protection-off event(s); current protection is not established by this log".format(len(protection_off)),
                _TR_WHY_RTP + " Check Windows Security and your antivirus application for their current status.", protection_off[0].observed))
    if threats:
        ranked = sorted(threats.items(), key=lambda kv: -kv[1]["count"])
        newest = max(e["when"] for e in threats.values())
        actions = sorted({e["action"] for e in threats.values() if e["action"]})
        leads.add("defender-history", Lead(
            "defender-history", log + " (events 1116/1117)",
            "Defender detected {} different threat(s): {}{}".format(
                len(threats), listing(["'{}' x{}".format(t, e["count"]) for t, e in ranked]),
                " (actions taken: {})".format(", ".join(actions)) if actions else ""),
            _TR_WHY_DETECT, newest))
    exclusions = len(exclusions)
    for rows, cap, what in ((detections, _TR_DEF_DETECT_CAP, "detection"),
                            (settings, _TR_DEF_SETTINGS_CAP, "settings-change")):
        if len(rows) >= cap:
            r.could_not_run("defender-history", "only the newest {:,} {} records were read; older records were not checked".format(
                cap, what))
    r.checked += len(detections) + len(settings)
    r.submetrics["defender_events_read"] = len(detections) + len(settings)
    r.submetrics["defender_threats"] = len(threats)
    r.submetrics["defender_exclusions_added"] = exclusions
    r.ran("defender-history")


# --- 4. PowerShell script-block log -------------------------------------------

_TR_PS_LOG = "Microsoft-Windows-PowerShell/Operational"


def _tr_check_powershell(r, ctx, leads):
    # Properties of 4104: 0 MessageNumber, 1 MessageTotal, 2 ScriptBlockText,
    # 3 ScriptBlockId, 4 Path.
    rows, err = _tr_events(_TR_PS_LOG, (4104,), _TR_PS_EVENTS, [2, 3, 4])
    if err:
        r.could_not_run("powershell-history", "PowerShell log not readable: {}".format(err))
        return
    if not rows:
        r.note("powershell-history: no script blocks are logged. PowerShell records "
               "them only when script-block logging is on (it is off by default, "
               "apart from scripts Windows itself considers suspicious).")
    blocks = {}
    for ev in rows:
        data = ev.get("Data") or {}
        block_id = str(data.get("p3") or "")
        when = str(ev.get("Time") or "")
        entry = blocks.setdefault(block_id or id(ev), {"text": [], "when": when,
                                                         "path": str(data.get("p4") or "")})
        entry["text"].append(str(data.get("p2") or ""))
    for entry in blocks.values():
        text = "\n".join(reversed(entry["text"]))     # events arrive newest first
        where = entry["path"] or "interactive or generated script"
        location = "PowerShell log (script: {})".format(where[:300])
        _tr_hit(r, ctx, text, location,
                "a PowerShell script that names {ioc} ran on this computer",
                EV_COMMAND, entry["when"])
        if _TR_CRADLE_RUN.search(text) and _TR_CRADLE_GET.search(text):
            leads.add("powershell-history", Lead(
                "powershell-history", location,
                "a PowerShell script downloaded and ran code: " +
                re.sub(r"\s+", " ", text)[:240], _TR_WHY_CRADLE, entry["when"]))
    r.checked += len(blocks)
    r.submetrics["powershell_script_blocks_read"] = len(blocks)
    if len(rows) >= _TR_PS_EVENTS:
        r.could_not_run("powershell-history", "only the newest {:,} log records were read; older records were not checked".format(
            _TR_PS_EVENTS))
    r.ran("powershell-history")


# --- 5. Compatibility and launch records: shim cache + Windows 11 launch list -------------------
#
# Windows keeps two lists of programs that ran, readable without admin. Every
# listed program that still exists is fingerprinted and
# compared with the published sample fingerprints - so a sample is found wherever
# it ran from, not only in the folders the hash check walks.

_TR_RAN_MAX_BYTES = 120 * 1024 * 1024     # this check's own cap (the hash check's is 512 MiB)
_TR_SHIM_ENTRIES = 4096                   # shim cache entries read at most
_TR_LOCAL_PATH = re.compile(r"^[A-Za-z]:\\")


def _tr_filetime_local(ft):
    if not ft:
        return ""
    try:
        when = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
    except OverflowError:
        return ""
    return when.replace(tzinfo=datetime.timezone.utc).astimezone().replace(
        tzinfo=None).isoformat(timespec="seconds")


def _tr_parse_shimcache(blob):
    """Paths from the shim cache value, Windows 10/11 layout (published format:
    each entry is b'10ts', 4 bytes, a 4-byte entry size, a 2-byte path length,
    the UTF-16LE path, an 8-byte FILETIME, then data). Malformed entries are
    skipped, never fatal. The FILETIME is the file's modified time, NOT a run
    time, so it is not reported as one."""
    out, pos = [], 0
    while len(out) < _TR_SHIM_ENTRIES:
        pos = blob.find(b"10ts", pos)
        if pos < 0 or pos + 14 > len(blob):
            break
        entry_size = struct.unpack_from("<I", blob, pos + 8)[0]
        plen = struct.unpack_from("<H", blob, pos + 12)[0]
        start = pos + 14
        if 0 < plen <= 2048 and plen % 2 == 0 and start + plen <= len(blob):
            out.append(blob[start:start + plen].decode("utf-16-le", "replace"))
        step = 12 + entry_size
        pos = pos + step if 12 < step <= len(blob) else pos + 4
    return out


def _tr_parse_pca(raw):
    """(path, launch time) from PcaAppLaunchDic.txt: one 'path|YYYY-MM-DD
    HH:MM:SS.fff' per line. Published research reads the time as UTC; keep it in
    UTC instead of converting to the host's local timezone, so the observation is
    stable across machines and matches the value recorded in the source file."""
    text = (raw.decode("utf-16", "replace") if raw[:2] in (b"\xff\xfe", b"\xfe\xff")
            else raw.decode("utf-8-sig", "replace"))
    out = []
    for line in text.splitlines():
        path, sep, stamp = line.rpartition("|")
        if not sep:
            continue
        when = ""
        try:
            when = datetime.datetime.strptime(stamp.strip()[:19], "%Y-%m-%d %H:%M:%S").replace(
                tzinfo=datetime.timezone.utc).isoformat(timespec="seconds")
        except ValueError:
            pass
        out.append((path.strip(), when))
    return out


def _tr_ran_programs():
    """Files in compatibility/launch records: ([(path, when, source)], errors).
    `errors` maps a source to why it could not be read."""
    programs, errors = [], {}
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Control\Session Manager"
                            r"\AppCompatCache") as key:
            blob, _type = winreg.QueryValueEx(key, "AppCompatCache")
        paths = _tr_parse_shimcache(bytes(blob))
        if not paths:
            # A value that exists but yields no entry is another layout, an
            # empty cache or a damaged one; none of those was read.
            errors["shim cache"] = ("the shim cache held no entry in the Windows 10/11 layout, so "
                                    "it was not read")
        elif len(paths) >= _TR_SHIM_ENTRIES:
            errors["shim cache"] = ("only the first {:,} shim cache entries were read; later "
                                    "entries were not fingerprinted".format(_TR_SHIM_ENTRIES))
        for path in paths:
            programs.append((path, "", "shim cache"))
    except (ImportError, OSError) as exc:
        errors["shim cache"] = str(exc)
    pca = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "AppCompat", "pca",
                       "PcaAppLaunchDic.txt")
    problem = path_problem(pca)
    if problem:
        errors["launch list"] = problem
    elif os.path.isfile(pca):
        try:
            with open(pca, "rb") as fh:
                raw = fh.read(32 * 1024 * 1024 + 1)
            if len(raw) > 32 * 1024 * 1024:
                errors["launch list"] = "launch list exceeds the read limit"
                raw = raw[:32 * 1024 * 1024].rsplit(b"\n", 1)[0]
            parsed = _tr_parse_pca(raw)
            if raw.strip() and not parsed:
                errors["launch list"] = ("the launch list has content but no entry in the "
                                         "'path|time' layout, so it was not read")
            for path, when in parsed:
                programs.append((path, when, "launch list"))
        except OSError as exc:
            errors["launch list"] = str(exc)
    # A missing launch list is normal before Windows 11 22H2: absent, not a gap.
    return programs, errors


def _tr_check_ran_programs(r, ctx):
    if ctx.quick:
        r.could_not_run("ran-programs", "skipped by --quick. Files Windows "
                        "recorded were not fingerprinted")
        return
    targets = {i.value: i for i in ctx.iocs.of_type(TYPE_SHA256)}
    if not targets:
        r.could_not_run("ran-programs", "no sample fingerprints in the indicator set")
        return
    programs, errors = _tr_ran_programs()
    if "shim cache" in errors:
        r.could_not_run("ran-programs: shim cache", errors["shim cache"])
    if "launch list" in errors:
        r.could_not_run("ran-programs: launch list", errors["launch list"])
    if not programs:
        if not errors:
            r.could_not_run("ran-programs", "Windows listed no program that ran, so no file was "
                            "fingerprinted from its compatibility and launch records")
        return
    merged = {}
    for path, when, source in programs:
        path = path[4:] if path.startswith("\\??\\") else path
        if not _TR_LOCAL_PATH.match(path):
            continue           # packaged-app ids and the like: not a file path
        entry = merged.setdefault(os.path.normcase(path), {"path": path, "when": "",
                                                           "sources": set()})
        entry["sources"].add(source)
        if when > entry["when"]:
            entry["when"] = when
    if not merged:
        r.could_not_run("ran-programs", "none of the {:,} listed entries is a local program file (they "
                        "are app identifiers or other names), so nothing was fingerprinted".format(len(programs)))
        return
    gone = unreadable = hashed = 0
    for entry in merged.values():
        path = entry["path"]
        try:
            if path_problem(path):
                unreadable += 1
                continue
            if not os.path.isfile(path):
                gone += 1
                continue
            if os.path.getsize(path) > _TR_RAN_MAX_BYTES:
                unreadable += 1
                continue
            digest = hashlib.sha256()
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError:
            unreadable += 1
            continue
        hashed += 1
        ind = targets.get(digest.hexdigest())
        if ind is not None:
            r.add_hit(Hit(indicator=ind.value, location=path,
                          detail="a file listed by Windows ({}) has the "
                                 "fingerprint of a published sample; ShimCache presence alone does not prove execution".format(
                                     " and ".join(sorted(entry["sources"]))),
                          tier=ind.tier, confidence=ind.confidence, source=ind.source,
                          evidence=EV_ON_DISK, observed=entry["when"], family=ind.family))
    r.checked += hashed
    r.skipped += unreadable
    r.submetrics.update({"ran_programs_listed": len(merged),
                         "ran_programs_fingerprinted": hashed,
                         "ran_programs_no_longer_on_disk": gone,
                         "ran_programs_unreadable": unreadable})
    if gone:
        r.note("Coverage limitation: {} historical program file(s) no longer exist "
               "and could not be fingerprinted. Their absence is not evidence of "
               "safety or spyware; only surviving files are checked.".format(gone))
    if unreadable:
        r.could_not_run("ran-programs", "{} listed program(s) were unreadable, refused or "
                       "too large and were not fingerprinted".format(unreadable))
    r.ran("ran-programs")


# --- entry point --------------------------------------------------------------

_TR_HISTORY_LIMIT = 8 * 1024 * 1024


def _tr_extra_history(r, ctx):
    """Saved input is a reference, not proof that a command succeeded."""
    from ..result import EV_REFERENCED
    base = os.environ.get("APPDATA", "")
    root = os.path.join(base, "Microsoft", "Windows", "PowerShell", "PSReadLine")
    try:
        if not base or path_problem(os.path.abspath(root)):
            raise OSError("history location unavailable or refused")
        paths = []
        try:
            with os.scandir(root) as entries:
                for n, entry in enumerate(entries):
                    if n >= 1000:
                        r.could_not_run("psreadline-history", "history directory entry limit reached")
                        break
                    if entry.name.lower().endswith("_history.txt"):
                        paths.append(entry.path)
        except FileNotFoundError:
            pass
        if not paths:
            r.note("No saved console history at the default PSReadLine location; custom history paths are outside scope.")
            r.ran("psreadline-history")
    except OSError:
        paths = []
        r.could_not_run("psreadline-history", "default history directory unreadable or refused")
    for path in sorted(paths):
        try:
            if path_problem(os.path.abspath(path)):
                raise OSError("history path refused")
            with open(path, "rb") as fh:
                fh.seek(0, os.SEEK_END)
                offset = max(0, fh.tell() - _TR_HISTORY_LIMIT)
                fh.seek(offset)
                raw = fh.read(_TR_HISTORY_LIMIT)
            if offset:
                r.could_not_run("psreadline-history", "only the newest history tail was read; older records exceed the limit")
                raw = raw.split(b"\n", 1)[1] if b"\n" in raw else b""
            for n, line in enumerate(raw.decode("utf-8-sig", "replace").splitlines()):
                _tr_hit(r, ctx, line, path + (":tail-line " if offset else ":") + str(n + 1),
                        "saved console input mentions {ioc}; execution and success are unverified", EV_REFERENCED)
                r.checked += 1
            r.ran("psreadline-history")
        except OSError:
            r.could_not_run("psreadline-history", "a discovered history file was unreadable or refused")
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths") as key:
            for n in range(1000):
                try:
                    name, value, typ = winreg.EnumValue(key, n)
                except OSError as exc:
                    if getattr(exc, "winerror", None) == 259:
                        break
                    raise
                if typ in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                    _tr_hit(r, ctx, value, "Explorer TypedPaths/" + name,
                            "saved Explorer input mentions {ioc}; a visit is unverified", EV_REFERENCED)
                r.checked += 1
            else:
                r.could_not_run("explorer-typed-paths", "value limit reached")
        r.ran("explorer-typed-paths")
    except FileNotFoundError:
        r.note("No saved Explorer TypedPaths entries are present.")
        r.ran("explorer-typed-paths")
    except (ImportError, OSError):
        r.could_not_run("explorer-typed-paths", "saved Explorer paths missing or unreadable")


def _tr_batch_continues(line):
    """A final unescaped caret continues a CMD line only outside quotes."""
    quoted, escaped = False, False
    for char in line:
        if escaped:
            escaped = False
        elif char == "^" and not quoted:
            escaped = True
        elif char == '"':
            quoted = not quoted
    return escaped


def _tr_batch_content(text):
    """Recognize limited launch configuration without executing or expanding it.

    A gap affects the unparsed command, not already recognized commands. Compound
    control flow can affect following lines, so its remainder stays unclassified.
    """
    # CMD removes CR bytes; Python splitlines() would invent commands at bare CR,
    # vertical tabs and Unicode separators. Only LF separates physical lines.
    lines = text.replace("\r", "").split("\n")
    active, reference = [], []
    supported = True
    pos = 0
    while pos < len(lines):
        line = lines[pos].lstrip(" \t").lstrip("@").lstrip(" \t")
        pos += 1
        help_form = re.match(r"(?i)^rem[ \t]*/\?", line)
        if not line or (re.match(r"(?i)^rem(?:[ \t]|$)", line) and not help_form):
            # Ordinary REM ignores its entire physical line, even a final caret.
            reference.append(line)
            continue
        if help_form:
            # REM /? is a help command, not a comment. Only the verified simple
            # separator form is understood; other help syntax is an explicit gap.
            tail = re.match(r"(?i)^rem[ \t]*/\?[ \t]*&[ \t]*(?!&)", line)
            if tail:
                line = line[tail.end():].lstrip("@").lstrip(" \t")
                if re.match(r"(?i)^rem[ \t]*/\?", line):
                    reference.append(line)
                    supported = False
                    continue
                if re.match(r"(?i)^rem(?:[ \t]|$)", line) and not re.match(r"(?i)^rem[ \t]*/\?", line):
                    reference.append(line)
                    continue
            else:
                reference.append(line)
                supported = False
                continue
        # Consume continuation lines together. They must not be interpreted as
        # independent commands (notably a continuation of ECHO data).
        parts = [line]
        continued = False
        while _tr_batch_continues(parts[-1]):
            continued = True
            if pos >= len(lines):
                break
            parts.append(lines[pos])
            pos += 1
            # A blank line immediately after an escaped newline is literal
            # data; CMD also consumes the next physical line into this command.
            if parts[-1] == "" and pos < len(lines):
                parts.append(lines[pos])
                pos += 1
        if continued:
            reference.append("\n".join(parts))
            supported = False
            continue
        if line.startswith(":"):
            reference.append(line)
            continue
        if re.match(r"(?i)^rem[.,]", line):
            # Punctuation variants can interact with help/separator syntax.
            # Keep this unparsed line as reference, preserving later commands.
            reference.append(line)
            supported = False
            continue
        if any(ord(c) < 32 and c != "\t" or c in "\x85\u2028\u2029" for c in line):
            reference.append(line)
            supported = False
            if "\0" in line or "\x1a" in line:
                reference.extend(lines[pos:])
                break
            continue
        if re.match(r"(?i)^(?:\(|if\b|for\b|else\b|call\b|goto\b|exit\b)", line):
            reference.extend([line] + lines[pos:])
            supported = False
            break
        quoted, escaped, operators = False, False, False
        for char in line:
            if escaped:
                escaped = False
            elif char == "^":
                escaped = True
            elif char == '"':
                quoted = not quoted
            elif char in "&|<>" and not quoted:
                operators = True
        expanded = bool(re.search(r"[%^!]", line))
        if quoted or operators:
            reference.append(line)
            supported = False
            continue
        if re.match(r"(?i)^(?:echo(?:[^a-z0-9_]|$)|set(?:[ \t]|$)|setlocal(?:[ \t]|$)|endlocal(?:[ \t]|$))", line):
            reference.append(line)
            supported = supported and not expanded
            continue
        command = re.match(r'^(?:"([^"]+)"|([^ \t]+))(?:[ \t]|$)', line)
        token = (command.group(1) or command.group(2)) if command else ""
        if not token or re.search(r"[%^!&|<>()]", token):
            reference.append(line)
            supported = False
            continue
        # The literal command and its literal indicator arguments are launch
        # configuration even when an argument includes an unresolved variable.
        # Do not expand it or claim successful execution; retain a coverage gap.
        active.append(line)
        supported = supported and not expanded
    return "\n".join(active), "\n".join(reference), supported


def _tr_startup_content(raw, name):
    """Separate supported launch configuration from comments and arbitrary text."""
    ext = os.path.splitext(name)[1].lower()
    if ext == ".lnk":
        from ..shelllinks import shelllink_content
        return shelllink_content(raw)
    encoding = "utf-16" if raw.startswith((b"\xff\xfe", b"\xfe\xff")) else "utf-8-sig"
    try:
        text = raw.decode(encoding)
    except UnicodeError:
        return "", raw.decode(encoding, "replace"), False
    active, reference = [], []
    if ext in (".bat", ".cmd"):
        if encoding == "utf-16":
            # Decoding bytes is not proof that CMD accepts them as a batch file.
            # BOM-marked UTF-16 fails the native marker fixture; text is reference
            # evidence only until a supported interpreter/encoding is established.
            return "", text, False
        return _tr_batch_content(text)
    if ext == ".url":
        section = ""
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                section = line.lower()
            elif section == "[internetshortcut]" and line.lower().startswith("url="):
                active.append(line[4:])
            else:
                reference.append(line)
        return "\n".join(active), "\n".join(reference), bool(active)
    # Shell links / other scripts need format-aware interpretation. Do not turn
    # arbitrary embedded strings into persistence evidence or silently clear them.
    # Narrow reference-document allow-list; unknown formats are coverage gaps.
    return "", text + " " + raw.decode("utf-16-le", "replace"), ext in (".txt", ".md", ".log", ".ini")


def _tr_persistence(r, ctx):
    from ..result import EV_PERSISTENCE, EV_REFERENCED
    from ..localpaths import walk_local
    import xml.etree.ElementTree as ET
    try:
        import winreg
        seen_values = set()
        for hive, label in ((winreg.HKEY_CURRENT_USER, "HKCU"), (winreg.HKEY_LOCAL_MACHINE, "HKLM")):
            for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
                for suffix in ("Run", "RunOnce"):
                    path = r"Software\Microsoft\Windows\CurrentVersion" + "\\" + suffix
                    try:
                        with winreg.OpenKey(hive, path, 0, winreg.KEY_READ | view) as key:
                            count = winreg.QueryInfoKey(key)[1]
                            if count > 10000:
                                r.could_not_run("startup-registrations", "registry value limit reached")
                            for n in range(min(count, 10000)):
                                name, value, typ = winreg.EnumValue(key, n)
                                identity = (label, path.casefold(), name.casefold(), typ, str(value))
                                if identity in seen_values:
                                    continue
                                seen_values.add(identity)
                                if typ in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                                    _tr_hit(r, ctx, value, label + "\\" + path + "/" + name,
                                            "auto-start registration mentions {ioc}", EV_PERSISTENCE)
                                r.checked += 1
                        r.ran("startup-registrations")
                    except FileNotFoundError:
                        r.ran("startup-registrations")
                    except OSError:
                        r.could_not_run("startup-registrations", "a registry view could not be read")
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services") as services:
            count = winreg.QueryInfoKey(services)[0]
            if count > 10000:
                r.could_not_run("service-registrations", "service limit reached")
            if count == 0:
                # Every Windows has hundreds of services; an empty key was not read.
                raise OSError("the services key lists no service")
            for n in range(min(count, 10000)):
                name = winreg.EnumKey(services, n)
                for subkey, value_name in ((name, "ImagePath"), (name + r"\Parameters", "ServiceDll")):
                    try:
                        with winreg.OpenKey(services, subkey) as service:
                            value, typ = winreg.QueryValueEx(service, value_name)
                            if typ in (winreg.REG_SZ, winreg.REG_EXPAND_SZ):
                                _tr_hit(r, ctx, value, "Services/" + subkey + "/" + value_name,
                                        "service configuration mentions {ioc}; enabled state is not inferred", EV_PERSISTENCE)
                            r.checked += 1
                    except FileNotFoundError:
                        pass
                    except OSError:
                        r.could_not_run("service-registrations", "a service registration was unreadable")
        r.ran("service-registrations")
    except (ImportError, OSError):
        r.could_not_run("service-registrations", "registry unavailable or unreadable")
    roots = [("scheduled-task-actions", os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Tasks"))]
    for base in (os.environ.get("APPDATA"), os.environ.get("PROGRAMDATA")):
        if base:
            roots.append(("startup-files", os.path.join(base, "Microsoft", "Windows", "Start Menu", "Programs", "Startup")))
    seen_roots = set()
    for check, root in roots:
        norm = os.path.normcase(os.path.abspath(root))
        if norm in seen_roots:
            continue
        seen_roots.add(norm)
        try:
            if path_problem(root):
                raise OSError("refused root")
            if not os.path.isdir(root):
                if check == "startup-files" and not os.path.lexists(root):
                    r.note("No Startup folder at a default location; no entries to inspect there.")
                    r.ran(check)
                    continue
                raise OSError("missing root")
            count = 0
            walk_failed = []
            def onerror(exc):
                walk_failed.append(True)
                r.could_not_run(check, "a directory was unreadable or refused")
            for folder, dirs, files in walk_local(root, onerror=onerror):
                for name in files:
                    count += 1
                    if count > 10000:
                        raise OSError("file count limit reached")
                    path = os.path.join(folder, name)
                    try:
                        if path_problem(path):
                            raise OSError("refused file")
                        with open(path, "rb") as fh:
                            raw = fh.read(1024 * 1024 + 1)
                        if len(raw) > 1024 * 1024:
                            raise OSError("file exceeds read limit")
                        if check == "scheduled-task-actions":
                            # Reject DTDs before parsing either UTF-8 or UTF-16 XML.
                            if b"<!DOCTYPE" in raw.replace(b"\0", b"").upper():
                                raise ValueError("DTD refused")
                            tree = ET.fromstring(raw)
                            text = " ".join(e.text or "" for actions in tree if actions.tag.rsplit("}", 1)[-1] == "Actions"
                                            for e in actions.iter() if e.tag.rsplit("}", 1)[-1] in ("Command", "Arguments", "ClassId"))
                        else:
                            active, reference, supported = _tr_startup_content(raw, name)
                            _tr_hit(r, ctx, active, path, "Startup launch configuration mentions {ioc}; successful execution is unverified", EV_PERSISTENCE)
                            _tr_hit(r, ctx, reference, path, "Startup file content mentions {ioc}; this text does not establish a launch command", EV_REFERENCED)
                            if not supported:
                                r.could_not_run(check, "a Startup file has an unsupported launch format or batch syntax; recognized commands are retained, other content was checked only as text")
                            r.checked += 1
                            continue
                        _tr_hit(r, ctx, text, path, "auto-start artifact mentions {ioc}; successful execution is unverified",
                                EV_PERSISTENCE)
                        r.checked += 1
                    except (OSError, ValueError, ET.ParseError):
                        r.could_not_run(check, "an artifact was unreadable, refused, oversized or malformed")
            if count or not walk_failed:
                r.ran(check)     # a folder that could not be walked and held nothing was not read
        except OSError as exc:
            r.could_not_run(check, str(exc))


def _tr_extended(r, ctx):
    from ..result import EV_DNS, EV_CONTACTED
    if not ctx.extended_windows:
        return
    for log, ids in (("Microsoft-Windows-Sysmon/Operational", [1, 3, 22]), ("Security", [4688])):
        rows, error = _tr_events(log, ids, 10001, "named")
        if error:
            r.could_not_run("extended-process-events", error)
            continue
        if len(rows) > 10000:
            r.could_not_run("extended-process-events", "only the newest 10000 events were checked")
        for n, row in enumerate(rows[:10000]):
            data = row.get("Data") or {}
            event = row.get("Id")
            if event in (1, 4688):
                text = " ".join(str(data.get(k) or "") for k in ("Image", "CommandLine", "NewProcessName"))
                grade = EV_COMMAND
            elif event == 3:
                text = " ".join(str(data.get(k) or "") for k in ("DestinationHostname", "DestinationIp"))
                grade = EV_CONTACTED
            elif event == 22:
                text, grade = str(data.get("QueryName") or ""), EV_DNS
            else:
                continue
            _tr_hit(r, ctx, text, log + "/" + str(event) + "/" + str(n),
                    "existing event record mentions {ioc}", grade, str(row.get("Time") or ""))
            r.checked += 1
        r.ran("extended-process-events")

def run(ctx) -> ModuleResult:
    r = ModuleResult(NAME)
    ctx.partial = r
    if sys.platform != "win32":
        for check in ("mark-of-the-web", "run-history", "defender-history", "antivirus-status",
                      "powershell-history", "ran-programs", "psreadline-history",
                      "explorer-typed-paths", "startup-registrations", "service-registrations",
                      "startup-files", "scheduled-task-actions"):
            r.could_not_run(check, "Windows-only record; not present on this system")
        if ctx.extended_windows:
            r.could_not_run("extended-process-events", "Windows-only records")
        return r
    leads = _TrLeads(r)

    def isolated(checks, fn, *args):
        """One failing check must not cost the others: an unexpected error is
        reported as a gap for that check's records, and the rest still run."""
        try:
            return fn(*args)
        except Exception as exc:  # noqa: BLE001
            # Recorded even if part of the check already succeeded: the rest of
            # its records were not checked, so it must not read as complete.
            for check in checks:
                r.could_not_run(check, "stopped unexpectedly ({}: {}); some of these records "
                                "were not checked".format(type(exc).__name__, str(exc)[:160]))
            return None

    ctx.emit("[*]   traces: files' download origins (Mark of the Web)")
    isolated(("mark-of-the-web",), _tr_check_motw, r, ctx)
    ctx.emit("[*]   traces: Win+R history, Defender and PowerShell logs")
    isolated(("run-history",), _tr_check_runbox, r, ctx, leads)
    protection = isolated(("antivirus-status",), _tr_check_antivirus, r, leads)
    isolated(("defender-history",), _tr_check_defender, r, ctx, leads, protection)
    isolated(("powershell-history",), _tr_check_powershell, r, ctx, leads)
    ctx.emit("[*]   traces: fingerprinting files in compatibility and launch records")
    isolated(("ran-programs",), _tr_check_ran_programs, r, ctx)
    isolated(("psreadline-history", "explorer-typed-paths"), _tr_extra_history, r, ctx)
    isolated(("startup-registrations", "service-registrations", "startup-files",
              "scheduled-task-actions"), _tr_persistence, r, ctx)
    isolated(("extended-process-events",) if ctx.extended_windows else (), _tr_extended, r, ctx)
    leads.finish()
    return r
