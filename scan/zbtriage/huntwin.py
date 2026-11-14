"""Look through Windows' own records (--hunt-windows): what was run, what was installed, what was switched off.

Windows keeps a record of a great deal that happens on it. This reads those records - on this computer, or from
log files (.evtx) someone sends a helper - and looks for the handful of things that mean someone else is in
control: commands whose text was hidden, programs fetched from the internet and run, protection switched off,
services installed from a personal folder, logs cleared, remote sessions, new administrators.

It reads only. Every finding says what the record was, what it means, and what is normal, and the exact text is
printed so a person can judge it themselves. The rules are in huntrules.py; the indicator lists are checked
against every record as well.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from typing import Dict, List, Tuple

from .huntrules import HR_CHANNELS, HR_IDS_BY_CHANNEL, HR_INFO, HR_KNOWN, HR_LOOK, hr_rules_for
from .localpaths import path_problem
from .i18n import T
from .linkcheck import lc_para, lc_say, lc_shown

HW_KNOWN, HW_LOOK, HW_NOTHING = "known-threat", "worth-a-look", "nothing-known"
HW_MAX_PER_CHANNEL = 20000
HW_MAX_FINDINGS = 400
HW_TIMEOUT = 300
HW_TEXT_SHOWN = 1200


class HwError(ValueError):
    pass


# --- matching ------------------------------------------------------------------------------------------------

_HW_ENCODED = re.compile(r"(?i)-e(?:nc(?:odedcommand)?|c)?\s+([A-Za-z0-9+/=]{24,})")


def hw_decoded(text: str) -> str:
    """What a hidden (base64) PowerShell command actually says, so the rules read the real thing.

    Windows records the command as it was typed, so `-EncodedCommand <base64>` hides the whole command from any
    search. Decoding it is the difference between seeing "a hidden command ran" and seeing what it did.
    """
    import base64
    out = []
    for blob in _HW_ENCODED.findall(text or "")[:8]:
        for pad in ("", "=", "==", "==="):
            try:
                raw = base64.b64decode(blob + pad, validate=True)
                break
            except (ValueError, Exception):  # noqa: BLE001
                raw = b""
        if not raw:
            continue
        for encoding in ("utf-16-le", "utf-8"):
            try:
                plain = raw.decode(encoding)
            except (UnicodeError, ValueError):
                continue
            printable = sum(1 for c in plain if c.isprintable() or c in "\r\n\t")
            if plain and printable >= 0.9 * len(plain):
                out.append(plain)
                break
    return "\n".join(out)


def _hw_field(event, field):
    if field == "Text":
        parts = [str(v) for v in event.get("Data", {}).values()]
        whole = "\n".join(parts + [event.get("Text") or ""])
        decoded = event.get("_decoded")
        if decoded is None:
            decoded = event["_decoded"] = hw_decoded(whole)
        return whole + ("\n--- the hidden command says ---\n" + decoded if decoded else "")
    data = event.get("Data") or {}
    if field in data:
        return str(data[field])
    for key, value in data.items():                       # Windows spells some fields differently per version
        if key.lower() == field.lower():
            return str(value)
    got = event.get(field)
    return "" if got is None else str(got)


def hw_test(event, condition) -> bool:
    field, test, *rest = condition
    value = _hw_field(event, field)
    want = rest[0] if rest else ""
    if test == "empty":
        return not value.strip()
    if not value:
        return False
    low, wlow = value.lower(), str(want).lower()
    if test == "has":
        return wlow in low
    if test == "is":
        return low == wlow
    if test == "starts":
        return low.startswith(wlow)
    if test == "ends":
        return low.endswith(wlow)
    if test == "re":
        return re.search(want, value) is not None
    raise HwError("unknown test: " + str(test))


def hw_match(event, rule) -> bool:
    if rule["ids"] and event.get("Id") not in rule["ids"]:
        return False
    if any(not hw_test(event, c) for c in rule.get("all", ())):
        return False
    if rule.get("any") and not any(hw_test(event, c) for c in rule["any"]):
        return False
    if any(hw_test(event, c) for c in rule.get("none", ())):
        return False
    return True


def hw_check(events, channel, iocs=None) -> List[dict]:
    """Findings for one channel's events."""
    rules = hr_rules_for(channel)
    out = []
    for event in events:
        text = _hw_field(event, "Text")
        decoded = event.get("_decoded") or ""
        plain, _sep, _rest = text.partition("\n--- the hidden command says ---\n")
        for rule in rules:
            if hw_match(event, rule):
                out.append({"rule": rule["id"], "level": rule["level"], "says": rule["says"],
                            "means": rule["means"], "channel": channel, "id": event.get("Id"),
                            "when": event.get("Time", ""), "record": event.get("RecordId", 0),
                            "text": plain[:HW_TEXT_SHOWN], "decoded": decoded[:HW_TEXT_SHOWN],
                            "indicator": None})
        if iocs is not None and text:
            for ind in iocs.search(text.lower())[:3]:
                out.append({"rule": "indicator", "level": HR_KNOWN,
                            "says": lc_say("a record mentions {value} - listed as {family} infrastructure",
                                           value=ind.value, family=ind.family or lc_say("spyware")),
                            "means": lc_say("This name or address is on a published list of spyware "
                                            "infrastructure. Keep the computer as it is and get expert help."),
                            "channel": channel, "id": event.get("Id"), "when": event.get("Time", ""),
                            "record": event.get("RecordId", 0), "text": plain[:HW_TEXT_SHOWN],
                            "decoded": decoded[:HW_TEXT_SHOWN],
                            "indicator": {"value": ind.value, "family": ind.family or "spyware",
                                          "source": ind.source}})
    return out


# --- collecting from this computer ----------------------------------------------------------------------------

_HW_PS = ("powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command")


def hw_powershell(script: str, timeout: int = HW_TIMEOUT) -> Tuple[int, str]:
    exe = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "WindowsPowerShell", "v1.0",
                       "powershell.exe")
    argv = [exe if os.path.isfile(exe) else "powershell.exe"] + list(_HW_PS[1:]) + [script]
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    try:
        done = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=timeout, creationflags=flags, stdin=subprocess.DEVNULL)
        return done.returncode, (done.stdout or "") + ("\n" + done.stderr if done.returncode else "")
    except (OSError, subprocess.SubprocessError) as exc:
        return 1, str(exc)[:200]


_HW_SCRIPT = (
    "$ErrorActionPreference='Stop'; "
    "try {{ $ev = Get-WinEvent -FilterHashtable @{{LogName='{log}'; Id={ids}}} -MaxEvents {n} -ErrorAction Stop }} "
    "catch {{ if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {{ '[]'; exit 0 }} else {{ throw }} }}; "
    "@($ev | ForEach-Object {{ $x=[xml]$_.ToXml(); $d=@{{}}; "
    "foreach($n in $x.Event.EventData.Data){{ if($n.Name){{ $d[[string]$n.Name]=[string]$n.'#text' }} "
    "else {{ $d['Data'+$d.Count]=[string]$n.'#text' }} }}; "
    "foreach($n in $x.Event.UserData.ChildNodes){{ foreach($c in $n.ChildNodes){{ "
    "$d[[string]$c.LocalName]=[string]$c.'#text' }} }}; "
    "[pscustomobject]@{{Id=$_.Id; Time=$_.TimeCreated.ToString('s'); RecordId=$_.RecordId; "
    "Provider=$_.ProviderName; Data=$d; Text=$_.Message}} }}) | ConvertTo-Json -Depth 5 -Compress")


def hw_live_channel(channel: str, ids, limit=HW_MAX_PER_CHANNEL) -> Tuple[List[dict], str]:
    """(events, why not) for one channel on this computer, through Windows' own reader."""
    if sys.platform != "win32":
        return [], "this computer is not Windows"
    code, text = hw_powershell(_HW_SCRIPT.format(log=channel, ids=",".join(str(i) for i in sorted(ids)) or "0",
                                                 n=int(limit)))
    body = (text or "").strip()
    if code or not body:
        reason = body.replace("\n", " ")[:160] or "no answer from Windows"
        if "No events were found" in reason or "NoMatchingEventsFound" in reason:
            return [], ""
        if "Attempted to perform an unauthorized operation" in reason or "Access is denied" in reason:
            return [], "needs administrator rights"
        if "There is not an event log" in reason or "could not be found" in reason:
            return [], "this log does not exist on this computer"
        return [], reason
    try:
        doc = json.loads(body[body.index("["):] if body.startswith("@") else body)
    except ValueError:
        try:
            doc = json.loads(body)
        except ValueError:
            return [], "the answer could not be read"
    if isinstance(doc, dict):
        doc = [doc]
    events = []
    for item in doc if isinstance(doc, list) else []:
        if isinstance(item, dict):
            data = item.get("Data")
            events.append({"Id": item.get("Id") or 0, "Time": item.get("Time") or "",
                           "RecordId": item.get("RecordId") or 0, "Provider": item.get("Provider") or "",
                           "Data": data if isinstance(data, dict) else {},
                           "Text": item.get("Text") or ""})
    return events, ""


# --- the check ------------------------------------------------------------------------------------------------

def hw_from_files(paths, iocs=None, progress=None) -> Dict[str, object]:
    """Check log files (.evtx), on any operating system."""
    from .evtxread import EvError, ev_events
    say = progress or (lambda text: None)
    findings, gaps, counts = [], [], {}
    for path in paths:
        problem = path_problem(os.path.abspath(path))
        if problem:
            gaps.append("{}: {}".format(path, problem))
            continue
        if not os.path.isfile(path):
            gaps.append(lc_say("{path}: not found", path=path))
            continue
        say("  " + T("reading {what}", what=os.path.basename(path)))
        try:
            events = ev_events(path, limit=HW_MAX_PER_CHANNEL)
        except (EvError, OSError) as exc:
            gaps.append("{}: {}".format(os.path.basename(path), exc))
            continue
        channel = (events[0].get("Channel") or os.path.basename(path)) if events else os.path.basename(path)
        counts[channel] = counts.get(channel, 0) + len(events)
        findings += hw_check(events, channel, iocs)
    return hw_report(findings, counts, gaps, source="files")


def hw_from_this_computer(iocs=None, progress=None, with_security=False) -> Dict[str, object]:
    say = progress or (lambda text: None)
    findings, gaps, counts = [], [], {}
    for channel, needs_admin in HR_CHANNELS:
        if needs_admin and not with_security:
            gaps.append(lc_say("{channel}: not read (needs administrator rights; add --with-security and run as "
                               "administrator)", channel=channel))
            continue
        ids = HR_IDS_BY_CHANNEL.get(channel) or set()
        say("  " + T("reading {what}", what=channel))
        events, why = hw_live_channel(channel, ids)
        if why:
            gaps.append("{}: {}".format(channel, why))
            continue
        counts[channel] = len(events)
        findings += hw_check(events, channel, iocs)
    return hw_report(findings, counts, gaps, source="this computer")


def hw_report(findings, counts, gaps, source="") -> Dict[str, object]:
    rank = {HR_KNOWN: 0, HR_LOOK: 1, HR_INFO: 2}
    findings.sort(key=lambda f: (rank[f["level"]], f["when"]), reverse=False)
    level = HW_NOTHING
    if any(f["level"] == HR_KNOWN for f in findings):
        level = HW_KNOWN
    elif any(f["level"] == HR_LOOK for f in findings):
        level = HW_LOOK
    groups: Dict[str, dict] = {}
    for f in findings:
        key = f["rule"] + "|" + (f["indicator"]["value"] if f["indicator"] else "")
        group = groups.setdefault(key, {"rule": f["rule"], "level": f["level"], "says": f["says"],
                                        "means": f["means"], "indicator": f["indicator"], "count": 0,
                                        "first": f["when"], "last": f["when"], "examples": []})
        group["count"] += 1
        group["first"] = min(group["first"] or f["when"], f["when"] or group["first"])
        group["last"] = max(group["last"] or f["when"], f["when"] or group["last"])
        if len(group["examples"]) < 3:
            group["examples"].append({"when": f["when"], "channel": f["channel"], "id": f["id"],
                                      "record": f["record"], "text": f["text"],
                                      "decoded": f.get("decoded", "")})
    ordered = sorted(groups.values(), key=lambda g: (rank[g["level"]], -g["count"]))
    return {"level": level, "groups": ordered[:HW_MAX_FINDINGS], "counts": counts, "gaps": gaps,
            "source": source, "events": sum(counts.values()), "findings": len(findings)}


_HW_HEAD = {HW_KNOWN: "SOMETHING IN THE RECORDS NEEDS ACTING ON", HW_LOOK: "WORTH A LOOK",
            HW_NOTHING: "NOTHING KNOWN IN THE RECORDS"}
_HW_WORD = {HR_KNOWN: "THIS IS HOW AN ATTACK LOOKS", HR_LOOK: "WORTH A LOOK", HR_INFO: "FOR CONTEXT"}


def hw_headline(result) -> str:
    return _HW_HEAD[result["level"]]


from .safetext import safe_render  # noqa: E402


@safe_render
def hw_render(result, show_context=False) -> str:
    lines = ["=" * 72, "  " + T("WINDOWS' OWN RECORDS") + "  -  " + T(_HW_HEAD[result["level"]]),
             "  " + T("Read only: nothing was changed, nothing was contacted."), "=" * 72, "",
             "  " + T("Read {n} records from {source} ({places} place(s) looked at).",
                      n="{:,}".format(result["events"]), source=T(result["source"]),
                      places=len(result["counts"])), ""]
    shown = 0
    for group in result["groups"]:
        if group["level"] == HR_INFO and not show_context:
            continue
        shown += 1
        when = group["first"][:19] if group["first"] else T("unknown time")
        span = "" if group["count"] == 1 else " " + T("({n} times, {first} to {last})", n=group["count"],
                                                      first=when, last=(group["last"] or "")[:19])
        lines.append("  [{}] {}{}".format(T(_HW_WORD[group["level"]]), lc_shown(group["says"]), span or ", " + when))
        lines.append("      " + T("what it means:") + " " + lc_shown(group["means"]))
        for example in group["examples"][:2]:
            lines.append("      " + T("{when} - {channel} event {id} (record {record})", when=example["when"][:19],
                                      channel=example["channel"], id=example["id"], record=example["record"]))
            shown_lines = 0
            for line in (example["text"] or "").splitlines():
                if line.strip() and shown_lines < 12:
                    lines.append("        | " + line.strip()[:160])
                    shown_lines += 1
            if example.get("decoded"):
                lines.append("        " + T("the hidden command actually says:"))
                for line in example["decoded"].splitlines()[:12]:
                    if line.strip():
                        lines.append("        >> " + line.strip()[:160])
        lines.append("")
    if not shown:
        lines.append("  " + T("Nothing in the records matched what this check looks for."))
        lines.append("")
    context = [g for g in result["groups"] if g["level"] == HR_INFO]
    if context and not show_context:
        lines.append("  " + T("FOR CONTEXT (add --all to read these in full)"))
        for group in context:
            lines.append("    - " + T("{what} ({n} times)", what=lc_shown(group["says"]), n=group["count"]))
        lines.append("")
    if result["gaps"]:
        lines.append("  " + T("NOT READ"))
        for gap in result["gaps"][:30]:
            lines.append("    - " + lc_shown(gap))
        lines.append("")
    lines += lc_para(["Windows keeps these records only for a while, and a smaller log holds less; something "
                      "missing here", "is not proof that nothing happened."], width=104)
    lines += lc_para(["A record is not a verdict. Read the text above and ask whether you, or software you installed,",
                      "could have done it."], width=104)
    return "\n".join(lines)


def hw_command(args, load_iocs, out=print) -> int:
    try:
        iocs = load_iocs(args)
    except Exception as exc:  # noqa: BLE001
        out(T("(Indicator lists could not be loaded: {why}. Checking behaviour only.)", why=str(exc)[:160]))
        iocs = None
    paths = [p for p in (args.hunt_windows or []) if p]
    if paths:
        result = hw_from_files(paths, iocs, progress=out)
    elif sys.platform != "win32":
        out(T("Reading this computer's own records only works on Windows. Give log files instead:") + "\n"
            "  zero-breach-toolkit --hunt-windows exported.evtx\n" + T("On the Windows computer, export them with:") +
            "\n  wevtutil epl \"Microsoft-Windows-PowerShell/Operational\" ps.evtx")
        return 1
    else:
        result = hw_from_this_computer(iocs, progress=out, with_security=bool(getattr(args, "with_security", False)))
    out("")
    out(hw_render(result, show_context=bool(getattr(args, "startup_all", False) or
                                            getattr(args, "hunt_all", False))))
    if getattr(args, "json", None):
        with open(args.json, "x", encoding="utf-8") as fh:
            json.dump(dict(result, tool="zero-breach-toolkit windows records"), fh, indent=2, ensure_ascii=False)
        out("\n" + T("Saved: {path}", path=args.json))
    return {HW_KNOWN: 3, HW_LOOK: 1, HW_NOTHING: 0}[result["level"]]
