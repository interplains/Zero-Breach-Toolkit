"""Household report (--combine): one summary of several saved reports.

A family checks the laptop, two phones, the router's DNS log and the home network on different days,
with the program and with the phone-check web page. Each run saves its own report. This puts them
side by side: one line per device, what was found, what is worth a look, and - as important - what
could NOT be checked, plus which kinds of check are missing from the house altogether.

Reads saved JSON only. Contacts nothing, changes nothing, never alters the reports it reads.
Everything read from a report is treated as untrusted text (it can quote evidence).
"""
from __future__ import annotations

import datetime
import html
import json
import os
import re

from . import __version__
from .contract import sanitize_untrusted
from .i18n import T, TN
from .localpaths import path_problem
from .report import _gap_lines

HH_MAX_BYTES = 256 * 1024 * 1024
HH_LIST_LIMIT = 8
HH_OLD_DAYS = 30

RED, AMBER, GREEN, GREY = "red", "amber", "green", "grey"
HH_ORDER = {RED: 0, AMBER: 1, GREY: 2, GREEN: 3}
HH_MARK = {RED: "[!!]", AMBER: "[! ]", GREEN: "[ok]", GREY: "[--]"}

HH_STATUS = {
    "INDICATORS_FOUND": (RED, "Known spyware indicators found"),
    "WITHDRAWN_ONLY": (AMBER, "Only indicators their publisher has since withdrawn matched"),
    "WITHDRAWN_ONLY_WITH_GAPS": (AMBER, "Only withdrawn indicators matched; parts could not be checked"),
    "REFERENCES_ONLY": (AMBER, "Only references to known spyware addresses (saved or mentioned, not contacted)"),
    "REFERENCES_ONLY_WITH_GAPS": (AMBER, "Only references to known spyware addresses; parts could not be checked"),
    "NO_KNOWN_INDICATORS_WITH_GAPS": (AMBER, "No known spyware indicators found, but parts could not be checked"),
    "NO_KNOWN_INDICATORS": (GREEN, "No known spyware indicators found"),
}

HH_KINDS = {
    "computer": "computer",
    "iphone": "iPhone",
    "android": "Android phone or TV",
    "phone": "phone",
    "dns-log": "DNS log (every device that used it)",
    "home-network": "home network",
    "tool-check": "single check",
}

# The smaller checks' saved results ("tool": "zero-breach-toolkit <name>", plus a "level"), and how to call them.
HH_TOOLS = {
    "wifi nearby": "Hidden Wi-Fi networks nearby",
    "live connections": "Live connections",
    "startup inventory": "What starts automatically",
    "network recording check": "Network recording",
    "windows records": "Windows' own records",
    "hash look-up": "File fingerprint look-up",
    "link check": "Link check",
    "email check": "Email check",
    "qr code check": "QR code check",
    "extraction check": "Phone extraction check",
}
HH_LEVEL_COLOUR = {"known-threat": RED, "dangerous": RED, "worth-a-look": AMBER, "incomplete": AMBER,
                   "nothing-known": GREEN, "clean": GREEN}
HH_LEVEL_TEXT = {RED: "Something known to be dangerous was found - open its own result",
                 AMBER: "Something is worth a look", GREEN: "Nothing known was found",
                 GREY: "Result not recognised - open the full result"}

# What a household would still be missing, and why it matters. Fixed text.
HH_MISSING = (
    ("computer", "No computer was checked. Run the program on each computer in the house."),
    ("phone", "No phone was checked. Phones are the usual target: check each one (the web page needs no install)."),
    ("home-network", "The home network was not checked (--home-network): who is on the Wi-Fi, open doors, "
                     "and whether the router's lookups are being changed."),
    ("dns-log", "No router or Pi-hole DNS log was checked (--dns-log). If your router or Pi-hole keeps one, it "
                "covers every device in the house at once, including TVs and tablets."),
)


class HouseholdError(Exception):
    pass


def _clean(value, limit=300):
    return sanitize_untrusted(str(value if value is not None else ""))[:limit]


def _parse_time(text):
    try:
        when = datetime.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    if when.tzinfo is None:
        when = when.astimezone()
    return when


def hh_load(path):
    """The JSON document at `path`, or raises HouseholdError with a plain reason."""
    problem = path_problem(os.path.abspath(path))
    if problem:
        raise HouseholdError("refused: " + problem)
    try:
        size = os.path.getsize(path)
        if size > HH_MAX_BYTES:
            raise HouseholdError("larger than {} MB, so it is not a report from this program".format(HH_MAX_BYTES >> 20))
        with open(path, "r", encoding="utf-8-sig") as fh:   # -sig: a report re-saved by Notepad/PowerShell has a BOM
            doc = json.load(fh)
    except OSError as exc:
        raise HouseholdError("could not be read: {}".format(exc.strerror or exc))
    except (ValueError, UnicodeDecodeError):
        raise HouseholdError("is not a JSON report")
    if not isinstance(doc, dict):
        raise HouseholdError("is not a report from this program")
    return doc


def _phone_kind(doc):
    modules = doc.get("modules") or {}
    if "ios" in modules and (modules["ios"] or {}).get("status") != "NOT_APPLICABLE":
        return "iphone"
    if "android" in modules and (modules["android"] or {}).get("status") != "NOT_APPLICABLE":
        return "android"
    return "phone"


def hh_kind(doc):
    """computer | iphone | android | phone | dns-log | home-network, or raises HouseholdError."""
    tool = doc.get("tool")
    if isinstance(tool, str) and tool.startswith("zero-breach-toolkit home-network"):
        return "home-network"
    if isinstance(tool, str) and tool[len("zero-breach-toolkit "):] in HH_TOOLS and \
            tool.startswith("zero-breach-toolkit ") and isinstance(doc.get("level"), str):
        return "tool-check"
    if not (isinstance(tool, dict) and tool.get("name") == "zero-breach-toolkit"):
        raise HouseholdError("is not a report from this program")
    scope = doc.get("scope") or {}
    if doc.get("report_type") == "sharing-summary":
        return "phone" if scope.get("phone") is True else "computer"
    if not isinstance(doc.get("verdict"), dict):
        raise HouseholdError("is not a complete report")
    if scope.get("dns_logs"):
        return "dns-log"
    if scope.get("phone"):
        return _phone_kind(doc)
    return "computer"


def _default_label(kind, doc):
    if kind == "computer":
        p = doc.get("platform") or {}
        name = " ".join(_clean(p.get(k), 40) for k in ("system", "release") if p.get(k))
        return T("Computer ({name})", name=name) if name else T("Computer")
    if kind == "iphone":
        for note in (doc.get("modules") or {}).get("ios", {}).get("notes", []):
            m = re.search(r"iOS version recorded by backup: ([0-9.]+)", str(note))
            if m:
                return T("iPhone (iOS {version})", version=m.group(1))
        return T("iPhone")
    if kind == "android":
        return T("Android phone or TV")
    if kind == "dns-log":
        return T("DNS log")
    if kind == "home-network":
        return T("Home network {subnet}", subnet=_clean(doc.get("subnet"), 40))
    if kind == "tool-check":
        return T(HH_TOOLS.get(str(doc.get("tool"))[len("zero-breach-toolkit "):], "Single check"))
    return T("Phone")


def _hit_line(hit, module):
    family = _clean(hit.get("family"), 60)
    what = _clean(hit.get("indicator"), 120)
    grade = _clean(hit.get("evidence"), 30)
    return "{}{} ({}{})".format(family + ": " if family else "", what, module, ", " + grade if grade else "")


def hh_entry(doc, label="", source=""):
    """One normalised line of the household report from a loaded document."""
    kind = hh_kind(doc)
    entry = {"label": _clean(label, 80) or _default_label(kind, doc), "kind": kind,
             "kind_label": T(HH_KINDS[kind]), "source": _clean(source, 260), "when": "", "age_days": None,
             "colour": GREY, "result": "", "findings": [], "more_findings": 0, "worth_a_look": [],
             "gaps": [], "notes": [], "summary_only": False}
    when = _parse_time(doc.get("timestamp") or doc.get("made") or doc.get("saved"))
    if when:
        entry["when"] = when.strftime("%Y-%m-%d %H:%M")
        entry["age_days"] = max(0, (datetime.datetime.now(datetime.timezone.utc) - when).days)
    if kind == "home-network":
        findings = doc.get("findings") or []
        entry["worth_a_look"] = [_clean(f[0] if isinstance(f, (list, tuple)) and f else f, 200)
                                 for f in findings[:HH_LIST_LIMIT]]
        entry["gaps"] = [_clean(g, 300) for g in (doc.get("gaps") or [])]
        entry["notes"].append(T("{n} devices seen", n=len(doc.get("devices") or [])))
        if findings:
            entry["colour"] = AMBER
            entry["result"] = TN("{n} thing worth a look", "{n} things worth a look", len(findings))
        else:
            entry["colour"] = GREEN
            entry["result"] = T("Nothing stood out")
        if entry["gaps"] and entry["colour"] == GREEN:
            entry["colour"] = AMBER
            entry["result"] = T("Nothing stood out, but parts could not be checked")
        return entry
    if kind == "tool-check":
        entry["colour"] = HH_LEVEL_COLOUR.get(doc.get("level"), GREY)
        entry["result"] = T(HH_LEVEL_TEXT[entry["colour"]])
        if doc.get("summary"):
            entry["notes"].append(_clean(doc["summary"], 300))
        for item in (doc.get("findings") or [])[:HH_LIST_LIMIT]:
            text = item.get("says") or item.get("what") or item.get("indicator") if isinstance(item, dict) else item
            if text:
                entry["worth_a_look"].append(_clean(text, 200))
        return entry
    verdict = doc.get("verdict") or {}
    colour, text = HH_STATUS.get(verdict.get("status"), (GREY, "Result not recognised - open the full report"))
    entry["colour"], entry["result"] = colour, T(text)
    if doc.get("report_type") == "sharing-summary":
        entry["summary_only"] = True
        entry["notes"].append(T("Sharing summary only: no details. Use the full report for those."))
        gap_count = (doc.get("coverage") or {}).get("gap_count") or 0
        if gap_count:
            entry["gaps"] = [TN("{n} part could not be checked", "{n} parts could not be checked", gap_count)]
    else:
        hits = [(name, h) for name, m in (doc.get("modules") or {}).items() for h in (m or {}).get("hits", [])]
        entry["findings"] = [_hit_line(h, _clean(name, 40)) for name, h in hits[:HH_LIST_LIMIT]]
        entry["more_findings"] = max(0, len(hits) - HH_LIST_LIMIT)
        entry["worth_a_look"] = [_clean(l.get("what") or l.get("check"), 200)
                                 for l in (doc.get("worth_a_look") or [])[:HH_LIST_LIMIT]]
        raw = [str(g) for g in (verdict.get("gaps") or [])]
        try:
            lines = _gap_lines(raw)          # the main report's grouping: one readable line per kind of gap
        except Exception:                    # an unexpected gap shape must not hide the rest of the house
            lines = raw
        # "android/android:history: no battery history" -> "no battery history" (the device is already named)
        entry["gaps"] = [_clean(re.sub(r"^\s*[\w.-]+/[\w.:-]+: ", "", g), 300) for g in lines]
    if doc.get("scan_state") == "partial" and (doc.get("scope") or {}).get("cancelled"):
        entry["notes"].append(T("The check was stopped before it finished."))
        if entry["colour"] == GREEN:
            entry["colour"] = AMBER
    ioc = doc.get("ioc_set") or {}
    if ioc.get("stale"):
        entry["notes"].append(T("Its indicator list was {n} days old: update and check again.", n=ioc.get("age_days")))
    return entry


def hh_parse_arg(arg):
    """'LABEL=PATH' or 'PATH' -> (label, path)."""
    if "=" in arg:
        label, path = arg.split("=", 1)
        if label and not re.search(r"[\\/:]", label) and os.path.exists(path):
            return label.strip(), path
    return "", arg


def hh_combine(args_list):
    """Build the household document from a list of 'PATH' or 'LABEL=PATH' strings."""
    entries, unreadable = [], []
    for arg in args_list:
        label, path = hh_parse_arg(arg)
        try:
            entries.append(hh_entry(hh_load(path), label, os.path.basename(path)))
        except HouseholdError as exc:
            unreadable.append({"source": _clean(os.path.basename(path), 260), "reason": _clean(exc, 200)})
        except Exception as exc:  # noqa: BLE001 - one damaged or hand-edited report must not hide the others
            unreadable.append({"source": _clean(os.path.basename(path), 260),
                               "reason": _clean("has an unexpected shape, so it could not be summarised ({})".format(
                                   type(exc).__name__), 200)})
    entries.sort(key=lambda e: (HH_ORDER[e["colour"]], e["label"].lower()))
    kinds = {e["kind"] for e in entries}
    present = kinds | ({"phone"} if kinds & {"iphone", "android", "phone"} else set())
    missing = [T(text) for kind, text in HH_MISSING if kind not in present]
    old = [e["label"] for e in entries if e["age_days"] is not None and e["age_days"] > HH_OLD_DAYS]
    worst = min((HH_ORDER[e["colour"]] for e in entries), default=HH_ORDER[GREY])
    overall = next(c for c, o in HH_ORDER.items() if o == worst)
    if unreadable and overall == GREEN:
        overall = AMBER
    return {"report_type": "household", "tool": {"name": "zero-breach-toolkit", "version": __version__},
            "made": datetime.datetime.now().astimezone().replace(microsecond=0).isoformat(),
            "overall": overall, "entries": entries, "unreadable": unreadable,
            "missing": missing, "old": old}


HH_HEADLINE = {
    RED: "AT LEAST ONE DEVICE HAS KNOWN SPYWARE INDICATORS - read that device's full report first.",
    AMBER: "No known spyware indicators, but some things are worth a look or could not be checked.",
    GREEN: "No known spyware indicators on the devices checked. That is not a guarantee.",
    GREY: "Nothing could be summarised.",
}


from .safetext import safe_render  # noqa: E402


@safe_render
def hh_render(doc):
    out = ["=" * 72, "  " + T("HOUSEHOLD REPORT") + "  -  " + doc["made"][:16].replace("T", " "),
           "  " + T("One summary of the separate checks. Each device's own report has the details."), "=" * 72, "",
           "  " + T(HH_HEADLINE[doc["overall"]]), ""]
    for e in doc["entries"]:
        out.append("  {} {}  -  {}".format(HH_MARK[e["colour"]], e["label"], e["result"]))
        out.append("       {}{}".format(e["kind_label"], ", " + T("checked {when}", when=e["when"]) if e["when"] else ""))
        for f in e["findings"]:
            out.append("       ! " + f)
        if e["more_findings"]:
            out.append("       ! " + T("and {n} more in that device's report", n=e["more_findings"]))
        for w in e["worth_a_look"]:
            out.append("       ? " + w)
        for g in e["gaps"][:HH_LIST_LIMIT]:
            out.append("       - " + T("not checked: {gap}", gap=g))
        if len(e["gaps"]) > HH_LIST_LIMIT:
            out.append("       - " + T("and {n} more gaps", n=len(e["gaps"]) - HH_LIST_LIMIT))
        for n in e["notes"]:
            out.append("       * " + n)
        out.append("")
    if doc["unreadable"]:
        out.append("  " + T("COULD NOT BE INCLUDED"))
        out += ["    - {}: {}".format(u["source"], u["reason"]) for u in doc["unreadable"]]
        out.append("")
    if doc["old"]:
        out.append("  " + T("OLDER THAN {n} DAYS - check these again:", n=HH_OLD_DAYS) + " " + ", ".join(doc["old"]))
        out.append("")
    if doc["missing"]:
        out.append("  " + T("NOT IN THIS REPORT"))
        out += ["    - " + m for m in doc["missing"]]
        out.append("")
    out.append("  " + T("Key: [!!] known indicators  [! ] worth a look or not fully checked  [ok] nothing known found"))
    from .safetext import st_wrap_lines
    return "\n".join(st_wrap_lines(out))


HH_CSS = ("body{font:15px/1.45 system-ui,sans-serif;max-width:860px;margin:24px auto;padding:0 16px;color:#16181d}"
          "h1{font-size:22px;margin:0 0 4px}.sub{color:#5b6270;margin:0 0 18px}"
          ".head{padding:12px 14px;border-radius:8px;font-weight:700;margin-bottom:18px}"
          ".dev{border:1px solid #d8dbe0;border-left:8px solid #9aa1ab;border-radius:8px;padding:10px 14px;margin:10px 0}"
          ".red{border-left-color:#c62828}.amber{border-left-color:#e0a100}.green{border-left-color:#2e7d32}"
          ".head.red{background:#fde8e8}.head.amber{background:#fff4d6}.head.green{background:#e6f4e7}.head.grey{background:#eee}"
          ".dev h2{font-size:17px;margin:0}.meta{color:#5b6270;font-size:13px}ul{margin:6px 0 0 18px;padding:0}"
          "li.f{color:#a11}li.g{color:#5b6270}h3{font-size:15px;margin:18px 0 6px}"
          "@media print{body{margin:0}}")


def hh_html(doc):
    e_ = html.escape
    parts = ["<!doctype html><html><head><meta charset='utf-8'><meta name='viewport' content='width=device-width'>"
             "<title>{}</title><style>{}</style></head><body>".format(e_(T("Household report")), HH_CSS),
             "<h1>{}</h1><p class='sub'>{} &middot; {}</p>".format(
                 e_(T("Household report")), e_(doc["made"][:16].replace("T", " ")),
                 e_(T("One summary of the separate checks. Each device's own report has the details."))),
             "<div class='head {}'>{}</div>".format(doc["overall"], e_(T(HH_HEADLINE[doc["overall"]])))]
    for e in doc["entries"]:
        items = ["<li class='f'>{}</li>".format(e_(f)) for f in e["findings"]]
        if e["more_findings"]:
            items.append("<li class='f'>{}</li>".format(e_(T("and {n} more in that device's report", n=e["more_findings"]))))
        items += ["<li>{}</li>".format(e_(w)) for w in e["worth_a_look"]]
        items += ["<li class='g'>{}</li>".format(e_(T("not checked: {gap}", gap=g))) for g in e["gaps"][:HH_LIST_LIMIT]]
        items += ["<li class='g'>{}</li>".format(e_(n)) for n in e["notes"]]
        parts.append("<div class='dev {}'><h2>{} &mdash; {}</h2><div class='meta'>{}{}</div>{}</div>".format(
            e["colour"], e_(e["label"]), e_(e["result"]), e_(e["kind_label"]),
            e_(", " + T("checked {when}", when=e["when"])) if e["when"] else "",
            "<ul>{}</ul>".format("".join(items)) if items else ""))
    if doc["unreadable"]:
        parts.append("<h3>{}</h3><ul>{}</ul>".format(e_(T("COULD NOT BE INCLUDED")), "".join(
            "<li>{}: {}</li>".format(e_(u["source"]), e_(u["reason"])) for u in doc["unreadable"])))
    if doc["old"]:
        parts.append("<h3>{}</h3><p>{}</p>".format(e_(T("OLDER THAN {n} DAYS - check these again:", n=HH_OLD_DAYS)),
                                                  e_(", ".join(doc["old"]))))
    if doc["missing"]:
        parts.append("<h3>{}</h3><ul>{}</ul>".format(e_(T("NOT IN THIS REPORT")),
                                                   "".join("<li>{}</li>".format(e_(m)) for m in doc["missing"])))
    parts.append("</body></html>")
    return "".join(parts)


def _write_new(path, text, out):
    path = os.path.abspath(path)
    problem = path_problem(path)
    if problem:
        out("[not written: {}]".format(problem))
        return False
    try:
        with open(path, "x", encoding="utf-8") as fh:    # never replaces an existing file
            fh.write(text)
    except FileExistsError:
        out("[not written: {} already exists - choose a new name]".format(path))
        return False
    except OSError as exc:
        out("[not written: {}]".format(exc))
        return False
    out("[wrote {}]".format(path))
    return True


def combine_command(args, out=print):
    """--combine for both entry points. Exit: 2 indicators somewhere, 3 worth a look / gaps, 0 otherwise."""
    doc = hh_combine(args.combine)
    out(hh_render(doc))
    ok = True
    if getattr(args, "json", None):
        ok &= _write_new(args.json, json.dumps(doc, indent=2, ensure_ascii=False), out)
    if getattr(args, "html", None):
        ok &= _write_new(args.html, hh_html(doc), out)
    if not ok:
        return 1
    return {RED: 2, AMBER: 3, GREY: 3, GREEN: 0}[doc["overall"]]
