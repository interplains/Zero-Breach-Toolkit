"""Block-list export: the website names a scan matched, for a DNS filter.

The report defangs indicators ("evil[.]com") so they are safe to forward; a
block list needs the real name, so names are written as they are. Only names
are written. A hosts file maps a NAME to an address, and Pi-hole, AdGuard and
NextDNS lists block names, so an IP address in either would be an invalid line
or silently ignored; matched IP addresses are counted and left out.

Left out as well:
- reference-only matches: a saved page ABOUT the indicator, such as a news
  article naming a server, is not contact, and blocking the site that
  published it would be a false positive;
- names that may belong to someone else now (tier "reclaimable"): contact
  with them is a lead at most, and the current owner may be an ordinary site;
- anything that is not a well-formed host name. Values can come from an
  indicator file the user supplied, so a value carrying a space, a newline or
  a wildcard must never become a line of its own in someone's DNS filter.

Names in this module carry a bl_ prefix: the single-file program joins every
module into one namespace.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict, List, Tuple

from .result import EV_REFERENCED
from .safetext import safe_render

BL_FORMATS = ("hosts", "domains")

# Most informative first, for a name matched at several grades: "contacted"
# says what the device did, "configured" only that a setting names it.
_BL_GRADE_ORDER = ("contacted", "dns-record", "received", "device-log", "attempted", "configured")

_BL_HOSTNAME = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_BL_LABEL_SAFE = re.compile(r"[^A-Za-z0-9 ._/()+:-]+")


def _bl_name(value: str) -> str:
    """The value as a host name ready to write, or '' if it is not one."""
    name = (value or "").strip().lower()
    if name.endswith("."):
        name = name[:-1]
    return name if _BL_HOSTNAME.match(name) else ""


def _bl_is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip().strip("[]"))
        return True
    except ValueError:
        return False


def _bl_label(text: str) -> str:
    return _BL_LABEL_SAFE.sub(" ", text or "").strip()[:60]


def bl_collect(document: Dict[str, Any]) -> Tuple[List[Tuple[str, str]], Dict[str, int]]:
    """(name, label) for every matched website name, one per name and sorted,
    plus counts of what was left out and why."""
    best: Dict[str, Tuple[int, str]] = {}
    left_out: Dict[str, int] = {"ip": 0, "reclaimable": 0, "other": 0}
    seen_left_out = set()
    for module in (document.get("modules") or {}).values():
        for hit in module.get("hits", []) or []:
            value = hit.get("indicator") or ""
            kind = hit.get("kind") or ""
            grade = hit.get("evidence") or ""
            if grade == EV_REFERENCED:
                continue
            if kind not in ("", "domain", "ip"):
                continue
            # Some checks do not record the kind. Browser history, the DNS cache
            # and connection records only ever match names and IPs, and they
            # grade what they found as contact, a lookup or a setting; a
            # file-fingerprint match without a kind is graded otherwise.
            if not kind and grade not in _BL_GRADE_ORDER:
                continue
            name = "" if kind == "ip" else _bl_name(value)
            if not name:
                reason = "ip" if kind == "ip" or _bl_is_ip(value) else "other"
                if (reason, value) not in seen_left_out:
                    seen_left_out.add((reason, value))
                    left_out[reason] += 1
                continue
            if hit.get("tier") == "reclaimable":
                if ("reclaimable", name) not in seen_left_out:
                    seen_left_out.add(("reclaimable", name))
                    left_out["reclaimable"] += 1
                continue
            rank = _BL_GRADE_ORDER.index(grade) if grade in _BL_GRADE_ORDER else len(_BL_GRADE_ORDER)
            label = " / ".join(p for p in (_bl_label(grade), _bl_label(hit.get("family") or ""),
                                           _bl_label(hit.get("tier") or "")) if p)
            if name not in best or rank < best[name][0]:
                best[name] = (rank, label)
    # A name that is also in the list is not "left out" for being reclaimable
    # at one grade and an ordinary match at another.
    left_out["reclaimable"] = len({v for r, v in seen_left_out if r == "reclaimable"} - set(best))
    return sorted((name, label) for name, (_rank, label) in best.items()), left_out


@safe_render
def bl_render(entries: List[Tuple[str, str]], fmt: str, version: str, when: str) -> str:
    if fmt not in BL_FORMATS:
        raise ValueError("unknown block-list format: {!r}".format(fmt))
    lines = [
        "# Zero Breach Toolkit {} - DNS block list".format(_bl_label(version)),
        "# Made {} from the website names this check matched: {}.".format(_bl_label(when), len(entries)),
        "# This is not the full indicator list, only what was found on this device.",
        "# A match is a reason to look closer, not proof that the device was infected.",
        "",
    ]
    if not entries:
        lines.append("# No matched website names.")
    for name, label in entries:
        # Comments on their own line: every hosts file and every DNS filter
        # reads those, while comments after an entry are not read everywhere.
        if label:
            lines.append("# " + label)
        lines.append("0.0.0.0 " + name if fmt == "hosts" else name)
    return "\n".join(lines) + "\n"


def bl_write(document: Dict[str, Any], path: str, fmt: str, version: str) -> Tuple[int, Dict[str, int]]:
    """Write the block list atomically (a DNS filter that reloads while it is
    written must never read half a list). Returns (names written, left out)."""
    from .workflow import workflow_write_text
    when = document.get("completed_at")
    if not when:
        raise ValueError("the report has no completion time, so the block list cannot be dated")
    entries, left_out = bl_collect(document)
    workflow_write_text(bl_render(entries, fmt, version, when), path)
    return len(entries), left_out


def bl_summary(path: str, written: int, left_out: Dict[str, int]) -> str:
    """One console line saying what was written and what was left out."""
    text = "[wrote DNS block list ({} website name{}) to {}".format(
        written, "" if written == 1 else "s", path)
    notes = []
    if left_out.get("ip"):
        notes.append("{} IP address{} left out: block lists hold names, not addresses".format(
            left_out["ip"], "" if left_out["ip"] == 1 else "es"))
    if left_out.get("reclaimable"):
        notes.append("{} name{} left out that may belong to someone else now".format(
            left_out["reclaimable"], "" if left_out["reclaimable"] == 1 else "s"))
    if left_out.get("other"):
        notes.append("{} value{} left out that {} not a valid website name".format(
            left_out["other"], "" if left_out["other"] == 1 else "s",
            "is" if left_out["other"] == 1 else "are"))
    return text + ("; " + "; ".join(notes) if notes else "") + "]"
