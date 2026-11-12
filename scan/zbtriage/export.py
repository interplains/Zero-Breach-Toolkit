"""Blocklist export: write matched network indicators for DNS filtering.

The report defangs indicators for safe forwarding ("evil[.]com"); a blocklist
needs the raw value to function, so hits are written verbatim. Only indicators
the report already classifies as network addresses are exported, and
reference-only matches (a cached page that mentioned the domain) are excluded —
sinking the news site that reported on a C2 would be a false positive.
"""

from __future__ import annotations

import os
import tempfile
from typing import Any, Dict, List, Tuple

from .result import EV_REFERENCED, NOT_ADDRESSES

FORMATS = ("hosts", "pihole", "plain")

_HEADER = """\
# Zero Breach Toolkit {version} — matched indicators
# Generated {when}. Only indicators this scan MATCHED are listed, not the
# full feed. A match is evidence to investigate, not proof of infection.
"""

# Which label to show when one indicator appears at several grades. Most
# informative first: "contacted" tells the reader what the device did, where
# "configured" only says a string was found in local config.
_GRADE_PREF = ("contacted", "dns-record", "attempted", "configured")


def _blocklistable(hit: Dict[str, Any]) -> bool:
    return (hit.get("evidence") != EV_REFERENCED
            and hit.get("kind") not in NOT_ADDRESSES
            and bool(hit.get("indicator")))


def collect(document: Dict[str, Any]) -> List[Tuple[str, str, str]]:
    """Deduped (indicator, evidence, provenance) for every network hit in the
    report. Deduped by indicator alone — one domain at "contacted" in three
    cache files is one blocklist line, not three."""
    best: Dict[str, Tuple[int, str, str]] = {}
    for module in document["modules"].values():
        for hit in module.get("hits", []):
            if not _blocklistable(hit):
                continue
            grade = hit.get("evidence") or ""
            rank = _GRADE_PREF.index(grade) if grade in _GRADE_PREF else len(_GRADE_PREF)
            prov = "/".join(p for p in (hit.get("tier"), hit.get("family")) if p) or "unclassified"
            prev = best.get(hit["indicator"])
            if prev is None or rank < prev[0]:
                best[hit["indicator"]] = (rank, grade, prov)
    return sorted((ind, grade, prov) for ind, (_r, grade, prov) in best.items())


def _render(entries: List[Tuple[str, str, str]], fmt: str, version: str, when: str) -> str:
    lines: List[str] = []
    if fmt != "plain":
        lines.extend(_HEADER.format(version=version, when=when).splitlines())
        lines.append("")
    for ind, grade, prov in entries:
        comment = "{}/{}".format(grade, prov) if grade else prov
        if fmt == "hosts":
            lines.append("0.0.0.0 {}  # {}".format(ind, comment))
        elif fmt == "pihole":
            lines.append("{}  # {}".format(ind, comment))
        else:
            lines.append(ind)
    return "\n".join(lines) + "\n" if lines else ""


def write_blocklist(document: Dict[str, Any], path: str, fmt: str,
                    version: str) -> int:
    """Write the blocklist atomically; return the number of indicators written.

    Temp file plus os.replace: a DNS filter that reloads mid-write otherwise
    reads a truncated file and silently loses entries. Overwriting is
    deliberate — this is a generated artifact, not evidence, and the
    protected-path check lives in workflow_output_guard, called by the caller.
    """
    if fmt not in FORMATS:
        raise ValueError("unknown blocklist format: {!r}".format(fmt))
    entries = collect(document)
    when = document.get("completed_at")
    if not when:
        raise ValueError("document has no completed_at; cannot stamp the blocklist")
    text = _render(entries, fmt, version, when)
    directory = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".blocklist-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return len(entries)
