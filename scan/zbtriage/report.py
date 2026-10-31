"""Human-readable + machine-readable reporting, and the overall verdict.

Doctrine enforced here:
  D1  Every run that finds nothing prints, verbatim, the mandatory closing line.
  D3  A module that could not run is UNKNOWN, never CLEAN; gaps are stated out
      loud in the interface, not buried.
  The verdict for a hit is "investigate", never "you are compromised" — an ad
  impression is not proof of infection (README / the IOC file header).
"""

from __future__ import annotations

import datetime
import copy
import json
import platform as _platform
import re
from typing import Any, Dict, List

from . import __version__
from .contract import (CHECK_CATALOGUE, CONTENT_TRUST, EXIT_CODES, HELP_LINKS,
                       INSTRUCTIONS_FOR_ASSISTANTS, MUST_RELAY, NEXT_STEPS,
                       SCHEMA_VERSION, contract_coverage, contract_exit_code,
                       contract_must_relay, contract_next_steps,
                       sanitize_module_dict, sanitize_untrusted)
from .iocs import DECAYING_IP_TIERS, IocSet
from .localpaths import path_problem
from .result import (CLEAN, HITS, PARTIAL, UNKNOWN, Lead, ModuleResult, is_serious,
                     EV_ON_DISK, EV_FILE_PATTERN, EV_PERSISTENCE, EV_COMMAND, EV_CONTACTED,
                     EV_ATTEMPTED, EV_ON_DEVICE, EV_DEVICE_LOG, EV_RECEIVED, EV_EXECUTION, EV_INVENTORY,
                     EV_CONFIGURED, EV_REFERENCED, EV_DNS, EVIDENCE_ORDER)

# The exact text required by D1. Do not reword.
D1_LINE = ("No known indicators were found in the places that can be checked. "
           "This is not a clean bill of health.")

V_HITS = "INDICATORS_FOUND"
V_NONE_WITH_GAPS = "NO_KNOWN_INDICATORS_WITH_GAPS"
V_NONE = "NO_KNOWN_INDICATORS"
V_REFERENCES = "REFERENCES_ONLY"
V_REFERENCES_WITH_GAPS = "REFERENCES_ONLY_WITH_GAPS"
# Every serious-grade match is to an indicator its publishers have withdrawn.
# Not an actionable finding, so not exit 2 and no request to preserve the
# device; also not a reference, because the grade may record real contact.
V_WITHDRAWN = "WITHDRAWN_ONLY"
V_WITHDRAWN_WITH_GAPS = "WITHDRAWN_ONLY_WITH_GAPS"


def _windows_release(release: str, version: str) -> str:
    """Correct Python's release string on Windows 11.

    platform.release() reports "10" on Windows 11, because the underlying
    GetVersionEx still reports major version 10 for compatibility. Windows 11 is
    build 22000 and up, so the build number in platform.version() is what
    actually distinguishes them. This matters because the JSON report is meant to
    be evidence: a report that names the wrong OS is a report someone has to
    double-check by hand.
    """
    if release != "10":
        return release
    try:
        build = int(version.split(".")[2])
    except (IndexError, ValueError):
        return release
    return "11" if build >= 22000 else release


def _platform_info() -> Dict[str, str]:
    system = _platform.system()
    release = _platform.release()
    version = _platform.version()
    if system == "Windows":
        release = _windows_release(release, version)
    return {
        "system": system,
        "release": release,
        "version": version,
        "machine": _platform.machine(),
        "python": _platform.python_version(),
    }


def _phone_modules():
    """Readers that only ever run on a phone collection, from their registered
    modes. A hand-kept list missed android-intrusion, so a stalkerware DNS
    lookup in a phone's own logs was treated as a computer's web visit."""
    from .readers import READER_SPECS
    return {spec.name for spec in READER_SPECS if spec.modes and set(spec.modes) <= {"android", "ios"}}


_WHY_STALKERWARE_SITE = (
    "Stalkerware runs on phones, not computers. On a computer this usually means "
    "someone opened the company's website or sign-in page, or saw an ad for it. If "
    "you think someone may have had access to your phone, check the phone itself.")


def _stalkerware_sites_to_leads(modules: List[ModuleResult]) -> None:
    """On a COMPUTER, a stalkerware company's domain is not a spyware finding.

    The Echap list names phone-monitoring companies' domains, which include their
    ordinary websites - Microsoft Family Safety's among them. An ordinary
    Windows widget cache can hold family.microsoft.com;
    calling that 'stalkerware' would frighten anyone with a Windows PC. So on a
    computer: a visit/connection becomes 'worth a look', a mere mention in saved
    content is only counted. Phone checks keep them as findings."""
    phone = _phone_modules()
    for m in modules:
        if m.name in phone:
            continue
        keep, mentions, mentioned = [], 0, []
        for h in m.hits:
            if h.tier != "stalkerware":
                keep.append(h)
            elif h.evidence == EV_REFERENCED:
                mentions += 1
                if h.indicator not in mentioned:
                    mentioned.append(h.indicator)
            else:
                m.add_lead(Lead(
                    "stalkerware-site", h.location,
                    "a record of {} - a site of the phone-monitoring company {} ({})".format(
                        h.indicator, h.family or "(unnamed)", h.evidence or "unclassified"),
                    _WHY_STALKERWARE_SITE, h.observed))
        m.hits = keep
        if mentions:
            m.note("{}: {} mention(s) of phone-monitoring companies' sites in saved web "
                   "content were not listed as findings - a mention is not a visit ({})".format(
                       m.name, mentions, ", ".join(_defang(d) for d in mentioned[:10])
                       + (", ..." if len(mentioned) > 10 else "")))


def build_document(iocs: IocSet, modules: List[ModuleResult],
                   started: datetime.datetime) -> Dict[str, Any]:
    _stalkerware_sites_to_leads(modules)
    # Provenance before the verdict. Whether every publisher has withdrawn an
    # indicator is only known after enrichment, and counting first meant a
    # withdrawn match still returned exit 2 and asked the person to preserve the
    # device as evidence, while the summary beside it said "withdrawn, review".
    module_dicts = {m.name: sanitize_module_dict(m.to_dict()) for m in modules}
    from .evidence import evidence_enrich, evidence_correlations
    evidence_enrich(module_dicts, iocs)
    hit_dicts = [h for md in module_dicts.values() for h in md.get("hits", [])]
    hits_total = len(hit_dicts)
    serious_total = sum(1 for h in hit_dicts if is_serious(h.get("evidence", "")))
    withdrawn_total = sum(1 for h in hit_dicts
                          if is_serious(h.get("evidence", "")) and h.get("withdrawn_only"))
    findings_total = serious_total - withdrawn_total
    references_total = hits_total - serious_total
    gaps: List[str] = []
    for m in modules:
        for c in m.checks:
            if not c.ran:
                gaps.append("{}/{}: {}".format(m.name, c.name, c.reason))
        # A module that produced NO checks at all is UNKNOWN - it observed
        # nothing - but has no failed Check to turn into a gap, so without this it
        # is invisible to the verdict and a "nothing found" reads as clean. The
        # common cause is a browser module on a machine where no supported browser
        # is installed, or on macOS/Linux before the platform paths existed.
        if m.status == UNKNOWN and not m.checks:
            gaps.append("{}: nothing in this check could run, so it cleared "
                        "nothing".format(m.name))

    feed_status = getattr(iocs, "feeds", None) or {}
    feed_gaps = []
    if feed_status.get("used"):
        for sid in feed_status.get("missing", []):
            feed_gaps.append("{}: indicator source missing".format(sid))
        for entry in feed_status.get("refused", []):
            feed_gaps.append("{}: indicator source refused ({})".format(
                entry.get("id", "source"), entry.get("reason", "unusable")))
        for entry in feed_status.get("loaded", []):
            if entry.get("stale") or entry.get("freshness_unknown"):
                feed_gaps.append("{}: indicator source {}".format(entry.get("id", "source"),
                    "last verified more than 30 days ago" if entry.get("stale") else "has unknown freshness"))
        if not feed_status.get("loaded") and not feed_gaps:
            feed_gaps.append("published indicator sources have not been loaded")
    gaps.extend("indicators/indicator-sources: " + reason for reason in feed_gaps)

    if findings_total > 0:
        status = V_HITS
    elif withdrawn_total:
        status = V_WITHDRAWN_WITH_GAPS if gaps else V_WITHDRAWN
    elif references_total:
        status = V_REFERENCES_WITH_GAPS if gaps else V_REFERENCES
    elif gaps:
        status = V_NONE_WITH_GAPS
    else:
        status = V_NONE

    age = iocs.age_days()
    gaps = [sanitize_untrusted(g) for g in gaps]
    document = {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "zero-breach-toolkit", "version": __version__},
        "timestamp": started.replace(microsecond=0).isoformat(),
        "platform": _platform_info(),
        "ioc_set": {
            "path": sanitize_untrusted(iocs.source_path),
            "count": len(iocs),
            "age_days": age,
            "stale": iocs.is_stale(),
            "freshness_unknown": iocs.has_unknown_age(),
            # What each indicator file contributed, and what it could not: a
            # published bundle may hold phone-only indicators this scan cannot use.
            "sets": copy.deepcopy(getattr(iocs, "sets", [])),
            "families": _family_counts(iocs),
            "feeds": _feed_block(getattr(iocs, "feeds", None)),
        },
        # Leftover temporary folders from an earlier scan that did not finish.
        "housekeeping": _housekeeping_block(getattr(iocs, "housekeeping", None)),
        "modules": module_dicts,
        # Heuristics: never part of the verdict (result.Lead).
        "worth_a_look": [dict(lead, module=name) for name, md in module_dicts.items()
                         for lead in md.get("leads", [])],
        # Every finding and lead that records a time, oldest first, in this
        # computer's local time. Idea from MVT's timeline (method only).
        "timeline": _timeline(module_dicts),
        "correlations": evidence_correlations(module_dicts),
        "verdict": {
            "status": status,
            "hits_total": hits_total,
            "findings_total": findings_total,
            "references_total": references_total,
            "withdrawn_total": withdrawn_total,
            "gaps": gaps,
        },
        # D1 line is present whenever nothing was found (CLEAN or with gaps).
        "doctrine_line": None if hits_total > 0 else D1_LINE,
        # Whether a "HOW TO TURN ON DNS HISTORY" block will actually be rendered,
        # so the summary's pointer to it does not dangle on a host where no reach
        # entry carried how_to_enable (e.g. a non-Windows machine).
        "_dns_howto": any(
            info.get("how_to_enable")
            for m in modules for info in (m.reach or {}).values()),
        "_indicators": iocs.network_strings,
    }
    # The machine contract (contract.py): fixed text and derived structure only.
    hits = [h for md in module_dicts.values() for h in md.get("hits", [])]
    action = max((_recommended_action(h) for h in hits), default=-1)
    document["exit_code"] = contract_exit_code(document)
    document["coverage"] = contract_coverage(module_dicts)
    document["coverage"]["not_checked"].extend(
        {"module": "indicators", "check": "indicator-sources", "reason": sanitize_untrusted(reason)}
        for reason in feed_gaps)
    if feed_status.get("used") and not feed_gaps:
        document["coverage"]["checked"].append({"module": "indicators", "check": "indicator-sources"})
    document["must_relay"] = contract_must_relay(document)
    document["next_steps"] = contract_next_steps(document, action)
    document["content_trust"] = copy.deepcopy(CONTENT_TRUST)
    document["instructions_for_assistants"] = list(INSTRUCTIONS_FOR_ASSISTANTS)
    return document


def _when_key(text: str):
    """A sortable local-time string for an artifact time, or None if unparseable.
    Times with a zone are converted to this computer's local time; naive ones are
    already local (that is how the modules record them)."""
    raw = (text or "").strip()
    if not raw:
        return None
    for candidate in (raw.replace("Z", "+00:00"), raw[:19]):
        try:
            when = datetime.datetime.fromisoformat(candidate)
        except ValueError:
            continue
        if when.tzinfo is not None:
            when = when.astimezone().replace(tzinfo=None)
        return when.replace(microsecond=0).isoformat(sep=" ")
    return None


def _timeline(module_dicts: Dict[str, Any]) -> List[Dict[str, Any]]:
    rows = []
    for name, md in module_dicts.items():
        for h in md.get("hits", []):
            when = _when_key(h.get("observed", ""))
            if when:
                kind = ("reference" if not is_serious(h.get("evidence", ""))
                        else "withdrawn" if h.get("withdrawn_only") else "finding")
                rows.append({"when": when, "kind": kind, "module": name,
                             "what": h.get("indicator", ""),
                             "evidence": h.get("evidence") or "unclassified",
                             "location": h.get("location", "")})
        for lead in md.get("leads", []):
            when = _when_key(lead.get("observed", ""))
            if when:
                rows.append({"when": when, "kind": "worth-a-look", "module": name,
                             "what": lead.get("what", ""), "evidence": "",
                             "location": lead.get("location", "")})
    rows.sort(key=lambda r: (r["when"], r["kind"] != "finding"))
    return rows


def describe_document() -> Dict[str, Any]:
    """Everything an assistant or script needs to plan a scan, without running
    one: checks, what each reads and cannot see, exit codes, evidence grades,
    tiers, and the fixed caveat and advice catalogues."""
    from .readers import reader_describe
    grades = dict(EVIDENCE_MEANING)
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "zero-breach-toolkit", "version": __version__,
                 "summary": ("Local, read-only check for traces of known commercial "
                             "spyware. Never contacts an indicator; never modifies "
                             "the machine. A clean result is not a clean bill of "
                             "health.")},
        "exit_codes": {str(k): v for k, v in EXIT_CODES.items()},
        "modules": copy.deepcopy(CHECK_CATALOGUE),
        "readers": reader_describe(),
        "indicator_inputs": {
            "curated": "tab-separated: indicator, tier, confidence[, source[, family]]",
            "stix2": ("STIX 2.x bundles (.stix2 / .json) as published by Amnesty, the "
                      "MVT project and others; domain, IP and SHA-256 indicators are "
                      "used, phone-only kinds are counted as not applicable"),
            "flag": "--iocs PATH (repeatable)",
        },
        "evidence_grades": grades,
        "report_sections": {
            "worth_a_look": ("heuristic items a person should look at; NEVER findings, "
                             "never change the verdict or exit code; each carries "
                             "usual_reason, the common harmless explanation"),
            "timeline": ("findings and worth-a-look items that record a time, oldest "
                         "first, in the scanned computer's local time"),
        },
        "workflow": {
            "readable_report": "--report PATH saves the displayed report independently of JSON outputs",
            "follow_up": "Interactive start-menu checks offer evidence inspection, coverage review and export; --post-menu requests this after an explicit scan; --no-menu disables it",
            "no_scan": "Leaving the start menu returns 4, produces no scan verdict and saves no report",
            "evidence_export": "--evidence-bundle PATH writes a NEW unencrypted private ZIP. Repeat --evidence-file PATH for deliberately selected originals. No uploads or inferred file selections.",
        },
        "evidence_order_strongest_first": list(EVIDENCE_ORDER),
        "tiers": dict(TIER_MEANING),
        "must_relay_catalogue": dict(MUST_RELAY),
        "next_steps_catalogue": {
            k: {"text": v["text"], "links": [HELP_LINKS[x] for x in v["links"]]}
            for k, v in NEXT_STEPS.items()},
        "content_trust": copy.deepcopy(CONTENT_TRUST),
        "instructions_for_assistants": list(INSTRUCTIONS_FOR_ASSISTANTS),
    }


def write_json(document: Dict[str, Any], path: str) -> None:
    import os
    import tempfile
    path = os.path.abspath(path)
    problem = path_problem(os.path.abspath(path))
    if problem:
        raise OSError("report output path refused: " + problem)
    # The internal rendering flag is not part of the evidence record.
    doc = {k: v for k, v in document.items() if not k.startswith("_")}
    pending = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", newline="\n",
                                         prefix=".zbt_report_", suffix=".tmp",
                                         dir=os.path.dirname(path), delete=False) as fh:
            pending = fh.name
            # JSON escapes preserve even lone UTF-16 surrogates from Windows
            # filenames, including mapping keys, without invalid UTF-8 output.
            json.dump(doc, fh, indent=2, ensure_ascii=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        if path_problem(path):
            raise OSError("report destination changed to a refused path")
        os.replace(pending, path)
    finally:
        if pending and os.path.exists(pending):
            os.unlink(pending)


def _report_console(text, stream):
    """Render unusual filenames safely even on strict or legacy consoles."""
    encoding = getattr(stream, "encoding", None) or "utf-8"
    print(text.encode(encoding, "backslashreplace").decode(encoding), file=stream)


def finalize_report(iocs, results, started, args, cancelled=False):
    """Save independent outputs before rendering; retry one interrupted operation."""
    import sys
    from .scope import scope_record
    from .training import training_marker
    from .workflow import (workflow_write_text, workflow_fingerprints,
                           workflow_interactive, workflow_menu, workflow_output_guard)
    def attempt(operation):
        try:
            return operation()
        except KeyboardInterrupt:
            print("Report finalization interrupted; preserving completed evidence (interrupt again to stop).", file=sys.stderr)
            return operation()
    document = attempt(lambda: build_document(iocs, results, started))
    document["scope"] = scope_record(args)
    document["scope"].update(scanned=True, cancelled=cancelled)
    training = training_marker(args)
    if training:
        document["training"] = training
    document["scan_state"] = "partial" if cancelled or document["verdict"]["gaps"] else "completed"
    document["completed_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    document["indicator_fingerprints"] = workflow_fingerprints(iocs)
    document["must_relay"] = contract_must_relay(document)
    failed = False
    for label, path, minimal in (("JSON report", args.json, False), ("sharing summary", args.share_json, True)):
        if not path:
            continue
        try:
            workflow_output_guard(args, path, document)
            attempt(lambda: write_json(share_summary(document) if minimal else document, path))
            _report_console("[wrote {} to {}]".format(label, path), sys.stderr)
        except (OSError, ValueError, TypeError) as exc:
            failed = True
            _report_console("[could not write {}: {}]".format(label, exc), sys.stderr)
    rendered = None
    try:
        rendered = attempt(lambda: render_human(document))
    except (OSError, ValueError, TypeError) as exc:
        failed = True
        _report_console("[could not render readable report: {}]".format(exc), sys.stderr)
    if rendered is not None and getattr(args, "report", None):
        try:
            workflow_output_guard(args, args.report, document)
            attempt(lambda: workflow_write_text(rendered, args.report))
            _report_console("[wrote readable report to {}]".format(args.report), sys.stderr)
        except (OSError, ValueError, TypeError) as exc:
            failed = True
            _report_console("[could not write readable report: {}]".format(exc), sys.stderr)
    if getattr(args, "evidence_bundle", None):
        try:
            from .handoff import handoff_preview, handoff_write
            paths = getattr(args, "evidence_file", ()) or ()
            preview = handoff_preview(document, paths)
            _report_console("[private evidence export preview]\n" + json.dumps(preview, indent=2, ensure_ascii=True), sys.stderr)
            attempt(lambda: handoff_write(document, args.evidence_bundle, paths))
            _report_console("[wrote private evidence bundle to {}]".format(args.evidence_bundle), sys.stderr)
        except (OSError, ValueError, TypeError) as exc:
            failed = True
            _report_console("[could not write evidence bundle: {}]".format(exc), sys.stderr)
    try:
        if rendered is None:
            raise ValueError("readable report unavailable")
        attempt(lambda: _report_console(rendered, sys.stdout))
    except (OSError, ValueError, TypeError) as exc:
        failed = True
        _report_console("[could not display report: {}]".format(exc), sys.stderr)
    if workflow_interactive(args):
        try:
            # Redirected stdout is still saved, but the person must see the
            # report before choosing an action in the terminal.
            if rendered is not None and not sys.stdout.isatty():
                _report_console(rendered, sys.stderr)
            if not workflow_menu(document, args):
                failed = True
        except (KeyboardInterrupt, EOFError):
            _report_console("Finished. Completed reports remain saved.", sys.stderr)
    return 1 if failed else contract_exit_code(document)


def share_summary(document: Dict[str, Any]) -> Dict[str, Any]:
    """A deliberately small allow-list, not search-and-replace redaction.

    No artifact text, indicator values, source paths, exception messages or
    timestamps cross this boundary. Keep the complete report locally if an
    expert later requests evidence through a secure channel.
    """
    counts = {}
    for module in document["modules"].values():
        for hit in module["hits"]:
            grade = hit.get("evidence")
            grade = grade if grade in EVIDENCE_ORDER else "unclassified"
            counts[grade] = counts.get(grade, 0) + 1
    v = document["verdict"]
    raw_scope = document.get("scope", {})
    mode = raw_scope.get("scan_type")
    mode = mode if mode in ("default", "full", "targeted", "browser") else "unspecified"
    return {
        "schema_version": SCHEMA_VERSION,
        "report_type": "sharing-summary",
        "tool": {"name": "zero-breach-toolkit", "version": __version__},
        "verdict": {k: v.get(k, 0) for k in ("status", "hits_total", "findings_total",
                                             "references_total", "withdrawn_total")},
        "exit_code": document["exit_code"],
        "evidence_counts": counts,
        "scope": {"scan_type": mode, "phone": raw_scope.get("phone") is True,
                  "cancelled": raw_scope.get("cancelled") is True},
        "coverage": {"checked_count": len(document["coverage"]["checked"]),
                     "gap_count": len(v["gaps"])},
        "worth_a_look_count": len(document.get("worth_a_look", [])),
        "must_relay": contract_must_relay(document),
        "next_steps": copy.deepcopy(document["next_steps"]),
        "omitted": "Indicator values, artifact text, message senders and bodies, paths, "
                   "profiles, dates and detailed gap reasons are omitted. This summary "
                   "cannot replace the full evidence report. Review it before sharing.",
    }


# --- human-readable rendering ----------------------------------------------

_RULE = "=" * 72


def _fmt_count(n: int) -> str:
    return "{:,}".format(n)


# Raw metric keys are developer shorthand. Say what each number is, in words,
# because "com_registrations=37" tells a reader nothing about whether 37 is bad.
_METRIC_LABELS = {
    "sqlite": "browser databases read",
    "blob": "cache / stored-data files searched",
    "hsts_entries": "HSTS security records checked (proof of past connections)",
    "connection_records": "saved connection records checked",
    "files_hashed": "files fingerprinted",
    "files_pattern_scanned": "files checked against Candiru patterns",
    "bytes_pattern_scanned": "bytes checked against Candiru patterns",
    "com_registrations": "auto-start COM registrations reviewed",
    "com_user_writable": "   of those, in a folder you can write to",
    "dns_cache_entries": "names in the DNS cache since last reboot",
    "dns_log_records": "DNS history records available",
    "dns_log_events_scanned": "DNS history events searched",
    "hosts_entries": "entries in the hosts file",
    "hosts_blocked_indicators": "   of those, indicators you are BLOCKING (good)",
    "known_paths_checked": "known malware file-paths checked",
    "known_paths_present": "   of those, a file is present at (see notes)",
}


def _describe_metrics(metrics: Dict[str, int]) -> List[str]:
    out = []
    for key, value in metrics.items():
        if key == "bytes_hashed":
            out.append("{:,.1f} GB of files read".format(value / 1e9))
            continue
        if key == "dns_log_enabled":
            out.append("Windows DNS history logging: {}".format(
                "ON" if value else "OFF (the Windows default)"))
            continue
        label = _METRIC_LABELS.get(key)
        if label is None:
            out.append("{}: {}".format(key, _fmt_count(value)))
        else:
            out.append("{}: {}".format(label, _fmt_count(value)))
    return out


def render_human(document: Dict[str, Any]) -> str:
    from .training import training_banner
    document = _human_document(document)
    out: List[str] = []
    w = out.append
    training_top, training_bottom = training_banner(document)
    out.extend(training_top)

    w(_RULE)
    w("  Zero Breach Toolkit {} - spyware indicator check".format(
        document["tool"]["version"]))
    # The name must not be read as a promise. The tagline carries the tool's one
    # non-negotiable caveat right next to it, so a screenshot of the top of the
    # report cannot imply "you are safe".
    scope = document.get("scope", {})
    if scope:
        w("  Scope: {}{}".format(scope.get("scan_type", "default"), " (phone evidence only)" if scope.get("phone") else ""))
        if scope.get("phone") and scope.get("ios_input"):
            w("  iPhone input: " + _safe_text(scope["ios_input"]))
        if scope.get("targets"):
            w("  Only selected targets were checked; system and other-user records are outside scope.")
        if scope.get("scan_type") == "browser":
            w("  Only browser profiles were checked; the rest of this computer was not.")
        if scope.get("scan_type") == "full":
            w("  Full includes more file types and caches in the usual roots; other drives require --target.")
        if scope.get("cancelled"):
            w("  Cancelled: this report contains partial evidence only.")
    w("  Checks for TRACES of known mercenary spyware. A clean result is NOT a")
    w("  clean bill of health - see what could not be checked, below.")
    w("  {}   {} {}".format(document["timestamp"],
                            document["platform"]["system"],
                            document["platform"]["release"]))
    w(_RULE)
    w("")

    # The answer first. Everything after it is the supporting evidence.
    out.extend(render_summary(document).split("\n"))

    ioc = document["ioc_set"]
    age = ioc["age_days"]
    age_txt = "unknown age" if age is None else "{} day(s) old".format(age)
    w("Indicator set : {:,} indicator{}, {}".format(ioc["count"], "" if ioc["count"] == 1 else "s", age_txt))
    for entry in ioc.get("sets", []) if len(ioc.get("sets", [])) > 1 else []:
        device = sum((entry.get("device_indicators") or {}).values())
        skipped = sum((entry.get("not_applicable_to_this_scan") or {}).values())
        refused = sum((entry.get("refused_invalid") or {}).values())
        extra = []
        if device:
            extra.append("{} for phone-backup / mail checks".format(device))
        if skipped:
            extra.append("{} not usable by this tool".format(skipped))
        if refused:
            extra.append("{} refused as malformed".format(refused))
        w("  from {} : {} for computer checks{}".format(
            _basename(entry.get("path", "")), entry.get("usable", 0),
            " ({})".format("; ".join(extra)) if extra else ""))
    if ioc["stale"]:
        w("  ** WARNING: this indicator set is more than 30 days old. Update it "
          "before trusting a clean result. **")
    if ioc.get("freshness_unknown"):
        w("  ** WARNING: one or more source dates are unknown; copying files does not refresh indicators. **")
    housekeeping = document.get("housekeeping") or {}
    if housekeeping.get("stale_temp_removed"):
        w("Clean-up      : removed {} leftover temporary folder(s) from an earlier scan that "
          "did not finish".format(housekeeping["stale_temp_removed"]))
    for path in housekeeping.get("stale_temp_not_removed", []):
        w("  ** WARNING: a leftover temporary folder from an earlier scan could not be removed "
          "and may hold private copies. Delete it yourself: {} **".format(path))
    w("")

    # Put the full indicator evidence after the coverage/DNS-history instructions.
    # The concise result and urgent next steps remain visible in the summary.
    _render_reach(w, document)

    w("DETAIL  —  what was examined, and the evidence behind the summary")
    w("")
    for name, m in document["modules"].items():
        took = (" in {:.0f}s".format(m["duration_s"])
                if m.get("duration_s") else "")
        w("--- {} check  [{}]{} ---".format(name, m["status"], took))
        w("    examined: {}    could not read: {}".format(
            _fmt_count(m["checked"]), _fmt_count(m["skipped"])))
        if m["submetrics"]:
            for line in _describe_metrics(m["submetrics"]):
                w("    {}".format(line))
        for note in m["notes"]:
            w("    note   : {}".format(note))
        if m["hits"]:
            # Strongest evidence first: someone reading this should see a sample
            # on disk or a proven contact before a string that merely appeared in
            # cached page text.
            order = {EV_ON_DISK: 0, EV_ON_DEVICE: 0.2, EV_FILE_PATTERN: 0.5,
                     EV_PERSISTENCE: 1, EV_COMMAND: 1.5, EV_EXECUTION: 1.6, EV_INVENTORY: 1.7, EV_CONTACTED: 2,
                     EV_RECEIVED: 2.2, EV_DEVICE_LOG: 2.5,
                     EV_DNS: 3, EV_ATTEMPTED: 4, EV_CONFIGURED: 5,
                     EV_REFERENCED: 6, "": 0}
            for h in sorted(m["hits"], key=lambda x: order.get(x.get("evidence", ""), 0)):
                prov = "{}/{}".format(h["tier"], h["confidence"]) if h["tier"] else "?"
                ev = h.get("evidence") or "unclassified"
                w("    !! HIT  {}  [{}]  evidence: {}".format(
                    _show_indicator(h, document), prov, ev.upper()))
                gloss = _evidence_gloss(h)
                if gloss:
                    w("            meaning: {}".format(gloss))
                if h.get("profile"):
                    w("            account: {}".format(h["profile"]))
                w("            at     : {}".format(
                    _defang_text(h["location"], _net_value(h))))
                w("            detail : {}".format(
                    _defang_text(h["detail"], _net_value(h))))
                if h.get("observed"):
                    w("            when   : {}".format(
                        _defang_text(h["observed"], _net_value(h))))
                if h.get("family"):
                    w("            family : {}".format(h["family"]))
                if h.get("source"):
                    w("            source : {}".format(h["source"]))
                for caution in h.get("context_cautions", []):
                    w("            context: " + caution)
        w("")

    for group in document.get("correlations", []):
        w("RELATED RECORDS: {} occurs in {} artifacts.".format(
            _show_indicator(group, document), group["artifact_count"]))
        w("  " + group["interpretation"])
    looks = document.get("worth_a_look") or []
    if looks:
        w("WORTH A LOOK  —  these are NOT findings")
        w("  Things this scan cannot judge on its own. Each has an ordinary")
        w("  explanation that is far more common, given below. They do not change")
        w("  the result.")
        w("")
        for item in looks:
            w("  - {}  ({} check)".format(item.get("what", ""), item.get("module", "")))
            w("      at     : {}".format(item.get("location", "")))
            if item.get("observed"):
                w("      when   : {}".format(item["observed"]))
            if item.get("usual_reason"):
                for i, line in enumerate(_wrap(item["usual_reason"], 60)):
                    w("      {} {}".format("usually:" if i == 0 else "        ", line))
        w("")
    timeline = document.get("timeline") or []
    if timeline:
        w("IN TIME ORDER  —  local time of this computer")
        for row in timeline:
            label = {"finding": "FINDING", "reference": "REF    "}.get(row["kind"], "look   ")
            extra = " [{}]".format(row["evidence"]) if row.get("evidence") else ""
            w("  {}  {}  {}{}  ({})".format(row["when"], label, row["what"], extra,
                                          row["module"]))
        w("")

    v = document["verdict"]
    w(_RULE)
    if v["status"] == V_HITS:
        w("VERDICT: {} indicator match{}.".format(v["hits_total"], "" if v["hits_total"] == 1 else "es"))
        w("")
        counts = {}
        for m in document["modules"].values():
            for h in m["hits"]:
                key = h.get("evidence") or "unclassified"
                counts[key] = counts.get(key, 0) + 1
        w("  By evidence strength: " + ", ".join(
            "{} {}".format(n, k) for k, n in sorted(counts.items())))
        w("")
        w("  Follow the next steps in the summary. The indicator's role and the")
        w("  evidence type determine those steps; the number of matches does not.")
        w("  A match means INVESTIGATE, not 'you are compromised'.")
        w("  A match does not by itself establish that spyware ran on this device.")
    elif v["status"] in (V_WITHDRAWN, V_WITHDRAWN_WITH_GAPS):
        w("VERDICT: every match is to an indicator its publisher has withdrawn;")
        w("no actionable finding.")
        w("A withdrawal means the publisher no longer stands behind the indicator. Review")
        w("its source context and timing. This does not clear the device.")
        if v["gaps"]:
            w("Checks that could NOT run (a gap is not a clean result):")
            for g in _gap_lines(v["gaps"]):
                w("  - {}".format(g))
    elif v["status"] in (V_REFERENCES, V_REFERENCES_WITH_GAPS):
        w("VERDICT: references in saved content only; no actionable finding.")
        w("A reference does not establish contact or infection. This does not clear the device.")
        if v["gaps"]:
            w("Checks that could NOT run (a gap is not a clean result):")
            for g in _gap_lines(v["gaps"]):
                w("  - {}".format(g))
    else:
        if v["gaps"]:
            w("VERDICT: no known indicators found IN WHAT COULD BE CHECKED.")
            w("")
            w("Checks that could NOT run (a gap is not a clean result):")
            for g in _gap_lines(v["gaps"]):
                w("  - {}".format(g))
            w("")
        else:
            w("VERDICT: no known indicators found in any check that ran.")
            w("")
        # D1: the mandatory closing line, verbatim.
        w(document["doctrine_line"])
        w("")
    w("")
    _support_options(w)
    w(_RULE)
    out.extend(training_bottom)
    return _defang_report("\n".join(out), document)


# The window the AdFection campaign was actually active, from the Citizen Lab
# report: at least 45 targeted devices at Al Jazeera during 2024-2025. If the
# evidence on this machine does not reach back that far, the honest thing is to say
# the check could not have covered it, rather than let a clean result imply it did.
CAMPAIGN_FROM = datetime.date(2024, 1, 1)
CAMPAIGN_TO = datetime.date(2025, 12, 31)
CAMPAIGN_LABEL = "2024-2025 (the documented campaign period)"


def overlap_statement(earliest: datetime.date, source: str) -> List[str]:
    """Compare the dates reported by this scan with the campaign window.

    Unread or out-of-scope records may be older; an oldest date does not prove
    that records cover every day since then or that missing evidence is gone.
    """
    if earliest > CAMPAIGN_TO:
        return [
            "** The oldest dated evidence reported by this scan is {} ({}).".format(
                source,
                earliest.isoformat()),
            "   The campaign this tool searches for was active in {}.".format(
                CAMPAIGN_LABEL),
            "   Those dates DO NOT OVERLAP. The dates reported here do not reach",
            "   the campaign period. Older or unread records may still exist;",
            "   this scan cannot rule out past contact during that period. **",
        ]
    if earliest > CAMPAIGN_FROM:
        return [
            "** The oldest dated evidence reported by this scan is {} ({}).".format(
                source, earliest.isoformat()),
            "   That reaches PART of the campaign period ({}),".format(CAMPAIGN_LABEL),
            "   from {} onwards, and only through that one kind of record.".format(
                earliest.isoformat()),
            "   This does not establish continuous coverage from that date.",
            "   Older or unread records may still exist. A clean result cannot",
            "   rule out past contact during the campaign period. **",
        ]
    return [
        "** The oldest dated evidence reported by this scan is {} ({}), which predates".format(
            source, earliest.isoformat()),
        "   the campaign period. This does not establish continuous coverage",
        "   through that period. Surviving records are never everything, and a",
        "   clean result cannot rule out past contact during that period. **",
    ]


def _render_reach(w, document: Dict[str, Any]) -> None:
    """Say how far back the evidence reaches. A clean result over 11 weeks and a
    clean result over 3 years are different findings, and the reader cannot tell
    them apart unless the tool says which one it just produced."""
    entries = []
    for mod_name, m in document["modules"].items():
        for label, info in (m.get("reach") or {}).items():
            entries.append((mod_name, label, info))
    if not entries:
        return

    w(_RULE)
    w("HOW FAR BACK THIS SCAN COULD SEE")
    w("")
    w("  These dates come from the records examined by this scan. They do not")
    w("  establish a complete history; older or unread records may still exist:")
    w("")

    earliest_overall = None
    earliest_source = ""
    for mod_name, label, info in entries:
        earliest = info.get("earliest")
        days = info.get("days")
        when = "unknown (no date established)" if not earliest else earliest[:10]
        age = ""
        if isinstance(days, int) and earliest:
            age = "  ({} days ago)".format(days)
        w("  {}/{}".format(mod_name, label))
        w("      reaches back to : {}{}".format(when, age))
        w("      basis           : {}".format(info.get("basis", "")))
        if info.get("note"):
            w("      {}".format(info["note"]))
        w("")
        if earliest:
            try:
                d = datetime.date.fromisoformat(earliest[:10])
                if earliest_overall is None or d < earliest_overall:
                    earliest_overall = d
                    earliest_source = "{}/{}".format(mod_name, label)
            except ValueError:
                pass

    # How many artifacts actually date from inside the campaign window. This is
    # the number that answers "could this scan have seen it?", where the oldest
    # surviving file only answers "how far back does anything reach?".
    in_window = 0
    total_dated = 0
    for _mod_name, _label, info in entries:
        by_year = info.get("by_year") or {}
        for year, count in by_year.items():
            year = int(year)
            total_dated += count
            if CAMPAIGN_FROM.year <= year <= CAMPAIGN_TO.year:
                in_window += count

    if earliest_overall is not None:
        for line in overlap_statement(earliest_overall, earliest_source):
            w("  " + line)
        w("")

    # Does ANY reach record - cookie ages, DNS, not just the cache files that
    # carry by_year - reach into the campaign window? This decides whether the
    # absolute "nothing dates from the campaign period" sentence is even true.
    something_in_window = False
    for _mod_name, _label, info in entries:
        earliest = info.get("earliest")
        if earliest:
            try:
                d = datetime.date.fromisoformat(earliest[:10])
                if d <= CAMPAIGN_TO:
                    something_in_window = True
            except ValueError:
                pass

    if total_dated:
        merged = {}
        for _mod_name, _label, info in entries:
            for year, count in (info.get("by_year") or {}).items():
                year = int(year)
                merged[year] = merged.get(year, 0) + count

        w("  Age of the browser cache files searched, by year (cache files only,")
        w("  not cookies or DNS - those are summarised above):")
        w("      " + "   ".join("{}: {:,}".format(y, merged[y])
                                for y in sorted(merged)))
        w("")
        pct = 100.0 * in_window / total_dated
        w("  Of those cache files, dating from the campaign period ({}-{}): "
          "{:,} of {:,} ({:.1f}%).".format(
              CAMPAIGN_FROM.year, CAMPAIGN_TO.year, in_window, total_dated, pct))

        # A per-year floor matters more than the total: the campaign ran across
        # several years, and a year with almost nothing left is a year this scan
        # cannot speak about, however healthy the overall percentage looks.
        sparse = [y for y in range(CAMPAIGN_FROM.year, CAMPAIGN_TO.year + 1)
                  if merged.get(y, 0) < 100]
        if in_window == 0 and not something_in_window:
            w("  No dated evidence summarised here reaches the campaign period.")
            w("  Older or unread records may still exist. A clean result cannot")
            w("  rule out past contact during that period.")
        elif in_window == 0 and something_in_window:
            w("  No browser CACHE file examined dates from the campaign period, though some")
            w("  older evidence (shown above) does. Cache is the thinnest record;")
            w("  the window above is the one to read.")
        elif sparse:
            w("  BUT cache coverage is uneven. These campaign years have almost no")
            w("  surviving cache, so a clean result says little about them:")
            for y in sparse:
                w("      {}: {:,} cache file(s)".format(y, merged.get(y, 0)))
        w("")

    # The actionable part, rendered as its own ruled-off section so the one thing
    # a reader can act on does not get lost at the tail of the reach block.
    howto = []
    for _mod_name, _label, info in entries:
        howto.extend(info.get("how_to_enable") or [])
    if howto:
        w("")
        w(_RULE)
        for line in howto:
            w(line)
        w(_RULE)
    w("")


# What a hit in each tier actually MEANS, in plain language. The tier is the
# whole point of curating the indicator set: contact with an ad tracker and
# contact with a command-and-control server are different events, and a report
# that renders them identically has failed the person reading it.
TIER_MEANING = {
    "stalkerware": ("A commercial phone-monitoring ('stalkerware') app or its company's "
                    "server. Some are sold as family-safety apps and installed knowingly. "
                    "If neither you nor someone you trust installed it, someone may be "
                    "monitoring this phone."),
    "delivery": ("Advertising/tracking infrastructure belonging to this network. "
                 "The evidence grade says what was observed; a DNS record or "
                 "saved reference does not prove an ad reached this device. "
                 "An ad impression is NOT evidence of infection. Apps that show "
                 "ads, such as the new Outlook for Windows, can record these too."),
    "cc": ("A Candiru command-and-control server. This is the most serious "
           "class of indicator - it is the address an active implant talks to."),
    "validator": ("A Candiru validator server. These profiled a device and "
                  "decided, per device, whether to deliver an exploit. Contact "
                  "suggests this device was being assessed as a target."),
    "candiru": ("A server attributed to Candiru by Recorded Future. Its exact "
                "role is not published, so treat it as serious but unspecified."),
    "candiru-ip": ("An IP address attributed to Candiru infrastructure in 2025. "
                   "Weak on its own: cloud IP addresses are reassigned to "
                   "unrelated, innocent customers within months."),
    "reclaimable": ("A name from a published campaign that may since have passed to "
                    "someone else: a hostname on a shared cloud platform, or a domain "
                    "registered again after the report. A match is a lead to check "
                    "against the date, not a finding by itself."),
    "historical": ("Infrastructure from separate, older Candiru campaigns. "
                   "Interpret dated evidence in the cited report's context; "
                   "current ownership and activity are not established."),
    "sample": ("The file fingerprint of a published spyware sample (its "
               "family is named where the source gives one). A match here is "
               "conclusive, not circumstantial."),
    "infrastructure": ("A server the cited researchers attribute to the named "
                       "spyware family. Its exact role - delivering an exploit, "
                       "controlling an implant or receiving stolen data - is not "
                       "stated in the source, so treat contact as serious but "
                       "unspecified. A domain can change hands after a campaign "
                       "ends: compare the date of the evidence with the date of "
                       "the research."),
    "infrastructure-ip": ("An IP address the cited researchers attribute to the "
                          "named spyware family. Weak on its own: hosting "
                          "addresses are reassigned to unrelated, innocent "
                          "customers, often within months."),
    "candiru-pattern": ("A published Candiru detection rule matched patterns "
                        "inside a file. This needs expert verification; it is "
                        "not an exact sample identification or proof that "
                        "spyware ran."),
    "vuln-driver": ("A LEGITIMATE, signed third-party driver that this actor "
                    "abuses to disable protections (bring-your-own-vulnerable-"
                    "driver). The file itself is not spyware and is present on "
                    "clean machines that genuinely use that hardware or "
                    "software. This is a lead worth checking - who installed "
                    "it, and when - NOT evidence that spyware is on this "
                    "machine."),
}

# Tiers whose file hashes identify legitimate software this actor abuses, rather
# than the spyware itself. A match must never be reported as proof of infection:
# the same file sits on clean machines for honest reasons (see `vuln-driver`).
NOT_MALWARE_TIERS = {"vuln-driver"}

EVIDENCE_MEANING = {
    EV_FILE_PATTERN: ("patterns inside a file matched a published detection "
                      "rule. This is a lead for investigation, not a confirmed "
                      "infection or an exact known-file match"),
    EV_ON_DISK: ("a file on this machine has the fingerprint of a published "
                 "spyware sample - this is conclusive, not circumstantial"),
    # Same grade, different claim: see _on_disk_gloss(). A legitimate-but-abused
    # driver sits on disk too, and saying "conclusive" about it would be false.
    EV_PERSISTENCE: ("the name is registered to run automatically on this "
                     "machine - a hallmark of installed spyware"),
    EV_COMMAND: ("a command or script that names it ran on this computer (typed into "
                 "the Win+R box, or recorded in the PowerShell log). It may have "
                 "contacted it, or only mentioned it - a researcher's own commands "
                 "look the same"),
    EV_EXECUTION: ("a historical execution record names this executable; a matching name "
                   "does not establish its contents, infection, or that it is still present"),
    EV_INVENTORY: ("a historical application inventory names this file; inventory presence "
                   "does not prove execution, infection, or that the file still exists"),
    EV_ON_DEVICE: ("the app, signing certificate, running process, file or setting the "
                   "researchers name is on this phone"),
    EV_DEVICE_LOG: ("the phone's own system logs name it - it may have been a connection, a "
                    "lookup, or only text an app wrote to the log"),
    EV_RECEIVED: ("a message that arrived on this device contains it - spyware links are "
                  "sent this way; it does not show whether the link was opened"),
    EV_CONTACTED: "this device demonstrably communicated with it",
    EV_DNS: ("the name or address appears in local DNS data; this does not "
             "establish communication with the indicated server, and a logged "
             "lookup may have failed"),
    EV_ATTEMPTED: ("something on this device looked the name up, but a filter "
                   "blocked the connection"),
    EV_CONFIGURED: ("the name is a literal executable or destination in local configuration; "
                    "this does not establish that it ran or was contacted"),
    EV_REFERENCED: ("the name appeared in stored content or ancillary metadata; "
                    "a reference alone does not establish execution or contact"),
}

# A short imperative headline per grade, used in the summary. The ones that are
# not EV_REFERENCED are serious and each gets its own, so a sample on disk and a
# persistence entry can never be rendered as "probably nothing".
EVIDENCE_HEADLINE = {
    EV_FILE_PATTERN: "A FILE MATCHED A CANDIRU DETECTION RULE - NEEDS REVIEW",
    EV_ON_DISK: "A KNOWN SPYWARE FILE IS ON THIS MACHINE",
    EV_PERSISTENCE: "SOMETHING IS SET TO RUN AUTOMATICALLY FROM THIS INFRASTRUCTURE",
    EV_COMMAND: "A COMMAND NAMING THIS INFRASTRUCTURE WAS RUN ON THIS MACHINE",
    EV_EXECUTION: "A HISTORICAL EXECUTION RECORD NAMES THIS EXECUTABLE",
    EV_INVENTORY: "A HISTORICAL FILE INVENTORY MATCHED THIS INDICATOR",
    EV_ON_DEVICE: "SOMETHING THE RESEARCHERS TIE TO SPYWARE IS ON THIS PHONE",
    EV_DEVICE_LOG: "THE PHONE'S SYSTEM LOGS NAME THIS SPYWARE INFRASTRUCTURE",
    EV_RECEIVED: "A MESSAGE ON THIS DEVICE CONTAINS A SPYWARE LINK OR ADDRESS",
    EV_CONTACTED: "THIS DEVICE CONTACTED THIS INFRASTRUCTURE",
    EV_DNS: "THIS INDICATOR APPEARS IN LOCAL DNS RECORDS",
    EV_ATTEMPTED: "THIS DEVICE TRIED TO REACH THIS INFRASTRUCTURE (a filter blocked it)",
    EV_CONFIGURED: "THIS INFRASTRUCTURE IS CONFIGURED ON THIS MACHINE",
}


# A file-on-disk hit means two very different things depending on what the file
# IS. The grade (EV_ON_DISK) is the same either way, so the claim has to be
# chosen from the tier, not from the grade alone.
ON_DISK_NOT_MALWARE_HEADLINE = (
    "A LEGITIMATE FILE THIS ATTACKER IS KNOWN TO ABUSE IS ON THIS MACHINE")
ON_DISK_NOT_MALWARE_GLOSS = (
    "this file is NOT spyware - it is signed, legitimate software that this "
    "actor loads to disable protections. It is also installed for honest "
    "reasons. Worth establishing how it got here; not proof of anything")


def _hit_watchware(hit) -> bool:
    """The publisher classes this monitoring app as one that does not hide
    itself (ECHAP's "watchware"), on every record that names it."""
    records = hit.get("indicator_context") or []
    return bool(records) and all(isinstance(r, dict) and r.get("monitoring") == "watchware"
                                 for r in records)


def _headline_for(hit) -> str:
    """The summary headline for one serious hit, chosen by grade AND tier."""
    if hit.get("withdrawn_only"):
        return "HISTORICAL MATCH TO A WITHDRAWN INDICATOR - REVIEW SOURCE CONTEXT"
    if hit.get("tier") == "stalkerware" and _hit_watchware(hit):
        return ("A MONITORING APP THAT DOES NOT HIDE ITSELF (OFTEN A FAMILY-SAFETY APP) "
                "WAS FOUND - DID YOU, OR SOMEONE YOU TRUST, INSTALL IT?")
    if hit.get("tier") == "stalkerware":
        return ("A PHONE-MONITORING APP OR ITS SERVER WAS FOUND - DID YOU, OR SOMEONE "
                "YOU TRUST, INSTALL IT?")
    if hit.get("tier") in NOT_MALWARE_TIERS and hit.get("evidence") == EV_ON_DISK:
        return ON_DISK_NOT_MALWARE_HEADLINE
    if hit.get("evidence") == EV_ON_DISK and hit.get("tier") != "sample":
        return "A FILE FINGERPRINT MATCHED; ITS CLASSIFICATION NEEDS REVIEW"
    if hit.get("tier") in DECAYING_IP_TIERS and hit.get("evidence") == EV_CONTACTED:
        return "THIS DEVICE CONTACTED A HISTORICALLY ATTRIBUTED IP ADDRESS"
    if hit.get("tier") == "reclaimable" and hit.get("evidence") == EV_CONTACTED:
        return "THIS DEVICE CONTACTED A NAME THAT MAY HAVE CHANGED OWNER SINCE THE REPORT"
    return EVIDENCE_HEADLINE.get(hit.get("evidence"), "A SERIOUS INDICATOR MATCHED")


def _evidence_gloss(hit) -> str:
    """What this grade establishes for this hit (tier-aware, same reason)."""
    if hit.get("tier") in NOT_MALWARE_TIERS and hit.get("evidence") == EV_ON_DISK:
        return ON_DISK_NOT_MALWARE_GLOSS
    if hit.get("evidence") == EV_ON_DISK and hit.get("tier") != "sample":
        return ("a file fingerprint matched an indicator, but its classification "
                "does not identify it as a known spyware sample; expert review "
                "is needed")
    if hit.get("tier") in DECAYING_IP_TIERS and hit.get("evidence") == EV_CONTACTED:
        return ("a connection record names this IP address; who controlled it "
                "at the time is not established by this match")
    if hit.get("tier") == "reclaimable" and hit.get("evidence") == EV_CONTACTED:
        return ("a connection record names this host; it may belong to someone "
                "else now, so only a record dated to the campaign period matters")
    return EVIDENCE_MEANING.get(hit.get("evidence") or "", "")


# Indicator kinds that are not network addresses: shown as written.
_NOT_ADDRESSES = {"app-id", "app-cert", "file-path", "file-name", "android-property",
                  "process", "profile-id", "sha256"}


def _net_value(hit) -> str:
    """The hit's indicator if it is (or may be) a network address, else ''."""
    return "" if hit.get("kind") in _NOT_ADDRESSES else hit.get("indicator", "")


def _show_indicator(hit, document=None) -> str:
    """Defang network indicators only. An app id such as com.life360.android
    is not an address anyone could click, and '[.]' made it look like one."""
    value = hit.get("indicator", "")
    return _defang(value) if _net_value(hit) else value


def _defang(indicator: str) -> str:
    """Make an indicator safe to paste into an email or chat without a client,
    gateway or link scanner auto-fetching it. The report is designed to be
    forwarded to Access Now / Amnesty, and the tool's own rule is never to
    contact an indicator - so it must not ship them in a fetchable form. The JSON
    report keeps the raw value; only the human text is defanged."""
    out = indicator.replace("http://", "hxxp://").replace("https://", "hxxps://")
    # Neuter the last dot (domains) or wrap every dot (IPs) so nothing resolves.
    if any(c.isalpha() for c in indicator) and "." in out:
        head, _, tail = out.rpartition(".")
        return "{}[.]{}".format(head, tail)
    return out.replace(".", "[.]")


# A URL scheme is all a mail gateway, link preview or security scanner needs in
# order to fetch the thing. ftp:// is covered too, because a detail line quotes
# whatever was in the saved page.
_SCHEMES = {"https://": "hxxps://", "http://": "hxxp://", "ftp://": "fxp://"}
_SCHEME_RE = re.compile("|".join(_SCHEMES), re.IGNORECASE)


def _defang_text(text: str, indicator: str) -> str:
    """Defang the indicator traces inside a free-text field - a detail line, a
    path - and change nothing else about it.

    Two passes, and only two. Schemes are neutered wherever they appear, because
    a detail line quotes saved page content and a live https:// in there is
    fetchable straight out of the report. Then the indicator's own value is
    swapped for whatever _defang() renders it as, so the two places a reader
    sees the same name agree. That match is case-insensitive: the browser module
    lowercases the text it quotes, while the indicator need not be lowercase.

    Deliberately NOT a general "wrap every dot" pass. A location is usually a
    Windows path - "C:\\Users\\x\\AppData\\...\\Network\\Cookies" - and blanket
    dot-wrapping would mangle real file and folder names into something the
    person acting on this report can no longer find on their own disk.
    """
    out = _SCHEME_RE.sub(lambda m: _SCHEMES[m.group(0).lower()], str(text))
    defanged = _defang(indicator) if indicator else indicator
    if indicator and defanged != indicator:
        out = re.sub(re.escape(indicator), lambda _m: defanged, out,
                     flags=re.IGNORECASE)
    return out


# Artifact-derived text is attacker-influenced: a browser profile's display name,
# a registry value, a page title. Rendered raw, a newline or a terminal escape
# inside one can forge whole report lines - a fake "VERDICT: no known indicators
# found" printed under a real hit, which survives being pasted into an email to a
# helpline. Control characters, Unicode line separators and bidirectional
# overrides (which can visually reverse a line without any newline) are
# replaced, and newlines collapse to spaces so a field can never begin a line of
# its own. Invisible formatting characters (zero-width spaces and joiners,
# direction marks, the byte-order mark) are removed, so text cannot hide
# anything or look different from what it is; Persian and Arabic words and
# emoji still read correctly without them. The JSON report keeps the raw evidence.
_UNSAFE_CHARS = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")
_INVISIBLE_CHARS = re.compile("[\xad\u180e\u200b-\u200f\u2060-\u2064\ufeff]")


def _safe_text(value, limit=2000):
    text = str(value).replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    text = text.encode("utf-8", "backslashreplace").decode("utf-8")
    text = _UNSAFE_CHARS.sub("�", _INVISIBLE_CHARS.sub("", text))
    return text if len(text) <= limit else text[:limit] + "…"


# Tighter limits for the single-line fields an attacker can fill most freely.
_HIT_FIELD_LIMITS = {"profile": 120, "observed": 64, "location": 500,
                     "detail": 500, "indicator": 300}


def _human_document(document):
    """Sanitize artifact-derived fields without changing the JSON evidence.

    Notes and gaps can quote remote paths just as hits can. Published source
    citations and the fixed help links remain usable.
    """
    doc = copy.deepcopy(document)

    def scrub(value, limit=2000):
        if isinstance(value, str):
            return _defang_text(_safe_text(value, limit), "")
        if isinstance(value, list):
            return [scrub(item, limit) for item in value]
        if isinstance(value, dict):
            return {key: scrub(item, limit) for key, item in value.items()}
        return value

    for module in doc["modules"].values():
        for key in ("notes", "checks", "reach"):
            if key in module:
                module[key] = scrub(module[key])
        for hit in module["hits"]:
            for key in ("location", "detail", "observed", "profile"):
                if key in hit:
                    hit[key] = scrub(hit[key], _HIT_FIELD_LIMITS[key])
            if isinstance(hit.get("indicator"), str):
                hit["indicator"] = _safe_text(hit["indicator"], _HIT_FIELD_LIMITS["indicator"])
        for lead in module.get("leads", []):
            for key in ("location", "what", "observed"):
                if key in lead:
                    lead[key] = scrub(lead[key], 500)
    for item in doc.get("worth_a_look", []):
        for key in ("location", "what", "observed"):
            if key in item:
                item[key] = scrub(item[key], 500)
    for row in doc.get("timeline", []):
        for key in ("when", "what", "location"):
            row[key] = scrub(row.get(key, ""), 500)
    doc["verdict"]["gaps"] = scrub(doc["verdict"].get("gaps", []))
    return doc


def _defang_report(text, document):
    """Cover every occurrence, including notes and another hit's details."""
    indicators = set(document.get("_indicators", []))
    indicators.update(_net_value(hit) for module in document["modules"].values()
                      for hit in module["hits"])
    # A value that is also a non-address indicator in this report (an app id
    # like com.life360.android.safetymapd) is never defanged.
    indicators -= {hit["indicator"] for module in document["modules"].values()
                   for hit in module["hits"] if not _net_value(hit)}
    for indicator in sorted(indicators, key=len, reverse=True):
        if indicator and _defang(indicator) != indicator:
            text = re.sub(re.escape(indicator), lambda m: _defang(m.group(0)),
                          text, flags=re.IGNORECASE)
    return text.encode("utf-8", "backslashreplace").decode("utf-8")


def _recommended_action(hit) -> int:
    """Human next steps, separate from evidence grades and the JSON verdict.

    0: saved context; 1: self-review; 2: qualified interpretation;
    3: prompt expert help. Unknown metadata never becomes reassurance.
    """
    evidence, tier = hit.get("evidence"), hit.get("tier")
    if evidence == EV_REFERENCED:
        return 0
    if hit.get("withdrawn_only"):
        return 1
    if tier == "stalkerware":
        # The person decides first whether they know about it; the next steps
        # carry the safety advice (removing it can alert whoever installed it).
        return 1
    if evidence == EV_ON_DISK and tier == "vuln-driver":
        return 1
    if evidence in (EV_ON_DISK, EV_PERSISTENCE, EV_ON_DEVICE):
        return 3
    if ((tier in ("delivery", "reclaimable") or tier in DECAYING_IP_TIERS) and
            evidence in (EV_CONTACTED, EV_DNS, EV_ATTEMPTED, EV_CONFIGURED)):
        return 1
    return 2


def _advice_paragraph(w, text):
    for line in _wrap(text, 66):
        w("    " + line)


def _next_steps(w, hits):
    action = max(_recommended_action(h) for h in hits)
    w("  WHAT TO DO")
    monitoring = [h for h in hits if h.get("tier") == "stalkerware"]
    if monitoring and all(_hit_watchware(h) for h in monitoring):
        _advice_paragraph(w, "A monitoring app that does not hide itself was found, "
                         "often a family-safety app. If you installed it yourself, or "
                         "someone you trust manages this phone, this may be expected. "
                         "If not, someone may be monitoring you, even though the app "
                         "is not hidden.")
        w("")
        _advice_paragraph(w, "Removing the app can alert whoever installed it. If you "
                         "could be in danger, talk to a support service before you "
                         "change anything: https://stopstalkerware.org/")
        w("")
    elif monitoring:
        _advice_paragraph(w, "A phone-monitoring app, or its company's server, was "
                         "found. If you installed it yourself, or someone you trust "
                         "manages this phone (some are family-safety apps), this may "
                         "be expected. If not, someone may be monitoring you.")
        w("")
        _advice_paragraph(w, "Removing the app can alert whoever installed it. If you "
                         "could be in danger, talk to a support service before you "
                         "change anything: https://stopstalkerware.org/")
        w("")
    if any(h.get("evidence") == EV_FILE_PATTERN for h in hits):
        _advice_paragraph(w, "A file matched a Candiru pattern rule. Ask a "
                         "qualified incident responder to verify the named file "
                         "and rule. Preserve the file and this report; do not "
                         "open, run or delete the file. A pattern match alone "
                         "does not prove infection or that the file executed.")
        w("")
        if all(h.get("evidence") in (EV_FILE_PATTERN, EV_REFERENCED) for h in hits):
            return
    if action == 3:
        _advice_paragraph(w, "Seek expert help promptly. Preserve this report and "
                         "the named files or registrations. Do NOT delete, move, "
                         "run or try to clean them. A file match establishes "
                         "presence; a registration establishes configuration. "
                         "Neither alone establishes that spyware executed.")
        w("")
        _advice_paragraph(w, "Contact a qualified incident responder or your "
                         "organisation's security team. You do not need to "
                         "finish investigating first. Support options are at "
                         "the end of this report.")
    elif action == 2:
        _advice_paragraph(w, "Qualified interpretation is recommended. Review "
                         "the evidence type, saved date and location below. "
                         "A DNS record may be a failed lookup; it does not "
                         "establish a connection. Missing or unrecognised "
                         "evidence labels also need review, not reassurance.")
        w("")
        _advice_paragraph(w, "A connection record for command-and-control, "
                         "validator or other attributed spyware infrastructure "
                         "warrants specialist review. For a DNS-only or "
                         "configuration finding, seek qualified help if the "
                         "local context does not explain it, or if you have "
                         "a credible reason to believe you are being targeted. "
                         "These records do not by themselves establish infection.")
        w("")
        _advice_paragraph(w, "Keep the report and original records. Do NOT delete "
                         "or clean them while arranging review. Your organisation's "
                         "security team or a qualified incident responder can help.")
    else:
        _advice_paragraph(w, "Start with the saved evidence below. Check the "
                         "indicator's role, evidence type, browser/profile, "
                         "date (if available), and file or record that matched. "
                         "Use the report and existing records; do not visit "
                         "the indicator to investigate it.")
        if any(h.get("tier") == "delivery" and h.get("evidence") in
               (EV_CONTACTED, EV_DNS, EV_ATTEMPTED) for h in hits):
            w("")
            _advice_paragraph(w, "Advertising-network records alone do not show "
                             "that you were selected for an exploit or infected. "
                             "A connection can result from an ordinary ad; a "
                             "DNS record does not even establish that connection. "
                             "This finding alone does not call for a spyware "
                             "helpline referral.")
        if any(h.get("tier") == "vuln-driver" and
               h.get("evidence") == EV_ON_DISK for h in hits):
            w("")
            _advice_paragraph(w, "For the legitimate driver, check whether its "
                             "location and installation history match hardware "
                             "or software you use. Your IT support or the "
                             "software vendor can help identify it. Do not "
                             "delete it solely because of this match.")
        if any(h.get("tier") in DECAYING_IP_TIERS for h in hits):
            w("")
            _advice_paragraph(w, "For a historical IP address, ownership can change. "
                             "The tool has not established who controlled it "
                             "at the time of this record. Check the saved date "
                             "against the cited research; an absent date leaves "
                             "that question unresolved.")
        configured = [h for h in hits if h.get("evidence") == EV_CONFIGURED]
        if configured:
            text = "For a configuration entry, check who or what created it and why. "
            if any(h.get("tier") == "delivery" for h in configured):
                # Only ad-delivery infrastructure has the ad-impression explanation.
                where = ("hosts-file entry" if any("hosts" in str(h.get("location", "")).lower()
                                                   for h in configured) else "configuration entry")
                text += "An ordinary ad impression does not explain a local " + where + ". "
            w("")
            _advice_paragraph(w, text + "Do not edit it merely to make this finding disappear.")
        w("")
        _advice_paragraph(w, "Keep the report. If you cannot explain a finding, "
                         "ask trusted IT support for help interpreting it. "
                         "Stronger findings or a credible targeting concern "
                         "warrant qualified security help directly; you do not "
                         "have to complete these steps first.")
    w("")
    _advice_paragraph(w, "Do NOT open, visit or look up indicator addresses. Keep "
                     "the [.] spelling when sharing them.")


def _support_options(w):
    w("WHEN TO SEEK SUPPORT")
    w("A credible targeting concern or a genuine security notification warrants")
    w("qualified help regardless of this scan's result. You do not need to")
    w("complete self-checks first. Contact your organisation's security team")
    w("or a qualified incident responder.")
    w("")
    w("For journalists, activists, human-rights defenders and other civil")
    w("society members, Access Now offers a Digital Security Helpline:")
    w("  https://www.accessnow.org/help/")
    w("  Eligibility and support: https://www.accessnow.org/help/helpline-faq/")
    w("Check its intake instructions before sending private evidence.")
    w("")
    w("Research and further guidance:")
    w("  Amnesty International Security Lab  https://securitylab.amnesty.org/")
    w("  The Citizen Lab                     https://citizenlab.ca/")
    w("")
    w("A saved reference or advertising-network trace alone is not a reason")
    w("to assume spyware infection. No result from this tool rules it out.")


def render_summary(document: Dict[str, Any]) -> str:
    """The part a person actually reads. Answers, in order: what was found, what
    it means, what to do, and what this scan could not check.

    Everything below this in the report is the evidence for these few lines."""
    document = _human_document(document)
    out: List[str] = []
    w = out.append
    v = document["verdict"]

    all_hits = [h for _m, m in document["modules"].items() for h in m["hits"]]
    serious = [h for h in all_hits if is_serious(h.get("evidence", ""))]
    benign = [h for h in all_hits if not is_serious(h.get("evidence", ""))]

    w(_RULE)
    w("  SUMMARY  —  read this part")
    w(_RULE)

    if not all_hits:
        w("  RESULT: no known indicator was found in anything that could be")
        w("          checked.")
        w("")
        w("  This is NOT a clean bill of health. See the two sections below for")
        w("  what was searched and, more importantly, what could not be.")
    elif serious:
        n = len(serious)
        action = max(_recommended_action(h) for h in serious)
        if all(h.get("withdrawn_only") for h in serious):
            w("  RESULT: a match to an indicator its publisher has WITHDRAWN - review")
            w("          the source context. Not an actionable finding.")
        elif action == 3:
            w("  RESULT: SERIOUS FINDING - seek expert help promptly.")
        elif action == 2:
            w("  RESULT: potentially SERIOUS finding - qualified review recommended.")
        else:
            # Count what was found, not how many records repeat it: one app seen
            # in a dozen databases is one thing to review, not twelve.
            k = len({h.get("indicator") for h in serious})
            if k == n:
                w("  RESULT: {} finding{} to review; start with the saved context.".format(
                    n, "" if n == 1 else "s"))
            else:
                w("  RESULT: {} indicator{} to review, recorded in {} places; start with".format(
                    k, "" if k == 1 else "s", n))
                w("          the saved context.")
        if benign:
            nb = len(benign)
            w("          ({} further match{} {} only {} in saved page "
              "content.)".format(
                  nb, "" if nb == 1 else "es", "is" if nb == 1 else "are",
                  "a reference" if nb == 1 else "references"))
        w("")
        w("  WHAT WAS FOUND")
        # Strongest grade first; collapse repeats of the same indicator+grade so
        # one domain in three cache files is not three lines.
        for h in sorted(_dedup_serious(serious),
                        key=_recommended_action, reverse=True):
            headline = _headline_for(h)
            w("    >> {}".format(headline))
            w("       {}  [{}]".format(_show_indicator(h, document), h["tier"]))
            if h.get("withdrawal_present"):
                for line in _wrap(MUST_RELAY["withdrawn"], 64):
                    w("          " + line)
            # A withdrawn-only match already says "not an actionable finding";
            # the tier's "treat contact as serious" text would contradict it.
            meaning = None if h.get("withdrawn_only") else TIER_MEANING.get(h["tier"])
            if meaning:
                for line in _wrap(meaning, 64):
                    w("          " + line)
            if h.get("profile"):
                w("          Account: {}".format(h["profile"]))
            if h.get("observed"):
                w("          When: {}".format(h["observed"][:19].replace("T", " ")))
            w("          Where: {}".format(
                _defang_text(h["location"], _net_value(h))))
            w("")
        _next_steps(w, serious)
        if benign:
            n_b = len(benign)
            w("")
            w("    The {} reference-only match{} {} listed in DETAIL. Saved text".format(
                  n_b, "" if n_b == 1 else "es", "is" if n_b == 1 else "are"))
            w("    can mention an indicator without a connection to it.")
    else:
        n = len(benign)
        w("  RESULT: {} match{} found, all of them reference-only.".format(
            n, "" if n == 1 else "es"))
        w("")
        w("  WHAT THIS PROBABLY IS")
        for line in _wrap(
                "These matches are names found in saved content, such as page "
                "text, an unvisited bookmark or browser storage. A reference "
                "does not establish a connection, execution or infection. "
                "Check the saved title, location and date in DETAIL without "
                "opening the indicator address. A reference alone is probably "
                "not a sign of compromise; it does not clear the device either.", 68):
            w("    " + line)
        w("")
        _advice_paragraph(w, "A reference alone does not call for a helpline "
                         "referral. If you have a credible targeting concern "
                         "or a genuine security notification, seek qualified "
                         "help directly regardless of this result.")

    for group in document.get("correlations", []):
        w("RELATED RECORDS: {} occurs in {} artifacts.".format(
            _show_indicator(group, document), group["artifact_count"]))
        w("  " + group["interpretation"])
    looks = document.get("worth_a_look") or []
    if looks:
        w("")
        w("  ALSO: {} item{} under \"WORTH A LOOK\" further down. {} NOT".format(
            len(looks), "" if len(looks) == 1 else "s",
            "It is" if len(looks) == 1 else "They are"))
        w("  a finding; each comes with its usual, ordinary explanation.")
    gaps = v.get("gaps") or []
    if gaps:
        w("")
        w("  WHAT COULD NOT BE CHECKED  ({} gap{}, grouped)".format(
            len(gaps), "" if len(gaps) == 1 else "s"))
        for g in _gap_lines(gaps):
            for i, line in enumerate(_wrap(g, 66)):
                w("    " + ("- " if i == 0 else "  ") + line)
        w("    (Each one is listed in full at the end of this report.)")
        # The DNS gap is the one a reader can actually close - but only point at
        # the instructions if they were actually rendered (they are not on a
        # non-Windows host), or the pointer dangles.
        if document.get("_dns_howto") and any("dns" in g.lower() for g in gaps):
            w("")
            w("    -> You can fix the DNS gap for next time, in one command.")
            w("       See \"HOW TO TURN ON DNS HISTORY\" further down. It tells you")
            w("       nothing about the past, but it means a future check can")
            w("       actually answer the question.")
    # Every report, not only one with findings. A clean or reference-only result
    # is the one people are most relaxed about posting publicly to say "I'm
    # fine" - and it carries the same usernames, profile names and paths.
    w("")
    for line in _wrap(_PRIVACY_NOTE, 68):
        w("  " + line)
    w(_RULE)
    w("")
    return _defang_report("\n".join(out), document)


_GAP_APP = re.compile(r"^browser/(?:app:)?([^:/]+):")
# Only real lock/permission wording: "could not read" also covers corrupt files,
# and telling someone to close an app does not fix a damaged database.
_GAP_LOCKED = ("was running", "permission denied", "locked")
_GAP_COUNT = re.compile(r"(\d+) of (\d+) candidate file")
_GAP_NONE = re.compile(r"\((\d+) candidate file\(s\)")
_GAP_FOLDERS = re.compile(r"(\d+) folder\(s\) or item\(s\)")
_APP_NAMES = {"edge": "Edge", "chrome": "Chrome", "brave": "Brave", "vivaldi": "Vivaldi",
              "chromium": "Chromium", "firefox": "Firefox", "safari": "Safari",
              "selected": "the selected browser folder"}


def _gap_lines(gaps: List[str]) -> List[str]:
    """The summary's gap list, grouped so a person can read it.

    An ordinary scan can list dozens of gaps, most of them the same thing - an
    open app locking its files - with raw error text pasted in. The
    full list stays in the JSON and at the end of the report; here, one line
    per kind of gap."""
    locked, files_missed, folders_missed, rest = [], 0, 0, {}
    private, full_disk = [], False
    missing_sources = False
    for g in gaps:
        low = g.lower()
        if "full disk access" in low:
            full_disk = True
        if "macos privacy protection blocked" in low:
            app = _GAP_APP.match(g)
            name = _APP_NAMES.get(app.group(1).strip(), app.group(1).strip().title()) if app else "some folders"
            if name not in private:
                private.append(name)
            continue
        if low.startswith("indicators/indicator-sources:") and "indicator source missing" in low:
            missing_sources = True
            continue
        app = _GAP_APP.match(g)
        if app and any(word in low for word in _GAP_LOCKED):
            name = app.group(1).strip()
            name = _APP_NAMES.get(name, name.title())
            if name not in locked:
                locked.append(name)
            continue
        if low.startswith("hash/root:"):
            m = _GAP_COUNT.search(g) or _GAP_NONE.search(g)
            folders = _GAP_FOLDERS.search(g)
            if m or folders:
                files_missed += int(m.group(1)) if m else 0
                folders_missed += int(folders.group(1)) if folders else 0
                continue
        rest[g] = rest.get(g, 0) + 1
    lines = []
    if missing_sources:
        lines.append("Indicator sources not downloaded — run --update once, then scan again.")
    if locked:
        lines.append("Open apps kept some of their data locked, so it was not read: {}. "
                     "Close them and run the check again to include it.".format(
                         ", ".join(sorted(locked))))
    if private:
        lines.append("macOS privacy protection kept some records from being read: {}. Give "
                     "Terminal Full Disk Access (System Settings > Privacy & Security > Full Disk "
                     "Access), then run the check again.".format(", ".join(sorted(private))))
    fda = (" Full Disk Access for Terminal lets macOS-protected folders be included."
           if full_disk and not private else "")
    if files_missed:
        lines.append("{:,} program file(s) could not be fingerprinted (in use, protected, "
                     "or over 120 MB).".format(files_missed)
                     + ("" if folders_missed else fda))
    if folders_missed:
        lines.append("{:,} folder(s) could not be opened, so the program files inside them "
                     "were not fingerprinted.".format(folders_missed) + fda)
    for reason, count in rest.items():
        line = reason if len(reason) <= 240 else reason[:237] + "..."
        if count > 1:
            line += " ({} occurrences)".format(count)
        lines.append(line)
    return lines


_PRIVACY_NOTE = ("Before you share this report: it can contain your Windows "
                 "username, browser profile names, file paths and browsing "
                 "details, SMS senders and message excerpts. --share-json writes a "
                 "minimal summary without artifact text. Ask a responder how to share "
                 "evidence securely; do not post the full report publicly.")


def _dedup_serious(hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse repeats of the same indicator at the same grade, strongest grade
    first, so one domain found in three cache files is one line, not three."""
    order = {g: i for i, g in enumerate(
        [EV_ON_DISK, EV_ON_DEVICE, EV_PERSISTENCE, EV_COMMAND, EV_EXECUTION, EV_INVENTORY, EV_CONTACTED, EV_RECEIVED,
         EV_DEVICE_LOG,
         EV_DNS, EV_ATTEMPTED, EV_CONFIGURED])}
    seen = {}
    for h in hits:
        key = (h["indicator"], h.get("evidence", ""))
        if key not in seen:
            seen[key] = h
    return sorted(seen.values(),
                  key=lambda h: order.get(h.get("evidence", ""), 99))


def _wrap(text: str, width: int) -> List[str]:
    words, lines, cur = text.split(), [], ""
    for word in words:
        if cur and len(cur) + 1 + len(word) > width:
            lines.append(cur)
            cur = word
        else:
            cur = (cur + " " + word).strip()
    if cur:
        lines.append(cur)
    return lines


def _referrals(w) -> None:
    w("  - Access Now Digital Security Helpline  https://www.accessnow.org/help/")
    w("  - Amnesty International Security Lab     https://securitylab.amnesty.org/")
    w("  - The Citizen Lab                        https://citizenlab.ca/")


def _family_counts(iocs) -> Dict[str, int]:
    """Indicators per spyware family across the merged set (curated file: none)."""
    counts: Dict[str, int] = {}
    for ind in iocs.indicators:
        for fam in (ind.family or "").split("; "):
            if fam:
                counts[fam] = counts.get(fam, 0) + 1
    return dict(sorted(counts.items()))


def _basename(path: str) -> str:
    """Last path component for either separator. Reports are read on other
    machines, so a Windows path must shorten correctly on Linux too."""
    return str(path).replace("\\", "/").rsplit("/", 1)[-1]


def _housekeeping_block(status):
    status = status or {}
    return {"stale_temp_removed": int(status.get("removed", 0)),
            "stale_temp_not_removed": [sanitize_untrusted(p) for p in status.get("failed", [])]}


def _feed_block(status):
    """Which downloaded indicator sets were used (sanitised: the cache path and
    refusal reasons come from this machine)."""
    if not status:
        return {"used": False, "reason": "not applicable"}
    out = copy.deepcopy(status)
    if "cache" in out:
        out["cache"] = sanitize_untrusted(out["cache"])
    for r in out.get("refused", []):
        r["reason"] = sanitize_untrusted(r.get("reason", ""))
    return out
