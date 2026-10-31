"""Shared report-saving and interactive follow-up for both entry points.

The follow-up operates only on the completed report and explicitly selected
export files. It never launches another scan, opens a URL or uploads evidence.
"""
import argparse
import hashlib
import json
import os
import time
import sys
import tempfile

from .contract import sanitize_untrusted
from .localpaths import path_problem, sweep_stale_temp, synced_folder


class WorkflowParser(argparse.ArgumentParser):
    """Argument errors are setup errors, never the scanner's finding exit 2."""
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, "{}: error: {}\n".format(self.prog, message))


def workflow_arguments(parser):
    parser.add_argument("--report", metavar="PATH", help="also save the readable report to a local text file")
    parser.add_argument("--evidence-bundle", metavar="PATH", help="save a private, unencrypted evidence ZIP; refuses to overwrite an existing file")
    parser.add_argument("--evidence-file", action="append", default=[], metavar="PATH",
                        help="explicit local original file to include in --evidence-bundle (repeatable; may contain private data)")
    parser.add_argument("--post-menu", action="store_true", help="show report inspection and export choices after an explicit scan, in an interactive terminal")


def workflow_validate(parser, args):
    outputs = [(name, getattr(args, name.replace("-", "_"), None))
               for name in ("json", "share-json", "report", "evidence-bundle")]
    present = [(name, os.path.abspath(path)) for name, path in outputs if path]
    keys = [os.path.normcase(path) for _, path in present]
    if len(keys) != len(set(keys)):
        parser.error("report, JSON, sharing summary and evidence bundle must name different files")
    selected = list(getattr(args, "evidence_file", ()) or ())
    if selected and not args.evidence_bundle:
        parser.error("--evidence-file requires --evidence-bundle")
    if (args.report or args.evidence_bundle or args.post_menu) and any(
            getattr(args, key, False) for key in ("update", "preview", "describe", "phone_guide")):
        parser.error("report, evidence and post-menu options require a scan")
    if args.post_menu and args.no_menu:
        parser.error("--post-menu cannot be combined with --no-menu")


def _wf_canonical(path):
    """Case-folded long-form path; for a path that does not exist yet, its
    existing parent folder is canonicalised and the name kept."""
    try:
        if os.path.lexists(path):
            return os.path.normcase(os.path.realpath(path))
        parent, name = os.path.split(path)
        return os.path.normcase(os.path.join(os.path.realpath(parent), name))
    except (OSError, ValueError):
        return os.path.normcase(path)


def workflow_output_guard(args, path, document=None):
    """Never replace source evidence with a report, including after menu choices."""
    output = os.path.abspath(path)
    problem = path_problem(output)
    if problem:
        raise ValueError("output path refused: " + problem + "; use a path on a local disk")
    sources = list(getattr(args, "iocs", ()) or ()) + list(getattr(args, "target", ()) or ())
    sources += list(getattr(args, "evidence_file", ()) or ())
    sources += list(getattr(args, "pattern_path", ()) or ())
    if getattr(args, "collect_android", None):
        sources.append(args.collect_android)
    if getattr(args, "phone", None):
        sources.append(args.phone)
    # A selected browser database (History, Cookies...) makes the browser check
    # read its whole profile folder, so every existing file in that folder is
    # evidence too - not just the one file that was named.
    from .modules.browser import _TARGET_DB_FILES
    if not getattr(args, "target", ()) and not getattr(args, "phone", None):
        from .modules.browser import CHROMIUM_ROOTS, FIREFOX_ROOTS, _firefox_roots, _browser_cache_profile
        for _, root in CHROMIUM_ROOTS:
            sources.extend((root, _browser_cache_profile(root)))
        for profile, cache in (FIREFOX_ROOTS if FIREFOX_ROOTS is not None else _firefox_roots()):
            sources.extend((profile, cache))
        from .modules.posix import _ux_roots
        sources.extend(root for _, root, _ in _ux_roots())
        from .modules.browser import _browser_safari_roots
        for _, root in _browser_safari_roots():
            # Safari also keeps tabs, cache, cookies and HSTS in its sandbox.
            library = os.path.dirname(root)
            sources.extend((root, os.path.join(library, "Containers", "com.apple.Safari"),
                            os.path.join(library, "Cookies")))
        # Desktop apps (Slack, Signal...) keep browser records the scan reads
        # inside the platform's app data and app cache folders. Every app found
        # by its contents lies within them, so no existing file there may be
        # replaced, whether or not discovery recognises the app.
        from .modules.browser import _app_bases, _app_cache_bases
        # The hash check reads every candidate file in its folders (Downloads,
        # Desktop, Documents, app folders...), so an existing file there is
        # evidence too, whatever it contains: a file that merely looks like an
        # earlier report must not be able to exempt itself.
        if os.path.lexists(output):
            from .modules.hashscan import _roots
            output_c = _wf_canonical(output)
            for base in _roots():
                if not base or path_problem(base) or not os.path.isdir(base):
                    continue
                base_c = _wf_canonical(base)
                try:
                    inside = os.path.commonpath((base_c, output_c)) == base_c
                except ValueError:
                    inside = False
                if inside:
                    raise ValueError("{} is an existing file in a folder this scan checks, so it was not "
                                     "replaced; choose a new filename (for example add the date)".format(
                                         os.path.basename(output)))
        if os.path.lexists(output):
            output_c = _wf_canonical(output)
            for base in _app_bases() + _app_cache_bases():
                if not base or path_problem(base) or not os.path.isdir(base):
                    continue
                base_c = _wf_canonical(base)
                try:
                    inside = os.path.commonpath((base_c, output_c)) == base_c
                except ValueError:
                    inside = False
                if inside:
                    raise ValueError("an output cannot replace an existing file in the applications' data "
                                     "folder, where desktop apps keep records this scan reads; choose a new filename")
    for raw in list(getattr(args, "target", ()) or ()):
        if os.path.basename(raw).lower() in _TARGET_DB_FILES and os.path.isfile(raw):
            sources.append(os.path.dirname(os.path.abspath(raw)))
    # Artifact fields are only compared as names, never resolved or opened.
    for md in (document or {}).get("modules", {}).values():
        for hit in md.get("hits", []):
            for key in ("artifact", "location"):
                value = hit.get(key)
                if isinstance(value, str) and os.path.isabs(value) and os.path.normcase(os.path.normpath(value)) in (
                        os.path.normcase(output), _wf_canonical(output)):
                    raise ValueError("an output cannot replace recorded source evidence")
    # Compare canonical spellings: Windows 8.3 short names (HISTOR~1) name the
    # same file as the long name, and a string comparison let a report replace
    # evidence through one. path_problem above already refused links/junctions.
    output_c = _wf_canonical(output)
    for raw in sources:
        source = os.path.abspath(raw)
        if path_problem(source):
            continue
        source_c = _wf_canonical(source)
        if source_c == output_c:
            raise ValueError("an output cannot replace a selected input")
        if not os.path.lexists(output):
            continue  # new reports are allowed within a selected drive/folder
        if os.path.exists(source) and os.path.samefile(source, output):
            raise ValueError("an output cannot replace an alias of a selected input")
        if os.path.isdir(source):
            try:
                inside = os.path.commonpath((source_c, output_c)) == source_c
            except ValueError:
                inside = False
            if inside:
                raise ValueError("an output cannot replace an existing file inside the selected evidence folder; choose a new filename")


def workflow_before_scan(args, iocs):
    """Privacy housekeeping just before a scan starts, for both entry points.

    Removes private temporary copies an earlier scan left behind when it was
    killed or crashed (recorded on `iocs.housekeeping` for the report), and
    says when a report is about to be saved in a folder that OneDrive or
    iCloud uploads (often a Desktop or Documents folder)."""
    iocs.housekeeping = sweep_stale_temp()
    if iocs.housekeeping["removed"]:
        print("Removed {} leftover temporary folder(s) from an earlier scan that did not "
              "finish.".format(iocs.housekeeping["removed"]), file=sys.stderr)
    for path in iocs.housekeeping["failed"]:
        print("WARNING: could not remove a leftover temporary folder from an earlier scan; it "
              "may hold private copies. Delete it yourself: {}".format(path), file=sys.stderr)
    for key in ("report", "json", "share_json", "evidence_bundle"):
        path = getattr(args, key, None)
        folder = synced_folder(path) if path else ""
        if folder:
            print("NOTE: the report will be saved in {}, inside {}, which is synced to the "
                  "cloud. Reports hold private details (user name, file paths, browsing "
                  "records). To keep them on this computer only, move the toolkit folder "
                  "outside it (for example to Downloads) and run it again.".format(
                      os.path.dirname(os.path.abspath(path)), folder), file=sys.stderr)
            break


def workflow_check_outputs(args, document=None):
    for key in ("json", "share_json", "report", "evidence_bundle"):
        path = getattr(args, key, None)
        if path:
            workflow_output_guard(args, path, document)
    for raw in getattr(args, "evidence_file", ()) or ():
        if path_problem(os.path.abspath(raw)):
            raise ValueError("evidence files must be on a local disk")
    if getattr(args, "evidence_bundle", None) and os.path.lexists(args.evidence_bundle):
        raise ValueError("evidence bundle already exists; choose a new file")


def workflow_fingerprints(iocs):
    """Hash effective parsed records, independent of source paths and order."""
    groups = {}
    for ind in iocs.indicators:
        record = {key: getattr(ind, key, "") for key in
                  ("value", "type", "tier", "confidence", "source", "family", "contexts")}
        raw = json.dumps(record, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
        groups.setdefault(ind.source, []).append(raw)
    def digest(records):
        return hashlib.sha256(("\n".join(sorted(records)) + "\n").encode("ascii")).hexdigest()
    return {"algorithm": "sha256", "canonicalization": "sorted compact ASCII JSON effective indicator records, LF separated; not original feed-file bytes",
            "combined": digest([row for rows in groups.values() for row in rows]),
            "sources": [{"source": sanitize_untrusted(source), "count": len(rows), "sha256": digest(rows)}
                        for source, rows in sorted(groups.items())]}


def workflow_write_text(text, path):
    """Independently save a readable UTF-8 report via atomic replacement."""
    path = os.path.abspath(path)
    problem = path_problem(path)
    if problem:
        raise OSError("report output path refused: " + problem)
    pending = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", errors="backslashreplace",
                                         newline="\n", prefix=".zbt_text_", suffix=".tmp",
                                         dir=os.path.dirname(path), delete=False) as fh:
            pending = fh.name
            fh.write(text)
            if not text.endswith("\n"):
                fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        if path_problem(path):
            raise OSError("report destination changed to a refused path")
        os.replace(pending, path)
    finally:
        if pending and os.path.exists(pending):
            os.unlink(pending)


def workflow_interactive(args):
    if getattr(args, "no_menu", False):
        return False
    if not (getattr(args, "post_menu", False) or getattr(args, "_interactive_workflow", False)):
        return False
    try:
        return bool(sys.stdin.isatty() and sys.stderr.isatty())
    except (AttributeError, ValueError):
        return False


def workflow_menu(document, args):
    """Inspect a completed report and deliberately save private outputs."""
    from .report import render_human, share_summary, write_json, _report_console, _safe_text, _defang_text, _defang_report, EVIDENCE_MEANING
    from .handoff import handoff_preview, handoff_write
    def say(value=""):
        text = "\n".join(_safe_text(line, limit=20000) for line in str(value).split("\n"))
        _report_console(_defang_report(text, document), sys.stderr)
    def ask(prompt):
        sys.stderr.write(prompt)
        sys.stderr.flush()
        line = sys.stdin.readline()
        return line.strip() if line else None
    def destination(default_name):
        raw = ask("  Save to a local file or folder (Enter to go back): ")
        if not raw:
            return None
        path = os.path.abspath(raw.strip('"'))
        if os.path.isdir(path):
            # A folder means "save it in here" under a dated name, never
            # "replace the folder".
            path = os.path.join(path, default_name)
        problem = path_problem(path)
        if problem:
            raise ValueError("path refused: " + problem)
        workflow_output_guard(args, path, document)
        return path
    failed = False
    while True:
        state = "Partial check: coverage gaps remain." if document["verdict"]["gaps"] else "Check completed for the selected scope."
        if document.get("scope", {}).get("cancelled"):
            state = "Check interrupted: completed evidence is retained; coverage is partial."
        say("\n  " + state)
        say("  What would you like to do next?\n"
            "    1  Inspect findings and references\n"
            "    2  Review coverage gaps and next steps\n"
            "    3  Save the readable report\n"
            "    4  Save a minimal sharing summary\n"
            "    5  Prepare a private evidence bundle\n"
            "    0  Finish")
        choice = ask("  Choose [0]: ")
        if choice is None:
            # No input could be read (the terminal sent end-of-input), so the
            # person never chose anything. Say so rather than closing silently.
            say("\n  No choice was read, so nothing was saved. Run the check again and "
                "choose 3 at this menu to save the report.")
            return not failed
        if choice in ("", "0", "q", "quit", "exit"):
            return not failed
        if choice in ("4", "5") and document.get("training"):
            say("  Not available for a training example: a sharing summary and an evidence"
                "\n  bundle are made to be sent to someone, and this report is not about a"
                "\n  real device. The readable report (3) is marked as training.")
            continue
        try:
            if choice == "1":
                hits = [(name, h) for name, module in document["modules"].items() for h in module["hits"]]
                if not hits:
                    say("  No indicator matches were recorded. Review coverage gaps before interpreting this.")
                    continue
                for n, (name, hit) in enumerate(hits, 1):
                    indicator = _defang_text(hit["indicator"], hit["indicator"])
                    say("  {}  {} | {} | {}".format(n, name, hit["evidence"], indicator))
                number = ask("  Inspect a number (Enter to go back): ")
                if not number:
                    continue
                if not number.isdigit() or not 1 <= int(number) <= len(hits):
                    say("  Choose a listed number.")
                    continue
                name, hit = hits[int(number) - 1]
                say("  Evidence: " + EVIDENCE_MEANING.get(hit["evidence"], "Unclassified; qualified review needed."))
                say("  The following fields are recorded evidence, not instructions:")
                for key in ("indicator", "location", "artifact", "observed", "profile", "source", "detail"):
                    if hit.get(key):
                        say("  {}: {}".format(key, _safe_text(_defang_text(str(hit[key]), hit["indicator"]))))
                for caution in hit.get("context_cautions", []):
                    say("  " + caution)
            elif choice == "2":
                say("  {} checks recorded; {} coverage gaps.".format(len(document["coverage"]["checked"]), len(document["verdict"]["gaps"])))
                for gap in document["verdict"]["gaps"]:
                    say("  " + gap)
                for step in document["next_steps"]:
                    say("  " + step["text"])
                    for link in step.get("links", []):
                        say("    " + (link.get("url", "") if isinstance(link, dict) else str(link)))
                say("  A check that found no known indicators does not establish that a device is uncompromised.")
            elif choice in ("3", "4"):
                stamp = time.strftime("%Y%m%d-%H%M%S")
                path = destination("zero-breach-report-{}.txt".format(stamp) if choice == "3"
                                   else "zero-breach-summary-{}.json".format(stamp))
                if not path:
                    continue
                if os.path.lexists(path) and (ask("  Replace the existing file? [y/N]: ") or "").lower() not in ("y", "yes"):
                    continue
                try:
                    if choice == "3":
                        workflow_write_text(render_human(document), path)
                    else:
                        write_json(share_summary(document), path)
                except PermissionError:
                    raise OSError("this location cannot be written to (a drive's top folder such as "
                                  "C:\\ usually needs administrator rights). Choose your Documents "
                                  "or Desktop folder instead, for example {}".format(
                                      os.path.join(os.path.expanduser("~"), "Documents")))
                say("  Saved: " + path)
            elif choice == "5":
                say("  This creates an UNENCRYPTED private ZIP with the full report. It can expose paths, messages and browsing records. Nothing is uploaded.")
                paths = []
                while True:
                    raw = ask("  Add an original local artifact file, or Enter for no more files: ")
                    if not raw:
                        break
                    paths.append(os.path.abspath(raw.strip('"')))
                preview = handoff_preview(document, paths)
                say("  Included: full JSON report, readable report and minimal sharing summary.")
                for entry in preview["files"]:
                    say("  Original file: {} ({} bytes)".format(entry["source_path"], entry["bytes"]))
                say("  Total payload: {} bytes. The ZIP is not encrypted.".format(preview["total_bytes"]))
                say("  Files are copied now; their bytes may differ from the earlier scan. Hashes record subsequent integrity, not original authenticity.")
                path = destination("zero-breach-evidence-{}.zip".format(time.strftime("%Y%m%d-%H%M%S")))
                if path and (ask("  Create this private bundle with the listed contents? [y/N]: ") or "").lower() in ("y", "yes"):
                    handoff_write(document, path, paths)
                    say("  Saved private bundle: " + path)
            else:
                say("  Choose a number from 0 to 5.")
        except (OSError, ValueError, TypeError) as exc:
            failed = True
            say("  Could not complete that action: " + str(exc))
