"""Build a single-file, self-contained copy of the scanner.

One .py file someone can be emailed, read, and run. It embeds the indicator data
so there is no second indicator file to lose. Scans read source evidence, use
local temporary copies and write requested reports. Indicator updates and guided
phone acquisition are explicit, separate commands.

The only transformation applied to the module sources is renaming the two names
that collide across the three scan modules (NAME and run), plus dropping the
package-internal imports, since everything lands in one namespace.
"""
import io
import ast
import os
import re
import sys
import time

# Defaults assume this file sits in <root>/build/. Both can still be overridden
# on the command line, which is how the one-off test builds were made.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = sys.argv[1] if len(sys.argv) > 1 else ROOT
OUT = (sys.argv[2] if len(sys.argv) > 2
       else os.path.join(SRC, "dist", "zero-breach-toolkit.py"))

PKG = os.path.join(SRC, "scan", "zbtriage")
import importlib.util
_build_reader_spec = importlib.util.spec_from_file_location("_build_readers", os.path.join(PKG, "readers.py"))
_build_readers = importlib.util.module_from_spec(_build_reader_spec)
sys.modules[_build_reader_spec.name] = _build_readers
_build_reader_spec.loader.exec_module(_build_readers)
_build_readers.reader_validate()
IOC = os.path.join(SRC, "iocs", "adfection_iocs.txt")
IOC2 = os.path.join(SRC, "iocs", "curated_mercenary.txt")

# Single source of truth for the version. Read it from the package rather than
# repeating it here: the two silently drifted once and the download shipped
# reporting the wrong version (it said 0.1.6 while it was v0.1.7). Derive it, so
# that can never happen again.
def _package_version():
    init = io.open(os.path.join(PKG, "__init__.py"), encoding="utf-8").read()
    m = re.search(r'__version__\s*=\s*"([^"]+)"', init)
    if not m:
        raise SystemExit("bundle: could not read __version__ from the package")
    return m.group(1)


VERSION = _package_version()


def read(path):
    return io.open(path, encoding="utf-8").read()


def strip_imports(text):
    """Remove package-internal imports and __future__ (re-emitted once at top).

    Handles a parenthesised multi-line import,
        from .result import (A, B,
                             C, D)
    by consuming lines until the parentheses balance. Dropping only the first
    line of such a statement would leave its continuation lines behind as stray
    indented text - a syntax error in the bundled file.
    """
    out = []
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        s = line.strip()
        is_future = s.startswith("from __future__")
        is_local = bool(re.match(r"^from \.+[A-Za-z_. ]* import ", s)
                        or re.match(r"^from \.+ import ", s))
        if is_future or is_local:
            # If the import opens a parenthesis that does not close on this line,
            # skip the whole continuation.
            depth = line.count("(") - line.count(")")
            i += 1
            while depth > 0 and i < len(lines):
                depth += lines[i].count("(") - lines[i].count(")")
                i += 1
            continue
        out.append(line)
        i += 1
    return "\n".join(out)


def namespace(text, suffix):
    """Rename source identifiers using AST byte offsets, never literal text.

    F-string expression locations differ between supported Python versions.
    Reject colliding names there explicitly rather than producing a bad bundle.
    """
    tree = ast.parse(text)
    renames = {"NAME": "NAME_" + suffix.upper(), "run": "run_" + suffix}
    # This transform supports a module constant and entry point, not arbitrary
    # lexical scope rewriting. Refuse colliding bindings we cannot preserve.
    parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    for node in ast.walk(tree):
        if isinstance(node, ast.JoinedStr) and any(
                isinstance(child, ast.Name) and child.id in renames
                for child in ast.walk(node)):
            raise ValueError("bundle: NAME/run inside f-string expressions is unsupported; use .format()")
        if isinstance(node, (ast.Global, ast.Nonlocal)) and set(node.names) & renames.keys():
            raise ValueError("bundle: global/nonlocal NAME/run declarations are unsupported")
        if isinstance(node, ast.ExceptHandler) and node.name in renames:
            raise ValueError("bundle: NAME/run exception bindings are unsupported")
        if isinstance(node, ast.ClassDef) and node.name in renames:
            raise ValueError("bundle: NAME/run class bindings are unsupported")
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in renames:
            if node.name != "run" or parents.get(node) is not tree:
                raise ValueError("bundle: NAME/run nested functions and methods are unsupported")
        if isinstance(node, ast.Name) and node.id in renames and not isinstance(node.ctx, ast.Load):
            parent = parents.get(node)
            if not (node.id == "NAME" and isinstance(parent, (ast.Assign, ast.AnnAssign))
                    and parents.get(parent) is tree):
                raise ValueError("bundle: NAME/run bindings outside the module constant are unsupported")
        if type(node).__name__ in ("MatchAs", "MatchStar", "MatchMapping"):
            if getattr(node, "name", None) in renames or getattr(node, "rest", None) in renames:
                raise ValueError("bundle: NAME/run pattern bindings are unsupported")
    raw = text.encode("utf-8")
    offsets = [0]
    for line in raw.split(b"\n"):
        offsets.append(offsets[-1] + len(line) + 1)
    edits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in renames:
            start = offsets[node.lineno - 1] + node.col_offset
            end = offsets[node.end_lineno - 1] + node.end_col_offset
            edits.append((start, end, renames[node.id].encode("ascii")))
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "run":
            start = offsets[node.lineno - 1] + node.col_offset
            match = re.match(rb"(?:async\s+)?def\s+(run)\b", raw[start:])
            if match is None:
                raise ValueError("bundle: could not locate run declaration")
            edits.append((start + match.start(1), start + match.end(1), renames["run"].encode("ascii")))
        elif isinstance(node, ast.arg) and node.arg in renames:
            raise ValueError("bundle: NAME/run parameter bindings are unsupported")
        elif isinstance(node, ast.alias) and (node.asname or node.name.split('.')[0]) in renames:
            raise ValueError("bundle: NAME/run import bindings are unsupported")
    for start, end, replacement in sorted(edits, reverse=True):
        raw = raw[:start] + replacement + raw[end:]
    return raw.decode("utf-8")


parts = []
A = parts.append

ioc_text = read(IOC)


def _asof_epoch(text):
    """The '# as-of: YYYY-MM-DD' date from the IOC header, as a UTC epoch.

    Using the committed date instead of os.path.getmtime makes the build
    REPRODUCIBLE: git does not preserve file modification times across a clone,
    so stamping the mtime meant a fresh checkout rebuilt to a different file and
    'rebuild from source and compare' - the whole point of an auditable security
    tool - would fail. The date is content, so every checkout agrees on it.
    """
    import datetime as _dt
    import re as _re
    m = _re.search(r"^#\s*as-of:\s*(\d{4})-(\d{2})-(\d{2})\s*$", text, _re.M)
    if not m:
        raise SystemExit("iocs file is missing a '# as-of: YYYY-MM-DD' line; "
                         "the reproducible build needs it")
    y, mo, d = (int(g) for g in m.groups())
    return _dt.datetime(y, mo, d, tzinfo=_dt.timezone.utc).timestamp()


ioc_mtime = _asof_epoch(ioc_text)

A('#!/usr/bin/env python3')
A('# -*- coding: utf-8 -*-')
A('"""Zero Breach (single-file build) - local check for published AdFection /')
A('Candiru spyware indicators.')
A('')
A('WHAT THIS IS')
A('  A read-only checker. It searches this computer\'s own leftover records -')
A('  browser cache and cookies, file fingerprints, auto-start registrations, the')
A('  DNS resolver cache - for {} indicators published by The Citizen Lab,'.format(
    len([l for l in ioc_text.split("\n")
         if l.strip() and not l.strip().startswith("#")])))
A('  Confiant, Recorded Future, Microsoft, ESET, Avast / Gen, Google TAG and')
A('  Amnesty Security Lab. The original citations are embedded.')
A('')
A('WHAT AN OFFLINE SCAN WILL NOT DO')
A('  - It does not change source files, registry entries or system settings.')
A('    It writes temporary database snapshots and embedded indicator data,')
A('    removes those after use, and retains a report only when requested.')
A('  - It makes no intentional network requests or indicator lookups. Redirected')
A('    paths and Windows remote drives are skipped; POSIX network mounts can')
A('    appear local and may be read. Authenticode checks are disabled.')
A('    Python network calls are blocked during the scan. This guard is not an')
A('    operating-system network sandbox.')
A('  - It does not decrypt credentials. Cookie queries select metadata, not')
A('    cookie values; temporary snapshots copy the entire source database.')
A('')
A('IMPORTANT - WHAT A CLEAN RESULT MEANS')
A('  "No known indicators found" means exactly that, and nothing more. It is not')
A('  a clean bill of health. Spyware of this grade is built to defeat this class')
A('  of check, most of the evidence it would leave expires within weeks, and')
A('  Windows does not record DNS history unless someone turned it on. If you have')
A('  real reason for concern, the answer is expert help, not this script:')
A('    Access Now Digital Security Helpline  https://www.accessnow.org/help/')
A('    Amnesty International Security Lab    https://securitylab.amnesty.org/')
A('    The Citizen Lab                       https://citizenlab.ca/')
A('')
A('LICENCE')
A('  Software: Apache License 2.0. Indicator data: CC0 1.0 (public domain).')
A('  Optional Candiru rules retain their separate DRL 1.1 / CC BY-SA 4.0')
A('  licences and author credits, embedded below with their provenance.')
A('  Copyright 2026 archivegenocide.com. Provided AS IS, without warranty.')
A('  Full text, and the sources every indicator came from:')
A('    https://github.com/interplains/Zero-Breach-Toolkit')
A('  NOT affiliated with, and NOT endorsed by, The Citizen Lab, Confiant,')
A('  Recorded Future, Amnesty International or Access Now.')
A('')
A('USAGE')
A('  python -X utf8 zero-breach-toolkit.py')
A('  python -X utf8 zero-breach-toolkit.py --json report.json')
A('  python -X utf8 zero-breach-toolkit.py --patterns   # optional YARA-X setup required')
A('')
A('Requires Python 3.8 or newer. Needs no administrator. All supported platforms')
A('get browser and file checks; Windows also gets host checks.')
A('Experimental --patterns also requires Python 3.9+ and yara-x==1.21.0.')
A('"""')
A('from __future__ import annotations')
A('')
A('import argparse')
A('import datetime')
A('import sys')
A('import time')
A('')
# A packaged program (PyInstaller sets sys.frozen) says so in every report.
A('__version__ = "{} (" + ("program build" if getattr(sys, "frozen", False) else "single-file build") + ")"'.format(VERSION))
A('')
A('# --- embedded indicator data ------------------------------------------------')
A('# The real file is iocs/adfection_iocs.txt in the project. Its provenance')
A('# comments are kept verbatim so every indicator can be traced to its report.')
A('IOC_BUILD_EPOCH = {!r}  # the IOC set\'s "as-of" date (deterministic)'.format(
    ioc_mtime))
def _embeddable(text, label):
    """Indicator text goes inside r'''...''' in the single file. Two quotes in a row
    or a backslash could end that string early and turn data into code, so such
    text is refused rather than escaped."""
    if "''" in text or "\\" in text:
        raise SystemExit("refusing to embed {}: it contains '' or a backslash".format(label))
    return text


A("IOC_DATA = r'''")
A(_embeddable(ioc_text, "the indicator file"))
A("'''")
A('# The hand-curated mercenary-vendor set (iocs/curated_mercenary.txt), e.g. Paragon.')
A("IOC_DATA_2 = r'''")
A(_embeddable(read(IOC2), "the curated indicator file"))
A("'''")
A('')

for label, fname in (("result", "result.py"),
                     ("iocs", "iocs.py"),
                     ("stix", "stix.py"),
                     ("netguard", "netguard.py"),
                     ("localpaths", "localpaths.py"),
                     ("feeds", "feeds.py"),
                     ("heuristics", "heuristics.py"),
                     ("context", "context.py"),
                     ("scope", "scope.py"),
                     ("phoneguide", "phoneguide.py"),
                     ("aes", "aes.py"),
                     ("backupcrypto", "backupcrypto.py"),
                     ("candiru_rules", "candiru_rules.py"),
                     ("banner", "banner.py"),
                     ("menu", "menu.py"),
                     ("training", "training.py"),
                     ("readers", "readers.py"),
                     ("contract", "contract.py"),
                     ("evidence", "evidence.py"),
                     ("report", "report.py"),
                     ("workflow", "workflow.py"),
                     ("handoff", "handoff.py"),
                     ("shelllinks", "shelllinks.py")):
    A('# --- {} {}'.format(label, '-' * max(0, 72 - len(label))))
    A(strip_imports(read(os.path.join(PKG, fname))))
    A('')

_build_reader_helpers = dict.fromkeys(helper for spec in _build_readers.READER_SPECS for helper in spec.helpers)
for fname in _build_reader_helpers:
    A('# --- reader helper: ' + fname)
    A(strip_imports(read(os.path.join(PKG, fname))))
    A('')

for _build_reader in _build_readers.READER_SPECS:
    fname, suffix = _build_reader.module + ".py", _build_reader.suffix
    label = "modules/" + _build_reader.module
    A('# --- {} {}'.format(label, '-' * max(0, 72 - len(label))))
    if suffix == "patterns":
        A('_pattern_roots = _roots  # hash module default local roots')
    A(namespace(strip_imports(read(os.path.join(PKG, "modules", fname))), suffix))
    A('')

A('# --- entry point ------------------------------------------------------------')
A('''

def _load_embedded_iocs(path=None):
    """Parse the embedded indicator data, or an external file if one is given."""
    if path:
        return load(path)
    import tempfile
    tmp = tempfile.mkdtemp(prefix="adint_ioc_", dir=local_temp_dir())
    try:
        p = os.path.join(tmp, "adfection_iocs.txt")
        with io.open(p, "w", encoding="utf-8", newline="\\n") as fh:
            fh.write(IOC_DATA)
        ioc_set = load(p)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    # Report the age of the DATA, not of the temp file we just wrote, so the
    # staleness warning stays truthful in a single-file build.
    ioc_set.source_mtime = IOC_BUILD_EPOCH
    ioc_set.source_path = "(embedded in this script)"
    tmp2 = tempfile.mkdtemp(prefix="zbt_ioc2_", dir=local_temp_dir())
    try:
        p2 = os.path.join(tmp2, "curated_mercenary.txt")
        with io.open(p2, "w", encoding="utf-8", newline="\\n") as fh:
            fh.write(IOC_DATA_2)
        second = load(p2)
    finally:
        shutil.rmtree(tmp2, ignore_errors=True)
    second.source_mtime = IOC_BUILD_EPOCH
    second.source_path = "(embedded in this script)"
    return merge([ioc_set, second])


def _hold(args):
    """Keep the window open when this was double-clicked.

    Double-clicking a .py in Explorer opens a console that closes the instant
    the script ends - so the entire report would flash past unread, which is the
    most likely way a non-technical person runs this. Pausing costs a keypress
    for anyone running it from a terminal, and saves the report for everyone else.
    """
    if (getattr(args, "no_pause", False) or not sys.stdout.isatty()
            or getattr(args, "_interactive_workflow", False) or getattr(args, "post_menu", False)):
        return
    try:
        input("\\nPress Enter to close this window...")
    except (EOFError, KeyboardInterrupt):
        pass


def _force_utf8_io():
    """Make stdout/stderr encode UTF-8 whatever the console code page is. On a
    stock Windows Python these default to cp1252, and printing a non-Latin
    profile name or username - Arabic, Hebrew, Persian, Cyrillic, CJK, i.e. this
    tool's users - then crashes with UnicodeEncodeError instead of producing a
    report, worst of all while writing the report file after the work is done.
    This makes the fix independent of the caller remembering `python -X utf8`."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass


def _bundle_main(argv=None):
    _force_utf8_io()
    p = WorkflowParser(
        prog="zero-breach-toolkit",
        description="Read-only check for known mercenary spyware "
                    "indicators. A clean result is NOT a clean bill of health.")
    p.add_argument("--json", metavar="PATH",
                   help="also write a machine-readable report to PATH")
    p.add_argument("--share-json", metavar="PATH",
                   help="write a minimal sharing summary without artifact text or indicator values")
    p.add_argument("--iocs", metavar="PATH", action="append", default=None,
                   help="use external indicator file(s) instead of the embedded "
                        "one; repeat to combine. Accepts the curated format and "
                        "STIX 2 bundles (.stix2 / .json)")
    p.add_argument("--version", action="version",
                   version="Zero Breach Toolkit " + __version__)
    p.add_argument("--quick", action="store_true",
                   help="skip candidate-file fingerprinting (roughly halves the "
                        "runtime). The skipped check is reported as a gap, not "
                        "as clean.")
    p.add_argument("--update", action="store_true",
                   help="download or refresh the published indicator sets into this "
                        "user's cache, then exit (separate from offline scanning)")
    p.add_argument("--indicator-cache", metavar="DIR", default=None,
                   help="where downloaded indicator sets are kept")
    p.add_argument("--accept-shrink", metavar="SOURCE_ID", action="append", default=[],
                   help="with --update: accept a source whose indicator count fell by more "
                        "than half (normally refused, keeping the previous copy)")
    p.add_argument("--latest", action="store_true",
                   help="with --update: download each source's newest upstream version "
                        "instead of the copy pinned and checked for this release; when "
                        "scanning: use lists downloaded that way (otherwise only the "
                        "pinned copies are used)")
    p.add_argument("--no-feeds", action="store_true",
                   help="scan with the embedded indicator set only")
    p.add_argument("--phone", metavar="FOLDER",
                   help="check an AndroidQF collection folder or local iPhone backup instead of this computer")
    p.add_argument("--describe", action="store_true",
                   help="print, as JSON, what this tool checks and the rules for "
                        "relaying a result, then exit without scanning")
    p.add_argument("--no-pause", action="store_true",
                   help="do not wait for a keypress before exiting")
    p.add_argument("--patterns", action="store_true",
                   help="experimental local Candiru file-pattern check; needs "
                        "Python 3.9+ and yara-x==1.21.0; no memory scan")
    p.add_argument("--pattern-path", action="append", default=[], metavar="PATH",
                   help="file or folder for --patterns (repeatable). Limits only "
                        "the pattern check, not the other checks")
    p.add_argument("--no-banner", action="store_true",
                   help="do not show the welcome banner")
    p.add_argument("--no-menu", action="store_true",
                   help="run the standard check straight away instead of showing the "
                        "start menu (the menu only appears for a person at a terminal "
                        "who has not chosen a check on the command line)")
    scope_arguments(p)
    workflow_arguments(p)
    training_arguments(p)
    raw = sys.argv[1:] if argv is None else argv
    args = p.parse_args(raw)
    scope_validate(p, args)
    workflow_validate(p, args)
    training_validate(p, args)
    if args.pattern_path and not args.patterns:
        p.error("--pattern-path requires --patterns")
    if args.share_json and args.update:
        p.error("--share-json is for scan summaries, not --update")
    if args.share_json and args.json and os.path.normcase(os.path.abspath(args.share_json)) == os.path.normcase(os.path.abspath(args.json)):
        p.error("--share-json and --json must name different files")
    if args.phone_guide:
        print(scope_guide(args.phone_guide))
        return 0
    if args.preview:
        try:
            print(json.dumps(scope_preview(args), indent=2, ensure_ascii=False))
            return 0
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 1
    if args.describe:
        print(json.dumps(describe_document(), indent=2, ensure_ascii=False))
        return 0
    if not args.no_banner:
        show_banner(__version__)
    if args.indicator_cache and path_problem(os.path.abspath(args.indicator_cache)):
        print("error: --indicator-cache must be a folder on a local disk", file=sys.stderr)
        _hold(args)
        return 1
    # Same start menu as the source CLI, for a person who double-clicked this
    # file. Never shown to scripts or when a check was chosen on the command line.
    if menu_wanted(raw, args) and not choose_scan(
            args, lambda: update_command(args.indicator_cache, None)):
        return EXIT_NOT_SCANNED
    # --training (or the menu's practice entry): a made-up phone and made-up
    # indicators, deleted by main() when the tool exits.
    training_prepare(args)
    try:
        workflow_check_outputs(args)
    except (OSError, ValueError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 1
    if args.update:
        if args.json and path_problem(os.path.abspath(args.json)):
            print("error: --json must be a path on a local disk", file=sys.stderr)
            _hold(args)
            return 1
        code = update_command(args.indicator_cache, args.json, args.accept_shrink, args.latest)
        _hold(args)
        return code

    if sys.version_info < (3, 8):
        print("This needs Python 3.8 or newer; this is {}.{}.".format(
            *sys.version_info[:2]), file=sys.stderr)
        _hold(args)
        return 1

    # Refuse a user-typed --iocs/--json path that is not on a local disk.
    # Opening or creating a UNC path or mapped network drive makes Windows open
    # an SMB session to that host - sending this account's network credentials
    # and, for --json, the whole report. Checked before anything is opened and
    # before the scan rather than after it. This entry point is separate from
    # the source CLI, so the guard has to live here too. abspath first, because
    # path_problem refuses relative paths and "--json report.json" is the
    # documented usage.
    for label, value in ([("--iocs", v) for v in (args.iocs or [])]
                         + [("--json", args.json), ("--share-json", args.share_json), ("--phone", args.phone)]):
        if value:
            problem = path_problem(os.path.abspath(value))
            if problem:
                print("error: {} {}: {} - use a path on a local disk".format(
                    label, value, problem), file=sys.stderr)
                _hold(args)
                return 1

    if args.collect_android:
        folder, code = collect_android(args.collect_android, args.age_recipient_file)
        if not folder:
            return code
        args.phone = folder
        try:
            workflow_check_outputs(args)
        except (OSError, ValueError) as exc:
            print("error: {}".format(exc), file=sys.stderr)
            return 1
    try:
        if args.iocs:
            ioc_set = merge([load_any(v, allow_empty=len(args.iocs) > 1)
                             for v in args.iocs])
            ioc_set.feeds = {"used": False, "reason": "--iocs given"}
        elif args.no_feeds:
            ioc_set = _load_embedded_iocs()
            ioc_set.feeds = {"used": False, "reason": "--no-feeds"}
        else:
            cached, feed_status = cached_sets(args.indicator_cache, args.latest)
            feed_status["used"] = True
            ioc_set = merge([_load_embedded_iocs()] + cached)
            ioc_set.feeds = feed_status
    except IocError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        _hold(args)
        return 1

    password = ""
    if args.backup_password:
        import getpass
        if not sys.stdin.isatty():
            print("error: backup password requires a private interactive terminal", file=sys.stderr)
            return 1
        password = getpass.getpass("Backup password (not saved): ")
    workflow_before_scan(args, ioc_set)
    ctx = ScanContext(iocs=ioc_set, quick=args.quick, patterns=args.patterns,
                      full=args.scan_type == "full", browser_only=args.scan_type == "browser",
                      targets=tuple(os.path.abspath(p) for p in args.target),
                      backup_password=password, extended_windows=args.extended_windows, ios_input=args.ios_input,
                      pattern_paths=tuple(args.pattern_path), phone_path=args.phone or "")
    started = datetime.datetime.now()
    results = ctx.completed
    # The whole scan runs inside the no-network guard (see the header).
    with scan_recovery(ctx), no_network():
        reader_run(ctx, lambda spec: globals()["run_" + spec.suffix])

    ctx.backup_password = password = ""
    code = finalize_report(ioc_set, results, started, args, ctx.cancelled)
    _hold(args)
    return code


def main(argv=None):
    try:
        return _bundle_main(argv)
    except KeyboardInterrupt:
        print("Stopped by user. Any completed report already saved remains on disk.", file=sys.stderr)
        return 1
    finally:
        training_cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
''')

text = "\n".join(parts)
io.open(OUT, "w", encoding="utf-8", newline="\n").write(text)
print("wrote {} ({:,} bytes, {:,} lines)".format(
    OUT, len(text.encode("utf-8")), text.count("\n") + 1))
