"""Command-line entry point and orchestration.

  zero-breach-toolkit [--quick] [--json <path>] [--share-json <path>] [--iocs <path>]

Default behaviour (no flags): read-only tier-1 IOC match across the browser, hash
and host modules, under the no-network guard. Requires no administrator (D7).

There is no system-writing mode. An earlier tier-5 feature (--arm / --undo) was
removed: a review found its --undo path could, from a journal file any program can
write, delete every scheduled task on the machine and still report success, and
could shrink the DNS log and destroy the history it had collected. None of that is
acceptable in a tool at-risk people run, and the one thing it was for - turning on
DNS history - is a single manual command the report already prints. The code is
gone rather than merely unwired, so a reviewer reading this read-only tool finds
no system-reconfiguration path. The separate --collect-android command runs an
external acquisition tool only after explicit owner consent.

Exit codes: 0 = no actionable matches or recorded gaps; 2 = actionable matches;
3 = no actionable matches but incomplete coverage; 1 = setup/output error.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
import time
from typing import List

from .i18n import I18N_CODES, i18n_set
from . import __version__
from .context import ScanContext, scan_recovery
from .iocs import IocError, load_any, merge
from .localpaths import path_problem
from .netguard import no_network
from . import feeds
from .contract import contract_exit_code, EXIT_NOT_SCANNED
from .report import V_HITS, build_document, describe_document, render_human, write_json, share_summary, finalize_report
from .result import ModuleResult
from .banner import show_banner
from .menu import menu_wanted, choose_scan
from .scope import SCOPE_BUGREPORT_GUIDE, scope_arguments, scope_validate, scope_preview, scope_guide
from .workflow import (WorkflowParser, workflow_arguments, workflow_validate,
                       workflow_check_outputs, workflow_before_scan, gui_wanted)
from .training import (training_arguments, training_validate, training_prepare,
                       training_cleanup)


def _force_utf8_io() -> None:
    """Make stdout/stderr encode UTF-8 regardless of the console code page.

    On a stock Windows Python the streams default to the legacy code page (cp1252
    in much of the world). Printing a non-Latin browser-profile name or username -
    Arabic, Hebrew, Persian, Cyrillic, CJK, i.e. exactly this tool's users - then
    raises UnicodeEncodeError and the whole scan dies with a traceback instead of
    a report, and worst of all when writing the report file AFTER the work is
    done. Reconfiguring here fixes it without depending on the caller remembering
    `-X utf8`. errors='backslashreplace' guarantees output can never crash."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError):
            pass  # very old Python, or a stream that is not reconfigurable


def _default_ioc_path() -> str:
    # scan/zbtriage/cli.py -> repo root is two levels up; IOCs live in iocs/.
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(os.path.dirname(here))
    return os.path.join(repo, "iocs", "adfection_iocs.txt")


def _default_ioc_paths() -> List[str]:
    """The curated files shipped with the tool: Zero Breach's AdFection/Candiru
    set, the hand-curated mercenary-vendor set (e.g. Paragon Graphite) and the
    set of spyware used against journalists, activists and minorities."""
    here = os.path.dirname(os.path.abspath(__file__))
    repo = os.path.dirname(os.path.dirname(here))
    return [_default_ioc_path(), os.path.join(repo, "iocs", "curated_mercenary.txt"),
            os.path.join(repo, "iocs", "curated_targeted.txt")]


def _parse(argv: List[str]) -> argparse.Namespace:
    p = WorkflowParser(
        prog="zero-breach-toolkit",
        description="Local, read-only check for known mercenary spyware indicators. "
                    "A clean result is NOT a clean bill of health.")
    p.add_argument("--quick", action="store_true",
                   help="skip candidate-file fingerprinting (roughly halves the "
                        "runtime). The skipped check is reported as a gap, not "
                        "as clean.")
    p.add_argument("--deep", action="store_true",
                   help=argparse.SUPPRESS)
    p.add_argument("--patterns", action="store_true",
                   help="experimental local Candiru file-pattern check; needs "
                        "the separately installed, pinned YARA-X dependency. "
                        "Does not inspect running memory.")
    p.add_argument("--pattern-path", action="append", default=[], metavar="PATH",
                   help="file or folder for --patterns (repeatable). Limits only "
                        "the pattern check; browser, hash and host checks keep "
                        "their usual scope.")
    p.add_argument("--json", metavar="PATH",
                   help="also write the machine-readable report to PATH.")
    p.add_argument("--share-json", metavar="PATH",
                   help="write a minimal sharing summary without paths, profiles, "
                        "message contents, timestamps or indicator values")
    p.add_argument("--iocs", metavar="PATH", action="append", default=None,
                   help="indicator file; repeat --iocs to combine several. Accepts the "
                        "curated tab-separated file and STIX 2 bundles "
                        "(.stix2 / .json) as published by Amnesty, the MVT "
                        "project and others. Default: the bundled set.")
    p.add_argument("--update", action="store_true",
                   help="download or refresh the published indicator sets (Amnesty, "
                        "the MVT project, Echap) into this user's cache, then exit. "
                        "Downloads use the network; offline scans never do.")
    p.add_argument("--indicator-cache", metavar="DIR", default=None,
                   help="where downloaded indicator sets are kept (default: a "
                        "per-user cache folder)")
    p.add_argument("--accept-shrink", metavar="SOURCE_ID", action="append", default=[],
                   help="with --update: accept a source whose indicator count fell by more "
                        "than half (normally refused, keeping the previous copy)")
    p.add_argument("--latest", action="store_true",
                   help="with --update: download each source's newest upstream version "
                        "instead of the copy pinned and checked for this release; when "
                        "scanning: use lists downloaded that way (otherwise only the "
                        "pinned copies are used)")
    p.add_argument("--no-version-check", action="store_true",
                   help="with --update (and the update in the menu or window): do not ask "
                        "GitHub whether a newer release exists")
    p.add_argument("--no-feeds", action="store_true",
                   help="scan with the built-in indicator set only, ignoring "
                        "downloaded sets")
    p.add_argument("--phone", metavar="FOLDER",
                   help="check an AndroidQF collection folder, an Android bug report (.zip made on the phone) "
                        "or a local iPhone backup instead of this computer")
    p.add_argument("--describe", action="store_true",
                   help="print, as JSON, every check this tool runs, what each reads and "
                        "cannot see, the exit codes and the rules for relaying a "
                        "result; then exit without scanning (for scripts and AI "
                        "assistants)")
    p.add_argument("--lang", metavar="CODE", default=None, choices=I18N_CODES,
                   help="report and window language: " + ", ".join(I18N_CODES) + ". The terminal report is English unless this is given; the window follows the computer's language. The JSON report and the sharing summary are always English")
    p.add_argument("--no-banner", action="store_true",
                   help="do not show the welcome banner (it is only ever shown to a "
                        "person at a terminal, never in redirected output)")
    p.add_argument("--no-menu", action="store_true",
                   help="run the standard check straight away instead of showing the "
                        "start menu (the menu only appears for a person at a terminal "
                        "who has not chosen a check on the command line)")
    p.add_argument("--version", action="version",
                   version="Zero Breach Toolkit {}".format(__version__))
    scope_arguments(p)
    workflow_arguments(p)
    training_arguments(p)
    args = p.parse_args(argv)
    scope_validate(p, args)
    workflow_validate(p, args)
    training_validate(p, args)
    args.iocs_explicit = bool(args.iocs)
    if not args.iocs:
        args.iocs = _default_ioc_paths()
    if args.pattern_path and not args.patterns:
        p.error("--pattern-path requires --patterns")
    if args.share_json and args.update:
        p.error("--share-json is for scan summaries, not --update")
    if args.share_json and args.json and os.path.normcase(os.path.abspath(args.share_json)) == os.path.normcase(os.path.abspath(args.json)):
        p.error("--share-json and --json must name different files")
    return args


def _run_modules(ctx: ScanContext) -> List[ModuleResult]:
    from .readers import reader_run
    return reader_run(ctx)


def _refuse_remote(label: str, value: str) -> bool:
    """Refuse a user-typed path that is not on a local disk.

    --iocs and --json are paths people type, often copied from an instruction
    somebody else wrote ("run it against our updated list at ..."). Opening or
    creating a UNC path or a mapped network drive makes Windows itself open an
    SMB session to that host - sending this account's network credentials and,
    for --json, the complete report. The socket guard cannot see that. Every
    other path the scanner opens is already checked this way; these two were
    the gap. abspath first: path_problem refuses relative paths outright, and
    "--json report.json" is the documented usage."""
    problem = path_problem(os.path.abspath(value))
    if problem:
        print("error: {} {}: {} - use a path on a local disk".format(
            label, value, problem), file=sys.stderr)
        return True
    return False


def _load_iocs(args):
    """The indicator set a scan uses: the built-in lists plus any downloaded,
    verified sources (or only --iocs files when given)."""
    many = len(args.iocs) > 1
    sets = [load_any(path, allow_empty=many) for path in args.iocs]
    if args.iocs_explicit:
        feed_status = {"used": False, "reason": "--iocs given"}
    elif args.no_feeds:
        # Downloaded sets are ignored, but the lists built into this release still count as built in.
        built, status = feeds.builtin_sets()
        sets += built
        feed_status = {"used": False, "reason": "--no-feeds", "loaded": status["loaded"],
                       "refused": status["refused"]}
    else:
        cached, feed_status = feeds.cached_sets(args.indicator_cache, args.latest)
        feed_status["used"] = True
        sets += cached
    iocs = merge(sets)
    iocs.feeds = feed_status
    return iocs


def _gui_hooks(version_check=True):
    def run_readers(ctx):
        ctx.completed = _run_modules(ctx)
    return {"parse": _parse, "load_iocs": _load_iocs, "run_readers": run_readers,
            "update": lambda: feeds.update_command(None, None, version_check=version_check),
            "version": __version__}


def _run_update(args) -> int:
    """--update: an explicit network step, never part of a scan."""
    return feeds.update_command(args.indicator_cache, args.json, args.accept_shrink, args.latest,
                                version_check=not args.no_version_check)


def _main(argv: List[str] = None) -> int:
    _force_utf8_io()
    raw = sys.argv[1:] if argv is None else argv
    # A file dropped onto the program (or passed as its only argument) is a file to check. The packaged program
    # opens the window on it; without a window, or from Python, it is checked in the terminal.
    if len(raw) == 1 and not raw[0].startswith("-") and os.path.isfile(raw[0]):
        dropped = os.path.abspath(raw[0])
        if getattr(sys, "frozen", False):
            from .gui import gui_main
            code = gui_main(dict(_gui_hooks(), open_file=dropped))
            if code is not None:
                return code
        raw = ["--check-file", dropped]
    args = _parse(raw)
    if args.check_file:
        from .filecheck import fc_command
        return fc_command(args, _load_iocs)
    if args.accounts or args.threat_warning:
        from .accounts import ac_command
        return ac_command(args)
    if args.combine:
        from .household import combine_command
        return combine_command(args)
    if args.home_network:
        from .homenet import homenet_command
        return homenet_command(args)
    if args.trackers is not None:
        from .trackers import trackers_command
        return trackers_command(args)
    if getattr(args, "wifi_nearby", False):
        from .wifinearby import wifi_nearby_command
        return wifi_nearby_command(args)
    if args.check_link or args.check_message:
        from .linkcheck import lc_command
        return lc_command(args, _load_iocs)
    if args.check_traffic:
        from .netcapture import nc_command
        return nc_command(args, _load_iocs)
    if args.startup:
        from .startup import su_command
        return su_command(args, _load_iocs)
    if args.package_for_helper or args.verify_package:
        from .helperpack import hp_command
        return hp_command(args)
    if args.hash_lookup or args.set_lookup_key:
        from .hashlook import hl_command
        return hl_command(args, _load_iocs)
    if args.hunt_windows is not None:
        from .huntwin import hw_command
        return hw_command(args, _load_iocs)
    if args.was_extracted:
        from .extracted import ex_command
        return ex_command(args, _load_iocs)
    if args.check_email:
        from .mailcheck import mc_command
        return mc_command(args, _load_iocs)
    if args.check_qr:
        from .qrcheck import qr_command
        return qr_command(args, _load_iocs)
    if args.fix_it is not None or args.undo_fix:
        from .fixit import fx_ask_terminal, fx_command
        return fx_command(args, ask=fx_ask_terminal)
    if args.phone_guide:
        print(scope_guide(args.phone_guide))
        if args.phone_guide == "android":
            print(SCOPE_BUGREPORT_GUIDE)
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
    if args.lang:
        i18n_set(args.lang)
    if gui_wanted(raw, args):
        from .gui import gui_main
        code = gui_main(dict(_gui_hooks(not args.no_version_check), lang=args.lang))
        if code is not None:
            return code
    if not args.no_banner:
        show_banner(__version__)
    if args.indicator_cache and _refuse_remote("--indicator-cache", args.indicator_cache):
        return 1
    # A person who opened the tool without saying what to check chooses from
    # the start menu. Scripts, AI assistants and explicit command lines never
    # see it (menu_wanted). The menu's update step never writes the scan's
    # --json file: that path is for the report of the check chosen next.
    if menu_wanted(raw, args) and not choose_scan(
            args, lambda: feeds.update_command(args.indicator_cache, None,
                                               version_check=not args.no_version_check),
            load_iocs=_load_iocs):
        return EXIT_NOT_SCANNED
    # --training (or the menu's practice entry) swaps in a made-up phone and
    # made-up indicators; main() deletes them when the tool exits.
    training_prepare(args)
    try:
        workflow_check_outputs(args)
    except (OSError, ValueError) as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 1
    if args.json and _refuse_remote("--json", args.json):
        return 1
    if args.share_json and _refuse_remote("--share-json", args.share_json):
        return 1
    if args.update:
        return _run_update(args)

    # Checked before anything is opened, and before a 15-minute scan rather than
    # after it. The bundled default is never attacker-chosen, so only a path the
    # user supplied is checked.
    for path in args.iocs:
        if path not in _default_ioc_paths() and _refuse_remote("--iocs", path):
            return 1
    if args.phone and _refuse_remote("--phone", args.phone):
        return 1
    for path in args.dns_log:
        if _refuse_remote("--dns-log", path):
            return 1

    made_password = ""
    if args.make_iphone_backup:
        from .iphonehelper import make_iphone_backup
        folder, made_password, code = make_iphone_backup(args.make_iphone_backup)
        if not folder:
            return code
        args.phone = folder
        args.backup_password = not made_password      # encryption was already on: ask for its existing password
        try:
            workflow_check_outputs(args)
        except (OSError, ValueError) as exc:
            print("error: {}".format(exc), file=sys.stderr)
            return 1
    if args.collect_android:
        from .phoneguide import collect_android
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
        iocs = _load_iocs(args)
    except IocError as exc:
        print("error: {}".format(exc), file=sys.stderr)
        return 1

    if args.deep:
        print("WARNING: --deep is not implemented; no full persistence sweep will run.\n",
              file=sys.stderr)

    password, made_password = made_password, ""
    if args.backup_password:
        import getpass
        if not sys.stdin.isatty():
            print("error: backup password requires a private interactive terminal", file=sys.stderr)
            return 1
        password = getpass.getpass("Backup password (not saved): ")
    workflow_before_scan(args, iocs)
    ctx = ScanContext(iocs=iocs, deep=args.deep, quick=args.quick,
                      full=args.scan_type == "full", browser_only=args.scan_type == "browser",
                      targets=tuple(os.path.abspath(p) for p in args.target),
                      backup_password=password, extended_windows=args.extended_windows, ios_input=args.ios_input,
                      patterns=args.patterns, pattern_paths=tuple(args.pattern_path),
                      phone_path=args.phone or "", dns_logs=tuple(os.path.abspath(p) for p in args.dns_log))
    from .termstyle import TsProgress, ts_enabled
    if ts_enabled(sys.stderr) and not getattr(args, "json", None) == "-":
        ctx.emit = TsProgress(sys.stderr)                 # one progress line, updated in place
    started = datetime.datetime.now()
    with scan_recovery(ctx):
        ctx.completed = _run_modules(ctx)
    if hasattr(ctx.emit, "finish"):
        ctx.emit.finish()

    ctx.backup_password = password = ""
    return finalize_report(iocs, ctx.completed, started, args, ctx.cancelled)


def main(argv: List[str] = None) -> int:
    try:
        return _main(argv)
    except FileExistsError as exc:
        # Every tool saves with "x" (never overwrite); say so instead of a traceback.
        print("error: {} already exists - choose a new name. Nothing was overwritten.".format(
            exc.filename or exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Stopped by user. Any completed report already saved remains on disk.", file=sys.stderr)
        return 1
    finally:
        training_cleanup()


if __name__ == "__main__":
    raise SystemExit(main())
