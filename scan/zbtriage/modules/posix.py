"""Bounded Linux/macOS configuration, saved shell input and text-log inspection.

No command is executed, no referenced program is opened, and configuration
presence does not establish activation or execution. Network text is only a
reference; an exact published executable path can support configuration evidence.
"""
from __future__ import annotations

import configparser
import contextlib
import datetime
import json
import os
import plistlib
import re
import sqlite3
import stat
import sys
import xml.parsers.expat

from ..localpaths import open_evidence_db, path_problem
from ..result import Hit, ModuleResult, EV_CONFIGURED, EV_CONTACTED, EV_REFERENCED
from .browser import (_MAC_EPOCH, _browser_url_evidence, _discard_snapshot, _guard_db,
                      _locked_note, copy_locked)

NAME = "unix-host"
_UX_DOWNLOAD_ROW_CAP = 200000
_UX_FILE_CAP = 1024 * 1024
_UX_COUNT_CAP = 4096
_UX_TOTAL_CAP = 32 * 1024 * 1024
_UX_TEXT_CAP = 4 * 1024 * 1024
_UX_UNIT_SUFFIXES = (".service", ".timer", ".socket", ".path", ".target", ".mount",
                     ".automount", ".swap", ".slice", ".scope")


def _ux_roots():
    home = os.path.expanduser("~")
    cfg = os.environ.get("XDG_CONFIG_HOME", "")
    cfg = cfg if os.path.isabs(cfg) else os.path.join(home, ".config")
    data = os.environ.get("XDG_DATA_HOME", "")
    data = data if os.path.isabs(data) else os.path.join(home, ".local", "share")
    common = [("unix-shell-history", os.path.join(home, name), "history-file")
              for name in (".bash_history", ".zsh_history")]
    common.append(("unix-shell-history", os.path.join(data, "fish", "fish_history"), "history-file"))
    # macOS Terminal keeps history per window session instead of one file.
    common += [("unix-shell-history", os.path.join(home, name), "history-dir")
               for name in (".zsh_sessions", ".bash_sessions")]
    common += [("unix-shell-profiles", os.path.join(home, name), "shell-file")
               for name in (".profile", ".bash_profile", ".bash_login", ".bashrc", ".zprofile", ".zshrc", ".zshenv", ".zlogin")]
    common += [("unix-shell-profiles", path, "shell-file") for path in (
        os.path.join(cfg, "fish", "config.fish"), "/etc/profile", "/etc/bash.bashrc",
        "/etc/bashrc", "/etc/zshenv", "/etc/zprofile", "/etc/zshrc")]
    common += [("unix-shell-profiles", path, "shell-dir") for path in (
        "/etc/profile.d", os.path.join(cfg, "fish", "conf.d"))]
    if sys.platform.startswith("linux"):
        return common + [
            ("linux-autostart", os.path.join(cfg, "autostart"), "desktop"),
            ("linux-autostart", "/etc/xdg/autostart", "desktop"),
            ("linux-systemd-units", os.path.join(cfg, "systemd", "user"), "unit"),
            ("linux-systemd-units", "/etc/systemd/user", "unit"),
            ("linux-systemd-units", "/etc/systemd/system", "unit"),
            ("linux-systemd-units", "/usr/lib/systemd/user", "unit"),
            ("linux-systemd-units", "/usr/lib/systemd/system", "unit"),
            ("linux-systemd-units", "/run/systemd/system", "unit"),
            ("linux-systemd-units", "/usr/local/lib/systemd/system", "unit"),
            ("linux-cron", "/etc/crontab", "cron-file"),
            ("linux-cron", "/etc/cron.d", "cron"),
            ("linux-cron", "/var/spool/cron/crontabs", "user-cron"),
            ("linux-cron", "/var/spool/cron", "user-cron"),
            ("linux-cron", "/etc/crontabs", "user-cron"),  # BusyBox cron (Alpine)
        ] + [("linux-cron", "/etc/cron." + period, "cron-script")
             for period in ("hourly", "daily", "weekly", "monthly")] + [
            ("unix-system-logs", path, "log-file") for path in (
                "/var/log/syslog", "/var/log/messages", "/var/log/auth.log", "/var/log/secure")]
    if sys.platform == "darwin":
        return common + [("macos-launch-items", p, "plist") for p in (
            os.path.join(home, "Library", "LaunchAgents"),
            "/Library/LaunchAgents", "/Library/LaunchDaemons",
            "/System/Library/LaunchAgents", "/System/Library/LaunchDaemons",
            # Apple ships Safari's and WebKit's agents in the App cryptex and
            # links them into /System/Library; reading them here keeps those
            # links from being gaps.
            "/System/Cryptexes/App/System/Library/LaunchAgents",
            "/System/Cryptexes/App/System/Library/LaunchDaemons")] + [
                ("unix-system-logs", "/var/log/system.log", "log-file"),
                ("macos-download-record", os.path.join(
                    home, "Library", "Preferences",
                    "com.apple.LaunchServices.QuarantineEventsV2"), "download-record-file")]
    return []


def _ux_reason(exc):
    """A short, specific reason for a file the reader could not use."""
    if isinstance(exc, UnicodeDecodeError):
        return "not UTF-8 text"
    text = " ".join(str(exc).split()) or type(exc).__name__
    return text[:160]


def _ux_where(root, paths):
    """'<file>' for one file (or a single-file root), else '<n> files under <root>,
    for example <file>'."""
    if len(paths) == 1:
        return paths[0]
    return "{} files under {}, for example {}".format(len(paths), root, paths[0])


def _ux_link_target(path):
    """Where a symbolic link points, worked out from its text without opening
    or resolving it; None when path is not a link."""
    try:
        if not stat.S_ISLNK(os.lstat(path).st_mode):
            return None
        target = os.readlink(path)
    except OSError:
        return None
    return os.path.normpath(target if os.path.isabs(target) else os.path.join(os.path.dirname(path), target))


def _ux_merged_usr(path):
    """On merged-/usr systems /lib, /bin and /sbin are root-owned links into
    /usr, so an alias spelled /lib/systemd/... names a /usr/lib/systemd file.
    Checked lexically (readlink of that one exact link), never followed."""
    parts = path.split("/")
    if len(parts) > 2 and parts[0] == "" and parts[1] in ("lib", "lib64", "bin", "sbin"):
        top = "/" + parts[1]
        try:
            info = os.lstat(top)
            if (stat.S_ISLNK(info.st_mode) and getattr(info, "st_uid", None) == 0
                    and os.readlink(top) in ("usr" + top, "/usr" + top)):
                return "/usr" + path
        except OSError:
            pass
    return path


def _ux_inspected(path, root_dirs):
    """True when path is a file this reader inspects under its own name: directly
    inside an inspected folder and accepted by that folder's file filter."""
    path = _ux_merged_usr(path)
    kind = root_dirs.get(os.path.dirname(path))
    if kind is None:
        return False
    suffix = {"desktop": ".desktop", "plist": ".plist", "unit": _UX_UNIT_SUFFIXES}.get(kind)
    return not suffix or os.path.basename(path).endswith(suffix)


def _ux_read(path):
    return _ux_read_data(path, False)[0]


def _ux_read_data(path, recent):
    problem = path_problem(path)
    if problem:
        raise OSError(problem)
    before = os.lstat(path)
    limit = _UX_TEXT_CAP if recent else _UX_FILE_CAP
    if not stat.S_ISREG(before.st_mode) or (not recent and before.st_size > limit):
        raise OSError("not a regular file or exceeds configuration size limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino):
            raise OSError("configuration changed before reading")
        truncated = recent and opened.st_size > limit
        if truncated:
            stream.seek(opened.st_size - limit)
        data = stream.read(limit if recent else limit + 1)
        after = os.fstat(stream.fileno())
    if recent:
        # A live log or history grows while it is read; appended records are
        # simply newer than this snapshot. Shrinking means it was rotated or
        # rewritten, and what was read may not be what the file holds.
        if after.st_size < opened.st_size:
            raise OSError("text log was truncated or rotated while reading")
    elif len(data) > limit or (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise OSError("configuration changed or exceeded read limit")
    if truncated:
        # The first bytes may be the middle of a UTF-8 character or a record.
        # One very long record has no line break to cut at: keep it, without
        # the partial character it may start with.
        head, newline, rest = data.partition(b"\n")
        data = rest if newline else data.lstrip(bytes(range(0x80, 0xC0)))
    return data, truncated


def _ux_program(command):
    # Desktop Exec is not shell syntax. Recognize only literal tokens with
    # optional double quotes. Escapes and field substitutions need the desktop
    # specification's expansion rules; keep those commands as references.
    token = r'''"[^"\\%`$\r\n]*"|[^\s"'\\%`$><~|&;*?#()=]+'''
    command = command.strip()
    if not re.fullmatch("(?:" + token + ")(?:[ \t]+(?:" + token + "))*", command):
        return ""
    first = re.match(token, command).group(0)
    return first[1:-1] if first.startswith('"') else first


# Some of Apple's own launch plists ship their XML declaration, DOCTYPE and
# <plist version=...> tag without quotes, which the XML parser rejects. The
# declaration and DOCTYPE are optional, and only that one attribute is quoted.
_UX_LOOSE_PROLOG = re.compile(rb"\A\s*<\?xml[^>]*\?>\s*(?:<!DOCTYPE[^>]*>\s*)?")
_UX_LOOSE_PLIST_TAG = re.compile(rb"\A<plist\s+version=([0-9.]+)\s*>")


def _ux_plist(data):
    try:
        return plistlib.loads(data)
    except xml.parsers.expat.ExpatError:
        body = _UX_LOOSE_PROLOG.sub(b"", data, count=1)
        body = _UX_LOOSE_PLIST_TAG.sub(lambda m: b'<plist version="' + m.group(1) + b'">', body, count=1)
        if body == data or not body.startswith(b"<plist"):
            raise
        return plistlib.loads(body)


def _ux_fields(data, kind):
    """Return (text, exact executable paths, limitation); no target access."""
    if kind == "plist":
        doc = _ux_plist(data)
        if not isinstance(doc, dict):
            raise ValueError("launch item is not a dictionary")
        argv, program = doc.get("ProgramArguments", []), doc.get("Program", "")
        if not isinstance(program, str) or not isinstance(argv, list) or not all(isinstance(v, str) for v in argv):
            raise ValueError("unsupported launch program fields")
        disabled = doc.get("Disabled", False)
        if not isinstance(disabled, bool):
            # Conditional (non-boolean) Disabled values exist in Apple's own
            # plists. Whether the job runs is then unknown: its text is still
            # searched, but no program is treated as configured to start.
            disabled = True
        # Other fields are metadata, not literal commands. Avoid recursive input
        # traversal and do not infer executables from arbitrary nested strings.
        text = "\n".join([program] + argv)
        labelled = isinstance(doc.get("Label"), str) and bool(doc["Label"])
        return text, [] if disabled or not labelled else [program or (argv[0] if argv else "")], ""
    text = data.decode("utf-8-sig", "replace" if kind == "history-file" else "strict")
    if "\x00" in text:
        raise ValueError("NUL in text configuration")
    if kind == "desktop":
        parser = configparser.ConfigParser(interpolation=None, strict=True)
        parser.optionxform = str
        parser.read_string(text)
        if parser.defaults():
            raise ValueError("unsupported inherited desktop keys")
        if not parser.has_section("Desktop Entry"):
            raise ValueError("missing Desktop Entry section")
        section = parser["Desktop Entry"]
        command = section.get("Exec", "")
        # Conditions and overrides are not resolved. Mark only unconditional
        # literal Application entries as configured executable paths.
        conditional = any(section.get(k, "") for k in ("OnlyShowIn", "NotShowIn", "TryExec"))
        enabled = (section.get("Type") == "Application" and
                   section.get("Hidden", "false") == "false" and
                   section.get("DBusActivatable", "false") == "false" and
                   section.get("X-GNOME-Autostart-enabled", "true") == "true" and not conditional)
        program = _ux_program(command)
        limitation = "unsupported desktop Exec syntax retained as references" if command and not program else ""
        return text, [program] if enabled and program else [], limitation
    # Unit activation, masking, drop-ins and variable expansion are deliberately
    # not resolved. The program a unit or crontab line runs is read literally
    # (_ux_commands): a published path there is graded configured, with
    # activation unverified. Its arguments, network names included, stay
    # references, as for desktop entries and launch items.
    if kind in _UX_COMMAND_KINDS:
        return text, [program for _command, program in _ux_commands(text, kind) if program], ""
    return text, [], ""


# Kinds whose lines name commands to run: systemd units and crontabs.
_UX_COMMAND_KINDS = {"unit", "cron", "cron-file", "user-cron"}
_UX_UNIT_EXEC = re.compile(r"Exec(?:Start|StartPre|StartPost|Reload|Stop|StopPost)[ \t]*=[ \t]*(.*)")
_UX_ENV_LINE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*[ \t]*=")
# A literal absolute path as the first word, quoted or bare, with nothing that
# needs shell or specifier expansion inside it.
_UX_FIRST_PATH = re.compile(r'''(?:"(/[^"\\$`%\r\n]*)"|(/[^\s"'\\$`%;|&<>()*?#]+))(?=$|[\s;|&<>])''')


def _ux_first_path(command):
    m = _UX_FIRST_PATH.match(command.strip())
    return (m.group(1) or m.group(2)) if m else ""


def _ux_commands(text, kind):
    """(command, literal program path or "") for each command a unit or crontab
    line runs. Only [Service] Exec lines in units; in crontabs every schedule
    line after its time fields (and the user field in system crontabs)."""
    out = []
    if kind == "unit":
        section = ""
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("[") and line.endswith("]"):
                section = line
                continue
            m = _UX_UNIT_EXEC.fullmatch(line) if section == "[Service]" else None
            if not m or m.group(1).endswith("\\"):
                continue        # continued lines are not resolved
            command = m.group(1).lstrip("-@:+!|")   # systemd command prefixes
            out.append((command, _ux_first_path(command)))
        return out
    with_user = kind in ("cron", "cron-file")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or _UX_ENV_LINE.match(line):
            continue
        fields = (1 if line.startswith("@") else 5) + (1 if with_user else 0)
        parts = line.split(None, fields)
        if len(parts) <= fields:
            continue
        # An unescaped % ends the command (the rest is standard input).
        command = re.split(r"(?<!\\)%", parts[fields], maxsplit=1)[0]
        out.append((command, _ux_first_path(command)))
    return out


def _ux_case_values(ind):
    """The publisher's original spellings (Unix names are case-sensitive)."""
    originals = set()
    for encoded in ind.contexts:
        try:
            context = json.loads(encoded)
        except (TypeError, ValueError):
            continue
        value = context.get("case_sensitive_value") if isinstance(context, dict) else None
        if isinstance(value, str):
            originals.add(value)
    return originals or {ind.value}


def _ux_match(result, ctx, path, text, programs, context="startup configuration"):
    for ind in ctx.iocs.search(text.lower()):
        result.add_hit(Hit(ind.value, path,
            "Indicator text in {}; contact and execution are unverified.".format(context),
            tier=ind.tier, confidence=ind.confidence, source=ind.source,
            family=ind.family, kind=ind.type, evidence=EV_REFERENCED, artifact=path))
    for ind in ctx.iocs.indicators:
        if ind.type != "file-path" or not ind.value.startswith("/"):
            continue
        # General typed lookup is case-insensitive for historical consumers.
        # Unix paths need the publisher's original case, including every value
        # retained when differently cased STIX records share a normalized key.
        originals = set()
        for encoded in ind.contexts:
            try:
                context = json.loads(encoded)
            except (TypeError, ValueError):
                continue
            value = context.get("case_sensitive_value") if isinstance(context, dict) else None
            if isinstance(value, str) and value.startswith("/"):
                originals.add(value)
        originals = sorted(originals or {ind.value})
        configured_paths = [value for value in originals if value in programs]
        # A path is a whole word of shell text: it may follow a command
        # substitution or separator ($(...), backticks, ;, |, &), not only a
        # space, quote or '='.
        matched_paths = configured_paths or [value for value in originals
            if re.search(r"(?<![^\s\"'=(`;|&:,])" + re.escape(value) + r"(?=$|[\s\"';)`|&:,])", text)]
        if not matched_paths:
            continue
        configured = bool(configured_paths)
        result.add_hit(Hit(ind.value, path,
            ("Literal executable path matches a published indicator; activation and execution are unverified."
             if configured else "Published path appears in {}; active executable use is unverified.".format(context))
            + " Exact path: " + matched_paths[0],
            tier=ind.tier, confidence=ind.confidence, source=ind.source,
            family=ind.family, kind=ind.type,
            evidence=EV_CONFIGURED if configured else EV_REFERENCED, artifact=path))
    # A configured program's file name is also its process name.
    names = {program.rsplit("/", 1)[-1] for program in programs if isinstance(program, str)}
    for ind in ctx.iocs.of_type("process") if names else ():
        matched = sorted(names & _ux_case_values(ind))
        if matched:
            result.add_hit(Hit(ind.value, path,
                "Configured program's process name matches a published indicator; activation and execution "
                "are unverified. Name: " + matched[0],
                tier=ind.tier, confidence=ind.confidence, source=ind.source,
                family=ind.family, kind=ind.type, evidence=EV_CONFIGURED, artifact=path))


def _ux_download_time(stamp):
    """The local time of an Apple timestamp, or None if it is not a plausible one."""
    if type(stamp) not in (int, float) or not 0 < stamp < 4e9:
        return None
    try:
        return datetime.datetime.fromtimestamp(stamp + _MAC_EPOCH)
    except (OverflowError, OSError, ValueError):
        return None


def _ux_download_record(result, ctx, check, path):
    """macOS's record of where downloaded files came from, separate from any browser.

    Only the two addresses and the date are read, from a private temporary copy.
    An application writes its own row, so only a file address on an indicator's
    host counts as contact; the page address stays a reference. A missing record
    is not checked rather than clean: it may simply have been cleared."""
    try:
        tmp, incomplete = copy_locked(path)
    except FileNotFoundError:
        result.could_not_run(check, "macOS has no record of downloaded files for this account, so "
                                    "none was checked. It may have been cleared; this says nothing "
                                    "about past downloads")
        return
    except OSError as exc:
        result.skipped += 1
        result.could_not_run(check, _locked_note(path, exc))
        return
    con = None
    try:
        con = open_evidence_db(tmp)
        _guard_db(con)
        con.text_factory = lambda b: b.decode("utf-8", "replace")
        oldest, count, seen = None, 0, set()
        # Oldest first, so a repeated indicator keeps the date it was first seen.
        with contextlib.closing(con.execute(
                "SELECT LSQuarantineDataURLString, LSQuarantineOriginURLString, LSQuarantineTimeStamp "
                "FROM LSQuarantineEvent ORDER BY LSQuarantineTimeStamp")) as rows:
            for data_url, origin_url, stamp in rows:
                if count >= _UX_DOWNLOAD_ROW_CAP:
                    result.could_not_run(check, "record limit reached; the newest download records "
                                                "were not searched")
                    break
                count += 1
                when = _ux_download_time(stamp)
                if when is not None and oldest is None:
                    oldest = when
                for url, grade in ((data_url, EV_CONTACTED), (origin_url, EV_REFERENCED)):
                    if not isinstance(url, str):
                        continue
                    for ind, evidence in _browser_url_evidence(url, ctx.iocs, grade):
                        if (ind.value, evidence) in seen:
                            continue
                        seen.add((ind.value, evidence))
                        contacted = evidence == EV_CONTACTED
                        result.add_hit(Hit(ind.value, path,
                            "macOS recorded a file downloaded from this host; execution is unverified."
                            if contacted else
                            "An address in macOS's record of downloaded files mentions this; "
                            "a saved reference, not proof of contact.",
                            tier=ind.tier, confidence=ind.confidence, source=ind.source,
                            family=ind.family, kind=ind.type, evidence=evidence, artifact=path,
                            observed=when.isoformat(timespec="seconds") if contacted and when else ""))
        result.checked += count
        result.submetrics["download_records"] = count
        if oldest is not None:
            result.reach["macos-download-record"] = {
                "earliest": oldest.isoformat(timespec="seconds"),
                "days": max(0, (datetime.datetime.now() - oldest).days),
                "basis": "oldest of {:,} macOS download records".format(count),
                "note": "This covers downloaded files only, not pages or ads that were merely "
                        "shown, and it can be cleared."}
        result.ran(check)
        if incomplete:
            result.could_not_run(check, "snapshot is incomplete - {}, so recent download records "
                                        "may be missing".format("; ".join(incomplete)))
    except (sqlite3.Error, ValueError, TypeError) as exc:
        result.skipped += 1
        result.could_not_run(check, "macOS's record of downloaded files is unreadable or "
                                    "unsupported: {}".format(exc))
    finally:
        if not _discard_snapshot(os.path.dirname(tmp), con):
            result.could_not_run(check, "temporary copy of the download record could not be "
                                        "removed: {}".format(os.path.dirname(tmp)))


def run(ctx):
    result = ModuleResult(NAME)
    ctx.partial = result
    roots = _ux_roots()
    if not roots:
        result.could_not_run("unix-host-platform", "Linux/macOS startup readers are not applicable on this platform")
        return result
    total = count = 0
    seen = set()
    # Distributions link standard locations to each other (Alpine's
    # /var/spool/cron/crontabs -> /etc/crontabs); such a link is inspected
    # under its own name, not reported as a refused redirection.
    root_dirs = {os.path.normpath(r): k for _c, r, k in roots if not k.endswith("-file")}
    for check, root, kind in roots:
        if kind == "download-record-file":
            _ux_download_record(result, ctx, check, root)
            continue
        problems, denied, unexpanded = [], [], []
        links_out = []
        try:
            if _ux_link_target(root) in root_dirs:
                result.ran(check)
                continue
            problem = path_problem(root)
            if problem:
                raise OSError(problem)
            info = os.lstat(root)
            if kind.endswith("-file"):
                candidates = [root]
            else:
                if not stat.S_ISDIR(info.st_mode):
                    raise OSError("configuration root is not a directory")
                candidates = []
                with os.scandir(root) as entries:
                    for entry in entries:
                        count += 1
                        if count > _UX_COUNT_CAP:
                            result.skipped += 1
                            result.could_not_run(check, "configuration entry count limit reached; retained entries still inspected")
                            break
                        if kind == "unit" and (entry.name.endswith(tuple(s + ".d" for s in _UX_UNIT_SUFFIXES))
                                               or entry.name in {s[1:] + ".d" for s in _UX_UNIT_SUFFIXES}):
                            try:
                                if path_problem(entry.path):
                                    raise OSError("redirected unit override directory")
                                with os.scandir(entry.path) as children:
                                    for child in children:
                                        count += 1
                                        if count > _UX_COUNT_CAP:
                                            result.could_not_run(check, "configuration entry count limit reached; retained entries still inspected")
                                            break
                                        if child.name.endswith(".conf"):
                                            candidates.append(child.path)
                            except OSError as exc:
                                problems.append((entry.path, _ux_reason(exc)))
                            if count > _UX_COUNT_CAP:
                                break
                            continue
                        suffix = {"desktop": ".desktop", "plist": ".plist", "unit": _UX_UNIT_SUFFIXES,
                                  "history-dir": ".history"}.get(kind)
                        if suffix and not entry.name.endswith(suffix):
                            continue
                        # Subdirectories and unit activation links are not followed.
                        if entry.is_dir(follow_symlinks=False):
                            continue
                        candidates.append(entry.path)
            read_before = result.checked
            for path in candidates:
                # Links are never followed. A unit masked by a link to /dev/null
                # has nothing to read, and a link whose target lies in an
                # inspected folder (systemd aliases) is read there under its own
                # name; any other link is a gap that names where it points.
                linked = _ux_link_target(path)
                if linked is not None:
                    if not (linked == os.devnull or linked in root_dirs or _ux_inspected(linked, root_dirs)):
                        links_out.append((path, linked))
                    continue
                if path in seen:
                    continue
                seen.add(path)
                try:
                    recent = kind in ("history-file", "history-dir", "log-file")
                    if recent:
                        data, truncated = _ux_read_data(path, True)
                        if truncated:
                            result.could_not_run(check, "older records outside the recent-text byte limit were not read: " + path)
                    else:
                        data = _ux_read(path)
                    total += len(data)
                    if total > _UX_TOTAL_CAP:
                        raise OSError("total configuration read limit reached")
                    text, programs, limitation = _ux_fields(data, "history-file" if kind == "history-dir" else kind)
                    context = ("saved shell history" if kind in ("history-file", "history-dir")
                               else "saved text log" if kind == "log-file"
                               else "shell startup configuration" if kind.startswith("shell-") else "startup configuration")
                    _ux_match(result, ctx, path, text, programs, context)
                    result.checked += 1
                    if limitation:
                        # The whole text was searched; only the stronger
                        # "configured program" grade could not be given.
                        unexpanded.append(path)
                except PermissionError:
                    denied.append(path)
                    result.skipped += 1
                except (OSError, ValueError, configparser.Error, plistlib.InvalidFileException,
                        xml.parsers.expat.ExpatError, OverflowError, RecursionError) as exc:
                    problems.append((path, _ux_reason(exc)))
                    result.skipped += 1
                if total > _UX_TOTAL_CAP:
                    break
            if not candidates or result.checked > read_before or not (problems or denied):
                # A root where every file failed (damaged, unreadable, refused) was
                # not read: its gap is reported below, not a clean read.
                result.ran(check)
            if links_out:
                result.could_not_run(check, "{} linked file(s) under {} point outside the inspected folders and "
                                     "were not followed (for example {} -> {})".format(
                                         len(links_out), root, links_out[0][0], links_out[0][1]))
            if denied:
                result.could_not_run(check, "{} could not be read with this account's permissions; reading "
                                     "{} needs administrator (root) rights".format(
                                         _ux_where(root, denied), "it" if len(denied) == 1 else "them"))
            if problems:
                result.could_not_run(check, "{} could not be used: {}".format(
                    _ux_where(root, [p for p, _ in problems]), problems[0][1]))
            if unexpanded:
                result.note("{}: {} autostart entr{} use launch syntax this reader does not expand (for "
                            "example {}); the text was searched, but no program is treated as "
                            "configured to start".format(check, len(unexpanded), "y" if len(unexpanded) == 1 else "ies",
                                                         unexpanded[0]))
        except FileNotFoundError:
            result.ran(check)  # known root absent, not an unreadable root
        except PermissionError:
            result.skipped += 1
            result.could_not_run(check, "{} could not be read with this account's permissions; reading it "
                                 "needs administrator (root) rights".format(root))
        except OSError as exc:
            result.skipped += 1
            result.could_not_run(check, "{}: {}".format(root, exc))
        if total > _UX_TOTAL_CAP or count > _UX_COUNT_CAP:
            result.could_not_run("unix-host-limits", "remaining startup roots were not inspected after the safety limit")
            break
    result.note("Saved configuration, shell input and text logs only: no commands or referenced programs were opened or executed. Network strings are references, not contact.")
    result.note("Scope: standard startup files, one-level unit overrides, cron scripts, shell profiles/history and readable current text logs. Links are not followed; masked units and aliases of inspected files are not gaps. Activation, effective overrides, custom shell locations, binary journals, rotated logs, other users' homes and managed login items are not resolved. Permissions and local filesystem redirections can leave gaps.")
    return result
