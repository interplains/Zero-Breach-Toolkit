"""Optional, bounded matching of pinned public Candiru research rules.

Matches require investigation; they are neither exact sample identifications nor
confirmation of infection. No rule or sample is fetched by this module.
"""

from __future__ import annotations

import importlib as _pattern_importlib
import io as _pattern_io
import os as _pattern_os
import stat as _pattern_stat
import sys as _pattern_sys

from ..result import Hit, ModuleResult
from ..localpaths import path_problem, cloud_placeholder
from ..candiru_rules import (CANDIRU_ENGINE_VERSION, CANDIRU_RULE_SOURCES,
                            CANDIRU_RULE_METADATA)
from .hashscan import _roots as _pattern_roots

NAME = "patterns"
_PATTERN_MAX_BYTES = 1024 * 1024
_PATTERN_MAX_FILES = 50000
_PATTERN_MAX_DIRS = 20000
_PATTERN_MAX_ENTRIES = 100000
_PATTERN_MAX_DEPTH = 64
_PATTERN_MAX_TOTAL_BYTES = 256 * 1024 * 1024
_PATTERN_TIMEOUT = 5
_PATTERN_PRUNE = ("cache", "cache_data", "gpucache", "code cache", "node_modules",
                  ".git", "servicepackfiles", "winsxs")
_PATTERN_CLOUD_ATTRIBUTES = 0x1000 | 0x40000 | 0x400000


class _PatternLimit(RuntimeError):
    """A resource bound left part of the requested scope unobserved."""


class _PatternNoRead(OSError):
    """A known preflight rejection before any file data read was attempted."""


def _pattern_budget(counts):
    if counts["files"] >= _PATTERN_MAX_FILES:
        raise _PatternLimit("file cap reached")
    if counts["bytes"] + _PATTERN_MAX_BYTES + 1 > _PATTERN_MAX_TOTAL_BYTES:
        raise _PatternLimit("byte cap reached")


def _pattern_walk(root, counts, r, onerror, depth=0):
    """Yield files from streaming scandir; never materialize directory entries.

    Entry budget includes refused and pruned entries, before any classification
    or locality/cloud checks. At most MAX_DEPTH iterators are open; early close
    unwinds every with-block. There is no growing pending-directory list.
    """
    _pattern_budget(counts)
    if counts["entries"] >= _PATTERN_MAX_ENTRIES:
        raise _PatternLimit("directory entry cap reached")
    if depth >= _PATTERN_MAX_DEPTH:
        raise _PatternLimit("directory depth cap reached")
    if counts["dirs"] >= _PATTERN_MAX_DIRS:
        raise _PatternLimit("directory cap reached")
    counts["dirs"] += 1
    r.submetrics["directories_pattern_visited"] = counts["dirs"]
    try:
        problem = _pattern_problem(root)
        if problem:
            raise OSError(problem)
        with _pattern_os.scandir(root) as entries:
            while True:
                # Check before requesting/classifying another entry. Reaching
                # the exact cap is conservatively a gap, even if it was last.
                _pattern_budget(counts)
                if counts["entries"] >= _PATTERN_MAX_ENTRIES:
                    raise _PatternLimit("directory entry cap reached")
                try:
                    entry = next(entries)
                except StopIteration:
                    return
                counts["entries"] += 1
                r.submetrics["filesystem_entries_considered"] = counts["entries"]
                try:
                    info = entry.stat(follow_symlinks=False)
                    if (_pattern_stat.S_ISLNK(info.st_mode)
                            or (getattr(info, "st_file_attributes", 0) & 0x400
                                and not cloud_placeholder(info))):
                        raise OSError("symlink or reparse point was not followed")
                    if getattr(info, "st_file_attributes", 0) & _PATTERN_CLOUD_ATTRIBUTES:
                        raise OSError("offline or cloud-recall path was not opened")
                    if _pattern_stat.S_ISDIR(info.st_mode):
                        if entry.name.lower() in _PATTERN_PRUNE:
                            r.submetrics["directories_pruned"] = r.submetrics.get("directories_pruned", 0) + 1
                            onerror("directory skipped by pattern scan's size limits", entry.path)
                        else:
                            yield from _pattern_walk(entry.path, counts, r, onerror, depth + 1)
                    elif _pattern_stat.S_ISREG(info.st_mode):
                        yield entry.path
                    else:
                        raise OSError("special filesystem entry was not opened")
                except OSError as exc:
                    onerror(str(exc), entry.path)
    except OSError as exc:
        onerror(str(exc), root)


def _pattern_problem(path):
    problem = path_problem(path)
    if problem:
        return problem
    # OFFLINE and recall attributes can occur independently of reparse points.
    # Inspect every ancestor without opening the file's data stream.
    current = path
    while current:
        try:
            info = _pattern_os.lstat(current)
        except FileNotFoundError:
            return ""
        if getattr(info, "st_file_attributes", 0) & _PATTERN_CLOUD_ATTRIBUTES:
            return "offline or cloud-recall path was not opened"
        parent = _pattern_os.path.dirname(current)
        if parent == current:
            break
        current = parent
    return ""


def _pattern_identity(info):
    return (info.st_dev, info.st_ino, info.st_size,
            getattr(info, "st_mtime_ns", info.st_mtime),
            getattr(info, "st_ctime_ns", info.st_ctime))


def _pattern_shared_identity(info):
    # Windows Python 3.12 can report different st_ctime_ns values for lstat
    # and fstat on the same file. Compare ctime only between calls to the same
    # API; volume, file ID, size and mtime remain comparable across APIs.
    return _pattern_identity(info)[:4]


def _pattern_read(path):
    """Bound the read, reject special files, and detect observable replacements.

    Like the shared locality guard, this is conservative filesystem validation,
    not a sandbox against a concurrent privileged filesystem adversary.
    """
    read_started = False
    try:
        problem = _pattern_problem(path)
        if problem:
            raise OSError(problem)
        before = _pattern_os.lstat(path)
        if not _pattern_stat.S_ISREG(before.st_mode):
            raise OSError("not a regular local file")
        if before.st_size > _PATTERN_MAX_BYTES:
            raise OSError("file exceeds 1 MiB pattern read cap")
        flags = (_pattern_os.O_RDONLY | getattr(_pattern_os, "O_BINARY", 0)
                 | getattr(_pattern_os, "O_NOFOLLOW", 0)
                 | getattr(_pattern_os, "O_NONBLOCK", 0))
        fd = _pattern_os.open(path, flags)
        try:
            stream = _pattern_io.open(fd, "rb", closefd=True)
        except Exception:
            _pattern_os.close(fd)
            raise
        with stream:
            opened = _pattern_os.fstat(stream.fileno())
            if (not _pattern_stat.S_ISREG(opened.st_mode)
                    or _pattern_shared_identity(before) != _pattern_shared_identity(opened)
                    or _pattern_identity(before) != _pattern_identity(_pattern_os.lstat(path))):
                raise OSError("file changed before bounded read")
            problem = _pattern_problem(path)
            if problem:
                raise OSError(problem)
            # From this point an incomplete/failed read may have consumed data;
            # preserve the caller's maximum reservation for every such failure.
            read_started = True
            data = stream.read(_PATTERN_MAX_BYTES + 1)
            after = _pattern_os.fstat(stream.fileno())
        final = _pattern_os.lstat(path)
        problem = _pattern_problem(path)
        if problem:
            raise OSError(problem)
        if (len(data) > _PATTERN_MAX_BYTES or len(data) != before.st_size
                or _pattern_shared_identity(before) != _pattern_shared_identity(after)
                or _pattern_identity(opened) != _pattern_identity(after)
                or _pattern_identity(before) != _pattern_identity(final)):
            raise OSError("file grew or changed during bounded read")
        return data
    except OSError as exc:
        if not read_started:
            raise _PatternNoRead(str(exc)) from exc
        raise


_PATTERN_PROBE = ("import yara_x\n"
                  "c = yara_x.Compiler()\n"
                  "c.add_source('rule probe { condition: true }')\n"
                  "s = yara_x.Scanner(c.build())\n"
                  "s.scan(b'probe')\n"
                  "print('probe-ok')\n")


def _pattern_probe():
    """Run one tiny yara-x scan in a separate process first.

    On some Macs (Apple's Python 3.9, Apple Silicon) yara-x kills the Python
    process at its first scan with no message. Loading it in this process would
    take the whole scan down with it, so a crash here only skips this check.
    """
    if getattr(_pattern_sys, "frozen", False):
        return  # the built programs do not include yara-x; the import below reports that
    import shutil
    import subprocess
    import tempfile
    work = tempfile.mkdtemp(prefix="zb-pattern-probe-")
    try:
        # A fresh empty directory, so nothing in the user's folder can shadow yara_x.
        result = subprocess.run([_pattern_sys.executable, "-c", _PATTERN_PROBE], cwd=work,
                                stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=60,
                                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except subprocess.TimeoutExpired:
        raise RuntimeError("the pattern engine did not finish a one-line test scan within 60 seconds")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    if result.returncode == 0 and "probe-ok" in result.stdout:
        return
    if "No module named" in result.stderr:
        return  # not installed; the import below gives the usual message
    if result.returncode < 0 or result.returncode in (137, 134, 139):
        raise RuntimeError("the pattern engine crashed during a one-line test scan (exit code {}); "
                           "this is a known problem with yara-x on some Macs. The rest of the scan "
                           "is unaffected".format(result.returncode))
    raise RuntimeError("the pattern engine failed a one-line test scan (exit code {}): {}"
                       .format(result.returncode, (result.stderr.strip().splitlines() or [""])[-1][:200]))


def _pattern_engine():
    if _pattern_sys.version_info < (3, 9):
        raise RuntimeError("optional Candiru patterns require Python 3.9 or newer")
    _pattern_probe()
    engine = _pattern_importlib.import_module("yara_x")
    metadata = _pattern_importlib.import_module("importlib.metadata")
    version = metadata.version("yara-x")
    if version != CANDIRU_ENGINE_VERSION:
        raise RuntimeError("unsupported yara-x version {}; supported pinned version is {}"
                           .format(version, CANDIRU_ENGINE_VERSION))
    compiler = engine.Compiler()
    compiler.enable_includes(False)
    for source in CANDIRU_RULE_SOURCES:
        compiler.add_source(source)
    scanner = engine.Scanner(compiler.build())
    scanner.set_timeout(_PATTERN_TIMEOUT)
    return scanner


def _pattern_selected_roots(ctx):
    requested = getattr(ctx, "pattern_paths", ())
    # High-value registered files go first. A broad root can exhaust the
    # bounded budget; it must not prevent these targeted paths from being read.
    roots = requested if requested else list(getattr(ctx, "pattern_candidate_paths", ())) + list(
        _pattern_roots())
    # Lexical normalization only: resolving first could follow a refused link.
    unique = []
    for root in roots:
        raw = _pattern_os.fspath(root)
        # Check traversal and UNC/device spellings before normalization.
        problem = path_problem(raw)
        normalized = raw if problem else _pattern_os.path.normpath(raw)
        key = _pattern_os.path.normcase(normalized)
        if not any(key == old[0] for old in unique):
            unique.append((key, normalized, bool(problem)))
    # An explicitly selected child remains meaningful even beneath a selected
    # parent: the parent traversal might prune its directory. File-level dedup
    # below avoids duplicate scans while retaining each requested root.
    return [path for _, path, _ in unique]


def run(ctx) -> ModuleResult:
    r = ModuleResult(NAME)
    ctx.partial = r
    r.note("Optional public Candiru file patterns; matches require investigation, "
           "not an exact sample identification or confirmed infection. "
           "No match does not exclude encrypted, packed, memory-only, or other builds.")
    r.note("All regular file names are eligible, including extensionless files. "
           "Read cap: 1 MiB/file; scan caps: {} files, {} directories, {} entries, "
           "{} directory levels, {} MiB read budget; "
           "{} seconds per engine scan. Pruned directory names: {}."
           .format(_PATTERN_MAX_FILES, _PATTERN_MAX_DIRS, _PATTERN_MAX_ENTRIES,
                   _PATTERN_MAX_DEPTH, _PATTERN_MAX_TOTAL_BYTES // (1024 * 1024), _PATTERN_TIMEOUT,
                   ", ".join(_PATTERN_PRUNE)))
    try:
        scanner = _pattern_engine()
    except Exception as exc:
        r.could_not_run("pattern-engine", "optional pinned yara-x {} unavailable "
                        "or could not compile trusted rules: {}: {}"
                        .format(CANDIRU_ENGINE_VERSION, type(exc).__name__, exc))
        return r
    try:
        roots = _pattern_selected_roots(ctx)
    except (OSError, ValueError, TypeError) as exc:
        r.could_not_run("pattern-roots", str(exc))
        return r
    if not roots:
        r.could_not_run("pattern-roots", "no local pattern paths were selected")
        return r

    auto_candidates = set()
    if not getattr(ctx, "pattern_paths", ()):
        auto_candidates = {_pattern_os.path.normcase(_pattern_os.path.normpath(p))
                           for p in getattr(ctx, "pattern_candidate_paths", ())}
        if auto_candidates:
            auto_candidates.difference_update(
                _pattern_os.path.normcase(_pattern_os.path.normpath(p))
                for p in _pattern_roots())
        if auto_candidates:
            r.note("Also checking up to {} local, user-writable files named by "
                   "per-user COM registrations; registration alone is not a finding."
                   .format(len(auto_candidates)))
        omitted = getattr(ctx, "pattern_candidate_omitted", 0)
        if omitted:
            r.could_not_run("com-pattern-candidates", "{} registered file path(s) "
                            "were omitted by the registered-path safety cap".format(
                                omitted))

    counts = {"files": 0, "dirs": 0, "entries": 0, "bytes": 0}
    seen_files = {}  # bounded by MAX_FILES; value says whether scan succeeded
    for root in roots:
        name = "root:" + root
        tally = {"checked": 0, "covered": 0, "gaps": 0, "candidates": 0}

        def _pattern_gap(reason, location=root):
            tally["gaps"] += 1
            r.skipped += 1
            # Keep output and memory bounded even with a tree of refused files.
            if tally["gaps"] <= 10:
                r.note("Pattern file skipped at {}: {}".format(location, reason))

        try:
            problem = _pattern_problem(root)
            if problem:
                raise OSError(problem)
            info = _pattern_os.lstat(root)
            if _pattern_stat.S_ISREG(info.st_mode):
                entries = iter((root,))
            elif _pattern_stat.S_ISDIR(info.st_mode):
                if _pattern_os.path.normcase(_pattern_os.path.normpath(root)) in auto_candidates:
                    raise OSError("registered COM target changed into a directory; not traversed")
                entries = _pattern_walk(root, counts, r, _pattern_gap)
            else:
                raise OSError("not a regular file or directory")
        except OSError as exc:
            r.skipped += 1
            r.could_not_run(name, str(exc))
            continue
        ctx.emit("[patterns] scanning {} ...".format(root))
        try:
            for full in entries:
                key = _pattern_os.path.normcase(_pattern_os.path.normpath(full))
                if key in seen_files:
                    if seen_files[key]:
                        tally["covered"] += 1
                    else:
                        tally["gaps"] += 1
                    continue
                _pattern_budget(counts)
                counts["files"] += 1
                seen_files[key] = False
                tally["candidates"] += 1
                # Charge the maximum bounded read before touching data. Failed
                # reads retain the reservation, so changed/failed files cannot
                # bypass the aggregate budget. Proven preflight rejections
                # refund it all; successful reads refund only unused bytes.
                counts["bytes"] += _PATTERN_MAX_BYTES + 1
                try:
                    data = _pattern_read(full)
                    counts["bytes"] -= _PATTERN_MAX_BYTES + 1 - len(data)
                    matches = scanner.scan(data).matching_rules
                    known = []
                    for rule in matches:
                        identifier = rule.identifier
                        if identifier not in CANDIRU_RULE_METADATA:
                            raise RuntimeError("engine returned unknown rule identifier: {}".format(identifier))
                        known.append(identifier)
                except _PatternNoRead as exc:
                    counts["bytes"] -= _PATTERN_MAX_BYTES + 1
                    _pattern_gap("{}: {}".format(type(exc).__name__, exc), full)
                    continue
                except Exception as exc:
                    _pattern_gap("{}: {}".format(type(exc).__name__, exc), full)
                    continue
                r.checked += 1
                seen_files[key] = True
                tally["checked"] += 1
                r.submetrics["files_pattern_scanned"] = r.checked
                r.submetrics["bytes_pattern_scanned"] = r.submetrics.get("bytes_pattern_scanned", 0) + len(data)
                for identifier in known:
                    attribution = CANDIRU_RULE_METADATA[identifier]
                    detail = ("Public research rule {} matched; author: {}; license: {} ({}). "
                              "Pattern match requires investigation; not an exact sample "
                              "identification or confirmed infection. Source: {}"
                              .format(identifier, attribution["author"], attribution["license"],
                                      attribution["license_url"], attribution["source"]))
                    r.add_hit(Hit(indicator="yara:" + identifier, location=full,
                                  detail=detail, tier="candiru-pattern",
                                  confidence="research-rule", source=attribution["source"],
                                  evidence="file-pattern"))
                    # Match messages also preserve the DRL-required authorship.
                    ctx.emit("[patterns] !! MATCH {}: {}".format(full, detail))
        except _PatternLimit as exc:
            if tally["checked"] or tally["covered"]:
                r.ran(name + " (scanned subset)")
            r.could_not_run("pattern-limits", str(exc) +
                            "; this and remaining roots were not fully scanned")
            return r
        finally:
            close = getattr(entries, "close", None)
            if close:
                close()
        if tally["checked"] or tally["covered"]:
            r.ran(name)
        elif not tally["gaps"]:
            r.could_not_run(name, "no regular files were available for pattern scanning")
        if tally["gaps"]:
            r.could_not_run(name + " (coverage gaps)",
                            "{} file/subtree item(s) unreadable, unsafe, oversized, changed, "
                            "or not scanned successfully; {} file(s) scanned".format(
                                tally["gaps"], tally["checked"] + tally["covered"]))
    return r
