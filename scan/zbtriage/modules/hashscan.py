"""Hunt known sample hashes across the user-writable parts of this machine.

Citizen Lab (and others) publish SHA-256 hashes for the Windows payloads this
infrastructure delivers. Hashing every file on C: would take hours, so this
scans the locations an implant DLL actually lands in, plus anything the user
downloaded, and compares each file's digest against the sample hashes carried in
the IOC set.

A clean result means "none of these exact files are in these locations" - nothing
more. Each sample is one build; another victim's payload would hash differently,
which is why a clean hash scan is never a clean bill of health (D1/D3).

Contract: defines NAME and run(ctx) -> ModuleResult. Read-only, stdlib only, no
network (D2) - hashing a local file resolves nothing.
"""

from __future__ import annotations

import hashlib
from concurrent.futures import ThreadPoolExecutor
import io
import os
import stat
import sys

from ..result import Hit, ModuleResult, EV_ON_DISK
from ..localpaths import (path_problem, walk_local, WALK_LINK_REFUSED, WALK_SPECIAL_REFUSED,
                          WALK_CLOUD_SKIPPED, SF_DATALESS)

from ..localpaths import _CLOUD_ONLY_ATTRIBUTES

NAME = "hash"

# Only file types a payload plausibly ships as. Keeps the walk cheap and avoids
# hashing the user's documents and media for no reason.
EXTS = (".dll", ".exe", ".sys", ".ocx", ".cpl", ".scr", ".tmp", ".dat", ".bin", ".ax")

# Files larger than this are almost certainly not the implant; skipping them
# (counted as skipped, never as clean) keeps the scan from stalling on big blobs.
MAX_BYTES = 120 * 1024 * 1024

# Directory names pruned from the walk: browser/code caches, dependency trees and
# the Windows component store - huge, noisy, and not where an implant DLL lands.
PRUNE_DIRS = (
    "cache", "cache_data", "gpucache", "code cache", "node_modules",
    ".git", "servicepackfiles", "winsxs",
)


def _hs_xdg_user_dirs(user, config):
    """Download, desktop and documents folders from XDG user-dirs.dirs."""
    found = []
    try:
        with io.open(os.path.join(config, "user-dirs.dirs"), encoding="utf-8", errors="replace") as fh:
            lines = fh.read(64 * 1024).splitlines()
    except OSError:
        return found
    for line in lines:
        key, sep, value = line.strip().partition("=")
        if not sep or key not in ("XDG_DOWNLOAD_DIR", "XDG_DESKTOP_DIR", "XDG_DOCUMENTS_DIR"):
            continue
        value = value.strip().strip('"')
        if value.startswith("$HOME/"):
            value = os.path.join(user, value[len("$HOME/"):])
        elif not value.startswith("/"):
            continue
        if os.path.normpath(value) != os.path.normpath(user):  # "$HOME" itself means "not set"
            found.append(value)
    return found


def _roots():
    """The user-writable locations an implant actually drops into, filtered to
    those that exist on this host. Matches the proof-of-concept exactly."""
    user = os.path.expanduser("~")
    roots = [
        os.environ.get("APPDATA", ""),
        os.environ.get("LOCALAPPDATA", ""),
        os.environ.get("PROGRAMDATA", ""),
        os.environ.get("TEMP", ""),
        os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Temp"),
        os.path.join(user, "Downloads"),
        os.path.join(user, "Desktop"),
        os.path.join(user, "Documents"),
        r"C:\Users\Public",
    ]
    if sys.platform.startswith("linux"):
        config = os.environ.get("XDG_CONFIG_HOME", "")
        data = os.environ.get("XDG_DATA_HOME", "")
        roots = [os.path.join(user, name) for name in
                 ("Downloads", "Desktop", "Documents", ".local/bin")]
        # A desktop in another language names these folders in that language
        # (~/Téléchargements, ~/التنزيلات...); user-dirs.dirs says where they are.
        roots += _hs_xdg_user_dirs(user, config if os.path.isabs(config) else os.path.join(user, ".config"))
        roots += [config if os.path.isabs(config) else os.path.join(user, ".config"),
                  data if os.path.isabs(data) else os.path.join(user, ".local/share"),
                  "/tmp", "/var/tmp"]
    elif sys.platform == "darwin":
        roots = [os.path.join(user, name) for name in
                 ("Downloads", "Desktop", "Documents", "Applications", "Library/Application Support",
                  "Library/LaunchAgents")]
        roots += ["/Applications", "/Library/LaunchAgents", "/Library/LaunchDaemons", "/private/tmp", "/private/var/tmp"]
    # De-duplicate by resolved, case-normalised path, then drop any root that is
    # nested inside another. %TEMP% is %LOCALAPPDATA%\Temp on a default install,
    # so without this every file under Temp is hashed twice - inflating the
    # coverage counts and reporting one real sample as two separate hits.
    resolved = []
    for raw in roots:
        if not raw:
            continue
        # Do not resolve links or test existence before the locality guard.
        norm = os.path.normcase(os.path.normpath(raw))
        if norm not in resolved:
            resolved.append(norm)
    kept = []
    for r1 in resolved:
        if any(r1 != r2 and r1.startswith(r2 + os.sep) for r2 in resolved):
            continue  # r1 lives inside another root; walking that one covers it
        kept.append(r1)
    return kept


def _hs_candidate(path, filename):
    """Platform default selection; full/targeted scans already select all files.

    Extensionless ELF/Mach-O and scripts are common on Unix. Include all
    extensionless files plus native libraries/scripts and executable files,
    without opening a candidate merely to guess its format.
    """
    if filename.lower().endswith(EXTS):
        return True
    if not (sys.platform.startswith("linux") or sys.platform == "darwin"):
        return False
    lower = filename.lower()
    if (not os.path.splitext(filename)[1] or lower.endswith((".so", ".dylib", ".sh", ".bash", ".zsh", ".py", ".pl"))
            or ".so." in lower):
        return True
    # stat errors belong in the normal guarded hashing path, where they become
    # explicit gaps rather than silently excluding a possible executable.
    try:
        return bool(os.stat(path, follow_symlinks=False).st_mode & 0o111)
    except OSError:
        return True


# Files fingerprinted at once. Reading and hashing release the interpreter lock,
# so threads give a real speed-up without a second process.
_WORKERS = max(2, min(8, (os.cpu_count() or 2)))


def _hash_one(full):
    """(path, hex digest or None, size, reason). With no digest, reason says why:
    "link" and "special" are aliases and device/socket entries, not files that
    can hold a program, and are not gaps (a link's target is fingerprinted
    where it lies inside a scanned folder); "large", "denied" and "unreadable"
    are files that were not compared, and the caller reports them as gaps."""
    try:
        if os.path.islink(full):
            return full, None, 0, "link"
        problem = path_problem(full)
        if problem:
            return full, None, 0, "unreadable"
        info = os.stat(full, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode):
            return full, None, 0, "special"
        if (getattr(info, "st_flags", 0) & SF_DATALESS
                or getattr(info, "st_file_attributes", 0) & _CLOUD_ONLY_ATTRIBUTES):
            return full, None, 0, "cloud"
        if info.st_size > MAX_BYTES:
            return full, None, 0, "large"
        digest, size = _sha256(full)
        return full, digest, size, ""
    except PermissionError:
        return full, None, 0, "denied"
    except OSError as exc:
        if "hash read limit" in str(exc):
            return full, None, 0, "large"
        return full, None, 0, "unreadable"


def _hs_reasons(reasons, fix=True):
    """Why files were not compared, in words, with the fix where there is one.
    fix=False leaves out the Full Disk Access advice when another part of the
    same gap already gives it."""
    parts = []
    if reasons["denied"]:
        parts.append("{} permission denied".format(reasons["denied"]))
    if reasons["large"]:
        parts.append("{} over {} MB".format(reasons["large"], MAX_BYTES // (1024 * 1024)))
    if reasons["unreadable"]:
        parts.append("{} could not be read".format(reasons["unreadable"]))
    if reasons.get("cloud"):
        parts.append("{} stored only in iCloud or OneDrive and not downloaded".format(reasons["cloud"]))
    text = ", ".join(parts) or "could not be read"
    if fix and reasons["denied"] and sys.platform == "darwin":
        text += ("; macOS privacy protection blocks some folders: give Terminal Full Disk Access "
                 "(System Settings > Privacy & Security > Full Disk Access) and run again")
    return text


def _sha256(full):
    """SHA-256 of a file, read in 1 MiB chunks so a large file never loads whole
    into memory. Returns (hex_digest, size) or raises OSError for the caller to
    count as skipped."""
    problem = path_problem(full)
    if problem:
        raise PermissionError(13, problem, full)
    info = os.stat(full, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode):
        raise OSError("not a regular file")
    size = info.st_size
    h = hashlib.sha256()
    read_bytes = 0
    # Opened without following a link and without blocking, then checked to be
    # the same regular file: a FIFO swapped in after the stat (in /tmp, say)
    # cannot hold a worker thread forever. The same rule as patternscan.
    flags = (os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_NONBLOCK", 0))
    fd = os.open(full, flags)
    try:
        fh = io.open(fd, "rb", closefd=True)
    except Exception:
        os.close(fd)
        raise
    with fh:
        opened = os.fstat(fh.fileno())
        if (not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino)):
            raise OSError("file changed before it was read")
        if hasattr(os, "O_NONBLOCK") and hasattr(os, "get_blocking"):
            os.set_blocking(fh.fileno(), True)
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            read_bytes += len(chunk)
            if read_bytes > MAX_BYTES:
                raise OSError("file exceeded hash read limit")
            h.update(chunk)
    return h.hexdigest(), read_bytes


def _hash_outcomes(candidates, ctx):
    with ThreadPoolExecutor(max_workers=_WORKERS) as pool:
        for start in range(0, len(candidates), 128):
            ctx.emit("[hash] fingerprinted {} / {} candidates".format(start, len(candidates)))
            yield from pool.map(_hash_one, candidates[start:start + 128])


def run(ctx) -> ModuleResult:
    r = ModuleResult(NAME)
    # Publish the result straight away so that if anything below raises,
    # the CLI can still recover whatever was found before the failure
    # instead of discarding it (see ScanContext.partial).
    ctx.partial = r

    # Build the hex-digest -> Indicator map once so each file is a single dict
    # lookup. The hashes come from the IOC set, never hardcoded (ctx.iocs.hashes).
    targets = {ind.value: ind for ind in ctx.iocs.hashes}

    # D3: with nothing to compare against we cannot claim CLEAN. State the gap
    # and stop - an empty target set is UNKNOWN for this check, not clean.
    if not targets:
        r.could_not_run("hash-compare", "no sample hashes in the indicator set")
        return r

    ctx.emit("[hash] looking for {} known sample hash(es)".format(len(targets)))

    for root in (ctx.targets or _roots()):
        problem = path_problem(root)
        if problem:
            r.could_not_run("root:" + root, problem)
            continue
        selected_file = bool(ctx.targets) and os.path.isfile(root)
        if not selected_file and not os.path.isdir(root):
            if ctx.targets:
                r.could_not_run("root:" + root, "target disappeared or is not a regular file/directory")
            continue
        # The full path, not the basename: %TEMP% and %SystemRoot%\Temp both end
        # in "Temp", and two roots collapsing to one name would make the check
        # list lie about what was actually covered.
        #
        # The verdict for this root is decided AFTER the walk, not before it.
        # Marking it as a check that ran up front meant a root where every
        # candidate file failed to open still counted as a clean, completed
        # check: nothing was fingerprinted, nothing was reported, and the scan
        # said CLEAN with no gap. A file that could not be read has not been
        # cleared of anything (D3).
        ctx.emit("[hash] scanning {} ...".format(root))
        # Files that were found but not compared, and folders or items the walk
        # could not open, are counted apart. A refused folder is not a candidate
        # file: adding it to the file tally made a root holding one readable
        # file and three refused folders report "3 of 1 candidate file(s)".
        tally = {"hashed": 0, "candidates": 0, "unreadable": 0, "unopened": 0}
        reasons = {"large": 0, "denied": 0, "unreadable": 0, "cloud": 0}
        walk_reasons = {"large": 0, "denied": 0, "unreadable": 0, "cloud": 0}

        def _walk_err(exc, _r=r, _t=tally, _w=walk_reasons):
            # Links and special entries are refused by the walker on purpose:
            # not files that were missed (a link's target is fingerprinted where
            # it lies inside a scanned folder), so they are counted, not gaps.
            if getattr(exc, "strerror", None) == WALK_CLOUD_SKIPPED:
                _r.skipped += 1
                _t["unopened"] += 1
                _w["cloud"] += 1
                return
            if getattr(exc, "strerror", None) in (WALK_LINK_REFUSED, WALK_SPECIAL_REFUSED):
                key = "links_not_followed" if exc.strerror == WALK_LINK_REFUSED else "special_entries"
                _r.submetrics[key] = _r.submetrics.get(key, 0) + 1
                return
            # An unreadable subtree would otherwise vanish silently from os.walk.
            _r.skipped += 1
            _t["unopened"] += 1
            _w["denied" if isinstance(exc, PermissionError) else "unreadable"] += 1

        candidates = [root] if selected_file else []
        for dirpath, dirs, files in ([] if selected_file else walk_local(root, onerror=_walk_err)):
            # Prune noisy / huge subtrees in place so os.walk never descends them.
            if not ctx.full and not ctx.targets:
                dirs[:] = [d for d in dirs if d.lower() not in PRUNE_DIRS]
            for fn in files:
                if ctx.full or ctx.targets or _hs_candidate(os.path.join(dirpath, fn), fn):
                    candidates.append(os.path.join(dirpath, fn))
        tally["candidates"] += len(candidates)

        # Fingerprinting is file reading plus hashing, both of which release
        # Python's interpreter lock, so several files are done at once. Results
        # are consumed in the original walk order, so the report is identical to
        # the one-at-a-time version (2026-10-25: 7 min for 45k files before).
        for full, digest, size, reason in _hash_outcomes(candidates, ctx):
            if reason in ("link", "special"):
                tally["candidates"] -= 1
                key = "links_not_followed" if reason == "link" else "special_entries"
                r.submetrics[key] = r.submetrics.get(key, 0) + 1
                continue
            if digest is None:
                # Locked, permission-denied, refused or over the size cap:
                # skipped, never clean (D3).
                r.skipped += 1
                tally["unreadable"] += 1
                reasons[reason] += 1
                continue

            tally["hashed"] += 1
            r.checked += 1
            r.submetrics["files_hashed"] = r.submetrics.get("files_hashed", 0) + 1
            r.submetrics["bytes_hashed"] = r.submetrics.get("bytes_hashed", 0) + size

            ind = targets.get(digest)
            if ind is not None:
                # EV_ON_DISK is the whole point: a file whose fingerprint
                # matches a published sample is conclusive. Without an
                # evidence grade the report defaulted it to "referenced" and
                # told the reader it was "probably not a sign of compromise" -
                # over a known spyware binary sitting on their disk.
                r.add_hit(Hit(
                    indicator=digest,
                    location=full,
                    detail="this file's SHA-256 matches a published sample: "
                           + ind.value,
                    tier=ind.tier,
                    confidence=ind.confidence,
                    source=ind.source,
                    family=ind.family,
                    evidence=EV_ON_DISK,
                ))
                ctx.emit("[hash] !! MATCH {} ({})".format(full, ind.value))

        # Now say honestly what this root amounted to.
        name = "root:" + root
        missed = []
        if tally["unreadable"]:
            file_reasons = _hs_reasons(reasons, fix=not walk_reasons["denied"])
            if tally["hashed"]:
                missed.append("{} of {} candidate file(s) under this root were not compared "
                              "against the known hashes ({})".format(
                                  tally["unreadable"], tally["candidates"], file_reasons))
            else:
                # Candidates existed but not one could be fingerprinted: this
                # root was not searched at all, however many files it holds.
                missed.append("no file under this root could be fingerprinted "
                              "({} candidate file(s): {})".format(tally["unreadable"], file_reasons))
        if tally["unopened"]:
            # How many files a refused folder holds is unknown, so it is
            # counted as a folder, never as a number of files.
            missed.append("{} folder(s) or item(s) under this root could not be opened, so "
                          "nothing in them was compared ({})".format(
                              tally["unopened"], _hs_reasons(walk_reasons)))
        if tally["hashed"]:
            r.ran(name)
            if missed:
                r.could_not_run(name + " (partial)", "; ".join(missed))
        elif missed:
            r.could_not_run(name, "; ".join(missed))
        else:
            # Walked cleanly, held nothing to fingerprint. Genuinely covered.
            r.ran(name)

    if r.submetrics.get("links_not_followed"):
        r.note("{:,} link(s) (aliases such as app framework shortcuts) were not followed; the files "
               "they point to are fingerprinted where they lie inside a scanned folder.".format(
                   r.submetrics["links_not_followed"]))
    return r
