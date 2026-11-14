"""Refuse Windows remote drives and filesystem redirections before reads.

Checks are conservative and use lstat so a reparse point is inspected rather
than followed. POSIX network mounts cannot always be distinguished from local
paths here. This is not a sandbox against concurrent filesystem changes.
"""

import os
import posixpath
import shutil
import ssl
import stat
import sys
import time


def local_temp_dir():
    """Select a local temp directory without tempfile's write-probing fallback."""
    candidates = [os.environ.get(key, "") for key in ("TMPDIR", "TEMP", "TMP")]
    if sys.platform == "win32":
        candidates.extend(os.path.join(base, "Temp") for base in
                          (os.environ.get("LOCALAPPDATA", ""),
                           os.environ.get("SystemRoot", "")) if base)
    else:
        candidates.extend(("/tmp", "/var/tmp", "/private/tmp"))
    for candidate in candidates:
        if candidate and not path_problem(candidate) and os.path.isdir(candidate):
            return candidate
    raise PermissionError("no safe local temporary directory is available")


def path_problem(path):
    """Return why a path cannot safely be inspected, or an empty string."""
    path = os.fspath(path)
    if not os.path.isabs(path):
        return "relative path cannot be classified as local"
    if ".." in path.replace("\\", "/").split("/"):
        return "parent-directory traversal cannot be classified as local"
    if sys.platform == "win32":
        s = path.replace("/", "\\")
        if s.startswith("\\\\"):
            return "UNC or device path was not opened"
        drive, _tail = os.path.splitdrive(s)
        if len(drive) != 2 or drive[1] != ":":
            return "path does not name an absolute local drive"
        try:
            import ctypes
            kind = ctypes.windll.kernel32.GetDriveTypeW(drive + "\\")
        except (AttributeError, OSError):
            return "drive locality could not be established"
        if kind not in (2, 3, 5, 6):  # removable, fixed, CD-ROM, RAM disk
            return "drive is remote or its locality is unknown"

    drive, tail = os.path.splitdrive(path)
    current = drive + os.sep
    # Windows accepts both separators, so both must split the path, or a junction
    # in a forward-slash path would never be inspected. On POSIX a backslash is an
    # ordinary filename character.
    if sys.platform == "win32":
        tail = tail.replace("/", "\\")
    parts = [p for p in tail.split(os.sep) if p]
    for index, part in enumerate(parts):
        current = os.path.join(current, part)
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            return ""  # caller handles a genuinely absent artifact
        except OSError as exc:
            return "cannot safely inspect {}: {}".format(current, exc)
        if cloud_placeholder(info):
            # A OneDrive (or other cloud-files) folder: it redirects nowhere,
            # so it is read in place unless reading would download it.
            if getattr(info, "st_file_attributes", 0) & _CLOUD_ONLY_ATTRIBUTES:
                return "{} is stored only in OneDrive or iCloud and was not downloaded".format(current)
            continue
        if (stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & 0x400):
            # macOS exposes its standard /var, /tmp and /etc directories through
            # root-owned aliases into /private. These exact system aliases are
            # safe to validate lexically; arbitrary user links remain refused.
            # readlink reads the link itself and does not traverse its target.
            # Apple's signed cryptexes (Safari's and WebKit's launch agents live
            # in the App one) are reached the same way, through root-owned
            # links into the Preboot volume.
            aliases = {"/var": "/private/var", "/tmp": "/private/tmp",
                       "/etc": "/private/etc",
                       "/System/Cryptexes/App": "/System/Volumes/Preboot/Cryptexes/App",
                       "/System/Cryptexes/OS": "/System/Volumes/Preboot/Cryptexes/OS"}
            target = aliases.get(current) if sys.platform == "darwin" else None
            if (target and stat.S_ISLNK(info.st_mode)
                    and getattr(info, "st_uid", None) == 0):
                try:
                    link = os.readlink(current)
                except OSError as exc:
                    return "cannot inspect system alias {}: {}".format(current, exc)
                # Apple's links commonly use 'private/var', relative to '/', or
                # '../../System/Volumes/...' relative to the link's folder.
                # Accept only spellings that name exactly the expected target.
                relative = posixpath.normpath(posixpath.join(posixpath.dirname(current), link))
                if link in (target, target.lstrip("/")) or relative == target:
                    canonical = os.path.join(target, *parts[index + 1:])
                    return path_problem(canonical)
            return "symlink or reparse point was not followed: {}".format(current)
    return ""


def path_problem_cached(path, cache):
    """path_problem for many files in turn, re-checking each file's folders only
    when the folder changes.

    path_problem inspects every folder from the drive down, one disk lookup per
    level. A walk lists thousands of files in the same folder, so checking each
    of them in full repeated the same lookups thousands of times (most of the
    browser check's time). Here the folder is checked in full once, then each
    file is checked on its own. Any file that is a link, a reparse point, a cloud
    placeholder or otherwise unusual gets the full check, so the answer is always
    what path_problem would give. `cache` is a one-item list owned by the caller
    for one walk; reading and replacing its single tuple is safe across threads.
    """
    path = os.fspath(path)
    parent, name = os.path.split(path)
    if not parent or name in ("", ".", ".."):
        return path_problem(path)
    known = cache[0]
    if known is not None and known[0] == parent:
        problem = known[1]
    else:
        problem = path_problem(parent)
        cache[0] = (parent, problem)
    return problem or _last_part_problem(path)


def _last_part_problem(path):
    """path_problem for a path whose folder is already known to be safe: only
    the last part is looked at, and anything unusual gets the full check."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return ""  # caller handles a genuinely absent artifact
    except OSError as exc:
        return "cannot safely inspect {}: {}".format(path, exc)
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & 0x400):
        return path_problem(path)
    return ""


WALK_LINK_REFUSED = "symlink or reparse point was not followed"
WALK_SPECIAL_REFUSED = "special filesystem entry was not opened"
WALK_CLOUD_SKIPPED = "stored only in iCloud or OneDrive and was not downloaded"
# Windows marks OneDrive online-only files with these attributes; opening one
# downloads it first (RECALL_ON_DATA_ACCESS, RECALL_ON_OPEN, OFFLINE).
_CLOUD_ONLY_ATTRIBUTES = 0x00400000 | 0x00040000 | 0x00001000
# macOS marks iCloud placeholders ("Optimise Mac Storage") with this flag; reading or
# listing one makes macOS download it first, which can stall a scan for hours.
SF_DATALESS = 0x40000000

# Windows cloud-files placeholders (OneDrive, iCloud for Windows and other sync
# clients) carry an IO_REPARSE_TAG_CLOUD_* tag: 0x9000001A with any of the 16
# sub-type values in bits 12-15. Unlike a link or junction, the tag does not
# redirect anywhere: the file or folder is read where it is. Whether reading
# would download it is told by the recall and offline attributes above.
_CLOUD_TAG_MASK = 0xFFFF0FFF
_CLOUD_TAG = 0x9000001A


def cloud_placeholder(info):
    """True for a Windows cloud-files placeholder (see _CLOUD_TAG)."""
    return bool(getattr(info, "st_file_attributes", 0) & 0x400) and (
        getattr(info, "st_reparse_tag", 0) & _CLOUD_TAG_MASK) == _CLOUD_TAG


# Folders a scan creates in the temporary directory. They hold private copies
# (decrypted iPhone databases, browser databases with cookie values, indicator
# files) and are removed when a scan ends, but a crash, a hard kill or a power
# cut leaves them behind.
STALE_TEMP_PREFIXES = ("zbt_ios_", "bscan_", "adint_ioc_", "zbt_ioc2_", "zb-bugreport-")
STALE_TEMP_AGE = 12 * 3600


def sweep_stale_temp(max_age=STALE_TEMP_AGE, now=None, base=None):
    """Remove this tool's temporary folders left by an earlier scan that did
    not finish. Only plain folders with the tool's prefixes, owned by this user
    (on Windows the temporary directory is already per user), and untouched for
    max_age seconds, so a scan running at the same time is never disturbed.
    Returns {"removed": count, "failed": [paths that are still there]}."""
    out = {"removed": 0, "failed": []}
    try:
        base = base or local_temp_dir()
        entries = list(os.scandir(base))
    except OSError:
        return out
    now = time.time() if now is None else now
    for entry in entries:
        if not entry.name.startswith(STALE_TEMP_PREFIXES):
            continue
        try:
            info = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if (not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400
                or (hasattr(os, "getuid") and info.st_uid != os.getuid())
                or now - info.st_mtime < max_age):
            continue
        shutil.rmtree(entry.path, ignore_errors=True)
        if os.path.lexists(entry.path):
            out["failed"].append(entry.path)
        else:
            out["removed"] += 1
    return out


def synced_folder(path):
    """The cloud-synced folder `path` lies in (OneDrive, iCloud Drive, or a
    macOS CloudStorage provider), or "". Lexical, plus an lstat of each
    ancestor on Windows to recognise OneDrive placeholder folders; nothing is
    opened or downloaded."""
    full = os.path.normcase(os.path.abspath(path))
    roots = [os.environ.get(key, "") for key in ("OneDrive", "OneDriveConsumer", "OneDriveCommercial")]
    home = os.path.expanduser("~")
    roots += [os.path.join(home, "Library", "Mobile Documents"),
              os.path.join(home, "Library", "CloudStorage")]
    for root in roots:
        if not root:
            continue
        norm = os.path.normcase(os.path.abspath(root)).rstrip("\\/")
        if full == norm or full.startswith(norm + os.sep):
            return root
    if sys.platform == "win32":
        current = os.path.dirname(os.path.abspath(path))
        while True:
            try:
                if cloud_placeholder(os.lstat(current)):
                    return current
            except OSError:
                pass
            parent = os.path.dirname(current)
            if parent == current:
                return ""
            current = parent
    return ""


def walk_local(root, onerror=None):
    """Top-down os.walk equivalent that never classifies a link by following it.

    The caller can prune the yielded dirs list in place, as with os.walk.
    Refused entries are delivered to onerror as PermissionError instances whose
    strerror is WALK_LINK_REFUSED or WALK_SPECIAL_REFUSED; any other error is a
    folder or entry that could not be read.
    """
    pending = [root]
    # What each folder's check found, so a subfolder only needs its own last part
    # looked at: its parent was checked in full (or from its own parent) when it
    # was opened, instead of every level again for every folder.
    checked = {}
    while pending:
        current = pending.pop()
        try:
            parent = os.path.dirname(current)
            if current != root and parent in checked:
                problem = checked[parent] or _last_part_problem(current)
            else:
                problem = path_problem(current)
            checked[current] = problem
            if problem:
                raise PermissionError(13, problem, current)
            dirs, files = [], []
            with os.scandir(current) as entries:
                for entry in entries:
                    try:
                        info = entry.stat(follow_symlinks=False)
                        attributes = getattr(info, "st_file_attributes", 0)
                        if attributes & 0x400 and attributes & _CLOUD_ONLY_ATTRIBUTES:
                            raise PermissionError(13, WALK_CLOUD_SKIPPED, entry.path)
                        if stat.S_ISLNK(info.st_mode) or (attributes & 0x400 and
                                                          not cloud_placeholder(info)):
                            raise PermissionError(13, WALK_LINK_REFUSED, entry.path)
                        if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                            raise PermissionError(13, WALK_SPECIAL_REFUSED, entry.path)
                        if stat.S_ISDIR(info.st_mode) and getattr(info, "st_flags", 0) & SF_DATALESS:
                            raise PermissionError(13, WALK_CLOUD_SKIPPED, entry.path)
                        (dirs if stat.S_ISDIR(info.st_mode) else files).append(entry.name)
                    except OSError as exc:
                        if onerror:
                            onerror(exc)
        except OSError as exc:
            if onerror:
                onerror(exc)
            continue
        yield current, dirs, files
        pending.extend(os.path.join(current, d) for d in reversed(dirs))


def open_evidence_db(path):
    """Open the tool's private temporary copy of an evidence database, hardened
    the same way for every reader: schema-defined functions and views are not
    trusted, nothing can be written, and string/blob, column and expression
    sizes are bounded so a hostile database cannot exhaust memory or the stack.
    Callers query only; the live original is never opened here."""
    import sqlite3
    con = sqlite3.connect(path)
    try:
        con.execute("PRAGMA trusted_schema=OFF")
        con.execute("PRAGMA query_only=ON")
        con.execute("PRAGMA mmap_size=0")
        if hasattr(con, "setlimit"):  # Python 3.11+
            con.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, 2 * 1024 * 1024)
            con.setlimit(sqlite3.SQLITE_LIMIT_COLUMN, 256)
            con.setlimit(sqlite3.SQLITE_LIMIT_EXPR_DEPTH, 100)
    except sqlite3.Error:
        con.close()
        raise
    return con


def is_packaged():
    """True when running as the packaged program (Windows .exe, Mac app, Linux
    program); False when run as a Python script."""
    return bool(getattr(sys, "frozen", False))


def mac_has_full_disk_access():
    """True on a Mac when this program can list Safari's folder, which macOS only
    allows with Full Disk Access. Then advice to turn it on would be wrong: what
    is still closed stays closed either way."""
    if sys.platform != "darwin":
        return False
    try:
        os.listdir(os.path.join(os.path.expanduser("~"), "Library", "Safari"))
    except OSError:
        return False
    return True


def mac_privacy_app():
    """What a Mac person gives Full Disk Access to: the app, or Terminal."""
    return "Zero Breach Toolkit" if is_packaged() else "Terminal"


# Where systems keep their trusted root certificates. A bundled OpenSSL looks in
# one fixed place (Debian's), so on other systems it can find none.
TLS_CA_BUNDLES = (
    "/etc/ssl/certs/ca-certificates.crt",
    "/etc/pki/tls/certs/ca-bundle.crt",
    "/etc/ssl/ca-bundle.pem",
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
    "/etc/ssl/cert.pem",
    "/usr/local/etc/openssl/cert.pem",
    "/opt/homebrew/etc/openssl@3/cert.pem",
)


def tls_context():
    """The default HTTPS context. If it loaded no trusted root certificates (a
    bundled OpenSSL on Fedora, Arch or a Mac app), add the system's own bundle.
    Verification is never turned off."""
    ctx = ssl.create_default_context()
    try:
        have = ctx.cert_store_stats().get("x509_ca", 0)
    except (AttributeError, ssl.SSLError):
        have = 0
    if have == 0:
        for path in TLS_CA_BUNDLES:
            if os.path.isfile(path):
                try:
                    ctx.load_verify_locations(cafile=path)
                    break
                except (ssl.SSLError, OSError):
                    continue
    return ctx
