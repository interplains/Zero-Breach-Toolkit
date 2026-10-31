"""Search this machine's browser artifacts for AdFection / Candiru IOC domains.

Why several artifact types and not just history: browser HISTORY only records
top-level navigations, and an ad is a subresource inside an iframe. A real
AdFection impression would almost certainly never appear in history. The HTTP
cache, the cookie stores and the local-storage LevelDB files do record
subresource origins, so they are where a retrospective trace would actually
survive.

Read-only. Databases are copied before being opened, because a running browser
holds a write lock on them; the copy is opened and the temp dir is always
cleaned up. No network, ever (CONTRACT D2) - needles are matched as plain
substrings and never resolved.

Honest gaps (CONTRACT D3). A browser's databases are often locked because the
browser is running. That is NOT a clean result, it is a gap: there was somewhere
to look and we could not look there. So this module tracks, per (browser label,
artifact kind), whether at least one profile could actually be read. A kind that
was present somewhere but could never be read is reported with
`r.could_not_run(...)`, which the verdict reads as a gap - rather than being
silently swallowed into a clean roll-up. A kind that is simply ABSENT (the
browser never created that artifact) is not a gap and is recorded as nothing at
all. A browser whose every database was locked therefore rolls up to
PARTIAL/UNKNOWN with those gaps named, never to CLEAN.
"""

from __future__ import annotations

import base64
import collections
import contextlib
import datetime
import hashlib
import io
import json
import os
import re
import shutil
import sqlite3
import plistlib
import stat
import struct
import sys
import tempfile
import time
from urllib.parse import urlsplit
from ..ios_sources import _is_wal_prefix
from ..localpaths import (WALK_LINK_REFUSED, WALK_SPECIAL_REFUSED, local_temp_dir, open_evidence_db,
                          path_problem, walk_local)

from ..result import (Hit, Lead, ModuleResult, EV_ON_DISK, EV_PERSISTENCE,
                      EV_CONTACTED, EV_ATTEMPTED, EV_CONFIGURED, EV_REFERENCED)

NAME = "browser"

LOCAL = os.environ.get("LOCALAPPDATA", "")
ROAMING = os.environ.get("APPDATA", "")


def _browser_packages(prefix):
    """Installed Windows app packages whose folder name starts with prefix."""
    folder = os.path.join(LOCAL, "Packages")
    try:
        if not LOCAL or path_problem(folder) or not os.path.isdir(folder):
            return []
        with os.scandir(folder) as entries:
            return sorted(e.name for e in entries if e.name.startswith(prefix) and e.is_dir(follow_symlinks=False))
    except OSError:
        return []


def _snap_revision(snap, app):
    """The folder a snap's "current" link names (~/snap/<app>/<revision>), found by
    reading the link rather than following it; "" when there is none. The target
    must be a plain revision name in the same folder."""
    current = os.path.join(snap, app, "current")
    try:
        target = os.readlink(current)
    except (OSError, ValueError, NotImplementedError):
        return ""
    if not target or os.sep in target or (os.altsep and os.altsep in target) or target in (".", ".."):
        return ""
    folder = os.path.join(snap, app, target)
    return folder if os.path.isdir(folder) and not os.path.islink(folder) else ""


def _chromium_roots():
    """Chromium user-data roots as (label, path), chosen by platform.

    The label names the browser in each per-artifact sub-check, so an
    installed-but-clean browser is recorded distinctly from an absent one, and a
    locked artifact names the browser it belongs to. Tests override the roots by
    patching CHROMIUM_ROOTS / FIREFOX_ROOTS directly (not by patching LOCAL /
    ROAMING), so the suite is hermetic on every platform, never the tester's own
    browser.
    """
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        return [
            ("chrome", os.path.join(LOCAL, "Google", "Chrome", "User Data")),
            ("edge", os.path.join(LOCAL, "Microsoft", "Edge", "User Data")),
            ("brave", os.path.join(LOCAL, "BraveSoftware", "Brave-Browser",
                                   "User Data")),
            ("chromium", os.path.join(LOCAL, "Chromium", "User Data")),
            ("vivaldi", os.path.join(LOCAL, "Vivaldi", "User Data")),
            ("chrome-beta", os.path.join(LOCAL, "Google", "Chrome Beta", "User Data")),
            ("chrome-dev", os.path.join(LOCAL, "Google", "Chrome Dev", "User Data")),
            ("chrome-canary", os.path.join(LOCAL, "Google", "Chrome SxS", "User Data")),
            ("edge-beta", os.path.join(LOCAL, "Microsoft", "Edge Beta", "User Data")),
            ("edge-dev", os.path.join(LOCAL, "Microsoft", "Edge Dev", "User Data")),
            ("edge-canary", os.path.join(LOCAL, "Microsoft", "Edge SxS", "User Data")),
            ("brave-beta", os.path.join(LOCAL, "BraveSoftware", "Brave-Browser-Beta", "User Data")),
            ("brave-nightly", os.path.join(LOCAL, "BraveSoftware", "Brave-Browser-Nightly", "User Data")),
            # Opera keeps the profile itself in Roaming (its cache in Local).
            ("opera", os.path.join(ROAMING, "Opera Software", "Opera Stable")),
            ("opera-gx", os.path.join(ROAMING, "Opera Software", "Opera GX Stable")),
            ("yandex", os.path.join(LOCAL, "Yandex", "YandexBrowser", "User Data")),
        ] + [("arc", os.path.join(LOCAL, "Packages", name, "LocalCache", "Local", "Arc", "User Data"))
             for name in _browser_packages("TheBrowserCompany.Arc_")]
    if sys.platform == "darwin":
        asup = os.path.join(home, "Library", "Application Support")
        return [
            ("chrome", os.path.join(asup, "Google", "Chrome")),
            ("edge", os.path.join(asup, "Microsoft Edge")),
            ("brave", os.path.join(asup, "BraveSoftware", "Brave-Browser")),
            ("chromium", os.path.join(asup, "Chromium")),
            ("vivaldi", os.path.join(asup, "Vivaldi")),
            ("chrome-beta", os.path.join(asup, "Google", "Chrome Beta")),
            ("chrome-dev", os.path.join(asup, "Google", "Chrome Dev")),
            ("chrome-canary", os.path.join(asup, "Google", "Chrome Canary")),
            ("edge-beta", os.path.join(asup, "Microsoft Edge Beta")),
            ("edge-dev", os.path.join(asup, "Microsoft Edge Dev")),
            ("edge-canary", os.path.join(asup, "Microsoft Edge Canary")),
            ("brave-beta", os.path.join(asup, "BraveSoftware", "Brave-Browser-Beta")),
            ("brave-nightly", os.path.join(asup, "BraveSoftware", "Brave-Browser-Nightly")),
            ("opera", os.path.join(asup, "com.operasoftware.Opera")),
            ("opera-gx", os.path.join(asup, "com.operasoftware.OperaGX")),
            ("arc", os.path.join(asup, "Arc", "User Data")),
            ("yandex", os.path.join(asup, "Yandex", "YandexBrowser")),
        ]
    if sys.platform.startswith("linux"):
        cfg = os.environ.get("XDG_CONFIG_HOME", "")
        cfg = cfg if os.path.isabs(cfg) else os.path.join(home, ".config")
        var = os.path.join(home, ".var", "app")
        snap = os.path.join(home, "snap")
        # Snap apps other than Chromium keep their data in a numbered revision
        # folder (~/snap/brave/<rev>/.config/...); "current" is only a link to it.
        snapped = [(label, os.path.join(_snap_revision(snap, app), *rest))
                   for label, app, rest in (
                       ("brave-snap", "brave", (".config", "BraveSoftware", "Brave-Browser")),
                       ("opera-snap", "opera", (".config", "opera")),
                       ("vivaldi-snap", "vivaldi", (".config", "vivaldi")),
                       ("chromium-snap-revision", "chromium", (".config", "chromium")))
                   if _snap_revision(snap, app)]
        return snapped + [
            ("chrome", os.path.join(cfg, "google-chrome")),
            ("chromium", os.path.join(cfg, "chromium")),
            ("brave", os.path.join(cfg, "BraveSoftware", "Brave-Browser")),
            ("edge", os.path.join(cfg, "microsoft-edge")),
            ("vivaldi", os.path.join(cfg, "vivaldi")),
            ("vivaldi-snapshot", os.path.join(cfg, "vivaldi-snapshot")),
            ("chrome-beta", os.path.join(cfg, "google-chrome-beta")),
            ("chrome-dev", os.path.join(cfg, "google-chrome-unstable")),
            ("edge-beta", os.path.join(cfg, "microsoft-edge-beta")),
            ("edge-dev", os.path.join(cfg, "microsoft-edge-dev")),
            ("brave-beta", os.path.join(cfg, "BraveSoftware", "Brave-Browser-Beta")),
            ("brave-nightly", os.path.join(cfg, "BraveSoftware", "Brave-Browser-Nightly")),
            ("opera", os.path.join(cfg, "opera")),
            ("opera-beta", os.path.join(cfg, "opera-beta")),
            ("yandex", os.path.join(cfg, "yandex-browser")),
            ("edge-flatpak", os.path.join(var, "com.microsoft.Edge", "config", "microsoft-edge")),
            # snap packaging
            ("chromium-snap", os.path.join(snap, "chromium", "common", "chromium")),
            # flatpak packaging
            ("chrome-flatpak", os.path.join(var, "com.google.Chrome", "config",
                                            "google-chrome")),
            ("brave-flatpak", os.path.join(var, "com.brave.Browser", "config",
                                           "BraveSoftware", "Brave-Browser")),
            ("chromium-flatpak", os.path.join(var, "org.chromium.Chromium",
                                              "config", "chromium")),
            ("vivaldi-flatpak", os.path.join(var, "com.vivaldi.Vivaldi",
                                             "config", "vivaldi")),
        ]
    return []


# Computed at import so the test-suite can monkeypatch this attribute directly.
CHROMIUM_ROOTS = _chromium_roots()
_DEFAULT_CHROMIUM_ROOTS = CHROMIUM_ROOTS


def _browser_below(path, base):
    """Path components of path strictly below base, or None (no resolution)."""
    try:
        relative = os.path.relpath(path, base)
    except ValueError:
        return None
    if (relative in (os.curdir, os.pardir) or relative.startswith(os.pardir + os.sep)
            or os.path.isabs(relative)):
        return None
    return relative.split(os.sep)


def _browser_cache_profile(profile):
    """Map a profile to Chromium's platform cache location without resolving it."""
    home = os.path.expanduser("~")
    if sys.platform.startswith("linux"):
        # Flatpak gives each app its own configuration and cache folders
        # (~/.var/app/<app>/config and .../cache); snap packages keep theirs
        # under ~/snap/<app>/common and its .cache folder.
        parts = _browser_below(profile, os.path.join(home, ".var", "app"))
        if parts and len(parts) > 2 and parts[1] == "config":
            return os.path.normpath(os.path.join(home, ".var", "app", parts[0], "cache", *parts[2:]))
        parts = _browser_below(profile, os.path.join(home, "snap"))
        if parts and len(parts) > 2 and parts[1] == "common" and parts[2] != ".cache":
            return os.path.normpath(os.path.join(home, "snap", parts[0], "common", ".cache", *parts[2:]))
        config = os.environ.get("XDG_CONFIG_HOME", "")
        cache = os.environ.get("XDG_CACHE_HOME", "")
        config = config if os.path.isabs(config) else os.path.join(home, ".config")
        cache = cache if os.path.isabs(cache) else os.path.join(home, ".cache")
    elif sys.platform == "darwin":
        config = os.path.join(home, "Library", "Application Support")
        cache = os.path.join(home, "Library", "Caches")
    elif (sys.platform == "win32" and ROAMING and LOCAL
          and _browser_below(profile, os.path.join(ROAMING, "Opera Software"))):
        # Chromium browsers and desktop apps keep their cache inside the
        # profile; Opera alone keeps the profile in Roaming, its cache in Local.
        config, cache = ROAMING, LOCAL
    else:
        return profile
    try:
        relative = os.path.relpath(profile, config)
    except ValueError:
        return profile
    if relative == os.pardir or relative.startswith(os.pardir + os.sep) or os.path.isabs(relative):
        return profile
    return os.path.normpath(os.path.join(cache, relative))


def _browser_cache_in_scope(path, targets):
    if not targets:
        return True
    for target in targets:
        # Explicit browser databases select their profile, but never a cache
        # elsewhere in the user's home directory.
        base = os.path.abspath(target)
        if os.path.isfile(base):
            base = os.path.dirname(base) if os.path.basename(base).lower() in _TARGET_DB_FILES else base
        try:
            if os.path.commonpath((os.path.abspath(path), base)) == base:
                return True
        except ValueError:
            continue
    return False

# Desktop apps with a built-in Chromium browser (Slack, Teams, Discord, WhatsApp,
# VS Code, Opera, Steam's store...). A link clicked or previewed inside them
# leaves the same cookies, cache and storage a browser does. None = discover at
# run() time. Discovery runs ONLY while CHROMIUM_ROOTS is the platform default:
# a caller that sets the roots (a test, the release fixture) has made the scope
# explicit, so nothing on the real machine is discovered behind its back.
APP_ROOTS = None
# App data folders are walked without a depth limit: real profiles sit as deep
# as six levels below AppData, and any fixed depth silently missed deeper ones.
# The walk is bounded by folder count and time instead, and running out of
# either is a reported gap.
_APP_MAX_FOLDERS = 400000
_APP_MAX_SECONDS = 120
_APP_SKIP = {"temp", "node_modules", ".git", "__pycache__", "crashdumps", "inetcache",
             "d3dscache", "cache", "cache_data", "code cache", "gpucache", "logs"}
_APP_GENERIC = {"microsoft", "google", "programs"}
_PROFILE_MARKERS = (("History",), ("History.db",), ("Bookmarks",), ("Network", "Cookies"), ("Cookies",), ("Local Storage", "leveldb"))


def _looks_like_profile(path):
    """A Chromium profile's own files, as an Electron app keeps them directly in
    its data folder (no Default/ subfolder)."""
    return any(not path_problem(os.path.join(path, *m)) and os.path.exists(os.path.join(path, *m))
               for m in _PROFILE_MARKERS)


# A person selecting "the browser folder" rarely picks the exact profile: the
# browser's own folder, the History file or Firefox's Profiles folder are just
# as likely. Each of those used to be silently skipped, which read as clean.
_TARGET_DB_FILES = {"history", "history.db", "bookmarks", "cookies", "favicons", "web data", "network persistent state",
                    "transportsecurity", "places.sqlite", "cookies.sqlite", "favicons.sqlite"}
_TARGET_SEARCH_DEPTH = 6
_TARGET_SEARCH_ENTRIES = 20000


def _browser_targeted_roots(selected):
    """(Chromium roots, Firefox profiles, gaps) found in one selected target: the
    target itself, the profile holding a selected browser database file, or
    profiles a few folders down. Links and junctions are never followed; the
    search stops descending once a folder is recognised as a browser profile.
    Every place the search had to stop is returned as a gap, because a profile
    below it was not checked - stopping silently would read as clean."""
    chromium, firefox, gaps = [], [], []
    if path_problem(selected):
        return chromium, firefox, gaps
    if os.path.isfile(selected) and os.path.basename(selected).lower() in _TARGET_DB_FILES:
        selected = os.path.dirname(selected)
    if not os.path.isdir(selected):
        return chromium, firefox, gaps
    pending, seen = [(selected, 0)], 0
    too_deep, unreadable, links = [], [], 0
    while pending:
        folder, depth = pending.pop()
        try:
            if _is_ff_profile_dir(folder):
                firefox.append(folder)
                continue
            if chromium_profiles(folder) or _looks_like_profile(folder):
                chromium.append(folder)
                continue
        except OSError:
            unreadable.append(folder)
            continue
        try:
            with os.scandir(folder) as entries:
                for entry in entries:
                    seen += 1
                    if seen > _TARGET_SEARCH_ENTRIES:
                        gaps.append("browser profile search inside {} stopped at its entry "
                                    "limit; profiles deeper in it were not checked".format(selected))
                        return chromium, firefox, gaps
                    if not entry.is_dir(follow_symlinks=False):
                        if entry.is_symlink() or path_problem(entry.path):
                            links += 1
                        continue
                    if path_problem(entry.path):
                        links += 1
                    elif depth >= _TARGET_SEARCH_DEPTH:
                        too_deep.append(entry.path)
                    else:
                        pending.append((entry.path, depth + 1))
        except OSError:
            unreadable.append(folder)
    if too_deep:
        gaps.append("browser profile search inside {} stops {} folders down; {} deeper folder(s) "
                    "were not checked (for example {}) - select a deeper folder to include "
                    "them".format(selected, _TARGET_SEARCH_DEPTH, len(too_deep), too_deep[0]))
    if unreadable:
        gaps.append("browser profile search inside {}: {} folder(s) could not be read (for "
                    "example {})".format(selected, len(unreadable), unreadable[0]))
    if links:
        gaps.append("browser profile search inside {}: {} link(s) or junction(s) were not "
                    "followed".format(selected, links))
    return chromium, firefox, gaps


def _app_label(base, path, taken):
    parts = os.path.relpath(path, base).split(os.sep)
    if parts[0].lower() == "packages" and len(parts) > 1:
        name = parts[1].split("_")[0]          # MSTeams_8wekyb3d8bbwe -> MSTeams
    elif parts[0].lower() in _APP_GENERIC and len(parts) > 1:
        name = parts[0] + "-" + parts[1]
    elif len(parts) > 1 and parts[1].lower().startswith(parts[0].lower()):
        name = parts[1]                        # Proton\Proton Drive -> Proton Drive
    else:
        name = parts[0]
    label, n = "app:" + name.lower(), 2
    while label in taken:
        label, n = "app:{}-{}".format(name.lower(), n), n + 1
    taken.add(label)
    return label


# Folders the operating system itself locks and that never hold an app's web
# data: unreadable as an ordinary user on a healthy machine, so they are not a
# coverage gap. Apple's own com.apple.* data under Application Support is
# skipped for the same reason (much of it is privacy-protected).
_APP_OS_LOCKED = {"elevateddiagnostics"}
_APP_MAC_SKIP = {"mobilesync", "addressbook", "callhistorydb", "callhistorytransactions",
                 "knowledge", "facetime", "fileprovider", "clouddocs"}


def _app_bases():
    """Where desktop apps keep their Chromium data on this platform."""
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        return [ROAMING, LOCAL]
    if sys.platform == "darwin":
        return [os.path.join(home, "Library", "Application Support")]
    if sys.platform.startswith("linux"):
        cfg = os.environ.get("XDG_CONFIG_HOME", "")
        cfg = cfg if os.path.isabs(cfg) else os.path.join(home, ".config")
        bases = [cfg]
        # Each Flatpak app has its own configuration folder.
        flatpak = os.path.join(home, ".var", "app")
        try:
            if not path_problem(flatpak) and os.path.isdir(flatpak):
                with os.scandir(flatpak) as entries:
                    bases += sorted(os.path.join(entry.path, "config") for entry in entries
                                    if entry.is_dir(follow_symlinks=False))
        except OSError:
            bases.append(flatpak)  # reported as unreadable by the walk below
        return bases
    return []


def _app_cache_bases():
    """Where those apps keep their separate caches (on Windows they are under
    LOCAL, which _app_bases already lists)."""
    home = os.path.expanduser("~")
    if sys.platform == "darwin":
        return [os.path.join(home, "Library", "Caches")]
    if sys.platform.startswith("linux"):
        cache = os.environ.get("XDG_CACHE_HOME", "")
        bases = [cache if os.path.isabs(cache) else os.path.join(home, ".cache")]
        flatpak = os.path.join(home, ".var", "app")
        try:
            if not path_problem(flatpak) and os.path.isdir(flatpak):
                with os.scandir(flatpak) as entries:
                    bases += sorted(os.path.join(entry.path, "cache") for entry in entries
                                    if entry.is_dir(follow_symlinks=False))
        except OSError:
            pass
        return bases
    return []


def _app_roots(gaps=None):
    """(label, path) for every Chromium data folder in the platform's app data
    folders that is not one of the browsers above. Found by what a folder
    CONTAINS ('Local State' plus a profile), not by a list of app names, so apps
    nobody listed are covered. Folders that could not be read are appended to
    gaps (when given) as one reason: an unreadable folder may hold an app."""
    known = {os.path.normcase(os.path.abspath(p)) for _l, p in CHROMIUM_ROOTS}
    found, taken, unreadable = [], set(), []
    folders, deadline, stopped = 0, time.monotonic() + _APP_MAX_SECONDS, None

    def onerror(exc):
        if isinstance(exc, PermissionError) and exc.strerror in (WALK_LINK_REFUSED, WALK_SPECIAL_REFUSED):
            return  # links and special entries are never followed, by design
        name = os.path.basename(str(getattr(exc, "filename", "") or "")).lower()
        if name in _APP_OS_LOCKED:
            return
        unreadable.append(str(getattr(exc, "filename", "") or exc))

    for base in _app_bases():
        if not base or not os.path.lexists(base):
            continue
        if path_problem(base) or not os.path.isdir(base):
            if path_problem(base):
                unreadable.append(base)
            continue
        base_depth = os.path.abspath(base).rstrip("\\/").count(os.sep)
        if stopped:
            stopped[1].append(base)
            continue
        for dirpath, dirs, files in walk_local(base, onerror=onerror):
            folders += 1
            if folders > _APP_MAX_FOLDERS or time.monotonic() > deadline:
                stopped = (dirpath, [base])
                break
            if os.path.normcase(os.path.abspath(dirpath)) in known:
                dirs[:] = []
                continue
            # Most apps keep a Chromium "Local State" beside their profile; some
            # (Signal on macOS) keep the profile itself as the app folder, with
            # its Preferences but no Local State.
            if (("Local State" in files and ("Default" in dirs or _looks_like_profile(dirpath)))
                    or ("Preferences" in files and "Local State" not in files and _looks_like_profile(dirpath)
                        and ("Network Persistent State" in files or "IndexedDB" in dirs))):
                found.append((_app_label(base, dirpath, taken), dirpath))
                dirs[:] = []
                continue
            depth = dirpath.count(os.sep) - base_depth
            if depth == 0 and sys.platform == "darwin":
                dirs[:] = [d for d in dirs if not d.lower().startswith("com.apple.")
                           and d.lower() not in _APP_MAC_SKIP]
            dirs[:] = [d for d in dirs if d.lower() not in _APP_SKIP]
    if stopped and gaps is not None:
        gaps.append("desktop app discovery stopped at its {:,}-folder / {}-second limit at {}; "
                    "the rest of {} was not searched for desktop apps".format(
                        _APP_MAX_FOLDERS, _APP_MAX_SECONDS, stopped[0], " and ".join(stopped[1])))
    if unreadable and gaps is not None:
        gaps.append("desktop app discovery: {} folder(s) could not be read, so web records "
                    "of a chat or other desktop app stored there were not checked (for "
                    "example {})".format(len(unreadable), unreadable[0]))
    return found

# Firefox (profiles_dir, cache_dir) pairs. None means "derive from the platform
# at run() time"; tests set an explicit list so the suite never reads the real
# profile on any OS (the Windows branch of _firefox_roots used to be the only one
# the tests could neutralise, which let the suite read the tester's real Firefox
# on macOS/Linux).
FIREFOX_ROOTS = None


def _firefox_label(profiles_dir):
    """Which Firefox-family browser a profiles folder belongs to."""
    low = profiles_dir.replace("\\", "/").lower()
    for marker, label in (("librewolf", "librewolf"), ("waterfox", "waterfox"), ("floorp", "floorp"),
                          ("/zen", "zen"), (".zen", "zen"), ("pale moon", "palemoon"),
                          ("torbrowser", "tor-browser"), ("tor-browser", "tor-browser"),
                          ("tor browser", "tor-browser")):
        if marker in low:
            return label
    return "firefox"


def _firefox_roots():
    """Firefox (profiles_dir, cache_dir) pairs by platform.

    Evaluated at run() time so the Windows pair reflects the current LOCAL /
    ROAMING globals (which the tests override to neutralise it). Returns [] on a
    platform with no known Firefox location.
    """
    home = os.path.expanduser("~")
    if sys.platform == "win32":
        tor = os.path.join(home, "Desktop", "Tor Browser", "Browser", "TorBrowser", "Data", "Browser")
        return [(os.path.join(ROAMING, "Mozilla", "Firefox", "Profiles"),
                 os.path.join(LOCAL, "Mozilla", "Firefox", "Profiles"))] + [
            (os.path.join(ROAMING, *parts), os.path.join(LOCAL, *parts)) for parts in (
                ("librewolf", "Profiles"), ("Waterfox", "Profiles"), ("Floorp", "Profiles"),
                ("zen", "Profiles"), ("Moonchild Productions", "Pale Moon", "Profiles"))] + [(tor, os.path.join(tor, "Caches"))]
    if sys.platform == "darwin":
        asup = os.path.join(home, "Library", "Application Support")
        caches = os.path.join(home, "Library", "Caches")
        tor = os.path.join(asup, "TorBrowser-Data", "Browser")
        return [(os.path.join(asup, "Firefox", "Profiles"),
                 os.path.join(caches, "Firefox", "Profiles"))] + [
            (os.path.join(asup, *parts), os.path.join(caches, *parts)) for parts in (
                ("librewolf", "Profiles"), ("Waterfox", "Profiles"), ("Floorp", "Profiles"),
                ("zen", "Profiles"), ("Pale Moon", "Profiles"))] + [(tor, os.path.join(tor, "Caches"))]
    if sys.platform.startswith("linux"):
        cache = os.environ.get("XDG_CACHE_HOME", "")
        cache = cache if os.path.isabs(cache) else os.path.join(home, ".cache")
        config = os.environ.get("XDG_CONFIG_HOME", "")
        config = config if os.path.isabs(config) else os.path.join(home, ".config")
        return [
            (os.path.join(home, ".mozilla", "firefox"),
             os.path.join(cache, "mozilla", "firefox")),
            # Firefox 147 and later create new profiles in the XDG folders.
            (os.path.join(config, "mozilla", "firefox"),
             os.path.join(cache, "mozilla", "firefox")),
            # snap packaging
            (os.path.join(home, "snap", "firefox", "common", ".mozilla",
                          "firefox"),
             os.path.join(home, "snap", "firefox", "common", ".cache", "mozilla",
                          "firefox")),
            # flatpak packaging
            (os.path.join(home, ".librewolf"), os.path.join(cache, "librewolf")),
            (os.path.join(home, ".waterfox"), os.path.join(cache, "waterfox")),
            (os.path.join(home, ".floorp"), os.path.join(cache, "floorp")),
            (os.path.join(home, ".zen"), os.path.join(cache, "zen")),
            (os.path.join(home, ".moonchild productions", "pale moon"),
             os.path.join(cache, "moonchild productions", "pale moon")),
            (os.path.join(home, ".var", "app", "io.gitlab.librewolf-community", ".librewolf"),
             os.path.join(home, ".var", "app", "io.gitlab.librewolf-community", ".cache", "librewolf")),
            (os.path.join(home, "tor-browser", "Browser", "TorBrowser", "Data", "Browser"),
             os.path.join(home, "tor-browser", "Browser", "TorBrowser", "Data", "Browser", "Caches")),
            (os.path.join(home, ".local", "share", "torbrowser", "tbb", "x86_64", "tor-browser", "Browser",
                          "TorBrowser", "Data", "Browser"),
             os.path.join(home, ".local", "share", "torbrowser", "tbb", "x86_64", "tor-browser", "Browser",
                          "TorBrowser", "Data", "Browser", "Caches")),
            (os.path.join(home, ".var", "app", "org.mozilla.firefox", ".mozilla",
                          "firefox"),
             os.path.join(home, ".var", "app", "org.mozilla.firefox", "cache",
                          "mozilla", "firefox")),
            (os.path.join(home, ".var", "app", "org.mozilla.firefox", "config", "mozilla",
                          "firefox"),
             os.path.join(home, ".var", "app", "org.mozilla.firefox", "cache",
                          "mozilla", "firefox")),
        ]
    return []


# Largest browser database we will snapshot, siblings included. Real History /
# Cookies files are tens of MB; 1 GiB leaves generous headroom.
_MAX_SNAPSHOT_BYTES = 1024 * 1024 * 1024
# A real profile holds tens of thousands of icons at most.
_FAVICON_ROW_LIMIT = 1000000


def copy_locked(path):
    """Copy a possibly-locked SQLite db (plus -wal/-shm/-journal) to a temp dir.

    A running browser holds a write lock on the live file, so we snapshot it and
    its write-ahead-log / journal siblings into the system temp dir and open the
    copy read-only. The caller removes the temp dir in a finally once it has the
    returned path; if the snapshot itself fails the caller never receives a path,
    so this function removes its own temp dir before re-raising (no leak).

    Returns (path_to_copy, incomplete) where `incomplete` lists the sibling
    suffixes that existed but could not be copied. A non-empty list means the
    snapshot is missing data the live database has."""
    problem = path_problem(path)
    if problem:
        raise PermissionError(13, problem, path)
    # Refuse an implausibly large database before copying anything. A profile
    # database the attacker can write could otherwise fill the temp drive - an
    # unbounded write by a tool that promises it only reads - and then exhaust
    # memory when its rows are read. Checked before mkdtemp so a refusal never
    # leaves a temp directory behind; the caller records it as a gap.
    # Each sibling is checked for links and reparse points BEFORE anything
    # follows it (exists/getsize follow a redirected file to its destination,
    # which could be a network share). An unsafe sibling is never touched; the
    # copy loop below records it as missing from the snapshot.
    safe_sidecars = [sfx for sfx in ("-wal", "-shm", "-journal")
                     if not path_problem(path + sfx)]
    try:
        total = os.path.getsize(path) + sum(
            os.path.getsize(path + sfx) for sfx in safe_sidecars
            if os.path.exists(path + sfx))
    except OSError:
        total = 0   # let the copy below surface the real error
    if total > _MAX_SNAPSHOT_BYTES:
        raise OSError(27, "database is {:,} bytes, over the {:,}-byte snapshot "
                      "limit, so it was not copied".format(
                          total, _MAX_SNAPSHOT_BYTES), path)
    tmpdir = tempfile.mkdtemp(prefix="bscan_", dir=local_temp_dir())
    try:
        base = os.path.join(tmpdir, os.path.basename(path))
        shutil.copy2(path, base)
        # A failed sibling copy is NOT cosmetic. A write-ahead log holds rows
        # that are committed but not yet folded into the main file, so losing it
        # silently drops the MOST RECENT evidence - exactly the rows that matter
        # for a campaign someone is checking for right now. Report which ones
        # failed so the caller can record a gap instead of reading a short file
        # and calling it clean (D3).
        incomplete = []
        for suffix in ("-wal", "-shm", "-journal"):
            if path_problem(path + suffix):
                incomplete.append("could not copy " + suffix)
                continue
            if os.path.exists(path + suffix):
                try:
                    shutil.copy2(path + suffix, base + suffix)
                except OSError:
                    incomplete.append("could not copy " + suffix)
        # SQLite silently ignores a damaged write-ahead log and reads the older
        # main file, so a broken WAL would drop the newest records without a
        # trace. Validate it the same way the iPhone reader does.
        if os.path.exists(base + "-wal"):
            try:
                with open(base, "rb") as fh:
                    header = fh.read(100)
                with open(base + "-wal", "rb") as fh:
                    wal = fh.read()
                _prefix, issues = _is_wal_prefix(wal, header, max_bytes=_MAX_SNAPSHOT_BYTES)
            except OSError as exc:
                issues = ["write-ahead log unreadable ({})".format(exc.strerror or type(exc).__name__)]
            incomplete.extend("the write-ahead log is damaged ({})".format(i) for i in issues)
        return base, incomplete
    except BaseException as exc:
        # The one place that makes the temp dir is also the one place that
        # removes it when it never hands it over. A failed copy may already
        # contain cookie values, so deletion failure must reach the report.
        if not _discard_snapshot(tmpdir):
            exc.snapshot_leftover = tmpdir
        raise


def _discard_snapshot(tmpdir, con=None):
    """Close the open handle, then delete the snapshot - and check it is gone.

    These temp copies are byte-for-byte duplicates of browser databases, cookie
    VALUES included, even though the queries only read metadata. Windows refuses
    to delete a file that an open SQLite connection still holds, and
    shutil.rmtree(ignore_errors=True) swallows that refusal without a word - so
    the copies survived in %TEMP% after every scan. A tool that leaves copies of
    your cookies behind is worse than no tool, so the handle is closed first and
    the removal is verified rather than assumed. Returns True if the directory
    is gone."""
    if con is not None:
        try:
            con.close()
        except Exception:
            pass
    shutil.rmtree(tmpdir, ignore_errors=True)
    if os.path.exists(tmpdir):
        # One retry: on Windows an antivirus or indexer can hold a file open for
        # a moment after the handle closes.
        shutil.rmtree(tmpdir, ignore_errors=True)
    return not os.path.exists(tmpdir)


def _chromium_profile_names(user_data):
    """Map profile folder -> display name, from the browser's own Local State.

    Chromium calls profile folders "Default", "Profile 1", "Profile 7"..., which
    is meaningless to a person with several accounts. Local State holds the name
    they actually see in the browser, which is what makes a finding
    actionable: "the cookie is in Work" rather than "the cookie is in
    Profile 1".

    Only the display name is read. The signed-in email address is in the same
    structure and is deliberately left alone - the name is enough to identify
    the account, and a report may be forwarded to other people.
    """
    out = {}
    path = os.path.join(user_data, "Local State")
    if path_problem(path):
        return out
    try:
        # Only display names come from here; an implausibly large file falls
        # back to folder names rather than spending gigabytes of memory.
        if os.path.getsize(path) > 16 * 1024 * 1024:
            return out
        with io.open(path, encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    # RecursionError is not a ValueError. A Local State file of 200,000 nested
    # brackets - about 400 KB, writable without admin - made json.load raise it
    # before a single profile was read, and the whole browser module was lost.
    # Malformed is malformed: fall back to folder names, keep scanning.
    except (OSError, ValueError, RecursionError, MemoryError):
        return out
    profile = data.get("profile", {}) if isinstance(data, dict) else {}
    if not isinstance(profile, dict):
        return out
    cache = profile.get("info_cache", {})
    if not isinstance(cache, dict):
        return out
    for folder, info in cache.items():
        if isinstance(info, dict) and info.get("name"):
            out[folder] = str(info["name"])
    return out


# Files that mark a directory as a real Firefox profile (as opposed to a sibling
# folder like Crash Reports / Pending Pings / Profile Groups that lives in the
# same root on Linux). Any one is enough.
_FF_PROFILE_MARKERS = ("prefs.js", "places.sqlite", "cookies.sqlite",
                       "favicons.sqlite", "SiteSecurityServiceState.txt", "SiteSecurityServiceState.bin",
                       "cert9.db", "key4.db", "logins.json")


def _firefox_ini(profiles_dir):
    """Parse Firefox's profiles.ini. Returns ({folder_basename: display_name},
    {folder basenames that profiles.ini lists as profiles}).

    profiles.ini sits INSIDE profiles_dir on Linux (~/.mozilla/firefox) but one
    level ABOVE it on Windows/macOS (...\\Firefox\\Profiles). Try both, so names
    resolve on every platform; the first readable one wins.
    """
    names, known = {}, set()

    def flush(sec):
        path = sec.get("Path")
        if path:
            base = os.path.basename(path.replace("/", os.sep).rstrip(os.sep))
            known.add(base)
            if sec.get("Name"):
                names[base] = sec["Name"]

    for ini in (os.path.join(profiles_dir, "profiles.ini"),
                os.path.join(os.path.dirname(profiles_dir), "profiles.ini")):
        if path_problem(ini):
            continue
        section = {}
        try:
            with io.open(ini, encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    line = raw.strip()
                    if line.startswith("["):
                        flush(section)
                        section = {}
                    elif "=" in line:
                        key, value = line.split("=", 1)
                        section[key.strip()] = value.strip()
            flush(section)
            break
        except OSError:
            continue
    return names, known


def _is_ff_profile_dir(path):
    """True if `path` looks like a real Firefox profile (holds a marker file)."""
    for marker in _FF_PROFILE_MARKERS:
        full = os.path.join(path, marker)
        problem = path_problem(full)
        if problem:
            raise PermissionError(13, problem, full)
        try:
            os.lstat(full)
            return True
        except FileNotFoundError:
            continue
    return False


def _browser_same_store_alias(alias, direct):
    """True when `alias` is a link whose own text points exactly at `direct`
    (macOS links Safari's sandbox Cookies folder to ~/Library/Cookies). Only the
    link itself is read, never what it points to; any other link is not an
    alias and stays refused by the normal checks."""
    try:
        if not os.path.islink(alias):
            return False
        target = os.readlink(alias)
    except OSError:
        return False
    resolved = os.path.normpath(os.path.join(os.path.dirname(alias), target))
    return os.path.normcase(resolved) == os.path.normcase(os.path.normpath(direct))


def _sqlite_or_absent(path):
    """True unless `path` is a readable regular file that is not SQLite."""
    try:
        if not os.path.isfile(path) or os.path.islink(path):
            return True
        with open(path, "rb") as fh:
            return fh.read(16) == b"SQLite format 3\0"
    except OSError:
        return True  # unreadable: let the normal reader report the gap


def _browser_read_small(path, limit=16 * 1024 * 1024):
    """A small evidence file's bytes: links are not followed, and a file that
    changes or grows past the limit while being read is refused."""
    problem = path_problem(path)
    if problem:
        raise OSError(problem)
    before = os.lstat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
        raise ValueError("not a regular file or larger than the read limit")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    with os.fdopen(os.open(path, flags), "rb") as stream:
        opened = os.fstat(stream.fileno())
        if (not stat.S_ISREG(opened.st_mode) or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or path_problem(path)):
            raise ValueError("file changed before reading")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("file changed while reading")
    if len(raw) > limit:
        raise ValueError("read limit reached")
    return raw


_MAC_EPOCH = 978307200  # 2001-01-01 UTC, the reference date of Apple timestamps


def _safari_cookie_domains(raw):
    """[(domain, creation unix time or None)] from a Cookies.binarycookies file:
    'cook', a big-endian page count and page sizes, then pages of little-endian
    cookie records whose header holds string offsets and two Apple dates."""
    if len(raw) < 8 or raw[:4] != b"cook":
        raise ValueError("not a Safari cookie file")
    pages = struct.unpack(">I", raw[4:8])[0]
    if pages > 100000 or 8 + 4 * pages > len(raw):
        raise ValueError("cookie page table exceeds the file")
    sizes = struct.unpack(">%dI" % pages, raw[8:8 + 4 * pages])
    pos, found = 8 + 4 * pages, []
    for size in sizes:
        page = raw[pos:pos + size]
        pos += size
        if len(page) != size or size < 12 or page[:4] != b"\x00\x00\x01\x00":
            raise ValueError("damaged cookie page")
        count = struct.unpack("<I", page[4:8])[0]
        if 8 + 4 * count > size:
            raise ValueError("damaged cookie page")
        for offset in struct.unpack("<%dI" % count, page[8:8 + 4 * count]):
            if offset + 56 > size:
                raise ValueError("damaged cookie record")
            length = struct.unpack("<I", page[offset:offset + 4])[0]
            cookie = page[offset:offset + length]
            if length < 56 or len(cookie) != length:
                raise ValueError("damaged cookie record")
            start = struct.unpack("<I", cookie[16:20])[0]
            end = cookie.find(b"\x00", start)
            if not 56 <= start < length or end < 0:
                raise ValueError("damaged cookie record")
            created = struct.unpack("<d", cookie[48:56])[0]
            when = created + _MAC_EPOCH if 0 < created < 4e9 else None
            found.append((cookie[start:end].decode("utf-8"), when))
            if len(found) > 200000:
                raise ValueError("cookie count limit reached")
    return found


def _safari_plist_strings(doc, limit=200000):
    """Every string in a property list, with the key it sits under."""
    pending, seen = [("", doc)], 0
    while pending:
        key, value = pending.pop()
        seen += 1
        if seen > limit:
            raise ValueError("property-list size limit reached")
        if isinstance(value, dict):
            pending.extend((str(k), v) for k, v in value.items())
        elif isinstance(value, list):
            pending.extend((key, v) for v in value)
        elif isinstance(value, str):
            yield key, value


def _browser_safari_roots():
    if sys.platform != "darwin":
        return []
    return [("safari", os.path.join(os.path.expanduser("~"), "Library", "Safari"))]


def _fmt_time(conv, raw):
    """Render an artifact timestamp, or "" if it is missing or unreadable."""
    if not raw:
        return ""
    try:
        return conv(int(raw)).isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


# A browser database is read as found, and one can be planted in a profile or
# handed over to be scanned. A view lets a 4 KiB file run forever (a recursive
# query) or return billions of rows. No browser writes views or recursive
# queries, so reading through one is refused outright.
# The time limit is the backstop for anything else slow. Either way the result
# is a gap, never a clean read.
_DB_SECONDS = 180
_SQLITE_RECURSIVE = getattr(sqlite3, "SQLITE_RECURSIVE", 33)


def _db_authorizer(action, arg1, arg2, dbname, source):
    # `source` names the view or trigger a read goes through; direct reads of a
    # real table have none.
    if action == _SQLITE_RECURSIVE or source is not None:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def _guard_db(con):
    deadline = time.monotonic() + _DB_SECONDS
    con.set_authorizer(_db_authorizer)
    con.set_progress_handler(lambda: int(time.monotonic() > deadline), 1000)


_WHY_SYNCED = (
    "Browser sync copies history between devices signed in to the same account. "
    "This visit was recorded on another of those devices, not on this computer, so "
    "it does not show this computer contacting the address. Check the device that "
    "made it, and who else can sign in to this browser account.")


def _chromium_visit_origins(con):
    """{urls.id: True if any visit was made in this browser, False if every
    visit came from another device}, or None when the database cannot tell.

    Chromium history sync keeps other devices' visits beside local ones and names
    the originating device in visits.originator_cache_guid (empty for a local
    visit). Older typed-URL sync marks such visits in visit_source (source 0).
    History imported from another browser on this computer counts as local."""
    try:
        vcols = {row[1] for row in con.execute("PRAGMA table_info(visits)")}
        scols = {row[1] for row in con.execute("PRAGMA table_info(visit_source)")}
    except sqlite3.Error:
        return None
    if "url" not in vcols:
        return None
    foreign, join = [], ""
    if "originator_cache_guid" in vcols:
        foreign.append("COALESCE(v.originator_cache_guid, '') <> ''")
    if {"id", "source"} <= scols and "id" in vcols:
        join = " LEFT JOIN visit_source s ON s.id = v.id"
        foreign.append("s.source = 0")
    if not foreign:
        return None
    try:
        return {url: bool(local) for url, local in con.execute(
            "SELECT v.url, MAX(CASE WHEN {} THEN 0 ELSE 1 END) FROM visits v{} GROUP BY v.url"
            .format(" OR ".join(foreign), join))}
    except sqlite3.Error:
        return None


def _locked_note(path, exc):
    """A locked database is the most common non-error a user will see, so say
    what it means and what to do rather than printing a raw errno.

    A running browser causes this two ways: the OS refuses the snapshot with a
    sharing violation (PermissionError / errno 13 on Windows), or SQLite reports
    "database is locked" when the copy is opened. Both mean the same thing to the
    person reading the report: close the browser and run again."""
    leftover = getattr(exc, "snapshot_leftover", "")
    cleanup_warning = (
        " WARNING: temporary snapshot cleanup failed; a copy of browser data "
        "may remain at {}. Remove this temporary directory when its files can "
        "be released.".format(leftover) if leftover else "")
    browser_name = "the browser"
    lowered = path.lower()
    for marker, label in (("bravesoftware", "Brave"), ("vivaldi", "Vivaldi"),
                          ("chromium", "Chromium"), ("google", "Chrome"),
                          ("microsoft", "Edge"), ("mozilla", "Firefox"),
                          ("firefox", "Firefox"), ("safari", "Safari")):
        if marker in lowered:
            browser_name = label
            break
    if "not authorized" in str(exc).lower():
        return ("{} contains a structure no browser creates (a view or a recursive "
                "query), so it was not read. The file may have been altered."
                .format(path) + cleanup_warning)
    if "interrupted" in str(exc).lower():
        return ("{} took longer than {} seconds to read, so the rest of it was not "
                "checked.".format(path, _DB_SECONDS) + cleanup_warning)
    if sys.platform == "darwin" and _permission_denied(exc) and not _database_locked(exc):
        # macOS does not lock a running browser's files; a refusal here is its
        # privacy protection (Safari's folders, Desktop, Documents...), and
        # closing the browser would not help. The refusal also hides whether the
        # folder exists, so it must not claim the browser is installed.
        return ("macOS privacy protection blocked {} so it could not be checked{}. Give "
                "Terminal Full Disk Access (System Settings > Privacy & Security > Full Disk "
                "Access), then run again.".format(
                    path, "" if browser_name == "the browser"
                    else " (or whether {} keeps data there)".format(browser_name))
                + cleanup_warning)
    if _database_locked(exc):
        return ("{} was running, so one of its databases was locked and could "
                "not be checked ({}). Close {} and run again to cover it."
                .format(browser_name, os.path.basename(path), browser_name)
                + cleanup_warning)
    if _permission_denied(exc):
        # Not a lock: the account running the check may not read this file
        # (another user's profile, restrictive permissions). Closing the
        # browser would not help, so do not say it was running.
        return ("permission to read {} was denied, so {} was not checked. Run the check "
                "as the account that owns this browser profile{}.".format(
                    path, "it" if browser_name == "the browser" else "this " + browser_name + " data",
                    " (or as an administrator)" if sys.platform == "win32" else "")
                + cleanup_warning)
    if isinstance(exc, sqlite3.DatabaseError) and "not a database" in str(exc).lower():
        return ("{} is damaged or is not a database a browser writes, so it was not "
                "read.".format(path) + cleanup_warning)
    return "could not read {}: {}".format(path, exc) + cleanup_warning


# Windows reports a file held open by a running program as a sharing or lock
# violation; access denied (5) is a permission problem, not a lock.
_WIN_LOCK_ERRORS = (32, 33)


def _database_locked(exc):
    """A real lock: SQLite's busy/locked, or a Windows sharing violation."""
    text = str(exc).lower()
    if "database is locked" in text or "database is busy" in text or "database table is locked" in text:
        return True
    winerror = getattr(exc, "winerror", None)
    if winerror in _WIN_LOCK_ERRORS:
        return True
    # Windows without a winerror (rare wrappers) keeps the old reading: a
    # running browser is by far the most common reason a copy is refused.
    return (sys.platform == "win32" and isinstance(exc, PermissionError) and winerror is None
            and "access is denied" not in text)


def _permission_denied(exc):
    return (isinstance(exc, PermissionError) or getattr(exc, "errno", None) in (1, 13)
            or getattr(exc, "winerror", None) == 5)


def _is_schema_drift(exc):
    """True for the benign "this browser version lacks that table/column" error,
    as opposed to real corruption or a lock. Only the former is safe to skip."""
    msg = str(exc).lower()
    return "no such table" in msg or "no such column" in msg


def _hsts_fingerprint(host):
    """Chromium stores HSTS hostnames as base64(sha256(DNS wire form)).

    The wire form is each label prefixed by its length, terminated by a zero
    byte: "a.example" -> b"\\x01a\\x07example\\x00". Hashing our indicators the
    same way lets us match an EXACT hostname without ever learning any other
    host the person visited - the file is deliberately a one-way set, and this
    respects that. It also means zero substring false positives.

    The length byte must count the BYTES that are hashed, not the str length.
    Indicator domains are ASCII (punycode) at load time, so ascii-encoding each
    label is exact; a stray non-ASCII label is idna-encoded instead, so the
    prefix and the payload always agree.
    """
    wire = b""
    for label in host.strip(".").lower().split("."):
        try:
            payload = label.encode("ascii")
        except UnicodeEncodeError:
            payload = label.encode("idna")
        wire += bytes([len(payload)]) + payload
    wire += b"\x00"
    return base64.b64encode(hashlib.sha256(wire).digest()).decode("ascii")


def _host_of(origin):
    """Host part of an origin like "https://example.org:443"."""
    s = str(origin).strip()
    try:
        # urlsplit is a lexical parser; it never resolves or opens a URL.
        parsed = urlsplit(s if "://" in s or s.startswith("//") else "//" + s)
        return (parsed.hostname or "").lower()
    except ValueError:
        return ""


# Ad-blocker filter lists. Some indicators are advertising domains used to deliver
# spyware through ads, and ad-blocker lists (uBlock Origin, AdGuard, EasyList, the
# lists this project publishes) contain exactly those domains in order to block
# them. A browser keeps its copy of those lists in the HTTP cache and in the
# extension's own storage, so a raw byte search finds the indicators there. That
# is protection, not contact: it is counted and noted, never reported as a finding.
# Recognition uses the address a cache entry was downloaded from, or the extension
# that owns the storage, never the file's content, which anyone can write.
_FILTER_LIST_HOSTS = frozenset((
    "ublockorigin.github.io", "ublockorigin.pages.dev", "filters.adtidy.org",
    "adguardteam.github.io", "easylist.to", "easylist-downloads.adblockplus.org",
    "secure.fanboy.co.nz", "fanboy.co.nz", "pgl.yoyo.org", "malware-filter.gitlab.io",
    "curbengh.github.io", "malware-filter.pages.dev", "urlhaus-filter.pages.dev",
    "phishing-filter.pages.dev", "someonewhocares.org", "adaway.org", "oisd.nl",
    "big.oisd.nl", "small.oisd.nl", "abp.oisd.nl", "nsfw.oisd.nl",
))
# Shared hosts where only some repositories are filter lists: (host, path prefix).
_FILTER_LIST_PATHS = tuple((h, p.lower()) for h, p in (
    ("raw.githubusercontent.com", "/ublockorigin/"), ("raw.githubusercontent.com", "/uBlockOrigin/"),
    ("raw.githubusercontent.com", "/adguardteam/"), ("raw.githubusercontent.com", "/easylist/"),
    ("raw.githubusercontent.com", "/stevenblack/hosts/"), ("raw.githubusercontent.com", "/hagezi/"),
    ("raw.githubusercontent.com", "/dandelionsprout/"), ("raw.githubusercontent.com", "/interplains/"),
    ("cdn.jsdelivr.net", "/gh/ublockorigin/"), ("cdn.jsdelivr.net", "/gh/easylist/"),
    ("cdn.jsdelivr.net", "/gh/hagezi/"), ("cdn.statically.io", "/gh/ublockorigin/"),
    ("gitlab.com", "/hagezi/"), ("codeberg.org", "/hagezi/"),
    ("archivegenocide.com", "/scan/"), ("archivegenocide.org", "/scan/"),
    ("archivegenocide.is", "/scan/"),
))
# Chrome Web Store / Edge Add-ons ids of content blockers that keep filter lists.
_FILTER_LIST_EXTENSIONS = {
    "cjpalhdlnbpafiamejdnhcphjbkeiagm": "uBlock Origin",
    "odfafepnkmbhccpbejgmiehpchacaeak": "uBlock Origin",
    "ddkjiahejlhfcafbddmgiahcphecmpfh": "uBlock Origin Lite",
    "bgnkhhnnamicmpeenaelnjfhikgbkllg": "AdGuard",
    "gighmmpiobklfepjocnamgkkbiglidom": "AdBlock",
    "cfhdojbkjhnklbpkdaibdccddilifddb": "Adblock Plus",
    "mlomiejdfkolichcflejclcbmpeaniij": "Ghostery",
    "pkehgijcmpdhfbdbbnkijodmdjhbjlgp": "Privacy Badger",
}
_SIMPLE_CACHE_MAGIC = struct.pack("<Q", 0xfcfb6d1ba7725c30)
_FF_CACHE_KEY = re.compile(rb"(?:^|[,\x00]):(https?://[\x21-\x7e]+?)\x00")


def _filter_list_url(url):
    """True when a request URL is a known filter-list download."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    path = (parts.path or "").lower()
    if host in _FILTER_LIST_HOSTS:
        return True
    return any(host == h and path.startswith(p) for h, p in _FILTER_LIST_PATHS)


def _filter_list_extension(text):
    """The content blocker named by a chrome-extension:// origin in `text`, or None."""
    for ext_id, name in _FILTER_LIST_EXTENSIONS.items():
        if "chrome-extension://" + ext_id in text:
            return name
    return None


def _cache_entry_urls(data, firefox=False):
    """The request key of one HTTP cache entry, as its space-separated parts.

    Chromium's simple cache starts each entry with a fixed header followed by the
    key ("1/0/_dk_<site> <frame> <url>" or just the url). Firefox's cache2 keeps the
    body first and its metadata, including the key (",:<url>"), after the offset
    stored in the last four bytes. Anything else returns []."""
    if data[:8] == _SIMPLE_CACHE_MAGIC and len(data) >= 24:
        size = struct.unpack_from("<I", data, 12)[0]
        if 0 < size <= 8192:
            for start in (24, 20):
                key = data[start:start + size]
                if key[:4] == b"1/0/" or key[:4] == b"http" or key[:4] == b"chro":
                    return key.decode("latin-1").split()
        return []
    if firefox and len(data) > 8:
        offset = struct.unpack(">I", data[-4:])[0]
        if 0 < offset < len(data) - 4:
            found = _FF_CACHE_KEY.search(data[offset:])
            if found:
                return [found.group(1).decode("latin-1")]
    return []


_BLOCKFILE_HEADER = 8192
_BLOCKFILE_SIZES = {2: 256, 3: 1024, 4: 4096}
_BLOCKFILE_EXTERNAL = re.compile(r"^f_[0-9a-f]{6}$")
_BLOCKFILE_INDEX_LIMIT = 64 * 1024 * 1024


def _blockfile_read(cache_dir, name, files):
    if name not in files:
        full = os.path.join(cache_dir, name)
        data = b""
        if not path_problem(full):
            try:
                if os.path.getsize(full) <= _BLOCKFILE_INDEX_LIMIT:
                    with io.open(full, "rb") as fh:
                        data = fh.read()
            except OSError:
                data = b""   # a running browser holds these files exclusively
        files[name] = data
    return files[name]


def _blockfile_external_keys(cache_dir):
    """Map each large-body file (f_xxxxxx) of a Chromium block-file cache, the
    layout Chromium uses on Windows, to the request key its index entry holds.

    Index entries are 256-byte records in data_1; a key longer than the record
    lives in another block file. Returns {} when the index cannot be read, which
    is normal while the browser is running."""
    files = {}
    index = _blockfile_read(cache_dir, "data_1", files)
    keys = {}
    for off in range(_BLOCKFILE_HEADER, len(index) - 255, 256):
        key_len, long_key = struct.unpack_from("<iI", index, off + 32)
        body = struct.unpack_from("<I", index, off + 60)[0]
        if not (0 < key_len <= 8192) or not body & 0x80000000 or (body >> 28) & 7:
            continue
        if long_key:
            kind = (long_key >> 28) & 7
            if not long_key & 0x80000000 or kind not in _BLOCKFILE_SIZES:
                continue
            data = _blockfile_read(cache_dir, "data_%d" % ((long_key >> 16) & 0xff), files)
            start = _BLOCKFILE_HEADER + (long_key & 0xffff) * _BLOCKFILE_SIZES[kind]
            key = data[start:start + key_len]
        else:
            key = index[off + 96:off + 96 + key_len]
        if len(key) == key_len:
            keys["f_%06x" % (body & 0x0fffffff)] = key.decode("latin-1").split()
    return keys


def _looks_like_filter_list(data):
    """True for a body that is plainly an ad-blocker filter list: a list header
    and rule lines throughout. Used only for Windows cache bodies whose index
    could not be read; a script or page does not have this shape."""
    text = data[:16384].decode("utf-8", "replace").lstrip("\ufeff")
    lines = [line.strip() for line in text.splitlines() if line.strip()][:40]
    if len(lines) < 3:
        return False
    first = lines[0].lower()
    if not (first.startswith(("[adblock", "[adguard", "[ublock")) or first.startswith("! ")):
        return False
    rules = sum(1 for line in lines
                if line.startswith(("!", "||", "@@", "##", "[", "0.0.0.0 ", "127.0.0.1 ")))
    return rules * 5 >= len(lines) * 4


def _filter_list_source(path, data, index_cache=None):
    """Describe the ad-blocker filter list this cache/storage file holds, or None.

    A cache entry counts when it was downloaded from a filter-list address or by a
    content-blocker extension; a Service Worker cache counts when its index names a
    content-blocker extension as the owner."""
    parts = os.path.normpath(path).split(os.sep)
    lowered = [p.lower() for p in parts]
    cache = index_cache if index_cache is not None else {}
    key = _cache_entry_urls(data, firefox="cache2" in lowered)
    blockfile = bool(_BLOCKFILE_EXTERNAL.match(parts[-1]))
    if blockfile and not key:
        folder = os.path.dirname(os.path.normpath(path))
        if ("blockfile", folder) not in cache:
            cache[("blockfile", folder)] = _blockfile_external_keys(folder)
        key = cache[("blockfile", folder)].get(parts[-1], [])
    # Only the requested address itself decides; the site that asked for it
    # (the other parts of the key) must not, or any page on a list site, and
    # every ad it loaded, would be passed over.
    if key and _filter_list_url(key[-1]):
        return "a filter list downloaded from " + (_host_of(key[-1]) or key[-1])
    name = _filter_list_extension(" ".join(key[:-1])) if len(key) > 1 else None
    if name:
        return "data downloaded by the " + name + " extension"
    if blockfile and not key and _looks_like_filter_list(data):
        return "a cached ad-blocker filter list"
    if "cachestorage" in lowered:
        at = lowered.index("cachestorage")
        if at + 1 < len(parts) - 1:
            owner_dir = os.sep.join(parts[:at + 2])
            if owner_dir not in cache:
                text = ""
                try:
                    with io.open(os.path.join(owner_dir, "index.txt"), "rb") as fh:
                        text = fh.read(65536).decode("latin-1")
                except OSError:
                    pass
                cache[owner_dir] = _filter_list_extension(text)
            if cache[owner_dir]:
                return "the " + cache[owner_dir] + " extension's own storage"
    return None


def _host_matches(host, ioc_set):
    """Exact host match, or a subdomain of an indicator. Not a substring test:
    these artifacts give us a real hostname, so we can compare properly."""
    host = host.lower().strip(".")
    ind = ioc_set.lookup(host)
    if ind is not None and ind.type in ("domain", "ip"):
        return ind
    # MOST specific wins, not first-found. The indicator set holds both parents
    # and children (powerium.net and qa-noas.powerium.net), and iteration order
    # is the file's order, so returning the first match could hand back the
    # parent while most_specific() - which callers use to pick the hit - keeps
    # the child. The two then disagree, the "is this the host?" comparison
    # fails, and a genuine contact is downgraded to a mere reference.
    #
    # Walk up the host's own name (a.b.example.com -> b.example.com ->
    # example.com) and look each parent up directly: the first domain found is
    # the longest, i.e. most specific. Comparing every host with every domain
    # indicator instead cost 191 million string comparisons for one browser
    # profile.
    labels = host.split(".")
    for i in range(1, len(labels)):
        parent = ioc_set.lookup_typed("domain", ".".join(labels[i:]))
        if parent is not None:
            return parent
    return None


def _browser_url_evidence(url, ioc_set, host_grade, reference=""):
    """Grade a URL host independently of its path, query and surrounding text.

    Parent/child specificity applies within one hostname, never across a title
    and a URL. A query mentioning a child indicator cannot erase the actual
    parent-host contact, and a parent reference beside a child host remains a
    reference. This is lexical parsing only.
    """
    try:
        raw_url = str(url)
        if any(ord(char) < 32 or ord(char) == 127 for char in raw_url):
            raise ValueError("control character in URL")
        parsed = urlsplit(raw_url)
        is_web = parsed.scheme.lower() in ("http", "https")
        if is_web:
            # urllib does not apply browser special-URL backslash handling and
            # validates ports only on access. Ambiguous authorities are text.
            if "\\" in parsed.netloc or " " in parsed.netloc:
                raise ValueError("ambiguous URL authority")
            parsed.port
        host_ind = _host_matches(parsed.hostname or "", ioc_set) if is_web else None
        nonhost = " ".join((parsed.username or "", parsed.password or "",
                            parsed.path, parsed.query, parsed.fragment)) if is_web else str(url)
    except ValueError:
        host_ind, nonhost = None, str(url)
    if host_ind is not None:
        yield host_ind, host_grade
    for ind in ioc_set.search((nonhost + " " + reference).lower()):
        if host_ind is None or host_ind.value != ind.value:
            yield ind, EV_REFERENCED


def chromium_profiles(user_data):
    """Every Default / Guest / Profile* directory under a Chromium user-data root.

    Raises OSError if the root exists but cannot be enumerated (a bad ACL); the
    caller turns that into a gap for this one root rather than aborting the whole
    module."""
    problem = path_problem(user_data)
    if problem:
        raise PermissionError(13, problem, user_data)
    if not os.path.isdir(user_data):
        return []
    out = []
    for name in os.listdir(user_data):
        p = os.path.join(user_data, name)
        # Default, Profile N, Guest Profile, System Profile, and any folder
        # named with --profile-directory: a profile always has Preferences.
        if (name == "Default" or name == "Guest Profile" or name.startswith("Profile")
                or os.path.isfile(os.path.join(p, "Preferences"))):
            out.append(p)
    return out


def _report_app_caches_skipped(r, folders):
    """One gap line for the app web caches the default scan leaves to the full
    scan - a choice, but still somewhere that was not searched (D3)."""
    size, apps = 0, set()
    for folder in folders:
        if path_problem(folder) or not os.path.isdir(folder):
            continue
        before = size
        for dirpath, _dirs, files in walk_local(folder, onerror=lambda _exc: None):
            for name in files:
                try:
                    size += os.path.getsize(os.path.join(dirpath, name))
                except OSError:
                    pass
        if size > before:
            # Cache/Cache_Data and Code Cache/js are both two levels under the
            # app's profile folder: count APPS, not cache folders.
            apps.add(os.path.normcase(os.path.dirname(os.path.dirname(folder))))
    if size:
        r.could_not_run(
            "desktop-app web caches",
            "the raw web caches of {} desktop app(s) ({:.1f} GB) were not searched; "
            "use the full scan (--scan-type full) to include them. Supported cookies, history, connection "
            "records and storage are checked separately; see their individual gaps".format(
                len(apps), size / 1e9))


def _browser_hsts_binary(raw):
    """Mozilla DataStorage HSTS slots: 6 metadata + 256 key + 24 value bytes.

    Validate the XOR checksum and state instead of searching arbitrary bytes.
    Last-access days and expiry are deliberately not presented as visit dates.
    """
    import struct
    if len(raw) > 286 * 2048 or len(raw) % 286:
        raise ValueError("unsupported or truncated Firefox HSTS binary store")
    entries, invalid = [], 0
    for offset in range(0, len(raw), 286):
        slot = raw[offset:offset + 286]
        if not any(slot):
            continue
        checksum = 0
        for value in struct.unpack(">143H", slot):
            checksum ^= value
        if checksum or not all(struct.unpack(">HH", slot[2:6])):
            invalid += 1
            continue
        try:
            key = slot[6:262].rstrip(b"\0").decode("ascii")
            value = slot[262:].rstrip(b"\0").decode("ascii")
            entries.append((key, value))
        except UnicodeError:
            invalid += 1
    return entries, invalid


def run(ctx) -> ModuleResult:
    r = ModuleResult(NAME)
    r.submetrics["sqlite"] = 0
    r.submetrics["blob"] = 0
    # Publish the result straight away so that if anything below raises,
    # the CLI can still recover whatever was found before the failure
    # instead of discarding it (see ScanContext.partial).
    ctx.partial = r

    # Matching itself lives in IocSet.search / search_bytes, so the boundary
    # rules (a domain must not match inside a longer name, an IP must not match
    # inside a longer number) exist in exactly one place for every module.

    # Modification times of every cache/LevelDB file searched, used at the end to
    # report the actual age of the oldest surviving artifact.
    seen_mtimes = []
    filter_lists = {"indicators": 0, "files": 0, "examples": []}
    # Creation times of the oldest cookie in each cookie store. Cookies outlive the
    # cache by a long way, so leaving them out would understate the window.
    cookie_times = []
    # How many cookie STORES were actually read. The reach "basis" count must be
    # the number of stores, not len(cookie_times) (which is inflated by one entry
    # per matching cookie plus one per store).
    cookie_stores = [0]
    # Whether any history query actually returned rows. reach["history"] is only
    # populated when it did, so an empty result never advertises a window the
    # scan did not actually observe.
    history_rows = [False]

    # Which profile is currently being scanned, so every hit can name the
    # account it came from. Updated as the walk moves between profiles.
    current = {"name": ""}

    # --- per (browser label, artifact kind) outcome ------------------------
    #
    # Each (label, kind) records whether ANY profile could read that artifact.
    #   ok     - at least one profile read this artifact successfully (a lock in
    #            a different profile is a note, not a whole-kind gap)
    #   fail   - present but unreadable, and no profile has read it yet
    #   absent - never recorded; the browser never created it (not a gap)
    # Insertion order is preserved so the checks list is stable.
    kinds = {}

    beat = [time.monotonic()]

    def heartbeat(label):
        # Long browser phases (big caches, many profiles) print a line now and
        # then, so a redirected or slow run visibly keeps working.
        now = time.monotonic()
        if now - beat[0] >= 20:
            beat[0] = now
            ctx.emit("[browser]   still working: {} ({:,} records checked so far)".format(label, r.checked))

    def _touch(label, kind):
        heartbeat(label)
        key = (label, kind)
        if key not in kinds:
            kinds[key] = {"ok": False, "reason": "", "failures": []}
        return kinds[key]

    def mark_ok(label, kind):
        _touch(label, kind)["ok"] = True

    def mark_fail(label, kind, reason):
        # Every failure is kept, with the profile it happened in. Keeping only a
        # single flag let one readable profile mask another profile's locked
        # database: the kind was reported as a check that ran, and the scan came
        # out CLEAN with no gap at all. That is precisely the collapse of UNKNOWN
        # into CLEAN that D3 forbids, so the failures are now carried through to
        # the rollup individually.
        entry = _touch(label, kind)
        if not entry["reason"]:
            entry["reason"] = reason
        entry["failures"].append((current["name"], reason))

    def chrome_time(us):
        # Chromium stores microseconds since 1601-01-01 UTC (the Windows epoch).
        # Report times are local, like Firefox's fromtimestamp below.
        utc = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=us)
        return utc.astimezone().replace(tzinfo=None)

    def unix_us_time(us):
        # Firefox stores microseconds since 1970-01-01.
        return datetime.datetime.fromtimestamp(us / 1e6)

    def record_hit(path, ind, detail, evidence=EV_REFERENCED, observed=""):
        # Attach tier/confidence/source provenance from the IOC set to every hit,
        # plus how strong the artifact makes it (see Hit.evidence).
        r.add_hit(Hit(indicator=ind.value, location=path, detail=detail,
                      tier=ind.tier, confidence=ind.confidence,
                      source=ind.source, evidence=evidence, observed=observed,
                      profile=current["name"], family=ind.family))

    def open_db(path, label, kind):
        """Snapshot and open a possibly-locked SQLite db read-only.

        Returns (con, tmp) on success, or None. A truly absent file (artifact not
        present for this profile) is NOT a gap and returns None silently; every
        other failure records a could-not-read for this (label, kind) - which is
        promoted to a gap only if no profile ever reads it. The db is not counted
        as checked here; that happens only once rows are actually read."""
        problem = path_problem(path)
        if problem:
            r.skipped += 1
            mark_fail(label, kind, "{}: {}".format(path, problem))
            return None
        try:
            os.stat(path)
        except FileNotFoundError:
            return None  # artifact simply absent for this profile
        except OSError as exc:
            r.skipped += 1
            note = _locked_note(path, exc)
            r.note(note)
            mark_fail(label, kind, note)
            return None
        try:
            tmp, incomplete = copy_locked(path)
        except OSError as exc:
            # A locked db we could not even snapshot is a gap, not a clean item.
            r.skipped += 1
            note = _locked_note(path, exc)
            r.note(note)
            mark_fail(label, kind, note)
            return None
        try:
            con = open_evidence_db(tmp)
        except sqlite3.Error as exc:
            if not _discard_snapshot(os.path.dirname(tmp)):
                exc.snapshot_leftover = os.path.dirname(tmp)
            r.skipped += 1
            note = _locked_note(path, exc)
            r.note(note)
            mark_fail(label, kind, note)
            return None
        if incomplete:
            # The main file opened, but a write-ahead log or journal that the
            # live database HAS could not be copied. Whatever was committed
            # there is missing from this snapshot - and that is the newest
            # evidence, not the oldest. Reading the short file and calling it
            # clean would be a false negative, so this is a gap.
            note = ("{}: snapshot is incomplete - {}, so recently written rows "
                    "may be missing from this read".format(
                        os.path.basename(path), "; ".join(incomplete)))
            r.note(note)
            mark_fail(label, kind, note)
        con.text_factory = lambda b: b.decode("utf-8", "replace")
        _guard_db(con)
        return con, tmp

    def _count_db():
        r.submetrics["sqlite"] += 1
        r.checked += 1

    def scan_bookmarks(label, path):
        kind = "bookmarks"
        try:
            problem = path_problem(path)
            if problem:
                raise OSError(problem)
            before = os.lstat(path)
            if not stat.S_ISREG(before.st_mode) or before.st_size > 16 * 1024 * 1024:
                raise ValueError("bookmark file is not regular or exceeds the byte limit")
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
            with os.fdopen(os.open(path, flags), "rb") as stream:
                opened = os.fstat(stream.fileno())
                if (not stat.S_ISREG(opened.st_mode)
                        or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                        or path_problem(path)):
                    raise ValueError("bookmark file changed before reading")
                raw = stream.read(16 * 1024 * 1024 + 1)
                after = os.fstat(stream.fileno())
                if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    raise ValueError("bookmark file changed while reading")
            if len(raw) > 16 * 1024 * 1024:
                raise ValueError("bookmark byte limit reached")
            doc = json.loads(raw)
            if not isinstance(doc, dict) or not isinstance(doc.get("roots"), dict):
                raise ValueError("unsupported bookmark roots")
        except FileNotFoundError:
            return
        except (OSError, ValueError, UnicodeError, RecursionError) as exc:
            mark_fail(label, kind, "bookmark file unreadable or unsupported: " + type(exc).__name__)
            return
        pending = [(node, 0) for node in doc["roots"].values()]
        count = unsupported = 0
        while pending:
            node, depth = pending.pop()
            count += 1
            if count > 100000:
                mark_fail(label, kind, "bookmark entry limit reached")
                break
            if depth > 32 or not isinstance(node, dict):
                unsupported += 1
                continue
            if node.get("type") == "folder" and isinstance(node.get("children"), list):
                pending.extend((child, depth + 1) for child in node["children"])
            elif node.get("type") == "url" and isinstance(node.get("url"), str):
                for ind in ctx.iocs.most_specific(ctx.iocs.search(node["url"].lower())):
                    record_hit(path, ind, "Saved bookmark URL; a bookmark does not establish a visit or contact.")
                r.checked += 1
            elif "type" not in node and node and all(isinstance(v, dict) for v in node.values()):
                # Opera groups its own roots (speed dial, trash, unsorted...) in
                # a map of folders with no type of its own.
                pending.extend((child, depth + 1) for child in node.values())
            else:
                unsupported += 1
        if unsupported:
            mark_fail(label, kind, "{} bookmark entr{} in an unsupported layout were not read".format(
                unsupported, "y" if unsupported == 1 else "ies"))
        mark_ok(label, kind)

    def scan_safari_history(label, path):
        kind = "safari-history"
        opened = open_db(path, label, kind)
        if opened is None:
            return
        con, tmp = opened
        try:
            items, byte_count = {}, 0
            with contextlib.closing(con.execute("SELECT id,url FROM history_items")) as rows:
                for n, (item_id, url) in enumerate(rows):
                    if n >= 200000:
                        raise ValueError("Safari item count limit reached")
                    if type(item_id) is not int or item_id <= 0 or not isinstance(url, str):
                        mark_fail(label, kind, "unsupported Safari item identity or URL")
                        continue
                    byte_count += len(url.encode("utf-8", "replace"))
                    if byte_count > 16 * 1024 * 1024:
                        raise ValueError("Safari URL byte limit reached")
                    if item_id in items:
                        items[item_id] = None
                        mark_fail(label, kind, "ambiguous Safari item identity; its visits were not interpreted")
                    else:
                        items[item_id] = url
            columns = {row[1] for row in con.execute("PRAGMA table_info(history_visits)")}
            origin = "origin" if "origin" in columns else "NULL"
            success = "load_successful" if "load_successful" in columns else "NULL"
            query = "SELECT history_item,visit_time," + origin + "," + success + " FROM history_visits"
            with contextlib.closing(con.execute(query)) as rows:
                for n, (item_id, when, origin, success) in enumerate(rows):
                    history_rows[0] = True
                    if n >= 200000:
                        mark_fail(label, kind, "Safari visit count limit reached")
                        break
                    url = items.get(item_id) if type(item_id) is int else None
                    if url is None:
                        mark_fail(label, kind, "Safari visit has an unavailable or ambiguous URL")
                        continue
                    grade = EV_REFERENCED
                    if type(origin) is not int or origin not in (0, 1) or type(success) is not int or success not in (0, 1):
                        mark_fail(label, kind, "unsupported Safari origin or load status; record retained as reference")
                    elif origin == 0:
                        grade = EV_CONTACTED if success else EV_ATTEMPTED
                    observed = ""
                    try:
                        if type(when) not in (int, float):
                            raise ValueError("unsupported visit timestamp")
                        observed = datetime.datetime.fromtimestamp(when + 978307200).isoformat(timespec="seconds")
                    except (ValueError, OverflowError, OSError):
                        mark_fail(label, kind, "unsupported Safari visit timestamp")
                    for ind, evidence in _browser_url_evidence(url, ctx.iocs, grade):
                        record_hit(path, ind, "Safari visit record; synced/unknown origins remain references; execution is unverified.", evidence, observed)
                    r.checked += 1
            mark_ok(label, kind)
            _count_db()
        except (sqlite3.Error, ValueError, TypeError) as exc:
            mark_fail(label, kind, "Safari history unreadable or unsupported: " + str(exc))
        finally:
            if not _discard_snapshot(os.path.dirname(tmp), con):
                mark_fail(label, kind, "temporary Safari snapshot cleanup failed")

    def scan_safari_stores(label, root):
        """Desktop Safari keeps more than History.db: open and iCloud tabs, a URL
        cache and WebKit's tracking-prevention list in its sandbox, cookies and
        HSTS records there too, and bookmarks, downloads, Top Sites and closed
        tabs as property lists beside its history."""
        current["name"] = "Safari"
        library = os.path.dirname(root)
        sandbox = os.path.join(library, "Containers", "com.apple.Safari", "Data", "Library")
        sql = (
            ("safari-tabs", ("Safari", "SafariTabs.db"), "SELECT url FROM bookmarks", "open Safari tab or tab group"),
            ("safari-cloud-tabs", ("Safari", "CloudTabs.db"), "SELECT url FROM cloud_tabs",
             "tab open on another of the owner's devices (iCloud Tabs)"),
            ("safari-cache", ("Caches", "com.apple.Safari", "Cache.db"),
             "SELECT request_key FROM cfurl_cache_response", "Safari URL cache entry"),
            ("safari-webkit-statistics", ("WebKit", "WebsiteData", "ResourceLoadStatistics", "observations.db"),
             "SELECT registrableDomain FROM ObservedDomains",
             "domain recorded by WebKit tracking prevention; seen in passing, not proof of a visit"),
        )
        for kind, parts, query, what in sql:
            # Current Safari keeps these in its sandbox; older releases beside History.db.
            for path in (os.path.join(sandbox, *parts), os.path.join(library, *parts)):
                opened = open_db(path, label, kind)
                if opened is None:
                    continue
                con, tmp = opened
                try:
                    with contextlib.closing(con.execute(query)) as rows:
                        for n, (value,) in enumerate(rows):
                            if n >= 200000:
                                mark_fail(label, kind, os.path.basename(path) + ": record limit reached; "
                                          "the remaining records were not searched")
                                break
                            if not isinstance(value, str):
                                continue
                            if kind == "safari-webkit-statistics":
                                ind = _host_matches(value, ctx.iocs)
                                if ind is not None:
                                    record_hit(path, ind, what, EV_REFERENCED)
                            else:
                                for ind, evidence in _browser_url_evidence(value, ctx.iocs, EV_REFERENCED):
                                    record_hit(path, ind, what + "; a saved reference, not proof of contact", evidence)
                            r.checked += 1
                    mark_ok(label, kind)
                    _count_db()
                except (sqlite3.Error, ValueError, TypeError) as exc:
                    mark_fail(label, kind, os.path.basename(path) + " unreadable or unsupported: " + str(exc))
                finally:
                    if not _discard_snapshot(os.path.dirname(tmp), con):
                        mark_fail(label, kind, "temporary Safari snapshot cleanup failed")

        def plist_at(kind, path):
            try:
                doc = plistlib.loads(_browser_read_small(path))
            except FileNotFoundError:
                return None
            except (OSError, ValueError, plistlib.InvalidFileException, RecursionError) as exc:
                mark_fail(label, kind, os.path.basename(path) + " unreadable or unsupported: " + type(exc).__name__)
                return None
            if not isinstance(doc, (dict, list)):
                mark_fail(label, kind, os.path.basename(path) + ": unsupported property-list root")
                return None
            return doc

        for kind, name, what in (
                ("safari-bookmarks", "Bookmarks.plist", "Safari bookmark or Reading List entry"),
                ("safari-top-sites", "TopSites.plist", "Safari Top Sites entry"),
                ("safari-closed-tabs", "RecentlyClosedTabs.plist", "recently closed Safari tab"),
                ("safari-downloads", "Downloads.plist", "Safari download record")):
            path = os.path.join(root, name)
            doc = plist_at(kind, path)
            if doc is None:
                continue
            try:
                # Download records are graded per record only in the known layout
                # (a DownloadHistory list of records, each with its own URL).
                # A URL is skipped by the reference pass only when such a record
                # already graded it; every other URL stays a reference, and each
                # record or layout that could not be graded is reported as a gap.
                graded = collections.Counter()
                unsupported = 0
                if kind == "safari-downloads":
                    history = doc.get("DownloadHistory") if isinstance(doc, dict) else None
                    if history is not None and not isinstance(history, list):
                        unsupported += 1
                    for entry in history if isinstance(history, list) else []:
                        url = entry.get("DownloadEntryURL") if isinstance(entry, dict) else None
                        if not isinstance(url, str):
                            unsupported += 1
                            continue
                        # Each record is graded by its own bytes: one that received
                        # data contacted its host, one that received none was only
                        # attempted. A URL repeated across records keeps every grade.
                        got = entry.get("DownloadEntryProgressBytesSoFar")
                        grade = EV_CONTACTED if type(got) is int and got > 0 else EV_ATTEMPTED
                        for ind, evidence in _browser_url_evidence(url, ctx.iocs, grade):
                            record_hit(path, ind, what + "; contact is graded by the bytes received; "
                                       "execution unverified", evidence)
                        graded[url] += 1
                        r.checked += 1
                for key, value in _safari_plist_strings(doc):
                    if key == "DownloadEntryURL" and kind == "safari-downloads":
                        if graded[value]:
                            graded[value] -= 1
                            continue
                        unsupported += 1
                    if not value.lower().startswith(("http://", "https://")):
                        continue
                    for ind, evidence in _browser_url_evidence(value, ctx.iocs, EV_REFERENCED):
                        record_hit(path, ind, what + "; a saved reference, not proof of a visit", evidence)
                    r.checked += 1
                if unsupported:
                    mark_fail(label, kind, "{}: {} download record(s) or field(s) in an unsupported "
                              "layout; their addresses were checked as references only".format(name, unsupported))
                else:
                    mark_ok(label, kind)
            except (ValueError, RecursionError) as exc:
                mark_fail(label, kind, os.path.basename(path) + ": " + str(exc))

        kind = "safari-hsts"
        for path in (os.path.join(sandbox, "Caches", "WebKit", "HSTS", "HSTS.plist"),
                     os.path.join(library, "Cookies", "HSTS.plist")):
            doc = plist_at(kind, path)
            if doc is None:
                continue
            if not isinstance(doc, dict):
                mark_fail(label, kind, "HSTS.plist: unsupported layout")
                continue
            for session in doc.values():
                if not isinstance(session, dict):
                    continue
                for host, record in session.items():
                    if not isinstance(record, dict) or record.get("HSTS Host") is not True:
                        continue
                    r.checked += 1
                    ind = _host_matches(str(host), ctx.iocs)
                    if ind is None:
                        continue
                    created = record.get("Create Time")
                    observed = ""
                    if type(created) in (int, float) and 0 < created < 4e9:
                        observed = datetime.datetime.fromtimestamp(created + _MAC_EPOCH).isoformat(timespec="seconds")
                    # Only a site that answered over HTTPS can set an HSTS record.
                    record_hit(path, ind, "Safari HSTS record: the site sent its security policy to this browser",
                               EV_CONTACTED, observed)
            mark_ok(label, kind)

        kind = "safari-cookies"
        cookie_paths = [os.path.join(sandbox, "Cookies", "Cookies.binarycookies"),
                        os.path.join(library, "Cookies", "Cookies.binarycookies")]
        if _browser_same_store_alias(os.path.join(sandbox, "Cookies"), os.path.join(library, "Cookies")):
            # macOS ships the sandbox Cookies folder as a link to ~/Library/Cookies,
            # which is read directly below; the link is never followed.
            cookie_paths = cookie_paths[1:]
        for path in cookie_paths:
            try:
                cookies = _safari_cookie_domains(_browser_read_small(path, 64 * 1024 * 1024))
            except FileNotFoundError:
                continue
            except (OSError, ValueError, UnicodeError, struct.error) as exc:
                mark_fail(label, kind, os.path.basename(path) + " unreadable or unsupported: " + str(exc))
                continue
            for domain, when in cookies:
                r.checked += 1
                ind = _host_matches(domain.lstrip("."), ctx.iocs)
                if ind is None:
                    continue
                observed = datetime.datetime.fromtimestamp(when).isoformat(timespec="seconds") if when else ""
                # A cookie exists only because the site's response set it.
                record_hit(path, ind, "Safari cookie: the site set it in this browser", EV_CONTACTED, observed)
            mark_ok(label, kind)

    def scan_history(label, path, flavour):
        """History / moz_places, host-graded.

        A history row whose URL HOST is the indicator means the browser actually
        went there, so it grades as contacted and carries the row's own visit
        date as the observed time (when the schema records it). A match only in
        the query string or page title is a reference - often a search for the
        name - so it stays referenced. Chromium's download records live in the
        same db and stay referenced (a saved path/URL, not proof of contact)."""
        kind = "history"
        opened = open_db(path, label, kind)
        if opened is None:
            return
        con, tmp = opened
        read_ok = False
        failed = False
        try:
            if flavour == "chromium":
                table, visit_col, conv = "urls", "last_visit_time", chrome_time
            else:
                table, visit_col, conv = ("moz_places", "last_visit_date",
                                          unix_us_time)
            try:
                present = {row[1] for row in
                           con.execute("PRAGMA table_info({})".format(table))}
            except sqlite3.Error as exc:
                present = set()
                if not _is_schema_drift(exc):
                    mark_fail(label, kind, _locked_note(path, exc))
                    failed = True

            if not failed and "url" not in present:
                mark_fail(label, kind, "the history store has no supported URL "
                          "column, so navigation history could not be searched")
                failed = True
            if not failed and "url" in present:
                cols = ["url"]
                if "title" in present:
                    cols.append("title")
                if visit_col in present:
                    cols.append(visit_col)
                if flavour == "firefox" and "visit_count" in present:
                    cols.append("visit_count")
                local_visit = None
                if flavour == "chromium" and "id" in present:
                    cols.append("id")
                    local_visit = _chromium_visit_origins(con)
                synced_seen = set()
                try:
                    rows = con.execute("SELECT {} FROM {}".format(
                        ", ".join(cols), table)).fetchall()
                except sqlite3.Error as exc:
                    rows = None
                    if not _is_schema_drift(exc):
                        mark_fail(label, kind, _locked_note(path, exc))
                        failed = True
                if rows is not None:
                    read_ok = True
                    if rows:
                        history_rows[0] = True
                    for row in rows:
                        rec = dict(zip(cols, row))
                        url = str(rec.get("url") or "")
                        title = str(rec.get("title") or "")
                        blob = (url + " " + title).lower()
                        observed = _fmt_time(conv, rec.get(visit_col))
                        # A URL row alone does not establish a visit. Firefox's
                        # places database stores never-visited bookmarks, and
                        # Chromium keeps rows with no recorded visit
                        # (last_visit_time 0). Where the visit column is missing or
                        # unreadable there is nothing to decide on, so such a row
                        # keeps its previous grade rather than being downgraded.
                        has_visit = flavour != "firefox"
                        if flavour == "firefox":
                            for raw in (rec.get(visit_col), rec.get("visit_count")):
                                try:
                                    has_visit = has_visit or int(raw or 0) > 0
                                except (TypeError, ValueError, OverflowError):
                                    pass
                        elif visit_col in rec:
                            try:
                                has_visit = int(rec.get(visit_col) or 0) > 0
                            except (TypeError, ValueError, OverflowError):
                                pass
                        # Every recorded visit came from another synced device.
                        synced_only = (has_visit and local_visit is not None
                                       and local_visit.get(rec.get("id")) is False)
                        for ind, grade in _browser_url_evidence(
                                url, ctx.iocs, EV_CONTACTED if has_visit else EV_REFERENCED, title):
                            if synced_only and grade == EV_CONTACTED:
                                record_hit(path, ind, "history, visited on another synced "
                                           "device: " + blob[:160], EV_REFERENCED)
                                if ind.value not in synced_seen:
                                    synced_seen.add(ind.value)
                                    r.add_lead(Lead(
                                        "browser:synced-history", path,
                                        "a device synced to this browser profile visited {} ({})"
                                        .format(ind.value, ind.family or "unnamed family"),
                                        _WHY_SYNCED, observed))
                                continue
                            record_hit(path, ind, "history: " + blob[:160], grade,
                                       observed if grade == EV_CONTACTED else "")

            if flavour == "chromium" and not failed:
                try:
                    rows = con.execute(
                        "SELECT current_path, tab_url, referrer "
                        "FROM downloads").fetchall()
                except sqlite3.Error as exc:
                    rows = None
                    if not _is_schema_drift(exc):
                        mark_fail(label, kind, _locked_note(path, exc))
                        failed = True
                if rows is not None:
                    read_ok = True
                    for row in rows:
                        blob = " ".join(str(c) for c in row
                                        if c is not None).lower()
                        for ind in ctx.iocs.most_specific(ctx.iocs.search(blob)):
                            record_hit(path, ind, "download: " + blob[:160],
                                       EV_REFERENCED)

            if flavour == "chromium":
                try:
                    download_cols = {c[1] for c in con.execute("PRAGMA table_info(downloads)")}
                    if {"id", "state", "received_bytes"} <= download_cols:
                        chain_query = ("SELECT c.id,c.chain_index,c.url,d.state,d.received_bytes "
                                       "FROM downloads_url_chains c LEFT JOIN downloads d ON c.id=d.id "
                                       "ORDER BY c.id,c.chain_index")
                    else:
                        chain_query = "SELECT id,chain_index,url,NULL,NULL FROM downloads_url_chains ORDER BY id,chain_index"
                    chains = con.execute(chain_query)
                    # Closed explicitly: a cursor left open after the row limit
                    # keeps the snapshot file locked on Windows, so the
                    # temporary copy of the database could not be removed.
                    try:
                        for n, row in enumerate(chains):
                            if n >= 200000:
                                mark_fail(label, "download-chains", "download-chain row limit reached")
                                break
                            url = str(row[2] or "")
                            contacted = row[3] == 1 or (isinstance(row[4], int) and row[4] > 0)
                            detail = "download chain {} step {}: {} (execution unverified; contact requires completed/received download metadata)".format(row[0], row[1], url[:160])
                            for ind, grade in _browser_url_evidence(
                                    url, ctx.iocs, EV_CONTACTED if contacted else EV_ATTEMPTED):
                                record_hit(path, ind, detail, grade)
                            r.checked += 1
                    finally:
                        chains.close()
                    mark_ok(label, "download-chains")
                except sqlite3.Error as exc:
                    if not _is_schema_drift(exc):
                        mark_fail(label, "download-chains", _locked_note(path, exc))

            if not failed:
                # Opened and queried without corruption: this artifact was read.
                mark_ok(label, kind)
                if read_ok:
                    _count_db()
        finally:
            # Close the handle BEFORE removing, or Windows keeps the copy.
            if not _discard_snapshot(os.path.dirname(tmp), con):
                r.note("could not remove the temporary snapshot of {} - a copy "
                       "may remain in the system temp directory"
                       .format(os.path.basename(path)))

    def scan_favicons(label, path, flavour):
        """Favicons. For Chromium, a favicon URL whose stored bitmap is present
        and non-empty means the browser actually fetched the icon from that host
        (contacted); a row with no image is only a reference. For Firefox the
        presence of a moz_icons entry already means the icon was fetched, so it
        grades as contacted."""
        kind = "favicons"
        opened = open_db(path, label, kind)
        if opened is None:
            return
        con, tmp = opened
        try:
            if flavour == "chromium":
                # EXISTS, not a join: duplicate ids in a crafted database would
                # multiply a join into millions of rows from a tiny file.
                sql = ("SELECT favicons.url, EXISTS(SELECT 1 FROM favicon_bitmaps "
                       "WHERE favicon_bitmaps.icon_id = favicons.id "
                       "AND favicon_bitmaps.image_data IS NOT NULL "
                       "AND length(favicon_bitmaps.image_data) > 0) "
                       "FROM favicons")
                graded = True
            else:
                sql = "SELECT icon_url FROM moz_icons"
                graded = False
            # Streamed and capped: rows are never all held in memory at once.
            limited = False
            try:
                rows = con.execute(sql)
                try:
                    for n, row in enumerate(rows):
                        if n >= _FAVICON_ROW_LIMIT:
                            limited = True
                            break
                        if graded:
                            url, has_bitmap = row[0], row[1]
                            ev = EV_CONTACTED if has_bitmap else EV_REFERENCED
                        else:
                            url, ev = row[0], EV_CONTACTED
                        blob = str(url or "").lower()
                        # Anchor to the HOST, the same way history does. A stored
                        # bitmap proves the browser fetched that icon - from the
                        # icon URL's own host. An indicator sitting in the query
                        # string of an otherwise innocent favicon URL proves
                        # contact with the innocent host, not with the indicator,
                        # so it must not be graded as contact.
                        for ind, grade in _browser_url_evidence(blob, ctx.iocs, ev):
                            record_hit(path, ind, "favicon: " + blob[:160], grade)
                finally:
                    rows.close()
            except sqlite3.Error as exc:
                mark_fail(label, kind, _locked_note(path, exc))
                return
            if limited:
                mark_fail(label, kind, "{} holds more than {:,} icons; the rest were not "
                          "checked".format(path, _FAVICON_ROW_LIMIT))
                return
            mark_ok(label, kind)
            _count_db()
        finally:
            # Close the handle BEFORE removing, or Windows keeps the copy.
            if not _discard_snapshot(os.path.dirname(tmp), con):
                r.note("could not remove the temporary snapshot of {} - a copy "
                       "may remain in the system temp directory"
                       .format(os.path.basename(path)))

    def scan_cookies(label, path, flavour):
        """Cookies get their own reader because they are the richest artifact
        here, and the generic row-to-string match throws away the two things a
        person actually needs: WHEN the cookie was set, and WHICH page they were
        on when it happened.

        Chromium partitions third-party cookies by top-level site, so
        `top_frame_site_key` names the site that was being visited when an ad
        tracker set its cookie. For an ad-delivered indicator that is the single
        most useful field in the whole scan - it turns "something was contacted"
        into "this happened on that site, on that date".

        The store is not counted as checked until rows are in hand: every early
        exit (unreadable schema, no usable columns, a failed SELECT) is a gap, so
        a locked cookie store - the common case, because the browser is open -
        shows up as such rather than as a clean, empty result.
        """
        kind = "cookies"
        opened = open_db(path, label, kind)
        if opened is None:
            return
        con, tmp = opened
        try:
            # Only ask for columns this database actually has. Cookie schemas
            # differ across browser versions and forks, and a single missing
            # column would otherwise fail the whole query and silently lose the
            # richest artifact in the scan.
            table = "cookies" if flavour == "chromium" else "moz_cookies"
            try:
                present = {row[1] for row in
                           con.execute("PRAGMA table_info({})".format(table))}
            except sqlite3.Error as exc:
                r.skipped += 1
                mark_fail(label, kind, _locked_note(path, exc))
                return
            if flavour == "chromium":
                candidates = ["host_key", "name", "creation_utc",
                              "last_access_utc", "top_frame_site_key"]
                conv = chrome_time
            else:
                candidates = ["host", "name", "creationTime", "lastAccessed"]
                conv = unix_us_time
            wanted = [c for c in candidates if c in present]
            host_column = "host_key" if flavour == "chromium" else "host"
            if host_column not in wanted:
                r.skipped += 1
                mark_fail(label, kind,
                          "the cookie store {} had no supported host column, "
                          "so its cookie origins could not be searched"
                          .format(os.path.basename(path)))
                return
            sql = "SELECT {} FROM {}".format(", ".join(wanted), table)
            try:
                rows = con.execute(sql).fetchall()
            except sqlite3.Error as exc:
                r.skipped += 1
                mark_fail(label, kind, _locked_note(path, exc))
                return

            # Rows are in hand: now the store genuinely counts as read.
            mark_ok(label, kind)
            _count_db()
            cookie_stores[0] += 1

            for row in rows:
                record = dict(zip(wanted, row))
                host = str(record.get("host_key") or record.get("host") or "")
                for ind in ctx.iocs.most_specific(ctx.iocs.search(host.lower())):
                    created = _fmt_time(conv, record.get("creation_utc")
                                        or record.get("creationTime"))
                    seen = _fmt_time(conv, record.get("last_access_utc")
                                     or record.get("lastAccessed"))
                    partition = str(record.get("top_frame_site_key") or "").strip()
                    bits = ["cookie set by {}".format(host),
                            "name {}".format(record.get("name") or "?")]
                    if partition:
                        bits.append("set while visiting {}".format(partition))
                    if created:
                        bits.append("first set {}".format(created))
                    if seen and seen != created:
                        bits.append("last used {}".format(seen))
                    elif seen:
                        bits.append("never used again after that")
                    record_hit(path, ind, "; ".join(bits), EV_CONTACTED,
                               created or seen)
                    if created:
                        cookie_times.append(conv(int(
                            record.get("creation_utc")
                            or record.get("creationTime"))))
            # Oldest cookie overall, for the time-coverage section.
            col = "creation_utc" if flavour == "chromium" else "creationTime"
            if col in present:
                try:
                    raw = con.execute(
                        "SELECT MIN({0}) FROM {1} WHERE {0} > 0".format(
                            col, table)).fetchone()
                    if raw and raw[0]:
                        cookie_times.append(conv(int(raw[0])))
                except (sqlite3.Error, ValueError, OverflowError, OSError):
                    pass
        finally:
            # Close the handle BEFORE removing, or Windows keeps the copy.
            if not _discard_snapshot(os.path.dirname(tmp), con):
                r.note("could not remove the temporary snapshot of {} - a copy "
                       "may remain in the system temp directory"
                       .format(os.path.basename(path)))

    def scan_blobs(label, root):
        """Substring-search binary files (HTTP cache, LevelDB) for the needles.

        Raw bytes do not distinguish origin keys from saved page content. Every
        match here is referenced, even when it looks like a complete origin URL.

        A directory that exists and can be walked is a successful check of the
        "blobs" kind, even if it holds no files (a present-but-empty cache is a
        legitimately clean cache). A subtree that could not be walked at all, or a
        file too large to hold in memory, is a gap - never dropped silently."""
        kind = "blobs"
        problem = path_problem(root)
        if problem:
            r.skipped += 1
            mark_fail(label, kind, "{}: {}".format(root, problem))
            return
        try:
            os.stat(root)
        except FileNotFoundError:
            return  # artifact absent for this profile — not a gap
        except OSError as exc:
            r.skipped += 1
            r.note(_locked_note(root, exc))
            mark_fail(label, kind, _locked_note(root, exc))
            return

        failures = []

        def onerror(exc):
            # os.walk swallows directory errors unless we catch them here.
            failures.append("could not enumerate {}: {}".format(
                getattr(exc, "filename", root), exc))
            r.skipped += 1
            r.note("could not enumerate {}: {}".format(
                getattr(exc, "filename", root), exc))

        read_any = False
        owner_index = {}
        for dirpath, _dirs, files in walk_local(root, onerror=onerror):
            for fn in files:
                heartbeat(label)
                full = os.path.join(dirpath, fn)
                try:
                    problem = path_problem(full)
                    if problem:
                        raise PermissionError(13, problem, full)
                    st = os.stat(full)
                except OSError as exc:
                    r.skipped += 1
                    r.note("could not read {}: {}".format(full, exc))
                    failures.append("could not stat {}: {}".format(full, exc))
                    continue
                if st.st_size > 400 * 1024 * 1024:
                    r.skipped += 1  # too large to search — a gap, not clean
                    r.note("{} is larger than 400 MB and was not searched"
                           .format(full))
                    failures.append("{} exceeds the 400 MB search limit".format(full))
                    continue
                try:
                    with io.open(full, "rb") as fh:
                        data = fh.read()
                    lowered = data.lower()
                except MemoryError:
                    # read() then .lower() needs two copies; a file that will not
                    # fit is recorded as a gap, not pretended to be searched.
                    r.skipped += 1
                    failures.append("{} could not fit in memory".format(full))
                    continue
                except OSError as exc:
                    if fn == "LOCK" and st.st_size == 0:
                        # LevelDB's empty lock sentinel, held open by a running
                        # browser. It never holds data, so missing it loses
                        # nothing; a LOCK file with content is still read.
                        continue
                    r.skipped += 1  # unreadable file — a gap, not clean
                    r.note("could not read {}: {}".format(full, exc))
                    failures.append("could not read {}: {}".format(full, exc))
                    continue
                # Oldest cache artifact = how far back this check can possibly see.
                # Browsers recycle the cache continuously, so this is a measured
                # window, not a guess, and it is usually far shorter than people
                # assume.
                seen_mtimes.append(st.st_mtime)
                r.submetrics["blob"] += 1
                r.checked += 1
                read_any = True
                matched = list(ctx.iocs.search_bytes(lowered))
                source = _filter_list_source(full, data, owner_index) if matched else None
                if source:
                    # An ad-blocker's own copy of a filter list: protection, not
                    # contact. Counted and noted once, never a finding.
                    filter_lists["indicators"] += len(matched)
                    filter_lists["files"] += 1
                    if len(filter_lists["examples"]) < 3:
                        filter_lists["examples"].append("{} ({})".format(full, source))
                    continue
                for ind in matched:
                    # Local Storage / Session Storage / Service Worker entries
                    # are KEYED BY ORIGIN, which is why a match there was graded
                    # as contact. But this is a raw byte search over the whole
                    # file, and these stores also hold page CONTENT - a saved
                    # article, a quoted report. An indicator inside a stored
                    # value proves someone read about this campaign, not that
                    # the device talked to it, and telling a journalist who read
                    # the Citizen Lab report that their device "demonstrably
                    # communicated with" spyware infrastructure is the worst
                    # kind of false alarm. A URL-looking string is not enough
                    # to identify a structured origin key, so retain a reference.
                    record_hit(full, ind,
                               "binary match in cache/leveldb; raw bytes do not "
                               "establish whether this is an origin or saved content",
                               EV_REFERENCED)

        if read_any or not failures:
            mark_ok(label, kind)
        if failures:
            mark_fail(label, kind,
                      "{} item(s) under {} were not searched: {}"
                      .format(len(failures), root, "; ".join(failures[:3])))

    def scan_connection_records(label, prof):
        """The two long-lived records of hosts the browser actually CONNECTED to.

        Why these matter more than the cache: the HTTP cache is recycled within
        weeks and a byte match in it may only be page content mentioning a name.
        These two files instead record that a connection happened, they survive
        far longer, and HSTS even carries the date it was observed.

        TransportSecurity - HSTS state. An entry exists because that host served
        an HSTS header over HTTPS. Hostnames are stored hashed, so we hash our
        indicators and compare; we never learn anything about other hosts.

        Network Persistent State - plaintext origins of servers the browser has
        connected to, plus hosts with broken alternative services.
        """
        net_dir = os.path.join(prof, "Network")

        ts_path = os.path.join(net_dir, "TransportSecurity")
        ts_present = True
        try:
            problem = path_problem(ts_path)
            if problem:
                raise PermissionError(13, problem, ts_path)
            os.stat(ts_path)
        except FileNotFoundError:
            ts_present = False
        except OSError as exc:
            r.skipped += 1
            mark_fail(label, "hsts", _locked_note(ts_path, exc))
            ts_present = False
        if ts_present:
            try:
                with io.open(ts_path, encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
                if not isinstance(data, dict):
                    raise ValueError("HSTS state must be an object")
                entries = data.get("sts", [])
                # Shape-check rather than trust: a file whose "sts" is a number
                # rather than a list made len() raise TypeError, which escaped
                # the (OSError, ValueError) handler below, propagated out of the
                # module and cost every hit already collected. A malformed
                # artifact is a gap for THIS artifact, never a crash.
                if not isinstance(entries, list):
                    raise ValueError(
                        "unexpected shape: 'sts' is {}, expected a list"
                        .format(type(entries).__name__))
                r.submetrics["hsts_entries"] = (
                    r.submetrics.get("hsts_entries", 0) + len(entries))
                r.checked += len(entries)
                mark_ok(label, "hsts")
                if entries:
                    held = {}
                    for e in entries:
                        if not isinstance(e, dict) or not isinstance(e.get("host"), str):
                            raise ValueError("HSTS entry must contain a host string")
                        held[e["host"]] = e
                    for ind in ctx.iocs.indicators:
                        if ind.type != "domain":
                            continue
                        e = held.get(_hsts_fingerprint(ind.value))
                        if e is None:
                            continue
                        when = ""
                        try:
                            when = datetime.datetime.fromtimestamp(
                                float(e.get("sts_observed"))).isoformat(
                                    timespec="seconds")
                        except (TypeError, ValueError, OverflowError, OSError):
                            pass
                        record_hit(
                            ts_path, ind,
                            "HSTS state recorded for this exact host - the "
                            "browser received an HSTS header from it over HTTPS"
                            + (" (observed {})".format(when[:10]) if when else ""),
                            EV_CONTACTED, when)
            except (OSError, ValueError, RecursionError, MemoryError) as exc:
                r.skipped += 1
                mark_fail(label, "hsts", _locked_note(ts_path, exc))

        nps_path = os.path.join(net_dir, "Network Persistent State")
        nps_present = True
        try:
            problem = path_problem(nps_path)
            if problem:
                raise PermissionError(13, problem, nps_path)
            os.stat(nps_path)
        except FileNotFoundError:
            nps_present = False
        except OSError as exc:
            r.skipped += 1
            mark_fail(label, "connection-records", _locked_note(nps_path, exc))
            nps_present = False
        if nps_present:
            try:
                with io.open(nps_path, encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
                if not isinstance(data, dict):
                    raise ValueError("network state must be an object")
                net = data.get("net", {})
                if not isinstance(net, dict):
                    raise ValueError("network state 'net' must be an object")
                hsp = net.get("http_server_properties", {})
                if not isinstance(hsp, dict):
                    raise ValueError("http_server_properties must be an object")
                for field, host_field in (("servers", "server"),
                                          ("broken_alternative_services", "host")):
                    entries = hsp.get(field, [])
                    if not isinstance(entries, list):
                        raise ValueError("{} must be a list".format(field))
                    for row in entries:
                        if not isinstance(row, dict) or not isinstance(
                                row.get(host_field), str):
                            raise ValueError("{} contains an invalid host record"
                                             .format(field))
                origins = []
                for row in hsp.get("servers") or []:
                    if isinstance(row, dict) and row.get("server"):
                        origins.append((_host_of(row["server"]), "connected server"))
                for row in hsp.get("broken_alternative_services") or []:
                    if isinstance(row, dict) and row.get("host"):
                        origins.append((_host_of(row["host"]),
                                        "broken alternative service"))
                r.submetrics["connection_records"] = (
                    r.submetrics.get("connection_records", 0) + len(origins))
                r.checked += len(origins)
                mark_ok(label, "connection-records")
                for host, kind in origins:
                    ind = _host_matches(host, ctx.iocs)
                    if ind is not None:
                        record_hit(
                            nps_path, ind,
                            "{}: the browser has a connection record for {}"
                            .format(kind, host), EV_CONTACTED)
            except (OSError, ValueError, RecursionError, MemoryError) as exc:
                r.skipped += 1
                mark_fail(label, "connection-records",
                          _locked_note(nps_path, exc))

    def scan_firefox_hsts(label, path):
        """Firefox's HSTS store, SiteSecurityServiceState.txt.

        Like Chromium's TransportSecurity, every hostname here is one the browser
        connected to over HTTPS and received an HSTS header from, so a match is
        proof of contact. Unlike Chromium's, Firefox keeps the hostnames in
        PLAINTEXT, so we read the file as text and run the shared matcher over it;
        only our indicators are searched for, so no other host from the file ever
        reaches the output.
        """
        try:
            problem = path_problem(path)
            if problem:
                raise PermissionError(13, problem, path)
            os.stat(path)
        except FileNotFoundError:
            return
        except OSError as exc:
            r.skipped += 1
            mark_fail(label, "hsts", _locked_note(path, exc))
            return
        try:
            with io.open(path, "rb") as fh:
                raw = fh.read(4 * 1024 * 1024 + 1)
            if len(raw) > 4 * 1024 * 1024:
                raise ValueError("HSTS store exceeds the read limit")
            if path.endswith(".bin"):
                rows, invalid = _browser_hsts_binary(raw)
            else:
                rows, invalid = [], 0
                for line in raw.decode("utf-8").splitlines():
                    fields = line.split("\t")
                    if len(fields) == 4:
                        rows.append((fields[0], fields[3]))
                    elif line.strip():
                        invalid += 1
        except (OSError, ValueError) as exc:
            r.skipped += 1
            mark_fail(label, "hsts", _locked_note(path, exc))
            return
        entries = len(rows)
        r.submetrics["hsts_entries"] = (
            r.submetrics.get("hsts_entries", 0) + entries)
        r.checked += entries
        mark_ok(label, "hsts")
        for key, value in rows:
            if not re.fullmatch(r"\d+,[012],[01](?:,\d+)?", value):
                invalid += 1
                continue
            host = key.removesuffix(":HSTS") if hasattr(key, "removesuffix") else (key[:-5] if key.endswith(":HSTS") else key)
            host = host.split("^", 1)[0]
            ind = _host_matches(host.lower(), ctx.iocs)
            if ind:
                grade = EV_CONTACTED if value.split(",")[1] == "1" else EV_REFERENCED
                record_hit(path, ind, "Firefox HSTS host state; expiry and last-access counters are not visit times", grade)
        if invalid:
            mark_fail(label, "hsts", "{} invalid HSTS record(s) were not interpreted".format(invalid))

    # No browser profile location is known for this platform at all: say so as a
    # gap rather than returning an empty, falsely-clean result.
    ff_roots = FIREFOX_ROOTS if FIREFOX_ROOTS is not None else _firefox_roots()
    # Desktop apps with a built-in Chromium (see APP_ROOTS). Decided before the
    # 'nothing to look at' test below: a machine with apps but no browser still
    # has somewhere to look.
    if ctx.targets:
        app_roots = []
    elif APP_ROOTS is not None:
        app_roots = list(APP_ROOTS)
    elif CHROMIUM_ROOTS is _DEFAULT_CHROMIUM_ROOTS:
        discovery_gaps = []
        app_roots = _app_roots(discovery_gaps)
        for reason in discovery_gaps:
            r.could_not_run("app-discovery", reason)
    else:
        app_roots = []
    chromium_roots = list(CHROMIUM_ROOTS)
    safari_roots = []
    if not ctx.targets and CHROMIUM_ROOTS is _DEFAULT_CHROMIUM_ROOTS:
        safari_roots = _browser_safari_roots()
        for label, root in safari_roots:
            chromium_roots.append((label, root))
            profiles, _, gaps = _browser_targeted_roots(os.path.join(root, "Profiles"))
            chromium_roots.extend((label, profile) for profile in profiles)
            for reason in gaps:
                r.could_not_run("browser", reason)
    if ctx.targets:
        app_roots, chromium_roots, ff_roots = [], [], []
        for selected in ctx.targets:
            found_chromium, found_firefox, search_gaps = _browser_targeted_roots(selected)
            chromium_roots += [("selected", p) for p in found_chromium if ("selected", p) not in chromium_roots]
            ff_roots += [(p, os.path.join(p, "cache2")) for p in found_firefox
                         if (p, os.path.join(p, "cache2")) not in ff_roots]
            for reason in search_gaps:
                r.could_not_run("browser", reason)
    r.submetrics["desktop_apps_found"] = len(app_roots)
    if app_roots:
        r.note("Checking web traces stored by desktop apps, including chat apps. Listing an app means its local records are being checked; it is not a finding against that app.")
    if not chromium_roots and not ff_roots and not app_roots:
        if ctx.targets:
            # Nothing to read is not the same as read and clean.
            r.inapplicable_reason = ("No browser profile was found in the selected targets. "
                                     "Selected file fingerprints are reported separately.")
            return r
        r.could_not_run("browser", "no browser profile locations are known for "
                        "{}".format(sys.platform))
        return r

    # --- Chromium family: Chrome, Edge, Brave, Vivaldi, Chromium ---------------------
    # ... plus desktop apps with a built-in Chromium (found above).
    app_caches_skipped = []
    # A History.db that is not SQLite stays a gap for Safari itself and for
    # folders the person chose; elsewhere it is some other app's own file.
    strict_safari = {label for label, _root in safari_roots} | {"selected"}
    for label, root in chromium_roots + app_roots:
        problem = path_problem(root)
        if problem:
            r.could_not_run(label + ":profiles", "{}: {}".format(root, problem))
            continue
        if not os.path.isdir(root):
            continue  # browser not installed — absent, so no sub-check for it
        try:
            profs = chromium_profiles(root)
        except OSError as exc:
            # One bad ACL on the user-data root must not abort the whole module.
            r.could_not_run(label + ":profiles", _locked_note(root, exc))
            continue
        if _looks_like_profile(root):
            # Safari can keep its main history alongside a Profiles directory.
            profs.insert(0, root)
        names = _chromium_profile_names(root)
        ctx.emit("[*] {} ({} profile(s))".format(root, len(profs)))
        for prof in profs:
            problem = path_problem(prof)
            if problem:
                r.could_not_run(label + ":profile:" + os.path.basename(prof), problem)
                continue
            if not os.path.isdir(prof):
                continue
            folder = os.path.basename(prof)
            display = names.get(folder, "")
            # Name the account in the hit, falling back to the folder when the
            # browser has no display name recorded for it.
            current["name"] = ("{} ({})".format(display, folder) if display
                               else folder)
            ctx.emit("[*]   profile: {}".format(current["name"]))
            scan_bookmarks(label, os.path.join(prof, "Bookmarks"))
            safari_db = os.path.join(prof, "History.db")
            if label in strict_safari or _sqlite_or_absent(safari_db):
                scan_safari_history(label, safari_db)
            else:
                # Another app's own "history.db" (FreeTube keeps a text file
                # under that name, and Windows ignores the case). It is not
                # Safari's database, so it is not a gap; say so plainly.
                r.note("{} has its own history.db in a non-database format; it is "
                       "not Safari history and was not read as such.".format(label))
            scan_history(label, os.path.join(prof, "History"), "chromium")
            scan_cookies(label, os.path.join(prof, "Network", "Cookies"),
                         "chromium")
            scan_cookies(label, os.path.join(prof, "Cookies"), "chromium")
            scan_favicons(label, os.path.join(prof, "Favicons"), "chromium")
            scan_connection_records(label, prof)
            # Raw stores: every match is graded referenced (see scan_blobs).
            for sub in (("Cache", "Cache_Data"), ("Code Cache", "js"),
                        ("Local Storage", "leveldb"), ("Session Storage",),
                        ("Service Worker", "CacheStorage")):
                # A desktop app's raw web cache is most of its data and only 'referenced'
                # evidence; it is read in the full scan. Cookies, history,
                # connection records and site storage are always read.
                if (label.startswith("app:") and not ctx.full
                        and sub[0] in ("Cache", "Code Cache")):
                    app_caches_skipped.append(os.path.join(prof, *sub))
                    continue
                blob_roots = [prof]
                if sub[0] in ("Cache", "Code Cache"):
                    cache_profile = _browser_cache_profile(prof)
                    if cache_profile != prof and _browser_cache_in_scope(cache_profile, ctx.targets):
                        blob_roots.append(cache_profile)
                for blob_root in blob_roots:
                    scan_blobs(label, os.path.join(blob_root, *sub))

    _report_app_caches_skipped(r, app_caches_skipped)

    # --- Firefox: roaming profiles for the dbs, local cache for the cache ---
    # A stray cross-profile hit must never be stamped with the last Chrome
    # profile, so reset attribution before the Firefox walk and keep it
    # per-profile inside the loop (the cache lives in a sibling tree whose
    # profile folders share the same names - the old code swept it ONCE, outside
    # the loop, stamping every Firefox cache hit with the last Chrome profile).
    current["name"] = ""
    for profiles_dir, cache_dir in ff_roots:
        ff_label = _firefox_label(profiles_dir)
        refused = [(p, path_problem(p)) for p in (profiles_dir, cache_dir)]
        if any(reason for _p, reason in refused):
            for p, reason in refused:
                if reason:
                    r.could_not_run(ff_label + ":profiles:" + p, reason)
            continue
        prof_is_dir = os.path.isdir(profiles_dir)
        cache_is_dir = os.path.isdir(cache_dir)
        if not prof_is_dir and not cache_is_dir:
            continue
        ff_names, ff_known = _firefox_ini(profiles_dir) if prof_is_dir and not ctx.targets else ({}, set())
        ctx.emit("[*] {}".format(profiles_dir if prof_is_dir else cache_dir))

        folders = set()
        if prof_is_dir:
            try:
                folders.update(os.listdir(profiles_dir))
            except OSError as exc:
                r.could_not_run(ff_label + ":profiles",
                                _locked_note(profiles_dir, exc))
        if cache_is_dir:
            try:
                folders.update(os.listdir(cache_dir))
            except OSError as exc:
                r.could_not_run(ff_label + ":cache-dir", _locked_note(cache_dir, exc))

        if ctx.targets:
            folders = {""}
        for name in sorted(folders):
            prof = os.path.join(profiles_dir, name)
            cprof = os.path.join(cache_dir, name)
            refused = [(p, path_problem(p)) for p in (prof, cprof)]
            if any(reason for _p, reason in refused):
                for p, reason in refused:
                    if reason:
                        r.could_not_run(ff_label + ":profile:" + p, reason)
                continue
            if not os.path.isdir(prof) and not os.path.isdir(cprof):
                continue
            # On Linux the profiles root also holds non-profile folders (Crash
            # Reports, Pending Pings, Profile Groups). Only treat a folder as a
            # profile if profiles.ini lists it or it holds a profile marker file,
            # so those are not scanned and mislabelled as profiles.
            if name not in ff_known:
                try:
                    if not _is_ff_profile_dir(prof):
                        continue
                except OSError as exc:
                    r.could_not_run(ff_label + ":profile:" + name, str(exc))
                    continue
            display = ff_names.get(name, "")
            current["name"] = ("{} ({})".format(display, name) if display
                               else name)
            ctx.emit("[*]   profile: {}".format(current["name"]))
            if os.path.isdir(prof):
                # Every Firefox-family browser uses Firefox's database formats.
                scan_history(ff_label, os.path.join(prof, "places.sqlite"),
                             "firefox")
                scan_cookies(ff_label, os.path.join(prof, "cookies.sqlite"),
                             "firefox")
                scan_favicons(ff_label, os.path.join(prof, "favicons.sqlite"),
                              "firefox")
                scan_firefox_hsts(
                    ff_label,
                    os.path.join(prof, "SiteSecurityServiceState.txt"))
                scan_firefox_hsts(ff_label, os.path.join(prof, "SiteSecurityServiceState.bin"))
            if os.path.isdir(cprof):
                scan_blobs(ff_label, cprof)

    # --- Safari's other stores (macOS): sandbox and ~/Library/Safari --------
    for label, root in safari_roots:
        scan_safari_stores(label, root)

    # Nothing written after this point should inherit a stale profile name.
    current["name"] = ""

    # --- roll each (browser, kind) up into a check the verdict can read -----
    #
    # A kind that at least one profile read is a check that ran (and, with no hit,
    # is clean). A kind that was present but could never be read is a check that
    # could_not_run, which the verdict surfaces as a gap - never folded into a
    # clean result.
    for (label, kind), state in kinds.items():
        check_name = "{}:{}".format(label, kind)
        if state["ok"]:
            r.ran(check_name)
            # A profile that could not be read is still a gap when a DIFFERENT
            # profile of the same browser read fine: the unread profile was
            # never searched, so nothing has been cleared for it. Previously the
            # successful profile set a single flag and these vanished, so a
            # locked second profile came out CLEAN with no gap - the collapse of
            # UNKNOWN into CLEAN that D3 exists to prevent. Each is named with
            # its account so the report can say WHICH one was not covered.
            for profile_name, reason in state["failures"]:
                r.could_not_run(
                    "{} [{}]".format(check_name, profile_name or "profile"),
                    reason)
        else:
            # Nothing anywhere read this kind: the kind itself is the gap.
            r.could_not_run(check_name, state["reason"] or "could not be read")

    if filter_lists["files"]:
        r.submetrics["filter_list_indicators"] = filter_lists["indicators"]
        r.note("{} indicator match(es) in {} file(s) are inside an ad-blocker's filter "
               "list, which contains these addresses in order to block them. This is "
               "expected and is not a sign of contact or infection, so they are not "
               "findings. For example: {}".format(
                   filter_lists["indicators"], filter_lists["files"],
                   "; ".join(filter_lists["examples"])))

    # Report the measured window. Without this, "browser: CLEAN" invites the reader
    # to assume it means "clean for as long as I have owned this computer", which is
    # never true — and for a campaign that ran in 2024-2025, the gap between the two
    # readings is the whole answer.
    if seen_mtimes:
        earliest = min(seen_mtimes)
        # The oldest surviving file is survivorship, not coverage: ONE artifact
        # from 2023 does not mean a usable record of 2023. So report the
        # distribution by year as well, and let the report say how much evidence
        # actually falls inside the period being asked about.
        by_year = {}
        for m in seen_mtimes:
            y = datetime.datetime.fromtimestamp(m).year
            by_year[y] = by_year.get(y, 0) + 1
        r.reach["cache"] = {
            "earliest": datetime.datetime.fromtimestamp(earliest).isoformat(
                timespec="seconds"),
            "days": max(0, (datetime.datetime.now()
                            - datetime.datetime.fromtimestamp(earliest)).days),
            "basis": "oldest of {:,} cache/LevelDB/Service-Worker files "
                     "searched".format(len(seen_mtimes)),
            "note": "The HTTP cache is recycled within weeks, but Local Storage, "
                    "LevelDB and Service Worker files can persist for years - "
                    "which is why this date is often much older than the cache "
                    "alone. It is the oldest SURVIVOR, not proof of a continuous "
                    "record since then.",
            "by_year": by_year,
        }
    if cookie_times:
        oldest = min(cookie_times)
        r.reach["cookies"] = {
            "earliest": oldest.isoformat(timespec="seconds"),
            "days": max(0, (datetime.datetime.now() - oldest).days),
            "basis": "oldest surviving cookie across {} cookie store(s)".format(
                cookie_stores[0]),
            "note": "Cookies are the strongest evidence the browser keeps: one "
                    "exists only if the browser actually got a response from that "
                    "site. But this is the oldest SURVIVOR, not a full record back "
                    "to that date. Cookies expire (Chrome caps them at 400 days) "
                    "or get cleared, so most cookies from that time are gone.",
        }
    if history_rows[0]:
        r.reach["history"] = {
            "earliest": None,
            "days": None,
            "basis": "browser history was searched, but records only top-level "
                     "navigations",
            "note": "History reaches back further than the cache but CANNOT record "
                    "an ad: ads load as a sub-resource inside a page, and only the "
                    "page itself is recorded. The long record cannot see ads; the "
                    "record that sees ads is not long.",
        }
    return r
