"""Help a person make an iPhone backup, then pick it up for checking.

Windows and Mac: Apple's own app makes the backup (Apple Devices or iTunes on Windows, Finder on a
Mac). This module opens that app, explains the three clicks, then watches the usual backup folders
and reports when a NEW backup has finished, so the window can offer to check it straight away.
Linux has no Apple app: see --make-iphone-backup in iphonehelper.py.

Reads backup folders' Status.plist only. Never changes or deletes a backup.
"""
from __future__ import annotations

import os
import plistlib
import subprocess
import sys
import time

IB_STABLE_SECONDS = 10          # a backup counts as finished only when Status.plist has stopped changing
IB_STATUS_LIMIT = 1024 * 1024

IB_STEPS = {
    "win32": (
        "Connect the iPhone to this computer with a cable, unlock it and tap \"Trust\" if it asks.",
        "In Apple Devices (or iTunes), select the iPhone. Under Backups choose \"Back up all of the data on "
        "your iPhone to this computer\".",
        "Tick \"Encrypt local backup\" and choose a password you will remember. An encrypted backup holds far "
        "more of what the check needs (Safari history, health and Wi-Fi records).",
        "Press \"Back Up Now\" and keep the iPhone connected until it finishes. This window notices when it is done.",
    ),
    "darwin": (
        "Connect the iPhone to this Mac with a cable, unlock it and tap \"Trust\" if it asks.",
        "In Finder, select the iPhone in the sidebar, then the General tab. Choose \"Back up all of the data on "
        "your iPhone to this Mac\".",
        "Tick \"Encrypt local backup\" and choose a password you will remember. An encrypted backup holds far "
        "more of what the check needs (Safari history, health and Wi-Fi records).",
        "Press \"Back Up Now\" and keep the iPhone connected until it finishes. This window notices when it is done.",
    ),
}

IB_WARNINGS = (
    "If you forget an encrypted backup's password, that backup cannot be opened by anyone, including this program.",
    "If encryption is already on and nobody remembers the password, the only way to reset it is on the iPhone: "
    "Settings > General > Transfer or Reset iPhone > Reset > Reset All Settings. That keeps your photos, "
    "messages and apps, but resets settings such as Wi-Fi passwords and wallpaper.",
    "The backup is a full private copy of the phone. Delete it afterwards if you do not want to keep it.",
)


def ib_backup_roots():
    """The usual local backup folders on this computer (they may not exist)."""
    home = os.path.expanduser("~")
    roots = [os.path.join(home, "Library", "Application Support", "MobileSync", "Backup"),
             os.path.join(home, "Apple", "MobileSync", "Backup")]
    if os.environ.get("APPDATA"):
        roots.append(os.path.join(os.environ["APPDATA"], "Apple Computer", "MobileSync", "Backup"))
    return roots


def ib_status(path):
    """(SnapshotState or "", Status.plist mtime or 0) for one backup folder."""
    status = os.path.join(path, "Status.plist")
    try:
        mtime = os.path.getmtime(status)
        with open(status, "rb") as fh:
            data = plistlib.loads(fh.read(IB_STATUS_LIMIT))
    except Exception:  # noqa: BLE001 - a half-written plist (ExpatError and friends) is simply "not finished yet"
        return "", 0
    state = data.get("SnapshotState", "") if isinstance(data, dict) else ""
    return str(state), mtime


def ib_snapshot(roots=None):
    """{backup folder: Status.plist mtime} for every backup now present."""
    seen = {}
    for root in roots or ib_backup_roots():
        try:
            names = os.listdir(root)
        except OSError:
            continue
        for name in names:
            path = os.path.join(root, name)
            if os.path.isdir(path):
                seen[path] = ib_status(path)[1]
    return seen


def ib_new_finished(baseline, roots=None, now=None):
    """Backups that finished after `baseline` (an ib_snapshot) was taken, newest first.

    Finished = Status.plist says "finished", a manifest is present, the status changed since the
    baseline (a new backup, or a fresh backup into the same folder), and it has been still for
    IB_STABLE_SECONDS - so a backup is never offered while Apple's app is still writing it."""
    now = time.time() if now is None else now
    found = []
    for root in roots or ib_backup_roots():
        try:
            names = os.listdir(root)
        except OSError:
            continue
        for name in names:
            path = os.path.join(root, name)
            state, mtime = ib_status(path)
            if state != "finished" or not mtime or mtime <= baseline.get(path, 0):
                continue
            if not (os.path.isfile(os.path.join(path, "Manifest.db"))
                    or os.path.isfile(os.path.join(path, "Manifest.plist"))):
                continue
            if now - mtime < IB_STABLE_SECONDS:
                continue
            found.append((mtime, path))
    return [path for _mtime, path in sorted(found, reverse=True)]


def ib_device_name(path):
    """'Sara's iPhone (iPhone15,2, iOS 18.6)' from Info.plist, or ''."""
    try:
        with open(os.path.join(path, "Info.plist"), "rb") as fh:
            info = plistlib.loads(fh.read(4 * 1024 * 1024))
    except Exception:  # noqa: BLE001 - a damaged Info.plist just means no name
        return ""
    if not isinstance(info, dict):
        return ""
    name = str(info.get("Device Name", ""))[:80]
    detail = ", ".join(str(info.get(k, ""))[:40] for k in ("Product Type", "Product Version") if info.get(k))
    return "{} ({})".format(name, detail) if name and detail else name or detail


def _ib_run(argv, timeout=30):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(argv, capture_output=True, text=True, timeout=timeout, shell=False, creationflags=flags)


def ib_windows_app():
    """(name, AppID) of Apple Devices or iTunes from Windows' own list of installed apps, or None."""
    try:
        done = _ib_run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                        "Get-StartApps | Where-Object { $_.Name -in @('Apple Devices','iTunes') } | "
                        "ForEach-Object { $_.Name + '|' + $_.AppID }"])
    except (OSError, subprocess.SubprocessError):
        return None
    apps = dict(line.split("|", 1) for line in done.stdout.splitlines() if "|" in line)
    for name in ("Apple Devices", "iTunes"):
        if apps.get(name):
            return name, apps[name].strip()
    return None


def ib_open_backup_app():
    """Open Apple's backup app. Returns a sentence saying what was opened (or what to do)."""
    try:
        if sys.platform == "win32":
            app = ib_windows_app()
            if app:
                _ib_run(["explorer.exe", "shell:AppsFolder\\" + app[1]])
                return "Opened {}.".format(app[0])
            os.startfile("ms-windows-store://search/?query=Apple%20Devices")   # type: ignore[attr-defined]
            return ("Apple Devices is not installed. The Microsoft Store was opened at Apple Devices: install it "
                    "(it is free, from Apple), then press \"Open Apple Devices\" again.")
        if sys.platform == "darwin":
            _ib_run(["open", "-a", "Finder"])
            return "Opened Finder."
    except (OSError, subprocess.SubprocessError) as exc:
        return "Could not open Apple's app: {}".format(exc)
    return ("Linux has no Apple app for backups. Use: zero-breach-toolkit --make-iphone-backup FOLDER "
            "(it downloads a verified helper after asking).")
