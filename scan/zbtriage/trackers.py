"""Bluetooth tracker check (--trackers [MINUTES]): is a location tracker travelling with you?

A separate, opt-in check for people worried about being followed (an AirTag in a bag or car).
It listens to Bluetooth advertisements for a few minutes - the same signals phones use for
their own "unknown tracker" warnings - and reports trackers it hears, especially ones that say
they are AWAY FROM THEIR OWNER, which is what a planted tracker does.

Recognised from published formats:
  Apple Find My (AirTag and other Find My items): manufacturer data, company 0x004C, type 0x12
    ("offline finding"). The long form (length 0x19) is sent when the item is separated from its
    owner; the short form when its owner's phone is near.
  Samsung SmartTag: 16-bit service data 0xFD5A.
  Tile: 16-bit service 0xFEED or 0xFEEC.
  Google Find Hub (Find My Device network): Eddystone service data 0xFEAA with frame type 0x40, or
    0x41 in "unwanted tracking protection" mode (separated from its owner).

Only receives; nothing is sent to the trackers and nothing leaves this computer. Needs the
`bleak` library: the programs include it; the Python version needs pip install -r requirements-bluetooth.txt
"""
from __future__ import annotations

import os
import sys
import time

from .i18n import T

APPLE = 0x004C
TK_TILE = {"0000feed-0000-1000-8000-00805f9b34fb", "0000feec-0000-1000-8000-00805f9b34fb"}
TK_SMARTTAG = "0000fd5a-0000-1000-8000-00805f9b34fb"
TK_EDDYSTONE = "0000feaa-0000-1000-8000-00805f9b34fb"


def tk_classify(manufacturer_data, service_data, service_uuids):
    """(kind, separated) for one advertisement, or None if it is not a known tracker.
    manufacturer_data: {company_id: bytes}; service_data: {uuid: bytes}; service_uuids: [uuid]."""
    apple = manufacturer_data.get(APPLE)
    if apple and len(apple) >= 2 and apple[0] == 0x12:
        return "Apple Find My item (AirTag or similar)", apple[1] == 0x19
    uuids = {u.lower() for u in service_uuids} | {u.lower() for u in service_data}
    if TK_SMARTTAG in uuids:
        return "Samsung SmartTag", None
    if uuids & TK_TILE:
        return "Tile tracker", None
    eddystone = service_data.get(TK_EDDYSTONE) or service_data.get(TK_EDDYSTONE.upper())
    if eddystone and eddystone[0] in (0x40, 0x41):
        return "Google Find Hub tracker", eddystone[0] == 0x41
    return None


def tk_summarise(sightings, minutes):
    """sightings: [(address, kind, separated, rssi, t)] -> per-tracker summary with advice level."""
    trackers = {}
    for address, kind, separated, rssi, t in sightings:
        # separated is three-state: True (says away from owner), False (says owner nearby), None (this kind of
        # tracker does not say - Tile and SmartTag). Unknown must never be shown as "owner nearby".
        item = trackers.setdefault(address, {"address": address, "kind": kind, "separated": None,
                                             "first": t, "last": t, "count": 0, "strongest": -999})
        item["count"] += 1
        item["last"] = max(item["last"], t)
        item["first"] = min(item["first"], t)
        item["strongest"] = max(item["strongest"], rssi if isinstance(rssi, int) else -999)
        if separated is True or item["separated"] is True:
            item["separated"] = True
        elif separated is False:
            item["separated"] = False
    out = []
    for item in trackers.values():
        seen_for = item["last"] - item["first"]
        item["seen_minutes"] = round(seen_for / 60, 1)
        item["persistent"] = seen_for >= min(60 * minutes * 0.6, 600)
        item["near"] = item["strongest"] >= -70
        out.append(item)
    out.sort(key=lambda i: (i["separated"] is not True, i["separated"] is False, not i["persistent"],
                            -i["strongest"]))
    return out


def tk_headline(trackers):
    """(one plain sentence, level) for the top of the result: the answer first, the details below it.
    Levels are the window's: dangerous (red), worth-a-look (amber), clean (green)."""
    if any(t.get("checks_seen", 0) >= 3 and t["separated"] is not False for t in trackers):
        return T("A tracker may be travelling with you - read IMPORTANT below"), "dangerous"
    if any(t["separated"] is not False and t["persistent"] for t in trackers):
        return T("A tracker stayed near you - worth a look"), "worth-a-look"
    if trackers:
        return T("No tracker seems to be following you"), "clean"
    return T("No trackers were heard nearby"), "clean"


def tk_plain_error(exc, platform=None):
    """What to do, in plain words, when Bluetooth cannot be used (off, missing, or not allowed)."""
    platform = platform or sys.platform
    text = str(exc).lower()
    if platform == "darwin":
        where = T("Turn Bluetooth on in System Settings > Bluetooth. If macOS asked whether Zero Breach may use "
                  "Bluetooth, allow it (System Settings > Privacy & Security > Bluetooth).")
    elif platform.startswith("win"):
        where = T("Turn Bluetooth on in Settings > Bluetooth & devices.")
    else:
        where = T("Turn Bluetooth on in your system settings, and make sure the Bluetooth service is running "
                  "(for example: sudo systemctl start bluetooth).")
    # Matched on the messages the Bluetooth library really gives on each system (seen on build machines).
    if any(w in text for w in ("unauthorized", "not authorized", "permission", "denied")):
        first = T("This computer did not allow the program to use Bluetooth.")
    elif "org.bluez" in text or "dbus" in text:
        first = T("The Bluetooth service is not running on this computer.")
    elif any(w in text for w in ("no bluetooth adapter", "adapter", "not found", "no such", "unavailable",
                                 "unsupported")):
        first = T("No Bluetooth was found on this computer, or it is switched off.")
    elif any(w in text for w in ("turned off", "switched off", "powered off", "disabled", "turned on?",
                                 "failed to start scanner")):
        first = T("Bluetooth is switched off, or this computer has no Bluetooth.")
    else:
        first = T("Bluetooth could not be used.")
    return "{} {} {}".format(first, where, T("Then try again. (Details: {details})",
                                             details=str(exc)[:160] or type(exc).__name__))


from .safetext import safe_render  # noqa: E402


@safe_render
def tk_render(trackers, minutes):
    lines = ["=" * 72, "  " + T("BLUETOOTH TRACKER CHECK") + "  -  " + T("listened for {n} minute(s)", n=minutes),
             "  " + T("Only received signals; nothing was sent. This is advice, not proof of being followed."),
             "=" * 72, "", "  " + T("RESULT:") + " " + tk_headline(trackers)[0], ""]
    # A tracker whose owner is nearby is not a concern; one that says it is away from its owner, or one that
    # cannot say (Tile, SmartTag), is - if it stayed near you.
    following = [t for t in trackers if t.get("checks_seen", 0) >= 3 and t["separated"] is not False]
    if following:
        lines.append("  " + T("IMPORTANT"))
        for t in following:
            lines += ["    - " + T("The same {kind} was heard in {n} separate checks over the last day.",
                                   kind=T(t["kind"]), n=t["checks_seen"]),
                      "      " + T("If you made those checks in different places, it is very likely travelling "
                                   "with you."),
                      "      " + T("Search your bags, coat, car and things you carry. If you feel unsafe, contact a "
                                   "support service before removing it: https://stopstalkerware.org/ (a found "
                                   "tracker's serial number can identify its owner to the police).")]
        lines.append("")
    concern = [t for t in trackers if t["separated"] is not False and t["persistent"] and t not in following]
    if concern:
        lines.append("  " + T("WORTH A LOOK"))
        for t in concern:
            state = (T("that is AWAY FROM ITS OWNER") if t["separated"] else
                     T("(this kind cannot say whether its owner is nearby)"))
            lines += ["    - " + T("A {kind} {state} stayed near you for {minutes} minutes (signal {rssi} dBm{close}).",
                                   kind=T(t["kind"]), state=state, minutes=t["seen_minutes"], rssi=t["strongest"],
                                   close=T(", very close") if t["near"] else ""),
                      "      " + T("It may belong to someone nearby (a neighbour, a passenger). If you are moving and "
                                   "it stays with you, it may be travelling with you."),
                      "      " + T("Check your bags, coat and car. On a phone: iPhone warns automatically; on Android "
                                   "use Settings > Safety & emergency > Unknown tracker alerts (or Samsung's "
                                   "SmartThings Find)."),
                      "      " + T("If you feel unsafe, contact a support service before removing it: "
                                   "https://stopstalkerware.org/")]
        lines.append("")
    lines.append("  " + T("TRACKERS HEARD ({n})", n=len(trackers)))
    for t in trackers:
        lines.append("    {:<40} {}  {}".format(
            T(t["kind"])[:40],
            T("{count:>5} sightings over {minutes:>5} min  strongest {rssi:>4} dBm", count=t["count"],
              minutes=t["seen_minutes"], rssi=t["strongest"]),
            T("AWAY FROM OWNER") if t["separated"] else (T("owner nearby") if t["separated"] is False
                                                         else T("owner unknown"))))
    if not trackers:
        lines.append("    " + T("None. A tracker that was out of range, switched off or silent while listening is "
                                "not heard."))
    lines += ["", "  " + T("Not every tracker nearby is listed: one whose owner's phone is close by often stays "
                           "quiet. That is not a worry - a tracker following you is away from its owner, and calls "
                           "out every few seconds."),
              "", "  " + T("For a better answer, run it again after moving to another place: a tracker that is still "
                           "heard in both places is the one travelling with you.")]
    from .safetext import st_wrap_lines
    return "\n".join(st_wrap_lines(lines))


async def _tk_listen(minutes, emit):
    from bleak import BleakScanner
    sightings = []

    def seen(device, adv):
        found = tk_classify(dict(adv.manufacturer_data or {}), dict(adv.service_data or {}),
                            list(adv.service_uuids or []))
        if found:
            sightings.append((device.address, found[0], found[1], adv.rssi, time.time()))
    import asyncio
    async with BleakScanner(detection_callback=seen):
        end = time.time() + 60 * minutes
        while time.time() < end:
            await asyncio.sleep(5)
            emit("[trackers] listening... {} tracker signals so far".format(len(sightings)))
    return sightings


TK_HISTORY_FILE = "tracker-checks.json"
TK_HISTORY_HOURS = 24
TK_HISTORY_GAP = 10 * 60          # two checks less than 10 minutes apart count as one place


def tk_history_update(trackers, history, now):
    """Add this check to the history (last 24 h, this computer only) and mark trackers heard in 3 or more
    separate checks. Trackers away from their owner keep the same address for about a day, so the same tracker
    turning up in checks made at different times and places is the clearest sign it travels with you.
    Returns the new history; sets t["checks_seen"] on each tracker."""
    keep = [h for h in history if isinstance(h, dict) and now - float(h.get("t", 0)) < TK_HISTORY_HOURS * 3600]
    for t in trackers:
        earlier = sorted(float(h["t"]) for h in keep if h.get("address") == t["address"])
        separate, last = 0, None
        for when in earlier + [now]:
            if last is None or when - last >= TK_HISTORY_GAP:
                separate += 1
                last = when
        t["checks_seen"] = separate
    keep += [{"address": t["address"], "kind": t["kind"], "t": now} for t in trackers]
    return keep[-2000:]


def _tk_history_io(trackers):
    import json
    from .feeds import default_cache_dir
    path = os.path.join(default_cache_dir(), TK_HISTORY_FILE)
    try:
        with open(path, encoding="utf-8") as fh:
            history = json.load(fh)
    except (OSError, ValueError):
        history = []
    history = tk_history_update(trackers, history if isinstance(history, list) else [], time.time())
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(history, fh)
    except OSError:
        pass


# --- the Bluetooth library for the Python version -------------------------------------------------------------------
# The programs include bleak. The Python version can install it - only when the person says yes: the exact pinned
# version (the one in requirements-bluetooth.txt), ready-made packages only (--only-binary: nothing is built or run
# while installing), from the official Python package index.
TK_BLEAK = "bleak==1.1.1"


def tk_install_command():
    """The pip command that installs the pinned bleak for this Python (a virtual environment, or the user's own
    packages folder otherwise)."""
    cmd = [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--only-binary=:all:", TK_BLEAK]
    if sys.prefix == getattr(sys, "base_prefix", sys.prefix) and not os.environ.get("VIRTUAL_ENV"):
        cmd.insert(4, "--user")
    return cmd


def tk_install_bleak(out=print, run=None):
    """Install the pinned bleak. True when it can then be imported. Tells the person plainly what went wrong
    otherwise (no pip, no internet, a system Python that refuses outside packages)."""
    import importlib
    import site
    import subprocess
    if getattr(sys, "frozen", False):
        return False                                      # the programs carry bleak; nothing to install
    cmd = tk_install_command()
    out(T("Installing {package} (a few seconds to a minute)...", package=TK_BLEAK))
    try:
        run = run or (lambda c: subprocess.run(c, capture_output=True, text=True, timeout=600))
        proc = run(cmd)
    except (OSError, subprocess.SubprocessError) as exc:
        out(T("It could not be installed ({why}). Use the downloadable program instead - it includes Bluetooth.",
              why=type(exc).__name__))
        return False
    text = (getattr(proc, "stdout", "") or "") + (getattr(proc, "stderr", "") or "")
    if proc.returncode != 0:
        if "externally-managed-environment" in text:
            out(T("This system's Python does not allow installing extra packages into it. Use the downloadable "
                  "Linux program instead - it includes Bluetooth - or a virtual environment."))
        elif "No module named pip" in text:
            out(T("This Python has no pip, so the library cannot be installed. Use the downloadable program instead "
                  "- it includes Bluetooth."))
        elif "Could not find a version" in text or "No matching distribution" in text:
            out(T("No ready-made Bluetooth package exists for this Python ({version}). Use the downloadable program "
                  "instead - it includes Bluetooth.", version="{}.{}".format(*sys.version_info[:2])))
        else:
            out(T("It could not be installed (pip exit {code}). Check the internet connection, or use the "
                  "downloadable program instead - it includes Bluetooth.", code=proc.returncode))
        return False
    try:
        user_site = site.getusersitepackages()
        if "--user" in cmd and user_site not in sys.path:
            site.addsitedir(user_site)                    # a first --user install: make it visible now, no restart
    except (AttributeError, OSError):
        pass
    importlib.invalidate_caches()
    try:
        importlib.import_module("bleak")
    except ImportError:
        out(T("It was installed, but this Python cannot load it yet. Start Zero Breach again to use the tracker "
              "check."))
        return False
    out(T("Installed. Starting the tracker check."))
    return True


def trackers_command(args, out=print):
    minutes = max(1, min(30, int(getattr(args, "trackers", 3) or 3)))
    try:
        import bleak  # noqa: F401
    except ImportError:
        out(T("The tracker check needs the Bluetooth library 'bleak', which this Python ({version}) does not have "
              "yet. (The downloadable programs include it.)", version="{}.{}".format(*sys.version_info[:2])))
        out(T("It can be installed now: {package} from the official Python package index, about 1 MB, nothing else "
              "is changed.", package=TK_BLEAK))
        interactive = False
        try:
            interactive = sys.stdin.isatty()
        except (AttributeError, ValueError):
            pass
        if not interactive:
            out(T("Install it with:") + " " + " ".join(tk_install_command()[1:]).replace(" -m ", "python -m ", 1))
            return 1
        try:
            answer = input("  " + T("Install it now? (Y/n)") + " ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer not in ("", "y", "yes") or not tk_install_bleak(out):
            if answer not in ("", "y", "yes"):
                out(T("Not installed. Nothing was changed."))
            return 1
    import asyncio
    out(T("Listening for Bluetooth trackers for {n} minute(s). Keep this computer with you; moving between two "
          "places makes the result clearer.", n=minutes))
    try:
        sightings = asyncio.run(_tk_listen(minutes, lambda m: print(m, file=sys.stderr)))
    except Exception as exc:  # noqa: BLE001 - Bluetooth off, no adapter, permission refused
        out(T("Bluetooth could not be used.") + " " + tk_plain_error(exc))
        return 1
    summary = tk_summarise(sightings, minutes)
    _tk_history_io(summary)
    out(tk_render(summary, minutes))
    return 0
