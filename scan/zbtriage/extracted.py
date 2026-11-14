"""Was my phone plugged into a forensics tool? (--was-extracted PATH)

A different question from "is there spyware on my phone". When a phone is taken at a border, a police station or
a checkpoint, what usually happens is not spyware: it is plugged into a machine that copies everything off it -
Cellebrite, GrayKey, Magnet or one of the Chinese tools. This answers that one question from a phone collection
(AndroidQF) or an iPhone backup, and says plainly what each sign does and does not prove.

🔴 READ THIS FIRST, AND IT IS PRINTED IN EVERY REPORT: a successful extraction can leave NO trace at all. Finding
nothing here does NOT mean a phone was not copied. If a phone was out of your hands and unlocked, treat what is
on it as known to whoever had it, whatever this says.

What it looks at:
  * Android: which computers are allowed to control the phone over USB (each authorised key is one computer),
    whether USB debugging and developer options are on, whether the bootloader is unlocked or verified boot is
    off, boots into recovery or fastboot, side-loaded apps holding the accessibility permission that a forensics
    helper uses to tap through consent prompts, and the fake USB devices Cellebrite's hardware imitates
    (published by Amnesty International, matched only together with the version they all reported).
  * iPhone: what the backup says about which computer made it and when, whether the backup was left unencrypted
    (an unencrypted backup is what a forensics tool prefers), and the Cellebrite traces published by the
    Citizen Lab.

It reads a collection or backup you already have. It does not touch a phone, and contacts nothing.
"""
from __future__ import annotations

import json
import os
import plistlib
from typing import Dict, List, Optional, Tuple

from .i18n import T, TX, i18n_lang

EX_FOUND, EX_LOOK, EX_NOTHING = "known-threat", "worth-a-look", "nothing-known"
EX_MAX_READ = 64 * 1024 * 1024

EX_ALWAYS = (
    "An extraction can leave no trace at all, so finding nothing here does not mean the phone was not copied. "
    "If it was out of your hands and unlocked, treat everything on it as known to whoever had it.")


class ExError(ValueError):
    pass


def ex_kind(path: str) -> str:
    """'android' for an AndroidQF collection, 'iphone' for a backup, or raises."""
    if not os.path.isdir(path):
        raise ExError("that is not a folder. Give the folder of an AndroidQF collection, or an iPhone backup "
                      "folder")
    names = {n.lower() for n in os.listdir(path)}
    if "getprop.txt" in names or "packages.json" in names or "dumpsys.txt" in names:
        return "android"
    if "manifest.db" in names or "manifest.plist" in names or "status.plist" in names:
        return "iphone"
    if "acquisition.json" in names:
        return "android"
    raise ExError("that folder is neither an AndroidQF collection (it would hold getprop.txt or packages.json) "
                  "nor an iPhone backup (Manifest.db)")


def _ex_read(path: str, limit: int = EX_MAX_READ) -> bytes:
    try:
        with open(path, "rb") as fh:
            return fh.read(limit)
    except OSError:
        return b""


def _ex_find(folder: str, *names) -> Optional[str]:
    try:
        listing = {n.lower(): n for n in os.listdir(folder)}
    except OSError:
        return None
    for name in names:
        if name.lower() in listing:
            return os.path.join(folder, listing[name.lower()])
    return None


def _ex_getprop(folder) -> Dict[str, str]:
    path = _ex_find(folder, "getprop.txt")
    out = {}
    if not path:
        return out
    for line in _ex_read(path, 4 * 1024 * 1024).decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line.startswith("[") and "]: [" in line and line.endswith("]"):
            key, value = line[1:-1].split("]: [", 1)
            out[key] = value
    return out


def _ex_settings(folder) -> Dict[str, str]:
    out = {}
    for name in ("settings_global.txt", "settings_secure.txt", "settings_system.txt"):
        path = _ex_find(folder, name)
        if not path:
            continue
        for line in _ex_read(path, 4 * 1024 * 1024).decode("utf-8", "replace").splitlines():
            if "=" in line:
                key, _sep, value = line.partition("=")
                out[key.strip()] = value.strip()
    return out


# --- Android ---------------------------------------------------------------------------------------------------

def ex_adb_keys(text: str) -> List[str]:
    """The comment on each authorised ADB key: every one is a computer allowed to control the phone."""
    out = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2 and len(parts[0]) > 40:
            out.append(parts[1].strip()[:120])
        elif len(parts[0]) > 40:
            out.append("(a key with no name)")
    return out


def _ex_android(folder: str, iocs=None) -> Tuple[List[dict], List[str], Dict[str, object]]:
    from .devicetraces import DT_CELLEBRITE_USB, DT_SOURCES, dt_android_usb
    found: List[dict] = []
    gaps: List[str] = []
    facts: Dict[str, object] = {}
    props = _ex_getprop(folder)
    settings = _ex_settings(folder)
    if not props and not settings:
        gaps.append("this collection has no getprop.txt or settings files, so the phone's own settings could "
                    "not be read")

    def add(level, what, means, evidence=""):
        found.append({"level": level, "what": what, "means": means, "evidence": evidence[:400]})

    # 1. which computers may control the phone
    keys_path = None
    for candidate in ("adb_keys", "adb_keys.txt"):
        keys_path = keys_path or _ex_find(folder, candidate)
    if keys_path:
        names = ex_adb_keys(_ex_read(keys_path, 1024 * 1024).decode("utf-8", "replace"))
        facts["authorised_computers"] = names
        if names:
            add(EX_LOOK, "{} computer(s) are allowed to control this phone over USB".format(len(names)),
                "Each of these was approved once by tapping \"Allow\" on the phone, and the approval does not "
                "expire. A computer you do not recognise here could copy the phone again whenever it is "
                "plugged in. Remove them with Developer options > Revoke USB debugging authorisations.",
                "; ".join(names[:8]))
    else:
        gaps.append("the list of computers allowed to control the phone (adb_keys) is not in this collection; "
                    "it needs root to read")

    # 2. the doors a forensics tool needs
    debugging = settings.get("adb_enabled") or settings.get("global:adb_enabled")
    if debugging == "1":
        add(EX_LOOK, "USB debugging is switched on",
            "This is the door most phone-extraction tools use. It is also needed by developers. If you did not "
            "turn it on, someone with the phone did: Settings > Developer options > USB debugging.")
    facts["usb_debugging"] = debugging
    if settings.get("development_settings_enabled") == "1":
        add(EX_LOOK, "Developer options are switched on",
            "On its own this is harmless and many people turn it on. It is listed because USB debugging, "
            "and so most extraction, needs it.")
    boot_state = props.get("ro.boot.verifiedbootstate") or props.get("ro.boot.flash.locked")
    facts["verified_boot"] = boot_state
    if boot_state in ("orange", "yellow", "0"):
        add(EX_FOUND if boot_state == "orange" else EX_LOOK,
            "the phone's bootloader is unlocked" if boot_state == "orange" else
            "the phone is running software signed by someone other than its maker",
            "An unlocked bootloader lets anyone with the phone replace its system software, which is how a "
            "locked phone is opened and copied. Phones do not come this way, and unlocking wipes the phone, so "
            "if you did not do it, someone who had the phone did.",
            "ro.boot.verifiedbootstate = {}".format(boot_state))
    if props.get("ro.debuggable") == "1" or props.get("ro.secure") == "0":
        add(EX_FOUND, "this phone is running a debug build of Android",
            "A build made for developers, where any program can be given full control. A shop-bought phone does "
            "not run one.", "ro.debuggable={} ro.secure={}".format(props.get("ro.debuggable"),
                                                                   props.get("ro.secure")))

    # 3. Cellebrite's imitated USB hardware, from the phone's own logs
    usb_hits = []
    for name in ("logcat.txt", "dmesg.txt", "bugreport.txt", "logs"):
        path = _ex_find(folder, name)
        if not path:
            continue
        if os.path.isdir(path):
            for inner in sorted(os.listdir(path))[:40]:
                usb_hits += list(dt_android_usb(_ex_read(os.path.join(path, inner)).decode("utf-8", "replace")))
        else:
            usb_hits += list(dt_android_usb(_ex_read(path).decode("utf-8", "replace")))
    if usb_hits:
        citation = DT_SOURCES.get("amnesty-cellebrite-serbia-2025-02", ("", ""))
        seen = set()
        for vid, pid, line_number in usb_hits[:40]:
            if (vid, pid) in seen:
                continue
            seen.add((vid, pid))
            add(EX_FOUND, "the phone's log shows {}".format(
                DT_CELLEBRITE_USB.get((vid, pid), "a USB device Cellebrite's hardware imitates")),
                "Amnesty International published these: Cellebrite's unlocking hardware pretends to be ordinary "
                "USB devices to reach weak points in Android's drivers, and every one it imitated reported the "
                "same version number, which is what makes this a match rather than a coincidence. Seeing it in "
                "the log means such hardware was plugged into this phone. Source: {}".format(citation[0]),
                "USB {}:{} at log line {}".format(vid, pid, line_number))
        facts["cellebrite_usb_devices"] = sorted("{}:{}".format(v, p) for v, p in seen)
    else:
        facts["usb_log_checked"] = bool(_ex_find(folder, "logcat.txt", "dmesg.txt", "bugreport.txt", "logs"))
        if not facts["usb_log_checked"]:
            gaps.append("no log file in this collection, so the phone's record of what was plugged into it "
                        "could not be read")

    # 4. a helper app side-loaded with the permission used to tap through consent prompts
    packages = _ex_find(folder, "packages.json")
    accessibility = (settings.get("enabled_accessibility_services") or "").split(":")
    facts["accessibility_services"] = [a for a in accessibility if a.strip()]
    if packages:
        try:
            listing = json.loads(_ex_read(packages).decode("utf-8", "replace") or "[]")
        except ValueError:
            listing = []
        sideloaded = {}
        for item in listing if isinstance(listing, list) else []:
            if not isinstance(item, dict):
                continue
            name = item.get("name") or item.get("package_name") or ""
            installer = item.get("installer") or ""
            if name and installer in ("", "null", None) and not item.get("system"):
                sideloaded[name] = item
        facts["sideloaded"] = sorted(sideloaded)[:60]
        for service in facts["accessibility_services"]:
            app = service.split("/")[0]
            if app in sideloaded:
                add(EX_FOUND, "a side-loaded app can tap the screen for itself ({})".format(app),
                    "This app was not installed from a shop and holds the accessibility permission, which lets "
                    "it press buttons and accept prompts on its own. Forensics helpers that are copied onto a "
                    "phone use exactly this to agree to their own permission requests. Screen readers and "
                    "automation apps use it legitimately - if you did not install this one, it does not belong.",
                    service)
    else:
        gaps.append("packages.json is not in this collection, so installed apps could not be read")
    if iocs is not None:
        for name in facts.get("sideloaded", []):
            ind = iocs.lookup(name.lower())
            if ind is not None:
                add(EX_FOUND, "a side-loaded app is on a published list ({})".format(name),
                    "This app is named in {} as {}.".format(ind.source or "an indicator list",
                                                            ind.family or "spyware or a forensics helper"), name)
    return found, gaps, facts


# --- iPhone ----------------------------------------------------------------------------------------------------

def _ex_plist(path) -> Dict:
    raw = _ex_read(path, 32 * 1024 * 1024)
    if not raw:
        return {}
    try:
        got = plistlib.loads(raw)
        return got if isinstance(got, dict) else {}
    except Exception:  # noqa: BLE001 - an unreadable property list is simply skipped
        return {}


def _ex_iphone(folder: str, iocs=None) -> Tuple[List[dict], List[str], Dict[str, object]]:
    from .devicetraces import DT_IOS_PROCESS, DT_IOS_STRINGS, DT_SOURCES
    found: List[dict] = []
    gaps: List[str] = []
    facts: Dict[str, object] = {}

    def add(level, what, means, evidence=""):
        found.append({"level": level, "what": what, "means": means, "evidence": evidence[:400]})
    info_path = _ex_find(folder, "Info.plist")
    manifest_path = _ex_find(folder, "Manifest.plist")
    info = _ex_plist(info_path) if info_path else {}
    manifest = _ex_plist(manifest_path) if manifest_path else {}
    if not info and not manifest:
        gaps.append("this backup has no readable Info.plist or Manifest.plist")
    for key, label in (("Device Name", "phone name"), ("Product Type", "model"),
                       ("Product Version", "iOS version"), ("Last Backup Date", "last backup"),
                       ("Target Identifier", "phone identifier"), ("Unique Identifier", "phone identifier")):
        if info.get(key):
            facts[label] = str(info[key])[:120]
    encrypted = bool(manifest.get("IsEncrypted"))
    facts["encrypted_backup"] = encrypted
    if not encrypted and manifest:
        add(EX_LOOK, "this backup is not encrypted",
            "An unencrypted backup is what a forensics tool wants: it holds everything in the clear. This says "
            "nothing about whether the phone was copied - it is about what a copy would get. Turn on \"Encrypt "
            "local backup\" in Finder or iTunes, and keep the password safe.")
    installed = info.get("Installed Applications") or []
    facts["apps"] = len(installed) if isinstance(installed, list) else 0
    if iocs is not None and isinstance(installed, list):
        for app in installed[:4000]:
            ind = iocs.lookup(str(app).lower())
            if ind is not None:
                add(EX_FOUND, "an app in this backup is on a published list ({})".format(app),
                    "Named in {} as {}.".format(ind.source or "an indicator list", ind.family or "spyware"),
                    str(app))
    # the Citizen Lab's published Cellebrite traces, searched in the backup's own text files
    citation = DT_SOURCES.get("citizenlab-cellebrite-jordan-2026-01", ("", ""))
    needles = {DT_IOS_PROCESS: "the process name Cellebrite's tooling runs under"}
    for value, (_kind, meaning) in DT_IOS_STRINGS.items():
        needles[value] = meaning
    checked = 0
    for name in ("Info.plist", "Manifest.plist", "Status.plist"):
        path = _ex_find(folder, name)
        if not path:
            continue
        checked += 1
        text = _ex_read(path).decode("utf-8", "replace")
        for needle, meaning in needles.items():
            if len(needle) >= 6 and needle in text:
                add(EX_FOUND, "this backup contains {}".format(meaning),
                    "The Citizen Lab published this value as a trace left by Cellebrite's tooling. Source: "
                    "{}".format(citation[0]), "{} (in {})".format(needle, name))
    if not checked:
        gaps.append("none of the backup's description files could be read")
    gaps.append("an iPhone keeps its record of which computers it trusts on the phone itself, not in a backup, "
                "so this check cannot see them. On the phone: Settings > General > Transfer or Reset iPhone > "
                "Reset > Reset Location & Privacy removes every trust, and Settings > Face ID & Passcode > "
                "Accessories should be OFF so a locked phone refuses USB devices")
    return found, gaps, facts


# --- putting it together ---------------------------------------------------------------------------------------

def ex_check(path: str, iocs=None) -> Dict[str, object]:
    kind = ex_kind(path)
    if kind == "android":
        found, gaps, facts = _ex_android(path, iocs)
    else:
        found, gaps, facts = _ex_iphone(path, iocs)
    level = EX_NOTHING
    if any(f["level"] == EX_FOUND for f in found):
        level = EX_FOUND
    elif found:
        level = EX_LOOK
    order = {EX_FOUND: 0, EX_LOOK: 1, EX_NOTHING: 2}
    found.sort(key=lambda f: order[f["level"]])
    return {"level": level, "kind": kind, "findings": found, "gaps": gaps, "facts": facts, "folder": path}


_EX_HEAD = {EX_FOUND: "SIGNS THAT THIS PHONE WAS OPENED OR COPIED",
            EX_LOOK: "SOME THINGS WORTH KNOWING", EX_NOTHING: "NO SIGNS FOUND - WHICH IS NOT PROOF"}
_EX_WORD = {EX_FOUND: "A SIGN OF EXTRACTION", EX_LOOK: "WORTH KNOWING", EX_NOTHING: ""}


def ex_headline(result) -> str:
    return T(_EX_HEAD[result["level"]])


def _ex_paragraph(lines, first, rest, width=96):
    """Fixed advice written as hand-broken English lines: English exactly as written, other languages as the
    translated sentence wrapped at the same indent."""
    if i18n_lang() == "en":
        return list(lines)
    import textwrap
    text = " ".join(line.strip() for line in lines)
    if text.startswith("- "):
        text = text[2:]
    return textwrap.wrap(T(text), width, initial_indent=first, subsequent_indent=rest) or [first + T(text)]


from .safetext import safe_render  # noqa: E402


@safe_render
def ex_render(result) -> str:
    lines = ["=" * 72, "  " + T("WAS THIS PHONE PLUGGED INTO A FORENSICS TOOL?"),
             "  " + T(_EX_HEAD[result["level"]]),
             "  " + (T("Read only, from the collection you gave. Nothing was contacted.") if result["kind"] == "android"
                     else T("Read only, from the backup you gave. Nothing was contacted.")), "=" * 72, "",
             "  " + T(EX_ALWAYS), ""]
    if result["facts"]:
        lines.append("  " + T("THE PHONE"))
        for key, value in result["facts"].items():
            if isinstance(value, list):
                if value:
                    lines.append("    {}: {}".format(key.replace("_", " "), ", ".join(str(v) for v in value[:8])
                                                     + (" " + T("and {n} more", n=len(value) - 8)
                                                        if len(value) > 8 else "")))
            elif value not in (None, "", False):
                lines.append("    {}: {}".format(key.replace("_", " "), value))
        lines.append("")
    if result["findings"]:
        for finding in result["findings"]:
            lines.append("  [{}] {}".format(T(_EX_WORD[finding["level"]]), TX(finding["what"])))
            lines.append("      " + TX(finding["means"]))
            if finding["evidence"]:
                lines.append("      " + T("what was read:") + " " + finding["evidence"])
            lines.append("")
    else:
        lines += ["  " + T("None of the things this check looks for were there."), ""]
    if result["gaps"]:
        lines.append("  " + T("NOT CHECKED"))
        for gap in result["gaps"]:
            lines.append("    - " + TX(gap))
        lines.append("")
    if result["level"] == EX_FOUND:
        lines.append("  " + T("WHAT TO DO"))
        for bullet in (("    - Assume everything that was on the phone is known to whoever had it: messages, photos,",
                        "      contacts, and the accounts it was signed in to."),
                       ("    - Change the passwords of those accounts from a DIFFERENT device, and turn on two-step",
                        "      sign-in. Remove any device you do not recognise from Signal and WhatsApp.")):
            lines += _ex_paragraph(bullet, "    - ", "      ")
        lines += ["    - " + T("Keep this phone as it is if you can, and get expert help: Access Now Helpline"),
                  "      https://www.accessnow.org/help/ " + T("(24/7)."), ""]
    lines += _ex_paragraph(("  Being copied is not the same as being infected: a tool that copies a phone usually "
                            "leaves nothing", "  running on it. The full phone check looks for what stays behind."),
                           "  ", "  ")
    return "\n".join(lines)


EX_HOW_TO = """  What this needs:
    Android: a collection made with AndroidQF (the toolkit can make one: --collect-android FOLDER).
             Unzip it first and give the folder.
    iPhone:  a backup folder. Windows: %APPDATA%\\Apple Computer\\MobileSync\\Backup\\<long id>
             Mac: ~/Library/Application Support/MobileSync/Backup/<long id>
  It reads what you already have. It never touches a phone and contacts nothing."""


def ex_command(args, load_iocs, out=print) -> int:
    path = args.was_extracted
    try:
        iocs = load_iocs(args)
    except Exception as exc:  # noqa: BLE001
        out(T("(Indicator lists could not be loaded: {why}. Checking settings and logs only.)",
              why=str(exc)[:160]))
        iocs = None
    try:
        result = ex_check(path, iocs)
    except ExError as exc:
        out("{}\n\n{}".format(TX(str(exc)), T(EX_HOW_TO)))
        return 1
    out(ex_render(result))
    if getattr(args, "json", None):
        with open(args.json, "x", encoding="utf-8") as fh:
            json.dump(dict(result, tool="zero-breach-toolkit extraction check", always=EX_ALWAYS), fh,
                      indent=2, ensure_ascii=False)
        out("\n" + T("Saved: {path}", path=args.json))
    return {EX_FOUND: 3, EX_LOOK: 1, EX_NOTHING: 0}[result["level"]]
