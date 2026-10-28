"""Android module - checks an AndroidQF collection folder.

AndroidQF (Amnesty-linked, open source) copies what an ordinary phone allows over
USB debugging into a folder: the app list with each APK's fingerprint and signing
certificate, running processes, system properties, settings, a file listing, the
system services' state (dumpsys), logs, a bug report and optionally an SMS backup.
This module reads that folder - it never talks to the phone.

Findings (published indicators):
  packages    app id, APK SHA-256, signing-certificate SHA-1/SHA-256  (on-device)
  processes   running apps by app id - on Android a process is named after
              its app                                                  (on-device)
  properties  system property names researchers tie to spyware        (on-device)
  files       file paths and SHA-256 fingerprints of collected files  (on-device)
  history     apps installed, updated or REMOVED, from the battery
              history - a spyware app deleted after use still shows    (device-log)
  device-logs spyware domains, IPs, app ids and file paths in the system
              services' state and logcat                               (device-log)
  crashes     crash records naming a spyware app or path                (device-log)
  messages    links in SMS messages, from the SMS backup                (received)

'Worth a look' - never findings. Such heuristics flag many harmless things on
ordinary phones, so powers are flagged only together with the
strongest stalkerware sign: an app installed outside any app store. Its line then
spells out what it can do (install apps, read SMS, microphone, camera, location,
notifications, accessibility, device admin, SMS listener) and when it arrived.
Phone-wide: third-party device admins, accessibility access, verification off,
wireless debugging, an insecure build, SELinux off, unlocked bootloader, root
tools, writable system partition, old security patch.

The collection's own footprint is recognised, never flagged: USB debugging (it is
needed), the ADB shell's permission records, AndroidQF's temporary folder.
"""

from __future__ import annotations

import datetime
import io
import json
import os
import re
import stat
import tarfile
import zipfile
import zlib

from ..iocs import (TYPE_ANDROID_PROP, TYPE_APP_CERT, TYPE_APP_ID, TYPE_DOMAIN,
                    TYPE_FILE_NAME, TYPE_FILE_PATH, TYPE_PROCESS, TYPE_SHA256, Indicator,
                    IocSet, ioc_exact_identity, ioc_path_mentioned)
from ..localpaths import path_problem
from ..result import EV_DEVICE_LOG, EV_ON_DEVICE, EV_RECEIVED, EV_REFERENCED, Hit, Lead, ModuleResult

NAME = "android"

# Installers that are app stores. Anything else that installed a third-party app
# means the app was installed by hand (a 'sideloaded' APK) - worth a look.
_AN_STORES = {
    "com.android.vending",            # Google Play
    "app.grapheneos.apps",            # GrapheneOS App Store
    "org.fdroid.fdroid", "org.fdroid.basic",
    "com.aurora.store",
    "com.amazon.venezia",
    "com.sec.android.app.samsungapps",
    "com.huawei.appmarket",
    "com.xiaomi.market", "com.xiaomi.mipicks",
    "com.heytap.market", "com.oppo.market",
    "com.vivo.appstore",
}
# The collection's own footprint: the ADB shell AndroidQF works through.
_AN_FOOTPRINT_APPS = {"com.android.shell"}
_AN_MAX_LOG_BYTES = 256 * 1024 * 1024
_AN_MAX_JSON_BYTES = 64 * 1024 * 1024
_AN_MAX_FILE_LIST_BYTES = 1024 * 1024 * 1024


def _an_file_records(path):
    """Stream the large files.json array without materialising the whole list.

    Separate 1 GiB input limit; at most 4 MiB buffered per record. A damaged
    suffix raises after already-yielded records so earlier matches survive.
    """
    decoder = json.JSONDecoder()
    with _an_open(path, "r", encoding="utf-8") as fh:
        buffer, pos, total, eof = "", 0, 0, False
        def more():
            nonlocal buffer, pos, total, eof
            chunk = fh.read(65536)
            total += len(chunk.encode("utf-8"))
            if total > _AN_MAX_FILE_LIST_BYTES:
                raise ValueError("file list exceeds the 1 GiB read limit")
            buffer = buffer[pos:] + chunk
            pos, eof = 0, not chunk
            if len(buffer) > 4 * 1024 * 1024:
                raise ValueError("individual file-list record exceeds the buffer limit")
        def token():
            nonlocal pos
            while True:
                while pos < len(buffer) and buffer[pos].isspace():
                    pos += 1
                if pos < len(buffer) or eof:
                    return buffer[pos:pos + 1]
                more()
        if token() != "[":
            raise ValueError("AndroidQF could not list files on this phone, or the file list is not a JSON array")
        pos += 1
        if token() == "]":
            pos += 1
        else:
            while True:
                while True:
                    try:
                        record, end = decoder.raw_decode(buffer, pos)
                        pos = end
                        break
                    except json.JSONDecodeError:
                        if eof:
                            raise ValueError("file list is incomplete or malformed")
                        more()
                yield record
                sep = token()
                if sep == "]":
                    pos += 1
                    break
                if sep != ",":
                    raise ValueError("file list is incomplete or malformed")
                pos += 1
                if token() == "]":
                    raise ValueError("file list has a trailing comma")
        if token():
            raise ValueError("unexpected data after the file list")
_AN_MAX_BACKUP_BYTES = 512 * 1024 * 1024
_AN_MAX_SMS_BYTES = 256 * 1024 * 1024
_AN_MAX_ARCHIVE_BYTES = 1024 * 1024 * 1024
_AN_MAX_MEMBERS = 10000
_AN_PATCH_DAYS = 180

# Powers worth naming for a sideloaded app (appops name -> plain words).
_AN_POWERS = {
    "REQUEST_INSTALL_PACKAGES": "install other apps",
    "READ_SMS": "read SMS", "RECEIVE_SMS": "receive SMS", "SEND_SMS": "send SMS",
    "RECORD_AUDIO": "use the microphone", "CAMERA": "use the camera",
    "FINE_LOCATION": "see precise location", "READ_CALL_LOG": "read the call log",
    "READ_CONTACTS": "read contacts", "SYSTEM_ALERT_WINDOW": "draw over other apps",
    "GET_USAGE_STATS": "see which apps you use", "PROJECT_MEDIA": "record the screen",
}
_AN_LISTENED = {"android.provider.Telephony.SMS_RECEIVED": "listens for incoming SMS",
                "android.intent.action.NEW_OUTGOING_CALL": "watches outgoing calls",
                "android.intent.action.PHONE_STATE": "watches calls"}

_AN_WHY_SIDELOAD = ("People install apps directly for ordinary reasons (alternative launchers, "
                    "beta versions, apps not offered in their country). Stalkerware is "
                    "installed the same way. Check you recognise this app and installed it.")
_AN_WHY_ACCESS = ("Screen readers, password managers and automation apps use accessibility "
                  "access. Stalkerware relies on it to read the screen. Check you recognise "
                  "every app listed.")
_AN_WHY_ADMIN = ("Work-profile, find-my-phone and some security apps are device admins. "
                 "Stalkerware uses it so it cannot be uninstalled normally.")
_AN_WHY_ROOT = ("Some people root their phones on purpose. Rooting also lets spyware hide "
                "and survive.")
_AN_WHY_VERIFY = ("Google's app checking ('Play Protect') is off. Some people switch it off; "
                  "stalkerware installers often ask for it.")
_AN_WHY_PATCH = ("Old security updates leave known holes open. Install the latest system "
                 "update.")
_AN_WHY_WIFI_ADB = ("Wireless debugging lets a computer on the same network control the "
                    "phone. Developers use it; switch it off if you do not.")
_AN_WHY_BUILD = ("This is a debug or engineering build of Android, not a normal consumer "
                 "build. Developers use them; on an ordinary phone it means it was modified.")
_AN_WHY_SELINUX = ("Android's built-in protection (SELinux) is not enforcing. That is normal "
                   "only on modified or development phones.")
_AN_WHY_BOOT = ("The bootloader is unlocked, so the system can be replaced. People do this "
                "to install other systems; it also lets someone with the phone in hand "
                "install spyware.")
_AN_WHY_MOUNT = ("The system partition is writable, which normal phones never allow. "
                 "It usually means the phone is rooted or modified.")


# --- reading the collection ------------------------------------------------------

def _an_local_file(path):
    path = os.path.abspath(path)
    problem = path_problem(path)
    if problem:
        raise OSError("collection artifact refused: " + problem)
    if not stat.S_ISREG(os.stat(path).st_mode):
        raise OSError("collection artifact is not a regular file")
    return path


def _an_open(path, mode="r", **kwargs):
    return open(_an_local_file(path), mode, **kwargs)


def _an_exists(path):
    try:
        _an_local_file(path)
        return True
    except FileNotFoundError:
        return False


def _an_why(exc):
    """A gap reason a person can act on: no exception dump, no local path."""
    if isinstance(exc, FileNotFoundError):
        return "not in the collection"
    if isinstance(exc, OSError):
        return "could not be read ({})".format(exc.strerror or type(exc).__name__)
    return str(exc)


def _an_read(path, limit):
    with _an_open(path, "rb") as fh:
        data = fh.read(limit + 1)
    if len(data) > limit:
        raise ValueError("collection artifact exceeds the {} byte limit".format(limit))
    return data


def _an_load_json(path):
    return json.loads(_an_read(path, _AN_MAX_JSON_BYTES).decode("utf-8"))


def _an_kv(path, sep="=", strict=False):
    out = {}
    try:
        for line in _an_read(path, _AN_MAX_JSON_BYTES).decode("utf-8", "replace").splitlines():
            key, s, value = line.partition(sep)
            if s:
                out[key.strip()] = value.strip()
    except (OSError, ValueError):
        if strict:
            raise
    return out


def _an_getprop(path):
    out = {}
    try:
        for line in _an_read(path, _AN_MAX_JSON_BYTES).decode("utf-8", "replace").splitlines():
            line = line.strip()
            if line.startswith("[") and "]: [" in line and line.endswith("]"):
                key, value = line[1:-1].split("]: [", 1)
                out[key] = value
    except (OSError, ValueError):
        pass
    return out


_AN_SECTION = re.compile(r"^DUMP OF SERVICE ([^:\n]+):\n", re.M)
_AN_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_AN_SHA1_RE = re.compile(r"[0-9a-f]{40}")
# Server-pushed feature flags: dumpsys device_config, and the same flags again as
# the CONFIG table of dumpsys settings. Google ships flags whose values list
# hundreds of package names (on Pixel, apps the notification features must skip,
# among them most family-safety apps), so searching them names monitoring apps
# that were never installed. Writing a flag needs WRITE_DEVICE_CONFIG, which no
# store or sideloaded app can hold, so the flags are never a trace of an app.
# A flag value can span lines, so the whole region is skipped up to the next
# settings table or service.
_AN_CONFIG_REGIONS = (
    re.compile(rb"^DUMP OF SERVICE device_config:\r?\n.*?(?=^DUMP OF SERVICE |\Z)",
               re.M | re.S),
    re.compile(rb"^CONFIG SETTINGS \(user \d+\)\r?\n.*?"
               rb"(?=^(?:GLOBAL|SECURE|SYSTEM) SETTINGS \(user \d+\)|^DUMP OF SERVICE |\Z)",
               re.M | re.S),
)


def _an_sections(text):
    """dumpsys output split into {service name: body}."""
    text = text.replace("\r\n", "\n")
    out = {}
    marks = list(_AN_SECTION.finditer(text))
    for i, m in enumerate(marks):
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        out[m.group(1).strip()] = text[m.end():end]
    return out


def _an_install_times(package_section):
    """{app id: firstInstallTime} from dumpsys package."""
    out, current = {}, None
    for line in package_section.splitlines():
        m = re.match(r"\s*Package \[([^\]]+)\]", line)
        if m:
            current = m.group(1)
            continue
        m = re.match(r"\s*firstInstallTime=(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)", line)
        if m and current and current not in out:
            out[current] = m.group(1).replace(" ", "T")
    return out


def _an_receivers(package_section):
    """{app id: {intent action}} for the actions in _AN_LISTENED, from the
    Receiver Resolver Table only (the Activity table lists screens, not
    listeners)."""
    start = package_section.find("Receiver Resolver Table:")
    if start < 0:
        return {}
    end = package_section.find("Resolver Table:", start + 10)
    block = package_section[start:end if end > 0 else len(package_section)]
    out, action = {}, None
    for line in block.splitlines():
        m = re.match(r"\s+([\w.]+):\s*$", line)
        if m and "." in m.group(1):
            action = m.group(1)
            continue
        m = re.match(r"\s+[0-9a-f]+ ([\w.]+)/", line)
        if m and action in _AN_LISTENED:
            out.setdefault(m.group(1), set()).add(action)
    return out


def _an_appops(section):
    """{app id: {ops in allow mode}} from dumpsys appops."""
    out, current = {}, None
    for line in section.splitlines():
        m = re.match(r"\s*Package ([\w.]+):\s*$", line)
        if m:
            current = m.group(1)
            continue
        if re.match(r"\s*Uid ", line):
            current = None
            continue
        m = re.match(r"\s+([A-Z_]+) \((allow|foreground)", line)
        if m and current:
            out.setdefault(current, set()).add(m.group(1))
    return out


def _an_device_admins(section):
    start = section.find("Enabled Device Admins")
    if start < 0:
        return set()
    admins = set()
    for line in section[start:].splitlines()[1:]:
        if re.match(r"\s{4}m[A-Z]", line):
            break
        m = re.match(r"\s{2,}([\w.]+)/[\w.$]+:?\s*$", line)
        if m:
            admins.add(m.group(1))
    return admins


def _an_battery_changes(section):
    """[(verb, app id, period end)] from the battery history's daily package
    changes. A removed app is listed here after it is gone from the phone."""
    out, period = [], ""
    for line in section.splitlines():
        m = re.match(r"\s*Daily from (\S+) to (\S+):", line)
        if m:
            raw = m.group(2)
            period = (raw[:10] + "T" + raw[11:].replace("-", ":")) if len(raw) >= 19 else ""
            continue
        m = re.match(r"\s*(Install|Update|Uninstall) ([\w.]+) vers=", line)
        if m:
            out.append((m.group(1), m.group(2), period))
    return out


def _an_tombstones(folder):
    """[(name, timestamp, cmdline)] of crash records in bugreport.zip."""
    path = os.path.join(folder, "bugreport.zip")
    if not _an_exists(path):
        return None
    out = []
    try:
        with _an_open(path, "rb") as source, zipfile.ZipFile(source) as z:
            for name in z.namelist():
                if not re.search(r"tombstones/tombstone_\d+$", name):
                    continue
                head = z.open(name).read(8192).decode("utf-8", "replace")
                ts = re.search(r"^Timestamp: (\S+ \S+)", head, re.M)
                cmd = re.search(r"^Cmdline: (.+)$", head, re.M)
                out.append((name, ts.group(1)[:19].replace(" ", "T") if ts else "",
                            cmd.group(1).strip() if cmd else ""))
    except (OSError, zipfile.BadZipFile, KeyError, RuntimeError):
        return None
    return out


def _an_inflate(data, limit):
    inflater = zlib.decompressobj()
    raw = inflater.decompress(data, limit + 1)
    if len(raw) > limit or not inflater.eof or inflater.unconsumed_tail:
        raise ValueError("compressed data is incomplete or exceeds the size limit")
    return raw


def _an_sms_from_backup(path, password=""):
    """(messages, problem). Reads an unencrypted Android backup (.ab) of the
    telephony provider: header lines, then (optionally zlib) a tar holding
    *_sms_backup and *_mms_backup files, each zlib-compressed JSON."""
    try:
        data = _an_read(path, _AN_MAX_BACKUP_BYTES)
    except (OSError, ValueError) as exc:
        return [], "SMS backup: {}".format(_an_why(exc))
    if not data:
        return [], ("the SMS backup is empty - the phone did not provide one (AndroidQF asks "
                    "for it during collection)")
    parts = data.split(b"\n", 4)
    if len(parts) < 5 or parts[0] != b"ANDROID BACKUP":
        return [], "the SMS backup is not an Android backup file"
    compressed, encryption, body = parts[2].strip(), parts[3].strip(), parts[4]
    if compressed not in (b"0", b"1"):
        return [], "the SMS backup has an unsupported compression header"
    if parts[1].strip() not in (b"1", b"2", b"3", b"4", b"5"):
        return [], "unsupported Android backup version"
    if encryption.lower() != b"none":
        if encryption != b"AES-256":
            return [], "unsupported SMS backup encryption"
        try:
            from ..backupcrypto import backup_android_decrypt
            body = backup_android_decrypt(body, password)
        except (ValueError, UnicodeError) as exc:
            return [], "encrypted SMS backup: " + _an_why(exc)
    try:
        if compressed == b"1":
            # Bounded: a hostile backup must not expand without limit.
            body = _an_inflate(body, _AN_MAX_ARCHIVE_BYTES)
        # The Android wrapper already handled compression. Never auto-detect an
        # inner compressed tar: skipping a non-SMS member could expand gigabytes.
        archive = tarfile.open(fileobj=io.BytesIO(body), mode="r:")
    except (zlib.error, tarfile.TarError, EOFError, OSError, ValueError) as exc:
        return [], "the SMS backup could not be unpacked (cut short or damaged): {}".format(exc)
    messages = []
    problems, found, expanded = [], 0, 0
    try:
        with archive:
            for index, member in enumerate(archive):
                if index >= _AN_MAX_MEMBERS:
                    problems.append("archive member limit reached")
                    break
                if not member.isfile() or not member.name.endswith(("_sms_backup", "_mms_backup")):
                    continue
                mms = member.name.endswith("_mms_backup")
                found += 1
                try:
                    if member.size > _AN_MAX_SMS_BYTES:
                        raise ValueError("SMS member exceeds the size limit")
                    with archive.extractfile(member) as fh:
                        raw = fh.read(_AN_MAX_SMS_BYTES + 1)
                    if not raw.lstrip().startswith((b"[", b"{")):
                        raw = _an_inflate(raw, _AN_MAX_SMS_BYTES)
                    expanded += len(raw)
                    if expanded > _AN_MAX_SMS_BYTES:
                        problems.append("total SMS data exceeds the size limit")
                        break
                    rows = json.loads(raw.decode("utf-8"))
                    if not isinstance(rows, list):
                        raise ValueError("SMS data must be a list")
                    for row in rows:
                        if mms and isinstance(row, dict):
                            # MMS keeps its text in mms_body and its folder in
                            # msg_box (1 = inbox, as SMS type 1). A picture-only
                            # MMS has no text; its attachments are not opened.
                            if row.get("mms_body") is None:
                                continue
                            row = dict(row, body=row.get("mms_body"), type=row.get("msg_box"), _mms=True)
                        if isinstance(row, dict) and isinstance(row.get("body"), str):
                            messages.append(row)
                        else:
                            problems.append("invalid SMS record")
                except (tarfile.TarError, EOFError, OSError, ValueError, zlib.error) as exc:
                    problems.append("an SMS member could not be read: {}".format(exc))
    except (tarfile.TarError, EOFError, OSError) as exc:
        problems.append("SMS archive incomplete: {}".format(exc))
    if not found:
        problems.append("no supported SMS data in the backup")
    return messages, "; ".join(dict.fromkeys(problems))[:1000]


def _an_hit(r, ind, location, detail, evidence=EV_ON_DEVICE, observed=""):
    r.add_hit(Hit(indicator=ind.value, location=location, detail=detail, tier=ind.tier,
                  confidence=ind.confidence, source=ind.source, evidence=evidence,
                  observed=observed, family=ind.family, kind=ind.type))


def _an_app_id_set(ctx):
    """App-id and file-path indicators as a searchable set: package names and
    paths follow the same boundary rules as domain names, so the fast matcher
    can find them in free text. Values map back to the original indicators."""
    originals = {}
    shadow = []
    for kind in (TYPE_APP_ID,):
        for ind in ctx.iocs.of_type(kind):
            if "." in ind.value and ind.value not in originals:
                originals[ind.value] = ind
                shadow.append(Indicator(ind.value, ind.tier, ind.confidence, TYPE_DOMAIN,
                                        ind.source, ind.family))
    return (IocSet(shadow, "app ids", None) if shadow else None), originals


# --- checks ----------------------------------------------------------------------

def _an_packages(r, ctx, folder, info):
    path = os.path.join(folder, "packages.json")
    try:
        packages = _an_load_json(path)
    except (OSError, ValueError) as exc:
        r.could_not_run("android:packages", "app list: {}".format(_an_why(exc)))
        return []
    if not isinstance(packages, list):
        r.could_not_run("android:packages", "app list must be a JSON list")
        return []
    iocs = ctx.iocs
    # App files whose fingerprint or signing certificate is missing or malformed
    # are not compared at all; counting them keeps that from reading as checked.
    # A certificate indicator is a SHA-256 or a SHA-1 digest, and an app file
    # covers only the digests it actually records, so each is counted apart.
    fp = {"files": 0, "no_hash": 0, "no_cert_sha256": 0, "no_cert_sha1": 0, "no_files": 0,
          "builtin_no_hash": 0, "builtin_no_cert_sha256": 0, "builtin_no_cert_sha1": 0}
    for pkg in packages:
        if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str) or not pkg["name"]:
            r.could_not_run("android:packages", "an app record has no valid package name")
            continue
        name = str(pkg.get("name") or "")
        where = "app {}".format(name)
        ind = iocs.lookup_typed(TYPE_APP_ID, name)
        if ind:
            if ind.tier == "stalkerware":
                detail = ("a phone-monitoring app is installed: {}{} - some are sold as "
                          "family-safety apps".format(
                              name, " ({})".format(ind.family) if ind.family else ""))
            else:
                detail = "an app the researchers name is installed: " + name
            _an_hit(r, ind, where, detail, observed=info["installed"].get(name, ""))
        files = pkg.get("files")
        if not isinstance(files, list) or not files:
            # No app file recorded: neither fingerprint check covered this app.
            # Some built-in components legitimately have none (Android 15's
            # com.android.privatespace), so only a user-installed app counts.
            if pkg.get("third_party"):
                fp["no_files"] += 1
            files = []
        # Built-in apps on the read-only system partitions are reported as a
        # note: collections commonly omit their certificates.
        prefix = "builtin_" if pkg.get("system") else ""
        for f in files:
            fp["files"] += 1
            if not isinstance(f, dict):
                fp[prefix + "no_hash"] += 1
                fp[prefix + "no_cert_sha256"] += 1
                fp[prefix + "no_cert_sha1"] += 1
                continue
            apk = str(f.get("path") or "")
            sha = str(f.get("sha256") or "").lower()
            if not _AN_SHA256_RE.fullmatch(sha):
                fp[prefix + "no_hash"] += 1
            ind = iocs.lookup_typed(TYPE_SHA256, sha) if sha else None
            if ind:
                _an_hit(r, ind, "{} ({})".format(where, apk),
                        "this app's file has the fingerprint of a published sample")
            cert = f.get("certificate") if isinstance(f.get("certificate"), dict) else {}
            for key, pattern in (("Sha256", _AN_SHA256_RE), ("Sha1", _AN_SHA1_RE)):
                value = str(cert.get(key) or "").replace(":", "").lower()
                if not pattern.fullmatch(value):
                    fp[prefix + "no_cert_" + key.lower()] += 1
                ind = iocs.lookup_typed(TYPE_APP_CERT, value) if value else None
                if ind:
                    _an_hit(r, ind, where, "this app is signed with a certificate the "
                            "researchers tie to spyware ({})".format(key.upper()))
        installer = str(pkg.get("installer") or "")
        if pkg.get("third_party") and installer not in _AN_STORES:
            powers = sorted({_AN_POWERS[op] for op in info["appops"].get(name, ())
                             if op in _AN_POWERS})
            powers += sorted({_AN_LISTENED[a] for a in info["receivers"].get(name, ())})
            if name in info["notification"]:
                powers.append("read all notifications")
            if name in info["accessibility"]:
                powers.append("has accessibility access (can read the screen)")
            if name in info["admins"]:
                powers.append("is a device admin (resists uninstalling)")
            text = "app installed outside an app store: {} (installed by: {})".format(
                name, installer or "unknown")
            if powers:
                text += "; it can: " + ", ".join(powers)
            r.add_lead(Lead("android:packages", where, text, _AN_WHY_SIDELOAD,
                            info["installed"].get(name, "")))
    r.checked += len(packages)
    r.submetrics["android_apps"] = len(packages)
    r.ran("android:packages")
    _an_fingerprint_coverage(r, iocs, fp)
    return packages


def _an_fingerprint_coverage(r, iocs, fp):
    """Report app files that could not be compared by fingerprint or signing
    certificate, for the indicator kinds that are actually loaded. Missing data
    for user-installed apps is a gap; for built-in apps it is a note."""
    r.submetrics["android_app_files"] = fp["files"]
    without = " and {} user-installed app(s) listed no app file".format(fp["no_files"]) if fp["no_files"] else ""
    certs = {len(i.value) for i in iocs.of_type(TYPE_APP_CERT)}
    # Only the digest kinds that are loaded need to be present.
    for name, size in (("sha256", 64), ("sha1", 40)):
        if size not in certs:
            fp["no_cert_" + name] = fp["builtin_no_cert_" + name] = 0
    fp["no_cert"] = max(fp["no_cert_sha256"], fp["no_cert_sha1"])
    fp["builtin_no_cert"] = max(fp["builtin_no_cert_sha256"], fp["builtin_no_cert_sha1"])
    needed = " and ".join(name for name, size in (("SHA-256", 64), ("SHA-1", 40)) if size in certs)
    for kind, check, missing, what, against in (
            (TYPE_SHA256, "android:app-fingerprints", "no_hash", "valid SHA-256 fingerprint",
             "published spyware sample fingerprints"),
            (TYPE_APP_CERT, "android:app-certificates", "no_cert",
             "signing-certificate " + (needed or "fingerprint"),
             "certificates tied to spyware")):
        if not iocs.of_type(kind):
            continue
        if fp["builtin_" + missing]:
            r.note("{}: {} built-in app file(s) on the system partitions had no {} in the "
                   "collection and were not compared with {}".format(
                       check, fp["builtin_" + missing], what, against))
        if fp[missing] or fp["no_files"]:
            r.could_not_run(check, "{} user-installed app file record(s) had no {}{}; those apps "
                            "were not compared with {}".format(fp[missing], what, without, against))
        else:
            r.ran(check)


def _an_processes(r, ctx, folder):
    """On Android a process is named after its app, so app-id indicators are
    compared with running processes ('com.spy.app' or 'com.spy.app:remote').

    Process-NAME indicators are deliberately not compared: every published one
    (83 as of 2026-10-25: Amnesty's 81 Pegasus names, Operation Triangulation,
    QuaDream) comes from iPhone investigations, where spyware imitated Apple's
    service names - and some are ordinary Android services: comparing them
    would report 'gatekeeperd' (Android's lock-screen service) as Pegasus on
    every Android phone. They are used on iPhones only."""
    names = len(ctx.iocs.of_type(TYPE_PROCESS))
    if names:
        r.note("android: {} process-name indicators were not compared - they come from "
               "iPhone investigations and some match normal Android services".format(names))
    seen, count, found_input = set(), 0, False
    def process_name(value, source):
        nonlocal count
        count += 1
        # Only the executable/app name is compared, never arguments, environment
        # variables or incidental app-id text elsewhere in a JSON record.
        app = value.split(":", 1)[0]
        if app in seen:
            return
        seen.add(app)
        ind = ctx.iocs.lookup_typed(TYPE_APP_ID, app)
        if ind:
            before = len(r.hits)
            _an_hit(r, ind, "running process " + value,
                    "an app the researchers name was running")
            if len(r.hits) > before:
                r.hits[-1].artifact = source

    # ps.txt is what older AndroidQF releases wrote.
    for filename in ("processes.json", "processes.txt", "ps.txt"):
        path = os.path.join(folder, filename)
        try:
            if not _an_exists(path):
                continue
            found_input = True
            if filename.endswith(".json"):
                # AndroidQF collector's ProcessInfo output: array of records,
                # pid integer and command_line array. A null/empty command line
                # may be a kernel task; its comm filename is not an app identity.
                records = _an_load_json(path)
                if not isinstance(records, list):
                    raise ValueError("unsupported process JSON; expected an array")
                if len(records) > 200000:
                    r.could_not_run("android:processes", "process JSON row limit reached")
                invalid = unavailable = 0
                for record in records[:200000]:
                    if (not isinstance(record, dict) or type(record.get("pid")) is not int
                            or record["pid"] <= 0 or "command_line" not in record):
                        invalid += 1
                        continue
                    command = record["command_line"]
                    if command is None or command == []:
                        unavailable += 1
                        continue
                    if (not isinstance(command, list) or not command
                            or not all(isinstance(v, str) for v in command)
                            or not command[0] or len(command[0]) > 4096
                            or any(ord(c) < 32 for c in command[0])):
                        invalid += 1
                        continue
                    process_name(command[0], path)
                if invalid:
                    r.skipped += invalid
                    r.could_not_run("android:processes", "{} invalid process JSON record(s) were not searched".format(invalid))
                if unavailable:
                    r.skipped += unavailable
                    r.could_not_run("android:processes", "{} process command line(s) unavailable; kernel tasks or unreadable records cannot be classified".format(unavailable))
            else:
                lines = _an_read(path, _AN_MAX_LOG_BYTES).decode("utf-8", "strict").splitlines()
                if not lines or not set(lines[0].upper().split()).intersection({"NAME", "CMD", "COMMAND"}):
                    raise ValueError("missing process-list header")
                for line in lines[1:]:
                    parts = line.split()
                    if parts:
                        process_name(parts[-1], path)
        except (OSError, ValueError, RecursionError) as exc:
            r.could_not_run("android:processes", "{}: {}".format(filename, _an_why(exc)))
    r.submetrics["android_processes"] = count
    if count:
        r.ran("android:processes")
    else:
        r.could_not_run("android:processes", "no supported process records" if found_input else "process list missing (processes.json, processes.txt or ps.txt)")


def _an_properties(r, ctx, props):
    if not props:
        r.could_not_run("android:properties", "no system properties in the collection")
        return
    for key in props:
        ind = ctx.iocs.lookup_typed(TYPE_ANDROID_PROP, key)
        if ind:
            _an_hit(r, ind, "system property " + key,
                    "a system property the researchers tie to spyware is set")
    patch = props.get("ro.build.version.security_patch", "")
    try:
        age = (datetime.date.today() - datetime.date.fromisoformat(patch)).days
    except ValueError:
        age = None
    if age is not None and age > _AN_PATCH_DAYS:
        r.add_lead(Lead("android:properties", "ro.build.version.security_patch",
                        "security updates are {} days old (patch level {})".format(age, patch),
                        _AN_WHY_PATCH))
    r.ran("android:properties")


def _an_settings(r, settings, info):
    if not settings:
        r.could_not_run("android:settings", "no settings in the collection")
        return
    services = settings.get("enabled_accessibility_services", "")
    if services and services != "null":
        r.add_lead(Lead("android:settings", "enabled_accessibility_services",
                        "apps with accessibility access: " + services.replace(":", ", "),
                        _AN_WHY_ACCESS))
    if settings.get("package_verifier_enable") == "0":
        r.add_lead(Lead("android:settings", "package_verifier_enable",
                        "app verification (Play Protect) is switched off", _AN_WHY_VERIFY))
    if settings.get("adb_wifi_enabled") == "1":
        r.add_lead(Lead("android:settings", "adb_wifi_enabled",
                        "wireless debugging is on", _AN_WHY_WIFI_ADB))
    if settings.get("adb_enabled") == "1":
        r.note("android: USB debugging was on - the collection needs it. Switch it off when "
               "you are done (Settings > System > Developer options), and revoke USB "
               "debugging authorisations.")
    third_party_admins = sorted(a for a in info["admins"] if a in info["third_party"])
    if third_party_admins:
        r.add_lead(Lead("android:settings", "device admins",
                        "apps that are device admins: " + ", ".join(third_party_admins),
                        _AN_WHY_ADMIN))
    r.ran("android:settings")


def _an_device_security(r, folder, props):
    """Phone-wide signs of a modified phone. 'yellow' boot state is NOT flagged:
    it is how GrapheneOS and other properly signed custom systems report."""
    if props.get("ro.debuggable") == "1" or props.get("ro.secure") == "0":
        r.add_lead(Lead("android:device-security", "ro.debuggable / ro.secure",
                        "the phone runs a debug or engineering build", _AN_WHY_BUILD))
    if props.get("ro.boot.flash.locked") == "0" or props.get(
            "ro.boot.verifiedbootstate") == "orange":
        r.add_lead(Lead("android:device-security", "ro.boot.flash.locked",
                        "the bootloader is unlocked", _AN_WHY_BOOT))
    try:
        selinux = _an_read(os.path.join(folder, "selinux.txt"), _AN_MAX_JSON_BYTES).decode(
            "utf-8", "replace").strip()
        if not selinux:
            raise ValueError("empty SELinux record")
    except (OSError, ValueError) as exc:
        selinux = ""
        r.could_not_run("android:device-security", "SELinux record: {}".format(_an_why(exc)))
    if selinux and selinux.lower() != "enforcing":
        r.add_lead(Lead("android:device-security", "selinux",
                        "SELinux is '{}', not enforcing".format(selinux[:40]), _AN_WHY_SELINUX))
    try:
        mounts = _an_load_json(os.path.join(folder, "mounts.json"))
    except (OSError, ValueError) as exc:
        mounts = None
        r.could_not_run("android:device-security", "mounts record: {}".format(_an_why(exc)))
    if mounts is not None and not isinstance(mounts, list):
        r.could_not_run("android:device-security", "mounts record must be a JSON list")
        mounts = None
    for m in mounts or []:
        text = m if isinstance(m, str) else json.dumps(m)
        if re.search(r"\s/system(\s|$)", " " + text + " ") and re.search(r"\brw\b", text):
            r.add_lead(Lead("android:device-security", "mounts",
                            "the system partition is mounted writable", _AN_WHY_MOUNT))
            break
    r.ran("android:device-security")


def _an_files(r, ctx, folder):
    path = os.path.join(folder, "files.json")
    count = invalid = valid = hashed = 0
    try:
        for f in _an_file_records(path):
            count += 1
            if not isinstance(f, dict) or not isinstance(f.get("path"), str) or not f["path"]:
                invalid += 1
                continue
            p = str(f.get("path") or "")
            ind = ctx.iocs.lookup_typed(TYPE_FILE_PATH, p)
            if ind and ioc_exact_identity(ind, p):
                _an_hit(r, ind, p, "a file at a path the researchers tie to spyware")
            sha = str(f.get("sha256") or "").lower()
            if len(sha) == 64 and all(c in "0123456789abcdef" for c in sha):
                hashed += 1
            else:
                sha = ""
            ind = ctx.iocs.lookup_typed(TYPE_SHA256, sha) if sha else None
            if ind:
                _an_hit(r, ind, p, "this file has the fingerprint of a published sample")
            base = p.rsplit("/", 1)[-1]
            ind = ctx.iocs.lookup_typed(TYPE_FILE_NAME, base) if base else None
            if ind and ioc_exact_identity(ind, base):
                r.add_lead(Lead("android:files", p,
                                "a file name researchers list ({}); a name alone is weak".format(base),
                                "Ordinary software can use the same file name."))
    except (OSError, ValueError, RecursionError) as exc:
        r.could_not_run("android:files", "file list: {}".format(_an_why(exc)))
    valid = count - invalid
    if invalid and valid:
        r.could_not_run("android:files", "invalid file-list record(s): {}".format(invalid))
    if not valid:
        r.could_not_run("android:files", "AndroidQF could not list files on this phone")
    else:
        r.ran("android:files")
        # Paths and names were checked; fingerprints only where AndroidQF
        # recorded them (its "hash files" option), so say how many.
        if hashed == valid:
            r.ran("android:file-hashes")
        elif not hashed:
            r.could_not_run("android:file-hashes", "the collection has no file fingerprints (AndroidQF's "
                            "\"hash files\" option was off), so files were checked by path and name only")
        else:
            r.could_not_run("android:file-hashes", "{} of {} listed file(s) have no valid fingerprint, so "
                            "they were checked by path and name only".format(valid - hashed, valid))
    r.submetrics["android_files_listed"] = valid
    r.submetrics["android_files_hashed"] = hashed



def _an_root(r, folder):
    try:
        found = _an_load_json(os.path.join(folder, "root_binaries.json"))
    except (OSError, ValueError) as exc:
        r.could_not_run("android:root", "root-tool record: {}".format(_an_why(exc)))
        return
    if not isinstance(found, list):
        r.could_not_run("android:root", "root-tool record must be a JSON list")
        return
    if found:
        r.add_lead(Lead("android:root", "root_binaries.json",
                        "root tools found: " + ", ".join(str(x) for x in found)[:300],
                        _AN_WHY_ROOT))
    r.ran("android:root")


def _an_history(r, ctx, sections):
    battery = sections.get("batterystats")
    if battery is None:
        r.could_not_run("android:history", "no battery history in the collection")
        return
    changes = _an_battery_changes(battery)
    reported = set()
    for verb, app, period in changes:
        ind = ctx.iocs.lookup_typed(TYPE_APP_ID, app)
        if ind and (app, verb) not in reported:
            reported.add((app, verb))
            word = {"Install": "installed", "Update": "updated",
                    "Uninstall": "REMOVED"}[verb]
            _an_hit(r, ind, "battery history (package changes)",
                    "an app the researchers name was {} on this phone (day ending {})".format(
                        word, period[:10] or "unknown"),
                    evidence=EV_DEVICE_LOG, observed=period)
    r.submetrics["android_package_changes"] = len(changes)
    r.ran("android:history")


def _an_device_logs(r, ctx, folder, already):
    read = 0
    app_set, originals = _an_app_id_set(ctx)
    for name in ("dumpsys.txt", "logcat.txt"):
        path = os.path.join(folder, name)
        try:
            with _an_open(path, "rb") as fh:
                data = fh.read(_AN_MAX_LOG_BYTES + 1)
        except OSError as exc:
            r.could_not_run("android:device-logs", "{}: {}".format(name, _an_why(exc)))
            continue
        if len(data) > _AN_MAX_LOG_BYTES:
            r.could_not_run("android:device-logs", "{} exceeds the read limit; its remaining "
                           "bytes were not checked".format(name))
            data = data[:_AN_MAX_LOG_BYTES]
        read += len(data)
        if name == "dumpsys.txt":
            for region in _AN_CONFIG_REGIONS:
                data = region.sub(b"\n", data)
        low = data.lower()
        for ind in ctx.iocs.search_bytes(low):
            _an_hit(r, ind, "phone log " + name,
                    "the phone's own system log names it", evidence=EV_DEVICE_LOG)
        if app_set is not None:
            for shadow in app_set.search_bytes(low):
                if shadow.value in already:
                    continue
                already.add(shadow.value)
                _an_hit(r, originals[shadow.value], "phone log " + name,
                        "the phone's system records name this app (it may have been "
                        "installed earlier)", evidence=EV_DEVICE_LOG)
        text = data.decode("utf-8", "replace")
        for ind in ctx.iocs.of_type(TYPE_FILE_PATH):
            if ind.value not in already and ioc_path_mentioned(ind, text):
                already.add(ind.value)
                _an_hit(r, ind, "phone log " + name,
                        "the phone's system records name this spyware path",
                        evidence=EV_DEVICE_LOG)
    if not read:
        r.could_not_run("android:device-logs", "no dumpsys or logcat output in the collection")
        return
    r.submetrics["android_log_bytes"] = read
    r.ran("android:device-logs")


def _an_crashes(r, ctx, folder):
    tombs = _an_tombstones(folder)
    if tombs is None:
        r.could_not_run("android:crashes", "bug report missing or unreadable; crash records "
                       "were not checked")
        return
    for name, when, cmdline in tombs:
        app = cmdline.split(":", 1)[0].strip()
        ind = ctx.iocs.lookup_typed(TYPE_APP_ID, app)
        if ind is None:
            executable = cmdline.split(" ", 1)[0]
            candidate = ctx.iocs.lookup_typed(TYPE_FILE_PATH, executable)
            if candidate and ioc_exact_identity(candidate, executable):
                ind = candidate
        if ind:
            _an_hit(r, ind, "crash record " + name.rsplit("/", 1)[-1],
                    "a crash record names it: " + cmdline[:200], evidence=EV_DEVICE_LOG,
                    observed=when)
    r.submetrics["android_crash_records"] = len(tombs)
    r.ran("android:crashes")


def _an_messages(r, ctx, folder):
    path = os.path.join(folder, "backup.ab")
    if not _an_exists(path):
        r.could_not_run("android:messages", "no SMS backup in the collection, so links in "
                        "messages were not checked")
        return
    messages, problem = _an_sms_from_backup(path, ctx.backup_password)
    if problem:
        r.could_not_run("android:messages", problem)
    for msg in messages:
        body = str(msg.get("body") or "")
        if not body:
            continue
        when = ""
        try:
            stamp = int(msg.get("date"))
            # SMS dates are milliseconds; MMS dates are seconds.
            when = datetime.datetime.fromtimestamp(stamp if stamp < 10 ** 11 else stamp / 1000).isoformat(
                timespec="seconds")
        except (TypeError, ValueError, OSError, OverflowError):
            pass
        kind = "MMS" if msg.get("_mms") else "SMS"
        address = msg.get("address")
        if not address and msg.get("_mms"):
            found = re.search(r"'address': '([^']{1,40})'", str(msg.get("mms_addresses") or ""))
            address = found.group(1) if found else ""
        # Folder 1 is the inbox. Sent, draft, outbox and failed messages were
        # written on this phone, so a link in them is a reference, not delivery.
        received = str(msg.get("type")) == "1"
        for ind in ctx.iocs.search(body.lower()):
            _an_hit(r, ind, "{} {} {}".format(kind, "from" if received else "to/with",
                                              str(address or "unknown")[:40]),
                    "a text message contains it: " + body[:200],
                    evidence=EV_RECEIVED if received else EV_REFERENCED, observed=when)
    r.checked += len(messages)
    r.submetrics["android_sms_messages"] = len(messages)
    if not problem or messages:
        r.ran("android:messages")


def run(ctx) -> ModuleResult:
    r = ModuleResult(NAME)
    ctx.partial = r
    folder = getattr(ctx, "phone_path", "") or ""
    problem = path_problem(os.path.abspath(folder)) if folder else "no folder given"
    if problem or not _an_exists(os.path.join(folder, "packages.json")):
        r.could_not_run("android", "not an AndroidQF collection folder ({})".format(
            problem or "packages.json missing"))
        return r
    try:
        acquisition = _an_load_json(os.path.join(folder, "acquisition.json"))
        started = acquisition.get("started", "") if isinstance(acquisition, dict) else ""
    except (OSError, ValueError, RecursionError):
        started = ""
    r.submetrics["collected"] = 1
    if started:
        r.note("android: collection made {}".format(str(started)[:19]))

    try:
        sections = _an_sections(_an_read(os.path.join(folder, "dumpsys.txt"),
                                        _AN_MAX_LOG_BYTES).decode("utf-8", "replace"))
    except (OSError, ValueError) as exc:
        sections = {}
        r.could_not_run("android:history", "dumpsys metadata: {}".format(_an_why(exc)))
    settings = {}
    for name in ("settings_global.txt", "settings_secure.txt", "settings_system.txt"):
        try:
            settings.update(_an_kv(os.path.join(folder, name), strict=True))
        except (OSError, ValueError) as exc:
            r.could_not_run("android:settings", "{}: {}".format(name, _an_why(exc)))
    try:
        third_party = {str(p.get("name")) for p in _an_load_json(
            os.path.join(folder, "packages.json"))
            if isinstance(p, dict) and p.get("third_party")}
    except (OSError, ValueError, AttributeError, TypeError, RecursionError):
        third_party = set()
    access = re.findall(r"\{?([\w.]+)/", settings.get("enabled_accessibility_services", ""))
    access += re.findall(r"\{([\w.]+)/", sections.get("accessibility", "").split(
        "Enabled services:", 1)[-1].split("\n", 1)[0])
    info = {
        "installed": _an_install_times(sections.get("package", "")),
        "receivers": _an_receivers(sections.get("package", "")),
        "appops": {k: v for k, v in _an_appops(sections.get("appops", "")).items()
                   if k not in _AN_FOOTPRINT_APPS},
        "admins": _an_device_admins(sections.get("device_policy", "")),
        "notification": set(re.findall(r"([\w.]+)/",
                                       settings.get("enabled_notification_listeners", ""))),
        "accessibility": set(access),
        "third_party": third_party,
    }
    props = _an_getprop(os.path.join(folder, "getprop.txt"))

    # Each part is guarded on its own: a collection made by hand, cut short or
    # damaged costs only the part it damaged, reported as a gap - never the
    # whole report.
    def guarded(check, fn, *args):
        before = len(r.hits)
        try:
            fn(*args)
        except Exception as exc:  # malformed collection data of any shape
            r.could_not_run(check, "this part of the collection could not be read "
                            "({}: {})".format(type(exc).__name__, str(exc)[:200]))
        finally:
            source = {"android:packages": "packages.json", "android:processes": "processes.txt",
                      "android:properties": "getprop.txt", "android:files": "files.json",
                      "android:history": "dumpsys.txt", "android:messages": "backup.ab",
                      "android:crashes": "bugreport"}.get(check, check)
            for hit in r.hits[before:]:
                if check == "android:device-logs" and hit.location.startswith("phone log "):
                    source = hit.location[len("phone log "):]
                hit.artifact = os.path.join(folder, source)

    guarded("android:packages", _an_packages, r, ctx, folder, info)
    guarded("android:processes", _an_processes, r, ctx, folder)
    guarded("android:properties", _an_properties, r, ctx, props)
    guarded("android:settings", _an_settings, r, settings, info)
    guarded("android:device-security", _an_device_security, r, folder, props)
    guarded("android:files", _an_files, r, ctx, folder)
    guarded("android:root", _an_root, r, folder)
    guarded("android:history", _an_history, r, ctx, sections)
    already = {h.indicator for h in r.hits}
    guarded("android:device-logs", _an_device_logs, r, ctx, folder, already)
    guarded("android:crashes", _an_crashes, r, ctx, folder)
    guarded("android:messages", _an_messages, r, ctx, folder)
    return r
