"""Check a suspicious file (--check-file PATH): a plain first look at one file, offline, without running it.

For someone who has found a file they do not trust - an attachment, a download, an app someone sent them - and
wants to know what it is before handing it to an expert:

  * fingerprints (SHA-256, SHA-1, MD5) compared with the spyware indicator lists;
  * what the file really is, from its first bytes, whatever its name says;
  * for Windows programs: who signed it and whether Windows trusts the signature (offline), the import hash;
  * web addresses, domains and IP addresses written inside it, and any of them that are on the spyware lists;
  * signs it is packed or scrambled to hide what it does;
  * for Android apps: the package name (compared with the lists) and what it asks to do - read messages, use the
    microphone, act as an accessibility service, become a device administrator;
  * for documents: macros, embedded programs, PDF actions that run when the file is opened;
  * for scripts and shortcuts: commands that download and run something.

Nothing is executed, opened in another program, uploaded or looked up online, and the file is never moved,
changed or deleted (moving it would destroy evidence of where it was). The only thing it writes is what you ask
for: a SEALED COPY - a ZIP protected with the password "infected", the usual way researchers pass samples to each
other, so the copy cannot be run or removed by accident on its way to an expert.

Hostile input: every reader has size limits and bounds checks; a damaged or booby-trapped file gives a shorter
result, never a crash or a hang.
"""
import binascii
import hashlib
import math
import html
import os
import re
import struct
import time
import zipfile
import zlib
from typing import Dict, List, Optional

from .bugreport import zip_open
from .i18n import T, TX
from .localpaths import path_problem
from .hashlook import hl_examine
from .heuristics import CRADLE_GET, CRADLE_RUN, REMOTE, RUNNER

FC_READ_MAX = 256 * 1024 * 1024          # bytes read for the content checks
FC_SEARCH_MAX = 32 * 1024 * 1024         # bytes searched for listed addresses (said in the result when cut)
# Document notes that mean "not all of it was read": they make the result incomplete, never "worth a look".
FC_DOC_PARTIAL = ("was too large to check completely", "has more compressed content than this check reads")
FC_SEAL_MAX = 1024 * 1024 * 1024         # largest file a sealed copy is made of
FC_MANIFEST_MAX = 8 * 1024 * 1024        # AndroidManifest.xml inside an app
FC_PASSWORD = b"infected"
FC_MAX_LISTED = 40

FC_KNOWN, FC_LOOK, FC_CLEAN = "known-threat", "worth-a-look", "clean"
FC_INCOMPLETE = "incomplete"      # nothing else stood out, but the spyware lists could not be compared

# --- addresses written inside the file ----------------------------------------------------------------------------

_URL = re.compile(rb"https?://[a-z0-9][a-z0-9.\-]{1,252}(?::\d{2,5})?(?:/[\x21-\x7e]{0,200})?", re.I)
_IP4 = re.compile(rb"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_FC_ASCII_RUN = re.compile(rb"[\x20-\x7e]{6,}")
_FC_WIDE_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")
_FC_TEXT_REGION = re.compile(rb"[\x09\x0a\x0d\x20-\x7e]{6,}")             # a stretch of text, lines and all
_FC_WIDE_REGION = re.compile(rb"(?:[\x09\x0a\x0d\x20-\x7e]\x00){6,}")


def _public_ip(text: str) -> bool:
    try:
        parts = [int(p) for p in text.split(".")]
    except ValueError:
        return False
    if len(parts) != 4 or any(p > 255 for p in parts):
        return False
    a, b = parts[0], parts[1]
    if a in (0, 10, 127) or a >= 224 or (a == 169 and b == 254) or (a == 172 and 16 <= b <= 31) \
            or (a == 192 and b == 168) or (a == 100 and 64 <= b <= 127):
        return False
    # Version numbers such as 1.2.3.4 look like addresses; 8.8.8.8 and 1.1.1.1 (public DNS) are real ones.
    return parts != [1, 0, 0, 0] and not (all(p < 10 for p in parts) and len(set(parts)) > 1)


def fc_addresses(data: bytes) -> Dict[str, List[str]]:
    """Web addresses and public IP addresses written in the file, as text or as wide (UTF-16) text."""
    data = data[:FC_SEARCH_MAX]                  # the same part the spyware lists are searched in
    views = [data]
    wide = b"".join(m.group(0)[::2] + b"\n" for m in _FC_WIDE_RUN.finditer(data))
    if wide:
        views.append(wide)
    # Ordered de-duplication with dicts: a file of many distinct addresses must not slow down with their square.
    urls, ips = {}, {}
    for view in views:
        for m in _URL.finditer(view):
            urls.setdefault(m.group(0).decode("ascii", "replace").rstrip(".,;:'\")]}>"), None)
        seen_ips = set()
        for m in _IP4.finditer(view):
            ip = m.group(0)
            if ip in seen_ips:                    # each distinct address is judged once
                continue
            seen_ips.add(ip)
            ip = ip.decode("ascii")
            if _public_ip(ip):
                ips.setdefault(ip, None)
    hosts = {}
    for u in urls:
        hosts.setdefault(u.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0].lower(), None)
    return {"urls": list(urls), "hosts": list(hosts), "ips": list(ips)}


# --- packed or scrambled -------------------------------------------------------------------------------------------

def fc_entropy(data: bytes) -> float:
    """Shannon entropy in bits per byte (8.0 = indistinguishable from random: compressed or encrypted)."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def _sample_entropy(data: bytes) -> float:
    """Entropy of up to 4 MB spread across the file (fast on big files)."""
    if len(data) <= 4 * 1024 * 1024:
        return fc_entropy(data)
    step = len(data) // 16
    return fc_entropy(b"".join(data[i * step:i * step + 256 * 1024] for i in range(16)))


_PACKER_SECTIONS = {b"UPX0": "UPX", b"UPX1": "UPX", b".aspack": "ASPack", b".adata": "ASPack", b".themida": "Themida",
                    b".vmp0": "VMProtect", b".vmp1": "VMProtect", b".enigma1": "Enigma", b"MPRESS1": "MPRESS",
                    b".petite": "Petite", b".nsp0": "NsPack"}


# Companies whose programs are widely imitated. A program that names one of them must be signed by it - when the
# signature can be judged: a signer written in the file, or Windows' own answer (which also knows the catalog
# signatures most of Windows' own programs use instead of one inside the file).
FC_CLAIMED_MAKERS = ("microsoft", "google", "apple", "adobe", "mozilla", "oracle", "intel", "nvidia", "advanced micro "
                     "devices", "zoom", "cisco", "dropbox", "opera", "whatsapp", "meta platforms", "facebook",
                     "telegram", "signal messenger", "valve", "anydesk", "teamviewer", "realtek", "logitech")
# Windows tools that attackers copy under another name to slip past rules that watch for the real name.
FC_RENAMED_TOOLS = ("powershell.exe", "pwsh.exe", "cmd.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
                    "wscript.exe", "cscript.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "installutil.exe",
                    "regasm.exe", "regsvcs.exe", "psexec.exe", "psexesvc.exe", "wmic.exe", "schtasks.exe", "nc.exe",
                    "ncat.exe", "msiexec.exe", "cmstp.exe", "forfiles.exe", "odbcconf.exe")


def fc_program_claims(rec) -> List[str]:
    """Warnings from what a Windows program says about itself: a famous maker its signature does not back, and a
    Windows tool saved under another name."""
    out = []
    company = (rec.get("version_companyName") or "").lower()
    original = (rec.get("version_originalFilename") or "").lower().replace(".mui", "").strip()
    name = (rec.get("name") or "").lower().rstrip(". ")
    signer = (rec.get("signer") or "").lower()
    status = rec.get("signature") or ""
    maker = next((m for m in FC_CLAIMED_MAKERS if m in company), "")
    # Only programs a person runs: apps routinely bundle (and re-sign) Microsoft's libraries, and Windows itself signs
    # the drivers it ships for other makers - a library or driver naming another maker is ordinary.
    runs = name.endswith((".exe", ".scr", ".com", ".pif", ".cpl"))
    if maker and runs:
        first = maker.split()[0]
        if signer and first not in signer and "microsoft" not in signer:
            out.append("it says it is made by {}, but it is signed by someone else ({})".format(
                rec.get("version_companyName", "")[:60], rec.get("signer", "")[:60]))
        elif status in ("not-signed", "bad-signature"):
            out.append("it says it is made by {}, but {}".format(
                rec.get("version_companyName", "")[:60],
                "it is not signed" if status == "not-signed" else "its signature is not valid"))
    if original in FC_RENAMED_TOOLS and name and name != original:
        out.append("it is the Windows tool {} saved under another name - a common way to slip past security "
                   "rules".format(original))
    return out


def fc_pe_packing(data: bytes) -> List[str]:
    """Known packer section names in a Windows program, and sections that are almost random."""
    out = []
    try:
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[lfanew:lfanew + 4] != b"PE\x00\x00":
            return out
        nsec = struct.unpack_from("<H", data, lfanew + 6)[0]
        opt_size = struct.unpack_from("<H", data, lfanew + 20)[0]
        sec = lfanew + 24 + opt_size
        seen, judged = set(), 0
        for i in range(min(nsec, 96)):
            off = sec + 40 * i
            name = data[off:off + 8].rstrip(b"\x00")
            raw_size, raw_ptr = struct.unpack_from("<II", data, off + 16)
            if name in _PACKER_SECTIONS:
                out.append("packed with {} (section {})".format(_PACKER_SECTIONS[name], name.decode("ascii", "replace")))
            body = data[raw_ptr:raw_ptr + min(raw_size, 8 * 1024 * 1024)]
            # .rsrc holds icons and pictures, which are compressed (PNG) and so look random in every ordinary
            # program; only code and data sections that look random say something.
            if (raw_ptr, raw_size) in seen or judged > 64 * 1024 * 1024:
                continue                            # the same bytes again, or enough read
            seen.add((raw_ptr, raw_size))
            judged += len(body)
            if name.lower() != b".rsrc" and len(body) >= 4096 and fc_entropy(body) > 7.4:
                out.append("section {} is almost random (compressed or encrypted code)".format(
                    name.decode("ascii", "replace") or "#{}".format(i)))
    except struct.error:
        pass
    return out


# --- Android apps --------------------------------------------------------------------------------------------------

# What a permission lets an app do, in plain words. Only the ones that matter for spying.
FC_PERMISSIONS = {
    "android.permission.READ_SMS": "read your text messages",
    "android.permission.RECEIVE_SMS": "receive your text messages",
    "android.permission.SEND_SMS": "send text messages",
    "android.permission.RECORD_AUDIO": "use the microphone",
    "android.permission.CAMERA": "use the camera",
    "android.permission.ACCESS_FINE_LOCATION": "know your exact location",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "know your location while you are not using it",
    "android.permission.READ_CONTACTS": "read your contacts",
    "android.permission.READ_CALL_LOG": "read your call history",
    "android.permission.PROCESS_OUTGOING_CALLS": "see the numbers you call",
    "android.permission.READ_PHONE_STATE": "read your phone number and call state",
    "android.permission.READ_EXTERNAL_STORAGE": "read your files and photos",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "read and change all your files",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "act as an accessibility service: read everything on screen "
                                                     "and tap for you",
    "android.permission.BIND_DEVICE_ADMIN": "become a device administrator (hard to remove)",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE": "read all your notifications, including messages",
    "android.permission.REQUEST_INSTALL_PACKAGES": "install other apps",
    "android.permission.SYSTEM_ALERT_WINDOW": "draw over other apps",
    "android.permission.QUERY_ALL_PACKAGES": "see every app on the phone",
    "android.permission.RECEIVE_BOOT_COMPLETED": "start by itself when the phone starts",
}
# Asked for by almost every spying app; with any of the "watch" permissions it is worth a look.
_FC_CONTROL = {"android.permission.BIND_ACCESSIBILITY_SERVICE", "android.permission.BIND_DEVICE_ADMIN",
               "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE"}
_FC_WATCH = {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.RECORD_AUDIO",
             "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.READ_CALL_LOG",
             "android.permission.PROCESS_OUTGOING_CALLS"}
# CAMERA is not a "watch" permission here: password managers (autofill + QR codes) and watch companion apps ask
# for it together with accessibility or notification access, and would all be called spying apps.
_ATTR_BY_RESID = {0x01010003: "name", 0x01010006: "permission"}


class AxmlError(ValueError):
    pass


def _axml_strings(data, off):
    count, _styles, flags, start = struct.unpack_from("<IIII", data, off + 8)
    if count > 200000:
        raise AxmlError("too many strings")
    utf8 = bool(flags & 0x100)
    base = off + start
    out = []
    for i in range(count):
        pos = base + struct.unpack_from("<I", data, off + 28 + 4 * i)[0]
        if utf8:
            n = data[pos]
            pos += 2 if n & 0x80 else 1
            blen = data[pos]
            if blen & 0x80:
                blen = ((blen & 0x7F) << 8) | data[pos + 1]
                pos += 2
            else:
                pos += 1
            out.append(data[pos:pos + blen].decode("utf-8", "replace"))
        else:
            n = struct.unpack_from("<H", data, pos)[0]
            pos += 2
            if n & 0x8000:
                n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, pos)[0]
                pos += 2
            out.append(data[pos:pos + 2 * n].decode("utf-16-le", "replace"))
    return out


def fc_axml(data: bytes) -> Dict[str, object]:
    """Package name, permissions and protected components from a binary AndroidManifest.xml."""
    if len(data) < 8 or struct.unpack_from("<H", data, 0)[0] != 0x0003:
        raise AxmlError("not a binary Android manifest")
    strings, resmap = [], []
    package, permissions, bound = "", [], []
    off = struct.unpack_from("<H", data, 2)[0]
    guard = 0
    while off + 8 <= len(data) and guard < 500000:
        guard += 1
        ctype, hsize, size = struct.unpack_from("<HHI", data, off)
        if size < 8 or off + size > len(data):
            break
        if ctype == 0x0001:
            strings = _axml_strings(data, off)
        elif ctype == 0x0180:
            resmap = list(struct.unpack_from("<%dI" % ((size - hsize) // 4), data, off + hsize))
        elif ctype == 0x0102:
            name_i = struct.unpack_from("<I", data, off + 20)[0]
            a_start, a_size, a_count = struct.unpack_from("<HHH", data, off + 24)
            tag = strings[name_i] if name_i < len(strings) else ""
            attrs = {}
            for k in range(min(a_count, 512)):
                a = off + 16 + a_start + k * a_size
                _ns, an, raw, _sz, _r0, dtype, value = struct.unpack_from("<IIIHBBI", data, a)
                aname = strings[an] if an < len(strings) and strings[an] else _ATTR_BY_RESID.get(
                    resmap[an] if an < len(resmap) else 0, "")
                if raw != 0xFFFFFFFF and raw < len(strings):
                    attrs[aname] = strings[raw]
                elif dtype == 0x03 and value < len(strings):
                    attrs[aname] = strings[value]
            if tag == "manifest":
                package = attrs.get("package", package)
            elif tag in ("uses-permission", "uses-permission-sdk-23") and attrs.get("name"):
                if attrs["name"] not in permissions:
                    permissions.append(attrs["name"])
            elif tag in ("service", "receiver", "activity") and attrs.get("permission"):
                if attrs["permission"] not in bound:
                    bound.append(attrs["permission"])
        off += size
    return {"package": package, "permissions": permissions, "bound": bound}


def fc_apk(path: str) -> Dict[str, object]:
    out = {"package": "", "permissions": [], "bound": [], "dex_files": 0, "problem": ""}
    try:
        with zip_open(path) as z:
            infos = z.infolist()[:100000]
            out["dex_files"] = sum(1 for i in infos if re.match(r"classes\d*\.dex$", i.filename))
            man = [i for i in infos if i.filename == "AndroidManifest.xml"]
            if not man:
                out["problem"] = "no AndroidManifest.xml inside"
                return out
            if man[0].file_size > FC_MANIFEST_MAX:
                out["problem"] = "AndroidManifest.xml is too large to read"
                return out
            with z.open(man[0]) as fh:
                raw = fh.read(FC_MANIFEST_MAX + 1)
            if raw.lstrip(b"\xef\xbb\xbf \t\r\n")[:1] == b"<":
                # A plain-text manifest: an Android library (.aar) or an unbuilt project. Android cannot install
                # it as an app, so it is read for what it asks for, not called damaged.
                text = raw.decode("utf-8", "replace")
                m = re.search(r"""<manifest\b[^>]*\bpackage\s*=\s*["']([^"']{1,200})""", text)
                out["package"] = m.group(1) if m else ""
                out["permissions"] = list(dict.fromkeys(re.findall(
                    r"""<uses-permission(?:-sdk-23)?\b[^>]*\bandroid:name\s*=\s*["']([^"']{1,200})""", text)))
                return out
            out.update(fc_axml(raw))
    except (zipfile.BadZipFile, OSError, AxmlError, struct.error, IndexError, NotImplementedError, RuntimeError,
            zlib.error, EOFError, ValueError) as exc:
        out["problem"] = "the app could not be fully read ({})".format(type(exc).__name__)
    return out


# --- documents, scripts and shortcuts ------------------------------------------------------------------------------

_FC_PART_MAX = 2 * 1024 * 1024      # one decompressed part of an Office file
_FC_PARTS_TOTAL = 32 * 1024 * 1024  # all decompressed parts together
# The Equation Editor object (CVE-2017-11882 and CVE-2018-0802): its class id, as stored in a compound file and
# as hex text inside RTF, and its program name "Equation.3" as hex text.
_FC_EQNEDT_BIN = bytes.fromhex("02ce020000000000c000000000000046")
_FC_EQNEDT_HEX = (b"02ce020000000000c000000000000046", b"4571756174696f6e2e33")
_FC_REL = re.compile(r"<Relationship\b[^<>]{0,4096}>", re.I)      # bounded: no slow backtracking on junk
# Every PDF name, with #xx escapes (/Java#53cript is /JavaScript): decoded before comparing.
_FC_PDF_NAME = re.compile(rb"/((?:[A-Za-z0-9_.\-]|#[0-9A-Fa-f]{2}){1,64})(?![A-Za-z0-9#_.\-])")
_FC_PDF_WANTED = {b"JavaScript", b"JS", b"OpenAction", b"AA", b"Launch", b"EmbeddedFile", b"XFA"}
_FC_PDF_STREAM_START = re.compile(rb"(?<![A-Za-z0-9])stream\r?\n")
_FC_ATTR = re.compile(r"""(\w+)\s*=\s*(?:"([^"]*)"|'([^']*)')""")


def _fc_host(url: str) -> str:
    m = re.match(r"(?i)[a-z][a-z0-9+.\-]*:(?://)?([^/\\:?#!]+)", url.strip())
    return (m.group(1) if m else url)[:100]


def fc_ooxml(path: str) -> List[str]:
    """Word / Excel / PowerPoint (ZIP-based): macros, embedded objects, and parts that reach out when opened.
    Relationship parts are read decompressed (they are deflated inside the file), each size-capped."""
    out = []
    try:
        with zip_open(path) as z:
            all_infos = z.infolist()
            infos = all_infos[:20000]
            if len(all_infos) > len(infos):
                out.append("has more internal parts than this check reads (an Office document normally has dozens)")
            names = [i.filename.lower() for i in infos]
            if any(n.endswith("vbaproject.bin") for n in names):
                out.append("contains macros (programs that can run when the document is opened)")
            if any(n.startswith("xl/macrosheets/") for n in names):
                out.append("contains Excel 4.0 macros (an old kind of macro attackers still use)")
            ordinary = (".xlsx", ".docx", ".pptx", ".emf", ".wmf", ".png", ".jpg", ".jpeg", ".gif", ".xml")
            if any(("/embeddings/" in n and not n.endswith(ordinary)) or
                   n.endswith((".exe", ".dll", ".scr", ".js", ".vbs", ".ps1", ".bat", ".cmd", ".hta", ".lnk"))
                   for n in names):
                out.append("contains embedded files or programs")
            budget = _FC_PARTS_TOTAL
            for info in infos:
                low = info.filename.lower()
                wanted = low.endswith(".rels") or low in ("word/document.xml",) or \
                    (low.startswith(("word/embeddings/", "xl/embeddings/", "ppt/embeddings/")) and low.endswith(".bin"))
                if not wanted:
                    continue
                if budget <= 0:
                    out.append("was too large to check completely")
                    continue
                # The document text and embedded objects can be large: read as much as the overall budget allows.
                take = min(info.file_size, budget)
                if take < info.file_size:
                    out.append("was too large to check completely")
                budget -= take
                with z.open(info) as fh:
                    part = fh.read(take)
                if low.endswith(".bin"):
                    if _FC_EQNEDT_BIN in part:
                        out.append("contains an Equation Editor object, used to attack old versions of Word "
                                   "(CVE-2017-11882)")
                    continue
                text = part.decode("utf-16" if part[:2] in (b"\xff\xfe", b"\xfe\xff") else "utf-8", "replace")
                if low == "word/document.xml":
                    if re.search(r"(?i)\bDDEAUTO\b|<w:instrText[^<>]{0,500}>\s{0,50}DDE\b", text):
                        out.append("uses DDE fields, which can run a command when the document is opened")
                    continue
                if low.endswith(".rels"):
                    for rel in _FC_REL.findall(text):
                        a = {k.lower(): html.unescape(x or y) for k, x, y in _FC_ATTR.findall(rel)}
                        if a.get("type", "").lower().endswith("/vbaproject"):
                            out.append("contains macros (programs that can run when the document is opened)")
                for rel in _FC_REL.findall(text):
                    attrs = {k.lower(): html.unescape(a or b) for k, a, b in _FC_ATTR.findall(rel)}
                    if attrs.get("targetmode", "").lower() != "external":
                        continue
                    target, kind = attrs.get("target", ""), attrs.get("type", "").lower()
                    if kind.endswith("/vbaproject"):
                        out.append("contains macros (programs that can run when the document is opened)")
                    tlow = target.lower()
                    if tlow.startswith("mhtml:") or "!x-usc:" in tlow or ("oleobject" in kind and tlow.endswith("!")):
                        out.append("uses the 'Follina' trick (an external object ending in '!') to run a program "
                                   "when it is opened (CVE-2022-30190)")
                    elif kind.endswith("/attachedtemplate"):
                        out.append("downloads a template from {} when opened - a way to fetch macros later "
                                   "(remote template)".format(_fc_host(target)))
                    elif kind.endswith(("/oleobject", "/frame", "/subdocument", "/externallinkpath")) and \
                            re.match(r"(?i)(?:https?|ftp)://|file://[^/]|\\\\|//", target):
                        out.append("loads something from {} when opened (external object)".format(_fc_host(target)))
                    # External hyperlinks (Type .../hyperlink) are ordinary links someone may click: not reported.
    except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, zlib.error, EOFError, ValueError):
        out.append("could not be fully read (damaged, or not really an Office document)")
    return list(dict.fromkeys(out))


def fc_pdf_streams(data: bytes, limit: int = 32 * 1024 * 1024, info=None) -> bytes:
    """The decompressed contents of a PDF's compressed streams (where /JavaScript can hide), size-capped. Pictures
    are skipped (they are most of a large PDF and never hold script); ASCIIHex is decoded as well as Flate. info,
    when given, gets "cut": True if the budget or the stream count ran out before the end."""
    out, total, count, pos = [], 0, 0, 0
    while True:
        m = _FC_PDF_STREAM_START.search(data, pos)
        if not m:
            break
        if count >= 4000 or total >= limit:
            if info is not None:
                info["cut"] = True
            break
        start = m.end()
        dictionary = data[max(0, m.start() - 1024):m.start()]
        end = data.find(b"endstream", start)
        if end < 0:
            if info is not None:
                info["cut"] = True                      # an unfinished stream: what follows it was not read
            break
        pos = end + 9                                   # the next stream starts after this one: one pass in all
        if re.search(rb"/Subtype\s*/Image\b", dictionary.rsplit(b"obj", 1)[-1]):
            continue
        count += 1
        raw = data[start:min(end, start + FC_READ_MAX)]
        try:
            if re.search(rb"/ASCIIHexDecode\b|/AHx\b", dictionary.rsplit(b"obj", 1)[-1]):
                digits = re.sub(rb"[^0-9A-Fa-f]", b"", raw.split(b">", 1)[0])[:2 * (limit - total)]
                body = binascii.unhexlify(digits[:len(digits) // 2 * 2])
                try:                                    # often Flate inside the hex as well
                    body = zlib.decompressobj().decompress(body, limit - total) or body
                except zlib.error:
                    pass
            else:
                body = zlib.decompressobj().decompress(raw, limit - total)
        except (zlib.error, binascii.Error, ValueError):
            continue
        out.append(body)
        total += len(body)
    return b"\n".join(out)


def _fc_pdf_outside_streams(data: bytes) -> bytes:
    """A PDF's own text with the (compressed, binary) stream contents left out. One pass, no backtracking."""
    out, pos = [], 0
    while True:
        m = _FC_PDF_STREAM_START.search(data, pos)  # the keyword itself, at the end of a line - not "upstream"
        if m is None:
            out.append(data[pos:])
            break
        start = m.start()
        out.append(data[pos:start + 6])
        end = data.find(b"endstream", m.end())
        if end < 0:
            out.append(data[start + 6:])             # never finished: keep it all, so nothing can hide behind
            break
        out.append(b" endstream")
        pos = end + 9                               # past "endstream", so its own "stream" is not taken again
    return b"".join(out)


def fc_document(path: str, head: bytes, data: bytes) -> List[str]:
    out = []
    if head[:2] == b"PK":
        out = fc_ooxml(path)
    elif head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        # Only the macro project's own storage name (stored as UTF-16 in the compound file's directory). The three
        # letters "VBA" occur by chance in MSI installers, Outlook messages and ordinary files.
        if b"_\x00v\x00b\x00a\x00_\x00p\x00r\x00o\x00j\x00e\x00c\x00t" in data[:64 * 1024 * 1024].lower():
            out.append("contains macros (programs that can run when the document is opened)")
        if _FC_EQNEDT_BIN in data:
            out.append("contains an Equation Editor object, used to attack old versions of Word (CVE-2017-11882)")
    elif b"%PDF" in head[:1024]:
        # PDF names are matched in the file's own text with the compressed stream bytes taken out, plus the
        # decompressed streams - never in raw stream bytes, where "/JS" or "/AA" turn up by chance in any large
        # scanned page or photo. A name ends at the first character that cannot be part of a name.
        info = {}
        view = _fc_pdf_outside_streams(data) + b"\n" + fc_pdf_streams(data, info=info)
        if info.get("cut"):
            out.append("has more compressed content than this check reads")
        names = set()
        for m in _FC_PDF_NAME.finditer(view):
            name = m.group(1)
            if b"#" in name:
                name = re.sub(rb"#([0-9A-Fa-f]{2})", lambda h: bytes([int(h.group(1), 16)]), name)
            if name in _FC_PDF_WANTED:
                names.add(name)
        # /OpenAction and /AA on their own are everyday (open at page 1, at a zoom level): they matter only
        # together with JavaScript.
        js = bool(names & {b"JavaScript", b"JS"})
        if js and names & {b"OpenAction", b"AA"}:
            out.append("runs JavaScript as soon as it is opened")
        elif js:
            out.append("runs JavaScript")
        for token, words in ((b"Launch", "can start another program"), (b"XFA", "contains an XFA form (can run scripts)")):
            if token in names and words not in out:
                out.append(words)
        if b"EmbeddedFile" in names:
            # An e-invoice (Factur-X / ZUGFeRD) or a signed form carries an XML file: data, not something to open.
            embedded = [n.decode("latin-1", "replace").lower() for n in
                        re.findall(rb"/(?:UF|F)\s*\(([^)\r\n]{1,200})\)", view)]
            plain = (".xml", ".json", ".csv", ".txt", ".pdf", ".png", ".jpg", ".jpeg", ".gif")
            # Content Credentials (C2PA), which editing tools attach to say where a document came from, are an
            # embedded record of type application/c2pa: data, never opened.
            objects = re.findall(rb"<<[^<>]{0,400}/Type\s*/EmbeddedFile\b[^<>]{0,400}>>", view)
            provenance_only = bool(objects) and all(re.search(rb"/Subtype\s*/application#2Fc2pa\b", o) for o in objects)
            if not provenance_only and (not embedded or not all(n.endswith(plain) for n in embedded)):
                out.append("carries embedded files")
    elif head[:4] == b"{\\rt":
        low = data[:64 * 1024 * 1024].lower()
        if b"\\objdata" in low or b"\\objupdate" in low:
            out.append("contains embedded objects (often used to attack old versions of Word)")
        if any(h in low for h in _FC_EQNEDT_HEX):
            out.append("contains an Equation Editor object, used to attack old versions of Word (CVE-2017-11882)")
    return out


# Text files Windows runs by their name, which the kind detector calls "other".
_FC_RUNS_AS_SCRIPT = (".vbe", ".wsh", ".reg", ".url", ".chm", ".hta", ".js", ".jse", ".vbs", ".wsf", ".ps1", ".bat",
                      ".cmd")


def fc_runnable_text(ext: str, data: bytes) -> str:
    """What a double-clicked .vbe / .wsh / .reg / .url / .chm does, in plain words (values shown, never followed)."""
    text = data[:65536].decode("utf-8", "replace")
    if ext == ".vbe":
        return "it is an encoded VBScript (.vbe): it runs when double-clicked, and the encoding hides what it does"
    if ext == ".chm":
        return "it is a compiled help file (.chm): opening it can run scripts inside it"
    if ext == ".wsh":
        m = re.search(r"(?im)^[ \t]*Path[ \t]*=[ \t]*(.{1,300})$", text)
        return "it is a Windows Script Host file that runs another script{}".format(
            ": " + fc_readable(m.group(1))[:200] if m and fc_readable(m.group(1)) else "")
    if ext == ".reg":
        autostart = re.search(r"(?i)\\(Run|RunOnce|Winlogon|Image File Execution Options|Policies)\b", text)
        return "it changes Windows settings (the registry) when opened{}".format(
            ", including what starts automatically or how Windows starts programs" if autostart else "")
    if ext == ".url":
        m = re.search(r"(?im)^[ \t]*URL[ \t]*=[ \t]*(.{1,500})$", _fc_url_section(text))
        target = fc_readable(m.group(1))[:200] if m else ""
        return "it is an internet shortcut that opens {}".format(target or "an address that could not be read")
    return "it runs when double-clicked"


def _fc_url_section(text: str) -> str:
    """The [InternetShortcut] section of a .url file - the one Windows reads; a decoy section before it is not."""
    m = re.search(r"(?im)^[ \t]*\[InternetShortcut\][ \t\r]*$", text)       # Windows lines end in \r\n
    if not m:
        return text
    rest = text[m.end():]
    nxt = re.search(r"(?m)^[ \t]*\[", rest)
    return rest[:nxt.start()] if nxt else rest


# Registry places a .reg file can use to start things, weaken protection or hijack how programs run.
_FC_REG_SENSITIVE = re.compile(
    r"(?i)\\(Run|RunOnce|RunServices|Winlogon|Image File Execution Options|Policies|Services|Shell\\Open\\Command|"
    r"Explorer\\Shell Folders|AppInit_DLLs|Windows Defender|SilentProcessExit|Environment|Classes\\CLSID)\b")


def _fc_url_runs_something(data: bytes) -> bool:
    """An internet shortcut whose target (or icon) is a local file, a network share or a program, not a web page.
    A remote icon path also leaks the computer's sign-in hash to whoever runs that share."""
    text = _fc_url_section(data[:65536].decode("utf-8", "replace"))
    for key in ("URL", "IconFile"):
        m = re.search(r"(?im)^[ \t]*" + key + r"[ \t]*=[ \t]*(.{1,500})$", text)
        if not m:
            continue
        value = m.group(1).strip().lower()
        if key == "IconFile" and (value.startswith(("\\\\", "//", "file:")) or "://" in value):
            return True
        # A local file, a network share, a scheme attackers abuse to run or fetch things, or a program at the end of
        # any address. App links such as steam:// or mailto: are not "something that runs".
        if key == "URL" and (value.startswith(("\\\\", "//")) or
                             re.match(r"(file|smb|search-ms|search|ms-msdt|ms-officecmd|ms-word|ms-excel|ms-powerpoint|"
                                      r"ms-appinstaller|mk|its|ms-its|ftp):", value) or
                             re.search(r"\.(exe|scr|hta|js|jse|vbs|vbe|wsf|lnk|bat|cmd|ps1|msi|cpl|jar|zip|iso)(\?|#|$)",
                                       value)):
            return True
    return False


def fc_script(data: bytes, is_script: bool = True) -> List[str]:
    """Download-and-run commands, and system tools started with an internet address. `is_script` False (a file of
    no recognised kind): only the strong download-and-run signal counts - a text or data file that merely mentions
    curl and an address is not a script anyone can run."""
    chunk = data[:FC_SEARCH_MAX]
    text = b"\n".join(_FC_ASCII_RUN.findall(chunk)).decode("ascii", "replace")
    text += "\n" + b"\n".join(m[::2] for m in _FC_WIDE_RUN.findall(chunk)).decode("ascii", "replace")
    out = []
    # Both halves of a download-and-run command in ONE stretch of text (line breaks included). Binary data holds
    # short random fragments - "iEx" here, "irm" there - that must never add up to a command.
    regions = [r.decode("ascii", "replace") for r in _FC_TEXT_REGION.findall(chunk)]
    regions += [r[::2].decode("ascii", "replace") for r in _FC_WIDE_REGION.findall(chunk)]
    if any(len(r) >= 20 and CRADLE_RUN.search(r) and CRADLE_GET.search(r) for r in regions):
        out.append("downloads something and runs it (a PowerShell download-and-run command)")
    if not is_script:
        return out
    for line in text.splitlines():
        if RUNNER.search(line) and REMOTE.search(line):
            out.append("starts a system tool with an internet address: " + line.strip()[:160])
            break
    # What droppers do without any address in sight (the same signs the shortcut check uses).
    for r in regions:
        if len(r) < 12:
            continue
        for pattern, words in _FC_SCRIPT_SIGNS:
            if words not in out and pattern.search(r):
                out.append(words)
        for words in fc_powershell_switches(r, with_policy=False):
            if words not in out:
                out.append(words)
    return out


# PowerShell takes any unambiguous start of a switch name, after "-", "/" or a dash character.
_FC_PS_SWITCH = re.compile("(?:^|[\\s\"'])[-/\u2013\u2014\u2015]([a-z]{1,15})\\s+[\"']?([^\\s\"']{1,4096})", re.I)


def fc_powershell_switches(text: str, with_policy: bool = True) -> List[str]:
    """Encoded command, hidden window and (for shortcuts) execution-policy bypass, however the switch is shortened
    (-e, -en, -enc, -encodedcommand, /enc, -win hidden, -windowstyle 1, -ep bypass ...)."""
    out = []
    for m in _FC_PS_SWITCH.finditer(text):                # callers already cap the text (32 MB)
        name, value = m.group(1).lower(), m.group(2).lower()
        if "encodedcommand".startswith(name) and len(value) >= 20 and re.fullmatch(r"[a-z0-9+/=]+", value):
            out.append("carries a hidden (encoded) command")
        elif len(name) >= 1 and "windowstyle".startswith(name) and name != "e" and value in ("h", "hidden", "1"):
            out.append("runs a command in a hidden window")
        elif with_policy and (name == "ep" or (len(name) >= 2 and "executionpolicy".startswith(name))) \
                and value in ("bypass", "unrestricted"):
            out.append("switches off PowerShell's script safety (execution policy bypass)")
    return list(dict.fromkeys(out))


_FC_SCRIPT_SIGNS = (
    (re.compile(r"(?i)frombase64string"), "carries a hidden (encoded) command"),
    (re.compile(r"#@~\^"), "is encoded with the Windows script encoder, which hides what it does"),
    (re.compile(r"(?i)language\s*=\s*[\"']?(?:vbscript|jscript)\.encode"),
     "is encoded with the Windows script encoder, which hides what it does"),
    (re.compile(r"(?i)eval\s*\(\s*function\s*\(\s*p\s*,\s*a\s*,\s*c\s*,\s*k\s*,\s*e"), "runs packed (scrambled) script code"),
    (re.compile(r"(?i)\bexecute(?:global)?\s*\(?\s*chr\w*\s*\("), "runs scrambled script code"),
    (re.compile(r"(?i)createobject\s*\(\s*\"[^\"]{0,40}\"\s*&"),
     "builds the name of what it starts from pieces, a way to hide it"),
    (re.compile(r"(?i)(wscript\.shell|shell\.application)[\s\S]{0,400}?\.(run|exec|shellexecute)\b"),
     "starts other programs through Windows Script Host"),
    (re.compile(r"(?i)new\s+activexobject\s*\("), "uses ActiveX to reach outside the script"),
    (re.compile(r"(?i)\beval\s*\(\s*(?:atob|unescape|decodeuricomponent|string\.fromcharcode)\s*\("),
     "runs scrambled script code"),
)


# --- names built to deceive ------------------------------------------------------------------------------------------

# Characters that change the direction text is shown in: one placed before "fdp.exe" makes it display as "exe.pdf".
_FC_BIDI = "‪‫‬‭‮⁦⁧⁨⁩‎‏؜"
_FC_RUN_EXT = (".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta",
               ".ps1", ".lnk", ".url", ".msi", ".cpl", ".jar", ".iso", ".img", ".vhd", ".vhdx", ".one", ".chm",
               ".reg", ".dll", ".apk")
_FC_DOC_EXT = (".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".odt", ".csv", ".jpg",
               ".jpeg", ".png", ".gif", ".bmp", ".mp4", ".mov", ".mp3", ".wav", ".zip", ".rar", ".html", ".htm")


def fc_show_name(name: str) -> str:
    """The name as it is safe to print: direction-changing characters shown as <U+202E> instead of acting."""
    return "".join("<U+{:04X}>".format(ord(c)) if c in _FC_BIDI else c for c in str(name))


def fc_name_tricks(name: str) -> List[str]:
    out = []
    if any(c in name for c in _FC_BIDI):
        out.append("its name contains invisible right-to-left characters that make the end of the name display "
                   "backwards, so a program can look like a document")
    low = "".join(c for c in name.lower() if c not in _FC_BIDI)
    base, ext = os.path.splitext(low)
    if ext in _FC_RUN_EXT:
        inner = os.path.splitext(base.rstrip())[1]
        if inner in _FC_DOC_EXT:
            out.append("its name has two endings ('{}' then '{}'): it is made to look like a {} file".format(
                inner, ext, inner.lstrip(".").upper()))
        if re.search(r"\s{5,}$", base) or "  " * 4 in base:
            out.append("its real ending is pushed out of sight by a row of spaces")
    return out


# --- shortcuts ------------------------------------------------------------------------------------------------------

# Tools ordinary shortcuts start every day (a command prompt, PowerShell, control-panel items, uninstallers): named
# only when something else about the shortcut is wrong. The second group is almost never in an honest shortcut.
_FC_LAUNCHERS = ("powershell", "pwsh", "cmd.exe", "cmd /", "wscript", "cscript", "rundll32", "msiexec", "wmic",
                 "schtasks", "conhost")
_FC_ABUSED = ("mshta", "certutil", "bitsadmin", "regsvr32", "forfiles", "msbuild", "installutil", "hh.exe",
              "curl.exe", "curl ")


def fc_shortcut(raw: bytes) -> Dict[str, object]:
    """What a Windows shortcut (.lnk) starts, judged from what it RUNS (target and arguments) - never from its
    description, working folder or icon. Nothing is resolved or followed. A damaged shortcut is judged on all of
    its text, since its fields cannot be told apart."""
    from .shelllinks import _sl_parse, shelllink_content
    try:
        active, reference, complete = _sl_parse(raw[:1024 * 1024])
        lines = reference.split("\n") if reference else []
        launch = active or (lines[-1] if lines else "")        # no stored target: the arguments are kept last
    except Exception:  # noqa: BLE001 - any damage: fall back to the whole text
        active, reference, complete = shelllink_content(raw[:1024 * 1024])
        launch = active + "\n" + reference
    text = launch.lower()
    flags = []
    if re.search(r"https?://|^\\\\|[\s\"']\\\\[a-z0-9]", text):
        flags.append("points at an address on the internet or on another computer")
    if "frombase64string" in text:
        flags.append("carries a hidden (encoded) command")
    for words in fc_powershell_switches(text):
        flags.append(words.replace("runs a command in a hidden window", "runs in a hidden window"))
    if re.search(r"(?<!\s)\s{40,}\S", launch):            # tried only where a run of spaces starts: linear
        flags.append("hides part of its command after a long row of spaces")
    abused = [t.strip(" ") for t in _FC_ABUSED if t in text]
    ordinary = [t.strip(" /") for t in _FC_LAUNCHERS if t in text]
    if ordinary:
        # A command tool (cmd, PowerShell, rundll32...) told to run a file kept next to the shortcut or in a
        # temporary folder - the classic loader. Only its ARGUMENTS are read, never an ordinary program's own path.
        at = min(text.find(t) for t in _FC_LAUNCHERS if t in text)
        parts = text[at:].split(None, 1)
        args = parts[1] if len(parts) > 1 else ""
        if re.search(r"(%appdata%|%localappdata%|%temp%|%tmp%|%public%|%programdata%|\\appdata\\|\\temp\\)", args) \
                or re.search(r"""(?:^|[\s"',=])(?:\.\\|[a-z0-9_\-]+\\)[^\s"',]*\.(dll|exe|ps1|vbs|js|jse|bat|cmd|hta|scr)\b""",
                             args):
            flags.append("starts a program or library kept next to it or in a temporary folder")
    if abused or (ordinary and flags):
        flags.insert(0, "starts a system tool that can run commands ({})".format(
            ", ".join(dict.fromkeys(abused + ordinary))[:80]))
    return {"starts": fc_readable(launch)[:400], "complete": bool(complete), "flags": flags}


def fc_readable(text: str) -> str:
    """Text read out of a file, made safe to show: control, invisible and direction-changing characters become
    spaces (they can break the layout or reverse what is shown). "" when nothing readable is left - a damaged
    file's bytes are not shown as if they were a command."""
    import unicodedata
    shown = "".join(" " if unicodedata.category(c)[0] == "C" or c == "�" else c for c in text or "").strip()
    return shown if len(re.findall(r"[A-Za-z0-9]", shown)) >= 3 else ""


# --- archives and disk images ---------------------------------------------------------------------------------------

# Inside an archive or disk image, what counts is what a person can start with a double-click (libraries, source
# code and data files that programs carry with them are not).
_FC_RISKY_INSIDE = tuple(e for e in _FC_RUN_EXT if e != ".dll") + (".dmg", ".pkg", ".app")
_FC_SCRIPTS = (".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".ps1", ".bat", ".cmd", ".reg")


def fc_tar(path: str) -> Dict[str, object]:
    """What a TAR archive holds, from its headers only (nothing unpacked), capped like a ZIP."""
    import tarfile
    out = {"type": "TAR", "count": 0, "entries": [], "risky": [], "encrypted": False, "nested": [], "tricks": [],
           "problem": ""}
    try:
        with tarfile.open(path, "r:") as t:
            for member in t:
                out["count"] += 1
                if out["count"] > 100000:
                    out["problem"] = "the archive holds more files than this check reads"
                    break
                if not member.isfile():
                    continue
                base = member.name.rsplit("/", 1)[-1]
                low = base.lower().rstrip(". ")
                if len(out["entries"]) < FC_MAX_LISTED:
                    out["entries"].append(fc_show_name(member.name)[:160])
                if low.endswith(_FC_RISKY_INSIDE) and len(out["risky"]) < FC_MAX_LISTED:
                    out["risky"].append(fc_show_name(member.name)[:160])
                for trick in fc_name_tricks(base):
                    if len(out["tricks"]) < 10:
                        out["tricks"].append("{}: {}".format(fc_show_name(base)[:80], trick))
    except (tarfile.TarError, OSError, EOFError, ValueError) as exc:
        out["problem"] = "the archive's list of contents could not be read ({})".format(type(exc).__name__)
    return out


def _fc_archive_entry(out, name: str, total: int) -> None:
    """One file named inside a ZIP or 7-Zip archive: listed, and judged by its name only (nothing is unpacked)."""
    base = name.rsplit("/", 1)[-1]
    low = base.lower().rstrip(". ")             # Windows drops trailing dots and spaces when it creates the file
    if len(out["entries"]) < FC_MAX_LISTED:
        out["entries"].append(fc_show_name(name)[:160])
    # Programs, shortcuts and disk images count anywhere; scripts only at the top or in a small archive -
    # web and code bundles carry hundreds of .js / .bat files nobody double-clicks.
    script = low.endswith(_FC_SCRIPTS)
    near_top = "/" not in name.strip("/") or total <= 10
    # A "Java program" shape (a manifest and one .class) must not hide the programs next to it.
    if low.endswith(_FC_RISKY_INSIDE) and (not script or near_top) \
            and not (out["type"] not in ("ZIP", "7-Zip") and script) and len(out["risky"]) < FC_MAX_LISTED:
        out["risky"].append(fc_show_name(name)[:160])
    if low.endswith((".zip", ".rar", ".7z", ".iso", ".img", ".vhd", ".vhdx")) and len(out["nested"]) < 10:
        out["nested"].append(fc_show_name(name)[:160])
    for trick in fc_name_tricks(base):
        if len(out["tricks"]) < 10:
            out["tricks"].append("{}: {}".format(fc_show_name(base)[:80], trick))


def fc_archive(path: str, head: bytes) -> Dict[str, object]:
    """What an archive holds, from its directory only - nothing is unpacked."""
    out = {"type": "", "count": 0, "entries": [], "risky": [], "encrypted": False, "nested": [], "tricks": [],
           "problem": ""}
    with open(path, "rb") as fh:
        first = fh.read(512)
    if first[257:262] == b"ustar":
        return fc_tar(path)
    if head[:2] == b"PK" or zipfile.is_zipfile(path):
        out["type"] = "ZIP"
        try:
            with zip_open(path) as z:
                infos = z.infolist()[:100000]
        except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, ValueError) as exc:
            out["problem"] = "the archive's list of contents could not be read ({})".format(type(exc).__name__)
            out["damaged"] = first[:4] == b"PK\x03\x04"     # a real ZIP that will not open (not ".p7x", "PKCX...")
            return out
        out["count"] = len(infos)
        names_low = {i.filename.lower() for i in infos}
        if "meta-inf/manifest.mf" in names_low and any(n.endswith(".class") for n in names_low):
            # A Java program (.jar): its own resources are not "files inside" a person would open.
            out["type"] = "Java program (JAR)"
        files = [i for i in infos if not i.filename.endswith("/")]
        for info in infos:
            if info.filename.endswith("/"):
                continue
            if info.flag_bits & 1:
                out["encrypted"] = True
            _fc_archive_entry(out, info.filename, len(files))
    elif head[:4] == b"Rar!":
        out["type"], out["problem"] = "RAR", "RAR contents are not listed by this check"
    elif head[:4] == b"7z\xbc\xaf":
        from .sevenzip import sz_list
        out["type"] = "7-Zip"
        listed = sz_list(path)
        files = [name for name, folder in listed["files"] if not folder]
        out["count"] = len(listed["files"])
        out["encrypted"] = listed["encrypted"]
        if listed["problem"]:
            out["problem"] = "the 7-Zip list of contents could not be read ({})".format(listed["problem"])
        elif listed["encrypted"] and not listed["files"]:
            out["names_locked"] = True          # "encrypt file names": even the list is behind the password
        for name in files[:100000]:
            _fc_archive_entry(out, name, len(files))
    elif head[:2] == b"\x1f\x8b":
        out["type"], out["problem"] = "gzip", "the compressed contents are not unpacked by this check"
    return out


def _fc_iso_records(fh, lba: int, size: int, joliet: bool) -> List[str]:
    names = []
    fh.seek(lba * 2048)
    block = fh.read(min(size, 1024 * 1024))
    pos = 0
    while pos < len(block) and len(names) < 2000:
        length = block[pos]
        if length == 0:                       # records never cross a sector: skip to the next one
            pos = (pos // 2048 + 1) * 2048
            continue
        if length < 34 or pos + length > len(block):
            break
        name_len = block[pos + 32]
        raw = block[pos + 33:pos + 33 + name_len]
        if raw not in (b"\x00", b"\x01"):
            try:
                name = raw.decode("utf-16-be") if joliet else raw.decode("ascii")
            except UnicodeDecodeError:
                name = raw.decode("latin-1")
            name = name.split(";")[0].rstrip(".")
            if block[pos + 25] & 2:
                name += "/"
            names.append(name)
        pos += length
    return names


def fc_disk_image(path: str, size: int) -> Optional[Dict[str, object]]:
    """ISO 9660 (root folder listed), UDF, VHD, VHDX and Mac disk images - recognised by their own markers."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0)
            first = fh.read(512)
            if first[:8] == b"vhdxfile":
                return {"type": "VHDX virtual disk", "entries": [], "risky": [], "listed": False}
            tail = b""
            if size >= 512:
                fh.seek(size - 512)
                tail = fh.read(512)
            if first[:8] == b"conectix" or tail[:8] == b"conectix":
                return {"type": "VHD virtual disk", "entries": [], "risky": [], "listed": False}
            if tail[:4] == b"koly":
                return {"type": "Mac disk image (DMG)", "entries": [], "risky": [], "listed": False}
            primary = joliet = None
            udf = False
            for k in range(16):
                fh.seek(0x8000 + 2048 * k)
                desc = fh.read(2048)
                if len(desc) < 2048:
                    break
                ident = desc[1:6]
                if ident in (b"BEA01", b"NSR02", b"NSR03"):
                    udf = True
                if ident != b"CD001":
                    continue
                if desc[0] == 1 and primary is None:
                    primary = desc
                elif desc[0] == 2 and desc[88:91] in (b"%/@", b"%/C", b"%/E"):
                    joliet = desc
                elif desc[0] == 255:
                    break
            chosen = joliet or primary
            if chosen is None:
                return {"type": "UDF disk image", "entries": [], "risky": [], "listed": False} if udf else None
            root = chosen[156:156 + 34]
            lba, rsize = struct.unpack_from("<I", root, 2)[0], struct.unpack_from("<I", root, 10)[0]
            names = _fc_iso_records(fh, lba, rsize, chosen is joliet)
    except (OSError, struct.error, IndexError):
        return None
    risky = [fc_show_name(n) for n in names if n.lower().endswith(_FC_RISKY_INSIDE)][:FC_MAX_LISTED]
    return {"type": "ISO disk image", "entries": [fc_show_name(n) for n in names[:FC_MAX_LISTED]],
            "count": len(names), "risky": risky, "listed": True}


# --- web pages ------------------------------------------------------------------------------------------------------

def fc_web_page(data: bytes) -> List[str]:
    """A saved web page or SVG picture: files built inside the browser, hidden payloads, password boxes."""
    text = data[:16 * 1024 * 1024].decode("utf-8", "replace")
    low = text.lower()
    out = []
    if "blob(" in low and ("createobjecturl" in low or "mssaveoropenblob" in low or "mssaveblob" in low) and \
            (".download" in low or "download=" in low or "mssave" in low):
        out.append("builds a file inside your browser and downloads it (HTML smuggling - a way to get a file "
                   "past email filters)")
    if re.search(r"atob\(\s*['\"`][a-z0-9+/=\s]{2000,}", low) or \
            re.search(r"data:application/(octet-stream|x-msdownload|x-msdos-program|zip|x-zip-compressed)"
                      r"[^,\"']{0,40};base64,[a-z0-9+/]{200,}", low):
        out.append("carries a whole file hidden inside the page as encoded text")
    # Bounded tag bodies ({0,2000}, never past a '<'): a page of thousands of unclosed "<input " must not make the
    # search slow down with the square of its size.
    if re.search(r"<input[^<>]{0,2000}type\s*=\s*['\"]?password", low):
        action = re.search(r"<form[^<>]{0,2000}action\s*=\s*['\"]?(https?://[^'\"\s>]{1,500})", low)
        out.append("has a password box{} - a page you open from a file should never ask you to sign in".format(
            "; what you type is sent to " + _fc_host(action.group(1)) if action else ""))
    # Only a file that IS an SVG picture: ordinary web pages carry small inline SVG icons next to their scripts.
    start = low.lstrip("﻿ \t\r\n")[:4096]
    is_svg = start.startswith("<svg") or (start.startswith("<?xml") and "<svg" in start and "<html" not in start)
    if is_svg and "<script" in low:
        out.append("is a picture (SVG) that contains a script")
    if re.search(r"eval\s*\(\s*(atob|unescape|decodeuricomponent)\s*\(", low) or \
            "document.write(unescape(" in low:
        out.append("runs scrambled script code")
    return out


def _fc_is_web_page(name: str, head: bytes) -> bool:
    if name.lower().endswith((".html", ".htm", ".shtml", ".xhtml", ".svg", ".mht", ".mhtml")):
        return True
    start = head.lstrip(b"\xef\xbb\xbf \t\r\n")[:64].lower()
    return start.startswith((b"<!doctype html", b"<html", b"<svg", b"<?xml version")) and b"<" in start


# --- OneNote --------------------------------------------------------------------------------------------------------

_FC_ONE_MAGIC = bytes.fromhex("e4525c7b8cd8a74daeb15378d02996d3")     # {7B5C52E4-D88C-4DA7-AEB1-5378D02996D3}
_FC_ONE_FILE = bytes.fromhex("e716e3bd65261145a4c48d4d0b7a9eac")      # FileDataStoreObject header GUID


def fc_onenote(data: bytes) -> Optional[Dict[str, object]]:
    """Files embedded in a OneNote notebook (.one) - in 2023 a common way to deliver malware by email."""
    if not data.startswith(_FC_ONE_MAGIC):
        return None
    embedded, risky = 0, []
    for m in re.finditer(re.escape(_FC_ONE_FILE), data):
        embedded += 1
        if embedded > 500:
            break
        body = data[m.start() + 36:m.start() + 36 + 4096]
        low = body.lower()
        if body[:2] == b"MZ":
            risky.append("a Windows program")
        elif any(s in low for s in (b"<script", b"powershell", b"@echo off", b"cmd /c", b"cmd.exe", b"wscript",
                                    b"createobject(", b"<hta:")):
            risky.append("a script")
        elif body[:4] == b"L\x00\x00\x00":
            risky.append("a shortcut")
    return {"embedded": embedded, "risky": sorted(set(risky))}


# --- the whole check ------------------------------------------------------------------------------------------------

def fc_examine(path: str, iocs=None, sign=None, lists_error: str = "") -> Dict[str, object]:
    """lists_error: why the spyware lists could not be loaded (the caller tried and failed) - the result then
    says that fingerprints and addresses were NOT compared, instead of "nothing known was found"."""
    rec = hl_examine(path, iocs, sign)
    rec.update({"name": os.path.basename(path), "inside": [], "hits": [], "addresses": {"urls": [], "hosts": [],
                "ips": []}, "packing": [], "app": None, "document": [], "script": [], "notes": [],
                "name_tricks": fc_name_tricks(os.path.basename(path)), "shortcut": None, "archive": None,
                "disk": None, "web": [], "onenote": None})
    if rec.get("error"):
        rec["level"] = FC_INCOMPLETE              # not read at all (locked, refused): not checked, not suspicious
        rec["incomplete"] = "the file could not be read, so it was not checked"
        return rec
    with open(path, "rb") as fh:
        data = fh.read(FC_READ_MAX)
    if rec.get("size", len(data)) > FC_READ_MAX:
        rec["notes"].append("Only the first {} MB were read for the checks below.".format(FC_READ_MAX // 2 ** 20))
    head = data[:4096]
    rec["entropy"] = round(_sample_entropy(data), 2)
    rec["addresses"] = fc_addresses(data)
    rec["mentions"] = []
    if iocs is not None:
        seen = set()
        if len(data) > FC_SEARCH_MAX:
            rec["notes"].append("Spyware addresses were looked for in the first {} MB.".format(FC_SEARCH_MAX // 2 ** 20))
        for ind in iocs.search_bytes(data[:FC_SEARCH_MAX].lower()):
            if ind.value not in seen and ind.type in ("domain", "ip", "ipv4", "ipv6", "url"):
                seen.add(ind.value)
                entry = {"value": ind.value, "family": ind.family or "spyware", "type": ind.type,
                         "tier": getattr(ind, "tier", "")}
                # Written inside a file is a mention, not a contact. Spyware servers mean something there; a
                # monitoring company's public website (Microsoft Family Safety is on that list), advertising
                # servers (every ad-blocker list holds thousands) or an address that may have been handed on since
                # do not - the same rule the main scan applies on a computer (report.py).
                (rec["mentions"] if entry["tier"] in FC_WEAK_TIERS else rec["inside"]).append(entry)
    kind = rec.get("kind")
    if kind == "archive" and head[:2] == b"PK":
        # An Android app renamed (invoice.zip, "document"): signed apps put META-INF first, so the manifest is not
        # in the first bytes the kind was judged from. Its contents list says what it is.
        try:
            with zip_open(path) as z:
                names = {i.filename for i in z.infolist()[:100000]}
            if "AndroidManifest.xml" in names and any(re.match(r"classes\d*\.dex$", n) for n in names):
                kind = rec["kind"] = "android-app"
            elif "[Content_Types].xml" in names and any(n.startswith(("word/", "xl/", "ppt/")) for n in names):
                # A Word / Excel / PowerPoint file under another name: checked as the document it is.
                kind = rec["kind"] = "document"
        except (zipfile.BadZipFile, OSError, RuntimeError, NotImplementedError, ValueError):
            pass
    # Many listed addresses in something that is not a program is a LIST of them - a blocklist, a research report,
    # an indicator file - made to protect people. Spyware carries a few of its own servers, not hundreds.
    # Never for something that runs: a script, a shortcut or any file Windows starts by its name. A dropper script
    # carrying ten spyware servers is not a blocklist.
    runs = kind in FC_PROGRAM_KINDS or kind == "script" or \
        os.path.splitext(rec["name"])[1].lower() in _FC_RUN_EXT + _FC_SCRIPTS
    rec["indicator_list"] = False
    # Only spyware servers count towards a list: public monitoring-company or advertising links added as padding
    # must never turn one real server into "a list".
    if not runs and len(rec["inside"]) >= FC_LIST_MIN:
        rec["indicator_list"] = True
        rec["mentions"] = rec["inside"] + rec["mentions"]
        rec["inside"] = []
    ext = os.path.splitext(rec["name"])[1].lower()
    # Disguised = a program NAMED like a document, picture, video or archive (invoice.pdf). Programs also come with
    # many ordinary extensions of their own (.pyd Python modules, .ax video filters, .node add-ons, .mui, .efi):
    # those are not disguises.
    rec["disguised"] = (kind in FC_PROGRAM_KINDS and ext in _FC_DOC_EXT)      # an Android app named .pdf too
    # Files that are not programs by their bytes, but run like one when double-clicked.
    rec["program_like"] = []
    if ext == ".hta":
        rec["program_like"].append("it is an HTML application (.hta): it opens like a web page but runs with full "
                                   "access to the computer, like a program")
    if ext in (".vbe", ".wsh", ".chm") or (ext == ".reg" and _FC_REG_SENSITIVE.search(data[:4 * 1024 * 1024]
                                                                                   .decode("utf-8", "replace"))):
        rec["program_like"].append(fc_runnable_text(ext, data))
    elif ext == ".reg":
        # A settings file that touches nothing sensitive (a game or tool tweak): named, not flagged.
        rec["notes"].append("It changes Windows settings (the registry) when opened.")
    elif ext == ".url":
        # An internet shortcut is worth a look only when it opens something that is not a web page (a local file,
        # a network share, a program); a plain web link is shown as a note, like any address.
        words = fc_runnable_text(ext, data)
        if _fc_url_runs_something(data):
            rec["program_like"].append(words + " - not a web page, but a file, a network share or a program")
        else:
            rec["notes"].append(words[:1].upper() + words[1:] + ".")
    if ext in (".com", ".pif", ".scr", ".cpl") and kind not in FC_PROGRAM_KINDS:
        rec["program_like"].append("its name ends in {} - Windows runs a file named like that as a program".format(ext))
    if ext == ".jar" or (head[:2] == b"PK" and ext not in (".apk", ".xapk", ".apks") and
                         b"META-INF/MANIFEST.MF" in data[-65536:] and b"Main-Class" in data[:4 * 1024 * 1024]):
        rec["notes"].append("It is a Java program: double-clicking it runs it, if Java is installed.")
    if kind == "windows-program":
        rec["packing"] = fc_pe_packing(data)
        rec["claims"] = fc_program_claims(rec)
    if kind in ("windows-program", "linux-program", "mac-program") and rec["entropy"] > 7.6 and not rec["packing"]:
        rec["packing"].append("the whole file is almost random (compressed or encrypted)")
    if kind == "android-app" and head[:2] == b"PK":
        app = fc_apk(path)
        rec["app"] = app
        if iocs is not None and app.get("package"):
            ind = iocs.lookup_typed("app-id", app["package"])
            if ind is not None:
                rec["inside"].append({"value": app["package"], "family": ind.family or "spyware", "type": "app-id",
                                      "tier": getattr(ind, "tier", "")})
    low_name = rec["name"].lower()
    if kind == "other" and (b"%PDF" in head[:1024] or head[:4] == b"{\\rt"):
        kind = rec["kind"] = "document"         # a PDF or RTF header a little way in still opens as one
    if kind == "other" and not _fc_is_web_page(rec["name"], head) and head[:2] != b"PK" and zipfile.is_zipfile(path):
        kind = rec["kind"] = "archive"          # a ZIP with bytes in front: 7-Zip and WinRAR open it
    if kind == "document" or b"%PDF" in head[:1024] or head[:4] == b"{\\rt":
        rec["document"] = fc_document(path, head, data)
    web_page = _fc_is_web_page(rec["name"], head)
    is_script = kind == "script" or low_name.endswith(".lnk") or ext in _FC_RUNS_AS_SCRIPT
    if (kind == "script" or (kind == "other" and not web_page)) or low_name.endswith(".lnk") or is_script:
        rec["script"] = fc_script(data, is_script=is_script)
        if len(data) > FC_SEARCH_MAX:
            rec["notes"].append("Commands written inside were looked for in the first {} MB only.".format(
                FC_SEARCH_MAX // 2 ** 20))
    if low_name.endswith(".lnk") or head[:20] == b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00" \
                                                  b"\x00\x00\x00\x46":
        rec["shortcut"] = fc_shortcut(data)
    if kind == "archive" or data[257:262] == b"ustar":
        rec["archive"] = fc_archive(path, head)
    if low_name.endswith((".iso", ".img", ".vhd", ".vhdx", ".dmg", ".udf")) or data[0x8001:0x8006] == b"CD001" \
            or head[:8] == b"vhdxfile":
        rec["disk"] = fc_disk_image(path, rec.get("size", len(data)))
    if web_page:
        rec["web"] = fc_web_page(data)
    rec["onenote"] = fc_onenote(data)
    rec["level"] = fc_level(rec)
    archive, disk = rec.get("archive") or {}, rec.get("disk") or {}
    unseen = (archive.get("problem") and not archive.get("damaged")) or \
        (disk and not disk.get("listed") and not disk.get("type", "").startswith("VHD"))
    if unseen and rec["level"] == FC_CLEAN:
        # A RAR, 7-Zip, gzip, DMG or UDF whose contents this check cannot list: not suspicious, but not checked
        # either - said plainly, never "nothing known was found".
        rec["level"] = FC_INCOMPLETE
        rec["incomplete"] = "the files inside it ({}) were not listed, so they were not checked".format(
            archive.get("type") or disk.get("type") or "a container")
    if rec["level"] == FC_CLEAN and any(d in FC_DOC_PARTIAL for d in rec.get("document") or []):
        rec["level"] = FC_INCOMPLETE
        rec["incomplete"] = "part of this document was too large to read, so not all of it was checked"
    if rec["level"] == FC_CLEAN and rec.get("size", len(data)) > FC_SEARCH_MAX:
        # Its fingerprint covers the whole file, but the addresses and commands inside were looked for in the first
        # 32 MB only: that is not "nothing known was found".
        rec["level"] = FC_INCOMPLETE
        rec["incomplete"] = ("only the first {} MB of this file were searched for spyware addresses and commands "
                             "(its fingerprint was checked in full)".format(FC_SEARCH_MAX // 2 ** 20))
    if lists_error:
        rec["lists_error"] = str(lists_error)[:200]
        rec["notes"].append("The spyware lists could not be loaded ({}), so the file's fingerprints and the "
                            "addresses inside it were NOT compared with them.".format(rec["lists_error"]))
        if rec["level"] == FC_CLEAN:
            rec["level"] = FC_INCOMPLETE
    return rec


def _app_flags(app) -> List[str]:
    if not app:
        return []
    asked = set(app.get("permissions") or []) | set(app.get("bound") or [])
    flags = []
    if asked & _FC_CONTROL and asked & _FC_WATCH:
        flags.append("asks for control of the phone together with access to messages, microphone or location - "
                     "the combination spying apps use")
    return flags


FC_WEAK_TIERS = ("stalkerware", "delivery", "reclaimable", "candiru-ip", "infrastructure-ip")
FC_PROGRAM_KINDS = ("windows-program", "mac-program", "linux-program", "android-app")
FC_LIST_MIN = 10


def fc_level(rec) -> str:
    offline = rec.get("offline") or {}
    if (offline and offline.get("tier") != "vuln-driver") or rec.get("inside"):
        return FC_KNOWN
    if offline:
        return FC_LOOK                     # a legitimate driver that attackers abuse: a lead
    # rec["mentions"] never changes the level: a mention of a website is not a finding (shown, explained).
    # Unsigned only when a check SAID so. Off Windows the signature cannot be checked (no answer): that is not
    # "unsigned", or every signed Windows program looked at from a Mac would be judged on its packing alone.
    unsigned_program = rec.get("kind") in ("windows-program", "mac-program", "linux-program") and \
        rec.get("signature") in ("not-signed", "bad-signature", "expired-signature")
    archive, disk, one = rec.get("archive") or {}, rec.get("disk") or {}, rec.get("onenote") or {}
    document = [d for d in rec.get("document") or [] if d not in FC_DOC_PARTIAL]
    if document or rec.get("script") or _app_flags(rec.get("app")) or rec.get("disguised") or \
            rec.get("program_like") or rec.get("claims") or (rec.get("app") or {}).get("problem") or \
            archive.get("damaged") or \
            (unsigned_program and rec.get("packing")) or rec.get("name_tricks") or \
            rec.get("signature") == "bad-signature" or \
            (rec.get("shortcut") or {}).get("flags") or archive.get("risky") or archive.get("encrypted") or \
            archive.get("tricks") or disk.get("risky") or disk.get("type", "").startswith(("VHD", "VHDX")) or \
            rec.get("web") or one.get("risky"):
        return FC_LOOK
    return FC_CLEAN


def _fc_stalkerware(rec) -> bool:
    """The match is a commercial phone-monitoring app (Echap's stalkerware list), not mercenary spyware."""
    offline = rec.get("offline") or {}
    if offline:
        return offline.get("tier") == "stalkerware"
    inside = rec.get("inside") or []
    return bool(inside) and all(h.get("type") == "app-id" and h.get("tier") == "stalkerware" for h in inside)


def fc_headline(rec) -> str:
    level = rec.get("level")
    if rec.get("error"):
        return T("This file could not be read")
    if level == FC_KNOWN:
        if _fc_stalkerware(rec):
            return T("This file is a phone-monitoring (stalkerware) app on the lists - do not install it")
        if any(h.get("type") == "app-id" for h in rec.get("inside") or []):
            return T("This app is on the spyware lists - do not install it")
        if rec.get("offline"):
            return T("This file matches known spyware - do not open it")
        return T("This file contains an address used by known spyware - do not open it or follow its links")
    if level == FC_INCOMPLETE:
        if rec.get("incomplete") and not rec.get("lists_error"):
            return T("Incomplete: {why}", why=TX(rec["incomplete"]))
        return T("Incomplete: the spyware lists could not be loaded, so this file was not compared with them")
    if level == FC_LOOK:
        return T("Nothing known was found, but this file does things worth an expert's look")
    return T("Nothing known was found in this file - that is not a guarantee")


from .safetext import ST_CONTROL, ST_INVISIBLE, safe_render, st_line  # noqa: E402


@safe_render
def fc_render(rec) -> str:
    def it(fragment):
        """'contains a macro' -> 'It contains a macro' (the fragment translated as a known sentence or template)."""
        return T("It {what}", what=TX(fragment))

    out = ["=" * 72, "  " + T("CHECK A SUSPICIOUS FILE") + "  -  " + fc_show_name(rec.get("name", "")),
           "  " + T("Read only: the file was not run, opened, moved or uploaded."), "=" * 72, "",
           "  " + T("RESULT: {headline}", headline=fc_headline(rec)), ""]
    if rec.get("error"):
        out.append("  " + TX(rec["error"]))
        return _fc_lines(out)
    kind_words = {"windows-program": T("a Windows program"), "mac-program": T("a Mac program"),
                  "linux-program": T("a Linux program"), "android-app": T("an Android app"),
                  "document": T("a document"), "archive": T("an archive (a file that holds other files)"),
                  "script": T("a script or shortcut"), "other": T("not a recognised program or document")}
    out.append("  " + T("WHAT IT IS"))
    out.append("    " + T("{kind}, {size} bytes", kind=kind_words.get(rec.get("kind"), rec.get("kind") or T("unknown")),
                          size="{:,}".format(rec.get("size", 0))))
    if rec.get("disguised"):
        out.append("    ! " + T("Its name ends in {ext} but it is really {kind} - a common disguise.",
                                ext=os.path.splitext(rec.get("name", ""))[1].lower(),
                                kind=kind_words.get(rec.get("kind"), T("a program"))))
    if rec.get("version_companyName") or rec.get("version_fileDescription"):
        out.append("    " + T("It describes itself as: {what}", what=st_line(" - ".join(
            x for x in (rec.get("version_fileDescription"), rec.get("version_companyName"),
                        rec.get("version_originalFilename")) if x))[:160]))
    for line in rec.get("claims") or []:
        out.append("  - " + st_line(TX(line)))
    for line in rec.get("program_like") or []:
        said = TX(line)
        out.append("    ! " + said[:1].upper() + said[1:] + ".")
    sig = rec.get("signature")
    if sig:
        words = {"signed": "signed by a developer (macOS checks it when the program opens)"
                 if rec.get("kind") == "mac-program" else "signed by a publisher Windows trusts",
                 "not-signed": "not signed", "bad-signature": "a signature that is NOT valid",
                 "ad-hoc": "signed without a developer identity (normal for tools built on a Mac, unusual for a "
                           "downloaded app)",
                 "expired-signature": "signed, but the certificate has expired",
                 "unknown": "could not be checked",
                 "missing": "could not be checked (the file could not be read)"}.get(sig)
        out.append("    " + T("Signature: {what}", what=T(words) if words else sig))
    elif rec.get("kind") == "windows-program":
        out.append("    " + T("Signature: not checked - Windows itself checks it, so this is only possible on Windows"))
    if rec.get("signer"):
        out.append("    " + T("Signed by (as written in the file): {who}", who=str(rec["signer"])[:120]))
    out += ["", "  " + T("FINGERPRINTS"), "    SHA-256  " + rec.get("sha256", ""), "    SHA-1    " + rec.get("sha1", ""),
            "    MD5      " + rec.get("md5", "")]
    if rec.get("imphash"):
        out.append("    imphash  " + rec["imphash"])
    out.append("")
    if rec.get("offline"):
        o = rec["offline"]
        if o.get("tier") == "vuln-driver":
            out += ["  " + T("A DRIVER ATTACKERS ABUSE"),
                    "    ? " + T("It is a legitimate, signed driver ({family}) that attackers are known to load to switch "
                                 "off security software. On its own it does not mean anyone did.", family=o["family"]),
                    ""]
        elif o.get("tier") == "stalkerware":
            out += ["  " + T("PHONE-MONITORING APP"),
                    "    ! " + T("It is {family} ({source}), on the stalkerware lists: an app that can be used to read "
                                 "someone's messages, location and calls. Do not install it unless you chose it "
                                 "yourself.", family=o["family"], source=o["source"]), ""]
        else:
            out += ["  " + T("KNOWN SPYWARE"),
                    "    ! " + T("The file itself is on the spyware lists: {family} ({source}).", family=o["family"],
                                 source=o["source"]), ""]
    if rec.get("inside"):
        apps = [h for h in rec["inside"] if h.get("type") == "app-id"]
        addresses = [h for h in rec["inside"] if h.get("type") != "app-id"]
        for hit in apps:
            out.append("  " + T("ON THE LISTS AS AN APP"))
            if hit.get("tier") == "stalkerware":
                out.append("    ! " + T("Its package name {package} is {family}, on the stalkerware lists: an app that "
                                        "can be used to read someone's messages, location and calls. Do not install it "
                                        "unless you chose it yourself.", package=hit["value"], family=hit["family"]))
            else:
                out.append("    ! " + T("Its package name {package} is on the spyware lists: {family}.",
                                        package=hit["value"], family=hit["family"]))
            out.append("")
        if addresses:
            out.append("  " + T("SPYWARE ADDRESSES INSIDE"))
            for hit in addresses[:FC_MAX_LISTED]:
                out.append("    ! {}  -  {}".format(hit["value"], hit["family"]))
            if len(addresses) >= FC_LIST_MIN:
                out += ["    " + T("Security programs sometimes carry lists of spyware addresses so that they can "
                                   "block them."),
                        "    " + T("If this is your antivirus or another security tool, that would explain it.")]
            out.append("")
    if rec.get("indicator_list"):
        out += ["  " + T("A LIST OF SPYWARE ADDRESSES (not a finding)"),
                "    " + T("This file holds {n} addresses from the spyware lists. That is what a blocklist, a research",
                           n=len(rec["mentions"])),
                "    " + T("report or an indicator file looks like - such lists are made to protect people. Spyware"),
                "    " + T("itself carries a few of its own servers, not a whole list. Do not visit the addresses."), ""]
    elif rec.get("mentions"):
        out.append("  " + T("LISTED ADDRESSES MENTIONED INSIDE (not a finding)"))
        for hit in rec["mentions"][:FC_MAX_LISTED]:
            out.append("    ? {}  -  {}".format(hit["value"], hit["family"]))
        out += ["    " + T("Usually harmless: these are the public websites of phone-monitoring companies (Microsoft"),
                "    " + T("Family Safety among them), advertising servers, or addresses that may belong to someone else"),
                "    " + T("by now. Ad-blocker lists, browser files and web pages often contain them. A file that only"),
                "    " + T("mentions one is not spyware."), ""]
    app = rec.get("app")
    if app:
        out.append("  " + T("ANDROID APP"))
        out.append("    " + T("Package name: {package}", package=app.get("package") or T("(not readable)")))
        asked = [p for p in (app.get("permissions") or []) + (app.get("bound") or []) if p in FC_PERMISSIONS]
        if asked:
            out.append("    " + T("It asks to:"))
            out += ["      - " + T(FC_PERMISSIONS[p]) for p in dict.fromkeys(asked)]
        for flag in _app_flags(app):
            out.append("    ! " + it(flag) + ".")
        if app.get("problem"):
            out.append("    (" + TX(app["problem"]) + ")")
        out.append("")
    if rec.get("name_tricks"):
        out.append("  " + T("ITS NAME"))
        for t in rec["name_tricks"]:
            said = TX(t)
            out.append("    ! " + said[:1].upper() + said[1:])
        out.append("")
    shortcut = rec.get("shortcut")
    if shortcut:
        out.append("  " + T("SHORTCUT"))
        out.append("    " + T("It starts: {what}", what=shortcut.get("starts") or T("(not stored in a readable form)")))
        out += ["    ? " + it(f) + "." for f in shortcut.get("flags") or []]
        out.append("")
    archive = rec.get("archive")
    if archive and archive.get("type"):
        if archive.get("count"):
            out.append("  " + T("WHAT IS INSIDE ({type} archive, {n} files)", type=archive["type"], n=archive["count"]))
        else:
            out.append("  " + T("WHAT IS INSIDE ({type} archive)", type=archive["type"]))
        if archive.get("encrypted"):
            out.append("    ? " + T("It is locked with a password, so antivirus could not look inside - a common way "
                                    "to get malware past email filters (the password is usually written in the "
                                    "message)."))
        if archive.get("names_locked"):
            out.append("    ? " + T("Even the names of the files inside are hidden behind the password, so this check "
                                    "could not see what it holds."))
        if archive.get("risky"):
            out.append("    ? " + T("It holds programs, scripts, shortcuts or disk images:"))
            out += ["      - " + n for n in archive["risky"]]
        if archive.get("nested"):
            out.append("    " + T("It holds other archives or disk images (not opened): {names}",
                                  names=", ".join(archive["nested"])))
        out += ["    ? " + TX(t) for t in archive.get("tricks") or []]
        if archive.get("entries") and not archive.get("risky"):
            out.append("    " + T("Files: {names}", names=", ".join(archive["entries"][:12]) +
                                  (" ..." if len(archive["entries"]) > 12 else "")))
        if archive.get("problem"):
            out.append("    (" + TX(archive["problem"]) + ")")
        out.append("")
    disk = rec.get("disk")
    if disk:
        out.append("  " + T("DISK IMAGE ({type})", type=disk["type"]))
        out.append("    " + T("Opening it attaches it like a drive, and files inside lose Windows' 'downloaded from the "
                              "internet' warning - which is why attackers send programs this way."))
        if disk.get("risky"):
            out.append("    ? " + T("It holds programs, scripts or shortcuts:"))
            out += ["      - " + n for n in disk["risky"]]
        elif disk.get("entries"):
            out.append("    " + T("Files at the top: {names}", names=", ".join(disk["entries"][:12])))
        elif not disk.get("listed"):
            out.append("    " + T("(its contents are not listed by this check)"))
        out.append("")
    if rec.get("web"):
        out.append("  " + T("WEB PAGE"))
        out += ["    ? " + it(w) + "." for w in rec["web"]]
        out.append("")
    one = rec.get("onenote")
    if one and one.get("embedded"):
        out.append("  " + T("ONENOTE NOTEBOOK"))
        out.append("    " + T("It carries {n} embedded file(s).", n=one["embedded"]))
        if one.get("risky"):
            out.append("    ? " + T("Among them: {names} - OneNote files like this were a common way to deliver malware "
                                    "by email.", names=", ".join(one["risky"])))
        out.append("")
    for title, items in ((T("DOCUMENT"), rec.get("document")), (T("SCRIPT OR SHORTCUT"), rec.get("script")),
                         (T("PACKED OR SCRAMBLED"), rec.get("packing"))):
        if items:
            out.append("  " + title)
            out += ["    ? " + it(i) if not i.startswith(("packed", "section", "the whole")) else "    ? " + TX(i)
                    for i in items]
            out.append("")
    addr = rec.get("addresses") or {}
    if addr.get("hosts") or addr.get("ips"):
        out.append("  " + T("ADDRESSES WRITTEN INSIDE (not contacted; most are harmless)"))
        for h in (addr.get("hosts") or [])[:FC_MAX_LISTED]:
            out.append("    " + h)
        for ip in (addr.get("ips") or [])[:FC_MAX_LISTED]:
            out.append("    " + ip)
        more = len(addr.get("hosts") or []) + len(addr.get("ips") or []) - 2 * FC_MAX_LISTED
        if more > 0:
            out.append("    " + T("... and {n} more", n=more))
        out.append("")
    out += ["  " + TX(n) for n in rec.get("notes") or []]
    out += ["  " + T("WHAT TO DO"),
            "    - " + T("Do not open or run it. Do not delete it either: where it was found is evidence."),
            "    - " + T("Make a sealed copy (password: infected) and send it to an expert or to us on Telegram."),
            "    - " + T("Its fingerprint can also be looked up online, only if you choose to: the"),
            "      " + T("\"Also look it up online...\" button below, or --hash-lookup FILE in the terminal.")]
    return _fc_lines(out)


def _fc_lines(lines) -> str:
    """Join the report's lines, showing any control or invisible character as <U+XXXX>. Every line is one line:
    a name inside an archive, a signer or a stored command can carry line breaks or terminal escape codes, which
    could otherwise add a fake line (a false RESULT) to the report or rewrite what the terminal shows."""
    import unicodedata
    return "\n".join("".join("<U+{:04X}>".format(ord(c)) if unicodedata.category(c)[0] == "C" else c
                             for c in str(line)) for line in lines)


# --- the sealed copy -----------------------------------------------------------------------------------------------

def _crc_table():
    table = []
    for i in range(256):
        c = i
        for _ in range(8):
            c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
        table.append(c)
    return table


_CRC = _crc_table()


class _ZipCrypto:
    """The traditional PKWARE ZIP encryption. Weak by modern standards, and used here on purpose: every unzip tool,
    Windows included, opens it with the password, and its job is only to stop the copy running or being removed by
    an antivirus on its way to an expert - not to keep a secret."""

    def __init__(self, password: bytes):
        self.k = [0x12345678, 0x23456789, 0x34567890]
        for b in password:
            self._update(b)

    def _update(self, b):
        k = self.k
        k[0] = (k[0] >> 8) ^ _CRC[(k[0] ^ b) & 0xFF]
        k[1] = ((k[1] + (k[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        k[2] = (k[2] >> 8) ^ _CRC[(k[2] ^ (k[1] >> 24)) & 0xFF]

    def encrypt(self, data: bytes) -> bytes:
        out = bytearray(len(data))
        for i, b in enumerate(data):
            t = (self.k[2] | 2) & 0xFFFF
            out[i] = b ^ (((t * (t ^ 1)) >> 8) & 0xFF)
            self._update(b)
        return bytes(out)


def _dos_time(ts):
    t = time.localtime(ts)
    return ((t.tm_hour << 11) | (t.tm_min << 5) | (t.tm_sec // 2),
            ((max(t.tm_year, 1980) - 1980) << 9) | (t.tm_mon << 5) | t.tm_mday)


def fc_seal(path: str, out_path: str, rand=os.urandom) -> Dict[str, object]:
    """Write a ZIP at out_path (never replacing a file) holding the sample, encrypted with the password "infected",
    plus a plain README. The original file is only read."""
    size = os.path.getsize(path)
    if size > FC_SEAL_MAX:
        raise ValueError("the file is larger than {} MB".format(FC_SEAL_MAX // 2 ** 20))
    crc, sha = 0, hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1024 * 1024), b""):
            crc = binascii.crc32(block, crc)
            sha.update(block)
    crc &= 0xFFFFFFFF
    name = re.sub(r"[\x00-\x1f\\/:*?\"<>|]", "_", os.path.basename(path)) or "sample"
    readme = ("This ZIP holds a POSSIBLE MALWARE SAMPLE, sealed by Zero Breach Toolkit.\r\n"
              "Password: infected\r\n"
              "File: {}\r\nSize: {} bytes\r\nSHA-256: {}\r\n\r\n"
              "Do not open or run it. Send it to an expert, who will analyse it on a machine kept for that.\r\n"
              ).format(name, size, sha.hexdigest()).encode("utf-8")
    mtime, mdate = _dos_time(os.path.getmtime(path))
    central = []
    out = open(out_path, "xb")                  # "x": never replaces a file; only a file made here is removed
    try:
        with out:
            # 1. the sample, deflated then encrypted
            offset = out.tell()
            fname = name.encode("utf-8")
            local = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0x0801, 8, mtime, mdate, crc, 0, size, len(fname), 0)
            out.write(local + fname)
            enc = _ZipCrypto(FC_PASSWORD)
            header = bytearray(rand(11)) + bytes([crc >> 24])
            written = len(header)
            out.write(enc.encrypt(bytes(header)))
            comp = zlib.compressobj(6, zlib.DEFLATED, -15)
            with open(path, "rb") as fh:
                for block in iter(lambda: fh.read(1024 * 1024), b""):
                    chunk = enc.encrypt(comp.compress(block))
                    written += len(chunk)
                    out.write(chunk)
            tail = enc.encrypt(comp.flush())
            written += len(tail)
            out.write(tail)
            end = out.tell()
            out.seek(offset + 18)
            out.write(struct.pack("<I", written))
            out.seek(end)
            central.append((fname, 0x0801, 8, crc, written, size, offset, mtime, mdate))
            # 2. a plain README next to it
            offset = out.tell()
            rname = b"README - password is infected.txt"
            rcrc = binascii.crc32(readme) & 0xFFFFFFFF
            out.write(struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 0x0800, 0, mtime, mdate, rcrc, len(readme),
                                  len(readme), len(rname), 0) + rname + readme)
            central.append((rname, 0x0800, 0, rcrc, len(readme), len(readme), offset, mtime, mdate))
            cd_start = out.tell()
            for fn, flags, method, c, csize, usize, off, mt, md in central:
                out.write(struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, flags, method, mt, md, c, csize, usize,
                                      len(fn), 0, 0, 0, 0, 0, off) + fn)
            cd_size = out.tell() - cd_start
            out.write(struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(central), len(central), cd_size, cd_start, 0))
    except BaseException:
        try:
            os.remove(out_path)                # a half-written sealed copy is worse than none
        except OSError:
            pass
        raise
    return {"path": out_path, "sha256": sha.hexdigest(), "size": size, "password": FC_PASSWORD.decode()}


# --- terminal ------------------------------------------------------------------------------------------------------

def fc_sealed_name(path: str) -> str:
    """The sealed copy's file name: the sample's name without control or direction-changing characters, so the
    copy itself cannot display as something else ("report<U+202E>fdp.exe" would read as "...exe.pdf")."""
    import unicodedata
    base = "".join(c for c in os.path.basename(path) if unicodedata.category(c)[0] != "C") or "sample"
    return "{}-sealed.zip".format(base)


def fc_command(args, load_iocs, out=print) -> int:
    import json
    path = args.check_file
    checked = [("--check-file", path), ("--json", getattr(args, "json", None)),
               ("--seal-copy", getattr(args, "seal_copy", None))]
    checked += [("--iocs", value) for value in (getattr(args, "iocs", None) or [])]
    for label, value in checked:
        problem = path_problem(os.path.abspath(value)) if value else ""
        if problem:
            # A network path would send this computer's credentials and the file's details elsewhere.
            out(T("{option} {path}: {problem} - use a file on this computer", option=label, path=st_line(value),
                  problem=TX(st_line(problem))))
            return 2
    if not os.path.isfile(path):
        out(T("Not a file: {path}", path=st_line(path)))
        return 2
    try:
        iocs, lists_error = load_iocs(args), ""
    except Exception as exc:  # noqa: BLE001 - checked without the lists, and the result says so
        iocs, lists_error = None, "{}: {}".format(type(exc).__name__, exc)
    rec = fc_examine(path, iocs, lists_error=lists_error)
    out(fc_render(rec))
    if getattr(args, "json", None):
        # --json PATH writes the record to PATH (never replacing a file), as --hash-lookup does. Control and
        # direction-changing characters from the file (archive names, signers) are written as \uXXXX escapes, so
        # the JSON stays valid and cannot rearrange what a terminal or editor shows.
        text = json.dumps({k: v for k, v in rec.items() if k != "path"}, indent=2, ensure_ascii=False, default=str)
        text = ST_CONTROL.sub(lambda m: "\\u{:04x}".format(ord(m.group(0))), ST_INVISIBLE.sub(
            lambda m: "\\u{:04x}".format(ord(m.group(0))), text))
        try:
            with open(args.json, "x", encoding="utf-8") as fh:
                fh.write(text)
        except OSError as exc:
            out(T("The JSON was not saved: {why}", why=exc))
            return 1
        out("\n" + T("Saved: {path}", path=args.json))
    if getattr(args, "seal_copy", None):
        target = args.seal_copy
        if os.path.isdir(target):
            target = os.path.join(target, fc_sealed_name(path))
        try:
            sealed = fc_seal(path, target)
        except (OSError, ValueError) as exc:
            out(T("The sealed copy was not made: {why}", why=TX(st_line(exc))))
            return 1
        out("\n" + T("Sealed copy saved: {path} (password: infected). The original was not touched.",
                     path=st_line(sealed["path"])))
    return {FC_KNOWN: 3, FC_LOOK: 1, FC_INCOMPLETE: 1}.get(rec.get("level"), 0)       # same exit codes as --hash-lookup
