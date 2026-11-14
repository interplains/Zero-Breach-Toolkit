"""Hash look-up (--hash-lookup PATH): fingerprint files and ask who knows them - offline first, online only if asked.

Per file: SHA-256, SHA-1 and MD5 in one pass, what kind of file it is (from its first bytes, not its name), and for
Windows programs the import hash (imphash, which stays the same across many re-packed variants of one malware) and
the name of whoever signed it (read from the embedded Authenticode certificate; on Windows the signature is also
checked offline).

OFFLINE (always): every fingerprint is compared with the spyware indicator lists the scan uses.

ONLINE (only with --online, or after saying yes in the menu or window): only the FINGERPRINTS are sent - never a
file, its name or its path - and by default only for files that are not validly signed and are programs, scripts,
documents or archives. Services, each chosen separately:
  circl           CIRCL hashlookup (Luxembourg; no key): files known to be ordinary software (NSRL, OS packages)
  malwarebazaar   MalwareBazaar by abuse.ch (Switzerland; free key): known malware samples, family, first seen
  threatfox       ThreatFox by abuse.ch (Switzerland; same key): fingerprints linked to malware campaigns
  virustotal      VirusTotal (Google, USA; your own free key): how many antivirus engines flag it
  hybrid          Hybrid Analysis (CrowdStrike, USA; your own free key): sandbox verdict and family
Answers are cached on this computer, so the same file is not asked about twice. "Unknown" means nobody has reported
the file either way: it is not the same as safe.
"""
from __future__ import annotations

import hashlib
import json
import os
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Dict, List, Optional, Tuple

from .i18n import T, TX
from .localpaths import path_problem, tls_context, walk_local
from .orddata import ORD_NAMES

HL_KNOWN, HL_LOOK, HL_NOTHING = "known-threat", "worth-a-look", "nothing-known"
HL_MAX_FILES = 20_000
HL_MAX_ONLINE = 500
HL_VT_FREE_LIMIT = 20
HL_TIMEOUT = 25

HL_SERVICES = {
    "circl": ("CIRCL hashlookup", "Luxembourg", None),
    "malwarebazaar": ("MalwareBazaar (abuse.ch)", "Switzerland", "abusech"),
    "threatfox": ("ThreatFox (abuse.ch)", "Switzerland", "abusech"),
    "virustotal": ("VirusTotal (Google)", "USA", "virustotal"),
    "hybrid": ("Hybrid Analysis (CrowdStrike)", "USA", "hybrid"),
}
HL_KEY_ENV = {"abusech": "ZB_ABUSECH_KEY", "virustotal": "ZB_VIRUSTOTAL_KEY", "hybrid": "ZB_HYBRID_KEY"}
HL_KEY_WHERE = {"abusech": "https://auth.abuse.ch/ (free; one key for MalwareBazaar and ThreatFox)",
                "virustotal": "https://www.virustotal.com/gui/join-us (free account, then API key)",
                "hybrid": "https://www.hybrid-analysis.com/signup (free account, then API key)"}
_HL_HOSTS = ("hashlookup.circl.lu", "mb-api.abuse.ch", "threatfox-api.abuse.ch", "www.virustotal.com",
             "hybrid-analysis.com")
_HL_INTERESTING = ("windows-program", "mac-program", "linux-program", "android-app", "script", "document", "archive")


class HlError(ValueError):
    pass


# --- fingerprints and file kind ------------------------------------------------------------------------------------

def hl_hashes(path: str) -> Dict[str, object]:
    md5, sha1, sha256 = hashlib.md5(), hashlib.sha1(), hashlib.sha256()  # noqa: S324 - matching published lists
    size, head = 0, b""
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            if not head:
                head = block[:4096]
            md5.update(block)
            sha1.update(block)
            sha256.update(block)
            size += len(block)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest(), "size": size,
            "kind": hl_kind(head, path)}


def hl_kind(head: bytes, name: str = "") -> str:
    low = name.lower()
    if head[:2] == b"MZ":
        return "windows-program"
    if head[:4] == b"\x7fELF":
        return "linux-program"
    if head[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xfe\xed\xfa\xcf"):
        return "mac-program"
    if head[:4] == b"dex\n":
        return "android-app"
    if head[:2] == b"PK":
        if low.endswith((".apk", ".xapk", ".apks")) or b"AndroidManifest.xml" in head or b"classes.dex" in head:
            return "android-app"
        if low.endswith((".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm")):
            return "document"
        return "archive"
    if head[:4] == b"%PDF" or head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" or head[:5] == b"{\\rtf":
        return "document"
    if head[:4] in (b"Rar!", b"7z\xbc\xaf") or head[:2] == b"\x1f\x8b":
        return "archive"
    if head[:2] == b"#!" or low.endswith((".ps1", ".vbs", ".js", ".jse", ".bat", ".cmd", ".hta", ".wsf", ".sh",
                                          ".py", ".lnk", ".scr", ".msi", ".iso", ".img", ".dmg", ".pkg")):
        return "script" if not low.endswith((".iso", ".img", ".dmg", ".pkg", ".msi")) else "archive"
    return "other"


# --- Windows programs: imphash and signer --------------------------------------------------------------------------

def hl_pe(data: bytes) -> Dict[str, object]:
    """imphash, compile time and the embedded signature's signer, from a PE file's bytes. {} if not a PE.
    The imphash is computed as pefile does (ordinal names for ws2_32, wsock32 and oleaut32 from its tables)."""
    try:
        if data[:2] != b"MZ":
            return {}
        lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[lfanew:lfanew + 4] != b"PE\x00\x00":
            return {}
        coff = lfanew + 4
        _machine, nsec, stamp, _sym, _nsym, opt_size, _ch = struct.unpack_from("<HHIIIHH", data, coff)
        opt = coff + 20
        magic = struct.unpack_from("<H", data, opt)[0]
        pe64 = magic == 0x20B
        dirs = opt + (112 if pe64 else 96)
        ndirs = struct.unpack_from("<I", data, dirs - 4)[0]
        sections = []
        sec = opt + opt_size
        for i in range(min(nsec, 96)):
            _name, vsize, va, rsize, raw = struct.unpack_from("<8sIIII", data, sec + 40 * i)
            sections.append((va, max(vsize, rsize), raw))

        def off(rva):
            for va, size, raw in sections:
                if va <= rva < va + size:
                    return rva - va + raw
            return rva if rva < len(data) else None

        def cstr(pos, limit=256):
            if pos is None:
                return ""
            end = data.find(b"\x00", pos, pos + limit)
            return data[pos:end if end >= 0 else pos + limit].decode("latin-1")
        # Reproducible builds (most of Windows) put a hash, not a date, here: show only plausible dates.
        plausible = 820454400 <= stamp <= time.time() + 86400 * 366
        out = {"compiled_utc": time.strftime("%Y-%m-%d", time.gmtime(stamp)) if plausible else ""}
        if ndirs > 1:
            imp_rva, imp_size = struct.unpack_from("<II", data, dirs + 8)
            out["imphash"] = _hl_imphash(data, imp_rva, off, cstr, pe64) if imp_rva else ""
        if ndirs > 2:
            res_rva, res_size = struct.unpack_from("<II", data, dirs + 16)
            if res_rva and res_size:
                out.update(hl_version_info(data, off(res_rva), off))
        if ndirs > 4:
            sig_off, sig_size = struct.unpack_from("<II", data, dirs + 32)
            if sig_off and sig_size and sig_off + 8 <= len(data):
                _len, _rev, ctype = struct.unpack_from("<IHH", data, sig_off)
                if ctype == 2:
                    out.update(hl_signer(data[sig_off + 8:sig_off + sig_size]))
        return out
    except (struct.error, IndexError, ValueError):
        return {}


HL_VERSION_KEYS = ("CompanyName", "FileDescription", "ProductName", "OriginalFilename", "InternalName")


def hl_version_info(data: bytes, root, off) -> Dict[str, str]:
    """What the program says about itself (company, description, product, original file name), from the version
    resource (resource type 16). Read with fixed bounds; a damaged resource just gives nothing."""
    if root is None or root + 16 > len(data):
        return {}

    def entries(pos):
        named, ids = struct.unpack_from("<HH", data, pos + 12)
        for i in range(min(named + ids, 64)):
            yield struct.unpack_from("<II", data, pos + 16 + 8 * i)

    blob = b""
    for ident, target in entries(root):
        if ident != 16 or not target & 0x80000000:
            continue
        level = root + (target & 0x7FFFFFFF)
        for _name, t2 in entries(level):
            pos = root + (t2 & 0x7FFFFFFF)
            for _ in range(3):                      # language directory, then the data entry
                if t2 & 0x80000000:
                    _lang, t2 = next(entries(pos), (0, 0))
                    pos = root + (t2 & 0x7FFFFFFF)
                else:
                    break
            rva, size = struct.unpack_from("<II", data, pos)
            start = off(rva)
            if start is not None and 0 < size <= 1024 * 1024:
                blob = data[start:start + size]
            break
        break
    out = {}
    for key in HL_VERSION_KEYS:
        needle = (key + "\x00").encode("utf-16-le")
        at = blob.find(needle)
        if at < 6:
            continue
        value_words = struct.unpack_from("<H", blob, at - 4)[0]
        start = (at + len(needle) + 3) & ~3
        value = blob[start:start + 2 * min(value_words, 512)].decode("utf-16-le", "replace").split("\x00", 1)[0]
        value = "".join(c for c in value if c.isprintable()).strip()
        if value:
            out["version_" + key[0].lower() + key[1:]] = value[:200]
    return out


# Imports read in total: ordinary programs have a few thousand; a crafted one can point 4,096 libraries at one
# list of 65,536 entries (268 million strings, gigabytes of memory). Past this, the value is simply not pefile's.
_HL_MAX_IMPORTS = 20000
_HL_FUNC_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._?@$()<>")


def _hl_imphash(data, rva, off, cstr, pe64):
    """MD5 of 'library.function' pairs as pefile computes it: names cut at 512 bytes, names with other characters
    written *invalid*, ordinals named from pefile's tables. (pefile stops after about 4,096 imports in very large
    programs; this does not, so those few programs get a different value.)"""
    pos = off(rva)
    parts = []
    for _ in range(4096):
        if pos is None or pos + 20 > len(data):
            break
        oft, _ts, _fw, name_rva, ft = struct.unpack_from("<IIIII", data, pos)
        if not (oft or name_rva or ft):
            break
        lib = cstr(off(name_rva)).lower()
        names = ORD_NAMES.get(lib[:-4]) if lib in ("ws2_32.dll", "wsock32.dll", "oleaut32.dll") else None
        stem, dot, ext = lib.rpartition(".")
        if dot and ext in ("ocx", "sys", "dll"):
            lib = stem
        thunk = off(oft or ft)
        size, flag = (8, 1 << 63) if pe64 else (4, 1 << 31)
        for _ in range(65536):
            if thunk is None or thunk + size > len(data) or len(parts) >= _HL_MAX_IMPORTS:
                break
            value = struct.unpack_from("<Q" if pe64 else "<I", data, thunk)[0]
            if not value:
                break
            if value & flag:
                func = ((names or {}).get(value & 0xFFFF) or "ord{}".format(value & 0xFFFF)).lower()
            else:
                func = cstr(off((value & 0x7FFFFFFF) + 2), 0x200)
                func = func.lower() if func and all(c in _HL_FUNC_CHARS for c in func) else "*invalid*"
            if func:
                parts.append("{}.{}".format(lib, func))
            thunk += size
        pos += 20
    return hashlib.md5(",".join(parts).encode("latin-1")).hexdigest() if parts else ""  # noqa: S324


def _hl_der(data, pos):
    """(tag, content start, content end) of the DER element at pos."""
    tag = data[pos]
    length = data[pos + 1]
    start = pos + 2
    if length & 0x80:
        n = length & 0x7F
        if n == 0 or n > 4:
            raise ValueError("unsupported DER length")
        length = int.from_bytes(data[start:start + n], "big")
        start += n
    end = start + length
    if end > len(data):
        raise ValueError("DER runs past the data")
    return tag, start, end


def _hl_children(data, start, end):
    out, pos = [], start
    while pos < end:
        tag, s, e = _hl_der(data, pos)
        out.append((tag, s, e))
        pos = e
    return out


_HL_OID = {b"\x55\x04\x03": "CN", b"\x55\x04\x0a": "O"}


def _hl_name(data, s, e):
    found = {}
    for _t, ss, se in _hl_children(data, s, e):              # SET
        for _t2, as_, ae in _hl_children(data, ss, se):      # AttributeTypeAndValue
            kids = _hl_children(data, as_, ae)
            if len(kids) == 2 and kids[0][0] == 0x06:
                key = _HL_OID.get(data[kids[0][1]:kids[0][2]])
                if key and key not in found:
                    found[key] = data[kids[1][1]:kids[1][2]].decode("utf-8", "replace")
    return found


def hl_macho(data: bytes) -> Dict[str, object]:
    """How a Mac program (Mach-O, thin or universal) is signed, read from the file: "signed" with the signer and
    Team ID, "ad-hoc" (a signature with no developer identity - normal for tools built on the Mac itself), or
    "not-signed". {} when the file is not a Mach-O program or its signature cannot be read. This does not check
    that the signature is valid - macOS does that when the program is opened."""
    try:
        if data[:4] in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf"):
            wide = data[3] == 0xBF
            count = struct.unpack_from(">I", data, 4)[0]
            if not 0 < count <= 16:                       # a Java class file starts with the same four bytes
                return {}
            entry = 8
            cpu, _sub, offset = struct.unpack_from(">IIQ" if wide else ">III", data, entry)[:3]
            return _hl_macho_slice(data, offset)
        return _hl_macho_slice(data, 0)
    except (struct.error, IndexError, ValueError):
        return {}


def _hl_macho_slice(data: bytes, base: int) -> Dict[str, object]:
    magic = data[base:base + 4]
    if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        end = "<"
    elif magic in (b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce"):
        end = ">"
    else:
        return {}
    wide = magic in (b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf")
    ncmds, sizeofcmds = struct.unpack_from(end + "II", data, base + 16)
    pos, stop = base + (32 if wide else 28), base + (32 if wide else 28) + min(sizeofcmds, 16 * 1024 * 1024)
    for _ in range(min(ncmds, 4096)):
        if pos + 8 > stop:
            break
        cmd, size = struct.unpack_from(end + "II", data, pos)
        if cmd == 0x1D:                                   # LC_CODE_SIGNATURE
            dataoff, datasize = struct.unpack_from(end + "II", data, pos + 8)
            return _hl_code_signature(data[base + dataoff:base + dataoff + min(datasize, 8 * 1024 * 1024)])
        if size < 8:
            break
        pos += size
    return {"signature": "not-signed"}


def _hl_code_signature(blob: bytes) -> Dict[str, object]:
    """The embedded signature's SuperBlob (big-endian): the CodeDirectory (identifier, Team ID, ad-hoc flag) and
    the CMS signature, whose signing certificate names the developer."""
    if blob[:4] != b"\xfa\xde\x0c\xc0":
        return {}
    count = struct.unpack_from(">I", blob, 8)[0]
    out, cms = {}, b""
    for i in range(min(count, 64)):
        _kind, offset = struct.unpack_from(">II", blob, 12 + 8 * i)
        magic, length = struct.unpack_from(">II", blob, offset)
        part = blob[offset:offset + length]
        if magic == 0xFADE0C02 and "identifier" not in out:     # CodeDirectory
            version, flags = struct.unpack_from(">II", part, 8)
            ident_off = struct.unpack_from(">I", part, 20)[0]
            end = part.find(b"\x00", ident_off)
            out["identifier"] = part[ident_off:end].decode("utf-8", "replace")[:120] if end > ident_off else ""
            if version >= 0x20200 and len(part) >= 52:
                team_off = struct.unpack_from(">I", part, 48)[0]
                end = part.find(b"\x00", team_off)
                if team_off and end > team_off:
                    out["team_id"] = part[team_off:end].decode("ascii", "replace")[:20]
            out["adhoc"] = bool(flags & 0x2)
        elif magic == 0xFADE0B01:                         # the CMS signature, wrapped
            cms = part[8:]
    signer = hl_signer(cms) if len(cms) > 16 else {}
    result = {"signature": "signed" if signer else "ad-hoc"}
    result.update(signer)
    for key in ("identifier", "team_id"):
        if out.get(key):
            result["mac_" + key] = out[key]
    return result


def hl_signer(pkcs7: bytes) -> Dict[str, str]:
    """{'signer': subject CN/O, 'signer_issuer': issuer CN} of the certificate that signed a PKCS#7 SignedData.
    Read only - this does not decide whether the signature is valid."""
    try:
        _t, s, e = _hl_der(pkcs7, 0)                                      # ContentInfo
        kids = _hl_children(pkcs7, s, e)
        _t, s, e = kids[1]                                                # [0] EXPLICIT
        _t, s, e = _hl_der(pkcs7, s)                                      # SignedData
        parts = _hl_children(pkcs7, s, e)
        certs = [p for p in parts if p[0] == 0xA0]
        signer_infos = [p for p in parts if p[0] == 0x31][-1]
        first_signer = _hl_children(pkcs7, signer_infos[1], signer_infos[2])[0]
        issuer_serial = _hl_children(pkcs7, first_signer[1], first_signer[2])[1]
        id_parts = _hl_children(pkcs7, issuer_serial[1], issuer_serial[2])
        want_issuer = pkcs7[slice(*id_parts[0][1:])]
        want_serial = pkcs7[slice(*id_parts[1][1:])]
        best = None
        for _t, cs, ce in (_hl_children(pkcs7, certs[0][1], certs[0][2]) if certs else []):
            tbs = _hl_children(pkcs7, cs, ce)[0]
            fields = _hl_children(pkcs7, tbs[1], tbs[2])
            if fields and fields[0][0] == 0xA0:
                fields = fields[1:]
            serial = pkcs7[fields[0][1]:fields[0][2]]
            issuer, subject = _hl_name(pkcs7, *fields[2][1:]), _hl_name(pkcs7, *fields[4][1:])
            # Issuer AND serial, as the signature names its certificate: the certificate list is outside what is
            # signed, so an extra certificate with the same serial and a made-up "Microsoft" subject must not win.
            if serial == want_serial and pkcs7[fields[2][1]:fields[2][2]] == want_issuer:
                best = (subject, issuer)
                break
        if not best:
            return {}
        subject, issuer = best
        name = subject.get("CN") or subject.get("O") or ""
        if subject.get("O") and subject.get("O") != name:
            name += " ({})".format(subject["O"])
        return {"signer": name[:200], "signer_issuer": issuer.get("CN", "")[:200]}
    except (ValueError, IndexError, TypeError):
        return {}


# --- collecting files ----------------------------------------------------------------------------------------------

def hl_collect(paths) -> Tuple[List[str], List[str]]:
    files, skipped = [], []
    for path in paths:
        path = os.path.abspath(path)
        problem = path_problem(path)
        if problem:
            skipped.append("{}: {}".format(path, problem))
        elif os.path.isfile(path):
            files.append(path)
        elif os.path.isdir(path):
            for folder, _dirs, names in walk_local(path, onerror=lambda exc: None):
                for name in names:
                    full = os.path.join(folder, name)
                    if not os.path.islink(full):
                        files.append(full)
                    if len(files) >= HL_MAX_FILES:
                        skipped.append("stopped at {:,} files; check a smaller folder".format(HL_MAX_FILES))
                        return files, skipped
        else:
            skipped.append("{}: not found".format(path))
    return files, skipped


def hl_examine(path: str, iocs=None, sign=None) -> Dict[str, object]:
    rec = {"path": path}
    try:
        rec.update(hl_hashes(path))
    except OSError as exc:
        rec["error"] = "could not be read ({})".format(exc.__class__.__name__)
        return rec
    if rec["kind"] == "windows-program":
        try:
            with open(path, "rb") as fh:
                data = fh.read(256 * 1024 * 1024)
            rec.update(hl_pe(data))
        except OSError:
            pass
        if sign is None and sys.platform == "win32":
            from .winsign import ws_status
            sign = ws_status
        if sign:
            rec["signature"] = sign(path)
    elif rec["kind"] == "mac-program":
        try:
            with open(path, "rb") as fh:
                rec.update(hl_macho(fh.read(256 * 1024 * 1024)))
        except OSError:
            pass
    rec["offline"] = None
    if iocs is not None:
        for key in ("sha256", "sha1", "md5"):
            ind = iocs.lookup(rec[key])
            if ind is not None and ind.type in ("sha256", "sha1", "md5"):
                rec["offline"] = {"family": ind.family or "spyware", "source": ind.source, "value": ind.value,
                                  "tier": getattr(ind, "tier", "")}
                break
    return rec


# --- keys and cache ------------------------------------------------------------------------------------------------

def _hl_config(config_dir=None):
    from .helperpack import hp_config_dir
    return config_dir or hp_config_dir()


def hl_keys(config_dir=None) -> Dict[str, str]:
    keys = {}
    try:
        with open(os.path.join(_hl_config(config_dir), "lookup-keys.json"), encoding="utf-8") as fh:
            keys = {k: str(v) for k, v in json.load(fh).items() if k in HL_KEY_ENV and v}
    except (OSError, ValueError, AttributeError):
        pass
    for name, env in HL_KEY_ENV.items():
        if os.environ.get(env):
            keys[name] = os.environ[env].strip()
    return keys


def hl_save_key(name: str, value: str, config_dir=None) -> str:
    if name not in HL_KEY_ENV:
        raise HlError("unknown key name: " + name)
    folder = _hl_config(config_dir)
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, "lookup-keys.json")
    keys = {}
    try:
        with open(path, encoding="utf-8") as fh:
            keys = json.load(fh)
    except (OSError, ValueError):
        pass
    if value:
        keys[name] = value.strip()
    else:
        keys.pop(name, None)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(keys, fh, indent=2)
    return path


class HlCache:
    TTL_FOUND, TTL_UNKNOWN = 30 * 86400, 3 * 86400

    def __init__(self, config_dir=None, now=time.time):
        self.path = os.path.join(_hl_config(config_dir), "lookup-cache.json")
        self.now = now
        try:
            with open(self.path, encoding="utf-8") as fh:
                self.data = json.load(fh)
        except (OSError, ValueError):
            self.data = {}

    def get(self, service, sha256):
        hit = self.data.get(service + ":" + sha256)
        if not hit:
            return None
        ttl = self.TTL_UNKNOWN if hit["result"]["status"] == "unknown" else self.TTL_FOUND
        return dict(hit["result"], cached=True) if self.now() - hit["time"] < ttl else None

    def put(self, service, sha256, result):
        if result["status"] != "error":
            self.data[service + ":" + sha256] = {"time": self.now(), "result": result}

    def save(self):
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.data, fh)
            os.replace(tmp, self.path)
        except OSError:
            pass


# --- the online services -------------------------------------------------------------------------------------------

def hl_http(method: str, url: str, headers: Dict[str, str], body: Optional[bytes]) -> Tuple[int, bytes]:
    """One HTTPS request to an allowed look-up host; (status, body)."""
    host = urllib.parse.urlsplit(url).hostname or ""
    if not url.startswith("https://") or host not in _HL_HOSTS:
        raise HlError("refused: not a look-up service address")
    opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=tls_context()))
    req = urllib.request.Request(url, data=body, method=method,
                                 headers=dict({"User-Agent": "Mozilla/5.0"}, **headers))
    try:
        with opener.open(req, timeout=HL_TIMEOUT) as resp:
            return resp.status, resp.read(8 * 1024 * 1024)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(65536) if exc.fp else b""


def _hl_result(service, status, family="", first_seen="", detail=""):
    return {"service": service, "status": status, "family": family or "", "first_seen": first_seen or "",
            "detail": detail or ""}


def hl_circl_bulk(records, http):
    """{sha256: result} for many files in one request per 100 (by SHA-1, which CIRCL covers best)."""
    out = {}
    for i in range(0, len(records), 100):
        batch = records[i:i + 100]
        status, body = http("POST", "https://hashlookup.circl.lu/bulk/sha1", {"Content-Type": "application/json"},
                            json.dumps({"hashes": [r["sha1"].upper() for r in batch]}).encode())
        if status != 200:
            for r in batch:
                out[r["sha256"]] = _hl_result("circl", "error", detail="HTTP {}".format(status))
            continue
        try:
            found = json.loads(body or b"[]")
        except ValueError:
            found = []
        by_sha1 = {}
        for item in found if isinstance(found, list) else []:
            if isinstance(item, dict) and item.get("SHA-1"):
                by_sha1[str(item["SHA-1"]).lower()] = item
        for r in batch:
            item = by_sha1.get(r["sha1"])
            if not item:
                out[r["sha256"]] = _hl_result("circl", "unknown")
            elif item.get("KnownMalicious"):
                out[r["sha256"]] = _hl_result("circl", "known-bad", str(item.get("KnownMalicious"))[:80],
                                              detail="listed as known malicious")
            else:
                name = item.get("ProductName") or os.path.basename(str(item.get("FileName") or "").rstrip("/\\"))
                where = str(item.get("db") or "").replace("_legacy", "").upper() or "CIRCL"
                trust = item.get("hashlookup:trust")
                out[r["sha256"]] = _hl_result("circl", "known-good", detail="known ordinary software ({}{}){}".format(
                    where, ": " + str(name)[:80] if name else "",
                    ", trust {}/100".format(trust) if trust is not None else ""))
    return out


def hl_malwarebazaar(rec, key, http):
    status, body = http("POST", "https://mb-api.abuse.ch/api/v1/",
                        {"Auth-Key": key, "Content-Type": "application/x-www-form-urlencoded"},
                        urllib.parse.urlencode({"query": "get_info", "hash": rec["sha256"]}).encode())
    if status != 200:
        return _hl_result("malwarebazaar", "error", detail="HTTP {}".format(status))
    try:
        doc = json.loads(body)
    except ValueError:
        return _hl_result("malwarebazaar", "error", detail="unreadable answer")
    if doc.get("query_status") == "hash_not_found":
        return _hl_result("malwarebazaar", "unknown")
    if doc.get("query_status") == "ok" and doc.get("data"):
        d = doc["data"][0]
        return _hl_result("malwarebazaar", "known-bad", d.get("signature") or ", ".join(d.get("tags") or [])[:80],
                          d.get("first_seen"), "a known malware sample")
    return _hl_result("malwarebazaar", "error", detail=str(doc.get("query_status"))[:60])


def hl_threatfox(rec, key, http):
    status, body = http("POST", "https://threatfox-api.abuse.ch/api/v1/",
                        {"Auth-Key": key, "Content-Type": "application/json"},
                        json.dumps({"query": "search_hash", "hash": rec["sha256"]}).encode())
    if status != 200:
        return _hl_result("threatfox", "error", detail="HTTP {}".format(status))
    try:
        doc = json.loads(body)
    except ValueError:
        return _hl_result("threatfox", "error", detail="unreadable answer")
    if doc.get("query_status") == "ok" and doc.get("data"):
        d = doc["data"][0]
        return _hl_result("threatfox", "known-bad", d.get("malware_printable") or d.get("malware"),
                          d.get("first_seen"), "linked to {} campaign indicator(s)".format(len(doc["data"])))
    if doc.get("query_status") in ("no_result", "hash_not_found"):
        return _hl_result("threatfox", "unknown")
    return _hl_result("threatfox", "error", detail=str(doc.get("query_status"))[:60])


def hl_virustotal(rec, key, http):
    status, body = http("GET", "https://www.virustotal.com/api/v3/files/" + rec["sha256"], {"x-apikey": key}, None)
    if status == 404:
        return _hl_result("virustotal", "unknown")
    if status == 429:
        return _hl_result("virustotal", "error", detail="free-key limit reached; try again later")
    if status != 200:
        return _hl_result("virustotal", "error", detail="HTTP {}".format(status))
    try:
        attrs = json.loads(body)["data"]["attributes"]
    except (ValueError, KeyError, TypeError):
        return _hl_result("virustotal", "error", detail="unreadable answer")
    stats = attrs.get("last_analysis_stats") or {}
    bad, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
    total = sum(int(v) for v in stats.values() if isinstance(v, int))
    label = ((attrs.get("popular_threat_classification") or {}).get("suggested_threat_label")) or ""
    first = attrs.get("first_submission_date")
    first = time.strftime("%Y-%m-%d", time.gmtime(first)) if isinstance(first, int) else ""
    detail = "{} of {} engines flag it".format(bad, total) + (", {} suspicious".format(sus) if sus else "")
    if bad >= 3:
        return _hl_result("virustotal", "known-bad", label, first, detail)
    if bad or sus:
        return _hl_result("virustotal", "suspicious", label, first, detail)
    return _hl_result("virustotal", "no-detection", "", first, detail)


def hl_hybrid(rec, key, http):
    status, body = http("POST", "https://hybrid-analysis.com/api/v2/search/hash",
                        {"api-key": key, "User-Agent": "Falcon Sandbox",
                         "Content-Type": "application/x-www-form-urlencoded"},
                        urllib.parse.urlencode({"hash": rec["sha256"]}).encode())
    if status == 404:
        return _hl_result("hybrid", "unknown")
    if status != 200:
        return _hl_result("hybrid", "error", detail="HTTP {}".format(status))
    try:
        doc = json.loads(body)
    except ValueError:
        return _hl_result("hybrid", "error", detail="unreadable answer")
    reports = doc if isinstance(doc, list) else (doc.get("reports") or doc.get("result") or [])
    reports = [r for r in reports if isinstance(r, dict)]
    if not reports:
        return _hl_result("hybrid", "unknown")
    verdicts = [str(r.get("verdict") or "").lower() for r in reports]
    family = next((r.get("vx_family") for r in reports if r.get("vx_family")), "")
    score = max((r.get("threat_score") or 0) for r in reports)
    detail = "sandbox verdict: {} (threat score {})".format(verdicts[0] or "none", score)
    if "malicious" in verdicts:
        return _hl_result("hybrid", "known-bad", family, "", detail)
    if "suspicious" in verdicts:
        return _hl_result("hybrid", "suspicious", family, "", detail)
    return _hl_result("hybrid", "no-detection", family, "", detail)


_HL_ONE = {"malwarebazaar": hl_malwarebazaar, "threatfox": hl_threatfox, "virustotal": hl_virustotal,
           "hybrid": hl_hybrid}


def hl_should_ask(rec, lookup_all=False) -> bool:
    if rec.get("error") or rec.get("offline"):
        return False
    if lookup_all:
        return True
    if rec.get("signature") == "signed":
        return False
    return rec["kind"] in _HL_INTERESTING


def hl_online(records, services, keys, http=hl_http, cache=None, progress=None, sleep=time.sleep,
              lookup_all=False, vt_wait=15.0) -> List[str]:
    """Ask the chosen services about the selected records (adds rec['online']); returns notes."""
    say = progress or (lambda text: None)
    notes = []
    ask = [r for r in records if hl_should_ask(r, lookup_all)]
    unique = list({r["sha256"]: r for r in ask}.values())
    if len(unique) > HL_MAX_ONLINE:
        notes.append("only the first {} files were looked up online".format(HL_MAX_ONLINE))
        unique = unique[:HL_MAX_ONLINE]
    answers: Dict[str, List[dict]] = {r["sha256"]: [] for r in unique}
    for service in services:
        need_key = HL_SERVICES[service][2]
        if need_key and not keys.get(need_key):
            notes.append("{} skipped: no key saved (get a free one at {})".format(HL_SERVICES[service][0],
                                                                                HL_KEY_WHERE[need_key]))
            continue
        todo = []
        for r in unique:
            hit = cache.get(service, r["sha256"]) if cache else None
            if hit:
                answers[r["sha256"]].append(hit)
            else:
                todo.append(r)
        if service == "virustotal" and len(todo) > HL_VT_FREE_LIMIT and not lookup_all:
            notes.append("VirusTotal: only {} files per run with a free key (4 a minute); add --lookup-all to ask "
                         "about all".format(HL_VT_FREE_LIMIT))
            todo = todo[:HL_VT_FREE_LIMIT]
        if not todo:
            continue
        say("  asking {} about {} fingerprint(s)...".format(HL_SERVICES[service][0], len(todo)))
        try:
            if service == "circl":
                got = hl_circl_bulk(todo, http)
            else:
                got = {}
                for n, r in enumerate(todo):
                    if service == "virustotal" and n:
                        sleep(vt_wait)
                    got[r["sha256"]] = _HL_ONE[service](r, keys[need_key], http)
        except (OSError, HlError, urllib.error.URLError) as exc:
            notes.append("{} could not be reached ({})".format(HL_SERVICES[service][0], str(exc)[:80]))
            continue
        for sha, result in got.items():
            answers[sha].append(result)
            if cache:
                cache.put(service, sha, result)
    for r in records:
        if r.get("sha256") in answers:
            r["online"] = answers[r["sha256"]]
    if cache:
        cache.save()
    return notes


# --- judging and words ---------------------------------------------------------------------------------------------

def hl_verdict(rec) -> Tuple[str, str]:
    """(level, plain words) for one file."""
    if rec.get("error"):
        return HL_NOTHING, rec["error"]
    if rec.get("offline"):
        o = rec["offline"]
        if o.get("tier") == "vuln-driver":
            return HL_LOOK, ("A LEGITIMATE DRIVER THAT ATTACKERS ABUSE: {} ({}) - on its own it does not mean anyone "
                             "used it".format(o["family"], o["source"] or "indicator list"))
        if o.get("tier") == "stalkerware":
            return HL_KNOWN, "PHONE-MONITORING (STALKERWARE) APP: matches {} ({})".format(
                o["family"], o["source"] or "indicator list")
        return HL_KNOWN, "KNOWN SPYWARE: matches {} ({})".format(o["family"], o["source"] or "indicator list")
    online = rec.get("online") or []
    bad = [a for a in online if a["status"] == "known-bad"]
    if bad:
        words = "; ".join("{}: {}{}".format(HL_SERVICES[a["service"]][0], a["family"] or a["detail"],
                                            ", first seen " + a["first_seen"] if a["first_seen"] else "")
                          for a in bad)
        return HL_KNOWN, "KNOWN MALICIOUS - {}".format(words)
    sus = [a for a in online if a["status"] == "suspicious"]
    if sus:
        return HL_LOOK, "SOME TOOLS FLAG IT - {}".format("; ".join("{}: {}".format(HL_SERVICES[a["service"]][0],
                                                                                    a["detail"]) for a in sus))
    good = [a for a in online if a["status"] == "known-good"]
    if good:
        return HL_NOTHING, "known good - {}".format(good[0]["detail"])
    if rec.get("signature") == "signed":
        return HL_NOTHING, "validly signed by {}".format(rec["signer"]) if rec.get("signer") else "validly signed"
    clean = [a for a in online if a["status"] == "no-detection"]
    if clean:
        return HL_NOTHING, "nothing found - {}".format("; ".join(a["detail"] for a in clean))
    if online and all(a["status"] == "unknown" for a in online):
        return HL_NOTHING, "unknown to every service asked - unknown is not the same as safe"
    return HL_NOTHING, "not on the spyware lists" if online else "not on the spyware lists (not looked up online)"


def hl_report(records, notes=(), skipped=()) -> Dict[str, object]:
    level = HL_NOTHING
    for r in records:
        r["level"], r["verdict"] = hl_verdict(r)
        if r["level"] == HL_KNOWN:
            level = HL_KNOWN
        elif r["level"] == HL_LOOK and level == HL_NOTHING:
            level = HL_LOOK
    return {"level": level, "files": records, "notes": list(notes), "skipped": list(skipped)}


_HL_HEAD = {HL_KNOWN: "KNOWN MALICIOUS FILE FOUND", HL_LOOK: "WORTH A LOOK", HL_NOTHING: "NOTHING KNOWN"}


def hl_headline(result) -> str:
    return T(_HL_HEAD[result["level"]])


from .safetext import safe_render, st_line  # noqa: E402


@safe_render
def hl_render(result, limit=200) -> str:
    files = result["files"]
    asked = any(r.get("online") for r in files)
    lines = ["=" * 72, "  " + T("HASH LOOK-UP") + "  -  " + hl_headline(result),
             "  " + (T("Fingerprints only were sent to the services you chose; no file, name or path.")
                     if asked else T("Checked offline: nothing was sent anywhere.")), "=" * 72, ""]
    order = {HL_KNOWN: 0, HL_LOOK: 1, HL_NOTHING: 2}
    for r in sorted(files, key=lambda x: (order[x["level"]], x["path"]))[:limit]:
        lines.append("  {}".format(st_line(r["path"])))
        lines.append("    {}".format(TX(r["verdict"])))
        if not r.get("error"):
            lines.append("    SHA-256 {}  ({})".format(r["sha256"], T("{size} bytes, {kind}", size="{:,}".format(
                r["size"]), kind=T(r["kind"].replace("-", " ")))))
            extra = []
            if r.get("signer"):
                extra.append(T("signed by {who}", who=st_line(r["signer"])) +
                             (" - " + T(r["signature"]) if r.get("signature") else ""))
            elif r.get("signature"):
                extra.append(T(r["signature"]))
            if r.get("imphash"):
                extra.append("imphash " + r["imphash"])
            if extra:
                lines.append("    " + "; ".join(extra))
        lines.append("")
    if len(files) > limit:
        lines.append("  " + T("... and {n} more files (all are in the JSON report)", n="{:,}".format(len(files) - limit)))
    if result["level"] == HL_KNOWN:
        lines += ["  " + T("WHAT TO DO"), "    - " + T("Do not open or run the file. Keep it: it is evidence."),
                  "    - " + T("Get help: Access Now Helpline {url} (24/7).", url="https://www.accessnow.org/help/"), ""]
    for n in result["notes"] + result["skipped"]:
        lines.append("  " + T("note: {note}", note=TX(n)))
    lines.append("  " + T("CIRCL hashlookup data: CC BY ({url}).", url="https://www.circl.lu/services/hashlookup/"))
    return "\n".join(lines)


def hl_consent_text(services, count) -> str:
    lines = ["  " + T("The fingerprints (SHA-256 / SHA-1) of {n} file(s) - never the files, names or paths - will be "
                      "sent to:", n=count)]
    for s in services:
        name, country, _k = HL_SERVICES[s]
        lines.append("    - {} ({})".format(name, country))
    lines.append("  " + T("A fingerprint of a file only you have (your own document) tells that service you have "
                          "it, which") + "\n  " +
                 T("is why only programs, scripts, documents and archives that are not validly signed are sent."))
    return "\n".join(lines)


def hl_run(paths, iocs=None, services=(), keys=None, http=hl_http, progress=None, lookup_all=False,
           config_dir=None, confirm: Optional[Callable[[str], bool]] = None) -> Dict[str, object]:
    say = progress or (lambda text: None)
    files, skipped = hl_collect(paths)
    records = []
    for n, path in enumerate(files):
        records.append(hl_examine(path, iocs))
        if n % 200 == 199:
            say("  fingerprinted {:,} of {:,} files".format(n + 1, len(files)))
    notes = []
    if services:
        count = len({r["sha256"] for r in records if hl_should_ask(r, lookup_all)})
        if count and (confirm is None or confirm(hl_consent_text(services, count))):
            notes = hl_online(records, list(services), keys if keys is not None else hl_keys(config_dir), http,
                              HlCache(config_dir), say, lookup_all=lookup_all)
        elif count:
            notes.append("nothing was looked up online")
    return hl_report(records, notes, skipped)


def hl_parse_services(text: str) -> List[str]:
    names = [s.strip().lower() for s in (text or "").split(",") if s.strip()]
    if names == ["all"]:
        return list(HL_SERVICES)
    bad = [n for n in names if n not in HL_SERVICES]
    if bad:
        raise HlError("unknown service(s): {} - choose from {}".format(", ".join(bad), ", ".join(HL_SERVICES)))
    return names


def hl_command(args, load_iocs, out=print) -> int:
    if getattr(args, "set_lookup_key", None):
        import getpass
        name = args.set_lookup_key
        out(T("Get a free key at {where}", where=HL_KEY_WHERE[name]))
        value = getpass.getpass(T("Paste the key (not shown; empty removes it): "))
        out(T("Saved to {path}", path=hl_save_key(name, value)))
        return 0
    try:
        services = hl_parse_services(getattr(args, "online", "") or "")
    except HlError as exc:
        out(TX(str(exc)))
        return 2
    try:
        iocs = load_iocs(args)
    except Exception as exc:  # noqa: BLE001
        out(T("(Indicator lists could not be loaded: {why})", why=str(exc)[:160]))
        iocs = None

    def notice(text):
        out(text + "\n  " + T("(--online was given, so this is going ahead.)"))
        return True
    result = hl_run(args.hash_lookup, iocs, services, progress=out, lookup_all=args.lookup_all, confirm=notice)
    out(hl_render(result))
    if getattr(args, "json", None):
        with open(args.json, "x", encoding="utf-8") as fh:
            json.dump(dict(result, tool="zero-breach-toolkit hash look-up"), fh, indent=2, ensure_ascii=False)
        out("\n" + T("Saved: {path}", path=args.json))
    return {HL_KNOWN: 3, HL_LOOK: 1, HL_NOTHING: 0}[result["level"]]
