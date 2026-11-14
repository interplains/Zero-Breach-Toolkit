"""Send evidence to a helper (--package-for-helper): one sealed, signed package.

A helper (Access Now's Digital Security Helpline, Amnesty's Security Lab, a trusted expert) gives you their age
public key, which starts with "age1". This puts the files you choose - saved reports, an AndroidQF phone
collection, screenshots, suspicious files - into one ZIP, encrypts it so only that helper can open it, and signs
a list of every file and its SHA-256 fingerprint with your own sender key, because encryption alone does not show
who sent a package or that nothing was swapped on the way.

Layout (compatible with AndroidQF, so a helper's usual tools work on a phone collection unchanged):
  <uuid>.zip.age
    <an AndroidQF collection's own files at the top, untouched>   or   files/<what you added>/...
    acquisition.json, hashes.csv                                (written only when there is no AndroidQF collection)
    zero-breach/manifest.json      every file: path, size, SHA-256, modified time
    zero-breach/manifest.sig       Ed25519 signature of manifest.json
    zero-breach/sender-key.txt     the sender's public key and its safety number
    zero-breach/README.txt         how the helper checks it

Nothing is uploaded: you send the file yourself, by a route the helper agrees. No user name or computer name goes
into the package; paths are kept relative to what you chose. The plaintext ZIP is never written to disk.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import sys
import uuid as _uuid
import zipfile
from typing import Callable, Dict, List, Optional, Tuple

from . import __version__
from .ageseal import (AgError, AgWriter, ag_encode_recipient, ag_parse_recipient, ag_safety_number, ed_public,
                      ed_sign, ed_verify)
from .localpaths import path_problem, walk_local
from .i18n import T, TX, i18n_lang

HP_FORMAT = "zero-breach-helper-package/1"
HP_MAX_FILES = 200_000
HP_MAX_TOTAL = 64 * 1024 ** 3
HP_KEY_NAME = "sender-ed25519.key"


class HpError(ValueError):
    pass


# --- the sender key ------------------------------------------------------------------------------------------------

def hp_config_dir() -> str:
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "ZeroBreach")
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Application Support/ZeroBreach")
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "zero-breach")


def hp_sender_key(config_dir: Optional[str] = None) -> Tuple[bytes, bytes, bool]:
    """(seed, public key, newly created). The key stays on this computer; only the public half is sent."""
    folder = config_dir or hp_config_dir()
    path = os.path.join(folder, HP_KEY_NAME)
    try:
        with open(path, encoding="ascii") as fh:
            seed = bytes.fromhex(fh.read().strip())
        if len(seed) == 32:
            return seed, ed_public(seed), False
    except (OSError, ValueError):
        pass
    os.makedirs(folder, exist_ok=True)
    seed = os.urandom(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(seed.hex() + "\n")
    return seed, ed_public(seed), True


# --- choosing what goes in -----------------------------------------------------------------------------------------

def _hp_is_androidqf(folder: str) -> bool:
    return os.path.isfile(os.path.join(folder, "acquisition.json")) and any(
        os.path.exists(os.path.join(folder, name)) for name in ("packages.json", "getprop.txt", "processes.json",
                                                                 "settings_secure.txt", "dumpsys.txt", "logs"))


def hp_collect(paths, exclude=()) -> Tuple[List[Tuple[str, str]], List[str], bool]:
    """([(file on disk, name in package)], skipped notes, is an AndroidQF collection)."""
    exclude = {os.path.normcase(os.path.abspath(p)) for p in exclude}
    picked: List[Tuple[str, str]] = []
    skipped: List[str] = []
    used = set()
    paths = [os.path.abspath(p) for p in paths]
    androidqf = len(paths) == 1 and os.path.isdir(paths[0]) and _hp_is_androidqf(paths[0])

    def add(src, arc):
        arc = arc.replace("\\", "/").lstrip("/")
        base, n = arc, 2
        while arc.lower() in used:
            stem, dot, ext = base.rpartition(".")
            arc = "{} ({}).{}".format(stem, n, ext) if dot and "/" not in ext else "{} ({})".format(base, n)
            n += 1
        used.add(arc.lower())
        picked.append((src, arc))

    for path in paths:
        problem = path_problem(path)
        if problem:
            skipped.append("{}: {}".format(os.path.basename(path), problem))
            continue
        top = "" if androidqf else "files/" + os.path.basename(path.rstrip("\\/"))
        if os.path.isfile(path):
            if os.path.normcase(path) not in exclude:
                add(path, top)
            continue
        if not os.path.isdir(path):
            skipped.append("{}: not found".format(os.path.basename(path)))
            continue

        def onerror(exc):
            skipped.append("a folder or link inside {} was not read".format(os.path.basename(path)))
        for folder, _dirs, files in walk_local(path, onerror=onerror):
            for name in sorted(files):
                src = os.path.join(folder, name)
                if os.path.normcase(src) in exclude or os.path.islink(src):
                    continue
                rel = os.path.relpath(src, path)
                add(src, (top + "/" + rel) if top else rel)
                if len(picked) > HP_MAX_FILES:
                    raise HpError("more than {:,} files; choose fewer".format(HP_MAX_FILES))
    return picked, skipped, androidqf


# --- building ------------------------------------------------------------------------------------------------------

def _hp_zipinfo(arc, mtime, size):
    t = datetime.datetime.fromtimestamp(max(mtime, 315532800 + 86400))
    info = zipfile.ZipInfo(arc, date_time=(t.year, t.month, t.day, t.hour, t.minute, t.second))
    info.compress_type = zipfile.ZIP_DEFLATED
    info.file_size = size
    return info


def _hp_utc(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


_HP_README = """This package was made with Zero Breach Toolkit {version}.

Check it was not changed and who sent it:
  1. Decrypt it with your age key:   age -d -i key.txt -o package.zip {name}
  2. With Zero Breach Toolkit:       zero-breach-toolkit --verify-package package.zip
     This checks the signature of zero-breach/manifest.json and every file's SHA-256 fingerprint.
     Without it: manifest.sig is an Ed25519 signature (hex) of manifest.json by the key in sender-key.txt.
  3. Ask the sender to read you their safety number by phone or in person, and compare it with:
       {safety}
     If it matches, the package comes from the person you spoke with.

Files: {count}. Created (UTC): {created}. AndroidQF collection: {androidqf}.
"""


def hp_build(paths, out_dir, recipient: Optional[str], progress: Optional[Callable[[str], None]] = None,
             config_dir: Optional[str] = None) -> Dict[str, object]:
    """Build the package; return a summary. recipient None = not encrypted (only on explicit request)."""
    say = progress or (lambda text: None)
    public_key = ag_parse_recipient(recipient) if recipient else None
    if path_problem(os.path.abspath(out_dir)):
        raise HpError("the output folder is not a local folder: " + path_problem(os.path.abspath(out_dir)))
    os.makedirs(out_dir, exist_ok=True)
    seed, sender, created_key = hp_sender_key(config_dir)
    key_file = os.path.join(config_dir or hp_config_dir(), HP_KEY_NAME)
    package_id = str(_uuid.uuid4())
    final = os.path.join(out_dir, package_id + (".zip.age" if public_key else ".zip"))
    part = final + ".part"
    picked, skipped, androidqf = hp_collect(paths, exclude=(key_file, part, final))
    if not picked:
        raise HpError("nothing to put in the package" + (": " + "; ".join(skipped[:3]) if skipped else ""))
    total = 0
    for src, _arc in picked:
        try:
            total += os.path.getsize(src)
        except OSError:
            pass
    if total > HP_MAX_TOTAL:
        raise HpError("the selection is {:.1f} GB; the limit is 64 GB".format(total / 1024 ** 3))
    created = _hp_utc(datetime.datetime.now(datetime.timezone.utc).timestamp())
    listing = []
    raw = open(part, "xb")
    sink = AgWriter(raw, [public_key]) if public_key else raw
    try:
        with zipfile.ZipFile(sink, "w", allowZip64=True) as zf:
            done = 0
            for i, (src, arc) in enumerate(picked):
                try:
                    st = os.stat(src)
                    info = _hp_zipinfo(arc, st.st_mtime, st.st_size)
                    digest = hashlib.sha256()
                    size = 0
                    with open(src, "rb") as fh, zf.open(info, "w", force_zip64=st.st_size > 2 ** 31) as dst:
                        for block in iter(lambda: fh.read(1 << 20), b""):
                            digest.update(block)
                            dst.write(block)
                            size += len(block)
                    listing.append({"path": arc, "size": size, "sha256": digest.hexdigest(),
                                    "modified_utc": _hp_utc(st.st_mtime)})
                    done += size
                except OSError as exc:
                    skipped.append("{}: could not be read ({})".format(arc, exc.__class__.__name__))
                if i % 25 == 0 or i == len(picked) - 1:
                    say("  " + T("sealing {i} of {n} files ({done} of {total} MB)", i="{:,}".format(i + 1),
                                 n="{:,}".format(len(picked)), done="{:.0f}".format(done / 1e6),
                                 total="{:.0f}".format(total / 1e6)))
            names = {e["path"] for e in listing}
            extra = {}
            if "acquisition.json" not in names:
                extra["acquisition.json"] = json.dumps({
                    "uuid": package_id, "collector": "Zero Breach Toolkit", "version": __version__,
                    "type": "helper-package", "created_utc": created, "files": len(listing)}, indent=2)
            if "hashes.csv" not in names:
                extra["hashes.csv"] = "path,sha256\n" + "".join("{},{}\n".format(e["path"], e["sha256"])
                                                                for e in listing)
            manifest = json.dumps({"format": HP_FORMAT, "uuid": package_id, "created_utc": created,
                                   "tool": {"name": "Zero Breach Toolkit", "version": __version__},
                                   "sender_key": sender.hex(), "androidqf_collection": androidqf,
                                   "encrypted_to": ag_encode_recipient(public_key) if public_key else None,
                                   "files": listing}, indent=2, ensure_ascii=False).encode("utf-8")
            safety = ag_safety_number(sender)
            extra["zero-breach/manifest.json"] = manifest
            extra["zero-breach/manifest.sig"] = ed_sign(seed, manifest).hex() + "\n"
            extra["zero-breach/sender-key.txt"] = "ed25519 {}\nsafety number: {}\n".format(sender.hex(), safety)
            extra["zero-breach/README.txt"] = _HP_README.format(
                version=__version__, name=os.path.basename(final), safety=safety, count=len(listing),
                created=created, androidqf="yes" if androidqf else "no")
            now = datetime.datetime.now()
            for arc, content in extra.items():
                info = zipfile.ZipInfo(arc, date_time=now.timetuple()[:6])
                info.compress_type = zipfile.ZIP_DEFLATED
                zf.writestr(info, content if isinstance(content, bytes) else content.encode("utf-8"))
        if public_key:
            sink.close()
        raw.close()
        os.replace(part, final)
    except BaseException:
        try:
            raw.close()
        finally:
            if os.path.exists(part):
                os.remove(part)
        raise
    digest = hashlib.sha256()
    with open(final, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            digest.update(block)
    code = digest.hexdigest()
    return {"path": final, "uuid": package_id, "encrypted": bool(public_key),
            "recipient": ag_encode_recipient(public_key) if public_key else None, "files": len(listing),
            "bytes": sum(e["size"] for e in listing), "package_sha256": code,
            "package_code": " ".join(code[i:i + 4] for i in range(0, 16, 4)), "safety_number": safety,
            "sender_key": sender.hex(), "new_sender_key": created_key, "skipped": skipped, "androidqf": androidqf}


# --- the helper's side ---------------------------------------------------------------------------------------------

def hp_verify(path: str) -> Dict[str, object]:
    """Check a decrypted package (ZIP or unpacked folder): the manifest signature and every file's fingerprint."""
    problems: List[str] = []
    if os.path.isdir(path):
        def read(name):
            with open(os.path.join(path, *name.split("/")), "rb") as fh:
                return fh.read()

        def stream(name):
            return open(os.path.join(path, *name.split("/")), "rb")
        close = None
    else:
        with open(path, "rb") as fh:
            if fh.read(21) == b"age-encryption.org/v1":
                raise HpError("this package is still encrypted: decrypt it first with your age key "
                              "(age -d -i key.txt -o package.zip " + os.path.basename(path) + ")")
        zf = zipfile.ZipFile(path)
        read, stream, close = zf.read, zf.open, zf.close
    try:
        manifest = read("zero-breach/manifest.json")
        sig = bytes.fromhex(read("zero-breach/manifest.sig").decode("ascii").strip())
        doc = json.loads(manifest)
        if doc.get("format") != HP_FORMAT:
            raise HpError("not a Zero Breach helper package (unknown format)")
        sender = bytes.fromhex(doc["sender_key"])
        signed = ed_verify(sender, manifest, sig)
        if not signed:
            problems.append("the signature does not match: manifest.json was changed or signed by a different key")
        checked = 0
        for entry in doc.get("files", []):
            try:
                digest = hashlib.sha256()
                with stream(entry["path"]) as fh:
                    for block in iter(lambda: fh.read(1 << 20), b""):
                        digest.update(block)
                if digest.hexdigest() != entry["sha256"]:
                    problems.append("{} was changed (its fingerprint differs)".format(entry["path"]))
                checked += 1
            except (KeyError, OSError):
                problems.append("{} is missing".format(entry.get("path")))
    except (KeyError, OSError, ValueError) as exc:
        raise HpError("the package's signed list could not be read ({})".format(str(exc)[:120]))
    finally:
        if close:
            close()
    return {"ok": signed and not problems, "signed": signed, "files": checked, "problems": problems,
            "safety_number": ag_safety_number(sender), "uuid": doc.get("uuid"), "created_utc": doc.get("created_utc"),
            "tool_version": (doc.get("tool") or {}).get("version")}


# --- words ---------------------------------------------------------------------------------------------------------

HP_HOW = """  Ask your helper for their age public key: one line starting with "age1". Access Now's Digital Security
  Helpline (https://www.accessnow.org/help/) and Amnesty's Security Lab give one per case. Never send a key that
  starts with AGE-SECRET-KEY - that is a secret key."""


from .safetext import safe_render  # noqa: E402


def _hp_paragraph(lines, first, rest, width=104):
    """Fixed advice written as hand-broken English lines: English exactly as written, other languages as the
    translated sentence wrapped at the same indent."""
    if i18n_lang() == "en":
        return list(lines)
    import textwrap
    text = " ".join(line.strip() for line in lines)
    return textwrap.wrap(T(text), width, initial_indent=first, subsequent_indent=rest) or [first + T(text)]


@safe_render
def hp_render(result) -> str:
    # The safety number and the package code are read aloud: each stays alone on its own line, never translated.
    lines = ["=" * 72, "  " + T("PACKAGE FOR A HELPER") + "  -  " + (T("SEALED") if result["encrypted"]
                                                                     else T("NOT ENCRYPTED")),
             "=" * 72, "",
             "  " + T("File:") + "   " + result["path"],
             "  " + T("Holds:") + "  " + T("{n} files, {mb} MB", n="{:,}".format(result["files"]),
                                           mb="{:.1f}".format(result["bytes"] / 1e6))
             + (" " + T("(an AndroidQF phone collection, kept as it was)") if result["androidqf"] else "")]
    if result["encrypted"]:
        lines.append("  " + T("Sealed for:") + " " + result["recipient"] + "  - " + T("only that key can open it."))
    else:
        lines += [""] + _hp_paragraph(("  ! NOT ENCRYPTED: anyone who gets this file can read everything in it. Send "
                                       "it only by a", "    route your helper agreed (for example their Signal or "
                                       "secure upload)."), "  ", "    ")
    lines += ["", "  " + T("Your safety number (read it to your helper by phone or in person, so they know it is "
                           "you):"),
              "      " + result["safety_number"],
              "  " + T("Package code (lets the helper confirm they got exactly this file):"),
              "      " + result["package_code"]]
    if result["new_sender_key"]:
        lines.append("  " + T("(Your sender key was created now and stays on this computer; the same safety number "
                              "will be used for every package you make here.)"))
    if result["skipped"]:
        lines += ["", "  " + T("NOT INCLUDED")] + ["    - " + TX(s) for s in result["skipped"][:30]]
    lines += ["", "  " + T("Send the file yourself, by the route your helper gives you. Nothing was uploaded."),
              "  " + T("The package holds private data: delete your copy once the helper confirms they have it.")]
    return "\n".join(lines)


@safe_render
def hp_render_verify(result) -> str:
    head = T("SIGNATURE AND FILES CHECK OUT") if result["ok"] else T("DOES NOT CHECK OUT")
    lines = ["=" * 72, "  " + T("PACKAGE CHECK") + "  -  " + head, "=" * 72, "",
             "  " + T("Package {uuid} made {created} with Zero Breach Toolkit {version}", uuid=result["uuid"],
                      created=result["created_utc"], version=result["tool_version"]),
             "  " + T("Files checked: {n}", n="{:,}".format(result["files"])),
             "  " + T("Sender's safety number:") + " " + result["safety_number"],
             "  " + T("Ask the sender to read theirs to you; if the numbers match, the package is from them.")]
    if result["problems"]:
        lines += ["", "  " + T("PROBLEMS")] + ["    - " + TX(p) for p in result["problems"][:50]]
    return "\n".join(lines)


def hp_command(args, out=print) -> int:
    if getattr(args, "verify_package", None):
        try:
            result = hp_verify(args.verify_package)
        except (HpError, zipfile.BadZipFile) as exc:
            out(T("Could not check that package: {why}", why=TX(str(exc))))
            return 2
        out(hp_render_verify(result))
        return 0 if result["ok"] else 2
    if not args.helper_key and not args.no_encryption:
        out(T("A helper key is needed to seal the package (--helper-key age1...).") + "\n\n" + T(HP_HOW) +
            "\n\n  " + T("To make an unencrypted package instead, add --no-encryption."))
        return 2
    try:
        result = hp_build(args.add, args.package_for_helper, None if args.no_encryption else args.helper_key,
                          progress=lambda text: out(text))
    except (AgError, HpError) as exc:
        out(T("The package was not made: {why}", why=TX(str(exc))))
        return 2
    out("\n" + hp_render(result))
    if getattr(args, "json", None):
        with open(args.json, "x", encoding="utf-8") as fh:
            json.dump(dict(result, tool="zero-breach-toolkit helper package"), fh, indent=2)
        out("\n" + T("Saved: {path}", path=args.json))
    return 0

