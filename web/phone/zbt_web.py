"""Browser driver for the phone check: runs the unchanged engine inside WebAssembly.

The page mounts the folder a person picked (read-only, never copied off their
computer) and calls run_check(). Everything below calls the same functions the
terminal and the window use, so the result, its colour and its wording cannot
differ from the desktop program for the same backup and indicator set.

This file is shipped inside the page's engine archive; it is not part of the
desktop program.
"""
import datetime
import hashlib
import json
import os
import sys
import types


ENGINE_ROOT = "/zbt"
EVIDENCE_ROOT = "/evidence"


def _install_shims():
    """Provide the two standard-library pieces WebAssembly Python lacks.

    ssl: the engine imports it for the indicator update's TLS context. The page
    never updates or connects, so a module that refuses to make a context is
    the honest stand-in.

    hashlib.pbkdf2_hmac: CPython builds it from OpenSSL, which this runtime does
    not include. Encrypted iPhone backups derive their key with it, so it is
    provided from the cryptography package, which carries its own OpenSSL.
    """
    try:
        import ssl  # noqa: F401
    except ImportError:
        stub = types.ModuleType("ssl")

        class SSLError(OSError):
            pass

        def _refuse(*_a, **_k):
            raise SSLError("network connections are not available in the browser check")

        stub.SSLError = SSLError
        stub.SSLContext = _refuse
        stub.create_default_context = _refuse
        stub.PROTOCOL_TLS_CLIENT = 16
        stub.CERT_REQUIRED = 2
        sys.modules["ssl"] = stub
    if not hasattr(hashlib, "pbkdf2_hmac") or not getattr(hashlib.pbkdf2_hmac, "_zbt_web", False):
        def pbkdf2_hmac(hash_name, password, salt, iterations, dklen=None):
            # Keys the page already derived with the browser's own Web Crypto
            # (native speed) for exactly these inputs; see keybag_steps().
            key = (hash_name, bytes(password), bytes(salt), int(iterations), dklen)
            if key in _DERIVED:
                return _DERIVED[key]
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            algorithms = {"sha1": hashes.SHA1, "sha256": hashes.SHA256, "sha512": hashes.SHA512}
            if hash_name not in algorithms:
                raise ValueError("unsupported hash type " + str(hash_name))
            length = dklen or algorithms[hash_name].digest_size
            return PBKDF2HMAC(algorithm=algorithms[hash_name](), length=length, salt=bytes(salt),
                              iterations=int(iterations)).derive(bytes(password))
        pbkdf2_hmac._zbt_web = True
        hashlib.pbkdf2_hmac = pbkdf2_hmac


# Derived keys handed in by the page for one check, then cleared.
_DERIVED = {}


def keybag_steps(folder):
    """The password-derivation steps an encrypted backup's keybag asks for, in
    order, as [digest, salt hex, rounds, length]. The engine performs the same
    steps itself (backupcrypto.backup_ios_keys); the page runs them first with
    Web Crypto, which is many times faster than WebAssembly in some browsers,
    and passes the results in. A wrong or missing value only means the engine
    derives the key itself."""
    import plistlib
    import struct
    try:
        with open(os.path.join(folder, "Manifest.plist"), "rb") as fh:
            manifest = plistlib.loads(fh.read(4 * 1024 * 1024))
        blob = manifest.get("BackupKeyBag") if isinstance(manifest, dict) else None
    except Exception:
        return "[]"
    if not isinstance(blob, bytes):
        return "[]"
    header, offset = {}, 0
    while offset + 8 <= len(blob):
        tag, size = struct.unpack_from(">4sI", blob, offset)
        offset += 8
        value = blob[offset:offset + size]
        offset += size
        if tag == b"UUID" and header.get(b"UUID"):
            break  # the first class key starts here; the header is complete
        header[tag] = value
    steps = []
    for digest, salt_tag, count_tag in (("sha256", b"DPSL", b"DPIC"), ("sha1", b"SALT", b"ITER")):
        salt, count = header.get(salt_tag), header.get(count_tag)
        if salt_tag == b"DPSL" and salt is None:
            continue
        if not isinstance(salt, bytes) or not isinstance(count, bytes) or len(count) != 4:
            return "[]"
        rounds = int.from_bytes(count, "big")
        if not 1 <= len(salt) <= 128 or not 1 <= rounds <= 20000000:
            return "[]"
        steps.append([digest, salt.hex(), rounds, 32])
    return json.dumps(steps)


def _accept_derived(password, derived):
    """Record the page's Web Crypto results against the exact inputs the
    engine will use: the password's UTF-8 bytes, then each step's output."""
    _DERIVED.clear()
    secret = password.encode("utf-8")
    for digest, salt_hex, rounds, length, out_hex in derived or ():
        out = bytes.fromhex(out_hex)
        _DERIVED[(digest, secret, bytes.fromhex(salt_hex), int(rounds), int(length))] = out
        secret = out


def _ready():
    _install_shims()
    scan = os.path.join(ENGINE_ROOT, "scan")
    if scan not in sys.path:
        sys.path.insert(0, scan)
    # The engine picks a temporary folder from these; in the page it is memory
    # inside this worker, gone when the worker ends.
    os.makedirs("/tmp", exist_ok=True)
    os.environ.setdefault("TMPDIR", "/tmp")
    _place_kev()


def _place_kev():
    """Put the exploited-vulnerability list shipped with the page where the
    engine reads it (its own indicator cache), so an iPhone backup's iOS
    version is compared exactly as the program compares it after an update.
    The engine re-checks the list against its hash before using it."""
    import shutil
    from zbtriage.feeds import default_cache_dir
    from zbtriage.kevdata import KEV_FILE, KEV_MANIFEST
    src = os.path.join(ENGINE_ROOT, "kev")
    if not os.path.isfile(os.path.join(src, KEV_FILE)):
        return
    dest = default_cache_dir()
    if os.path.isfile(os.path.join(dest, KEV_FILE)):
        return
    os.makedirs(dest, exist_ok=True)
    for name in (KEV_FILE, KEV_MANIFEST):
        shutil.copyfile(os.path.join(src, name), os.path.join(dest, name))


def _kev_catalog():
    from zbtriage.feeds import default_cache_dir
    from zbtriage.kevdata import kev_load
    doc, _problem = kev_load(default_cache_dir())
    return doc.get("catalogVersion") if doc else None


def engine_info():
    """Version and indicator counts, for the page header before any check."""
    _ready()
    from zbtriage import __version__
    from zbtriage.cli import _parse, _load_iocs
    args = _parse(["--no-feeds", "--no-banner", "--no-menu", "--no-version-check"])
    iocs = _load_iocs(args)
    return json.dumps({"version": __version__, "indicators": len(iocs),
                       "languages": _languages(), "kev": _kev_catalog()})


def _languages():
    from zbtriage.i18n import I18N_LANGUAGES, i18n_available
    available = set(i18n_available())
    return [[code, name] for code, name in I18N_LANGUAGES if code in available]


def _is_backup(folder):
    return os.path.isfile(os.path.join(folder, "Manifest.db")) or os.path.isfile(
        os.path.join(folder, "Manifest.plist"))


def _device_name(folder):
    import plistlib
    try:
        with open(os.path.join(folder, "Info.plist"), "rb") as fh:
            info = plistlib.loads(fh.read(4 * 1024 * 1024))
    except Exception:
        return ""
    if not isinstance(info, dict):
        return ""
    parts = [str(info.get(key, ""))[:80] for key in ("Device Name", "Product Type", "Product Version")]
    when = info.get("Last Backup Date")
    if isinstance(when, datetime.datetime):
        parts.append(when.strftime("%Y-%m-%d"))
    return " · ".join(p for p in parts if p)


def find_inputs():
    """What the picked folder holds: one iPhone backup, several (the parent
    Backup folder), or something else (an Android collection or a mistake).
    The page asks the person to choose when there is more than one."""
    _ready()
    found = []
    if _is_backup(EVIDENCE_ROOT):
        found.append({"path": EVIDENCE_ROOT, "kind": "iphone", "label": _device_name(EVIDENCE_ROOT)})
    else:
        try:
            names = sorted(os.listdir(EVIDENCE_ROOT))
        except OSError:
            names = []
        for name in names:
            sub = os.path.join(EVIDENCE_ROOT, name)
            if os.path.isdir(sub) and _is_backup(sub):
                found.append({"path": sub, "kind": "iphone", "label": _device_name(sub) or name})
        if not found and names:
            found.append({"path": EVIDENCE_ROOT, "kind": "android", "label": ""})
    for item in found:
        if item["kind"] == "iphone":
            item["encrypted"] = _encrypted(item["path"])
    return json.dumps(found)


def _encrypted(folder):
    import plistlib
    try:
        with open(os.path.join(folder, "Manifest.plist"), "rb") as fh:
            manifest = plistlib.loads(fh.read(4 * 1024 * 1024))
    except Exception:
        return None
    return bool(isinstance(manifest, dict) and manifest.get("IsEncrypted") is True)


def run_check(folder, password, lang, emit, derived_json="[]"):
    """Run the phone check exactly as `--phone FOLDER` does and return the
    report document plus its readable renderings."""
    _ready()
    try:
        _accept_derived(password or "", json.loads(derived_json or "[]"))
        return _run_check(folder, password, lang, emit)
    finally:
        _DERIVED.clear()


def _run_check(folder, password, lang, emit):
    from zbtriage.cli import _parse, _load_iocs, _run_modules
    from zbtriage.context import ScanContext, scan_recovery
    from zbtriage.i18n import i18n_set
    from zbtriage.report import (prepare_document, render_human, render_summary,
                                 result_kind, share_summary)
    # The window's own wording for the headline, the next steps and progress,
    # so the page and the desktop program say the same thing.
    from zbtriage.gui import gui_headline, gui_next_steps, gui_progress
    from zbtriage.i18n import i18n_rtl
    if folder != EVIDENCE_ROOT and not folder.startswith(EVIDENCE_ROOT + "/"):
        raise ValueError("the check only reads the folder that was picked")
    argv = ["--phone", folder, "--no-feeds", "--no-banner", "--no-menu", "--no-version-check"]
    if lang:
        argv += ["--lang", lang]
    args = _parse(argv)
    i18n_set(lang or "en")
    iocs = _load_iocs(args)
    state = {}

    def progress(message):
        text, percent = gui_progress(str(message), state)
        emit(json.dumps({"line": str(message), "text": text, "percent": percent}))

    ctx = ScanContext(iocs=iocs, phone_path=folder, backup_password=password or "", emit=progress)
    password = ""
    started = datetime.datetime.now()
    with scan_recovery(ctx):
        ctx.completed = _run_modules(ctx)
    ctx.backup_password = ""
    document = prepare_document(iocs, ctx.completed, started, args, ctx.cancelled)
    document.setdefault("scope", {})["runtime"] = "browser (WebAssembly); nothing uploaded"
    colour, title, text = gui_headline(document)
    from zbtriage.i18n import T
    # The result area's labels, in the program's own translated wording.
    labels = {key: T(key) for key in ("What should I do now?", "Show full report",
                                      "Save report...", "Save sharing summary...")}
    # The "worth a look" items, so the page can show them beside the result
    # instead of only inside the full report. Fixed wording from the readers;
    # location/observed values come from the evidence and are shown as text.
    leads = [{"what": l.get("what", ""), "usual_reason": l.get("usual_reason", ""),
              "location": l.get("location", "")}
             for m in document.get("modules", {}).values() for l in m.get("leads", [])][:50]
    labels["Worth a look"] = T("Worth a look")
    return json.dumps({
        "labels": labels,
        "leads": leads,
        "kind": result_kind(document),
        "colour": colour,
        "title": title,
        "text": text,
        "next_steps": gui_next_steps(document),
        "rtl": bool(i18n_rtl()),
        "summary": render_summary(document),
        "report": render_human(document),
        "document": document,
        "share": share_summary(document),
    }, ensure_ascii=False, default=str)
