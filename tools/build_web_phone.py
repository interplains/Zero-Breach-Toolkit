"""Build the browser phone check (web/phone/) into a self-contained static folder.

    python tools/build_web_phone.py --pyodide DIR --wheels DIR [--out DIR]

--pyodide is the unpacked npm package `pyodide` at the pinned version; --wheels
holds the four wheels the encrypted-backup path needs. Every wheel is checked
against the SHA-256 in that Pyodide release's lock file before it is copied, and
the build refuses a different Pyodide version from the one pinned here.

Output (default web/phone/dist/): the page, its scripts, runtime/ (Pyodide and
the wheels), engine.zip (this repository's scan engine, the built-in indicator
lists and the browser driver) and files.json (every file the page loads, with
its size and SHA-256, which the page checks before it uses anything).

Nothing here downloads anything; it only copies and hashes local files.
"""
import argparse
import hashlib
import json
import os
import shutil
import sys
import zipfile

PYODIDE_VERSION = "314.0.7"
CORE = ("pyodide.mjs", "pyodide.asm.mjs", "pyodide.asm.wasm", "python_stdlib.zip", "pyodide-lock.json")
PACKAGES = ("cryptography", "cffi", "pycparser", "six")
PAGE = ("index.html", "phone.css", "phone.js", "worker.js")
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(REPO, "web", "phone")
# A fixed timestamp makes engine.zip byte-identical for identical sources.
ZIP_TIME = (2026, 1, 1, 0, 0, 0)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def engine_files():
    """(archive name, disk path) for the engine, its indicator lists and the driver."""
    out = []
    package = os.path.join(REPO, "scan", "zbtriage")
    for folder, dirs, files in os.walk(package):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for name in sorted(files):
            if name.endswith(".py"):
                path = os.path.join(folder, name)
                out.append(("scan/" + os.path.relpath(path, os.path.join(REPO, "scan")).replace(os.sep, "/"), path))
    iocs = os.path.join(REPO, "iocs")
    for name in sorted(os.listdir(iocs)):
        if name.endswith((".txt", ".sha256")):
            out.append(("iocs/" + name, os.path.join(iocs, name)))
    out.append(("zbt_web.py", os.path.join(SRC, "zbt_web.py")))
    return out


def kev_files(cache):
    """The exploited-vulnerability summary (and its hash file) from an indicator
    cache, verified the same way the engine verifies it before use."""
    if not cache:
        return [], None
    sys.path.insert(0, os.path.join(REPO, "scan"))
    from zbtriage.kevdata import KEV_FILE, KEV_MANIFEST, kev_load
    doc, problem = kev_load(cache)
    if problem or doc is None:
        sys.exit("error: --kev-cache: " + (problem or "no exploited-vulnerability list in " + cache))
    return [("kev/" + KEV_FILE, os.path.join(cache, KEV_FILE)),
            ("kev/" + KEV_MANIFEST, os.path.join(cache, KEV_MANIFEST))], doc.get("catalogVersion")


def build_engine(dest, extra=()):
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for name, path in list(engine_files()) + list(extra):
            info = zipfile.ZipInfo(name, ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            with open(path, "rb") as fh:
                zf.writestr(info, fh.read())


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--pyodide", required=True, help="unpacked npm package folder for pyodide " + PYODIDE_VERSION)
    p.add_argument("--wheels", required=True, help="folder holding the Pyodide wheels for " + ", ".join(PACKAGES))
    p.add_argument("--out", default=os.path.join(SRC, "dist"))
    p.add_argument("--kev-cache", help="indicator cache holding a verified exploited-vulnerability list "
                   "(written by --update) to ship with the page, so iPhone checks can say when iOS is out of date")
    args = p.parse_args(argv)
    extra, kev_version = kev_files(args.kev_cache)

    with open(os.path.join(args.pyodide, "package.json"), encoding="utf-8") as fh:
        version = json.load(fh).get("version")
    if version != PYODIDE_VERSION:
        sys.exit("error: Pyodide {} given; this build is pinned to {}".format(version, PYODIDE_VERSION))
    with open(os.path.join(args.pyodide, "pyodide-lock.json"), encoding="utf-8") as fh:
        lock = json.load(fh)

    out = os.path.abspath(args.out)
    if os.path.isdir(out):
        shutil.rmtree(out)
    runtime = os.path.join(out, "runtime")
    os.makedirs(runtime)

    for name in CORE:
        shutil.copyfile(os.path.join(args.pyodide, name), os.path.join(runtime, name))
    for package in PACKAGES:
        entry = lock["packages"][package]
        src = os.path.join(args.wheels, entry["file_name"])
        actual = sha256(src)
        if actual != entry["sha256"]:
            sys.exit("error: {} does not match the Pyodide lock file ({} != {})".format(
                entry["file_name"], actual, entry["sha256"]))
        shutil.copyfile(src, os.path.join(runtime, entry["file_name"]))
    for name in PAGE:
        shutil.copyfile(os.path.join(SRC, name), os.path.join(out, name))
    build_engine(os.path.join(out, "engine.zip"), extra)

    files = []
    for folder, _dirs, names in os.walk(out):
        for name in sorted(names):
            path = os.path.join(folder, name)
            rel = os.path.relpath(path, out).replace(os.sep, "/")
            if rel in PAGE or rel == "files.json":
                continue
            files.append({"path": rel, "bytes": os.path.getsize(path), "sha256": sha256(path)})
    files.sort(key=lambda f: f["path"])
    sys.path.insert(0, os.path.join(REPO, "scan"))
    from zbtriage import __version__
    manifest = {"engine_version": __version__, "pyodide": PYODIDE_VERSION, "kev_catalog": kev_version,
                "packages": [lock["packages"][p]["file_name"] for p in PACKAGES], "files": files}
    with open(os.path.join(out, "files.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, indent=1)
        fh.write("\n")
    total = sum(f["bytes"] for f in files)
    print("built {} ({} files, {:.1f} MB loaded by the page)".format(out, len(files), total / 1e6))
    return 0


if __name__ == "__main__":
    sys.exit(main())
