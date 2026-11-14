"""Pin the indicator sources to reviewed upstream commits (maintainers only).

For each source repository, reads the commit at the head of its branch (or the
commit given with --pin owner/repo=SHA), downloads every source file at that
commit, checks that it parses, and rewrites the FEED_PINS / FEED_FILE_SHA256
block in scan/zbtriage/feeds.py. Read the upstream changes before committing
the result: a release then downloads exactly these files.

    python tools/pin_feeds.py            # pin every repository at its branch head
    python tools/pin_feeds.py --check    # verify the recorded pins, change nothing
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "scan"))

from zbtriage import feeds  # noqa: E402

FEEDS_PY = os.path.join(ROOT, "scan", "zbtriage", "feeds.py")
BLOCK = re.compile(r"(?ms)^FEED_PINS = \{\n.*?^\}\nFEED_IOS_ONLY_APP_IDS = \{\n.*?^\}\n"
                   r"FEED_FILE_SHA256 = \{\n.*?^\}\n")

# Sources whose STIX export writes iPhone bundle ids and Android packages alike
# as app ids, and the publisher files at the same commit that tell them apart.
IOS_ID_FILES = {"echap-stalkerware": ("ioc.yaml", "watchware.yaml")}


def branch_head(repo, branch):
    url = "https://api.github.com/repos/{}/commits/{}".format(repo, branch)
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0",
                                               "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode("utf-8"))["sha"]


def file_hashes(pins):
    """SHA-256 of every source file at its pinned commit, after a parse check."""
    out = {}
    with tempfile.TemporaryDirectory() as tmp:
        for src in feeds.all_sources():
            url = feeds.RAW + src["repo"] + "/" + pins[src["repo"]] + "/" + src["path"]
            data = feeds._fetch(url)
            if feeds._looks_like_html(data):
                raise SystemExit("{}: got a web page, not an indicator file".format(src["id"]))
            path = os.path.join(tmp, src["id"] + feeds._EXT[src["format"]])
            with open(path, "wb") as fh:
                fh.write(data)
            count = len(feeds._load_source_file(src, path))
            out[src["id"]] = hashlib.sha256(data).hexdigest()
            print("  {:<40} {:>6} indicators  {}".format(src["id"], count, out[src["id"]][:16]))
    return out


def yaml_lists(text, key):
    """Every item of every `key:` list in a simple YAML file (block lists of
    plain scalars, as the publisher writes them). No YAML library needed."""
    items, inside, indent = [], False, 0
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        depth = len(line) - len(line.lstrip())
        if inside and stripped.startswith("- ") and depth >= indent:
            items.append(stripped[2:].strip().strip("'\"").lower())
            continue
        inside = stripped == key + ":"
        indent = depth
    return items


def ios_only_ids(pins):
    """{source id: sorted app ids the publisher lists only as iPhone bundles}."""
    out = {}
    for sid, names in IOS_ID_FILES.items():
        src = next(s for s in feeds.SOURCES if s["id"] == sid)
        ios, android = set(), set()
        for name in names:
            url = feeds.RAW + src["repo"] + "/" + pins[src["repo"]] + "/" + name
            text = feeds._fetch(url).decode("utf-8")
            ios.update(yaml_lists(text, "ios_bundles"))
            android.update(yaml_lists(text, "packages"))
        out[sid] = sorted(ios - android)
        print("  {}: {} iPhone-only bundle ids".format(sid, len(out[sid])))
    return out


def render(pins, hashes, ios_ids):
    lines = ["FEED_PINS = {"]
    lines += ['    "{}": "{}",'.format(k, pins[k]) for k in sorted(pins)]
    lines += ["}", "FEED_IOS_ONLY_APP_IDS = {"]
    for sid in sorted(ios_ids):
        lines.append('    "{}": ['.format(sid))
        lines += ['        "{}",'.format(v) for v in ios_ids[sid]]
        lines.append("    ],")
    lines += ["}", "FEED_FILE_SHA256 = {"]
    lines += ['    "{}": "{}",'.format(k, hashes[k]) for k in sorted(hashes)]
    lines += ["}", ""]
    return "\n".join(lines)


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    p.add_argument("--check", action="store_true",
                   help="download at the recorded pins and compare; change nothing")
    p.add_argument("--pin", action="append", default=[], metavar="OWNER/REPO=SHA",
                   help="pin one repository to a given commit instead of its branch head")
    args = p.parse_args(argv)
    repos = {}
    for src in feeds.all_sources():
        repos[src["repo"]] = src["url"][len(feeds.RAW + src["repo"]) + 1:].split("/", 1)[0]
    if args.check:
        missing = sorted(set(repos) - set(feeds.FEED_PINS))
        if missing:
            raise SystemExit("not pinned: " + ", ".join(missing))
        hashes = file_hashes(feeds.FEED_PINS)
        if ios_only_ids(feeds.FEED_PINS) != {k: list(v) for k, v in feeds.FEED_IOS_ONLY_APP_IDS.items()}:
            raise SystemExit("recorded iPhone-only app ids differ from the pinned publisher files")
        wrong = sorted(k for k in hashes if feeds.FEED_FILE_SHA256.get(k) != hashes[k])
        if wrong or set(feeds.FEED_FILE_SHA256) != set(hashes):
            raise SystemExit("recorded hashes differ for: " + ", ".join(wrong or ["(source list)"]))
        print("all {} sources match their pinned hashes".format(len(hashes)))
        return 0
    given = dict(item.split("=", 1) for item in args.pin)
    pins = {}
    for repo, branch in sorted(repos.items()):
        pins[repo] = given.get(repo) or branch_head(repo, branch)
        if not re.fullmatch(r"[0-9a-f]{40}", pins[repo]):
            raise SystemExit("{}: not a full commit SHA: {}".format(repo, pins[repo]))
        print("{} @ {}".format(repo, pins[repo]))
    hashes = file_hashes(pins)
    ios_ids = ios_only_ids(pins)
    text = open(FEEDS_PY, encoding="utf-8").read()
    if len(BLOCK.findall(text)) != 1:
        raise SystemExit("feeds.py: pinned-revision block not found exactly once")
    text = BLOCK.sub(lambda _m: render(pins, hashes, ios_ids), text)
    with open(FEEDS_PY, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    print("wrote {} pins and {} file hashes to feeds.py".format(len(pins), len(hashes)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
