#!/usr/bin/env python3
"""Small, offline pre-release gate. Never runs a scan against the real host."""
import argparse
import hashlib
from html.parser import HTMLParser
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
CASES = ("clean", "contact", "reference", "hash", "corrupt", "hit-and-gap", "quick",
         "dns-cap-hit", "dns-cap-gap", "dns-off-retained-hit", "dns-off-retained-clean",
         "dns-off-unreadable", "dns-off-empty", "bad-feed", "patterns", "patterns-localserver", "phone-process", "unicode-report", "ios-row-recovery",
         "history-host-reference", "workflow-handoff", "windows-records", "android-intrusion",
         "linux-startup", "macos-startup", "ios-wal", "ios-sysdiagnose",
         "antivirus-active", "antivirus-unknown")


class DownloadPanel(HTMLParser):
    """Read code/copy values from the actual verification card, not comments."""
    def __init__(self):
        super().__init__()
        self.depth = 0
        self.group_depth = None
        self.group = None
        self.capture = None
        self.cards = 0
        self.groups = []

    def handle_starttag(self, tag, attributes):
        attrs = dict(attributes)
        if tag == "div":
            if attrs.get("id") == "verify-download":
                self.cards += 1
                self.depth = 1
            elif self.depth:
                self.depth += 1
            if self.depth and "ea-copy" in attrs.get("class", "").split():
                self.group = {"code": "", "label": "", "copy": None}
                self.groups.append(self.group)
                self.group_depth = self.depth
        elif self.group is not None and tag in ("code", "button"):
            self.capture = "code" if tag == "code" else "label"
            if tag == "button":
                self.group["copy"] = attrs.get("data-copy")

    def handle_endtag(self, tag):
        if tag in ("code", "button"):
            self.capture = None
        if tag == "div" and self.depth:
            if self.depth == self.group_depth:
                self.group = None
                self.group_depth = None
            self.depth -= 1

    def handle_data(self, text):
        if self.group is not None and self.capture:
            self.group[self.capture] += text


def check_web_checksum(html, digest):
    panel = DownloadPanel()
    panel.feed(html)
    candidates = [g for g in panel.groups if g["label"].strip() == "Copy SHA-256"]
    if panel.cards != 1 or len(candidates) != 1:
        raise RuntimeError("Scan page must have one verification card and SHA-256 copy control")
    value = candidates[0]
    if value["code"].strip() != digest or value["copy"] != digest:
        raise RuntimeError("Scan page displayed/copied checksum differs from the candidate download")


def release_web_directory(supplied, required=False):
    web = supplied
    if web is None and (ROOT / "web/scan").is_dir():
        web = ROOT / "web/scan"
    if web is None and required:
        raise RuntimeError("Website verification required; supply --web-dir with the scan-page source")
    return web


def check_downloaded_scanner(path, digest):
    # A separately saved download is data, never imported or executed here.
    actual = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            actual.update(chunk)
    if actual.hexdigest() != digest:
        raise RuntimeError("Downloaded scanner differs from the candidate build")


def check_backup_dependency():
    if importlib.util.find_spec("cryptography") is None:
        raise RuntimeError("Encrypted-backup coverage requires the pinned requirements-backups.txt dependency")
    from importlib.metadata import version
    # One pinned version per platform (selected by an environment marker when
    # pip installs it); the installed version must be one of them.
    required = {line.split("==", 1)[1].split()[0].rstrip("\\").strip() for line in
                (ROOT / "requirements-backups.txt").read_text(encoding="utf-8").splitlines()
                if line.startswith("cryptography==")}
    if version("cryptography") not in required:
        raise RuntimeError("Optional backup dependency differs from requirements-backups.txt")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require-patterns", action="store_true",
                        help="require the pinned optional engine (use for releases)")
    parser.add_argument("--e2e-only", action="store_true",
                        help="CI: unit suite already ran in the same job")
    parser.add_argument("--scanner", type=Path,
                        help="also require this staged download to match the fresh build")
    parser.add_argument("--web-dir", type=Path,
                        help="Scan-page directory; require its logic test and checksum to pass")
    parser.add_argument("--require-web", action="store_true",
                        help="fail instead of skipping when the scan-page source is unavailable")
    parser.add_argument("--downloaded-scanner", type=Path,
                        help="also compare a separately saved public download with the candidate; never execute it")
    parser.add_argument("--require-backups", action="store_true",
                        help="require the pinned encrypted-backup dependency")
    parser.add_argument("--output-dir", type=Path,
                        default=ROOT / "findings" / "release-checks")
    args = parser.parse_args()
    output = args.output_dir.resolve()
    output.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    steps = []
    summary = {"status": "FAIL", "steps": steps, "skipped": [],
               "scope": "Offline fixtures; OS collection is simulated; no personal scan"}
    env = dict(os.environ, PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1")

    def run(name, command, timeout=60, environment=None):
        tick = time.monotonic()
        try:
            proc = subprocess.run(command, cwd=ROOT, env=environment or env, stdin=subprocess.DEVNULL,
                                  stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  timeout=timeout)
            text = proc.stdout.decode("utf-8", errors="replace")
            (output / (name + ".log")).write_text(text, encoding="utf-8")
            if proc.returncode:
                raise RuntimeError("{} failed (exit {}); see {}".format(
                    name, proc.returncode, output / (name + ".log")))
        except subprocess.TimeoutExpired:
            raise RuntimeError("{} exceeded {}s; release check failed".format(name, timeout))
        steps.append({"name": name, "seconds": round(time.monotonic() - tick, 2)})
        print("PASS {} ({:.1f}s)".format(name, time.monotonic() - tick), flush=True)

    try:
        web = release_web_directory(args.web_dir, args.require_web)
        if args.require_backups:
            check_backup_dependency()
        sys.path.insert(0, str(ROOT / "scan"))
        from zbtriage.candiru_rules import CANDIRU_ENGINE_VERSION
        engine = importlib.util.find_spec("yara_x") is not None
        if engine:
            from importlib.metadata import version
            if version("yara-x") != CANDIRU_ENGINE_VERSION:
                raise RuntimeError("optional engine version differs from requirements-patterns.txt")
        elif args.require_patterns:
            raise RuntimeError("pinned YARA-X missing; install requirements-patterns.txt "
                               "in this interpreter's virtual environment first")
        else:
            summary["skipped"].append("Real YARA-X positives: engine not installed")

        if not args.e2e_only:
            # Snapshot-cleanup tests inspect the temp directory. Separate
            # release runs must not see each other's transient snapshots.
            with tempfile.TemporaryDirectory(prefix="zb_unit_") as unit_temp:
                unit_env = dict(env, TMP=unit_temp, TEMP=unit_temp, TMPDIR=unit_temp)
                # The limit catches a hung test, not a slow machine: the suite passed 3,500 tests and
                # several minutes, so 180 s failed the gate on its own.
                run("unit-tests", [sys.executable, "-B", "-m", "pytest", "-q",
                                   "scan/tests"], timeout=600, environment=unit_env)

        with tempfile.TemporaryDirectory(prefix="zb_release_") as temp:
            work = Path(temp)
            first, second = work / "scanner.py", work / "scanner-again.py"
            for name, path in (("build", first), ("rebuild", second)):
                run(name, [sys.executable, "-B", str(ROOT / "build/bundle.py"),
                           str(ROOT), str(path)])
            if first.read_bytes() != second.read_bytes():
                raise RuntimeError("two single-file builds differ")
            digest = hashlib.sha256(first.read_bytes()).hexdigest()
            summary["scanner_sha256"] = digest
            if args.downloaded_scanner:
                check_downloaded_scanner(args.downloaded_scanner, digest)
                steps.append({"name": "downloaded-scanner-checksum", "seconds": 0})
            scanner = first
            if args.scanner:
                scanner = args.scanner.resolve()
                if scanner.read_bytes() != first.read_bytes():
                    raise RuntimeError("staged scanner differs from the tested source build")
            run("scanner-help", [sys.executable, "-B", str(scanner), "--help"])
            run("scanner-version", [sys.executable, "-B", str(scanner), "--version"])

            for case in CASES:
                pair = []
                for target in ("source", "bundle"):
                    case_root = work / (target + "-" + case)
                    result = case_root / "result.json"
                    run(target + "-" + case,
                        [sys.executable, "-B", str(ROOT / "tools/release_fixture.py"),
                         target, case, str(case_root), str(scanner)], timeout=45)
                    pair.append(json.loads(result.read_text(encoding="utf-8")))
                if pair[0] != pair[1]:
                    raise RuntimeError("source/download results disagree for " + case)

            if web is not None:
                web = web.resolve()
                test = web / "ops/test_scan_logic.js"
                if not all((web / name).is_file() for name in
                           ("index.html", "scan.js", "ops/test_scan_logic.js")) or not shutil.which("node"):
                    raise RuntimeError("web check requires Node, index.html, scan.js and ops/test_scan_logic.js")
                run("web-logic", ["node", str(test)])
                html = (web / "index.html").read_text(encoding="utf-8")
                check_web_checksum(html, digest)
                steps.append({"name": "web-download-checksum", "seconds": 0})
            else:
                summary["skipped"].append("Website: separate site source not supplied (--web-dir)")

        summary["status"] = "PASS_WITH_SKIPS" if summary["skipped"] else "PASS"
        print("\nPASS: source/download fixtures agree; inputs unchanged; "
              "no socket/subprocess activity during fixture scans.")
        for skip in summary["skipped"]:
            print("NOT RUN: " + skip)
        print("Scanner SHA-256: " + digest)
        return 0
    except (OSError, RuntimeError, ValueError) as exc:
        summary["error"] = str(exc)
        print("\nFAIL: " + str(exc), file=sys.stderr)
        return 1
    finally:
        summary["seconds"] = round(time.monotonic() - started, 2)
        (output / "summary.json").write_text(
            json.dumps(summary, indent=2) + "\n", encoding="utf-8")
        print("Results: " + str(output / "summary.json"))


if __name__ == "__main__":
    raise SystemExit(main())
