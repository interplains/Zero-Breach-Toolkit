"""Black-box check of a packaged program against the single-file build.

    python tools/program_smoke.py PROGRAM [SINGLE_FILE]

Builds harmless fixtures and scans them with PROGRAM and with the single-file
Python build through the command line only, and requires both to agree:

  - a Chromium profile whose history visited a synthetic .invalid domain, and a
    file whose SHA-256 is listed as an indicator;
  - an unencrypted iPhone backup whose text message names that domain;
  - an ENCRYPTED iPhone backup, scanned without a password. The program must
    give the same gap as the single file ("needs --backup-password"). The
    single file gets that message only when the Python running it has
    cryptography, so a program built without the library fails here. The
    correct-password finding cannot be automated: the password is read only
    from a private interactive terminal, by design.

Nothing here touches the network or the machine's own records. Exits non-zero
on any difference.
"""
import contextlib
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOMAIN = "program-smoke.invalid"
PAYLOAD = b"Harmless Zero Breach program check bytes; not malware.\n"
NEEDS_PASSWORD = "needs --backup-password"


def fixture(base):
    profile = os.path.join(base, "target", "User Data", "Default")
    os.makedirs(profile)
    with open(os.path.join(base, "target", "User Data", "Local State"), "w", encoding="utf-8") as fh:
        fh.write("{}")
    with contextlib.closing(sqlite3.connect(os.path.join(profile, "History"))) as db:
        db.execute("CREATE TABLE urls(url TEXT,title TEXT,last_visit_time INTEGER)")
        db.execute("INSERT INTO urls VALUES(?,?,?)", ("https://" + DOMAIN + "/", "", 13000000000000000))
        db.commit()
    with open(os.path.join(base, "target", "sample.bin"), "wb") as fh:
        fh.write(PAYLOAD)
    feed = os.path.join(base, "feed.txt")
    with open(feed, "w", encoding="utf-8") as fh:
        fh.write(DOMAIN + "\tinfrastructure\tprimary\tprogram-smoke\n")
        fh.write(hashlib.sha256(PAYLOAD).hexdigest() + "\tsample\tprimary\tprogram-smoke\n")
    return os.path.join(base, "target"), feed


def iphone_fixtures(base):
    """Plain and encrypted iPhone backups, built with the test suite's own writer
    (scan/tests/test_ios_upgrade.py) so the bytes match what the scanner is tested
    against. Encrypting needs cryptography in the Python that runs this script."""
    sys.path[:0] = [os.path.join(ROOT, "scan"), os.path.join(ROOT, "scan", "tests")]
    from test_ios_upgrade import backup, db_bytes
    sms, _ = db_bytes(Path(base), "CREATE TABLE message(text,date,is_from_me)",
                      [("INSERT INTO message VALUES(?,700000000,0)", ("https://" + DOMAIN + "/",))])
    items = [("HomeDomain", "Library/SMS/sms.db", sms)]
    plain = Path(base, "iphone-plain")
    encrypted = Path(base, "iphone-encrypted")
    backup(plain, items)
    backup(encrypted, items, encrypted=True, modern=True)
    return str(plain), str(encrypted)


def scan(command, base, name, args, feed):
    report = os.path.join(base, name + ".json")
    proc = subprocess.run(command + args + ["--iocs", feed,
                                            "--no-banner", "--no-pause", "--no-menu", "--no-feeds",
                                            "--json", report],
                          stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=600)
    if not os.path.isfile(report):
        sys.exit("{}: no report written (exit {})\n{}".format(
            name, proc.returncode, proc.stdout.decode("utf-8", "replace")[-3000:]))
    with open(report, encoding="utf-8") as fh:
        doc = json.load(fh)
    hits = sorted({(h["indicator"], h["evidence"]) for m in doc["modules"].values() for h in m["hits"]})
    gaps = sorted(doc.get("verdict", {}).get("gaps", []))
    return proc.returncode, hits, gaps, doc


def pair(program, single, base, label, args, feed):
    """Scan one fixture with both builds; returns (program result, single-file result)."""
    return (scan([program], base, label + "-program", args, feed),
            scan([sys.executable, "-X", "utf8", single], base, label + "-single", args, feed))


def main():
    program = os.path.abspath(sys.argv[1])
    single = os.path.abspath(sys.argv[2]) if len(sys.argv) > 2 else os.path.join(ROOT, "dist", "zero-breach-toolkit.py")
    problems = []
    with tempfile.TemporaryDirectory(prefix="zbt-program-smoke-") as base:
        target, feed = fixture(base)
        plain, encrypted = iphone_fixtures(base)

        (code_p, hits_p, _g, doc_p), (code_s, hits_s, _gs, _d) = pair(
            program, single, base, "files", ["--scan-type", "targeted", "--target", target], feed)
        print("program exit {} hits {}".format(code_p, hits_p))
        print("single  exit {} hits {}".format(code_s, hits_s))
        indicators = {i for i, _e in hits_p}
        if DOMAIN not in indicators:
            problems.append("the planted history visit was not found")
        if hashlib.sha256(PAYLOAD).hexdigest() not in indicators:
            problems.append("the planted file fingerprint was not found")
        if hits_p != hits_s or code_p != code_s:
            problems.append("program and single-file results differ")

        (code_p, hits_p, _g, _d), (code_s, hits_s, _gs, _d) = pair(
            program, single, base, "iphone-plain", ["--phone", plain], feed)
        print("iPhone plain: program exit {} hits {}".format(code_p, hits_p))
        print("iPhone plain: single  exit {} hits {}".format(code_s, hits_s))
        if DOMAIN not in {i for i, _e in hits_p}:
            problems.append("the planted iPhone message was not found")
        if hits_p != hits_s or code_p != code_s:
            problems.append("iPhone plain backup: program and single-file results differ")

        (code_p, hits_p, gaps_p, _d), (code_s, hits_s, gaps_s, _d) = pair(
            program, single, base, "iphone-encrypted", ["--phone", encrypted], feed)
        print("iPhone encrypted, no password: program exit {} gaps {}".format(code_p, gaps_p))
        print("iPhone encrypted, no password: single  exit {} gaps {}".format(code_s, gaps_s))
        if not any(NEEDS_PASSWORD in g for g in gaps_s):
            problems.append("the single-file build did not report the encrypted backup as needing a password")
        if gaps_p != gaps_s or code_p != code_s or hits_p != hits_s:
            problems.append("encrypted iPhone backup: program does not match the single file "
                            "(is cryptography bundled in the program?)")

        if problems:
            sys.exit("FAIL: " + "; ".join(problems))
        print("PASS: program and single-file build agree on files, iPhone and encrypted iPhone fixtures "
              "({})".format((str(doc_p.get("tool", "")) + str(doc_p.get("version", "")))[:80]))


if __name__ == "__main__":
    main()
