"""Assemble a self-contained test package for testers (no server, no publishing).

    python web/phone/tests/team_package.py FIXTURES_DIR OUT_DIR

OUT_DIR/
  START (Windows).cmd, START (Mac).command, START (Linux).sh
      start a local server with the production security headers and open the page
  phone-check/        the built page (web/phone/dist)
  serve.py            the local server
  sample-backups/     small synthetic backups with known expected results
  program-source/     the scan engine and indicator lists from this branch (for the Wi-Fi check)
  HOW TO TEST.txt
Then zips OUT_DIR next to itself.
"""
import os
import shutil
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
SAMPLES = ("plain-clean", "plain-hit", "encrypted-hit", "parent", "not-a-backup",
           "android-clean", "android-hit", "android-cellebrite")

SERVE_LAUNCH = ('serve.py --dir phone-check --port 8771')

WIN = ("@echo off\r\ncd /d \"%~dp0\"\r\n"
       "where python >nul 2>nul || (echo Python 3 is needed: https://www.python.org/downloads/ & pause & exit /b 1)\r\n"
       "start \"\" http://127.0.0.1:8771/index.html\r\n"
       "echo Phone check running at http://127.0.0.1:8771/index.html - close this window to stop.\r\n"
       "python " + SERVE_LAUNCH + "\r\n")
NIX = ("#!/bin/sh\ncd \"$(dirname \"$0\")\"\n"
       "command -v python3 >/dev/null || { echo 'Python 3 is needed'; exit 1; }\n"
       "( sleep 1; {opener} http://127.0.0.1:8771/index.html ) &\n"
       "echo 'Phone check running at http://127.0.0.1:8771/index.html - press Ctrl+C to stop.'\n"
       "python3 " + SERVE_LAUNCH + "\n")

GUIDE = """ZERO BREACH - PHONE CHECK IN THE BROWSER - TEAM TEST BUILD
============================================================
Private test build. Please do not share this folder or post screenshots of real results.

1. START IT
   Windows: double-click "START (Windows).cmd"   (needs Python 3 from python.org)
   Mac:     double-click "START (Mac).command"   (first time: right-click > Open)
   Linux:   run ./START\\ \\(Linux\\).sh
   Your browser opens http://127.0.0.1:8771/index.html. The page runs only on your computer.
   Try Chrome, Edge, Firefox and Safari if you can.

2. CHECK THE SEAL
   The box under "Why nothing can leave your computer" must turn green and say
   "Sealed: ... your browser blocked it". If it says "Warning", tell us which browser.

3. SAMPLE BACKUPS (made-up phones; the expected result is fixed)
   sample-backups\\plain-clean          -> green  "No known spyware traces found"
   sample-backups\\plain-hit            -> red    "Something needs a closer look" (a planted spyware address)
   sample-backups\\encrypted-hit        -> red; password: fixture-pass   (try a wrong password too: amber, never green)
   sample-backups\\parent               -> asks which of two phones; "New phone" is red, "Old phone" green
   sample-backups\\not-a-backup         -> amber "This phone could not be checked"
   sample-backups\\android-clean        -> grey  "Nothing found in what could be checked"
   sample-backups\\android-hit          -> red    (a planted spyware app)
   sample-backups\\android-cellebrite   -> red    "This phone was unlocked with a phone-forensics tool"
   The made-up iPhones run an old iOS on purpose: you should also see "Update the iPhone".
   Try: drag the folder onto the page instead of using the button; Stop during a check;
   a result in Arabic (right to left); "Save report", "Save full JSON", "Save sharing summary".

4. YOUR OWN PHONE (most useful test)
   Make a real backup as the page explains (iPhone: Finder or Apple Devices app, tick "Encrypt local
   backup"; Android: AndroidQF) and check it. Note how long it took and whether anything looked wrong.
   Nothing is uploaded, but the saved REPORT contains personal details (sites, contacts): keep it
   private. If you report a problem, send the "sharing summary" file, not the full report.

5. WI-FI CHECK (computer program, optional, for people comfortable with a terminal)
   cd program-source
   python scan/zero-breach-toolkit.py --no-menu --no-gui --quick
   Look for "Wi-Fi settings" in the report. It reads saved Wi-Fi settings only: no network is
   joined or scanned and no password is read. Mac and Linux results are the most useful to us.

6. TELL US
   Browser + version, computer (Windows/Mac/Linux), which step, what you expected, what happened,
   and a screenshot of the page (not of a real report).
"""


def main(fixtures, out):
    out = os.path.abspath(out)
    if os.path.isdir(out):
        shutil.rmtree(out)
    os.makedirs(out)
    shutil.copytree(os.path.join(REPO, "web", "phone", "dist"), os.path.join(out, "phone-check"))
    shutil.copyfile(os.path.join(HERE, "serve.py"), os.path.join(out, "serve.py"))
    for name in SAMPLES:
        shutil.copytree(os.path.join(fixtures, name), os.path.join(out, "sample-backups", name))
    src = os.path.join(out, "program-source")
    os.makedirs(src)
    # Only tracked files from the current commit: no notes, caches or personal material.
    archive = subprocess.run(["git", "-C", REPO, "archive", "--format=tar", "HEAD", "scan", "iocs",
                              "README.md", "PRIVACY.md", "LICENSE", "NOTICE"],
                             capture_output=True, check=True).stdout
    import io
    import tarfile
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(src)
    with open(os.path.join(out, "START (Windows).cmd"), "w", newline="") as fh:
        fh.write(WIN)
    for name, opener in (("START (Mac).command", "open"), ("START (Linux).sh", "xdg-open")):
        path = os.path.join(out, name)
        with open(path, "w", newline="\n") as fh:
            fh.write(NIX.replace("{opener}", opener))
        os.chmod(path, 0o755)
    with open(os.path.join(out, "HOW TO TEST.txt"), "w", encoding="utf-8", newline="\r\n") as fh:
        fh.write(GUIDE)
    zip_base = out.rstrip("\\/")
    shutil.make_archive(zip_base, "zip", os.path.dirname(out), os.path.basename(out))
    size = os.path.getsize(zip_base + ".zip")
    print("package:", out)
    print("zip:", zip_base + ".zip", "({:.1f} MB)".format(size / 1e6))


if __name__ == "__main__":
    main(os.path.abspath(sys.argv[1]), sys.argv[2])
