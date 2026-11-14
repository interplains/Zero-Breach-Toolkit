"""Check that a packaged program carries the Bluetooth tracker check.

    python tools/bluetooth_smoke.py PROGRAM

Runs PROGRAM --trackers 1 and reads what it says. Build machines usually have no Bluetooth radio, so a
program that carries the library tries to listen and reports that Bluetooth could not be used (or listens
and reports what it heard). It fails when the library is missing ("needs the optional Bluetooth library"),
when part of it was left out of the package ("No module named ..."), or when the program is stopped by the
system (on macOS that happens when the app does not declare why it uses Bluetooth). The tracker history is
written to a throwaway folder. Only receives; nothing is sent.
"""
import os
import subprocess
import sys
import tempfile

MISSING = ("needs the optional Bluetooth library", "No module named", "ModuleNotFoundError", "ImportError")


def main():
    program = os.path.abspath(sys.argv[1])
    home = tempfile.mkdtemp(prefix="zb_bt_")
    env = dict(os.environ, LOCALAPPDATA=home, XDG_CACHE_HOME=home, HOME=home)
    try:
        done = subprocess.run([program, "--trackers", "1", "--no-menu", "--no-banner"], env=env,
                              capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180)
        out, code, timed_out = done.stdout + done.stderr, done.returncode, False
    except subprocess.TimeoutExpired as exc:
        out = ((exc.stdout or b"").decode("utf-8", "replace") if isinstance(exc.stdout, bytes) else exc.stdout or "")
        out += ((exc.stderr or b"").decode("utf-8", "replace") if isinstance(exc.stderr, bytes) else exc.stderr or "")
        code, timed_out = None, True
    print(out[-3000:])
    if any(m in out for m in MISSING):
        sys.exit("FAIL: the Bluetooth library is missing from the program")
    if "Listening for Bluetooth trackers" not in out:
        sys.exit("FAIL: the tracker check did not start (exit {})".format(code))
    if code is not None and code < 0 or code in (134, 137, 139):
        sys.exit("FAIL: the program was stopped by the system (exit {})".format(code))
    if timed_out:
        print("PASS (the library loaded; this machine kept waiting for Bluetooth, which build machines may do)")
    elif "BLUETOOTH TRACKER CHECK" in out:
        print("PASS: listened and reported")
    elif "Bluetooth could not be used" in out:
        print("PASS: the library loaded; this machine has no usable Bluetooth")
    else:
        sys.exit("FAIL: unexpected result (exit {})".format(code))


if __name__ == "__main__":
    main()
