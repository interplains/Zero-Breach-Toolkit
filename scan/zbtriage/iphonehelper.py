"""--make-iphone-backup FOLDER (Linux): make an encrypted iPhone backup without Apple's app, then check it.

Linux has no Apple app for backups. This uses pymobiledevice3 (GPL-3.0-or-later), run as a separate
program in its own folder - it is never imported into Zero Breach, so its licence stays its own. It is
installed only when this command runs and the person agrees, into
~/.local/share/zero-breach-toolkit/iphone-helper-<pin>/, with every file checked against the SHA-256
hashes in requirements-iphone-backup.txt (pip --require-hashes --no-deps --only-binary=:all:): nothing
unpinned and nothing built from source. Re-runs reuse the verified folder.

The backup password is typed privately and handed to the helper on its standard input, never on its
command line (where other programs on the computer could read it).
"""
from __future__ import annotations

import getpass
import hashlib
import os
import re
import shutil
import subprocess
import sys
import tempfile

from .contract import sanitize_untrusted
from .localpaths import path_problem
from .iphonehelper_reqs import IH_REQUIREMENTS, IH_REQUIREMENTS_SHA256

IH_PIN = "pymobiledevice3-11.50.2"
IH_USBMUXD_SOCKET = "/var/run/usbmuxd"
IH_MARKER = "zero-breach-verified.txt"

# Runs inside the helper's own Python. Reads the password from standard input (one line), turns backup
# encryption on with it when encryption is off, then makes a full backup into the folder given.
IH_DRIVER = r'''
import asyncio
import sys
from pymobiledevice3.lockdown import create_using_usbmux
from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service


async def main():
    password = sys.stdin.readline().rstrip("\n")
    folder = sys.argv[1]
    lockdown = await create_using_usbmux()
    info = lockdown.short_info
    print("PHONE " + str(info.get("DeviceName", "")) + " | iOS " + str(info.get("ProductVersion", "")), flush=True)
    async with Mobilebackup2Service(lockdown) as backup:
        if await backup.get_will_encrypt():
            print("ENCRYPTION ALREADY ON", flush=True)
        else:
            await backup.change_password(folder, new=password)
            print("ENCRYPTION ON", flush=True)
    async with Mobilebackup2Service(lockdown) as backup:
        await backup.backup(full=True, backup_directory=folder,
                            progress_callback=lambda p: print("PROGRESS {:.0f}".format(p), flush=True))
    print("DONE " + str(lockdown.udid), flush=True)


asyncio.run(main())
'''


# The helper's own error names (pymobiledevice3.exceptions) -> what the person should do.
IH_ERRORS = (
    ("ConnectionFailedToUsbmuxdError", "the iPhone USB service (usbmuxd) is not running - start it, e.g. "
                                       "sudo systemctl start usbmuxd"),
    ("NoDeviceConnectedError", "no iPhone was found - connect it with a cable and unlock it"),
    ("DeviceNotFoundError", "no iPhone was found - connect it with a cable and unlock it"),
    ("NotTrustedError", "the iPhone has not trusted this computer - unlock it and tap Trust"),
    ("PasswordRequiredError", "the iPhone is locked - unlock it, tap Trust, and try again"),
    ("PairingError", "the iPhone did not pair with this computer - unlock it, tap Trust, and try again"),
    ("NotPairedError", "the iPhone did not pair with this computer - unlock it, tap Trust, and try again"),
)


def ih_home():
    base = os.environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share")
    return os.path.join(base, "zero-breach-toolkit", "iphone-helper-" + IH_PIN)


def ih_python(home):
    return os.path.join(home, "bin", "python")


def ih_requirements_text():
    text = "".join(IH_REQUIREMENTS)
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != IH_REQUIREMENTS_SHA256:
        raise ValueError("the pinned helper list inside this program is damaged; nothing was installed")
    return text


def ih_clean_env():
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("PYTHON", "PIP_", "LD_", "VIRTUAL_ENV"))}
    env["PIP_DISABLE_PIP_VERSION_CHECK"] = "1"
    return env


def ih_installed(home):
    try:
        with open(os.path.join(home, IH_MARKER), "r", encoding="utf-8") as fh:
            return fh.read().strip() == IH_REQUIREMENTS_SHA256 and os.path.isfile(ih_python(home))
    except OSError:
        return False


def ih_system_python():
    """A real Python 3 to build the helper with. In the packaged program sys.executable is the toolkit itself
    (PyInstaller), which cannot run '-m venv', so the system's python3 is used instead."""
    if not getattr(sys, "frozen", False):
        return sys.executable
    for name in ("python3", "python"):
        path = shutil.which(name)
        if path:
            return path
    return ""


def ih_install(home, run=subprocess.run, out=print):
    """Create the helper's own Python environment and install the pinned files. Raises ValueError."""
    text = ih_requirements_text()
    if os.path.isdir(home) and not ih_installed(home):
        shutil.rmtree(home)                       # a half-finished earlier install: start clean
    os.makedirs(os.path.dirname(home), exist_ok=True)
    out("Setting up the backup helper (first time only; about 350 MB)...")
    env = ih_clean_env()
    base = ih_system_python()
    if not base:
        raise ValueError("no Python 3 was found to build the helper with (on Debian/Ubuntu: sudo apt install python3 "
                         "python3-venv)")
    # -I everywhere: the folder the person runs this from must never be able to supply 'venv' or 'pip'
    if run([base, "-I", "-m", "venv", home], env=env, cwd=os.path.dirname(home)).returncode:
        raise ValueError("Python could not create the helper's folder (on Debian/Ubuntu: sudo apt install python3-venv)")
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as fh:
        fh.write(text)
        req = fh.name
    try:
        done = run([ih_python(home), "-I", "-m", "pip", "install", "--quiet", "--require-hashes", "--no-deps",
                    "--only-binary=:all:", "-r", req], env=env, cwd=home)
    finally:
        os.remove(req)
    if done.returncode:
        shutil.rmtree(home, ignore_errors=True)
        raise ValueError("the helper could not be installed with every file verified, so nothing was installed. "
                         "Your Python may be too new or too old for the pinned files (tested with Python 3.11 and 3.12)")
    with open(os.path.join(home, IH_MARKER), "w", encoding="utf-8") as fh:
        fh.write(IH_REQUIREMENTS_SHA256 + "\n")


def ih_new_password(ask=getpass.getpass, out=print):
    for _ in range(3):
        first = ask("Choose a backup password (not shown, not saved): ")
        if len(first) < 6:
            out("Use at least 6 characters.")
            continue
        if ask("Type it again: ") == first:
            return first
        out("The two did not match.")
    raise ValueError("no password was chosen; nothing was done")


def ih_find_backup(destination, udid):
    """The backup folder the helper wrote, checked to look like a finished backup."""
    folder = os.path.join(destination, udid)
    if not (os.path.isfile(os.path.join(folder, "Manifest.plist"))
            and (os.path.isfile(os.path.join(folder, "Manifest.db")))):
        raise ValueError("the helper finished but no complete backup was found in " + destination)
    return folder


def make_iphone_backup(destination, run=subprocess.run, popen=subprocess.Popen, ask=getpass.getpass, out=print):
    """Returns (backup folder or None, password, exit code)."""
    if not sys.platform.startswith("linux"):
        out("This command is for Linux. On Windows and Mac, Apple's own app makes the backup: in the window, "
            "press \"Make an iPhone backup...\" on the phone screen.")
        return None, "", 1
    if not sys.stdin.isatty():
        out("This needs an interactive terminal and the phone owner's consent.")
        return None, "", 1
    destination = os.path.abspath(destination)
    problem = path_problem(destination)
    if problem or sanitize_untrusted(destination) != destination:
        out("Backup folder refused: " + (problem or "unsupported characters"))
        return None, "", 1
    if os.path.isdir(destination) and os.listdir(destination):
        out("Choose an empty or new folder for the backup: " + destination + " is not empty.")
        return None, "", 1
    if not os.path.exists(IH_USBMUXD_SOCKET):
        out("The iPhone USB service (usbmuxd) is not running. Install and start it, then connect the iPhone:\n"
            "  Debian/Ubuntu: sudo apt install usbmuxd     Fedora: sudo dnf install usbmuxd\n"
            "  Arch: sudo pacman -S usbmuxd")
        return None, "", 1
    home = ih_home()
    out("MAKE AN iPHONE BACKUP\n"
        "  This makes a full, ENCRYPTED backup of the iPhone into " + destination + ", then checks it.\n"
        "  " + ("It will download and verify a backup helper (pymobiledevice3, about 350 MB, every file "
                "checked against a pinned fingerprint) into " + home + ".\n" if not ih_installed(home) else
                "It uses the backup helper already verified in " + home + ".\n") +
        "  Connect the iPhone with a cable, unlock it, and tap \"Trust\" when it asks.\n"
        "  If backup encryption is already on, you need its existing password. If nobody remembers it, the only\n"
        "  way to reset it is on the iPhone: Settings > General > Transfer or Reset iPhone > Reset >\n"
        "  Reset All Settings (keeps photos, messages and apps).")
    try:
        consent = input("Do you own this iPhone or have its owner's explicit consent? Type YES to continue: ").strip()
    except (EOFError, KeyboardInterrupt):
        consent = ""
    if consent != "YES":
        out("Not started. Nothing was downloaded or changed.")
        return None, "", 1
    proc = None
    try:
        if not ih_installed(home):
            ih_install(home, run=run, out=out)
        password = ih_new_password(ask=ask, out=out)
        os.makedirs(destination, exist_ok=True)
        out("Backing up. Keep the iPhone connected and unlocked; the phone may ask for its passcode.")
        proc = popen([ih_python(home), "-I", "-c", IH_DRIVER, destination], stdin=subprocess.PIPE,
                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=ih_clean_env(), cwd=home)
        proc.stdin.write(password + "\n")
        proc.stdin.close()
        udid, last, already, reason = "", -1, False, ""
        for line in proc.stdout:
            line = sanitize_untrusted(line.rstrip("\n"))[:300]
            for marker, why in IH_ERRORS:
                if marker in line:
                    reason = why
            if line.startswith("PROGRESS "):
                try:
                    value = float(line.split()[1])
                except (IndexError, ValueError):
                    continue
                if value != value or value in (float("inf"), float("-inf")):
                    continue                                    # nan / inf: ignore, never crash
                step = int(max(0.0, min(100.0, value)) // 10) * 10
                if step != last:
                    out("  {}%".format(step))
                    last = step
            elif line.startswith("DONE "):
                candidate = line.split(" ", 1)[1].strip()
                # A device id is hex with optional dashes; anything else must not become a path.
                if re.fullmatch(r"[0-9A-Fa-f-]{20,64}", candidate):
                    udid = candidate
            elif line.startswith("PHONE "):
                out("  Phone: " + line[6:])
            elif line == "ENCRYPTION ON":
                out("  Backup encryption is now on, with the password you chose.")
            elif line == "ENCRYPTION ALREADY ON":
                already = True
                out("  Backup encryption was already on: the backup uses its EXISTING password, not the one you "
                    "just typed. You will be asked for the existing one to check it.")
        if proc.wait() or not udid:
            raise ValueError("the backup did not finish: {}. Any partial files are in {}".format(
                reason or "is the iPhone connected, unlocked and trusted?", destination))
        folder = ih_find_backup(destination, udid)
        out("Backup finished: " + folder)
        return folder, "" if already else password, 0
    except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt) as exc:
        out("Backup stopped: {}".format(exc))
        return None, "", 1
    finally:
        if proc is not None and getattr(proc, "poll", lambda: 0)() is None:
            proc.kill()                                         # never leave the helper running
