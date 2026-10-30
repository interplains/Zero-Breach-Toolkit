"""Explicit Android acquisition, separate from offline scanning.

Official AndroidQF v1.8.3 release assets, pinned to the publisher's SHA-256
digests. No external program or network request is made unless this command
is invoked and the owner confirms consent in an interactive terminal.
"""
import hashlib
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile
import base64
import zlib

from .feeds import _certificate_help, _certificate_problem
from .localpaths import path_problem, local_temp_dir, walk_local
from .contract import sanitize_untrusted

_PHONE_RELEASE = "https://github.com/mvt-project/androidqf/releases/download/v1.8.3/"
_PHONE_ASSETS = {
    ("win32", "amd64"): ("androidqf_windows_amd64_1.8.3_unsigned.exe", "2a5aa89b8aa2145d1246372ef3310ffd1e6d8a457c59b0a232c3de79892d4650"),
    ("linux", "amd64"): ("androidqf_linux_amd64_1.8.3", "59e6071fd41c4cee71f31f9a179ac3ebf9e783cece8422d89a73452335369ebe"),
    ("linux", "arm64"): ("androidqf_linux_arm64_1.8.3", "c2c729058e4cb96150e98b0a9f1ab211e179743a4e5d64dd37a3e9f3fd49d619"),
    ("darwin", "universal"): ("androidqf_macos_universal_1.8.3_signed", "466156b828472a9e81485829ca7e2e853f7ca068b799e21aafca59e998f3b89b"),
}
_PHONE_DOWNLOAD_LIMIT = 128 * 1024 * 1024
_PHONE_ARCHIVE_LIMIT = 10 * 1024 * 1024 * 1024


def _phone_download_url_ok(url):
    parsed = urllib.parse.urlsplit(url)
    return (parsed.scheme == "https" and not parsed.username and not parsed.password
            and parsed.port in (None, 443) and parsed.hostname in
            {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"})


class _PhoneRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not _phone_download_url_ok(newurl):
            raise ValueError("collector download redirected outside the official release hosts")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _phone_download(asset, digest, dest):
    if not re.fullmatch(r"androidqf_[A-Za-z0-9_.]+", asset) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("invalid pinned collector metadata")
    problem = path_problem(os.path.abspath(dest))
    if problem:
        raise ValueError("download path refused: " + problem)
    opener = urllib.request.build_opener(_PhoneRedirect())
    req = urllib.request.Request(_PHONE_RELEASE + asset, headers={"User-Agent": "Mozilla/5.0"})
    actual, count = hashlib.sha256(), 0
    with opener.open(req, timeout=60) as response, open(dest, "xb") as out:
        if not _phone_download_url_ok(response.geturl()):
            raise ValueError("untrusted collector download origin")
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            count += len(chunk)
            if count > _PHONE_DOWNLOAD_LIMIT:
                raise ValueError("collector download exceeds size limit")
            actual.update(chunk)
            out.write(chunk)
    if actual.hexdigest() != digest:
        raise ValueError("collector SHA-256 does not match the pinned release; nothing was launched")
    os.chmod(dest, 0o700)


def _phone_extract(archive, destination):
    """Bounded ZIP extraction; no links, device paths, traversal or overwrites."""
    for value in (archive, destination):
        if path_problem(os.path.abspath(value)):
            raise ValueError("acquisition path refused")
    # Bound the ZIP directory before ZipFile materialises it. End records have
    # fixed-size fields; ZIP64 offsets are read without allocating their payload.
    info = os.stat(archive, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_size > _PHONE_ARCHIVE_LIMIT:
        raise ValueError("acquisition archive is not a regular file or is too large")
    with open(archive, "rb") as source:
        source.seek(max(0, info.st_size - 65557))
        tail = source.read(65557)
        offset = tail.rfind(b"PK\x05\x06")
        if offset < 0 or len(tail) - offset < 22:
            raise ValueError("missing ZIP end record")
        disk, cd_disk, disk_count, members, directory_bytes, directory_offset, comment = struct.unpack_from("<4H2IH", tail, offset + 4)
        if offset + 22 + comment != len(tail) or disk or cd_disk:
            raise ValueError("unsupported ZIP end record")
        if members == 65535 or directory_bytes == 0xffffffff or directory_offset == 0xffffffff:
            locator = tail[offset - 20:offset] if offset >= 20 else b""
            if len(locator) != 20 or locator[:4] != b"PK\x06\x07":
                raise ValueError("missing ZIP64 locator")
            disk, position, disks = struct.unpack_from("<IQI", locator, 4)
            if disk or disks != 1 or position > info.st_size - 56:
                raise ValueError("unsupported ZIP64 locator")
            source.seek(position)
            record = source.read(56)
            if len(record) != 56 or record[:4] != b"PK\x06\x06":
                raise ValueError("invalid ZIP64 end record")
            members, directory_bytes = struct.unpack_from("<QQ", record, 32)
        if members > 100000 or directory_bytes > 64 * 1024 * 1024:
            raise ValueError("acquisition archive directory exceeds the limit")
    total, count, seen = 0, 0, set()
    with zipfile.ZipFile(archive) as zf:
        entries = zf.infolist()
        if len(entries) > 100000:
            raise ValueError("acquisition archive member limit exceeded")
        for entry in entries:
            if entry.flag_bits & 1 or entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise ValueError("encrypted ZIP members and unsupported compression are refused")
            parts = entry.filename.replace("\\", "/").split("/")
            if entry.is_dir():
                parts = parts[:-1]
            if (not parts or any(p in ("", ".", "..") or ":" in p or p.endswith((".", " ")) for p in parts)
                    or any(sanitize_untrusted(p) != p or "\n" in p or "\t" in p for p in parts)
                    or len(parts) > 64 or any(len(p) > 240 for p in parts)):
                raise ValueError("unsafe acquisition archive path")
            if any(re.match(r"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", p.upper()) for p in parts):
                raise ValueError("device names in acquisition archives are refused")
            mode = stat.S_IFMT(entry.external_attr >> 16)
            if mode not in (0, stat.S_IFREG, stat.S_IFDIR):
                raise ValueError("links and special files in acquisition archives are refused")
            dest = os.path.abspath(os.path.join(destination, *parts))
            norm = os.path.normcase(dest)
            if norm in seen or os.path.commonpath((os.path.abspath(destination), dest)) != os.path.abspath(destination):
                raise ValueError("duplicate or escaping archive path")
            seen.add(norm)
            if path_problem(dest):
                raise ValueError("archive destination refused")
            if entry.is_dir():
                os.makedirs(dest, exist_ok=True)
                continue
            if entry.file_size > 1024 * 1024 * 1024 or entry.file_size + total > _PHONE_ARCHIVE_LIMIT:
                raise ValueError("acquisition archive size limit exceeded")
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            size = 0
            with zf.open(entry) as source, open(dest, "xb") as output:
                while True:
                    chunk = source.read(65536)
                    if not chunk:
                        break
                    size += len(chunk)
                    total += len(chunk)
                    if size > 1024 * 1024 * 1024 or total > _PHONE_ARCHIVE_LIMIT:
                        raise ValueError("acquisition archive expanded beyond the size limit")
                    output.write(chunk)
            count += 1
    candidates = []
    for folder, dirs, files in walk_local(destination):
        if "packages.json" in files:
            candidates.append(folder)
    if len(candidates) != 1:
        raise ValueError("archive does not contain one unambiguous AndroidQF collection")
    return candidates[0]


def _phone_age_envelope(path):
    """Validate bounded native age framing, not recipient identity or authentication."""
    if path_problem(os.path.abspath(path)):
        raise ValueError("encrypted archive path refused")
    info = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_size > _PHONE_ARCHIVE_LIMIT:
        raise ValueError("encrypted archive is not a bounded regular file")
    def decoded(value):
        if not re.fullmatch(rb"[A-Za-z0-9+/]*", value):
            raise ValueError("invalid age base64 field")
        result = base64.b64decode(value + b"=" * (-len(value) % 4), validate=True)
        if base64.b64encode(result).rstrip(b"=") != value:
            raise ValueError("noncanonical age field")
        return result
    with open(path, "rb") as fh:
        raw = fh.read(65536)
    if not raw.startswith(b"age-encryption.org/v1\n"):
        raise ValueError("output does not contain a native age v1 envelope")
    pos, recipients = len(b"age-encryption.org/v1\n"), 0
    while pos < len(raw):
        end = raw.find(b"\n", pos)
        if end < 0:
            break
        line, pos = raw[pos:end], end + 1
        if line.startswith(b"--- "):
            if not recipients or len(decoded(line[4:])) != 32 or info.st_size - pos < 32:
                raise ValueError("truncated or invalid age envelope")
            return
        if not re.fullmatch(rb"-> [!-~]+(?: [!-~]+)*", line):
            raise ValueError("invalid age recipient stanza")
        fields = line.split()
        body = b""
        while pos < len(raw):
            end = raw.find(b"\n", pos)
            if end < 0 or end - pos > 64:
                raise ValueError("invalid age stanza body")
            part, pos = raw[pos:end], end + 1
            body += part
            if len(part) < 64:
                break
        data = decoded(body)
        if fields[1] == b"X25519":
            if len(fields) != 3 or len(decoded(fields[2])) != 32 or len(data) != 32:
                raise ValueError("invalid X25519 stanza")
            recipients += 1
    raise ValueError("age header missing or exceeds the read limit")


# AndroidQF unpacks its own adb into "the executable's directory", which its
# helper computes with a '/'-only path function: on Windows that is the current
# directory (here the collection folder), while the fallback that looks for adb
# uses the real executable folder. The collection folder therefore has to be on
# PATH on Windows. The same helper locates key.txt, so on macOS and Linux the
# recipient file must sit beside the executable as well.
_PHONE_ADB_FILES = ("adb.exe", "AdbWinApi.dll", "AdbWinUsbApi.dll")


def _phone_finish_adb(environment, *folders):
    """Stop the adb server AndroidQF leaves running and remove the adb files it
    unpacked into the collection folder (the first folder given)."""
    for folder in folders:
        for name in ("adb.exe", "adb"):
            adb = os.path.join(folder, name)
            if os.path.isfile(adb) and not os.path.islink(adb):
                try:
                    subprocess.run([adb, "kill-server"], cwd=folder, env=environment, shell=False,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, timeout=20)
                except (OSError, subprocess.SubprocessError):
                    pass
                break
    for name in _PHONE_ADB_FILES:
        path = os.path.join(folders[0], name)
        try:
            if os.path.isfile(path) and not os.path.islink(path):
                os.remove(path)
        except OSError:
            pass        # still in use: harmless tool files, never evidence


def collect_android(destination, recipient_file=None):
    """Return (plaintext collection folder or None, command exit code)."""
    if not sys.stdin.isatty():
        print("Acquisition requires an interactive terminal and the device owner's consent.", file=sys.stderr)
        return None, 1
    arch = platform.machine().lower()
    arch = "amd64" if arch in ("amd64", "x86_64") else "arm64" if arch in ("arm64", "aarch64") else arch
    key = (sys.platform, "universal" if sys.platform == "darwin" else arch)
    if key not in _PHONE_ASSETS:
        print("No pinned collector for this platform; use --phone-guide android.", file=sys.stderr)
        return None, 1
    destination = os.path.abspath(destination)
    problem = path_problem(destination)
    if problem or sanitize_untrusted(destination) != destination or "\n" in destination or "\t" in destination:
        print("Acquisition output refused: " + (problem or "unsupported path characters"), file=sys.stderr)
        return None, 1
    asset, digest = _PHONE_ASSETS[key]
    print("This downloads and verifies official AndroidQF v1.8.3, then launches it to collect from a USB-connected Android device.")
    print("Acquisition changes device state and saves private records under: " + destination)
    if sys.platform == "win32":
        print("AndroidQF for Windows is not code-signed by its publisher, so this tool checks the downloaded "
              "file against its published fingerprint before running it. This is a notice, not an error.")
    print("Enable USB debugging, approve this computer on the phone, and follow AndroidQF's prompts.")
    try:
        consent = input("Do you own this device or have the data owner's explicit consent? Type YES to continue: ").strip()
    except (EOFError, KeyboardInterrupt):
        return None, 1
    if consent != "YES":
        return None, 1
    work = extracted = None
    collecting = False
    try:
        recipient = None
        if recipient_file:
            path = os.path.abspath(recipient_file)
            if path_problem(path):
                raise ValueError("age recipient file must be local")
            with open(path, "rb") as fh:
                recipient = fh.read(16385)
            if len(recipient) > 16384:
                raise ValueError("age recipient file is too large")
            lines = [line.strip() for line in recipient.decode("ascii").splitlines() if line.strip() and not line.lstrip().startswith("#")]
            if not lines or any(not re.fullmatch(r"age1[0-9a-z]{58}", line) for line in lines):
                raise ValueError("use public age1 recipients only; never a private identity key")
        os.makedirs(destination, exist_ok=True)
        work = tempfile.mkdtemp(prefix="androidqf_", dir=destination)
        if recipient:
            with open(os.path.join(work, "key.txt"), "xb") as fh:
                fh.write(recipient)
        with tempfile.TemporaryDirectory(prefix="zbt_collector_", dir=local_temp_dir()) as binaries:
            exe = os.path.join(binaries, "androidqf.exe" if sys.platform == "win32" else "androidqf")
            print("Downloading pinned official collector...")
            _phone_download(asset, digest, exe)
            if recipient:
                with open(os.path.join(binaries, "key.txt"), "xb") as fh:
                    fh.write(recipient)
            environment = dict(os.environ)
            for name in list(environment):
                if name.startswith(("ADB_", "ANDROID_ADB_", "LD_", "DYLD_")):
                    environment.pop(name, None)
            environment["PATH"] = (work + os.pathsep +
                                   os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32")
                                   if sys.platform == "win32" else os.defpath)
            collecting = True
            try:
                completed = subprocess.run([exe, "-output", work], cwd=work, env=environment, shell=False)
            finally:
                _phone_finish_adb(environment, work, binaries)
            if completed.returncode:
                raise ValueError("AndroidQF did not complete successfully; any partial acquisition remains in " + work)
        archives = [os.path.join(work, name) for name in os.listdir(work) if name.endswith((".zip", ".zip.age"))]
        if len(archives) != 1:
            raise ValueError("Expected one acquisition archive; inspect " + work)
        if recipient and not archives[0].endswith(".zip.age"):
            raise ValueError("Encryption was requested but the collector returned plaintext. No extraction or scan was performed")
        if archives[0].endswith(".age"):
            _phone_age_envelope(archives[0])
            allowed = {os.path.abspath(archives[0]), os.path.join(work, "key.txt")}
            allowed |= {os.path.join(work, name) for name in _PHONE_ADB_FILES}
            def refused(exc):
                raise OSError("cannot verify acquisition output contents")
            for folder, dirs, files in walk_local(work, onerror=refused):
                if any(os.path.join(folder, name) not in allowed for name in files):
                    raise ValueError("Unexpected files remain beside the encrypted archive; treat the acquisition directory as potentially containing plaintext")
            print("Acquisition saved with an age envelope: " + archives[0])
            print("Envelope format checked; recipient ownership and ciphertext authentication require decryption with the owner's identity.")
            print("No scan was performed. Decrypt it separately with the owner's age identity, extract locally, then run --phone FOLDER.")
            return None, 0
        extracted = tempfile.mkdtemp(prefix="analysis_", dir=work)
        folder = _phone_extract(archives[0], extracted)
        print("Collection ready for offline checking: " + folder)
        print("After collection, disable USB debugging and revoke this computer's authorization if no longer needed.")
        return folder, 0
    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, zlib.error, EOFError, KeyboardInterrupt) as exc:
        if extracted and work:
            # Only remove the new analysis directory created by this invocation.
            target, parent = os.path.abspath(extracted), os.path.abspath(work)
            if (target != parent and os.path.commonpath((parent, target)) == parent
                    and not path_problem(target)):
                try:
                    shutil.rmtree(target)
                except OSError:
                    print("Partial analysis files could not be removed: " + target, file=sys.stderr)
        if _certificate_problem(exc):
            print("Acquisition stopped: " + _certificate_help(
                "the collector was not downloaded and nothing was collected from the phone"), file=sys.stderr)
        else:
            print("Acquisition stopped: " + str(exc), file=sys.stderr)
        if work and not collecting:
            # The collector never ran: the folder holds at most the public
            # recipient key this run wrote, never anything from the phone.
            target, parent = os.path.abspath(work), os.path.abspath(destination)
            if (target != parent and os.path.commonpath((parent, target)) == parent
                    and set(os.listdir(target)) <= {"key.txt"} and not path_problem(target)):
                shutil.rmtree(target, ignore_errors=True)
            print("Nothing was collected from the phone.", file=sys.stderr)
        elif work:
            print("Original or partial acquisition retained; it may contain unencrypted private records: " + work, file=sys.stderr)
        return None, 1
