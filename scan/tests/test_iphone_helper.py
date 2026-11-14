"""--make-iphone-backup (Linux helper). Fake pip and a fake helper process stand in for the network and the
phone; the real install and driver are exercised separately in a Linux container."""
import ast
import hashlib
import io
import os
import types

import pytest

from zbtriage import iphonehelper as ih
from zbtriage.iphonehelper_reqs import IH_REQUIREMENTS, IH_REQUIREMENTS_SHA256

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_embedded_list_matches_the_requirements_file_and_is_fully_pinned():
    with open(os.path.join(ROOT, "requirements-iphone-backup.txt"), encoding="utf-8") as fh:
        text = fh.read().replace("\r\n", "\n")
    assert "".join(IH_REQUIREMENTS) == text
    assert hashlib.sha256(text.encode()).hexdigest() == IH_REQUIREMENTS_SHA256
    pins = [l for l in text.splitlines() if l and not l.startswith((" ", "#"))]
    assert pins and all("==" in l and l.endswith("\\") for l in pins)
    assert "pymobiledevice3==11.50.2 \\" in pins


def test_driver_is_valid_python_and_reads_the_password_from_stdin():
    tree = ast.parse(ih.IH_DRIVER)
    assert "sys.stdin.readline" in ih.IH_DRIVER
    assert not any(isinstance(n, ast.Name) and n.id == "argv" for n in ast.walk(tree)) or "sys.argv[1]" in ih.IH_DRIVER


@pytest.fixture
def linux(monkeypatch, tmp_path):
    monkeypatch.setattr(ih.sys, "platform", "linux")
    monkeypatch.setattr(ih.sys.stdin, "isatty", lambda: True, raising=False)
    sock = tmp_path / "usbmuxd"
    sock.write_text("")
    monkeypatch.setattr(ih, "IH_USBMUXD_SOCKET", str(sock))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    return tmp_path


def _out():
    lines = []
    return lines, lines.append


def test_windows_and_mac_are_sent_to_apple_s_app(monkeypatch):
    monkeypatch.setattr(ih.sys, "platform", "win32")
    lines, out = _out()
    assert ih.make_iphone_backup("C:\\b", out=out) == (None, "", 1)
    assert "Make an iPhone backup" in lines[0]


def test_refuses_a_non_empty_folder(linux):
    full = linux / "full"
    full.mkdir()
    (full / "x").write_text("x")
    lines, out = _out()
    assert ih.make_iphone_backup(str(full), out=out)[2] == 1 and "not empty" in lines[0]


def test_explains_missing_usb_service(linux, monkeypatch):
    monkeypatch.setattr(ih, "IH_USBMUXD_SOCKET", str(linux / "nope"))
    lines, out = _out()
    assert ih.make_iphone_backup(str(linux / "b"), out=out)[2] == 1 and "usbmuxd" in lines[0]


def test_nothing_happens_without_yes(linux, monkeypatch):
    monkeypatch.setattr("builtins.input", lambda _p: "yes please")
    called = []
    lines, out = _out()
    result = ih.make_iphone_backup(str(linux / "b"), run=lambda *a, **k: called.append(a), out=out)
    assert result == (None, "", 1) and not called and "Nothing was downloaded" in lines[-1]


def test_password_must_match_and_be_long_enough():
    answers = iter(["short", "abcdefgh", "different", "abcdefgh", "abcdefgh"])
    lines, out = _out()
    assert ih.ih_new_password(ask=lambda _p: next(answers), out=out) == "abcdefgh"
    assert lines == ["Use at least 6 characters.", "The two did not match."]


class KeepStdin(io.StringIO):
    def close(self):              # keep what was written, so the test can read it after the helper closes stdin
        self.kept = self.getvalue()


class FakeProc:
    def __init__(self, lines, code=0):
        self.stdin = KeepStdin()
        self.stdout = iter(l + "\n" for l in lines)
        self.code = code
        self.sent = None

    def wait(self):
        self.sent = self.stdin.getvalue()
        return self.code


def _run_backup(linux, monkeypatch, lines, code=0, make_folder=True):
    monkeypatch.setattr("builtins.input", lambda _p: "YES")
    home = ih.ih_home()
    os.makedirs(os.path.join(home, "bin"))
    open(ih.ih_python(home), "w").close()
    with open(os.path.join(home, ih.IH_MARKER), "w") as fh:
        fh.write(IH_REQUIREMENTS_SHA256)
    dest = linux / "backup"
    procs = []

    def popen(argv, **kw):
        if make_folder:                     # the helper writes the backup while it runs
            (dest / "00008110-001A2B3C4D5E801E").mkdir(parents=True)
            (dest / "00008110-001A2B3C4D5E801E" / "Manifest.plist").write_bytes(b"x")
            (dest / "00008110-001A2B3C4D5E801E" / "Manifest.db").write_bytes(b"x")
        proc = FakeProc(lines, code)
        proc.argv = argv
        procs.append(proc)
        return proc
    log, out = _out()
    result = ih.make_iphone_backup(str(dest), popen=popen, ask=lambda _p: "s3cret-pass", out=out)
    return result, procs[0] if procs else None, log


def test_password_goes_on_stdin_never_on_the_command_line(linux, monkeypatch):
    (folder, password, code), proc, log = _run_backup(
        linux, monkeypatch, ["PHONE Sara | iOS 18.6", "ENCRYPTION ON", "PROGRESS 50", "PROGRESS 100", "DONE 00008110-001A2B3C4D5E801E"])
    assert code == 0 and folder.endswith("00008110-001A2B3C4D5E801E") and password == "s3cret-pass"
    assert "s3cret-pass" not in " ".join(proc.argv)
    assert proc.stdin.kept == "s3cret-pass\n"
    assert any("encryption is now on" in l for l in log)


def test_already_encrypted_asks_for_the_existing_password_later(linux, monkeypatch):
    (folder, password, code), _proc, log = _run_backup(linux, monkeypatch, ["ENCRYPTION ALREADY ON", "DONE 00008110-001A2B3C4D5E801E"])
    assert code == 0 and password == ""
    assert any("EXISTING password" in l for l in log)


def test_unfinished_backup_is_reported_not_checked(linux, monkeypatch):
    (folder, _pw, code), _proc, log = _run_backup(linux, monkeypatch, ["PROGRESS 40"], code=1)
    assert folder is None and code == 1 and "did not finish" in log[-1]


def test_helper_errors_become_plain_advice(linux, monkeypatch):
    lines = ["Traceback (most recent call last):",
             "pymobiledevice3.exceptions.NoDeviceConnectedError"]
    (folder, _pw, code), _proc, log = _run_backup(linux, monkeypatch, lines, code=1, make_folder=False)
    assert folder is None and "no iPhone was found - connect it with a cable" in log[-1]
    assert "Traceback" not in " ".join(log)


def test_missing_backup_files_are_reported(linux, monkeypatch):
    (folder, _pw, code), _proc, log = _run_backup(linux, monkeypatch, ["DONE 00008110-001A2B3C4D5E801E"], make_folder=False)
    assert folder is None and "no complete backup" in log[-1]


def test_failed_install_leaves_nothing_behind(tmp_path):
    home = str(tmp_path / "helper")
    calls = []

    def run(argv, **kw):
        calls.append(argv)
        if argv[1:4] == ["-I", "-m", "venv"]:
            os.makedirs(os.path.join(argv[4], "bin"))
            return types.SimpleNamespace(returncode=0)
        return types.SimpleNamespace(returncode=1)       # pip refuses (e.g. a hash mismatch)
    with pytest.raises(ValueError, match="every file verified"):
        ih.ih_install(home, run=run, out=lambda _l: None)
    assert not os.path.exists(home)
    pip = calls[1]
    assert "--require-hashes" in pip and "--no-deps" in pip and "--only-binary=:all:" in pip
    # isolated mode everywhere: nothing in the current folder can stand in for venv or pip
    assert all(call[1] == "-I" for call in calls)


def test_packaged_program_uses_the_system_python(monkeypatch):
    monkeypatch.setattr(ih.sys, "frozen", True, raising=False)
    monkeypatch.setattr(ih.shutil, "which", lambda name: "/usr/bin/python3" if name == "python3" else None)
    assert ih.ih_system_python() == "/usr/bin/python3"
    monkeypatch.setattr(ih.shutil, "which", lambda name: None)
    assert ih.ih_system_python() == ""


def test_odd_progress_and_device_ids_never_crash_or_become_paths(linux, monkeypatch):
    (folder, _pw, code), _proc, log = _run_backup(
        linux, monkeypatch, ["PROGRESS inf", "PROGRESS nan", "PROGRESS x", "DONE ../../etc"], code=0,
        make_folder=False)
    assert folder is None and code == 1 and "did not finish" in log[-1]


def test_cli_options():
    from zbtriage.cli import _parse
    with pytest.raises(SystemExit):
        _parse(["--make-iphone-backup", "b", "--phone", "x"])
    assert _parse(["--make-iphone-backup", "b"]).make_iphone_backup == "b"
