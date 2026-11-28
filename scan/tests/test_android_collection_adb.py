"""Guided Android collection with AndroidQF's real file layout.

AndroidQF unpacks adb into "the executable's directory", computed with a
'/'-only path function: on Windows that is the current directory (the
collection folder), and it then looks for adb on PATH or beside the
executable. The collection folder must be on PATH on Windows. The same helper
locates key.txt, which on macOS and Linux is the real executable folder.
Afterwards the adb server is stopped and the unpacked adb files are removed,
so an encrypted collection is not refused for leftover tool files."""
import contextlib
import io
import os
import sys
import types
from pathlib import Path

import pytest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import phoneguide
from test_followup_fixes import age_bytes

ADB_FILES = ("adb.exe", "AdbWinApi.dll", "AdbWinUsbApi.dll")
# The Windows layout needs Windows paths (the local-disk check is platform-aware).
windows_only = pytest.mark.skipif(os.name != "nt", reason="Windows collector layout")


def _run(tmp_path, platform_name, recipient=None):
    calls = []

    def download(asset, digest, path):
        Path(path).write_bytes(b"fixture never executed")

    def fake_run(argv, **kw):
        calls.append((list(argv), kw))
        if argv[-1] == "kill-server":
            return types.SimpleNamespace(returncode=0)
        work = Path(kw["cwd"])
        if platform_name == "win32":
            # Windows: unpacked into the current directory, found only via PATH.
            for name in ADB_FILES:
                (work / name).write_bytes(b"x")
            path_dirs = kw["env"]["PATH"].split(os.pathsep)
            if str(work) not in path_dirs:
                return types.SimpleNamespace(returncode=1)
        # key.txt is read beside the executable on macOS/Linux, from the
        # current directory on Windows.
        key_dir = work if platform_name == "win32" else Path(argv[0]).parent
        if recipient and (key_dir / "key.txt").exists():
            (work / "fixture.zip.age").write_bytes(age_bytes())
        else:
            import zipfile
            with zipfile.ZipFile(work / "fixture.zip", "w") as zf:
                zf.writestr("fixture/packages.json", "[]")
        return types.SimpleNamespace(returncode=0)

    with patch.object(phoneguide, "_phone_download", download), \
         patch.object(phoneguide.subprocess, "run", fake_run), \
         patch.object(phoneguide.sys, "platform", platform_name), \
         patch.object(phoneguide.platform, "machine", return_value="amd64"), \
         patch.object(phoneguide.sys.stdin, "isatty", return_value=True), \
         patch("builtins.input", return_value="YES"), \
         contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        result = phoneguide.collect_android(str(tmp_path / "collected"), recipient)
    return result, calls


@windows_only
def test_windows_collector_finds_the_adb_it_unpacked(tmp_path):
    (folder, code), calls = _run(tmp_path, "win32")
    assert code == 0 and folder
    launch = [c for c in calls if c[0][-1] != "kill-server"][0]
    assert launch[1]["env"]["PATH"].split(os.pathsep)[0] == launch[1]["cwd"]


@windows_only
def test_adb_server_is_stopped_and_unpacked_files_removed(tmp_path):
    (folder, code), calls = _run(tmp_path, "win32")
    work = next((tmp_path / "collected").iterdir())
    assert not [n for n in ADB_FILES if (work / n).exists()]
    stops = [c for c in calls if c[0][-1] == "kill-server"]
    assert len(stops) == 1 and stops[0][0][0] == str(work / "adb.exe")


@windows_only
def test_encrypted_collection_is_not_refused_for_adb_files(tmp_path):
    key = tmp_path / "recipient.txt"
    key.write_text("age1" + "q" * 58)
    (folder, code), _calls = _run(tmp_path, "win32", str(key))
    assert code == 0 and folder is None          # encrypted: saved, not scanned
    work = next((tmp_path / "collected").iterdir())
    assert (work / "fixture.zip.age").exists()


def test_recipient_reaches_the_collector_on_linux_and_macos(tmp_path):
    key = tmp_path / "recipient.txt"
    key.write_text("age1" + "q" * 58)
    for name in ("linux", "darwin"):
        (folder, code), _calls = _run(tmp_path / name, name, str(key))
        assert code == 0 and folder is None, name
        work = next((tmp_path / name / "collected").iterdir())
        assert (work / "fixture.zip.age").exists(), name


def _run_folder_layout(tmp_path, platform_name, recipient=None, nested=False):
    """AndroidQF 1.8.3 without a recipient key: the collection is written as
    plain files into the output folder, with the phone's own bugreport.zip
    among them, and no acquisition archive is made."""
    import zipfile

    def download(asset, digest, path):
        Path(path).write_bytes(b"fixture never executed")

    def fake_run(argv, **kw):
        if argv[-1] == "kill-server":
            return types.SimpleNamespace(returncode=0)
        out = Path(kw["cwd"])
        if nested:
            out = out / "acquisition-1"
            out.mkdir()
        (out / "packages.json").write_text("[]")
        (out / "dumpsys.txt").write_text("DUMP OF SERVICE package:\n")
        with zipfile.ZipFile(out / "bugreport.zip", "w") as zf:
            zf.writestr("FS/data/x.txt", "x")
        return types.SimpleNamespace(returncode=0)

    err = io.StringIO()
    with patch.object(phoneguide, "_phone_download", download), \
         patch.object(phoneguide.subprocess, "run", fake_run), \
         patch.object(phoneguide.sys, "platform", platform_name), \
         patch.object(phoneguide.platform, "machine", return_value="amd64"), \
         patch.object(phoneguide.sys.stdin, "isatty", return_value=True), \
         patch("builtins.input", return_value="YES"), \
         contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(err):
        result = phoneguide.collect_android(str(tmp_path / "collected"), recipient)
    return result, err.getvalue()


@pytest.mark.skipif(os.name == "nt", reason="POSIX collector layout")
@pytest.mark.parametrize("nested", (False, True))
def test_plain_folder_collection_is_checked(tmp_path, nested):
    for name in ("linux", "darwin"):
        (folder, code), err = _run_folder_layout(tmp_path / name, name, nested=nested)
        assert code == 0 and folder, (name, err)
        assert os.path.isfile(os.path.join(folder, "packages.json")), name
        # The phone's own bug report is evidence, not the acquisition archive.
        assert os.path.isfile(os.path.join(folder, "bugreport.zip")), name


@pytest.mark.skipif(os.name == "nt", reason="POSIX collector layout")
def test_plain_folder_is_refused_when_encryption_was_requested(tmp_path):
    key = tmp_path / "recipient.txt"
    key.write_text("age1" + "q" * 58)
    (folder, code), err = _run_folder_layout(tmp_path, "linux", str(key))
    assert folder is None and code == 1
    assert "Encryption was requested" in err
