"""Files kept only in iCloud or OneDrive are reported instead of downloaded (a
download can stall a scan for hours); the Windows launcher only uses a Python
that actually runs; the reassignable Azure IP is in the weaker IP tier."""
import os
import shutil
import stat
import subprocess
import sys
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import localpaths
from zbtriage.iocs import load_any
from zbtriage.modules import hashscan

SCAN = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROOT = os.path.dirname(SCAN)


def _fake_stat(flags=0, attributes=0):
    return types.SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_size=10, st_flags=flags,
                                 st_file_attributes=attributes)


@pytest.mark.parametrize("flags,attributes", [(localpaths.SF_DATALESS, 0), (0, 0x00400000), (0, 0x00001000)])
def test_cloud_only_file_is_not_read(tmp_path, monkeypatch, flags, attributes):
    target = tmp_path / "evicted.exe"
    target.write_bytes(b"x")
    monkeypatch.setattr(hashscan.os, "stat", lambda p, follow_symlinks=True: _fake_stat(flags, attributes))
    monkeypatch.setattr(hashscan, "_sha256", lambda p, *_rest: pytest.fail("a cloud-only file was read"))
    assert hashscan._hash_one(str(target))[3] == "cloud"


def test_cloud_reason_is_named_in_the_gap():
    text = hashscan._hs_reasons({"denied": 0, "large": 0, "unreadable": 0, "cloud": 4})
    assert "4 stored only in iCloud or OneDrive" in text


def test_icloud_placeholder_folder_is_not_listed(tmp_path, monkeypatch):
    (tmp_path / "placeholder").mkdir()
    (tmp_path / "placeholder" / "inside.exe").write_bytes(b"x")
    real_scandir = os.scandir

    class Entry:
        def __init__(self, entry):
            self._e, self.name, self.path = entry, entry.name, entry.path

        def stat(self, follow_symlinks=True):
            info = self._e.stat(follow_symlinks=False)
            flags = localpaths.SF_DATALESS if self.name == "placeholder" else 0
            return types.SimpleNamespace(st_mode=info.st_mode, st_flags=flags, st_file_attributes=0)

    class Listing:
        def __init__(self, path):
            self._it = real_scandir(path)

        def __enter__(self):
            return (Entry(e) for e in self._it)

        def __exit__(self, *a):
            self._it.close()

    monkeypatch.setattr(localpaths.os, "scandir", Listing)
    errors, walked = [], []
    for current, dirs, files in localpaths.walk_local(str(tmp_path), onerror=errors.append):
        walked.append(os.path.basename(current))
    assert "placeholder" not in walked
    assert [e.strerror for e in errors] == [localpaths.WALK_CLOUD_SKIPPED]


def test_reassignable_azure_ip_is_in_the_weaker_ip_tier():
    iocs = load_any(os.path.join(ROOT, "iocs", "adfection_iocs.txt"))
    tiers = {i.value: i.tier for i in iocs.indicators}
    assert tiers["52.174.65.77"] == "candiru-ip"


@pytest.mark.skipif(sys.platform != "win32", reason="cmd.exe launcher")
def test_launcher_skips_a_python_that_does_not_run(tmp_path):
    stub = tmp_path / "stub"
    stub.mkdir()
    marker = tmp_path / "stub-was-used"
    # Like the Microsoft Store stand-in: exits 9009; records it if ever used for the scan.
    (stub / "python.bat").write_text(
        '@echo off\r\nif "%~1"=="-c" exit /b 9009\r\necho used> "{}"\r\nexit /b 9009\r\n'.format(marker))
    folder = tmp_path / "kit" / "scan"
    folder.mkdir(parents=True)
    shutil.copy(os.path.join(SCAN, "run-scan.cmd"), folder / "run-scan.cmd")
    (folder / "zero-breach-toolkit.py").write_text("import sys\nsys.exit(0)\n")
    env = dict(os.environ, PATH=str(stub) + os.pathsep + os.environ.get("PATH", ""))
    subprocess.run('echo.| "{}"'.format(folder / "run-scan.cmd"), shell=True, env=env,
                   capture_output=True, text=True, timeout=120)
    assert not marker.exists()
