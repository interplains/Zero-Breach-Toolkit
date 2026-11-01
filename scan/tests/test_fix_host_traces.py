"""2.0.3: the Windows trace checks must not report "ran" from nothing.

Fixture sources:
  * ShimCache / AppCompatCache, Windows 10 and 11 layout: per entry the signature
    b"10ts", 4 bytes, a 4-byte entry size, a 2-byte path length, the UTF-16LE path,
    an 8-byte FILETIME, a 4-byte data size and the data (Eric Zimmerman's
    AppCompatCacheParser documentation; the same layout the reader's docstring
    cites). Registry key HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager
    \\AppCompatCache, value AppCompatCache.
  * PcaAppLaunchDic.txt: one "path|YYYY-MM-DD HH:MM:SS.fff" per line (Windows 11
    22H2 Program Compatibility Assistant; published DFIR research).
  * Task Scheduler: XML files under %SystemRoot%\\System32\\Tasks (Microsoft task
    schema).
  * winreg is replaced by a small fake that returns what the real API returns
    (OpenKey as a context manager, QueryInfoKey -> (subkeys, values, last write),
    EnumKey/EnumValue/QueryValueEx), so the real reader code runs on any platform.
Synthetic values only.
"""
import os
import struct
import sys
import types
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import traces
from zbtriage.result import ModuleResult

SHA = "a" * 64


def _ctx(**kw):
    iocs = IocSet([Indicator(SHA, "sample", "primary", "sha256", "fixture", "Family"),
                   Indicator("spy-c2.test", "cc", "primary", "domain", "fixture", "Family")], "fixture", None)
    return ScanContext(iocs=iocs, emit=lambda _m: None, **kw)


def _ran(result, name):
    return any(c.ran and c.name == name for c in result.checks)


def _gap(result, name):
    return any((not c.ran) and c.name.startswith(name) for c in result.checks)


def shim_entry(path):
    raw = path.encode("utf-16-le")
    body = struct.pack("<H", len(raw)) + raw + b"\0" * 8 + struct.pack("<I", 0)
    return b"10ts" + b"\0\0\0\0" + struct.pack("<I", len(body)) + body


class FakeKey:
    def __init__(self, values=(), subkeys=()):
        self.values, self.subkeys = list(values), list(subkeys)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def fake_winreg(tree):
    """tree: {lowercased key path: FakeKey}; a missing key raises FileNotFoundError."""
    module = types.ModuleType("winreg")
    for name in ("HKEY_LOCAL_MACHINE", "HKEY_CURRENT_USER"):
        setattr(module, name, name)
    for name, value in (("KEY_READ", 1), ("KEY_WOW64_32KEY", 2), ("KEY_WOW64_64KEY", 4),
                        ("REG_SZ", 1), ("REG_EXPAND_SZ", 2)):
        setattr(module, name, value)

    def open_key(hive, path, *rest):
        base = hive if isinstance(hive, FakeKey) else None
        key = (path if base is None else base.path + "\\" + path).lower()
        if key not in tree:
            raise FileNotFoundError(2, "not found", key)
        found = tree[key]
        found.path = key
        return found
    module.OpenKey = open_key
    module.QueryInfoKey = lambda key: (len(key.subkeys), len(key.values), 0)
    module.EnumKey = lambda key, n: key.subkeys[n]
    module.EnumValue = lambda key, n: key.values[n]
    module.QueryValueEx = lambda key, name: next((v, t) for n, v, t in key.values if n == name)
    return module


# --- item 5: ran-programs ---------------------------------------------------------------

def _programs_with(blob):
    tree = {r"system\currentcontrolset\control\session manager\appcompatcache": FakeKey([("AppCompatCache", bytes(blob), 3)])}
    module = fake_winreg(tree)
    module.QueryValueEx = lambda key, name: (bytes(blob), 3)
    return module


def test_a_shim_cache_with_no_parseable_entry_is_an_error(tmp_path):
    with patch.dict(sys.modules, {"winreg": _programs_with(b"\x00" * 64 + b"not the windows 10 layout")}), \
            patch.dict(os.environ, {"SystemRoot": str(tmp_path)}):
        programs, errors = traces._tr_ran_programs()
    assert programs == []
    assert "shim cache" in errors


def test_hitting_the_entry_cap_is_stated(tmp_path):
    blob = b"".join(shim_entry("C:\\fixture\\p{}.exe".format(n)) for n in range(5000))
    with patch.dict(sys.modules, {"winreg": _programs_with(blob)}), \
            patch.dict(os.environ, {"SystemRoot": str(tmp_path)}):
        programs, errors = traces._tr_ran_programs()
    assert len(programs) == 4096
    assert "4,096" in errors.get("shim cache", "")


def test_no_programs_from_any_source_is_a_gap_not_a_clean_read():
    r = ModuleResult("traces")
    with patch.object(traces, "_tr_ran_programs", lambda: ([], {})):
        traces._tr_check_ran_programs(r, _ctx())
    assert not _ran(r, "ran-programs")
    assert _gap(r, "ran-programs")


def test_only_non_file_entries_is_a_gap_not_a_clean_read():
    r = ModuleResult("traces")
    only_ids = ([("Microsoft.WindowsCalculator_8wekyb3d8bbwe!App", "", "launch list")], {})
    with patch.object(traces, "_tr_ran_programs", lambda: only_ids):
        traces._tr_check_ran_programs(r, _ctx())
    assert not _ran(r, "ran-programs")
    assert _gap(r, "ran-programs")


@pytest.mark.skipif(sys.platform != "win32", reason="the reader only accepts drive-letter paths")
def test_listed_programs_that_were_fingerprinted_are_a_clean_read(tmp_path):
    exe = tmp_path / "ordinary.exe"
    exe.write_bytes(b"MZ ordinary program")
    r = ModuleResult("traces")
    with patch.object(traces, "_tr_ran_programs", lambda: ([(str(exe), "", "shim cache")], {})):
        traces._tr_check_ran_programs(r, _ctx())
    assert _ran(r, "ran-programs")


# --- Mark of the Web: every folder unreadable ----------------------------------------------

def _walk_that_fails(root, onerror=None):
    if onerror:
        onerror(PermissionError(13, "Access is denied", root))
    return iter(())


def test_mark_of_the_web_with_every_folder_unreadable_is_not_a_clean_read(tmp_path):
    r = ModuleResult("traces")
    with patch.object(traces, "_tr_motw_roots", lambda: [str(tmp_path)]), \
            patch.object(traces, "walk_local", _walk_that_fails):
        traces._tr_check_motw(r, _ctx())
    assert not _ran(r, "mark-of-the-web")
    assert _gap(r, "mark-of-the-web")


def test_mark_of_the_web_on_a_readable_empty_folder_is_a_clean_read(tmp_path):
    r = ModuleResult("traces")
    with patch.object(traces, "_tr_motw_roots", lambda: [str(tmp_path)]):
        traces._tr_check_motw(r, _ctx())
    assert _ran(r, "mark-of-the-web")


# --- startup files and scheduled tasks ----------------------------------------------------

def _persistence(tmp_path, walk=None, services=None):
    env = {"SystemRoot": str(tmp_path / "Windows"), "APPDATA": str(tmp_path / "Roaming"),
           "PROGRAMDATA": str(tmp_path / "ProgramData")}
    (tmp_path / "Windows" / "System32" / "Tasks").mkdir(parents=True)
    for base in ("Roaming", "ProgramData"):
        (tmp_path / base / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup").mkdir(parents=True)
    run_keys = {}
    for suffix in ("run", "runonce"):
        run_keys[r"software\microsoft\windows\currentversion\{}".format(suffix)] = FakeKey()
    tree = dict(run_keys)
    tree[r"system\currentcontrolset\services"] = services if services is not None else FakeKey()
    r = ModuleResult("traces")
    from zbtriage import localpaths
    with patch.dict(os.environ, env), patch.dict(sys.modules, {"winreg": fake_winreg(tree)}):
        if walk:
            with patch.object(localpaths, "walk_local", walk):
                traces._tr_persistence(r, _ctx())
        else:
            traces._tr_persistence(r, _ctx())
    return r


def test_startup_and_task_folders_that_cannot_be_read_are_not_clean_reads(tmp_path):
    r = _persistence(tmp_path, walk=_walk_that_fails)
    for check in ("scheduled-task-actions", "startup-files"):
        assert not _ran(r, check), check
        assert _gap(r, check), check


def test_empty_startup_and_task_folders_are_clean_reads(tmp_path):
    r = _persistence(tmp_path)
    assert _ran(r, "scheduled-task-actions")
    assert _ran(r, "startup-files")


def test_a_services_key_with_no_services_is_not_a_clean_read(tmp_path):
    # Every Windows has hundreds of services; an empty key means it was not read.
    r = _persistence(tmp_path, services=FakeKey(subkeys=[]))
    assert not _ran(r, "service-registrations")
    assert _gap(r, "service-registrations")


def test_a_services_key_with_services_is_a_clean_read(tmp_path):
    key = FakeKey(subkeys=["Dnscache"])
    tree_services = key
    r = _persistence(tmp_path, services=tree_services)
    # Dnscache has no ImagePath in the fake: nothing to compare, the key itself was read.
    assert _ran(r, "service-registrations")
