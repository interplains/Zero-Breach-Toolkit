"""SHA-1 sample fingerprints (for publishers that give no SHA-256) and the
Memento Labs Dante traces (Kaspersky, 2025-10-27).

SHA-1 is matched only against digests this tool computes over the whole file,
in the same single read as the SHA-256, and only when SHA-1 samples are loaded."""
import hashlib
import json
import os
import sys
from unittest.mock import patch

import pytest

from zbtriage import feeds, stix
from zbtriage.context import ScanContext
from zbtriage.iocs import (COMPUTER_TYPES, TYPE_DOMAIN, TYPE_SHA1, TYPE_SHA256, Indicator, IocSet,
                           infer_type, load)
from zbtriage.modules import android, hashscan, host, traces
from zbtriage.report import _show_indicator
from zbtriage.result import EV_ON_DISK, ModuleResult

CONTENT = b"Zero Breach SHA-1 fixture - not software"
SHA1 = hashlib.sha1(CONTENT).hexdigest()
SHA256 = hashlib.sha256(CONTENT).hexdigest()


def _set(*indicators):
    return IocSet(list(indicators), "fixture", None)


def _ctx(*indicators, **kwargs):
    return ScanContext(_set(*indicators), emit=lambda _m: None, **kwargs)


def _sha1_ind(value=SHA1):
    return Indicator(value, "sample", "primary", TYPE_SHA1, "fixture", "Fixture family")


def _sha256_ind(value=SHA256):
    return Indicator(value, "sample", "primary", TYPE_SHA256, "fixture", "Fixture family")


# --- the indicator kind ------------------------------------------------------------------------

def test_forty_hex_digits_are_a_sha1_and_sixty_four_a_sha256():
    assert infer_type("A" * 40) == TYPE_SHA1
    assert infer_type("a" * 64) == TYPE_SHA256
    assert infer_type("a" * 39) == TYPE_DOMAIN and infer_type("a" * 41) == TYPE_DOMAIN
    assert TYPE_SHA1 in COMPUTER_TYPES


def test_curated_row_with_a_sha1_loads_as_a_file_hash(tmp_path):
    path = tmp_path / "x.txt"
    path.write_text("# as-of: 2026-11-02\n{}\tsample\tprimary\tsrc\tFam\n".format(SHA1.upper()),
                    encoding="utf-8")
    s = load(str(path))
    assert [(i.type, i.value) for i in s.indicators] == [(TYPE_SHA1, SHA1)]
    assert [i.value for i in s.hashes] == [SHA1]
    assert s.domains == [] and s.ips == [] and s.computer_count == 1


def test_a_sha1_hit_is_shown_as_written_not_defanged():
    assert _show_indicator({"indicator": SHA1, "kind": TYPE_SHA1}) == SHA1


# --- computer file check (an .apk is fingerprinted by the Full check) -----------------------------------------------------------------------

def test_file_check_matches_a_sha1_only_sample(tmp_path):
    target = tmp_path / "update.apk"
    target.write_bytes(CONTENT)
    with patch.object(hashscan, "_roots", lambda: [str(tmp_path)]):
        r = hashscan.run(_ctx(_sha1_ind(), full=True))
    assert [(h.indicator, h.location, h.evidence) for h in r.hits] == [(SHA1, str(target), EV_ON_DISK)]
    assert "SHA-1" in r.hits[0].detail and "SHA-256" not in r.hits[0].detail


def test_file_check_still_matches_by_sha256(tmp_path):
    (tmp_path / "update.apk").write_bytes(CONTENT)
    with patch.object(hashscan, "_roots", lambda: [str(tmp_path)]):
        r = hashscan.run(_ctx(_sha256_ind(), _sha1_ind(), full=True))
    assert [h.indicator for h in r.hits] == [SHA256]
    assert "SHA-256" in r.hits[0].detail


def test_sha1_is_computed_only_when_sha1_samples_are_loaded(tmp_path):
    target = tmp_path / "update.apk"
    target.write_bytes(CONTENT)
    assert hashscan._hash_one(str(target))[1] == (SHA256, None)
    assert hashscan._hash_one(str(target), None, True)[1] == (SHA256, SHA1)
    seen = []
    real = hashscan._hash_one

    def spy(full, folder_checked=None, with_sha1=False):
        seen.append(with_sha1)
        return real(full, folder_checked, with_sha1)

    with patch.object(hashscan, "_hash_one", spy), patch.object(hashscan, "_roots", lambda: [str(tmp_path)]):
        hashscan.run(_ctx(_sha256_ind("b" * 64), full=True))
        assert seen == [False]
        hashscan.run(_ctx(_sha256_ind("b" * 64), _sha1_ind("c" * 40), full=True))
        assert seen == [False, True]


@pytest.mark.skipif(sys.platform != "win32", reason="ran-program records name Windows paths")
def test_programs_windows_recorded_are_matched_by_sha1(tmp_path):
    target = tmp_path / "tool.exe"
    target.write_bytes(CONTENT)
    r = ModuleResult("traces")
    with patch.object(traces, "_tr_ran_programs",
                      lambda: ([(str(target), "2026-11-01T00:00:00Z", "shim cache")], {})):
        traces._tr_check_ran_programs(r, _ctx(_sha1_ind()))
    assert [h.indicator for h in r.hits] == [SHA1]


# --- Android collections -----------------------------------------------------------------------

def _collection(tmp_path, files_record, listed_files=()):
    pkgs = [{"name": "com.example.fixture", "installer": "com.android.packageinstaller",
             "third_party": True, "system": False, "disabled": False, "uid": 1,
             "files": [dict({"path": "/data/app/f/base.apk"}, **files_record)]}]
    for name, data in (("packages.json", pkgs), ("files.json", list(listed_files)),
                       ("root_binaries.json", []),
                       ("acquisition.json", {"started": "2026-11-01T00:00:00Z"})):
        (tmp_path / name).write_text(json.dumps(data), encoding="utf-8")
    (tmp_path / "getprop.txt").write_text("[ro.build.version.security_patch]: [2099-01-01]\n",
                                          encoding="utf-8")
    return str(tmp_path)


def _gaps(r, check):
    return [c.reason for c in r.checks if c.name == check and not c.ran]


def test_android_app_file_matched_by_sha1(tmp_path):
    folder = _collection(tmp_path, {"sha256": "d" * 64, "sha1": SHA1})
    r = android.run(_ctx(_sha1_ind(), phone_path=folder))
    assert [h.indicator for h in r.hits] == [SHA1]
    assert "SHA-1" in r.hits[0].detail


def test_android_app_file_without_sha1_is_a_gap_only_when_sha1_samples_are_loaded(tmp_path):
    folder = _collection(tmp_path, {"sha256": "d" * 64})
    r = android.run(_ctx(_sha256_ind("e" * 64), phone_path=folder))
    assert _gaps(r, "android:app-fingerprints") == []
    r = android.run(_ctx(_sha256_ind("e" * 64), _sha1_ind("f" * 40), phone_path=folder))
    gaps = _gaps(r, "android:app-fingerprints")
    assert len(gaps) == 1 and "SHA-256 and SHA-1" in gaps[0]


def test_android_listed_file_matched_by_sha1(tmp_path):
    listed = [{"path": "/sdcard/Download/update.apk", "sha256": "d" * 64, "sha1": SHA1}]
    folder = _collection(tmp_path, {"sha256": "d" * 64, "sha1": "a" * 40}, listed)
    r = android.run(_ctx(_sha1_ind(), phone_path=folder))
    assert [(h.indicator, h.location) for h in r.hits] == [(SHA1, "/sdcard/Download/update.apk")]


def test_android_listed_file_with_sha256_only_is_partly_compared(tmp_path):
    listed = [{"path": "/sdcard/a.bin", "sha256": "d" * 64}, {"path": "/sdcard/b.bin"}]
    folder = _collection(tmp_path, {"sha256": "d" * 64, "sha1": "a" * 40}, listed)
    r = android.run(_ctx(_sha256_ind("e" * 64), phone_path=folder))
    assert _gaps(r, "android:file-hashes") == [
        "1 of 2 listed file(s) have no valid fingerprint, so they were checked by path and name only"]
    r = android.run(_ctx(_sha256_ind("e" * 64), _sha1_ind("f" * 40), phone_path=folder))
    assert _gaps(r, "android:file-hashes") == [
        "2 of 2 listed file(s) lack a valid SHA-256 or SHA-1 fingerprint, so they were not "
        "compared with every published sample fingerprint"]


# --- published feeds ---------------------------------------------------------------------------

def _bundle(tmp_path, *patterns):
    objects = [{"type": "indicator", "id": "indicator--{:08d}-0000-4000-8000-000000000000".format(n),
                "pattern": p, "pattern_type": "stix", "valid_from": "2026-01-01T00:00:00Z"}
               for n, p in enumerate(patterns)]
    path = tmp_path / "x.stix2"
    path.write_text(json.dumps({"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000000",
                                "objects": objects}), encoding="utf-8")
    return str(path)


def test_stix_sha1_is_imported_as_a_sample(tmp_path):
    path = _bundle(tmp_path, "[file:hashes.'SHA-1' = '{}']".format(SHA1),
                   "[file:hashes.SHA1 = 'not-a-hash']",
                   "[file:hashes.MD5 = '{}']".format("0" * 32))
    s = stix.load_stix(path)
    assert [(i.type, i.value, i.tier) for i in s.indicators] == [(TYPE_SHA1, SHA1, "sample")]


def test_misp_sha1_is_imported_as_a_sample(tmp_path):
    path = tmp_path / "x.misp.csv"
    path.write_text("type,value\nsha1,{}\nmd5,{}\n".format(SHA1, "0" * 32), encoding="utf-8")
    s = feeds.load_list(str(path), "misp-csv", "fixture", "Fixture family")
    assert [(i.type, i.value, i.tier) for i in s.indicators] == [(TYPE_SHA1, SHA1, "sample")]
    assert s.sets[0]["not_applicable_to_this_scan"] == {"md5": 1}


# --- Memento Labs Dante traces -----------------------------------------------------------------

def _dante(tmp_path, servers=None):
    servers = servers if servers is not None else {
        ("HKLM", host._DANTE_CLASS): os.path.join("C:", "Windows", "System32", "twinapi.dll")}
    r = ModuleResult("host")
    with patch.dict(os.environ, {"LOCALAPPDATA": str(tmp_path)}), \
            patch.object(host, "_dt_class_server", lambda hive, clsid: servers.get((hive, clsid))):
        host._check_dante(r, _ctx())
    return r


def _module_folder(base, name="Qm9vazEx", files=("Qm9vazEx", "TW9kdWxl")):
    folder = base / name
    folder.mkdir()
    for f in files:
        (folder / f).write_bytes(b"x")
    return folder


def test_dante_normal_machine_has_no_leads(tmp_path):
    for name in ("Discovery", "Packages", "Programs"):
        folder = tmp_path / name
        folder.mkdir()
        (folder / "settings.json").write_bytes(b"{}")
    r = _dante(tmp_path)
    assert r.leads == [] and r.hits == []
    assert [c.name for c in r.checks if c.ran] == ["dante-traces"]


@pytest.mark.parametrize("hive", ["HKLM", "HKCU"])
def test_dante_hijacked_class_is_a_lead(tmp_path, hive):
    servers = {("HKLM", host._DANTE_CLASS): os.path.join("C:", "Windows", "System32", "twinapi.dll")}
    servers[(hive, host._DANTE_CLASS)] = os.path.join("C:", "Users", "x", "AppData", "Local", "a.dll")
    r = _dante(tmp_path, servers)
    assert r.hits == [] and len(r.leads) == 1
    assert r.leads[0].location.startswith(hive) and host._DANTE_CLASS in r.leads[0].location


def test_dante_module_folder_layout_is_a_lead(tmp_path):
    folder = _module_folder(tmp_path)
    r = _dante(tmp_path)
    assert r.hits == [] and [lead.location for lead in r.leads] == [str(folder)]
    assert "Do not delete" in r.leads[0].usual_reason


@pytest.mark.parametrize("files", [
    ("TW9kdWxl", "QWJjZGVm"),             # no file named like the folder
    ("Qm9vazEx", "module.dll"),           # a file with an extension
    ("Qm9vazEx", "TW9kdWxlLong"),         # a name of another length
])
def test_dante_other_layouts_are_not_leads(tmp_path, files):
    _module_folder(tmp_path, files=files)
    r = _dante(tmp_path)
    assert r.leads == []


def test_dante_unopened_candidate_folder_is_a_gap(tmp_path):
    _module_folder(tmp_path)
    real = os.scandir

    def refusing(path="."):
        if os.path.basename(str(path)) == "Qm9vazEx":
            raise PermissionError(13, "refused")
        return real(path)

    with patch.object(host.os, "scandir", refusing):
        r = _dante(tmp_path)
    assert r.leads == []
    gaps = [c.reason for c in r.checks if c.name == "dante-traces" and not c.ran]
    assert len(gaps) == 1 and "1 folder(s)" in gaps[0]
