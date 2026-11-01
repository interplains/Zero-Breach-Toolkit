"""Built-in phone traces (devicetraces.py): Cellebrite's imitated USB devices on
Android (Amnesty, 2025), Cellebrite's iPhone traces (Citizen Lab, 2026) and the
Heliconia properties and folder (Google, 2023). The log lines below copy the
formats quoted in those reports."""
import datetime
import json
import os

import pytest

from zbtriage import contract, gui, report
from zbtriage.context import ScanContext
from zbtriage.iocs import IocSet
from zbtriage.modules import android, ios
from zbtriage.training import _trn_collection
from test_followup_fixes import bundle
from test_ios_real_world_layouts import _ips, _sysdiagnose

AMNESTY_LINES = (
    "USB device attached: vidpid 04f2:b071 mfg/product/ver/serial Video/Video Device/12.34/00001\n"
    "USB device attached: vidpid 0763:2012 mfg/product/ver/serial Sound/Sound Device/12.34/00001\n"
    "USB device attached: vidpid 0763:2012 mfg/product/ver/serial Sound/Sound Device/12.34/00001\n"
    "uevent: ACTION=add PRODUCT=45e/76c/1234 TYPE=0/0/0\n")
REAL_DEVICES = (
    "USB device attached: vidpid 045e:076c mfg/product/ver/serial Microsoft/Comfort Mouse 4500/1.00/A1\n"
    "uevent: ACTION=add PRODUCT=4f2/b071/100 TYPE=239/2/1\n")


def _empty_iocs():
    return IocSet([], "fixture", None)


@pytest.fixture(params=("source", "bundle"))
def android_reader(request, bundle):
    return android.run if request.param == "source" else bundle.run_android


@pytest.fixture(params=("source", "bundle"))
def ios_reader(request, bundle):
    return ios.run if request.param == "source" else bundle.run_ios


def _android(tmp_path, logcat="", props="", files=None):
    folder = tmp_path / "phone"
    folder.mkdir()
    _trn_collection(str(folder), "clean")
    if logcat:
        with open(folder / "logcat.txt", "a", encoding="utf-8") as fh:
            fh.write(logcat)
    if props:
        with open(folder / "getprop.txt", "a", encoding="utf-8") as fh:
            fh.write(props)
    if files is not None:
        (folder / "files.json").write_text(json.dumps(files), encoding="utf-8")
    return ScanContext(_empty_iocs(), phone_path=str(folder), emit=lambda _: None)


def test_cellebrite_usb_devices_are_found_once_each(tmp_path, android_reader):
    result = android_reader(_android(tmp_path, logcat=AMNESTY_LINES + REAL_DEVICES))
    forensic = [h for h in result.hits if h.tier == "forensic"]
    assert sorted(h.indicator for h in forensic) == [
        "cellebrite usb 045e:076c",
        "cellebrite usb 04f2:b071",
        "cellebrite usb 0763:2012"]
    sound = next(h for h in forensic if "0763:2012" in h.indicator)
    assert "2 times" in sound.detail and sound.evidence == "device-log"
    assert all(h.source == "amnesty-cellebrite-serbia-2025-02" for h in forensic)


def test_real_devices_with_the_same_ids_are_not_cellebrite(tmp_path, android_reader):
    result = android_reader(_android(tmp_path, logcat=REAL_DEVICES))
    assert not [h for h in result.hits if h.tier == "forensic"]


def test_heliconia_property_and_folder(tmp_path, android_reader):
    files = [{"path": "/data/local/tmp/dropbox/libsomething.so", "sha256": ""},
             {"path": "/data/local/tmp/dropboxes", "sha256": ""}]
    result = android_reader(_android(tmp_path, props="[sys.brand.note]: [1]\n", files=files))
    found = {(h.indicator, h.location) for h in result.hits if h.family == "Variston Heliconia"}
    assert ("sys.brand.note", "system property sys.brand.note") in found
    assert ("/data/local/tmp/dropbox", "/data/local/tmp/dropbox/libsomething.so") in found
    assert not any(h.location == "/data/local/tmp/dropboxes" for h in result.hits)


def _ios_ctx(path, kind):
    return ScanContext(_empty_iocs(), phone_path=str(path), ios_input=kind, emit=lambda _: None)


def test_cellebrite_crash_log_on_iphone(tmp_path, ios_reader):
    stackshot = _ips({"bug_type": "288", "timestamp": "2026-01-02 03:04:05.00 +0000"},
                     {"processByPid": {"24": {"procname": "mnm",
                                              "dispatch_queue_label": "com.cellebrite.bruteforce"}}})
    archive = _sysdiagnose(tmp_path, [("crashes_and_spins/stacks-2026-01-02-030405.ips", stackshot)])
    result = ios_reader(_ios_ctx(archive, "sysdiagnose"))
    forensic = {h.indicator for h in result.hits if h.tier == "forensic"}
    assert {"mnm", "com.cellebrite.bruteforce"} <= forensic
    assert all(h.source == "citizenlab-cellebrite-jordan-2026-01"
               for h in result.hits if h.tier == "forensic")


def test_cellebrite_computer_in_lockdown_records(tmp_path, ios_reader):
    folder = tmp_path / "filesystem" / "private/var/root/Library/Lockdown"
    folder.mkdir(parents=True)
    import plistlib
    (folder / "data_ark.plist").write_bytes(plistlib.dumps(
        {"HostID": "9016926980658937761372207", "SystemBUID": "30313996-42072961236303456"},
        fmt=plistlib.FMT_BINARY))
    result = ios_reader(_ios_ctx(tmp_path / "filesystem", "filesystem"))
    forensic = {h.indicator: h for h in result.hits if h.tier == "forensic"}
    assert set(forensic) == {"9016926980658937761372207", "30313996-42072961236303456"}
    assert all(h.evidence == "on-device" for h in forensic.values())


def test_a_process_called_mnm_is_never_matched_on_a_computer():
    # The trace lives only in the phone checks: the indicator lists that
    # computer checks use do not contain it.
    from zbtriage.cli import _load_iocs, _parse
    iocs = _load_iocs(_parse(["--no-menu", "--no-banner", "--no-feeds"]))
    assert not [i for i in iocs.of_type("process") if i.value == "mnm"]


def _forensic_doc():
    hit = {"indicator": "cellebrite usb 04f2:b071", "tier": "forensic",
           "evidence": "device-log", "confidence": "primary", "location": "phone log logcat.txt",
           "detail": "x", "source": "amnesty-cellebrite-serbia-2025-02", "family": "Cellebrite"}
    return {"verdict": {"status": report.V_HITS, "gaps": [], "findings_total": 1},
            "modules": {"android": {"hits": [hit], "leads": []}}}


def test_forensic_findings_get_their_own_wording_and_advice():
    doc = _forensic_doc()
    hit = doc["modules"]["android"]["hits"][0]
    assert report._headline_for(hit).startswith("SIGNS THIS PHONE WAS UNLOCKED")
    assert report._recommended_action(hit) == 3
    steps = [s["id"] for s in contract.contract_next_steps(doc, 3)]
    assert "forensic-access" in steps
    assert gui.gui_headline(doc)[1] == "This phone was unlocked with a phone-forensics tool"
    assert any("copied" in s for s in gui.gui_next_steps(doc))
    assert "forensic" in report.TIER_MEANING
