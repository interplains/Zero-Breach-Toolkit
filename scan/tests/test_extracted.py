"""Was this phone plugged into a forensics tool? The signs must be found, an ordinary phone must not be
accused, and - the most important promise of this check - the report must always say that finding nothing is
not proof. Nothing may touch the network or a phone."""
import json
import os
import plistlib
import socket
import subprocess

import pytest

from zbtriage import extracted as ex
from zbtriage.iocs import Indicator, IocSet


@pytest.fixture(autouse=True)
def nothing_outside(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("this check must never touch the network or run a program")
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)


def android(tmp_path, props=None, settings=None, packages=None, keys=None, log=None, name="collection"):
    folder = tmp_path / name
    folder.mkdir()
    (folder / "getprop.txt").write_text(
        "".join("[{}]: [{}]\n".format(k, v) for k, v in (props or {"ro.product.model": "Pixel 7"}).items()),
        encoding="utf-8")
    (folder / "settings_secure.txt").write_text(
        "".join("{}={}\n".format(k, v) for k, v in (settings or {}).items()), encoding="utf-8")
    (folder / "packages.json").write_text(json.dumps(packages if packages is not None else []), encoding="utf-8")
    if keys is not None:
        (folder / "adb_keys").write_text(keys, encoding="utf-8")
    if log is not None:
        (folder / "logcat.txt").write_text(log, encoding="utf-8")
    return str(folder)


def iphone(tmp_path, info=None, manifest=None, name="backup"):
    folder = tmp_path / name
    folder.mkdir()
    (folder / "Manifest.db").write_bytes(b"SQLite format 3\x00")
    with open(folder / "Info.plist", "wb") as fh:
        plistlib.dump(info if info is not None else {"Device Name": "My iPhone", "Product Type": "iPhone14,2"},
                      fh)
    with open(folder / "Manifest.plist", "wb") as fh:
        plistlib.dump(manifest if manifest is not None else {"IsEncrypted": True}, fh)
    return str(folder)


# --- which kind of thing was given --------------------------------------------------------------------------

def test_it_recognises_a_collection_and_a_backup(tmp_path):
    assert ex.ex_kind(android(tmp_path)) == "android"
    assert ex.ex_kind(iphone(tmp_path)) == "iphone"


def test_a_file_or_an_unrelated_folder_is_explained(tmp_path):
    lonely = tmp_path / "notes.txt"
    lonely.write_text("hello", encoding="utf-8")
    with pytest.raises(ex.ExError, match="not a folder"):
        ex.ex_kind(str(lonely))
    empty = tmp_path / "holiday photos"
    empty.mkdir()
    with pytest.raises(ex.ExError, match="neither an AndroidQF collection"):
        ex.ex_kind(str(empty))
    assert "AndroidQF" in ex.EX_HOW_TO and "MobileSync" in ex.EX_HOW_TO


# --- the promise that must never be dropped ------------------------------------------------------------------

@pytest.mark.parametrize("make", [android, iphone])
def test_every_report_says_that_finding_nothing_is_not_proof(tmp_path, make):
    result = ex.ex_check(make(tmp_path))
    text = ex.ex_render(result)
    assert ex.EX_ALWAYS in text
    assert "not mean the phone was not copied" in text
    assert "NOT PROOF" in text or result["level"] != ex.EX_NOTHING


def test_a_clean_collection_says_no_signs_found(tmp_path):
    result = ex.ex_check(android(tmp_path, settings={"adb_enabled": "0"},
                                 packages=[{"name": "com.android.chrome", "installer": "com.android.vending"}],
                                 log="usb 1-1: new high-speed USB device number 3 using xhci_hcd\n"))
    assert result["level"] == ex.EX_NOTHING and result["findings"] == []
    assert "None of the things this check looks for were there" in ex.ex_render(result)


# --- Android signs -------------------------------------------------------------------------------------------

def test_an_unlocked_bootloader_is_a_sign(tmp_path):
    result = ex.ex_check(android(tmp_path, props={"ro.boot.verifiedbootstate": "orange"}))
    assert result["level"] == ex.EX_FOUND
    assert any("bootloader is unlocked" in f["what"] for f in result["findings"])


def test_a_debug_build_is_a_sign(tmp_path):
    result = ex.ex_check(android(tmp_path, props={"ro.debuggable": "1", "ro.secure": "0"}))
    assert any("debug build" in f["what"] for f in result["findings"])
    assert result["level"] == ex.EX_FOUND


def test_cellebrites_imitated_usb_hardware_is_named(tmp_path):
    log = ("usb 1-1: New USB device found\n"
           "USB device attached: vidpid 045e:076c mfg/product/ver/serial HID/HID Device/12.34/0001\n")
    result = ex.ex_check(android(tmp_path, log=log))
    assert result["level"] == ex.EX_FOUND
    found = [f for f in result["findings"] if "Comfort Mouse" in f["what"]]
    assert found and "Amnesty International" in found[0]["means"]
    assert "045e:076c" in found[0]["evidence"]


def test_a_real_microsoft_mouse_is_not_mistaken_for_cellebrite(tmp_path):
    """The same device id with its own version number is just a mouse."""
    log = "USB device attached: vidpid 045e:076c mfg/product/ver/serial Microsoft/Mouse/1.07/0001\n"
    result = ex.ex_check(android(tmp_path, log=log))
    assert not any("Comfort Mouse" in f["what"] for f in result["findings"])


def test_authorised_computers_are_listed_with_their_names(tmp_path):
    keys = "A" * 64 + " police-lab-pc\n" + "B" * 64 + " my-laptop\n"
    result = ex.ex_check(android(tmp_path, keys=keys))
    found = [f for f in result["findings"] if "allowed to control" in f["what"]]
    assert found and "police-lab-pc" in found[0]["evidence"] and "2 computer" in found[0]["what"]
    assert result["facts"]["authorised_computers"] == ["police-lab-pc", "my-laptop"]
    assert found[0]["level"] == ex.EX_LOOK          # your own computer is normally in this list


def test_adb_keys_reader_handles_comments_and_unnamed_keys():
    text = "# a comment\n\n" + "A" * 64 + " desktop-1\n" + "B" * 64 + "\n"
    assert ex.ex_adb_keys(text) == ["desktop-1", "(a key with no name)"]
    assert ex.ex_adb_keys("") == [] and ex.ex_adb_keys("short line") == []


def test_usb_debugging_is_worth_knowing_not_an_accusation(tmp_path):
    result = ex.ex_check(android(tmp_path, settings={"adb_enabled": "1"}))
    found = [f for f in result["findings"] if "USB debugging" in f["what"]]
    assert found and found[0]["level"] == ex.EX_LOOK
    assert "needed by developers" in found[0]["means"]


def test_a_sideloaded_app_that_can_tap_the_screen_is_a_sign(tmp_path):
    result = ex.ex_check(android(
        tmp_path, settings={"enabled_accessibility_services": "com.odd.helper/.Svc"},
        packages=[{"name": "com.odd.helper", "installer": None, "system": False}]))
    found = [f for f in result["findings"] if "tap the screen" in f["what"]]
    assert found and found[0]["level"] == ex.EX_FOUND
    assert "Screen readers and automation apps use it legitimately" in found[0]["means"]


def test_a_shop_installed_accessibility_app_is_not_flagged(tmp_path):
    """A screen reader from the Play Store must not be called a forensics helper."""
    result = ex.ex_check(android(
        tmp_path, settings={"enabled_accessibility_services": "com.google.android.marvin.talkback/.Svc"},
        packages=[{"name": "com.google.android.marvin.talkback", "installer": "com.android.vending"}]))
    assert not any("tap the screen" in f["what"] for f in result["findings"])


def test_an_app_on_a_published_list_is_a_sign(tmp_path):
    iocs = IocSet([Indicator("com.spy.tool", "app", "primary", "app_id", "mvt-test", "Massistant")], "t", 0)
    result = ex.ex_check(android(tmp_path, packages=[{"name": "com.spy.tool", "installer": None,
                                                      "system": False}]), iocs)
    assert result["level"] == ex.EX_FOUND
    assert any("published list" in f["what"] and "Massistant" in f["means"] for f in result["findings"])


def test_missing_pieces_of_a_collection_are_said_to_be_missing(tmp_path):
    folder = tmp_path / "thin"
    folder.mkdir()
    (folder / "acquisition.json").write_text("{}", encoding="utf-8")
    result = ex.ex_check(str(folder))
    gaps = " ".join(result["gaps"])
    assert "adb_keys" in gaps and "packages.json" in gaps and "no log file" in gaps
    assert "NOT CHECKED" in ex.ex_render(result)


# --- iPhone ---------------------------------------------------------------------------------------------------

def test_an_unencrypted_backup_is_worth_knowing(tmp_path):
    result = ex.ex_check(iphone(tmp_path, manifest={"IsEncrypted": False}))
    found = [f for f in result["findings"] if "not encrypted" in f["what"]]
    assert found and found[0]["level"] == ex.EX_LOOK
    assert "says nothing about whether the phone was copied" in found[0]["means"]
    assert not any(f["level"] == ex.EX_FOUND for f in result["findings"])


def test_an_encrypted_backup_is_not_flagged(tmp_path):
    result = ex.ex_check(iphone(tmp_path, manifest={"IsEncrypted": True}))
    assert not any("not encrypted" in f["what"] for f in result["findings"])


def test_the_published_cellebrite_traces_are_found_in_a_backup(tmp_path):
    from zbtriage.devicetraces import DT_IOS_STRINGS
    host_id = [v for v in DT_IOS_STRINGS if v.isdigit()][0]
    result = ex.ex_check(iphone(tmp_path, info={"Device Name": "iPhone", "Notes": host_id}))
    assert result["level"] == ex.EX_FOUND
    found = [f for f in result["findings"] if "Cellebrite" in f["means"]]
    assert found and "Citizen Lab" in found[0]["means"]


def test_the_phones_own_details_are_shown(tmp_path):
    result = ex.ex_check(iphone(tmp_path, info={"Device Name": "Sam's iPhone", "Product Type": "iPhone14,2",
                                                "Product Version": "18.1",
                                                "Last Backup Date": "2026-11-01"}))
    text = ex.ex_render(result)
    assert "Sam's iPhone" in text and "iPhone14,2" in text and "18.1" in text


def test_a_backup_cannot_show_trusted_computers_and_says_so(tmp_path):
    result = ex.ex_check(iphone(tmp_path))
    gaps = " ".join(result["gaps"])
    assert "which computers it trusts" in gaps and "Reset Location & Privacy" in gaps
    assert "Accessories" in gaps


def test_a_damaged_backup_does_not_crash(tmp_path):
    folder = tmp_path / "broken"
    folder.mkdir()
    (folder / "Manifest.plist").write_bytes(b"\x00\x01 not a property list")
    (folder / "Info.plist").write_bytes(b"also not one")
    result = ex.ex_check(str(folder))
    assert result["kind"] == "iphone" and any("no readable" in g for g in result["gaps"])


# --- what the report says -------------------------------------------------------------------------------------

def test_a_found_sign_says_what_to_do(tmp_path):
    text = ex.ex_render(ex.ex_check(android(tmp_path, props={"ro.boot.verifiedbootstate": "orange"})))
    assert "Change the passwords" in text and "accessnow.org" in text
    assert "DIFFERENT device" in text


def test_being_copied_is_told_apart_from_being_infected(tmp_path):
    text = ex.ex_render(ex.ex_check(android(tmp_path)))
    assert "not the same as being infected" in text


def test_every_finding_explains_itself(tmp_path):
    collections = [android(tmp_path, props={"ro.boot.verifiedbootstate": "orange", "ro.debuggable": "1",
                                            "ro.secure": "0"},
                           settings={"adb_enabled": "1", "development_settings_enabled": "1",
                                     "enabled_accessibility_services": "com.odd.helper/.Svc"},
                           packages=[{"name": "com.odd.helper", "installer": None, "system": False}],
                           keys="A" * 64 + " pc\n",
                           log="USB device attached: vidpid 041e:3000 mfg/product/ver/serial S/Sound "
                               "Device/12.34/1\n", name="busy"),
                   iphone(tmp_path, manifest={"IsEncrypted": False}, name="backup2")]
    for folder in collections:
        for finding in ex.ex_check(folder)["findings"]:
            assert len(finding["means"]) > 60, finding["what"] + " does not explain itself"
            assert finding["level"] in (ex.EX_FOUND, ex.EX_LOOK)
            assert not finding["what"].endswith(".")


# --- entry points --------------------------------------------------------------------------------------------
from test_followup_fixes import bundle  # noqa: E402,F401  (pytest fixture)


def test_bundle_checks_a_collection_and_does_not_scan(bundle, capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(bundle, "reader_run", lambda *a, **k: pytest.fail("a computer scan must not start"),
                        raising=False)
    folder = android(tmp_path)
    assert bundle._bundle_main(["--no-menu", "--no-banner", "--no-feeds", "--was-extracted", folder]) == 0
    out = capsys.readouterr().out
    assert "WAS THIS PHONE PLUGGED INTO A FORENSICS TOOL?" in out and "not mean the phone was not copied" in out


def test_a_missing_folder_is_refused():
    from zbtriage import cli
    with pytest.raises(SystemExit):
        cli._parse(["--was-extracted", "no-such-collection"])
