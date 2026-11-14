"""wifi-settings: saved Wi-Fi settings as prevention leads; read only, no keys."""
import json
import os
import tempfile
from unittest.mock import patch

import pytest

from zbtriage.context import ScanContext
from zbtriage.iocs import IocSet
from zbtriage.modules import wifi

NS = "http://www.microsoft.com/networking/WLAN/profile/v1"
SECRET = "KEY-MATERIAL-MUST-NEVER-BE-READ"


def profile_xml(ssid, auth, enc, mode="auto", hidden=False, key=True):
    shared = ("<sharedKey><keyType>passPhrase</keyType><protected>true</protected>"
              "<keyMaterial>{}</keyMaterial></sharedKey>".format(SECRET)) if key else ""
    return ('<?xml version="1.0"?><WLANProfile xmlns="{ns}"><name>{s}</name><SSIDConfig><SSID>'
            "<name>{s}</name></SSID><nonBroadcast>{h}</nonBroadcast></SSIDConfig>"
            "<connectionType>ESS</connectionType><connectionMode>{m}</connectionMode>"
            "<MSM><security><authEncryption><authentication>{a}</authentication>"
            "<encryption>{e}</encryption><useOneX>false</useOneX></authEncryption>{k}"
            "</security></MSM></WLANProfile>").format(ns=NS, s=ssid, h=str(hidden).lower(), m=mode,
                                                      a=auth, e=enc, k=shared)


def ctx():
    return ScanContext(IocSet([], "fixture", None), emit=lambda _m: None)


def windows_export(files, rc=0, out="", err=""):
    """A stand-in for `netsh wlan export profile folder=...` writing XML files."""
    def fake(argv, timeout=60):
        assert argv[:4] == ["netsh", "wlan", "export", "profile"]
        assert not any("key=" in a.lower() for a in argv), "keys must never be requested"
        folder = argv[4].split("=", 1)[1]
        for n, text in enumerate(files):
            with open(os.path.join(folder, "Wi-Fi-{}.xml".format(n)), "w", encoding="utf-8") as fh:
                fh.write(text)
        return rc, out, err
    return fake


def run_windows(files, visible=(), visible_error=None, **kw):
    """Run the reader as on Windows, with a stand-in export and a stand-in list of nearby networks
    (the real WLAN API is never touched by the tests)."""
    def nearby():
        if visible_error:
            raise visible_error
        return list(visible)
    # Faking sys.platform is global: the shared temp-folder helper would then also believe it is on Windows
    # and refuse a non-Windows host's /tmp (found running the suite on Linux, 2026-11-12). Hand it the host's
    # real temp folder so the Windows path can be exercised on any machine.
    with patch.object(wifi.sys, "platform", "win32"), patch.object(wifi, "_wifi_run", windows_export(files, **kw)), \
            patch.object(wifi, "_wifi_visible_windows", nearby), \
            patch.object(wifi, "local_temp_dir", tempfile.gettempdir):
        return wifi.run(ctx())


def test_windows_profile_types():
    p = wifi.wifi_windows_profile
    assert p(profile_xml("Cafe", "open", "none"))["security"] == "open"
    assert p(profile_xml("Old", "open", "WEP"))["security"] == "wep"
    assert p(profile_xml("Old2", "shared", "WEP"))["security"] == "wep"
    assert p(profile_xml("Legacy", "WPAPSK", "TKIP"))["security"] == "wpa-tkip"
    assert p(profile_xml("Mixed", "WPA2PSK", "TKIP"))["security"] == "wpa-tkip"
    assert p(profile_xml("Home", "WPA2PSK", "AES"))["security"] == "protected"
    assert p(profile_xml("Home6", "WPA3SAE", "AES"))["security"] == "protected"
    assert p(profile_xml("Work", "WPA2", "AES"))["security"] == "enterprise"
    assert p(profile_xml("Airport", "OWE", "AES"))["security"] == "protected"


def test_leads_for_weak_networks_and_none_for_good_ones():
    r = run_windows([profile_xml("Cafe", "open", "none", key=False),
                     profile_xml("Cafe-manual", "open", "none", mode="manual", key=False),
                     profile_xml("OldRouter", "open", "WEP"),
                     profile_xml("Legacy", "WPAPSK", "TKIP"),
                     profile_xml("Home", "WPA2PSK", "AES"),
                     profile_xml("Hidden", "WPA2PSK", "AES", hidden=True)])
    places = sorted(l.location for l in r.leads)
    assert places == ['Wi-Fi network "Cafe"', 'Wi-Fi network "Hidden"', 'Wi-Fi network "Legacy"',
                      'Wi-Fi network "OldRouter"']
    assert all(c.ran for c in r.checks) and r.checks
    assert not r.hits
    assert r.checked == 6


def test_key_material_is_never_read_or_reported():
    r = run_windows([profile_xml("OldRouter", "open", "WEP")])
    dumped = json.dumps(r.to_dict(), default=str)
    assert SECRET not in dumped


def test_export_files_are_deleted(tmp_path):
    seen = {}
    real = windows_export([profile_xml("Home", "WPA2PSK", "AES")])

    def spy(argv, timeout=60):
        seen["folder"] = argv[4].split("=", 1)[1]
        return real(argv, timeout)
    # The nearby-networks lookup is stubbed too: without it this test called the real Windows WLAN API (on
    # Windows it read the actual adapter; elsewhere it failed with AttributeError), against the file's own rule.
    with patch.object(wifi.sys, "platform", "win32"), patch.object(wifi, "_wifi_run", spy), \
            patch.object(wifi, "local_temp_dir", tempfile.gettempdir), \
            patch.object(wifi, "_wifi_visible_windows", lambda: []):
        wifi.run(ctx())
    assert not os.path.exists(seen["folder"])


def test_no_wifi_is_not_a_gap():
    r = run_windows([], rc=1, out="The Wireless AutoConfig Service (wlansvc) is not running.")
    assert r.checks and all(c.ran for c in r.checks)
    assert not r.leads


def test_export_failure_is_a_gap():
    r = run_windows([], rc=5, err="Access is denied.")
    assert any(not c.ran for c in r.checks)


def test_damaged_profile_is_skipped_not_fatal():
    r = run_windows(["<not xml", profile_xml("Cafe", "open", "none", key=False)])
    assert r.skipped == 1
    assert [l.location for l in r.leads] == ['Wi-Fi network "Cafe"']


def test_linux_networkmanager():
    def fake(argv, timeout=60):
        if argv[:3] == ["nmcli", "-t", "-f"]:
            return 0, "u1:802-11-wireless\nu2:802-11-wireless\nu3:802-3-ethernet\nu4:802-11-wireless\n", ""
        uuid = argv[-1]
        values = {"u1": "Cafe\nyes\nno\n\n", "u2": "Home\nyes\nno\nsae\n", "u4": "Old\nyes\nno\nnone\n40-bit\n"}
        return 0, values[uuid], ""
    with patch.object(wifi.sys, "platform", "linux"), patch.object(wifi.shutil, "which", return_value="/usr/bin/nmcli"), \
            patch.object(wifi, "_wifi_run", fake):
        r = wifi.run(ctx())
    assert sorted(l.location for l in r.leads) == ['Wi-Fi network "Cafe"', 'Wi-Fi network "Old"']
    assert r.checked == 3


def test_linux_escaped_colons_in_names_are_undone():
    def fake(argv, timeout=60):
        if argv[:3] == ["nmcli", "-t", "-f"]:
            return 0, "u1:802-11-wireless\n", ""
        return 0, "Cafe\\:Guest\nyes\nno\n\n", ""
    with patch.object(wifi.sys, "platform", "linux"), patch.object(wifi.shutil, "which", return_value="/usr/bin/nmcli"), \
            patch.object(wifi, "_wifi_run", fake):
        r = wifi.run(ctx())
    assert [l.location for l in r.leads] == ['Wi-Fi network "Cafe:Guest"']


def test_linux_without_networkmanager_is_a_gap():
    with patch.object(wifi.sys, "platform", "linux"), patch.object(wifi.shutil, "which", return_value=None):
        r = wifi.run(ctx())
    assert any(not c.ran for c in r.checks)


@pytest.mark.parametrize("mode,lead", [("spairport_security_mode_wep", True),
                                       ("spairport_security_mode_none", True),
                                       ("spairport_security_mode_wpa_personal_mixed", True),
                                       ("spairport_security_mode_wpa2_personal", False),
                                       ("spairport_security_mode_wpa3_transition", False)])
def test_macos_current_network(mode, lead):
    doc = {"SPAirPortDataType": [{"spairport_airport_interfaces": [
        {"_name": "en0", "spairport_current_network_information": {"_name": "Net", "spairport_security_mode": mode}}]}]}
    with patch.object(wifi.sys, "platform", "darwin"), \
            patch.object(wifi, "_wifi_run", return_value=(0, json.dumps(doc), "")):
        r = wifi.run(ctx())
    assert bool(r.leads) == lead
    assert all(c.ran for c in r.checks)


def test_leads_never_change_the_verdict():
    from zbtriage.report import build_document
    r = run_windows([profile_xml("Cafe", "open", "none", key=False)])
    document = build_document(IocSet([], "fixture", None), [r], __import__("datetime").datetime.now())
    assert document["verdict"]["status"] == "NO_KNOWN_INDICATORS"


# --- look-alike networks nearby -----------------------------------------------------------------

def saved(ssid, security):
    return {"ssid": ssid, "security": security, "auto": True, "hidden": False}


def test_lookalike_open_copy_of_protected_network():
    found = wifi.wifi_lookalikes([saved("Home", "protected"), saved("Cafe", "open")],
                                 [("Home", "open"), ("Home", "protected"), ("Cafe", "open"), ("Other", "open")])
    assert found == [("Home", "open")]


def test_lookalike_wep_copy_and_no_false_alarm_for_equal_security():
    assert wifi.wifi_lookalikes([saved("Office", "enterprise")], [("Office", "wep")]) == [("Office", "wep")]
    assert wifi.wifi_lookalikes([saved("Home", "protected")], [("Home", "protected"), ("Home", "enterprise")]) == []


@pytest.mark.parametrize("text,kind", [("", "open"), ("--", "open"), ("WEP", "wep"), ("WPA1", "wpa-tkip"),
                                       ("WPA1 WPA2", "protected"), ("WPA3", "protected"), ("WPA2 802.1X", "protected")])
def test_nm_visible_security(text, kind):
    assert wifi.wifi_nm_visible_security(text) == kind


def test_lookalike_lead_from_run():
    r = run_windows([profile_xml("Home", "WPA2PSK", "AES")], visible=[("Home", "open")])
    assert [l.check for l in r.leads] == ["wifi-lookalike"]
    assert any(c.ran and c.name == "wifi-lookalike" for c in r.checks)


def test_lookalike_list_failure_is_a_gap_but_saved_check_still_ran():
    r = run_windows([profile_xml("Home", "WPA2PSK", "AES")], visible_error=OSError("WlanOpenHandle failed (5)"))
    assert any(c.ran and c.name == "wifi-settings" for c in r.checks)
    assert any(not c.ran and c.name == "wifi-lookalike" for c in r.checks)


def test_redacted_names_never_match():
    from zbtriage.modules import wifi
    saved = [{"ssid": "<redacted>", "security": wifi._WIFI_OK}, {"ssid": "", "security": wifi._WIFI_OK}]
    visible = [("<redacted>", wifi._WIFI_OPEN), ("", wifi._WIFI_OPEN)]
    assert wifi.wifi_lookalikes(saved, visible) == []
