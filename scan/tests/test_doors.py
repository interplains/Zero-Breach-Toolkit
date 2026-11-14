"""Doors to close: parsers and decisions, with no real system read."""
import json
from types import SimpleNamespace

import pytest

from zbtriage.modules import doors
from zbtriage.result import ModuleResult


def test_remote_access_and_monitoring_programs_are_recognised():
    found = doors.dr_match_programs(["TeamViewer 15.60", "AnyDesk", "Spyrix Free Keylogger", "Notepad++",
                                     "RealVNC Viewer 7.15", "Radmin VPN 2.0", "Radmin Server 3.5",
                                     "Chrome Remote Desktop Host", "Splashtop Personal"])
    names = {p: k for p, k, _m in found}
    assert names["TeamViewer"] == "remote" and names["AnyDesk"] == "remote"
    assert names["Spyrix"] == "monitoring"
    assert names["Radmin Server"] == "remote" and names["Chrome Remote Desktop"] == "remote"
    assert "RealVNC / VNC Server" not in names           # a viewer controls OTHER computers
    assert "Splashtop" not in names                      # the personal client, not the streamer
    assert not any("Notepad" in m for _p, _k, m in found)


def test_viewer_rule_does_not_hide_teamviewer():
    assert doors.dr_match_programs(["TeamViewer Host"])[0][0] == "TeamViewer"


def test_monitoring_is_high_and_remote_is_medium(monkeypatch):
    monkeypatch.setattr(doors.sys, "platform", "linux")
    monkeypatch.setattr(doors, "_dr_posix_program_names", lambda: ["kidlogger", "anydesk"])
    r = ModuleResult("doors")
    doors._check_programs(r)
    sev = {d.title: d.severity for d in r.doors}
    assert sev["Monitoring software is installed: KidLogger"] == "high"
    assert sev["Remote-access software is installed: AnyDesk"] == "medium"


def test_nothing_installed_is_a_closed_door(monkeypatch):
    monkeypatch.setattr(doors.sys, "platform", "linux")
    monkeypatch.setattr(doors, "_dr_posix_program_names", lambda: ["firefox", "libreoffice"])
    r = ModuleResult("doors")
    doors._check_programs(r)
    assert [d.state for d in r.doors] == ["closed"]


def test_firewall_profiles():
    assert doors.dr_firewall_state("Domain True\nPrivate False\nPublic True\n") == \
        {"Domain": True, "Private": False, "Public": True}
    assert doors.dr_firewall_state("garbage") == {}


@pytest.mark.parametrize("tree,expected", [
    ({"blockdevices": [{"name": "nvme0n1", "type": "disk", "children": [
        {"name": "p3", "type": "part", "children": [{"name": "root", "type": "crypt", "mountpoint": "/"}]}]}]}, True),
    ({"blockdevices": [{"name": "sda", "type": "disk", "children": [
        {"name": "sda2", "type": "part", "mountpoint": "/"}]}]}, False),
    ({"blockdevices": [{"name": "sda", "type": "disk", "children": [
        {"name": "sda1", "type": "crypt", "mountpoints": ["/home"]}]}]}, None),
])
def test_linux_root_encryption(tree, expected):
    assert doors.dr_linux_root_encrypted(json.dumps(tree)) is expected


def test_linux_root_encryption_bad_input():
    assert doors.dr_linux_root_encrypted("not json") is None


def test_extension_names_and_all_sites_access():
    name, broad = doors.dr_extension_info({"name": "__MSG_appName__", "host_permissions": ["<all_urls>"]},
                                          {"appName": {"message": "Helper"}})
    assert (name, broad) == ("Helper", True)
    assert doors.dr_extension_info({"name": "Tabs", "permissions": ["tabs", "storage"]}) == ("Tabs", False)
    assert doors.dr_extension_info({"name": "X", "content_scripts": [{"matches": ["*://*/*"]}]})[1] is True


def test_emails_are_masked():
    assert doors.mask_email("sara@gmail.com") == "s***@gmail.com"
    assert doors.mask_email("not an email") == ""
    assert doors.mask_email("") == ""


def _chromium(tmp_path, ext_id, manifest, email=""):
    user_data = tmp_path / "User Data"
    ext = user_data / "Default" / "Extensions" / ext_id / "1.0_0"
    ext.mkdir(parents=True)
    (ext / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    (user_data / "Local State").write_text(json.dumps(
        {"profile": {"info_cache": {"Default": {"name": "Person 1", "user_name": email}}}}), encoding="utf-8")
    return str(user_data)


def test_known_malicious_extension_is_a_high_door_and_account_is_a_lead(monkeypatch, tmp_path):
    from zbtriage.modules import browser
    bad_id = "a" * 32
    user_data = _chromium(tmp_path, bad_id, {"name": "Free VPN"}, email="ex@example.org")
    monkeypatch.setattr(browser, "CHROMIUM_ROOTS", [("chrome", user_data)])
    monkeypatch.setattr(browser, "_firefox_roots", lambda: [])
    monkeypatch.setattr(doors, "_bad_extension_ids", lambda: {bad_id: "Free VPN: spyware (researcher-confirmed)"})
    r = ModuleResult("doors")
    doors._check_browsers(r)
    high = [d for d in r.doors if d.severity == "high"]
    assert high and "known to be malicious" in high[0].title and bad_id in high[0].observed
    assert [l.location for l in r.leads] == ["chrome (Person 1): e***@example.org"]
    assert "ex@example.org" not in json.dumps([l.to_dict() for l in r.leads])


def test_shipped_malicious_list_is_well_formed():
    from zbtriage.extensiondata import BAD_EXTENSIONS
    import re
    assert len(BAD_EXTENSIONS) > 5000
    assert all(re.fullmatch(r"[a-p]{32}", k) for k in BAD_EXTENSIONS)


def test_one_failing_check_does_not_hide_the_others(monkeypatch):
    monkeypatch.setattr(doors.sys, "platform", "linux")
    monkeypatch.setattr(doors, "_check_programs", lambda r: (_ for _ in ()).throw(RuntimeError("boom")))
    monkeypatch.setattr(doors, "_check_linux", lambda r: r.ran("linux-disk-encryption"))
    monkeypatch.setattr(doors, "_check_browsers", lambda r: r.ran("browser-extensions"))
    monkeypatch.setattr(doors, "_check_downloads", lambda r: r.ran("remote-access-downloads"))
    r = doors.run(SimpleNamespace(partial=None))
    assert any(not c.ran and "boom" in c.reason for c in r.checks)
    assert any(c.ran and c.name == "browser-extensions" for c in r.checks)


def test_doors_never_change_the_status():
    r = ModuleResult("doors")
    from zbtriage.result import Door
    r.add_door(Door("x:y", "open", "Something is open", severity="high"))
    r.ran("x")
    assert r.status == "CLEAN"
    with pytest.raises(ValueError):
        r.add_door(Door("x:z", "maybe", "bad state"))


def test_report_section_and_summary_line():
    from zbtriage import report
    doc = {"doors": report._doors({"doors": {"doors": [
        {"door": "a", "state": "closed", "title": "Firewall on", "severity": "medium"},
        {"door": "b", "state": "open", "title": "Disk not encrypted", "severity": "high", "why": "w", "fix": "f",
         "setting": "ms-settings:deviceencryption", "observed": ""},
        {"door": "c", "state": "unknown", "title": "Secure Boot could not be checked", "severity": "medium"}]}})}
    assert [d["door"] for d in doc["doors"]] == ["b", "c", "a"]
    lines = []
    report._render_doors(lines.append, doc)
    text = "\n".join(lines)
    assert "DOORS TO CLOSE" in text and "Disk not encrypted" in text and "ms-settings:deviceencryption" in text
    assert "Could not check: Secure Boot" in text and "Already closed: 1 protection" in text


def test_iphone_passcode_and_lockdown_doors():
    from zbtriage.modules import ios
    r = ModuleResult("ios")
    ios.ios_passcode_door(r, False)
    ios.ios_lockdown_door(r, False)
    states = {d.door: (d.state, d.severity) for d in r.doors}
    assert states == {"iphone:passcode": ("open", "high"), "iphone:lockdown-mode": ("open", "medium")}
    r = ModuleResult("ios")
    ios.ios_passcode_door(r, True)
    ios.ios_lockdown_door(r, True)
    assert {d.state for d in r.doors} == {"closed"}
    r = ModuleResult("ios")
    ios.ios_passcode_door(r, None)          # not recorded in the backup: say nothing rather than guess
    ios.ios_lockdown_door(r, None)
    assert r.doors == []


def test_android_encryption_and_updates_doors():
    import datetime
    from zbtriage.modules import android
    r = ModuleResult("android")
    r_props = {"ro.crypto.state": "unencrypted",
               "ro.build.version.security_patch": (datetime.date.today() - datetime.timedelta(days=400)).isoformat()}
    android._an_properties(r, SimpleNamespace(iocs=SimpleNamespace(lookup_typed=lambda *a: None)), r_props)
    states = {d.door: d.state for d in r.doors}
    assert states["android:encryption"] == "open" and states["android:security-updates"] == "open"


@pytest.mark.parametrize("uri,ok", [
    ("ms-settings:deviceencryption", True), ("windowsdefender://network", True),
    ("x-apple.systempreferences:com.apple.preference.security?FileVault", True),
    ("https://example.com/", False), ("file:///C:/Windows/system32/cmd.exe", False),
    ("ms-settings:x & calc", False), ("", False)])
def test_window_opens_only_settings_links(uri, ok):
    from zbtriage import gui
    assert gui.gui_setting_allowed(uri) is ok


def test_every_door_setting_link_is_openable():
    import re
    from zbtriage import gui
    from zbtriage.modules import doors as dm, ios, android
    import inspect
    for module in (dm, ios, android):
        for uri in re.findall(r'"((?:ms-settings|windowsdefender|x-apple\.systempreferences)[^"]*)"',
                              inspect.getsource(module)):
            assert gui.gui_setting_allowed(uri), uri


def test_recheck_runs_only_the_doors_check(monkeypatch):
    from zbtriage import gui
    from zbtriage.modules import doors as dm
    from zbtriage.result import Door
    def fake_run(ctx):
        r = ModuleResult("doors")
        r.add_door(Door("x:y", "open", "Something"))
        return r
    monkeypatch.setattr(dm, "run", fake_run)
    assert gui.gui_doors_recheck() == [{"door": "x:y", "state": "open", "title": "Something", "why": "", "fix": "",
                                        "setting": "", "severity": "medium", "observed": "", "module": "doors"}]
