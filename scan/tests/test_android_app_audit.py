"""Android app audit: every user-installed app's powers, OEM stores, transfers, restricted settings, owners, VPN."""
import json
import os

from test_android import check, collection

DUMPSYS = """DUMP OF SERVICE package:
  Packages:
    Package [com.watch.helper] (1):
      firstInstallTime=2026-10-20 09:00:00
    Package [com.store.spyish] (2):
      firstInstallTime=2025-01-01 09:00:00
    Package [com.honor.game] (3):
      firstInstallTime=2025-01-01 09:00:00
DUMP OF SERVICE appops:
  Uid u0a201:
    Package com.watch.helper:
      GET_USAGE_STATS (allow / switch COARSE_LOCATION=allow):
      ACCESS_RESTRICTED_SETTINGS (allow):
      RECORD_AUDIO (allow):
  Uid u0a202:
    Package com.store.spyish:
      GET_USAGE_STATS (allow):
      SYSTEM_ALERT_WINDOW (allow):
DUMP OF SERVICE device_policy:
Current Device Policy Manager state:
  Device Owner:
    admin=ComponentInfo{com.mdm.agent/com.mdm.agent.Admin}
    name=MDM
DUMP OF SERVICE deviceidle:
  Whitelist user apps:
    user,com.watch.helper,10201
"""


def make(**extra_settings):
    d = collection(spy=False)
    pkgs = json.load(open(os.path.join(d, "packages.json")))
    pkgs += [
        {"name": "com.watch.helper", "installer": "com.google.android.packageinstaller", "third_party": True,
         "system": False, "files": []},
        {"name": "com.store.spyish", "installer": "com.android.vending", "third_party": True, "system": False,
         "files": []},
        {"name": "com.honor.game", "installer": "com.hihonor.appmarket", "third_party": True, "system": False,
         "files": []},
        {"name": "com.moved.app", "installer": "com.sec.android.easyMover", "third_party": True, "system": False,
         "files": []},
    ]
    json.dump(pkgs, open(os.path.join(d, "packages.json"), "w"))
    json.dump({"started": "2026-10-23T20:00:24Z"}, open(os.path.join(d, "acquisition.json"), "w"))
    with open(os.path.join(d, "dumpsys.txt"), "w") as fh:
        fh.write(DUMPSYS)
    with open(os.path.join(d, "settings_secure.txt"), "w") as fh:
        fh.write("enabled_accessibility_services=com.watch.helper/.A\n"
                 "enabled_notification_listeners=com.watch.helper/.N\n")
        for k, v in extra_settings.items():
            fh.write("{}={}\n".format(k, v))
    return d


def leads_for(r, app):
    return [l.what for l in r.leads if app in l.what or app in l.location]


def test_honor_store_and_phone_transfer_are_not_sideloads():
    r = check(make())
    assert not leads_for(r, "com.honor.game")       # issue #43
    assert not leads_for(r, "com.moved.app")


def test_sideloaded_app_with_spy_powers_names_the_override_and_age():
    r = check(make())
    text = leads_for(r, "com.watch.helper")[0]
    assert "installed outside an app store" in text
    assert "installed 3 days before this check" in text
    assert "restricted-settings" not in text            # shown as the override sentence instead
    assert "protection against exactly this was switched off" in text
    assert "read all notifications" in text and "accessibility" in text
    assert "run in the background without battery limits" in text
    why = [l.usual_reason for l in r.leads if "com.watch.helper" in l.what][0]
    assert "Allow restricted settings" in why and "stopstalkerware.org" in why


def test_store_app_with_two_spy_powers_is_named():
    r = check(make())
    text = leads_for(r, "com.store.spyish")[0]
    assert text.startswith("app with the powers stalkerware needs: com.store.spyish (from an app store)")


def test_store_app_with_one_power_is_not_named():
    d = make()
    dump = open(os.path.join(d, "dumpsys.txt")).read().replace("      SYSTEM_ALERT_WINDOW (allow):\n", "")
    open(os.path.join(d, "dumpsys.txt"), "w").write(dump)
    assert not leads_for(check(d), "com.store.spyish")


def test_device_owner_and_always_on_vpn():
    r = check(make(always_on_vpn_app="com.vpn.thing"))
    whats = " | ".join(l.what for l in r.leads)
    assert "device owner app: com.mdm.agent" in whats
    assert "go through this app's VPN: com.vpn.thing" in whats


def test_no_vpn_setting_means_no_vpn_lead():
    r = check(make(always_on_vpn_app="null"))
    assert not any("VPN" in l.what for l in r.leads)


def test_isdi_dual_use_apps_are_grouped_and_stalkerware_named():
    d = make()
    pkgs = json.load(open(os.path.join(d, "packages.json")))
    pkgs += [{"name": "com.life360.android.safetymapd", "installer": "com.android.vending", "third_party": True,
              "system": False, "files": []},
             {"name": "aktualizacja.apps", "installer": "com.android.vending", "third_party": True,
              "system": False, "files": []}]
    json.dump(pkgs, open(os.path.join(d, "packages.json"), "w"))
    r = check(d)
    whats = " | ".join(l.what for l in r.leads)
    assert "can also be used to watch someone" in whats and "com.life360.android.safetymapd" in whats
    assert "listed as stalkerware by Cornell" in whats and "aktualizacja.apps" in whats
