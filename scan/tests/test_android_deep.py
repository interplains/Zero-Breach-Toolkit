"""Android: system-service state, install history, crash records, SMS backup and
device security (formats as AndroidQF writes them).

Pinned here:
  - a running spyware app, a REMOVED one in the battery history, one named only in
    system records, and one in a crash record are all findings (device-log or
    on-device), each once;
  - a sideloaded app's powers are spelled out in its 'worth a look' line;
  - the collection's own footprint (the ADB shell) and GrapheneOS's 'yellow' boot
    state are never flagged; an unlocked bootloader, a debug build and SELinux off are;
  - links in an SMS backup are 'received'; an encrypted or empty backup is a gap.
"""

from __future__ import annotations

import io
import json
import os
import sys
import tarfile
import tempfile
import unittest
import zipfile
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from test_android import check, collection  # noqa: E402
from zbtriage.result import EV_DEVICE_LOG, EV_ON_DEVICE, EV_RECEIVED  # noqa: E402

SPY = "com.spy.app"


def add_dumpsys(folder, **sections):
    with open(os.path.join(folder, "dumpsys.txt"), "w", encoding="utf-8") as fh:
        for name, body in sections.items():
            fh.write("-" * 20 + "\nDUMP OF SERVICE {}:\n{}\n".format(name, body))


def add_props(folder, **props):
    with open(os.path.join(folder, "getprop.txt"), "a", encoding="utf-8") as fh:
        for k, v in props.items():
            fh.write("[{}]: [{}]\n".format(k.replace("_", "."), v))


class TestDeepFindings(unittest.TestCase):
    def test_running_app_is_on_device(self):
        d = collection(spy=False)
        with open(os.path.join(d, "processes.txt"), "a") as fh:
            fh.write("u0_a99 4000 1 1 1 0 0 S {}:remote\n".format(SPY))
        hits = [(h.indicator, h.evidence) for h in check(d).hits]
        self.assertEqual(hits, [(SPY, EV_ON_DEVICE)])

    def test_older_androidqf_ps_txt_is_read(self):
        # Older AndroidQF releases wrote the process list as ps.txt.
        d = collection(spy=False)
        os.replace(os.path.join(d, "processes.txt"), os.path.join(d, "ps.txt"))
        with open(os.path.join(d, "ps.txt"), "a") as fh:
            fh.write("u0_a99 4000 1 1 1 0 0 S {}\n".format(SPY))
        r = check(d)
        self.assertEqual([(h.indicator, h.evidence) for h in r.hits], [(SPY, EV_ON_DEVICE)])
        self.assertFalse([c for c in r.checks if c.name == "android:processes" and not c.ran])

    def test_removed_app_still_shows_in_battery_history(self):
        d = collection(spy=False)
        add_dumpsys(d, batterystats="  Daily from 2026-10-01-00-00-00 to 2026-10-02-00-00-00:\n"
                                    "    Package changes:\n"
                                    "      Uninstall {} vers=3\n".format(SPY))
        r = check(d)
        hit = [h for h in r.hits if h.indicator == SPY]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0].evidence, EV_DEVICE_LOG)
        self.assertIn("REMOVED", hit[0].detail)
        self.assertEqual(hit[0].observed, "2026-10-02T00:00:00")

    def test_app_named_only_in_system_records_is_found_once(self):
        d = collection(spy=False)
        add_dumpsys(d, usagestats="  package={} totalTime=5\n  package={} x\n".format(SPY, SPY))
        hits = [h for h in check(d).hits if h.indicator == SPY]
        self.assertEqual([h.evidence for h in hits], [EV_DEVICE_LOG])

    def test_installed_app_is_not_reported_twice_from_the_logs(self):
        d = collection(spy=True)
        add_dumpsys(d, usagestats="  package={}\n".format(SPY))
        hits = [h for h in check(d).hits if h.indicator == SPY]
        self.assertEqual([h.evidence for h in hits], [EV_ON_DEVICE])

    def test_crash_record_naming_the_app(self):
        d = collection(spy=False)
        with zipfile.ZipFile(os.path.join(d, "bugreport.zip"), "w") as z:
            z.writestr("FS/data/tombstones/tombstone_03",
                       "Timestamp: 2026-09-20 12:33:31.7+0300\nCmdline: {}\npid: 1\n".format(SPY))
            z.writestr("FS/data/tombstones/tombstone_04",
                       "Timestamp: 2026-09-21 10:00:00.0+0300\nCmdline: /system/bin/ordinary\n")
        r = check(d)
        hit = [h for h in r.hits if h.indicator == SPY]
        self.assertEqual((len(hit), hit[0].evidence, hit[0].observed),
                         (1, EV_DEVICE_LOG, "2026-09-20T12:33:31"))
        self.assertEqual(r.submetrics["android_crash_records"], 2)


class TestSideloadPowersAndFootprint(unittest.TestCase):
    def test_powers_are_spelled_out(self):
        d = collection(spy=False, enabled_notification_listeners="com.example.launcher/.N")
        add_dumpsys(d,
                    appops="  Uid 10090:\n    Package com.example.launcher:\n"
                           "      READ_SMS (allow):\n      RECORD_AUDIO (allow):\n"
                           "      CAMERA (ignore):\n"
                           "  Uid 2000:\n    Package com.android.shell:\n"
                           "      REQUEST_INSTALL_PACKAGES (allow):\n",
                    package="Receiver Resolver Table:\n  Non-Data Actions:\n"
                            "      android.provider.Telephony.SMS_RECEIVED:\n"
                            "        2fcfaab com.example.launcher/.SmsIn\n"
                            "Service Resolver Table:\n"
                            "Package [com.example.launcher] (1a):\n"
                            "    firstInstallTime=2026-10-05 16:48:06\n")
        leads = [l for l in check(d).leads if "com.example.launcher" in l.what]
        self.assertEqual(len(leads), 1)
        what = leads[0].what
        for power in ("read SMS", "use the microphone", "listens for incoming SMS",
                      "read all notifications"):
            self.assertIn(power, what)
        self.assertNotIn("camera", what)                  # mode ignore = not granted
        self.assertEqual(leads[0].observed, "2026-10-05T16:48:06")
        self.assertFalse(any("com.android.shell" in l.what for l in check(d).leads))

    def test_device_security_signs(self):
        d = collection(spy=False)
        add_props(d, ro_debuggable="1", ro_boot_flash_locked="0")
        with open(os.path.join(d, "selinux.txt"), "w") as fh:
            fh.write("Permissive\n")
        whats = " | ".join(l.what for l in check(d).leads)
        for text in ("debug or engineering build", "bootloader is unlocked", "SELinux"):
            self.assertIn(text, whats)

    def test_grapheneos_yellow_boot_state_is_not_flagged(self):
        d = collection(spy=False)
        add_props(d, ro_boot_verifiedbootstate="yellow", ro_boot_flash_locked="1")
        with open(os.path.join(d, "selinux.txt"), "w") as fh:
            fh.write("Enforcing\n")
        self.assertFalse(any(l.check == "android:device-security" for l in check(d).leads))


def sms_backup(messages, encrypted=False, compressed=True):
    inner = zlib.compress(json.dumps(messages).encode())
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo("apps/com.android.providers.telephony/d_f/000000_sms_backup")
        info.size = len(inner)
        tar.addfile(info, io.BytesIO(inner))
    body = buf.getvalue()
    if compressed:
        body = zlib.compress(body)
    head = b"ANDROID BACKUP\n5\n" + (b"1" if compressed else b"0") + b"\n" + \
        (b"AES-256" if encrypted else b"none") + b"\n"
    return head + body


class TestMessages(unittest.TestCase):
    def folder_with(self, data):
        d = collection(spy=False)
        with open(os.path.join(d, "backup.ab"), "wb") as fh:
            fh.write(data)
        return d

    def test_link_in_an_sms_is_received(self):
        d = self.folder_with(sms_backup([
            {"address": "+100", "type": "1", "body": "Your parcel: https://spy-c2.example/t/9", "date": "1760000000000"},
            {"address": "+200", "body": "see you at 5", "date": "1760000001000"}]))
        r = check(d)
        hits = [(h.indicator, h.evidence) for h in r.hits]
        self.assertEqual(hits, [("spy-c2.example", EV_RECEIVED)])
        self.assertEqual(r.submetrics["android_sms_messages"], 2)
        self.assertTrue(r.hits[0].observed)

    def test_uncompressed_backup_also_reads(self):
        d = self.folder_with(sms_backup([{"body": "https://spy-c2.example/", "type": "1"}], compressed=False))
        self.assertEqual([h.evidence for h in check(d).hits], [EV_RECEIVED])

    def test_a_link_the_owner_sent_is_a_reference(self):
        # type 2 = sent; the owner wrote it, so it was not delivered to them.
        d = self.folder_with(sms_backup([{"body": "https://spy-c2.example/", "type": "2", "address": "+3"}]))
        self.assertEqual([h.evidence for h in check(d).hits], ["referenced"])

    def test_mms_text_is_read(self):
        inner = zlib.compress(json.dumps([
            {"date": "1760000000", "msg_box": "1", "mms_body": "click https://spy-c2.example/m",
             "mms_addresses": "[{'type': 137, 'address': '+12345678', 'charset': 106}]"},
            {"date": "1760000001", "msg_box": "1", "mms_body": None}]).encode())
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo("apps/com.android.providers.telephony/d_f/000001_mms_backup")
            info.size = len(inner)
            tar.addfile(info, io.BytesIO(inner))
        d = self.folder_with(b"ANDROID BACKUP\n5\n1\nnone\n" + zlib.compress(buf.getvalue()))
        r = check(d)
        self.assertEqual([(h.indicator, h.evidence) for h in r.hits], [("spy-c2.example", EV_RECEIVED)])
        self.assertIn("MMS from +12345678", r.hits[0].location)
        self.assertTrue(r.hits[0].observed.startswith("2025-"))
        self.assertFalse([c for c in r.checks if c.name == "android:messages" and not c.ran])

    def test_encrypted_or_empty_backup_is_a_gap(self):
        for data, words in ((sms_backup([], encrypted=True), "encrypted"), (b"", "empty")):
            with self.subTest(words=words):
                r = check(self.folder_with(data))
                gaps = [c.reason for c in r.checks if c.name == "android:messages" and not c.ran]
                self.assertTrue(gaps and words in gaps[0], gaps)


if __name__ == "__main__":
    unittest.main()


class TestDamagedCollections(unittest.TestCase):
    """Four ways a damaged collection could stop phone mode; each must cost only
    its own part, as a gap, never the report."""

    def test_truncated_acquisition_json(self):
        d = collection(spy=True)
        with open(os.path.join(d, "acquisition.json"), "w") as fh:
            fh.write('{"started": "2026-10')
        self.assertIn("com.spy.app", {h.indicator for h in check(d).hits})

    def test_non_object_entries(self):
        d = collection(spy=True)
        pkgs = json.load(open(os.path.join(d, "packages.json")))
        pkgs += ["junk", 7, None, {"name": "x.y", "files": ["junk", 3]}]
        json.dump(pkgs, open(os.path.join(d, "packages.json"), "w"))
        json.dump(["junk", {"path": "/data/local/tmp/spyd"}], open(os.path.join(d, "files.json"), "w"))
        r = check(d)
        self.assertIn("com.spy.app", {h.indicator for h in r.hits})
        self.assertIn("/data/local/tmp/spyd", {h.indicator for h in r.hits})

    def test_cut_short_sms_backup(self):
        d = collection(spy=False)
        data = sms_backup([{"body": "https://spy-c2.example/", "type": "1"}] * 50)
        with open(os.path.join(d, "backup.ab"), "wb") as fh:
            fh.write(data[: len(data) // 2])
        r = check(d)
        gaps = [c.reason for c in r.checks if c.name == "android:messages" and not c.ran]
        self.assertTrue(gaps and "cut short" in gaps[0], gaps)

    def test_unreadable_log_is_a_gap_not_a_crash(self):
        d = collection(spy=True)
        os.remove(os.path.join(d, "dumpsys.txt"))
        os.mkdir(os.path.join(d, "dumpsys.txt"))           # cannot be opened as a file
        r = check(d)
        self.assertIn("com.spy.app", {h.indicator for h in r.hits})
        self.assertIn("android:device-logs", [c.name for c in r.checks if not c.ran])

    def test_cli_keeps_the_report_if_the_module_itself_fails(self):
        import contextlib
        from unittest.mock import patch
        from zbtriage import cli
        from zbtriage.modules import android
        report = os.path.join(tempfile.mkdtemp(prefix="rep_"), "r.json")

        def boom(ctx):
            ctx.partial = android.ModuleResult("android")
            raise RuntimeError("simulated")
        with patch.object(android, "run", boom), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(["--no-banner", "--no-feeds", "--phone", collection(), "--json", report])
        doc = json.load(open(report, encoding="utf-8"))
        self.assertIn("android", doc["modules"])
        self.assertEqual(code, 3)


class TestFamilySafetyAppIsNotSpywareAlarm(unittest.TestCase):
    """Life360 from Google Play is on the Echap stalkerware list. It must read as a
    monitoring app to check, with safe advice about removing it, not as a serious
    spyware finding."""

    def test_life360_case(self):
        import datetime as _dt
        from zbtriage.context import ScanContext
        from zbtriage.iocs import Indicator, IocSet
        from zbtriage.modules import android
        from zbtriage.report import build_document, render_summary
        app = "com.life360.android.safetymapd"
        d = collection(spy=False)
        pkgs = json.load(open(os.path.join(d, "packages.json")))
        pkgs.append({"name": app, "installer": "com.android.vending", "third_party": True,
                     "system": False, "disabled": False, "uid": 9, "files": []})
        json.dump(pkgs, open(os.path.join(d, "packages.json"), "w"))
        iocs = IocSet([Indicator(app, "stalkerware", "primary", "app-id", "ECHAP", "Life360")],
                      "t.txt", None)
        r = android.run(ScanContext(iocs=iocs, emit=lambda _m: None, phone_path=d))
        doc = build_document(iocs, [r], _dt.datetime(2026, 10, 25))
        summary = render_summary(doc)
        self.assertNotIn("SERIOUS", summary)
        self.assertNotIn("expert help promptly", summary.lower())
        self.assertIn("PHONE-MONITORING APP", summary)
        self.assertIn(app, summary)                        # shown as written, not defanged
        self.assertNotIn("com[.]life360", summary)
        steps = [s["id"] for s in doc["next_steps"]]
        self.assertIn("stalkerware-safety", steps)
        self.assertNotIn("expert-help", steps)
        self.assertIn("Removing the app can alert", [s for s in doc["next_steps"]
                                                     if s["id"] == "stalkerware-safety"][0]["text"])
        self.assertIn("phone-monitoring app is installed", r.hits[0].detail)

    def test_echap_app_ids_get_the_stalkerware_tier(self):
        from zbtriage import feeds
        path = os.path.join(tempfile.mkdtemp(prefix="echap_"), "e.stix2")
        json.dump({"type": "bundle", "objects": [
            {"type": "indicator", "id": "indicator--1",
             "pattern": "[app:id='com.life360.android.safetymapd']"},
            {"type": "indicator", "id": "indicator--2",
             "pattern": "[domain-name:value='life360.com']"}]}, open(path, "w"))
        src = {"id": "x", "name": "Stalkerware", "cite": "ECHAP", "format": "stix2",
               "category": "stalkerware", "family": ""}
        s = feeds._load_source_file(src, path)
        self.assertEqual({i.tier for i in s.indicators}, {"stalkerware"})
        self.assertEqual(len(s.indicators), 2)


class TestServerPushedFlagsAreNotTraces(unittest.TestCase):
    """Pixel phones carry a Google flag whose value lists hundreds of apps the
    notification features must skip, family-safety apps among them. It appears in
    dumpsys device_config and again in the CONFIG table of dumpsys settings. A name
    in a flag value is not a trace of the app; a name in the same dump's other
    tables still is."""

    FLAG = "device_personalization_services/SmartNotification__excluded_packages"

    def hits_for(self, **sections):
        d = collection(spy=False)
        add_dumpsys(d, **sections)
        return [h for h in check(d).hits if h.indicator == SPY]

    def test_device_config_flag_is_not_a_trace(self):
        flag = "DeviceConfig flags:\n{}=android,com.Slack,{},com.nest.android\n".format(
            self.FLAG, SPY)
        self.assertEqual(self.hits_for(device_config=flag), [])

    def test_settings_config_table_is_not_a_trace(self):
        config = ("CONFIG SETTINGS (user 0)\n"
                  "_id:11818 name:{} pkg:com.google.android.gms value:android,{}\n"
                  "_id:11819 name:x/prompt pkg:com.google.android.gms value:first line\n"
                  "RULES FOR REPLYING:\n  mention {} here\n").format(self.FLAG, SPY, SPY)
        self.assertEqual(self.hits_for(settings=config), [])

    def test_settings_tables_after_the_config_table_are_still_searched(self):
        settings = ("CONFIG SETTINGS (user 0)\n"
                    "_id:1 name:{} pkg:com.google.android.gms value:android\n"
                    "SECURE SETTINGS (user 0)\n"
                    "_id:2 name:enabled_notification_listeners pkg:android "
                    "value:{}/.Listener\n").format(self.FLAG, SPY)
        self.assertEqual([h.evidence for h in self.hits_for(settings=settings)],
                         [EV_DEVICE_LOG])

    def test_service_after_device_config_is_still_searched(self):
        hits = self.hits_for(device_config="DeviceConfig flags:\na/b=android\n",
                             usagestats="  package={} totalTime=5\n".format(SPY))
        self.assertEqual([h.evidence for h in hits], [EV_DEVICE_LOG])
