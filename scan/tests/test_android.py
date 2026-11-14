"""Android module (AndroidQF collection folder) and --phone.

Pinned here, on a synthetic collection:
  - app ids, APK fingerprints, signing certificates, properties, file paths and
    log mentions are findings with the right grade;
  - 'gatekeeperd' on Android is NEVER a finding, even though Amnesty's iPhone
    Pegasus list names a process 'gatekeeperd';
  - sideloaded apps, accessibility access, verification off and an old patch are
    'worth a look'; store installs and system apps are not;
  - USB debugging is reported as the collection's own footprint, not a lead;
  - --phone checks only the phone, and a network folder is refused.
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import cli  # noqa: E402
from zbtriage.context import ScanContext  # noqa: E402
from zbtriage.iocs import Indicator, IocSet  # noqa: E402
from zbtriage.modules import android  # noqa: E402
from zbtriage.result import EV_DEVICE_LOG, EV_ON_DEVICE  # noqa: E402

APK_SHA = "a" * 64
CERT_SHA = "b" * 64


def iocs():
    return IocSet([
        Indicator("com.spy.app", "artifact", "primary", "app-id", "t", "Spyfam"),
        Indicator(APK_SHA, "sample", "primary", "sha256", "t", "Spyfam"),
        Indicator(CERT_SHA, "artifact", "primary", "app-cert", "t", "Spyfam"),
        Indicator("sys.spy.flag", "artifact", "primary", "android-property", "t", "Spyfam"),
        Indicator("/data/local/tmp/spyd", "artifact", "primary", "file-path", "t", "Spyfam"),
        Indicator("gatekeeperd", "artifact", "primary", "process", "t", "Pegasus"),
        Indicator("spy-c2.example", "cc", "primary", "domain", "t", "Spyfam"),
    ], "t.txt", None)


def collection(spy=True, **settings):
    d = tempfile.mkdtemp(prefix="aqf_")
    pkgs = [
        {"name": "com.android.chrome", "installer": "com.android.vending", "third_party": True,
         "system": False, "disabled": False, "uid": 1, "files": []},
        {"name": "com.android.privatespace", "installer": "null", "third_party": False,
         "system": False, "disabled": False, "uid": 2, "files": []},
        {"name": "com.example.launcher", "installer": "com.android.packageinstaller",
         "third_party": True, "system": False, "disabled": False, "uid": 3, "files": []},
    ]
    if spy:
        pkgs.append({"name": "com.spy.app", "installer": "com.android.vending",
                     "third_party": True, "system": False, "disabled": False, "uid": 4,
                     "files": [{"path": "/data/app/spy/base.apk", "sha256": APK_SHA.upper(),
                                "certificate": {"Sha256": CERT_SHA, "Sha1": "c" * 40}}]})
    json.dump(pkgs, open(os.path.join(d, "packages.json"), "w"))
    json.dump([{"path": "/data/local/tmp/spyd" if spy else "/data/local/tmp/ok",
                "sha256": ""}], open(os.path.join(d, "files.json"), "w"))
    json.dump([], open(os.path.join(d, "root_binaries.json"), "w"))
    json.dump({"started": "2026-10-23T20:00:24Z"}, open(os.path.join(d, "acquisition.json"), "w"))
    with open(os.path.join(d, "processes.txt"), "w") as fh:
        fh.write("USER PID PPID VSZ RSS WCHAN ADDR S NAME\n"
                 "system 900 1 1 1 0 0 S gatekeeperd\n")
    with open(os.path.join(d, "getprop.txt"), "w") as fh:
        fh.write("[ro.build.version.security_patch]: [{}]\n".format(
            settings.pop("patch", "2099-01-01")))
        if spy:
            fh.write("[sys.spy.flag]: [1]\n")
    with open(os.path.join(d, "settings_global.txt"), "w") as fh:
        fh.write("adb_enabled=1\n")
        for k, v in settings.items():
            fh.write("{}={}\n".format(k, v))
    with open(os.path.join(d, "dumpsys.txt"), "w") as fh:
        fh.write("Connection to https://spy-c2.example/beacon\n" if spy else "nothing\n")
    return d


def check(folder):
    return android.run(ScanContext(iocs=iocs(), emit=lambda _m: None, phone_path=folder))


class TestFindings(unittest.TestCase):
    def test_every_kind_is_found_with_its_grade(self):
        r = check(collection(spy=True))
        got = {(h.indicator, h.evidence) for h in r.hits}
        self.assertEqual(got, {("com.spy.app", EV_ON_DEVICE), (APK_SHA, EV_ON_DEVICE),
                               (CERT_SHA, EV_ON_DEVICE), ("sys.spy.flag", EV_ON_DEVICE),
                               ("/data/local/tmp/spyd", EV_ON_DEVICE),
                               ("spy-c2.example", EV_DEVICE_LOG)})

    def test_gatekeeperd_is_never_pegasus_on_android(self):
        r = check(collection(spy=False))
        self.assertEqual(r.hits, [])
        self.assertTrue(any("iPhone investigations" in n for n in r.notes))


class TestWorthALook(unittest.TestCase):
    def test_only_the_sideloaded_app_is_flagged(self):
        r = check(collection(spy=False))
        whats = [l.what for l in r.leads]
        self.assertEqual(len(whats), 1, whats)
        self.assertIn("com.example.launcher", whats[0])

    def test_honor_store_install_is_not_a_sideload(self):
        # Honor split from Huawei in 2020: its store is com.hihonor.appmarket,
        # not com.huawei.appmarket. An app it installed is a store install.
        d = collection(spy=False)
        path = os.path.join(d, "packages.json")
        pkgs = json.load(open(path, encoding="utf-8"))
        pkgs.append({"name": "com.example.honorapp", "installer": "com.hihonor.appmarket",
                     "third_party": True, "system": False, "disabled": False,
                     "uid": 9, "files": []})
        json.dump(pkgs, open(path, "w"))
        whats = [l.what for l in check(d).leads]
        self.assertEqual(len(whats), 1, whats)
        self.assertIn("com.example.launcher", whats[0])
        self.assertFalse(any("honorapp" in w for w in whats))

    def test_accessibility_verification_and_old_patch(self):
        d = collection(spy=False, enabled_accessibility_services="com.x/.Svc:com.y/.Svc",
                       package_verifier_enable="0", patch="2020-01-05")
        r = check(d)
        whats = " | ".join(l.what for l in r.leads)
        self.assertIn("accessibility access: com.x/.Svc, com.y/.Svc", whats)
        # Protections moved to "Doors to close" (prevention), out of "worth a look"
        doors = {x.door: x for x in r.doors}
        self.assertEqual(doors["android:play-protect"].state, "open")
        self.assertEqual(doors["android:security-updates"].state, "open")
        self.assertIn("security updates are", doors["android:security-updates"].title)

    def test_usb_debugging_is_our_footprint_not_a_lead(self):
        r = check(collection(spy=False))
        self.assertTrue(any("USB debugging" in n for n in r.notes))
        self.assertFalse(any("debugging" in l.what for l in r.leads))
        # ... but it is a (low) door to close once the collection is done
        self.assertEqual([(x.state, x.severity) for x in r.doors if x.door == "android:usb-debugging"],
                         [("open", "low")])


class TestFolderAndCli(unittest.TestCase):
    def test_not_a_collection_is_a_gap(self):
        r = check(tempfile.mkdtemp(prefix="empty_"))
        self.assertEqual([(c.name, c.ran) for c in r.checks], [("android", False)])

    def test_phone_option_checks_only_the_phone(self):
        report = os.path.join(tempfile.mkdtemp(prefix="rep_"), "r.json")
        out = io.StringIO()
        with patch.object(cli, "_default_ioc_paths", return_value=[]), \
                patch("zbtriage.cli.load_any", side_effect=lambda *a, **k: iocs()), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = cli.main(["--iocs", "x.txt", "--phone", collection(spy=True),
                             "--json", report])
        doc = json.load(open(report, encoding="utf-8"))
        self.assertEqual(set(doc["modules"]), {"android", "android-intrusion"})
        self.assertEqual(code, 2)

    @unittest.skipUnless(sys.platform == "win32", "UNC paths are a Windows concept")
    def test_network_folder_is_refused(self):
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["--phone", r"\\server\share\aqf"]), 1)


if __name__ == "__main__":
    unittest.main()
