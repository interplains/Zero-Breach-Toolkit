"""Training mode: practise reading a report on a made-up phone.

Trainers teaching people to use this tool need a result to show. Real spyware
cannot be used for that, and a trainer's own devices will usually come back with
nothing found. `--training SCENARIO` builds a small, entirely synthetic AndroidQF
collection and a matching made-up indicator list in a fresh temporary folder,
checks it with the ordinary phone check, and deletes it afterwards. The report is
the real report, so what people learn transfers, but every page of it says it is
a training example.

What keeps it from being mistaken for, or mixed with, a real check:
  - It never reads this computer, a real phone or a downloaded indicator list.
    The options that would point it at real evidence or real indicators are
    refused alongside --training (training_validate).
  - Every indicator is invented. The one domain uses the reserved .invalid
    top-level domain (RFC 2606), which can never be registered or resolved; the
    app ids live under the reserved example.org namespace; the hashes are of
    text written here. Nothing real can match them and nothing real is named.
  - The family name is "Training example (not real spyware)", and the readable
    report, the JSON report and the relay rules for assistants all carry a
    training marker. A sharing summary or evidence bundle cannot be made from a
    training example, because both exist to be sent to someone.
  - The folder is made in the local temporary directory and removed when the
    tool exits (training_cleanup), whatever happened in between.
"""

import hashlib
import json
import os
import shutil
import tempfile

from .localpaths import local_temp_dir

TRAINING_FAMILY = "Training example (not real spyware)"
TRAINING_SCENARIOS = ("spyware", "worth-a-look", "clean")
TRAINING_DOMAIN = "training-spyware-server.invalid"
TRAINING_APP = "org.example.training.spyapp"
TRAINING_LAUNCHER = "org.example.training.launcher"
TRAINING_PROPERTY = "persist.training.spy.flag"
TRAINING_PATH = "/data/local/tmp/training-spy-daemon"
_TRN_APK = hashlib.sha256(b"Zero Breach Toolkit training APK - not software").hexdigest()
_TRN_CERT = hashlib.sha256(b"Zero Breach Toolkit training certificate").hexdigest()

# Options that point a check at real evidence, real indicators, or produce
# something meant to be sent to another person. None of them belongs in a
# training run. Values are the argparse destinations and how they are spelt.
_TRN_REFUSED = (("phone", "--phone"), ("target", "--target"),
                ("collect_android", "--collect-android"), ("update", "--update"),
                ("iocs", "--iocs"), ("share_json", "--share-json"),
                ("evidence_bundle", "--evidence-bundle"), ("evidence_file", "--evidence-file"),
                ("patterns", "--patterns"), ("pattern_path", "--pattern-path"),
                ("backup_password", "--backup-password"), ("extended_windows", "--extended-windows"),
                ("latest", "--latest"), ("indicator_cache", "--indicator-cache"),
                ("preview", "--preview"))

_TRN_NOTES = {
    "spyware": (
        "This made-up phone has an app and other traces that match the made-up",
        "indicator list. Things to point out:",
        "  - Each finding has an evidence grade. A match on the device itself is",
        "    stronger than a name mentioned in a log, which is stronger than a",
        "    saved reference. Read the grade before reacting.",
        "  - The report says to keep the phone and the report, and not to delete",
        "    or 'clean' anything. Ask: who would you contact next, and how?",
        "  - The sideloaded launcher under 'worth a look' is NOT a finding.",
        "  - Look at what could not be checked: a finding does not mean every",
        "    place was examined.",
    ),
    "worth-a-look": (
        "This made-up phone matches nothing on the indicator list, but has",
        "settings and apps the report lists under 'worth a look'. Things to point out:",
        "  - None of these is a sign of spyware on its own. Each comes with its",
        "    ordinary explanation; someone who knows the phone can rule it out.",
        "  - Practise: which of these would you ask the phone's owner about, and",
        "    what question would you ask?",
        "  - Old security updates are worth fixing whatever the result.",
    ),
    "clean": (
        "This made-up phone matches nothing. Things to point out:",
        "  - 'Nothing found' means no KNOWN indicator was found in the places that",
        "    could be checked. It is not proof the phone is safe.",
        "  - Read the list of what could not be checked, and the advice for someone",
        "    who still has a concrete reason to worry: contact a helpline.",
    ),
}

# Folders made by training_prepare in this process, removed by training_cleanup.
_TRN_CREATED = []


def training_arguments(parser):
    parser.add_argument(
        "--training", nargs="?", const="spyware", choices=TRAINING_SCENARIOS, default=None,
        metavar="SCENARIO",
        help="practise on a made-up phone instead of real evidence: 'spyware' (default), "
             "'worth-a-look' or 'clean'. Uses only invented indicators, reads nothing on "
             "this computer and deletes the example afterwards.")


def training_validate(parser, args):
    """Refuse a training run combined with anything that touches real evidence."""
    if not getattr(args, "training", None):
        return
    for dest, flag in _TRN_REFUSED:
        if getattr(args, dest, None):
            parser.error("--training uses only its own made-up example; it cannot be "
                         "combined with {}".format(flag))
    if getattr(args, "scan_type", "default") not in (None, "default"):
        parser.error("--training checks a made-up phone; it cannot be combined with "
                     "--scan-type")
    if getattr(args, "ios_input", ""):
        parser.error("--training uses an Android example; it cannot be combined with "
                     "--ios-input")


def _trn_json(folder, name, value):
    with open(os.path.join(folder, name), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(value, fh, indent=1)


def _trn_text(folder, name, text):
    with open(os.path.join(folder, name), "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _trn_app(name, installer, uid, label):
    """One installed app with an invented file fingerprint and certificate."""
    return {"name": name, "installer": installer, "third_party": True, "system": False,
            "disabled": False, "uid": uid,
            "files": [{"path": "/data/app/{}/base.apk".format(name),
                       "sha256": hashlib.sha256(b"training apk " + label).hexdigest(),
                       "certificate": {"Sha256": hashlib.sha256(b"training cert " + label).hexdigest(),
                                       "Sha1": hashlib.sha1(b"training cert " + label).hexdigest()}}]}


def _trn_collection(folder, scenario):
    """An AndroidQF-shaped folder with the files the phone check reads.

    A few records are left out on purpose (file fingerprints, battery history,
    a bug report, an SMS backup), as they often are in real collections, so
    every scenario also shows how the report lists what it could not check."""
    spy = scenario == "spyware"
    packages = [_trn_app("com.android.chrome", "com.android.vending", 10101, b"browser"),
                _trn_app("com.whatsapp", "com.android.vending", 10102, b"messenger")]
    if scenario != "clean":
        # Installed from a downloaded file rather than an app store: a lead.
        packages.append(_trn_app(TRAINING_LAUNCHER, "com.android.packageinstaller", 10103,
                                 b"launcher"))
    if spy:
        packages.append({"name": TRAINING_APP, "installer": "com.android.packageinstaller",
                         "third_party": True, "system": False, "disabled": False, "uid": 10104,
                         "files": [{"path": "/data/app/training-spyapp/base.apk",
                                    "sha256": _TRN_APK,
                                    "certificate": {"Sha256": _TRN_CERT, "Sha1": "0" * 40}}]})
    _trn_json(folder, "packages.json", packages)
    _trn_json(folder, "files.json", [{"path": TRAINING_PATH if spy else "/data/local/tmp/notes.txt",
                                      "sha256": ""}])
    _trn_json(folder, "root_binaries.json", [])
    _trn_json(folder, "acquisition.json", {"started": "2026-01-15T10:00:00Z",
                                           "note": "Zero Breach Toolkit training example"})
    _trn_text(folder, "processes.txt",
              "USER PID PPID VSZ RSS WCHAN ADDR S NAME\n"
              "system 900 1 1 1 0 0 S system_server\n")
    props = ["[ro.build.version.security_patch]: [{}]".format(
        "2022-03-05" if scenario == "worth-a-look" else "2099-01-01")]
    if spy:
        props.append("[{}]: [1]".format(TRAINING_PROPERTY))
    _trn_text(folder, "getprop.txt", "\n".join(props) + "\n")
    settings = ["adb_enabled=1"]
    if scenario == "worth-a-look":
        settings += ["package_verifier_enable=0"]
    _trn_text(folder, "settings_global.txt", "\n".join(settings) + "\n")
    _trn_text(folder, "settings_secure.txt",
              "enabled_accessibility_services={}\n".format(
                  TRAINING_LAUNCHER + "/.HelperService" if scenario == "worth-a-look" else "null"))
    _trn_text(folder, "settings_system.txt", "screen_brightness=128\n")
    _trn_text(folder, "selinux.txt", "Enforcing\n")
    _trn_json(folder, "mounts.json", [])
    _trn_text(folder, "logcat.txt", "01-15 10:00:00.000  1000  1000 I ActivityManager: Start proc\n")
    _trn_text(folder, "dumpsys.txt",
              "Connection to https://{}/check-in\n".format(TRAINING_DOMAIN) if spy
              else "No unusual connections recorded in this example.\n")


def _trn_indicators(path):
    """A STIX 2.1 bundle of invented indicators, read by the ordinary loader."""
    family_id = "malware--00000000-0000-4000-8000-000000000001"
    patterns = [
        "[domain-name:value='{}']".format(TRAINING_DOMAIN),
        "[app:id='{}']".format(TRAINING_APP),
        "[file:hashes.sha256='{}']".format(_TRN_APK),
        "[app:cert.sha256='{}']".format(_TRN_CERT),
        "[android-property:name='{}']".format(TRAINING_PROPERTY),
        "[file:path='{}']".format(TRAINING_PATH),
    ]
    objects = [{"type": "malware", "spec_version": "2.1", "id": family_id,
                "name": TRAINING_FAMILY, "is_family": True}]
    for n, pattern in enumerate(patterns, 1):
        ind_id = "indicator--00000000-0000-4000-8000-{:012d}".format(n)
        objects.append({"type": "indicator", "spec_version": "2.1", "id": ind_id,
                        "pattern": pattern, "pattern_type": "stix",
                        "valid_from": "2026-01-01T00:00:00Z", "x_mvt_platforms": ["android"]})
        objects.append({"type": "relationship", "spec_version": "2.1",
                        "id": "relationship--00000000-0000-4000-8000-{:012d}".format(n),
                        "relationship_type": "indicates", "source_ref": ind_id,
                        "target_ref": family_id})
    _trn_json(os.path.dirname(path), os.path.basename(path),
              {"type": "bundle", "id": "bundle--00000000-0000-4000-8000-000000000000",
               "objects": objects})


def training_prepare(args):
    """Build the example and point the check at it. No-op unless --training."""
    scenario = getattr(args, "training", None)
    if not scenario:
        return
    root = tempfile.mkdtemp(prefix="zbt_training_", dir=local_temp_dir())
    _TRN_CREATED.append(root)
    phone = os.path.join(root, "training-phone")
    os.mkdir(phone)
    _trn_collection(phone, scenario)
    indicators = os.path.join(root, "training-indicators.stix2.json")
    _trn_indicators(indicators)
    args.phone = phone
    args.iocs = [indicators]
    args.iocs_explicit = True
    args.no_feeds = True
    args.scan_type = "default"


def training_cleanup():
    while _TRN_CREATED:
        shutil.rmtree(_TRN_CREATED.pop(), ignore_errors=True)


def training_marker(args):
    """What the JSON report records about a training run, or None."""
    scenario = getattr(args, "training", None)
    if not scenario:
        return None
    return {"scenario": scenario, "synthetic": True,
            "statement": "TRAINING EXAMPLE. This report is about a made-up phone and "
                         "made-up indicators. It says nothing about any real device."}


def training_banner(document):
    """Lines placed at the top and bottom of the readable report."""
    marker = document.get("training") or {}
    scenario = marker.get("scenario")
    if scenario not in TRAINING_SCENARIOS:
        return [], []
    rule = "#" * 72
    top = [rule,
           "  TRAINING EXAMPLE - NOT A REAL CHECK",
           "  Scenario: {}. This is a made-up phone checked against made-up".format(scenario),
           "  indicators. It says nothing about this computer or any real device.",
           rule]
    bottom = [rule, "  TRAINING NOTES - scenario: " + scenario, ""]
    bottom += ["  " + line for line in _TRN_NOTES[scenario]]
    bottom += ["", "  Other scenarios: --training spyware | worth-a-look | clean",
               "  This example has been deleted. Nothing on this computer was read.", rule]
    return top, bottom
