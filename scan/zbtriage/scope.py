"""Shared scope controls for the package and standalone entry points."""
import os
import sys

from .localpaths import path_problem
from .contract import sanitize_untrusted
from .i18n import T


def scope_arguments(parser):
    parser.add_argument("--scan-type", choices=("default", "full", "targeted", "browser"),
                        default="default", help="full includes app caches and all file extensions in the usual roots; targeted reads only selected targets; browser reads only this account's browser profiles")
    parser.add_argument("--target", action="append", default=[], metavar="PATH",
                        help="local file, directory, drive or browser profile (repeatable; requires targeted)")
    parser.add_argument("--preview", action="store_true", help="show scope and phone artifact availability as JSON, without scanning")
    parser.add_argument("--collect-android", metavar="DIR", help="separate guided acquisition: download and verify a pinned official AndroidQF release, collect with owner consent, then check the plaintext collection")
    parser.add_argument("--age-recipient-file", metavar="PATH", help="public age1 recipients for --collect-android; encrypted acquisitions are saved for separate analysis")
    parser.add_argument("--phone-guide", choices=("android", "ios"), help="print local-backup preparation instructions and exit")
    parser.add_argument("--backup-password", action="store_true", help="prompt privately for an encrypted phone backup password; never pass the password on the command line")
    parser.add_argument("--ios-input", choices=("backup", "filesystem", "sysdiagnose"), default="",
                        help="explicit iPhone input format for --phone; filesystem is an extracted tree, sysdiagnose is a directory or TAR/TAR.GZ")
    parser.add_argument("--extended-windows", action="store_true", help="opt-in additional existing Windows event records; does not elevate or enable logging")


def scope_validate(parser, args):
    # A mistyped phone folder must stop here: scanning nothing and printing an
    # ordinary "no known indicator" report reads like an all-clear.
    # Only a local path is tested: asking Windows whether a network path exists
    # would contact that server. Network paths are refused later, as before.
    if (args.phone and not path_problem(os.path.abspath(args.phone))
            and not os.path.exists(args.phone)):
        parser.error("phone evidence not found: " + args.phone + " - nothing was checked")
    if args.ios_input and not args.phone:
        parser.error("--ios-input requires --phone")
    if args.backup_password and args.ios_input in ("filesystem", "sysdiagnose"):
        parser.error("--backup-password is for backup input only")
    if bool(args.target) != (args.scan_type == "targeted"):
        parser.error("--scan-type targeted requires --target; --target requires --scan-type targeted")
    if args.phone and args.target:
        parser.error("use --phone for a collection, or --target for computer files/profiles")
    if args.quick and args.scan_type == "targeted":
        parser.error("--quick cannot be combined with targeted")
    if args.age_recipient_file and not args.collect_android:
        parser.error("--age-recipient-file requires --collect-android")
    if args.collect_android and (args.phone or args.target or args.preview or args.phone_guide or args.describe):
        parser.error("--collect-android is a separate acquisition command")
    if args.backup_password and not (args.phone or args.collect_android):
        parser.error("--backup-password requires --phone")
    if args.update and (args.target or args.phone or args.preview or args.phone_guide or args.collect_android):
        parser.error("--update is a separate operation")
    for path in args.target:
        problem = path_problem(os.path.abspath(path))
        if problem:
            parser.error("target refused: " + problem)
        if not os.path.exists(path):
            parser.error("target does not exist: " + path)
    if args.target and args.patterns and not args.pattern_path:
        args.pattern_path = list(args.target)


def scope_record(args):
    result = {"scan_type": args.scan_type, "targets": [sanitize_untrusted(os.path.abspath(p)) for p in args.target],
              "phone": bool(args.phone), "scanned": False,
              "ios_input": getattr(args, "ios_input", ""),
              "host_platform": sys.platform,
              "limits": ["Read-only local evidence; no infection-free guarantee.",
                         "File hashing remains bounded to 512 MiB per file.",
                         "Full means broader checks in the usual roots, not every drive or every user."]}
    return result


def scope_preview(args):
    result = scope_record(args)
    if args.phone:
        folder = os.path.abspath(args.phone)
        problem = path_problem(folder)
        if problem:
            raise ValueError("phone folder refused: " + problem)
        if getattr(args, "ios_input", "") in ("filesystem", "sysdiagnose"):
            result["collection_type"] = "ios-" + args.ios_input
            result["checks"] = ["supported local iPhone artifacts", "bounded evidence inventory"]
            result["limits"].append("Preview does not open the archive or validate schemas. No device acquisition is performed.")
            return result
        artifacts = ("packages.json", "processes.txt", "processes.json", "backup.ab", "dumpsys.txt",
                     "getprop.txt", "files.json", "Manifest.plist", "Manifest.db", "Info.plist")
        result["artifacts"] = {}
        for name in artifacts:
            path = os.path.join(folder, name)
            problem = path_problem(path)
            result["artifacts"][name] = "refused" if problem else "present" if os.path.isfile(path) else "missing"
        is_ios = getattr(args, "ios_input", "") == "backup" or result["artifacts"]["Manifest.plist"] == "present"
        result["collection_type"] = "ios-backup" if is_ios else "androidqf" if result["artifacts"]["packages.json"] == "present" else "unrecognized"
        result["checks"] = (["manifest", "supported message text and metadata", "Safari profiles", "optional Chrome and historical Firefox visits", "data-usage process names", "application identifiers", "supported cache, configuration, analytics and diagnostic artifacts"]
                            if is_ios else ["packages", "processes", "settings and properties", "file inventory", "logs and crashes", "SMS backup", "optional decrypted intrusion logs"])
        intrusion = os.path.join(folder, "intrusion_logs")
        problem = path_problem(intrusion)
        result["artifacts"]["intrusion_logs"] = "refused" if problem else "present" if os.path.isdir(intrusion) else "missing"
        result["limits"].append("Presence is not validation: corrupt, unsupported or encrypted artifacts can still be unreadable.")
    elif args.target:
        result["checks"] = ["selected file fingerprints", "supported browser artifacts inside selected profiles", "supported copied Prefetch and Amcache artifacts"]
        result["limits"].append("Live host, live registry and system event checks are outside targeted scope.")
    elif args.scan_type == "browser":
        result["checks"] = ["browser"]
        result["limits"].append("Only browser profiles and desktop apps with a built-in browser are read; "
                                "files, startup entries, DNS, registry and system events are not.")
    else:
        from .context import ScanContext
        from .readers import reader_select
        result["checks"] = [spec.name for spec in reader_select(ScanContext(None, patterns=args.patterns))]
    if not args.phone and sys.platform != "win32":
        result["limits"].append("Linux/macOS host checks cover selected startup configuration only, not Windows DNS, registry or event sources.")
    return result


def scope_guide(platform):
    if platform == "android":
        return """Checking an Android phone - step by step

 1. On the phone: Settings > About phone, tap "Build number" seven times to turn on
    Developer options. Then Settings > System > Developer options > turn on
    "USB debugging".
 2. Connect the phone to this computer with a USB cable. On the phone, tap "Allow"
    when it asks to allow USB debugging from this computer.
 3. Download AndroidQF for your computer from
    https://github.com/mvt-project/androidqf/releases and run it.
    (Or let this tool do it: --collect-android "OUTPUT FOLDER")
 4. AndroidQF asks a few questions. Answer:
      Backup? -> Only SMS
      Download copies of all apps or ...? -> Only non-system packages
      Remove copies of apps signed with a trusted certificate? -> No
      Intrusion Logs? -> No (unless you turned on Intrusion Logging in Advanced Protection)
      Hash files on the device? -> No (Yes also checks file fingerprints, but it is slow)
      Browser history / Magisk modules? -> No
    The phone will ask you to confirm the backup: tap "Back up my data"
    (leave the password empty).
 5. When AndroidQF finishes, it leaves a .zip file next to itself. Unzip it.
 6. Check the unzipped folder. Run this from inside the Zero-Breach-Toolkit
    folder, and keep the quotes around the folder path:
      python -X utf8 scan/zero-breach-toolkit.py --phone "PATH TO THE UNZIPPED FOLDER"
    Or open the menu (run the tool with no options), choose the phone check, and
    drag the unzipped folder into the window.
 7. Afterwards, turn USB debugging off again on the phone.

The collection holds private information about the phone: keep it on this computer.
Things the collection did not include are listed in the report as not checked.
"""
    return """Checking an iPhone - step by step

 1. Make a local backup on a computer:
      Mac: connect the iPhone, open Finder, select the iPhone, choose
           "Back up all of the data on your iPhone to this Mac".
      Windows: install Apple Devices (or iTunes), connect the iPhone, choose
           "Back up all of the data on your iPhone to this computer".
    Tick "Encrypt local backup" and choose a password you will remember:
    encrypted backups include more of the records this tool checks.
 2. Find the backup folder (one folder per device, with Manifest.plist inside):
      Mac:     ~/Library/Application Support/MobileSync/Backup/
      Windows: %USERPROFILE%\\Apple\\MobileSync\\Backup\\
               (older iTunes: %APPDATA%\\Apple Computer\\MobileSync\\Backup\\)
 3. Run this from inside the Zero-Breach-Toolkit folder, keeping the quotes:
      python -X utf8 scan/zero-breach-toolkit.py --phone "PATH TO THE BACKUP FOLDER" --backup-password
    Leave out --backup-password if the backup is not encrypted. The password is
    asked for privately and never saved.
    Or open the menu (run the tool with no options), choose the phone check, and
    drag the backup folder into the window.

Already have a file-system extraction or a sysdiagnose? Use
  --phone "FOLDER" --ios-input filesystem
  --phone "FOLDER OR .tar.gz" --ios-input sysdiagnose
The backup is never changed; anything decrypted is a temporary copy removed after the
check. Apple's backup help: https://support.apple.com/108353
"""


def scope_window_guide(platform):
    """The phone guides as the window of the packaged program shows them: the
    steps are the window's own (the check type, the folder box, the buttons),
    never a command to type. Every button is named with the label the person
    actually sees in their language."""
    labels = {"phone": T("A phone"), "find": T("Find iPhone backups"), "choose": T("Choose..."),
              "password": T("Backup password"), "start": T("Start check"), "kind": T("What is it?"),
              "collect": T("Collect from an Android phone...")}
    if platform == "android":
        steps = [
            T("On the phone: Settings > About phone, tap \"Build number\" seven times to turn on "
              "Developer options. Then Settings > System > Developer options > turn on "
              "\"USB debugging\"."),
            T("Connect the phone to this computer with a USB cable. On the phone, tap \"Allow\" "
              "when it asks to allow USB debugging from this computer."),
            T("In this window, on the Check tab, choose \"{phone}\" and click \"{collect}\". Choose an "
              "empty folder. A guided collection opens, downloads the official AndroidQF program, "
              "checks it and runs it. On a Mac or Linux it shows a command to paste into Terminal "
              "instead. (You can also download AndroidQF yourself from "
              "https://github.com/mvt-project/androidqf/releases and run it.)", **labels),
            T("AndroidQF asks a few questions. Answer:") + "\n" + "\n".join(
                "• " + line for line in (
                    T("Backup? Choose \"Only SMS\"."),
                    T("Download copies of all apps or ...? Choose \"Only non-system packages\"."),
                    T("Remove copies of apps signed with a trusted certificate? Choose \"No\"."),
                    T("Intrusion Logs? Choose \"No\" (unless you turned on Intrusion Logging in "
                      "Advanced Protection)."),
                    T("Hash files on the device? Choose \"No\" (\"Yes\" also checks file fingerprints, "
                      "but it is slow)."),
                    T("Browser history / Magisk modules? Choose \"No\"."))) + "\n" +
            T("The phone will ask you to confirm the backup: tap \"Back up my data\" "
              "(leave the password empty)."),
            T("When AndroidQF finishes, it leaves a .zip file next to itself. Unzip it."),
            T("Back in this window, choose \"{phone}\", set \"{kind}\" to the Android collection, click "
              "\"{choose}\" and pick the unzipped folder, then click \"{start}\".", **labels),
            T("Afterwards, turn USB debugging off again on the phone."),
        ]
        closing = T("The collection holds private information about the phone: keep it on this "
                    "computer. Things the collection did not include are listed in the report as "
                    "not checked.")
    else:
        steps = [
            T("Make a local backup on a computer. On a Mac: connect the iPhone, open Finder, select "
              "the iPhone and choose \"Back up all of the data on your iPhone to this Mac\". On "
              "Windows: install Apple Devices (or iTunes), connect the iPhone and choose \"Back up "
              "all of the data on your iPhone to this computer\"."),
            T("Tick \"Encrypt local backup\" and choose a password you will remember: encrypted "
              "backups include more of the records this tool checks."),
            T("In this window, on the Check tab, choose \"{phone}\" and click \"{find}\". It looks in "
              "the usual places and fills in the newest backup. If it finds none, click \"{choose}\" "
              "and pick the backup folder yourself: one folder per device, with a file called "
              "Manifest.plist inside.", **labels),
            T("If you encrypted the backup, type its password in the \"{password}\" box. It is used "
              "for this check only and is never saved.", **labels),
            T("Click \"{start}\".", **labels),
        ]
        closing = "\n".join([
            T("Where the backups are kept:"),
            "Mac: ~/Library/Application Support/MobileSync/Backup/",
            "Windows: %USERPROFILE%\\Apple\\MobileSync\\Backup\\",
            "iTunes (older): %APPDATA%\\Apple Computer\\MobileSync\\Backup\\",
            "",
            T("Already have a file-system extraction or a sysdiagnose? Choose it in the \"{kind}\" box "
              "instead.", **labels),
            T("The backup is never changed; anything decrypted is a temporary copy removed after the "
              "check."),
            T("Apple's backup help: {url}", url="https://support.apple.com/108353")])
    return "\n\n".join(["{}. {}".format(n, step) for n, step in enumerate(steps, 1)] + [closing])