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
    parser.add_argument("--make-iphone-backup", metavar="DIR",
                        help="Linux: make an encrypted iPhone backup into DIR (asks first; downloads a verified helper), "
                             "then check it. On Windows and Mac use Apple's app, or the window's backup button")
    parser.add_argument("--age-recipient-file", metavar="PATH", help="public age1 recipients for --collect-android; encrypted acquisitions are saved for separate analysis")
    parser.add_argument("--phone-guide", choices=("android", "ios"), help="print local-backup preparation instructions and exit")
    parser.add_argument("--backup-password", action="store_true", help="prompt privately for an encrypted phone backup password; never pass the password on the command line")
    parser.add_argument("--ios-input", choices=("backup", "filesystem", "sysdiagnose"), default="",
                        help="explicit iPhone input format for --phone; filesystem is an extracted tree, sysdiagnose is a directory or TAR/TAR.GZ")
    parser.add_argument("--dns-log", action="append", default=[], metavar="FILE",
                        help="check a DNS log from a router, Pi-hole, AdGuard Home or DNS server instead of this computer "
                             "(repeatable): every device on the network, offline")
    parser.add_argument("--home-network", action="store_true",
                        help="separate check of the devices on your own local network: who is there and which risky "
                             "doors are open (asks first; contacts only local devices; never logs in)")
    parser.add_argument("--wifi-nearby", action="store_true",
                        help="separate check: the Wi-Fi networks this computer hears, and what a hidden one probably "
                             "is (who made it, whether it is part of your own router, how close); reads only what "
                             "is already heard, joins nothing")
    parser.add_argument("--trackers", nargs="?", const=3, type=int, metavar="MINUTES",
                        help="separate check: listen for Bluetooth location trackers (AirTag, SmartTag, Tile, Find Hub) "
                             "near you for MINUTES (default 3); receives only; needs the optional bleak library")
    parser.add_argument("--check-link", action="append", default=[], metavar="TEXT",
                        help="separate check: is this link (or text containing links) dangerous? Offline: nothing is "
                             "opened or looked up. Repeatable; defanged links (hxxp, [.]) work too")
    parser.add_argument("--check-message", metavar="TEXT|FILE",
                        help="separate check: every link and lure in a message (SMS, WhatsApp, email body): the "
                             "message itself in quotes, a saved file, or - to paste it")
    # default None, not []: "not given at all" must be told apart from "given with no file", or an ordinary scan
    # would start this check by itself.
    parser.add_argument("--was-extracted", metavar="FOLDER",
                        help="separate check: was a phone plugged into a forensics tool? Reads an AndroidQF "
                             "collection or an iPhone backup folder and says what each sign does and does not "
                             "prove. An extraction can leave no trace, so finding nothing is not proof")
    parser.add_argument("--check-email", metavar="FILE",
                        help="separate check: a saved email (.eml, or the 'Show original' text). Says who really "
                             "sent it, what the receiving server decided about it, and checks its links and "
                             "attachments. Nothing is opened")
    parser.add_argument("--check-qr", metavar="IMAGE",
                        help="separate check: a picture of a QR code (PNG, GIF, BMP, PPM). Reads what the code "
                             "says without following it, then checks it like a pasted link")
    parser.add_argument("--fix-it", nargs="?", const="list", metavar="WHAT",
                        help="separate step: close the doors the scan found open. On its own it lists what can "
                             "be done and what is better done by you, changing nothing; with a name (for "
                             "example windows:firewall) it does that one, after asking, saving a way back first")
    parser.add_argument("--undo-fix", metavar="RECORD",
                        help="put back a setting --fix-it changed, by the record name it printed")
    parser.add_argument("--hunt-windows", action="append", default=None, nargs="?", const="",
                        metavar="FILE",
                        help="separate check: look through Windows' own records for commands whose text was "
                             "hidden, downloads, protection switched off, services installed from personal "
                             "folders, cleared logs and remote sessions. With no FILE it reads this computer; "
                             "give one or more .evtx files to read logs from elsewhere (works on any system)")
    parser.add_argument("--with-security", action="store_true",
                        help="with --hunt-windows: also read the Security log (needs administrator rights)")
    parser.add_argument("--hunt-all", action="store_true",
                        help="with --hunt-windows: also print the records kept back as context")
    parser.add_argument("--check-file", metavar="PATH",
                        help="separate check: a first look at one suspicious file without running it - fingerprints, "
                             "what it really is, signature, spyware addresses inside, packing, Android app "
                             "permissions, document macros. Offline; the file is never moved or changed")
    parser.add_argument("--seal-copy", metavar="PATH",
                        help="with --check-file: also save a sealed copy (a ZIP with the password 'infected') to PATH "
                             "(a folder or a new .zip), ready to send to an expert. Never replaces a file")
    parser.add_argument("--accounts", action="store_true",
                        help="separate check: a guided checklist of your online accounts (linked devices, forwarding "
                             "rules, location sharing, recovery details). You look and answer; nothing is signed in "
                             "to, opened or sent")
    parser.add_argument("--threat-warning", action="store_true",
                        help="print what to do after Apple, Google, WhatsApp or another service warns that you may "
                             "be targeted, and exit")
    parser.add_argument("--hash-lookup", action="append", default=[], metavar="PATH",
                        help="separate check: fingerprint files (SHA-256, SHA-1, MD5; imphash and signer for Windows "
                             "programs) and compare them with the indicator lists. Offline unless --online is given")
    parser.add_argument("--online", metavar="SERVICES",
                        help="with --hash-lookup: also send the FINGERPRINTS (never files or names) of unsigned "
                             "programs, scripts, documents and archives to these services, comma-separated: circl, "
                             "malwarebazaar, threatfox, virustotal, hybrid, or all")
    parser.add_argument("--lookup-all", action="store_true",
                        help="with --hash-lookup --online: look up every file, signed or not, beyond the free limits")
    parser.add_argument("--set-lookup-key", choices=("abusech", "virustotal", "hybrid"),
                        help="save your own key for an online look-up service (asked for privately, not on the "
                             "command line)")
    parser.add_argument("--package-for-helper", metavar="FOLDER",
                        help="separate step: put the files given with --add into one package for a helper, sealed "
                             "with their age key (--helper-key age1...) and signed with your own sender key; written "
                             "to FOLDER. Nothing is uploaded")
    parser.add_argument("--add", action="append", default=[], metavar="PATH",
                        help="with --package-for-helper: a file or folder to include (repeat for more)")
    parser.add_argument("--helper-key", metavar="AGE1KEY",
                        help="with --package-for-helper: the helper's age public key (starts with age1)")
    parser.add_argument("--no-encryption", action="store_true",
                        help="with --package-for-helper: do not encrypt (only if your helper asked for that)")
    parser.add_argument("--verify-package", metavar="PATH",
                        help="separate step for a helper: check a decrypted package's signature and fingerprints")
    parser.add_argument("--startup", action="store_true",
                        help="separate check: list every program set to start automatically (Run keys, Startup "
                             "folders, scheduled tasks, services; launch agents and app permissions on a Mac) with "
                             "its signature, and mark what is worth a look. Read only")
    parser.add_argument("--startup-all", action="store_true",
                        help="with --startup: also list signed Windows / system components")
    parser.add_argument("--check-traffic", metavar="FILE",
                        help="separate check: a network recording (.pcap / .pcapng, e.g. from the PCAPdroid app on "
                             "Android): which servers were contacted, and which app contacted them. Offline")
    parser.add_argument("--combine", nargs="+", default=None, metavar="REPORT",
                        help="household report: one summary of several saved JSON reports (computers, phones, the "
                             "phone-check page, DNS logs, the home network); name one with LABEL=FILE. Reads only")
    parser.add_argument("--html", metavar="PATH",
                        help="with --combine: also save the household report as a page to print or keep")
    parser.add_argument("--no-camera-check", action="store_true",
                        help="with --home-network: do not ask cameras whether their video needs a password")
    parser.add_argument("--no-router-lookups", action="store_true",
                        help="with --home-network: skip asking the router to look up test names (the only part of "
                             "that check whose questions leave your network)")
    parser.add_argument("--yes-my-network", action="store_true",
                        help="with --home-network: confirm without the question (for scripts on your own network)")
    parser.add_argument("--extended-windows", action="store_true", help="opt-in additional existing Windows event records; does not elevate or enable logging")


def scope_message_is_text(value) -> bool:
    """--check-message "Your parcel is held: http://..." is the message itself, not a file name."""
    return bool(value) and value != "-" and not os.path.isfile(value) and (
        " " in value.strip() or "\n" in value or "://" in value)


def scope_validate(parser, args):
    # An option given an empty value ("--check-file ''", a shell variable that was not set) must stop here: an
    # empty value reads as "not given", and the program would start an ordinary full scan instead.
    bare = {a.dest for a in parser._actions if a.const == ""}   # "--hunt-windows" alone means "this computer"
    for dest, value in sorted(vars(args).items()):
        if parser.get_default(dest) == value or dest in bare:   # not typed (some options default to "")
            continue
        if value == "" or (isinstance(value, list) and "" in value and dest != "check_link"):
            parser.error("--{} was given an empty value - nothing was checked".format(dest.replace("_", "-")))
    # A mistyped phone folder must stop here: scanning nothing and printing an
    # ordinary "no known indicator" report reads like an all-clear.
    # Only a local path is tested: asking Windows whether a network path exists
    # would contact that server. Network paths are refused later, as before.
    if (args.phone and not path_problem(os.path.abspath(args.phone))
            and not os.path.exists(args.phone)):
        parser.error("phone evidence not found: " + args.phone + " - nothing was checked")
    for path in args.dns_log:
        if not path_problem(os.path.abspath(path)) and not os.path.isfile(path):
            parser.error("DNS log not found: " + path + " - nothing was checked")
    if args.dns_log and (args.phone or args.target or args.collect_android or args.update):
        parser.error("--dns-log is checked on its own: not with --phone, --target, --collect-android or --update")
    if args.home_network and (args.phone or args.target or args.dns_log or args.collect_android or args.update):
        parser.error("--home-network is a separate check: not with --phone, --target, --dns-log, --collect-android or --update")
    if args.trackers is not None and (args.home_network or args.phone or args.target or args.dns_log or args.update):
        parser.error("--trackers is a separate check")
    if args.make_iphone_backup and (args.phone or args.target or args.dns_log or args.collect_android or args.update
                                    or args.home_network or args.combine or args.trackers is not None):
        parser.error("--make-iphone-backup makes a backup and checks it: not with another input")
    if args.combine and (args.phone or args.target or args.dns_log or args.home_network or args.update
                         or args.collect_android or args.trackers is not None):
        parser.error("--combine reads saved reports on its own: not with a check")
    if (args.check_link or args.check_message) and (args.phone or args.target or args.dns_log or args.home_network
                                                     or args.update or args.collect_android or args.combine
                                                     or args.trackers is not None or args.make_iphone_backup):
        parser.error("--check-link / --check-message check what you received on their own: not with another check")
    if args.check_message and args.check_message != "-" and not scope_message_is_text(args.check_message) \
            and not path_problem(os.path.abspath(args.check_message)) and not os.path.isfile(args.check_message):
        parser.error("message file not found: " + args.check_message + " - nothing was checked")
    if args.check_traffic and (args.phone or args.target or args.dns_log or args.home_network or args.update
                               or args.collect_android or args.combine or args.trackers is not None
                               or args.make_iphone_backup or args.check_link or args.check_message):
        parser.error("--check-traffic reads a recording on its own: not with another check")
    if args.check_traffic and not path_problem(os.path.abspath(args.check_traffic)) \
            and not os.path.isfile(args.check_traffic):
        parser.error("recording not found: " + args.check_traffic + " - nothing was checked")
    if args.seal_copy and not args.check_file:
        parser.error("--seal-copy goes with --check-file")
    separate = [flag for flag, on in (("--check-file", args.check_file), ("--accounts", args.accounts),
                                      ("--threat-warning", args.threat_warning),
                                      ("--wifi-nearby", getattr(args, "wifi_nearby", False))) if on]
    others = (args.phone or args.target or args.dns_log or args.home_network or args.update or args.collect_android
              or args.combine or args.trackers is not None or args.make_iphone_backup or args.check_link
              or args.check_message or args.check_traffic or args.check_email or args.check_qr or args.hash_lookup
              or args.was_extracted or args.startup or args.hunt_windows is not None or args.fix_it
              or args.describe or args.preview or args.phone_guide or getattr(args, "verify_package", None)
              or getattr(args, "package_for_helper", None) or getattr(args, "undo_fix", None)
              or getattr(args, "training", None))
    if len(separate) > 1 or (separate and others):
        parser.error("{} is a separate check: run it on its own".format(separate[0]))
    if args.startup_all:
        args.startup = True
    if args.hunt_windows is not None:
        args.hunt_windows = [p for p in args.hunt_windows if p]
    for flag, value in (("--check-email", args.check_email), ("--check-qr", args.check_qr)):
        if value and not path_problem(os.path.abspath(value)) and not os.path.isfile(value):
            parser.error("not found: " + value + " - nothing was checked")
    if args.was_extracted and not path_problem(os.path.abspath(args.was_extracted)) \
            and not os.path.isdir(args.was_extracted):
        parser.error("not a folder: " + args.was_extracted + " - give the folder of a phone collection or an "
                     "iPhone backup")
    if args.was_extracted and (
            args.phone or args.target or args.dns_log or args.home_network or args.update or args.collect_android
            or args.combine or args.trackers is not None or args.make_iphone_backup or args.check_link
            or args.check_message or args.check_traffic or args.startup or args.package_for_helper
            or args.verify_package or args.hash_lookup or args.set_lookup_key or args.hunt_windows is not None
            or args.fix_it is not None or args.undo_fix or args.check_email or args.check_qr):
        parser.error("the extraction check is a check on its own: not with another check")
    if (args.check_email or args.check_qr) and (
            args.phone or args.target or args.dns_log or args.home_network or args.update or args.collect_android
            or args.combine or args.trackers is not None or args.make_iphone_backup or args.check_link
            or args.check_message or args.check_traffic or args.startup or args.package_for_helper
            or args.verify_package or args.hash_lookup or args.set_lookup_key or args.hunt_windows is not None
            or args.fix_it is not None or args.undo_fix or (args.check_email and args.check_qr)):
        parser.error("checking a saved email or a QR code is a check on its own: not with another check")
    if args.fix_it is not None and args.undo_fix:
        parser.error("choose either --fix-it or --undo-fix")
    if (args.fix_it is not None or args.undo_fix) and (
            args.phone or args.target or args.dns_log or args.home_network or args.update or args.collect_android
            or args.combine or args.trackers is not None or args.make_iphone_backup or args.check_link
            or args.check_message or args.check_traffic or args.startup or args.package_for_helper
            or args.verify_package or args.hash_lookup or args.set_lookup_key or args.hunt_windows is not None):
        parser.error("closing a door is a step on its own: not with another check")
    if (args.with_security or args.hunt_all) and args.hunt_windows is None:
        parser.error("--with-security and --hunt-all go with --hunt-windows")
    for chosen in (args.hunt_windows or []):
        if not path_problem(os.path.abspath(chosen)) and not os.path.isfile(chosen):
            parser.error("log file not found: " + chosen + " - nothing was checked")
    if args.hunt_windows is not None and (
            args.phone or args.target or args.dns_log or args.home_network or args.update or args.collect_android
            or args.combine or args.trackers is not None or args.make_iphone_backup or args.check_link
            or args.check_message or args.check_traffic or args.startup or args.package_for_helper
            or args.verify_package or args.hash_lookup or args.set_lookup_key):
        parser.error("looking through Windows' records is a check on its own: not with another check")
    if (args.online or args.lookup_all) and not args.hash_lookup:
        parser.error("--online and --lookup-all go with --hash-lookup PATH")
    for chosen in args.hash_lookup:
        if not path_problem(os.path.abspath(chosen)) and not os.path.exists(chosen):
            parser.error("not found: " + chosen + " - nothing was checked")
    if (args.hash_lookup or args.set_lookup_key) and (
            args.phone or args.target or args.dns_log or args.home_network or args.update or args.collect_android
            or args.combine or args.trackers is not None or args.make_iphone_backup or args.check_link
            or args.check_message or args.check_traffic or args.startup or args.package_for_helper
            or args.verify_package or (args.hash_lookup and args.set_lookup_key)):
        parser.error("the hash look-up is a check on its own: not with another check")
    if (args.add or args.helper_key or args.no_encryption) and not args.package_for_helper:
        parser.error("--add, --helper-key and --no-encryption go with --package-for-helper")
    if args.package_for_helper and not args.add:
        parser.error("--package-for-helper needs at least one --add PATH (a file or folder to include)")
    if args.helper_key and args.no_encryption:
        parser.error("choose either --helper-key or --no-encryption")
    for chosen in args.add:
        if not path_problem(os.path.abspath(chosen)) and not os.path.exists(chosen):
            parser.error("not found: " + chosen + " - nothing was packaged")
    if (args.package_for_helper or args.verify_package) and (
            args.phone or args.target or args.dns_log or args.home_network or args.update or args.collect_android
            or args.combine or args.trackers is not None or args.make_iphone_backup or args.check_link
            or args.check_message or args.check_traffic or args.startup
            or (args.package_for_helper and args.verify_package)):
        parser.error("making or checking a helper package is a step on its own: not with another check")
    if args.startup and (args.phone or args.target or args.dns_log or args.home_network or args.update
                         or args.collect_android or args.combine or args.trackers is not None
                         or args.make_iphone_backup or args.check_link or args.check_message or args.check_traffic):
        parser.error("--startup lists this computer's start-up programs on its own: not with another check")
    if args.html and not args.combine:
        parser.error("--html goes with --combine")
    if args.no_camera_check and not args.home_network:
        parser.error("--no-camera-check goes with --home-network")
    if args.no_router_lookups and not args.home_network:
        parser.error("--no-router-lookups goes with --home-network")
    if args.yes_my_network and not args.home_network:
        parser.error("--yes-my-network goes with --home-network")
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
              "phone": bool(args.phone), "dns_logs": len(getattr(args, "dns_log", []) or []), "scanned": False,
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


# Kept apart from the guide above (which is translated as one block) so that adding it changed none of them.
SCOPE_BUGREPORT_GUIDE = """No USB debugging? Use a bug report the phone makes itself

 1. Turn on Developer options as in step 1 above (USB debugging is NOT needed).
 2. Settings > System > Developer options > "Take bug report" (or "Bug report").
    Choose "Full report" if it asks. After a few minutes a notification says it
    is ready.
 3. Tap the notification and choose Share > save it to the phone's Files (for
    example Downloads) - Android keeps bug reports in a place a cable cannot reach.
    Then copy it to this computer the way you copy photos: a USB cable with the
    phone set to "File transfer" (that is not USB debugging), or a memory card.
    If your accounts may be watched, do not email it to yourself or put it in a
    cloud folder - it holds private details about your phone.
 4. Check the .zip itself - do not unzip it:
      python -X utf8 scan/zero-breach-toolkit.py --phone "PATH TO THE BUG REPORT .zip"
    Or in the window: A phone > What is it? > Android bug report, then Choose...

A bug report holds the phone's system state, settings, logs and recently removed
apps, but not the apps' files, the file list or text messages - those parts are
listed as not checked. It also holds private information: keep it on this computer.
"""

def scope_bugreport_window_guide():
    """The bug report steps for the double-click program: the window's own steps, every button named with the
    label the person sees in their language (as scope_window_guide does)."""
    labels = {"phone": T("A phone"), "kind": T("What is it?"), "choose": T("Choose..."),
              "start": T("Start check"),
              "bugreport": T("Android bug report (made on the phone, no USB debugging needed)")}
    steps = [
        T("Turn on Developer options as in step 1 above (USB debugging is NOT needed)."),
        T("Settings > System > Developer options > \"Take bug report\" (or \"Bug report\"). Choose \"Full report\" "
          "if it asks. After a few minutes a notification says it is ready."),
        T("Tap the notification and choose Share > save it to the phone's Files (for example Downloads) - Android "
          "keeps bug reports in a place a cable cannot reach. Then copy it to this computer the way you copy "
          "photos: a USB cable with the phone set to \"File transfer\" (that is not USB debugging), or a memory "
          "card. If your accounts may be watched, do not email it to yourself or put it in a cloud folder - it "
          "holds private details about your phone."),
        T("In this window, choose \"{phone}\", set \"{kind}\" to \"{bugreport}\", click \"{choose}\" and pick the "
          ".zip itself (do not unzip it), then click \"{start}\".", **labels),
    ]
    return (T("No USB debugging? Use a bug report the phone makes itself") + "\n\n" +
            "\n\n".join("{}. {}".format(i, s) for i, s in enumerate(steps, 1)) + "\n\n" +
            T("A bug report holds the phone's system state, settings, logs and recently removed apps, but not the "
              "apps' files, the file list or text messages - those parts are listed as not checked. It also holds "
              "private information: keep it on this computer."))


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