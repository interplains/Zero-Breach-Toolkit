"""Trusted built-in reader registry shared by both entry points and the builder.

A reader implements NAME and run(ScanContext) -> ModuleResult. Registration is
source-controlled: scan inputs cannot load Python plugins or change this list.
Each descriptor owns selection, bundle naming, helpers and public coverage.
"""
from __future__ import annotations

import copy
import importlib
import os
import sys
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class ReaderSpec:
    name: str
    module: str
    suffix: str
    platforms: tuple
    modes: tuple
    catalogue: dict
    helpers: tuple = ()
    optional: str = ""


# Descriptors are populated below; their order is the execution/build order.
READER_SPECS = (
    ReaderSpec('browser', 'browser', 'browser', ('all',), ('desktop', 'targeted'), {
        "platforms": ["Windows", "macOS", "Linux"],
        "reads": "Chromium-family and Firefox profiles: history, cookies (host names and "
                 "times only), favicons, cache and stored data, HSTS and connection "
                 "records, including separate standard Linux/macOS Chromium cache directories (Flatpak "
                 "and snap caches included). Also desktop apps with a built-in Chromium browser "
                 "(Slack, Teams, Discord, Signal, WhatsApp, Outlook, VS Code...), found "
                 "by what their folder contains - under AppData on Windows, Application Support "
                 "on macOS, and the user and Flatpak configuration folders on Linux - labelled app:<name>.",
        "check_kinds": {
            "<browser profile>:bookmarks": "saved Chromium bookmark URLs; references, never proof of a visit",
            "<browser profile>:safari-history": "supported Safari history: known local origin and successful loads establish contact; failed local loads are attempts; synced/unknown origin stays reference",
            "<browser profile>:download-chains": "Chromium download URL chains; completion and execution unverified",
            "<browser profile>:history": "visited-site history",
            "<browser profile>:cookies": "cookie host names and times",
            "<browser profile>:favicons": "site icon records",
            "<browser profile>:blobs": "HTTP cache, Local/Session Storage, service worker caches",
            "<browser profile>:hsts": "HSTS records (proof of a past secure connection)",
            "<browser profile>:connection-records": "saved connection records",
            "<browser profile>:<kind> [<profile name>]": ("one profile of this browser "
                                                          "that could not be read - a gap "
                                                          "for that account only"),
            "desktop-app web caches": "desktop apps' raw web caches; skipped in default, included by --scan-type full",
            "app-discovery": "folders that could not be read while looking for desktop apps",
            "firefox:profiles": "finding Firefox profiles",
            "firefox:profiles:<root>": "one folder searched for Firefox profiles",
            "firefox:profile:<name>": "one Firefox profile",
            "firefox:cache-dir": "Firefox cache folder",
            "browser": "the module as a whole (error)",
        },
        "blind_spots": ["private/incognito browsing leaves no history",
                        "cleared history and cache cannot be checked",
                        "browsers not installed in their standard locations",
                        "desktop apps that keep their browser data encrypted or outside "
                        "the standard app data folders (snap-packaged apps on Linux "
                        "included), and apps built on something other than Chromium "
                        "(e.g. Telegram Desktop)"],
    }),
    ReaderSpec('hash', 'hashscan', 'hash', ('all',), ('desktop', 'targeted'), {
        "platforms": ["Windows", "macOS", "Linux"],
        "reads": "SHA-256 of candidate files in user-writable locations, compared with "
                 "published sample hashes.",
        "check_kinds": {
            "root:<folder>": "one folder that was fingerprinted",
            "hash-compare": "comparison against the published sample hashes",
            "file-fingerprints": "skipped by --quick",
            "hash": "the module as a whole (error)",
        },
        "blind_spots": ["this spyware is often rebuilt per target, so a new sample will "
                        "not match a published hash",
                        "platform-specific candidates up to 120 MiB in selected folders: Windows binary extensions; Unix also extensionless/executable files, libraries and scripts. Full/targeted modes accept all extensions",
                        "files that ran only in memory leave nothing to fingerprint"],
    }),
    ReaderSpec('host', 'host', 'host', ('win32', 'linux', 'darwin'), ('desktop',), {
        "platforms": ["Windows", "macOS", "Linux"],
        "reads": "Windows: per-user COM registrations, the DNS resolver cache, retained DNS "
                 "history (if enabled), the hosts file, known malware file paths. "
                 "macOS and Linux: the hosts file only.",
        "check_kinds": {
            "com-persistence": "per-user COM registrations (auto-start)",
            "com-signatures": "signature status of registered COM servers",
            "dns-cache": "current DNS resolver cache",
            "dns-log": "retained DNS history (Windows DNS Client log)",
            "dns-log-recording": "whether DNS history is being recorded",
            "dns-log-older-events": "older retained DNS events",
            "hosts-file": "the hosts file",
            "known-paths": "published file locations",
            "known-path:<path>": "one published file location",
            "devilstongue-traces": "file locations and hijacked COM classes published for Candiru's DevilsTongue (leads to check, not findings)",
            "host": "the module as a whole (error)",
        },
        "blind_spots": ["Windows does not keep DNS history unless it was turned on",
                        "the DNS cache only holds recent lookups"],
    }),
    ReaderSpec('traces', 'traces', 'traces', ('win32',), ('desktop',), {
        "platforms": ["Windows"],
        "reads": ("Windows records an ordinary account can read: the download origin "
                  "stamped on files (Mark of the Web) in Downloads, Desktop and "
                  "Documents; commands typed into the Win+R box; Microsoft Defender's "
                  "log; PowerShell's script-block log; registered antivirus status from Windows Security Center. No administrator rights."),
        "check_kinds": {
            "psreadline-history": "saved console input; successful execution unverified",
            "explorer-typed-paths": "saved Explorer input; contact unverified",
            "startup-registrations": "Run/RunOnce registry values in both views",
            "service-registrations": "service image and DLL registrations",
            "startup-files": "Startup batch/Internet Shortcut and bounded Shell Link literal target/argument metadata; unresolved shortcut IDLists and unsupported syntax remain gaps",
            "scheduled-task-actions": "task action fields, excluding descriptions",
            "extended-process-events": "opt-in existing Sysmon and Security process events; never enables logs or elevates",
            "mark-of-the-web": "download origins of files (Zone.Identifier)",
            "mark-of-the-web: remaining files": "files beyond the examination cap",
            "mark-of-the-web: unreadable": "files and folders whose download origin could not be read",
            "mark-of-the-web: deep folders": "folders below the depth limit",
            "mark-of-the-web: not downloaded": "files stored only in iCloud or OneDrive, not downloaded",
            "run-history": "commands typed into Win+R (where fake 'verify you are "
                           "human' pages tell people to paste)",
            "antivirus-status": "current registered antivirus product and update status reported by Windows Security Center; not an independent protection test",
            "defender-history": "Defender detections, historical protection-off events, "
                                "exclusions added",
            "powershell-history": "PowerShell script blocks, when that log is on",
            "ran-programs": "fingerprints of files in compatibility and launch records "
                            "(shim cache, Windows 11 launch list), wherever they are",
            "ran-programs: shim cache": "the shim cache could not be read",
            "ran-programs: launch list": "the Windows 11 launch list could not be read",
        },
        "blind_spots": ["files that were deleted take their download origin with them",
                        "commands run any other way than Win+R",
                        "the PowerShell log is usually off and holds a limited amount",
                        "Defender's exclusion list itself needs administrator rights; "
                        "only exclusions added while the log covers it are seen",
                        "a program that ran and was then deleted cannot be "
                        "fingerprinted (its name stays in Windows' lists)",
                        "Antivirus inventory requires Windows 8 or later desktop Security Center; unregistered products and Windows Server are not covered."],
    }, helpers=('security_products.py',)),
    ReaderSpec('windows-execution', 'execution', 'execution', ('win32',), ('desktop', 'targeted'), {
        "platforms": ["Windows; copied supported artifacts on any OS"],
        "reads": "Bounded Prefetch executable records and read-only Amcache registry hives; no referenced executable is opened.",
        "check_kinds": {"windows-prefetch": "supported SCCA Prefetch records; Windows MAM04 decompression where available",
                        "windows-amcache": "supported Amcache file inventory records; never execution proof"},
        "blind_spots": ["Locked, inaccessible, malformed and unsupported records remain gaps.",
                        "Executable names are not file-content identification; inventory does not prove execution.",
                        "Compressed Prefetch requires the Windows system decompressor; no registry hive mounting or transaction-log replay."]
    }, helpers=("winrecords.py",)),
    ReaderSpec('exploited-software', 'exploited', 'exploited', ('win32', 'darwin'), ('desktop',), {
        "platforms": ["Windows", "macOS"],
        "reads": "Installed program versions (Windows' list of installed programs and the Windows build; "
                 "macOS version and apps in /Applications), compared offline with CISA's Known Exploited "
                 "Vulnerabilities list and the fixed versions in each CVE record, saved by the indicator update.",
        "check_kinds": {"exploited-software": "installed programs older than the fix for an actively exploited "
                                              "vulnerability (prevention advice, never a finding)"},
        "blind_spots": ["Only a short list of common programs is checked.",
                        "Where a CVE record gives no comparable fixed version, only update advice is given.",
                        "Linux is not checked: distributions patch these programs through their own updates."]
    }),
    ReaderSpec('unix-host', 'posix', 'posix', ('linux', 'darwin'), ('desktop',), {
        "platforms": ["Linux", "macOS"],
        "reads": "Linux autostart entries, systemd units and one-level overrides, cron files/scripts; macOS launchd property lists; both platforms' standard shell profiles, saved shell history and current readable text logs. No commands are executed.",
        "check_kinds": {"linux-autostart": "supported autostart desktop entries",
                        "linux-systemd-units": "literal systemd command fields; activation unverified",
                        "linux-cron": "readable cron configuration; shell interpretation unverified",
                        "unix-shell-history": "saved Bash, Zsh and Fish history text; execution unverified",
                        "unix-shell-profiles": "standard shell startup files and immediate profile snippets; commands not interpreted",
                        "unix-system-logs": "readable current system/authentication text logs; bounded recent records, matches remain references",
                        "macos-launch-items": "supported launchd property-list command fields",
                        "unix-host-platform": "host platform applicability",
                        "unix-host-limits": "reader budgets and unsupported configurations"},
        "blind_spots": ["File presence does not establish enablement, execution or infection.",
                        "No binary journal/unified-log, rotated-log, memory, managed-login-item or system-wide forensic coverage. Custom shell paths and effective unit overrides are not resolved.",
                        "Permission failures, unsupported syntax, symlinks and budget exhaustion remain gaps."]
    }),
    ReaderSpec('android-intrusion', 'intrusion', 'intrusion', ('all',), ('android',), {
        "platforms": ["any (decrypted Android intrusion logs)"],
        "reads": "Supported newline JSON DNS, TCP connection and security-event exports from Android intrusion logging, including bounded ZIP members.",
        "check_kinds": {"android-intrusion:files": "availability, supported files and bounds",
                        "android-intrusion:dns": "DNS event hostnames and addresses; contact unverified",
                        "android-intrusion:connections": "TCP connection attempts; success unverified",
                        "android-intrusion:processes": "structured process-start events",
                        "android-intrusion:security-events": "supported typed security events; unsupported events remain gaps"},
        "blind_spots": ["Optional logging may be disabled or its records unavailable.",
                        "Encrypted archives require separate owner-authorized decryption.",
                        "A TCP connection event may represent a failed attempt; it is not proof of contact.",
                        "Unknown schemas, malformed events and exhausted budgets remain gaps."]
    }),
    ReaderSpec('android', 'android', 'android', ('all',), ('android',), {
        "platforms": ["any (reads an AndroidQF collection folder; --phone PATH)"],
        "reads": ("An AndroidQF collection: the app list with each app's fingerprint and "
                  "signing certificate, running processes, system properties, settings, the "
                  "collected file list and the phone's system logs (dumpsys, logcat). Never "
                  "talks to the phone itself."),
        "check_kinds": {
            "android": "the folder as a whole (not an AndroidQF collection)",
            "android:packages": "installed apps vs app ids, APK fingerprints, signing certs; "
                                "sideloaded apps with what they can do and when installed",
            "android:app-fingerprints": "user-installed app files that had no valid SHA-256 fingerprint in the collection",
            "android:app-certificates": "user-installed app files that had no readable signing certificate in the collection",
            "android:processes": "running apps from processes.txt or AndroidQF processes.json pid/command_line records; arguments are not app identities",
            "android:history": "apps installed, updated or removed, from the battery history",
            "android:crashes": "crash records in the bug report",
            "android:messages": "links and addresses in SMS messages, from the SMS backup",
            "android:device-security": "debug build, unlocked bootloader, SELinux, writable "
                                       "system partition",
            "android:properties": "system properties; security patch age",
            "android:settings": "accessibility access, app verification, debugging, "
                                "device admins",
            "android:files": "collected file paths and fingerprints",
            "android:file-hashes": "file fingerprints recorded in the collection",
            "android:root": "collected root-tool records",
            "android:device-logs": "spyware domains, IPs, app ids and paths in the system "
                                   "services' state (dumpsys) and logcat",
        },
        "blind_spots": ["only what Android lets USB debugging read: no app private data, no "
                        "deleted traces", "only crash records are read from the bug report",
                        "encrypted SMS backups without the password or with unsupported encryption",
                        "spyware that leaves no app, process or log entry",
                        "process names are not compared on Android: every published list "
                        "comes from iPhone investigations and some names are normal "
                        "Android services"],
    }),
    ReaderSpec('ios', 'ios', 'ios', ('all',), ('ios',), {
        "platforms": ["any (local Finder/iTunes backup)"],
        "reads": "Local backups (including password-based decryption), extracted filesystems and sysdiagnose directories/TAR archives. Supported messages, browser, process, configuration and diagnostic artifacts; validated SQLite WAL replay on temporary copies.",
        "check_kinds": {"ios:manifest": "backup manifest", "ios:messages": "SMS text and dates", "ios:safari": "Safari visits", "ios:processes": "data-usage process names", "ios:applications": "installed application identifiers",
                        "ios:chrome-history": "optional Chrome backup History visits; known local visits establish contact, synced/imported/unknown origin stays reference",
                        "ios:firefox-history": "optional historical Firefox browser.db history/visits; only is_local=1 establishes local contact",
                        "ios:input": "bounded evidence inventory and temporary plaintext cleanup",
                        "ios:message-handles": "message correspondent identifiers",
                        "ios:message-attachments": "attachment metadata references",
                        "ios:browser-state": "saved browser tab references",
                        "ios:safari-bookmarks": "saved Safari bookmark and reading-list URLs; references, not visits",
                        "ios:webkit-statistics": "WebKit observed domain references",
                        "ios:url-cache": "URL cache request references",
                        "ios:whatsapp": "supported WhatsApp message text and direction",
                        "ios:permissions": "TCC client permission records",
                        "ios:calls": "call correspondent records",
                        "ios:calendar": "calendar text and URL references",
                        "ios:interactions": "interaction bundle identifiers",
                        "ios:shortcuts": "shortcut names and inert plist action references",
                        "ios:analytics": "supported analytics identifiers and literal references",
                        "ios:location-clients": "location client metadata",
                        "ios:preferences": "recorded Lockdown Mode preference and literal references",
                        "ios:id-status-cache": "accounts looked up by iMessage and FaceTime",
                        "ios:favicons": "page and icon addresses stored by Safari and Chromium browsers",
                        "ios:webkit-origins": "sites that stored data in an app's web view (LocalStorage, IndexedDB, WebsiteData origins)",
                        "ios:keychain-analytics": "calling processes and strings in security-framework analytics records (file-system extractions)",
                        "ios:profiles": "profile configuration identifiers",
                        "ios:profile-events": "historical profile identifiers",
                        "ios:profile-settings": "literal references in device-management settings",
                        "ios:app-metadata": "application metadata identifiers",
                        "ios:webkit-session": "saved WebKit resource references",
                        "ios:shutdown": "shutdown process paths and investigation leads",
                        "ios:crashes": "supported IPS and legacy crash process identities",
                        "ios:process-list": "processes running when a sysdiagnose was captured",
                        "ios:browser-connections": "servers Chromium-based iPhone browsers connected to",
                        "ios:brave-sites": "sites recorded by the Brave browser",
                        "ios:installations": "app identifiers and container paths in installation logs"},
        "blind_spots": ["Unsupported schemas and encoded message variants, missing artifacts, deleted data and live phone state.", "Encrypted backups require the owner's password and optional cryptography; encrypted Manifest.db WAL cannot be replayed without independent key metadata.", "Only selected sysdiagnose artifacts are parsed; unified logs and binary diagnostics are unsupported."],
    }, helpers=("ios_sources.py", "ios_messages.py", "ios_artifacts.py")),
    ReaderSpec('patterns', 'patternscan', 'patterns', ('all',), ('desktop', 'targeted'), {
        "platforms": ["Windows", "macOS", "Linux"],
        "optional": "--patterns; needs the pinned YARA-X engine",
        "reads": "Files checked against published Candiru detection rules.",
        "check_kinds": {
            "pattern-engine": "the YARA-X engine is present and pinned",
            "pattern-limits": "size and count limits",
            "pattern-roots": "folders selected for pattern checks",
            "com-pattern-candidates": "files named by COM registrations",
            "root:<folder>": "one folder that was pattern-checked",
            "patterns": "the module as a whole (error)",
        },
        "blind_spots": ["running memory is not inspected",
                        "a rule match is a lead for an expert, not proof"],
    }, optional='patterns'),
)
_READER_META = {'scan': {
        "platforms": ["all"], "reads": "Scan lifecycle; no additional artifacts.",
        "check_kinds": {"scan-interrupted": "remaining checks were cancelled"},
        "blind_spots": ["A cancelled scan does not cover its remaining checks."],
    },
'indicators': {
        "platforms": ["any"],
        "reads": "Downloaded source availability, integrity and last verified refresh dates.",
        "check_kinds": {"indicator-sources": "missing, refused, stale or undated downloaded sources"},
        "blind_spots": ["A refreshed source can still contain historical indicators."],
    },
'deep': {
        "platforms": [],
        "optional": "--deep; not implemented yet (always reported as not run)",
        "reads": "full persistence sweep (planned)",
        "check_kinds": {"persistence-sweep": "full persistence sweep (planned)",
                        "deep": "the module as a whole (error)"},
        "blind_spots": ["not implemented"],
    }}


def reader_validate(specs=None):
    """Reject ambiguous registrations before building or executing readers."""
    import re
    specs = READER_SPECS if specs is None else specs
    for attr in ("name", "module", "suffix"):
        values = [getattr(spec, attr) for spec in specs]
        if len(values) != len(set(values)):
            raise ValueError("duplicate reader " + attr)
    for spec in specs:
        if not re.fullmatch(r"[a-z][a-z0-9_]*", spec.module) or not re.fullmatch(r"[a-z][a-z0-9_]*", spec.suffix):
            raise ValueError("invalid reader module or bundle suffix")
        if not spec.name or spec.name in _READER_META:
            raise ValueError("invalid reader name")
        if not spec.modes or not set(spec.modes) <= {"desktop", "targeted", "android", "ios"}:
            raise ValueError("invalid reader mode")
        if not spec.platforms or not set(spec.platforms) <= {"all", "win32", "linux", "darwin"}:
            raise ValueError("invalid reader platforms")
        if spec.optional not in ("", "patterns"):
            raise ValueError("invalid reader option")
        if not all(re.fullmatch(r"[a-z][a-z0-9_]*\.py", path) for path in spec.helpers):
            raise ValueError("invalid reader helper")
        if not all(key in spec.catalogue for key in ("platforms", "reads", "check_kinds", "blind_spots")):
            raise ValueError("incomplete reader coverage description")
        if not isinstance(spec.catalogue["check_kinds"], dict):
            raise ValueError("invalid reader checks")


def reader_catalogue():
    reader_validate()
    result = copy.deepcopy(_READER_META)
    result.update({spec.name: copy.deepcopy(spec.catalogue) for spec in READER_SPECS})
    for spec in READER_SPECS:
        result[spec.name]["check_kinds"].setdefault(spec.name, "reader import, interface, runtime or cancellation failure")
    return result


def reader_describe():
    return [{"name": spec.name, "module": spec.module,
             "platforms": list(spec.platforms), "modes": list(spec.modes),
             "optional": spec.optional} for spec in READER_SPECS]


def reader_select(ctx, platform=None):
    """Select only applicable built-ins; explicit artifacts are host-independent."""
    from .localpaths import path_problem
    reader_validate()
    platform = sys.platform if platform is None else platform
    platform = "linux" if platform.startswith("linux") else platform
    if ctx.phone_path:
        marker = os.path.join(os.path.abspath(ctx.phone_path), "Manifest.plist")
        mode = "ios" if getattr(ctx, "ios_input", "") or (not path_problem(marker) and os.path.isfile(marker)) else "android"
    else:
        mode = "targeted" if ctx.targets else "desktop"
    browser_only = mode == "desktop" and getattr(ctx, "browser_only", False)
    return tuple(spec for spec in READER_SPECS
                 if mode in spec.modes
                 and (not browser_only or spec.name == "browser")
                 and (mode != "desktop" or "all" in spec.platforms or platform in spec.platforms)
                 and (not spec.optional or getattr(ctx, spec.optional, False)))


def reader_resolve(spec):
    module = importlib.import_module(".modules." + spec.module, "zbtriage")
    if module.NAME != spec.name or not callable(module.run):
        raise ValueError("reader interface mismatch: " + spec.name)
    return module.run


def reader_run(ctx, resolver=None):
    """One guarded lifecycle for source and bundle, retaining partial findings."""
    from .netguard import no_network
    from .result import ModuleResult
    resolver = reader_resolve if resolver is None else resolver
    with no_network():
        for spec in reader_select(ctx):
            if ctx.cancelled:
                break
            result = None
            if spec.name == "hash" and ctx.quick:
                result = ModuleResult(spec.name)
                result.could_not_run("file-fingerprints", "skipped by --quick. No file on this machine was "
                                    "fingerprinted, so a known sample sitting on disk would "
                                    "not have been found. Re-run without --quick to include it")
                ctx.completed.append(result)
                ctx.emit("[*] skipping file fingerprints (--quick)")
                continue
            ctx.emit("[*] running check: " + spec.name)
            started = time.monotonic()
            ctx.partial = None
            try:
                result = resolver(spec)(ctx)
                if not isinstance(result, ModuleResult) or result.name != spec.name:
                    raise ValueError("reader returned an invalid result")
            except (Exception, KeyboardInterrupt) as exc:
                partial = ctx.partial
                result = (partial if isinstance(partial, ModuleResult) and partial.name == spec.name
                          else ModuleResult(spec.name))
                ctx.cancelled = isinstance(exc, KeyboardInterrupt)
                result.could_not_run(spec.name, "scan cancelled; remaining checks did not run"
                                     if ctx.cancelled else "module error: {}".format(str(exc) or type(exc).__name__))
            ctx.completed.append(result)
            ctx.partial = None
            result.duration_s = time.monotonic() - started
            ctx.emit("[*]   {} finished in {:.0f}s".format(spec.name, result.duration_s))
        if ctx.deep and not ctx.phone_path and not ctx.cancelled:
            result = ModuleResult("deep")
            result.could_not_run("persistence-sweep", "tier 2 (--deep) is not implemented yet — no full "
                                "persistence sweep was performed. A full persistence review "
                                "requires a separate forensic examination")
            ctx.completed.append(result)
    return ctx.completed
