# Methodology

How the toolkit decides what to check, how strong each kind of evidence is, and what it
learned from other forensic tools. Only methods and facts were taken from those tools; no
code was copied into this project (several are under copyleft licences).

## Principles

1. **Never contact an indicator.** A scan blocks Python socket calls and refuses redirected
   paths and Windows remote drives. `--update` downloads from fixed official sources, and
   the separately invoked guided Android acquisition downloads its pinned collector after
   owner consent. This is not an OS network sandbox; see [PRIVACY.md](../PRIVACY.md).
2. **A check that could not run is a gap, never a clean result.** Every report lists what
   it could not check. Incomplete evidence or indicator sources give exit `3` when there
   are no actionable matches; findings take precedence with exit `2`, and the gaps are kept.
3. **Evidence is graded.** The same indicator means different things in different places:
   a spyware file's fingerprint on disk is conclusive, while the address in a saved web
   page is usually an article about the spyware. The grade, not the number of matches,
   decides the advice.
4. **Hunches are not findings.** Things the tool cannot judge go under "worth a look", each
   with its usual harmless explanation, and never change the result.

## Evidence grades (strongest first)

| Grade | Meaning |
|---|---|
| on-disk | a file has the fingerprint of a published spyware sample |
| on-device | an app, signing certificate, file or setting researchers name is on the phone |
| file-pattern | a published detection rule matched a file (a lead, not proof) |
| persistence | the name is registered to start automatically |
| ran-command | a command or script that names it ran here (Win+R, PowerShell log); it may be a researcher's own command |
| execution-record | a historical execution record names an executable; its contents and resolved path are not established |
| inventory-record | a historical file inventory names it; execution and current presence are not established |
| contacted | the device demonstrably talked to it (a cookie it set, a secure-connection record, a download from it) |
| device-log | the phone's own system logs name it |
| received | a message that arrived on the device (an inbox SMS/MMS, an incoming iMessage or WhatsApp message) contains it; opening or following it is not established |
| dns-record | a name lookup was recorded; contact unverified |
| attempted | something tried to reach it and was blocked |
| configured | it appears in local configuration |
| referenced | it appears in saved content, which is usually not contact |

## What we learned from other tools

**MVT (Mobile Verification Toolkit) and Amnesty's forensic method.** Which phone records
carry evidence: on Android, the app list with fingerprints and signing certificates,
properties, settings, files and system logs; on iPhone, backup records such as data-usage
process names, browser history, messages and configuration profiles. MVT also raises
heuristic flags (sideloaded apps, risky permissions, crash logs). On an ordinary phone these
usually have a harmless cause, and some are produced by the collection itself. Two rules
follow: heuristics are only ever "worth a look", and the check recognises its own footprint
(for example, USB debugging being on because the collection needed it).

**Process names are platform-specific.** The process-name lists used here come from iPhone
investigations, where spyware imitated Apple's service names, and some of those names are
ordinary Android services (`gatekeeperd` is Android's lock-screen service). The Android
check therefore does not compare process names; the iPhone reader does.

**Stalkerware lists name companies.** Domain lists of commercial phone-monitoring apps
include the companies' ordinary websites (Microsoft Family Safety's among them). On a
computer such a domain is never a spyware finding: a visit is "worth a look" and a mention
is only counted. On a phone, where stalkerware runs, it stays a finding.

**Kaspersky's iShutdown method.** An iPhone's shutdown log, inside a sysdiagnose archive
the owner can create, records processes that delayed a reboot; some spyware families leave
traces there. The iPhone reader checks supported shutdown client records and rotations.
Directory anomalies are leads to confirm with other evidence; delays and path names alone
do not establish infection.

**Velociraptor's documentation and Sigma rules: where Windows keeps evidence.** An ordinary
account can read the Win+R history, the shim cache, the Windows 11 program-launch list,
Microsoft Defender's log and the PowerShell log; these are in the default scan. Further
readers cover PSReadLine, Explorer TypedPaths, Run/RunOnce, Startup files, task actions,
services, Prefetch and Amcache. Existing Sysmon and Security events are opt-in with
`--extended-windows` and may need administrator rights. BAM and SRUM are not implemented.

Design notes:

- Windows' launch list records programs started through the desktop shell.
- Most of Defender's "settings changed" events are its own housekeeping, so exclusions are
  read separately and listed first.
- Desktop apps' raw web caches are most of their data and hold only "referenced" evidence.
  The default scan reads their supported cookies, history and storage and reports the
  skipped caches as a gap; `--scan-type full` includes them.

## Result and source limits

### Reader selection

Platform selection comes from the shared built-in reader registry. Browser and file
fingerprinting readers run on supported desktop platforms; live Windows readers run only on
Windows, and Linux/macOS startup readers only on their own platform. Targeted scope can
include copied Windows execution artifacts on any platform. Registration is in the source,
not an input-file plugin loader; see [scan/READERS.md](../scan/READERS.md).

### Verdicts and indicator sources

Reference-only matches are kept as context, with their own verdict and counts. They do not
trigger preservation advice or exit `2`; coverage gaps still give exit `3`. Matches to
indicators that every listing publisher has withdrawn are handled the same way under their
own `WITHDRAWN_ONLY` verdict, because their grade may still record real contact and calling
them references would understate it; the summary advice changes to historical review,
while a source that has not withdrawn the indicator keeps its recommendation. Each STIX
object's newest version decides, so a stale
cached copy of an active bundle cannot outvote that publisher's later withdrawal. Versions
belong to one object: revoking one indicator object does not withdraw a different, still
active object the same publisher has for the same value. A STIX `file:name` that holds a
full path is used as a path.

Some matching choices are deliberate:

- An IP indicator is bounded by digits and dots on both sides but not by letters, so a
  dotted quad inside text such as `v1.2.3.4` still matches. The evidence grade decides what
  it means, and a mention in saved content stays a reference.
- When the same value comes from several files, the first file's tier and confidence are
  kept, and the curated file is loaded first, so a hand-reviewed tier is never overwritten
  by a feed's. Confidence is provenance only and never changes a verdict.
- Duplicate rows within one curated file must agree on tier and confidence; conflicting
  rows are refused. Matching duplicates keep each source and family. STIX objects sharing a
  value keep all linked families and each publisher's assertions.
- Curated files are limited to 16 MiB and 64 KiB per line. More than 256 distinct publisher
  assertions for one indicator is refused rather than silently dropping versions or
  attribution.

Missing, rejected, stale or undated downloaded sources are coverage gaps. Freshness comes
from curated content dates and successful feed verification times, never from file
modification times. Refreshing a source does not mean its old indicators were newly seen.

STIX publisher assertions keep dates, explicit platform labels and withdrawal flags. They do
not establish an indicator's current ownership, independent confirmation or a campaign's
duration. Correlation groups exact matching indicators across different artifact
locations, removes exact duplicate records and orders available timestamps. It never
changes evidence grades, verdicts or recommended actions. See [COVERAGE.md](COVERAGE.md).

### Browsers

A Chromium history entry counts as contact only when this browser made the visit. Visits
that history sync copied from another device are references, with a worth-a-look note to
check that device. History imported from another browser on the same computer counts as
local. Browser databases are read only from real tables: a view or recursive query, which
no browser writes, is refused, and each database has a time limit. Both produce a gap, not
a clean result.

History, favicon and download-chain readers grade an HTTP(S) URL's host separately from its
path, query, fragment, user information and surrounding title. A more specific indicator in
reference text cannot erase a recorded contact with the host; a parent-domain reference
beside a child-host contact stays a reference. Download-chain host matches are attempted
contact; completed or received-byte metadata supports contacted. Neither proves execution
or infection.

Chromium's HSTS record stores only a hash of each host name, so it can be matched to an indicator only by the exact host name; subdomains of an indicator cannot be derived from it, and HSTS alone will not name them (history, cookies and connection records still do).

Chromium cache roots are mapped separately from profile roots on Linux and macOS, using the
standard configuration/cache relationship, each Flatpak app's own `config`/`cache` folders
and a snap package's `common`/`common/.cache` folders. Standard Linux browser paths honour
absolute XDG configuration and cache overrides. Explicit selections include a separate cache
only when it falls inside a selected target. Chromium bookmark JSON is bounded by bytes,
entries and folder depth; bookmark URLs are references, not visits.

Desktop apps with a built-in Chromium browser are found by folder contents under AppData
on Windows, Application Support on macOS (Apple's own `com.apple.*` data is skipped) and the
user and per-app Flatpak configuration folders on Linux. An app whose own folder is a
Chromium profile is found too. There is no fixed depth limit; the search is bounded by
folder count and time, and reaching the bound is a gap. Unreadable folders are a gap, links
are not followed, and folders the operating system itself locks are not counted.

Desktop Safari's `History.db` records use visit-level origin and load status: known local
successful visits are contacts, known local failures are attempts, synced visits are
references, and uncertain metadata stays a reference with a gap. Ambiguous duplicate item
IDs are refused as visit targets. Safari's other stores are read from its sandbox
(`~/Library/Containers/com.apple.Safari/Data/Library`) and `~/Library/Safari`:

- cookies (`Cookies.binarycookies`, parsed page by page with every offset bounded) and HSTS
  records exist only because the site answered this browser, so both are contacts;
- a download is a contact if bytes were received, an attempt if not;
- tabs, iCloud tabs, the URL cache, WebKit's tracking-prevention domains, bookmarks, Top
  Sites and recently closed tabs are references.

Temporary SQLite copies keep the usual WAL and source-read protections.

### Windows records

The compatibility and launch readers cover ShimCache and the Windows 11 launch list.
ShimCache alone shows presence, not execution, and its file-modification time is not used
as a launch time. Hashing has explicit extension, size and directory limits (see
[README.md](../README.md)). Task parsing examines action fields, not descriptions.

**Startup batch files.** Supported batch commands and Internet Shortcut URLs are
persistence configuration; comments and arbitrary embedded text are references. This is a
limited reader, not a CMD interpreter, and it does not prove execution.

- Carriage returns are removed and physical lines are split only at line feeds.
- Ordinary REM comments consume their line; the supported `rem /? & command` form is a help
  command followed by a command. Unparsed REM punctuation variants affect only their own
  logical line.
- Continuation lines stay together. Recognition accounts for quoted carets and the extra
  physical line consumed after an escaped newline followed by a blank line.
- Pipes, redirection, general chaining and control flow are unsupported and produce gaps
  without discarding commands already recognised. Unsupported control flow leaves the rest
  of the block or file uninterpreted.
- A literal command with unresolved argument expansion, such as
  `start "" "%APPDATA%\x.exe" URL`, keeps its literal launch evidence plus a gap for the
  expansion. Variables are never expanded.
- Continued `::` labels and BOM-marked UTF-16 batch files stay reference text with a gap.

**Startup shortcuts.** `.lnk` files are parsed as bounded binary metadata following
Microsoft's [MS-SHLLINK specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-shllink/).
Recognised literal relative paths, local and network LinkInfo paths and command-line
arguments are configuration evidence, not proof of the resolved target or of execution.
Descriptions, working-directory and icon strings are references. Environment-path strings
are kept literally with a gap for expansion. IDLists are structurally bounded but not
resolved; unfamiliar extra blocks and flags are gaps. Unicode strings are supported; ANSI
strings accept only their unambiguous ASCII subset. Nested volume and network fields and
string extents are validated; overlapping LinkInfo fields are treated as unsupported.
Malformed shortcuts give references and a gap, never guessed launch findings. The parser
does not access a shortcut's target, share, icon or working directory, call shell APIs or
expand environment variables.

Other unknown Startup formats are gaps; only `.txt`, `.md`, `.log` and `.ini` are accepted
as reference documents without launch interpretation. Saved console and Explorer input is
reference evidence. Nothing found in a task, registry value or history record is executed.

**PSReadLine and registry.** History discovery uses PSReadLine's default Windows directory,
including host-specific history filenames. Large histories are read from the newest end and
the omitted older records are reported. Custom history paths are out of scope. Absent
optional history is distinguished from an unreadable existing file. Deleted historical
program files are counted and explained as a limitation; only surviving files can be
fingerprinted. Unreadable existing files are gaps. Shared registry values are deduplicated
across views.

**Prefetch.** Supported SCCA headers, section extents, executable basenames, file metrics,
run counts and timestamps are validated. A complete basename with a nonzero run count and a
recorded time can match a file-name indicator as `execution-record`. A file metric may name
a DLL or another accessed file; a matching basename does not establish the executed
program's full path, so metric matches are references. Truncated names and incomplete run
metadata keep references and gaps. On Windows, supported MAM04 compression uses the system
decompressor with bounded output; other compression variants, and compressed Prefetch on
other platforms, are gaps.

**Amcache.** Allocated records in clean supported hives are read, including modern
`Root\InventoryApplicationFile` paths and legacy `Root\File` records. Matching file
identities are `inventory-record`, not proof of execution or of present-day contents. The
reader does not mount hives, replay transaction logs, carve deleted cells or treat
Amcache's FileId as a full-file hash. Dirty hives, unsupported schemas and inconsistent
records are gaps.

Neither the Prefetch nor the Amcache reader opens a program path taken from an artifact.
Binary input, record counts, decoded text and total work are bounded; earlier findings
survive later unsupported records where recovery is possible.

**Antivirus inventory.** Windows Security Center's native product-list interface is loaded
from system libraries, with no vendor-specific executable or remediation action. All
registered products are eligible. Product and signature states are reported as Windows
reports them; a failed or unsupported query is a gap. If a registered product is on,
historical Defender protection-off events are context, not current warnings. Defender
detections, added exclusions and indicator matches are still reported. Current
registration cannot establish protection at an earlier time or verify a product's health;
unregistered products and Windows Server are not covered.

### Linux and macOS

**Linux startup.** Immediate entries in standard autostart directories, systemd unit
directories, one-level unit/type `.d/*.conf` overrides, readable cron configuration and the
hourly/daily/weekly/monthly script directories are read. The desktop-entry reader
recognises a narrow literal `Exec` grammar with optional double quotes. It does not use
shell parsing, expand field codes or resolve executable search paths; unsupported quoting,
escapes and substitutions stay references with a gap. Disabled or conditional entries are
references. Systemd and cron content is reference evidence, because unit activation,
effective overrides and shell interpretation are not resolved. Reading an override file does
not establish whether its settings take effect.

**macOS startup.** Standard LaunchAgent and LaunchDaemon XML and binary property lists are
read. In a valid labelled entry that is not explicitly disabled, the literal `Program` (or
first `ProgramArguments` element) can match an exact executable-path indicator, and its file
name a process-name indicator, as configured evidence. An entry with a conditional
`Disabled` value is searched as text only. Apple's App cryptex launch folders are read, so
the system links into them are not gaps. Apple plists shipped with an unquoted XML
declaration, DOCTYPE or `<plist version>` are read after that prolog is normalised. External
launchd overrides are not resolved, and activation or execution is not established.
Arbitrary arguments and network strings are references. Managed login items, binary
journal and unified logs, and memory are outside these readers.

**Shell history, hosts and logs (both).** Standard Bash/Zsh/fish startup files and saved
history are read, including macOS Terminal's per-session files (`~/.zsh_sessions/*.history`,
`~/.bash_sessions/*.history`), which replace a single history file on current macOS.
Executable paths are matched as whole shell words, including inside `$( )` and backticks
and after `;`, `|` and `&`. Selected current text system logs are read where permitted. All
of this is reference evidence: a saved command is not proof it ran, and a log string is not
proof of contact. The hosts file follows the Windows rules: an indicator pointed at a real
address is configured evidence, one pointed at a block address is only counted.

Configuration files have a 1 MiB limit. History and logs keep at most their most recent
4 MiB, drop a partial first line and report the omitted part as a gap. Total bytes and
entries are also bounded. Custom history paths, unsaved shell input, rotated or compressed
logs and other users' homes are not covered.

Linked startup files are not followed. A unit masked by a link to `/dev/null` has nothing to
read, and a systemd alias whose target is inspected in its own right (including one spelled
through a merged-`/usr` system's root-owned `/lib` link) is not a gap; a link anywhere else
is a gap naming its target. A standard location that is only a link to another inspected
location (Alpine's `/var/spool/cron/crontabs`) is inspected once. Files this account cannot
read are reported as needing administrator rights. Permissions, redirections, malformed
input and exhausted entry or byte limits are gaps; files already collected are still checked
when an enumeration limit is reached.

**File fingerprints.** Default roots are platform-specific. Linux includes ordinary user
folders, `.local/bin`, XDG configuration and data locations and temporary directories; macOS
includes ordinary user folders, application and support locations, launch directories and
temporary directories. Besides the Windows candidate extensions, Unix candidates include
extensionless files, executable files, `.so` and versioned shared libraries, `.dylib` and
supported script extensions. They are never executed or loaded. Full and targeted scans
accept every extension; the 512 MiB limit and access restrictions still apply. Arbitrary
file-system links are refused; the exact root-owned macOS `/var`, `/tmp` and `/etc` aliases
are validated against their `/private` locations, and the `/System/Cryptexes/App` and `OS`
links against their Preboot volume locations.

### Android

File-path and filename identities keep the publisher's original case, including merged
assertions; case differences and longer path prefixes do not become exact matches.
Structured crash command paths are matched as complete identities; generic device-log path
strings need token boundaries and keep the log reader's evidence grade.

App files are compared by SHA-256 fingerprint and by signing certificate. Certificate
indicators may be SHA-256 or SHA-1 digests, and an app file covers only the digests it
records, so missing SHA-256 and SHA-1 certificate digests are counted separately. A
user-installed app whose fingerprint or certificate digest is missing from the collection
is a gap for that comparison; built-in apps on the system partitions, whose certificates
collections commonly omit, are listed in a note instead.

## Verification

See [VERIFYING.md](VERIFYING.md) to check that a downloaded file was built from this source.

## Added format readers and context

### iPhone

The iPhone reader uses a local manifest index and explicitly supported SQLite schemas. It
never joins a file-system path taken from a backed-up app: source files are selected only
by validated hexadecimal manifest IDs. Encrypted records use the supplied password, the
backup keybag's class keys, RFC 3394 key unwrapping and per-file AES-CBC. Selected inert
attributed-message encodings are decoded; unsupported encoded bodies and binary fields are
gaps.

Message, browser-visit and process records are read in bounded pages of integer SQLite row
IDs, at most 16 payloads at a time; if a batch fails, each row is retried on its own.
Oversized or undecodable rows are skipped with a specific reason and their readable
neighbours are kept. Repeated gaps are counted once per check and reason, with the
occurrence count in the reason; skipped-record totals stay available. An unreadable row
index or wider database corruption can still stop that artifact; there is no general
database repair or deleted-record recovery.

Required artifacts are looked up separately from the bounded manifest filename sweep.
Views, virtual tables and generated columns are refused; database operations, returned
field sizes and per-artifact text processing are limited. Each SQLite query has its own
10-second and 20-million-VM-operation budget (checked every 1,000 operations), so time spent
between queries does not use up a later lookup's budget. Running out identifies a query
limit, not a missing artifact. Row, byte and per-artifact time caps bound the total work,
including per-row recovery queries; there is no single deadline for the whole backup.
Payloads skipped for exceeding the text limit do not count against the searched-text
budget. Validated committed WAL records are replayed on temporary copies; damaged or
unsupported WALs are gaps, and encrypted root-manifest WALs, which lack separate key
metadata, are not replayed. Temporary plaintext copies are removed after use; removal is
not secure erasure.

Additional iPhone browser checks use exact manifest locations and physical tables:

- **Chrome:** `AppDomain-com.google.chrome`,
  `Library/Application Support/Google/Chrome/Default/History`; `urls` and `visits` tables.
  A local visit requires `visit_source` provenance of `1` (a missing source row defaults to
  `1`) and an absent, NULL or empty `originator_cache_guid`. Without the `visit_source`
  table, URLs stay references and a provenance gap is recorded.
- **Firefox:** `AppDomainGroup-group.org.mozilla.ios.Firefox`, `profile.profile/browser.db`;
  the historical `history(id,url)` and `visits(siteID,date,is_local)` schema. Only integer
  `is_local=1` establishes a local visit. Missing provenance keeps references and records a
  gap. Other schemas are unsupported.

Both need actual visit records, not just a URL or bookmark. Host and reference grading
follows the desktop browser rules. An absent optional browser database is ignored; a
present unreadable, unsupported, truncated or damaged-WAL database is a gap. Hit provenance
identifies the original backup blob, not a temporary decrypted file.

The shared iPhone source layer also accepts selected extracted file systems and sysdiagnose
directories or TAR archives, with bounded access, temporary database replay and source and
member hashes. Generic cache and metadata strings are references; typed records keep their
narrower meaning. See [IPHONE.md](IPHONE.md) for schemas, bounds, provenance and unsupported
formats.

### Android

Process inventories are read from `processes.json`, from the legacy text format
(`processes.txt`, or `ps.txt` from older AndroidQF releases). JSON entries need a positive
integer `pid` and a `command_line` string array. Only the first command-line element is
compared with app identifiers, allowing an Android `:service` suffix. Arguments and
environment text are not app identities, and iPhone process-name indicators are not applied
to Android. Null or empty command lines and malformed records are counted as skipped with
gaps. Duplicate app findings across JSON and text are suppressed. The Android file inventory
is streamed with a 1 GiB input limit and a 4 MiB limit per record.

SMS and MMS messages from the backup are searched; only inbox messages are graded
`received`, and sent, draft and failed messages are references. MMS attachments are not
opened.

The intrusion-log reader inspects already decrypted `intrusion_logs` or `intrusion-logs`
exports: newline-JSON `.txt` records and supported ZIP members. It validates typed
`dns_event`, `connect_event` and supported `security_event` payloads before matching their
fields. DNS hostnames and returned addresses are `dns-record`; a TCP connection event is a
`device-log` attempt whose success is unverified. Neither is upgraded to contacted.
Process-start records describe past activity, not current installation or file presence.
Unsupported security tags are gaps. Duplicate events are suppressed. File and member counts,
JSON line sizes, expanded bytes, event counts and processing time are bounded. Archive
members are read without extracting paths; links, unsafe names, unsupported encryption or
compression and oversized indexes are refused. Invalid rows produce gaps while later
readable rows are still read. The reader does not enable logging, access a live phone or
decrypt an encrypted export.

### Format sources

Android backup encryption follows the format described by AOSP's
[backup writer](https://github.com/aosp-mirror/platform_frameworks_base/blob/master/services/backup/java/com/android/server/backup/fullbackup/PerformAdbBackupTask.java)
and [password/checksum routines](https://github.com/aosp-mirror/platform_frameworks_base/blob/master/services/backup/java/com/android/server/backup/utils/PasswordUtils.java).
Apple describes the [backup keybag](https://support.apple.com/guide/security/keybags-for-data-protection-sec6483d5760/web).
The iOS implementation uses the format notes published by
[ios-backup-crypt](https://pkg.go.dev/github.com/novkostya/ios-backup-crypt/internal/keybag)
and [golemine](https://github.com/pmeenan/golemine/blob/main/docs/iOS-Backup-Format.md).
Firefox binary HSTS slots follow Mozilla's
[DataStorage format](https://github.com/mozilla/gecko-dev/blob/master/security/manager/ssl/data_storage/src/lib.rs);
checksums, fixed field widths and HSTS state are validated before host keys are read. No
source code from these projects was copied.

### Guided acquisition

`--collect-android` is a separate, explicit operation. It pins AndroidQF v1.8.3 and its
official release digests, verifies the downloaded bytes before running them and requires
interactive owner consent. It does not search PATH for an existing collector. Plaintext ZIP
extraction rejects traversal, links, device filenames, duplicate outputs and oversized
members. Public age recipients can be supplied with `--age-recipient-file`; encrypted output
is kept for separate decryption. No collector code is copied or bundled. Release metadata:
https://github.com/mvt-project/androidqf/releases/tag/v1.8.3.

## Inspection and private handoff

The interactive follow-up reads the completed report (findings with their grades, gaps and
fixed next steps). It does not rescan, execute evidence or open links, and an output error
never turns an incomplete save into a successful scan. A completed scan with gaps is partial
even when it has no findings.

Evidence export is explicit and produces a private, **unencrypted** ZIP. Only files the
person selects are added; report strings never select them, and nothing is uploaded. Report
outputs are refused when they would replace selected source evidence (including files under
a selected input folder) or an existing file in the app data and app cache folders where
desktop apps keep the records the scan reads. Selected files are copied at export time with
their metadata checked before and after, so the hashes establish later archive integrity,
not original authenticity, infection or a transaction-consistent forensic image. Limits and
manifest contents are listed in [scan/CONTRACT.md](../scan/CONTRACT.md).
