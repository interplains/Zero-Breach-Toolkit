# Changelog

## 2.0.0 (unreleased)

Languages
- The window and the report are available in 27 languages: English, Arabic, Chinese,
  Croatian, Farsi, French, German, Greek, Hebrew, Italian, Japanese, Korean, Kurdish, Malay,
  Polish, Portuguese, Punjabi, Romanian, Russian, Spanish, Swahili, Swedish, Tagalog, Tamil,
  Telugu, Turkish and Ukrainian. The window starts in the computer's language and has a
  language picker; `--lang CODE` chooses it for the terminal report. Arabic, Farsi and Hebrew
  are laid out right to left, on Linux too.
- English stays the record: a report saved in another language also contains the English
  original, and the JSON report and sharing summary are always English. Indicator values,
  paths, commands and numbers are never translated. Anything without a translation is shown
  in English rather than left out.

Programs and a window
- Double-click programs for Windows, macOS (Apple silicon and Intel) and Linux: no Python
  install, no commands. Built by GitHub Actions from the release tag, checked against the
  single-file build, with a public build attestation for every file.
- A simple window: choose a check, start it, read the result, save the report or a sharing
  summary. It runs exactly the same check as the terminal version. A packaged program opens
  the window when double-clicked; `--gui` opens it anywhere and `--no-gui` keeps the terminal.
- Live connections: which programs are connected to which addresses right now, with any
  address on the spyware lists marked. Read from the system; nothing is looked up or contacted.
- Check a phone from the window: an iPhone backup (with a button that finds local backups and
  a password box for encrypted ones), an Android collection, a sysdiagnose archive or an
  extracted file system, with the step-by-step guides and the guided Android collection one
  click away. Results open in their own tab.
- macOS download is a standard .dmg with a Mac app that opens the window when double-clicked.
- The window shows progress as it goes ("Step 2 of 6: Program files - 41,000 of 110,000 files")
  with the time so far, has a Stop button that keeps everything already checked (like Ctrl+C in
  the terminal), offers Quick, Standard and Full checks with rough times, and ends with a short
  "What should I do now?" list drawn from the result. An advertising-network trace on its own is
  shown as what it usually is, the mark of an ordinary ad, not as spyware.
- Paragraphs in the window wrap to the width it has and again when it is resized, so no step is
  cut off in a small window and right-to-left text wraps evenly. Switching the language keeps
  the open tab, the window size, the chosen check, phone folder and practice example. On Linux,
  English words and numbers inside Arabic, Farsi or Hebrew text read the right way round, and
  those languages' names read correctly in the language list.

Practice mode
- Training mode for trainers and workshops: `--training spyware | worth-a-look | clean |
  cellebrite` (also "Practise" in the window and the start menu) checks a made-up phone against
  made-up indicators so people can learn to read a report. Four examples: spyware found, things
  worth a look, nothing found, and a phone unlocked with Cellebrite ("Phone seized
  (Cellebrite)"). Nothing real is read, every output is marked as a training example, and no
  sharing summary or evidence bundle can be made from it. Contributed by @compsudev.

Phone-forensics tools and more spyware families
- Android: signs the phone was unlocked with Cellebrite, the phone-forensics tool police and
  security services use on seized phones. Its unlocking hardware imitates particular USB
  devices (a mouse, a webcam, sound cards, a touch pad), all reporting the version 12.34; the
  phone's own logs record them (Amnesty International Security Lab, 2025). A real device with
  the same ids is never reported.
- iPhone: Cellebrite traces published by the Citizen Lab (2026) in crash reports and diagnostic
  logs (a process named `mnm` working on `com.cellebrite.bruteforce`), and the identifiers of a
  Cellebrite computer in the phone's records of trusted computers in a file-system extraction.
- These are reported in their own category with their own advice: not spyware, but the phone
  was unlocked while out of its owner's hands, so its contents were most likely copied.
- Android: the system properties and folder of Variston's Heliconia framework, and five
  related web addresses (Google Threat Analysis Group, 2023).

Faster checks
- Each folder's safety check now runs once per folder instead of once per file and folder
  level. On a busy Windows PC the program-file check went from 280 to 167 seconds and the app
  and startup check from 65 to 41, with identical results; links, junctions and cloud-only files
  are still refused exactly as before.

Indicators and checks
- The indicator update (`--update`, the start menu and the window's update button) now also
  asks GitHub once for the latest release number and prints "Version X.Y.Z is available" with
  the release link if yours is older. It happens only during an explicit update, never during a
  scan; any failure is silent and never changes the update's result; `--no-version-check`
  turns it off.
- A result made only of advertising-network traces keeps its calm explanation, but the
  window and the report now give protective steps instead of "nothing to do": an ad blocker
  such as uBlock Origin, or a DNS resolver that blocks ads and known spyware domains, and a
  link to the project's own blocklists (adblock, hosts and dnsmasq formats). Detection and exit
  codes are unchanged.
- The packaged program can update the indicator lists on Linux systems whose certificate
  folder differs from Debian's (Fedora, Arch and others) and in the macOS app: if no trusted
  certificates are found, the system's own certificate file is used. Certificate checking is
  never turned off. The macOS app's advice now says to give Full Disk Access to "Zero Breach
  Toolkit" (Terminal when run as a script) and no longer mentions Install Certificates.command.
- If the window cannot be built for any reason, the program continues in the terminal.
- 150 more indicators for Candiru DevilsTongue and Intellexa Predator from Microsoft, ESET,
  Google, Cisco Talos, Amnesty International and Recorded Future, each checked against its
  source. Old IP addresses are in the tiers that treat them as possibly reassigned.
- 909 more indicators of spyware used against journalists, activists, human-rights defenders
  and minorities, in a new built-in set (`iocs/curated_targeted.txt`): 893 file fingerprints
  and 16 Android package names, each copied from the researchers' own indicator files and
  cited. Arid Viper against Palestinians: 30 fingerprints and 5 package names (ESET, Cisco
  Talos, SentinelLabs). The Palestinian Preventive Security Service's spyware: 14 (Meta).
  EvilBamboo against Tibetan, Uyghur and Taiwanese people: 212 (Volexity). HenBox against
  Uyghurs: 215 and 8 package names (Unit 42). LIGHTSPY and DEEPDATA: 57 (Volexity). A Chrome
  exploit chain sent to NGOs in 2026: 19 (Volexity). BoneSpy and PlainGnome: 36 (Lookout).
  DoNot spyware against activists in Togo: 228; OceanLotus against Vietnamese human-rights
  defenders: 14; NetWire against Indian human-rights defenders: 12 (Amnesty International).
  ESET: GhostChat 2, Kamran 1 and its package name, VajraSpy 13, eXotic Visit 20, GravityRAT 3
  and 2 package names, DazzleSpy 3, ScarCruft 14. No web addresses or IP addresses from these
  reports are included (old ones may now belong to someone else), and package names another
  app could share are left out.
- New Windows check: the file locations and hijacked COM classes published for DevilsTongue,
  reported as leads to check (never findings on their own).
- Program files up to 512 MB are now fingerprinted (was 120 MB); the report notes that known
  spyware files are far smaller.
- iPhone: installed configuration profiles that manage the phone (MDM), trust a root
  certificate, route traffic through a VPN, proxy or DNS server, or cannot be removed are listed
  as worth a look, with name, issuer and install date.
- Out-of-date programs (Windows and macOS): common programs are compared with CISA's Known
  Exploited Vulnerabilities list and the fixed versions in the official CVE records. A program is
  called out of date only when it is older than a published fix; otherwise update advice only.
  The lists are fetched by the indicator update; the comparison is offline.
- Tests can no longer reach the internet by accident.

Fewer false alarms
- Android: an app's manifest declarations in `dumpsys package` (`queriesPackages`,
  `queriesProviders`, `queriesIntents` and the `uses...Libraries` lines) no longer make the
  phone's system records "name" a monitoring app. They list what an app wants to see, not what
  is installed: Microsoft Office apps list `com.microsoft.familysafety`, so a phone that never
  had that app was reported. A real `Package [...]` record is still reported, and addresses on
  those lines are still checked. Reported and fixed by @BEKO2210.
- The Citizen Lab list `201707_InsiderInfo` is labelled as its publisher describes it, an
  intrusion campaign against Chinese-language news sites (2017), no longer as NSO Group's
  Pegasus in Mexico, so a match from it is not reported as Pegasus. Lists already downloaded
  take the corrected label without updating.

Also in this release
- Everything in 0.1.12 to 0.1.15 below: full backups of current iPhones, clearer help for
  certificate and cryptography problems, folders counted apart from files in the program-file
  gap, and ad-blocker filter lists no longer reported.
- The out-of-date program message is translated in every language; Tamil and Hebrew command
  options and links are no longer altered by the translation.

## 0.1.15 (2026-10-31)

- Browsers: an ad-blocker's own copy of a filter list is no longer reported. Lists such as
  uBlock Origin's, AdGuard's, EasyList and this project's blocklists contain the advertising
  domains used to deliver spyware, in order to block them, and the browser keeps a copy in its
  cache. Those matches are now counted and explained in a note instead of appearing as
  findings. A list is recognised by the address it was downloaded from or by the extension
  that stores it (Chrome, Edge, Brave and other Chromium browsers on Windows, macOS and Linux,
  and Firefox); ordinary cached pages that mention an indicator are still reported.

## 0.1.14 (2026-10-31)

- Windows: when a download fails because certificates cannot be checked, the message now gives
  the Windows fix (let Windows fetch the missing certificate with one PowerShell command, or pause
  an antivirus's HTTPS scanning). It used to suggest a Linux package, and the Android collector
  showed only the raw error.
- Android collection: if the collector could not be downloaded, the tool now says nothing was
  collected from the phone and removes the empty folder, instead of warning that private
  records may remain.
- Android collection on Windows: the note that AndroidQF is not code-signed now says plainly
  that it is a notice, not an error.

## 0.1.13 (2026-10-29)

- iPhone: when an encrypted backup cannot be read because `cryptography` is missing, the
  message names the Python running the check and gives the command that installs it there.
  The usual cause is that it was installed for a different Python on the same computer.
- The program-file check counts folders it could not open separately from files it could not
  read, so a gap no longer says impossible things like "3 of 1 candidate file(s)", and the
  summary names them as folders (contributed in #19).
- Help: a simpler fix for "No such file or directory" on a Mac (drag the script into
  Terminal, from any folder), the install command for encrypted backups now says `python3` on
  a Mac, and the `third_party/candiru` folder is explained: it holds the published detection
  rules, not spyware.

## 0.1.12 (2026-10-29)

- iPhone: a full backup of a current phone is checked again. A 512 GB phone with a large photo
  library has a `Manifest.db` over 300 MB and an `Info.plist` over 16 MiB, which were over the
  check's limits, so the report said "exceeds the read limit" and nothing on the phone was
  checked. The limits are now sized for current phones (1 GiB per file, 1,000,000 manifest
  rows, 8 GiB in total, 64 MiB property lists, more time and text for long message
  histories) and still bound what a crafted backup can make the check load.
- When a file is over a limit, the report names it with its size, for example
  "Manifest.db is 1.2 GB, over the 1.0 GB limit for one file".

## 0.1.11 (2026-10-29)

- Saving a report, summary or evidence bundle to a folder now saves inside that folder under
  a dated name (for example `zero-breach-report-20261029-071600.txt`). Before, typing a
  folder asked to replace it and then failed with "Access is denied" (WinError 5 / Errno 13).
- If Windows will not let the toolkit write to the chosen place (such as the top of the C:
  drive without administrator rights), the message says so and suggests Documents or the
  Desktop.

## 0.1.10 (2026-10-29)

Fewer false "could not run" lines, from a real Windows report:
- An app's own `history.db` that is not a database (FreeTube keeps one, and Windows ignores
  the case of names) is no longer read as Safari history and reported as a gap. For Safari
  itself, or a folder you chose to check, an unreadable one is still a gap.
- A problem finding Amcache is no longer also reported under Prefetch, and when Windows
  refuses access the line says these records need the check to run as administrator.
- A missing Microsoft Defender log is explained plainly (usual when another antivirus is in
  charge) instead of showing PowerShell's error text.

## 0.1.9 (2026-10-28)

Browsers
- "The browser was running" is now said only for a real lock (SQLite busy or locked, or a
  Windows sharing violation). Other refusals say permission was denied and what to do; on
  a Mac they point to Full Disk Access without claiming the browser is installed. Firefox
  and Chromium are named correctly on a Mac.
- The empty LevelDB `LOCK` file a running Chromium browser holds is no longer reported as
  a coverage gap. A `LOCK` file with content is still read.
- Safari: the standard sandbox link to `~/Library/Cookies` is no longer a coverage gap; that
  store is read directly and the link is still never followed.
- A desktop browser's write-ahead log is checked against the desktop snapshot limit, not the
  smaller phone-extraction limit, so a valid log is no longer called damaged.

- Browser icon stores are read row by row with a cap, and without a join, so a small
  crafted icon database can no longer use up memory and stop the browser check. A store
  past the cap is reported as not fully checked.

Reports
- Ad-network matches mention that apps showing ads, such as the new Outlook for Windows,
  can record them too.
- A check that stops on an error with no message now names the error instead of leaving
  the reason blank.

Indicator lists
- A downloaded list is used only if its content matches the copy pinned for this release,
  whatever its saved record says. Lists fetched with `--update --latest` are used only
  when the scan is also run with `--latest`. After moving to a new release, update the
  lists once (menu option 8, or `--update`).

Releases
- The release check on GitHub now also downloads the published single file and requires
  it to match the rebuild, and checks both signatures against the pinned release key.

## 0.1.8 (2026-10-28)

- Updating the indicator lists on a Mac no longer fails with 29 cryptic certificate errors
  when Python's certificates are not installed. The update stops at the first one, keeps
  the previous lists and says how to fix it (double-click Install Certificates.command in
  the Python folder). The Mac setup steps in the README now include this.
- If the final menu cannot read any input, the toolkit now says nothing was saved instead
  of closing silently.

## 0.1.7 (2026-10-28)

Android
- Windows: the guided Android collection works again. AndroidQF unpacks its own adb into
  the collection folder and then could not find it ("Impossible to find ADB"); that folder
  is now on its search path. Afterwards the adb server is stopped and the unpacked adb files
  are removed. On macOS and Linux, an encrypted collection now reaches the collector (the
  recipient file was placed where AndroidQF does not look).
- Pixel phones no longer show eight false monitoring-app matches. A Google feature flag
  lists hundreds of apps the notification features skip, family-safety apps among them;
  server-pushed feature flags (`dumpsys device_config` and the CONFIG table of `dumpsys
  settings`) are no longer searched for app names. Contributed by Luke Hutchison.
- iPhone app ids from the monitoring-app list are no longer matched on Android. The
  publisher's export writes both kinds the same way; the ids it lists only as iPhone
  bundles are now recorded with each release and skipped by the Android checks.

Reports
- A monitoring app that does not hide itself (often a family-safety app, which the
  publisher calls "watchware") is described as such, with the same safety advice.


Detection
- Hosts hidden by URL escapes are found: percent-encoded (also double-encoded) and
  JavaScript-escaped addresses such as `u=https%3A%2F%2Fexample.com` or
  `https:\/\/example.com`, common in ad-click links and browser storage.
- IPv6 indicators match however the address is written (compressed, expanded, leading
  zeros, upper case).
- Linux: the program a systemd unit or crontab line runs is read like a desktop entry's
  `Exec=`, so a published implant path there is graded "configured" (activation
  unverified) instead of a mere reference.
- OneDrive files kept on this device, and OneDrive folders, are now checked; they were
  skipped as links. Files that would need downloading are still listed as not checked.
- Names that may have changed owner since their report are a lead, not a serious finding:
  shared cloud-platform hostnames, and 21 historical domains that registry records show
  were registered again after publication (registry lookups only). They are also left
  out of the blocklists.

Robustness
- Crafted evidence can no longer stall a scan: domain matching is linear on long dotted
  tokens, iPhone diagnostic report lines are parsed without backtracking and stop at the
  time limit, and the file-fingerprint check cannot block on a FIFO swapped in for a file.

Privacy
- Temporary copies left by a scan that was killed or crashed are removed at the next
  start (only the tool's own folders, older than 12 hours); the report says if any could
  not be removed.
- The scanner says so when a report is about to be saved in a folder that OneDrive or
  iCloud uploads.

Indicator updates
- `--update` downloads each source at the commit pinned for this release and requires
  the SHA-256 the release records for it. `--update --latest` follows the upstream branch.
  The report records which revision each source came from.
- The shrink guard compares with the highest count a source has had, so repeated smaller
  drops cannot empty it.

Release process
- `tools/make_release.py` refuses a dirty working tree, a commit not on origin/main, or a
  version tag on another commit. CI checks the generated files are current, and a new
  workflow rebuilds each published release from its tag and compares the checksum.

## 0.1.5 (2026-10-28)

Fewer stalls and false alarms
- Files kept only in iCloud (macOS "Optimise Mac Storage") or OneDrive (online-only) are
  no longer downloaded during the file-fingerprint check, which could stall a scan for
  hours; they are listed as not checked.
- 52.174.65.77, a reassignable Azure address, moves to the weaker IP tier like the other
  cloud IPs, so an undated hit on it alone is no longer reported as a serious finding.
- zsh history containing non-English commands is searched instead of skipped as a whole.
- Long lines in iPhone diagnostic reports are capped like crash logs.

Windows launcher (run-scan.cmd)
- Report paths are printed in quotes, so a folder name containing "&" can no longer run an
  extra command, and a "!" in the folder name no longer breaks the launch (it could be
  reported as a match without any scan). If the scanner cannot be found, it says so.
- Uses a Python that actually runs, so the Microsoft Store "python" stand-in no longer makes
  it fail; falls back to the `py` launcher.

Hardening
- The build refuses indicator text that could end its embedded string early.
- Indicator values are cleaned like every other field in the readable report.

## 0.1.4 (2026-10-28)

Linux
- Translated user folders (for example `~/Téléchargements` or an Arabic desktop folder) are
  found from `user-dirs.dirs` and fingerprinted.
- Snap Brave, Opera and Vivaldi (data in the current revision folder), Firefox 147's
  `~/.config/mozilla/firefox` profiles and Flatpak Firefox's newer layout are checked.

Phones
- iPhone support is no longer labelled experimental: it has been checked against real iOS
  15 to 18 backups, file-system extractions and sysdiagnose archives.
- Guided Android collection: press Enter to save it on the Desktop.

Updates and housekeeping
- `--update --accept-shrink SOURCE_ID` accepts a source whose list genuinely shrank by more
  than half; without it such an update is still refused.
- The AndroidQF download uses the same generic user agent as indicator updates.
- No deprecation warnings on Python 3.12 and later; invisible characters in the source are
  written as visible `\u` escapes.
- README: a simpler step-by-step guide for each device, with a troubleshooting table.

## 0.1.3 (2026-10-27)

- A report never replaces an existing file in a folder the hash check reads, including a
  file that looks like an earlier report (0.1.2 trusted such files, and their content
  could be forged). Choose a new filename instead.
- Invisible formatting characters (zero-width spaces and joiners, direction marks) are
  removed from the readable report and from text handed to an assistant, so scanned text
  cannot hide anything; the JSON report keeps the raw evidence.
- iPhone: one unreadable security analytics record no longer stops the rest of that file.

## 0.1.2 (2026-10-27)

iPhone
- Accounts looked up by iMessage and FaceTime (`idstatuscache.plist`) are checked against
  published operator email addresses.
- Safari's and Chromium browsers' favicon stores are checked.
- Sites that stored data in an app's web view (LocalStorage, IndexedDB and the iOS 16+
  `origin` files) are checked.
- File-system extractions: security-framework analytics records (calling processes and
  hosts) are checked.

Computers
- macOS: folders blocked by macOS privacy protection (Safari's records and others) are
  reported as such, with the Full Disk Access fix, instead of "close the browser". The
  README now says to grant Terminal Full Disk Access first.
- File fingerprint gaps say why: permission denied, over 120 MB, or unreadable. Links,
  such as app framework aliases, are no longer counted as missed files.
- Opera's own bookmark folders (speed dial, trash, unsorted) are read.
- Safari download records in an unexpected layout keep their addresses as references and
  are reported as not fully checked.
- Windows: download-origin records that cannot be read, and folders below the depth
  limit, are reported as not checked.
- A report can no longer replace an existing file in a folder the hash check reads (an
  earlier report of this tool still can be).

Android
- Files without a valid fingerprint are reported as `android:file-hashes`, so a
  collection made without AndroidQF's "hash files" option is no longer complete by path
  alone.

Updates and reports
- `--update` shows each source's SHA-256 and the total number of indicators; an
  interrupted update leaves every finished source usable.
- Reports name the tool `zero-breach-toolkit`; a long browser phase prints a progress
  line; suppressed phone-monitoring mentions are named in the note.

## 0.1.1 (2026-10-27)

The project is now called Zero Breach Toolkit: the repository is `Zero-Breach-Toolkit` and
the single file is `zero-breach-toolkit.py`. Old links redirect.

iPhone
- Encrypted backups from real devices are read correctly. Files whose recorded size
  differs from the copied data (live databases) and iCloud-only files no longer fail.
- Supports the table layouts used by iOS 15 to 18 for WebKit statistics, Calendar,
  Shortcuts and Calls; Safari tabs and iCloud tabs; the iOS 18 network-usage database.
- Installed configuration profiles and profile install history; calendar participants;
  privacy-permission clients compared as process names; connection records of
  Chromium-based iPhone browsers and Brave's site list.
- Sysdiagnose: memory-pressure, stackshot and text reports, running processes and
  installation logs (apps installed as developer builds are listed as worth a look).
- Fewer false gaps on real phones, and every record limit that is reached is reported.

Computers
- More browsers on Windows, macOS and Linux: Chrome, Edge and Brave beta/dev/canary
  channels, Opera, Opera GX, Arc, Yandex, LibreWolf, Waterfox, Floorp, Zen, Pale Moon and
  Tor Browser.
- macOS: Safari cookies, HSTS, tabs, iCloud tabs, cache, bookmarks, downloads, Top Sites
  and closed tabs; Terminal session history; desktop apps such as Signal; launch items
  matched by process name. The hosts file is checked on macOS and Linux.
- Desktop-app discovery has no fixed depth limit.
- Reports never replace existing files in app data or app cache folders.

Android
- Process lists from older AndroidQF versions, MMS text, and only received messages
  graded "received". Certificate coverage counts SHA-256 and SHA-1 separately.

Safety and reliability
- `--update` refuses a list whose indicator count suddenly falls by more than half (or to
  zero) and keeps the previous copy, so a broken or tampered source cannot quietly make
  scans look clean. Update requests use a generic user agent.
- PowerShell loads modules only from Windows' own folder.
- On Windows, one check that fails no longer stops the others; it is listed as not checked.
- A DNS-log lookup answered only with a block address is graded as a blocked attempt.
- Repeated Safari downloads of the same address are graded per download. Reports cannot
  overwrite Safari's sandbox or cookie files. Malformed iPhone connection data is a gap for
  that file only.
- Paths in colon- or comma-separated lists are matched on macOS and Linux; Chromium
  profiles with custom folder names are found.

Reports and guides
- The summary counts each indicator once, with the number of places it was recorded.
- Step-by-step phone guides (`--phone-guide android|ios`), including how to answer
  AndroidQF's questions, and clearer install steps in the README.

## 0.1.0 (2026-10-27)

First version of Zero Breach Toolkit, built on Zero Breach.

- Indicators from 25 published sources (Amnesty International Security Lab, the MVT
  project, the Citizen Lab, Echap) via `--update`, plus a hand-curated, cited set for
  Candiru / DevilsTongue and Paragon's Graphite that works offline. STIX 2, MISP CSV and
  list formats; downloads verified and refused if changed afterwards.
- Windows checks without administrator rights: browsers and desktop apps with a built-in
  browser (found automatically), Mark of the Web on downloads, Win+R history, Microsoft
  Defender's history, the PowerShell log, programs Windows recorded as having run
  (fingerprinted wherever they are), file fingerprints, DNS cache and history, hosts file,
  per-user auto-start registrations.
- Windows execution and inventory evidence: Prefetch files, Amcache records, and auto-start
  shortcuts read for the program they point at without opening or resolving the target.
  Amcache entries are reported as inventory, never as proof that something ran or is still
  present.
- Linux and macOS: auto-start desktop entries, service units and readable cron files;
  LaunchAgent and LaunchDaemon settings. Literal program paths can be evidence; command
  arguments and unverified commands remain references.
- Android: `--phone FOLDER` reads an AndroidQF collection: installed and running apps,
  fingerprints, signing certificates, install/uninstall history, system services' state,
  logs, crash records and SMS links (new grade "received"); sideloaded apps listed with
  what they can do and when they were installed; signs of a modified phone. The
  collection's own footprint is recognised. Decrypted intrusion logs are read where the
  format is supported: DNS lookups, connection attempts and app starts.
- Android guided acquisition, experimental and separate from scanning: `--collect-android`
  downloads the official AndroidQF release pinned to its SHA-256, refuses it if the digest
  does not match, asks the device owner for consent at the terminal, then checks the
  collection it produced. Installing AndroidQF yourself remains fully supported.
- iPhone, experimental: `--phone FOLDER` reads a local Finder, Apple Devices or iTunes
  backup: SMS and Safari records, data-usage processes and applications, optional Chrome
  and historical Firefox history. Encrypted backups are supported with `--backup-password`.
  Synced and imported records are distinguished from local visits.
- Report: graded evidence, a "worth a look" section that never changes the result, a
  timeline, grouped gaps, exit code 3 for "nothing found but checks were missing".
- Saved reports and follow-up: `--report` writes the readable report to a file, and a menu
  after the scan explains what was found, saves reports and minimal summaries, and can
  export a private evidence bundle: a new ZIP holding the reports, the originals you
  explicitly choose, the scope and times, and a SHA-256 for every file in it. The manifest
  does not claim the originals are authentic. Output guards refuse to overwrite anything
  the scan read. Piped input never prompts, and `--no-menu` turns the menus off.
- Start menu for people who open the tool without arguments, shown only at a terminal.
- Machine contract for scripts and AI assistants: `--describe`, JSON fields to relay,
  untrusted-text marking. Report schema 1.4 adds reader descriptions, the host platform,
  execution and inventory records, and states explicitly when an optional input was absent
  and why. None of that can hide a finding, an error or a gap. Schema 1.5 adds the
  `WITHDRAWN_ONLY` verdicts and `withdrawn_total`.
- Withdrawn indicators are not findings: when every publisher that lists a matched
  indicator has withdrawn it, the result is `WITHDRAWN_ONLY` (exit 0, or 3 with gaps) and the
  person is not told to preserve the device. Each publisher's newest version decides, and
  one current active listing anywhere keeps a match actionable.
- Hand-written indicator lists refuse loopback, private, link-local, multicast and reserved
  addresses, so a list cannot match ordinary local traffic. The RFC 5737 and RFC 3849
  documentation ranges stay allowed, because they never occur on a real network and test
  lists rely on them; published feeds still refuse those as well.
- Domain names containing `ß` or a final sigma are refused rather than stored in the form
  older IDNA produces, which is not what browsers record and can name a different domain.
- A hosts-file or DNS-cache entry that points an indicator at any loopback or unspecified
  address, such as `127.0.0.2` or `::ffff:127.0.0.1`, is recognised as a block. Only
  `127.0.0.1` and a few fixed spellings were before, so other blocks were reported as findings.
- A Chromium history row with no recorded visit is a reference, not contact.
- Withdrawals are decided per STIX object. One publisher revoking one indicator object no
  longer withdraws a different, still active object it publishes for the same value, which
  could turn a real contact match into `WITHDRAWN_ONLY` with exit 0.
- A stalkerware match in decrypted Android intrusion logs stays a phone finding. The
  computer rule that turns stalkerware company sites into "worth a look" had treated it as
  a web visit; phone readers are now taken from the reader registry, not a hand-kept list.
- A Chromium visit synced from another device is no longer called contact by this
  computer. It is kept as a reference with a "worth a look" note to check that device.
- A browser database that reads through a view or a recursive query, which no browser
  writes, is refused as a gap, and each database read has a time limit. A 4 KiB crafted
  History file could previously keep the scan running indefinitely.
- New `--scan-type browser`: reads only this account's browser profiles and desktop apps
  with a built-in browser. The report says so, and adds a `browser-only` line that must be
  passed on. The start menu has a matching "browsers only" entry, which also offers a test
  of whether your browser blocks ads. The test page opens in your browser only after you
  say yes; the tool itself still makes no request.
- One file with a malformed Mark of the Web address no longer stops the rest of the Windows
  trace checks, and one ambiguous iPhone record no longer stops the backup reader. A changed
  Defender exclusion is reported, not only a newly added one.
- Built-in readers share one registry for platform selection, coverage descriptions and the
  single-file build; no outside plugins are loaded.
- Fast: one-pass matching of domains and addresses, parallel file fingerprinting.
- Welcome banner for people at a terminal (`--no-banner` to hide it).
- Verifiable instead of signed: `python build/bundle.py` rebuilds the single-file scanner
  from this source, and every rebuild produces a byte-identical file. There is no signed
  Windows program; see
  [docs/VERIFYING.md](docs/VERIFYING.md).
