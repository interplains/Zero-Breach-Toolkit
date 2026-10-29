# Changelog

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
