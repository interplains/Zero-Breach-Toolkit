# Changelog

## 3.0.1

- The result card now says what was found - how many, and which addresses, apps or files (addresses written so
  they cannot be clicked) - before you open the report. On a small screen the summary underneath could be out
  of sight.
- "Show full report" opens the report in its own window, prepared in the background. On a small screen it
  changed a box that was out of sight, and on a large result the window froze while it was written.
- The plain-words advice after an advertising-network trace no longer assumes an ad blocker is already
  installed, and the related-records note is indented and wrapped like the rest of the report.

## 3.0.0

**Doors to close.** Besides looking for spyware that is already there, every check now lists the ways in that
are left open, each with why it matters and how to close it. They never change the verdict.
- Computer: remote-access and monitoring programs (a list of 70+ kept with this project; viewers are not
  counted), and on Windows Remote Desktop, automatic sign-in (and whether a password is stored for it - never
  read), password on wake, firewall, BitLocker/device encryption, Secure Boot, SMB1 and administrator
  accounts; on macOS FileVault, firewall, System Integrity Protection, Gatekeeper, Remote Login, Screen
  Sharing and automatic login; on Linux root disk encryption, an SSH server and automatic login.
- Browsers: extensions that can read every site, and 9,014 extensions confirmed malicious (chrome-mal-ids,
  CC BY 4.0). The account each browser is signed in to is shown masked (t***@gmail.com): is it yours?
- iPhone: no passcode, Lockdown Mode. Android: security update age, encryption, Play Protect, wireless and USB
  debugging (these moved from "worth a look" to doors).
- A list of accounts to check yourself (Apple Safety Check, Google Security Checkup, linked devices in
  messaging apps, mail forwarding, recovery details, two-step sign-in, a SIM port-out lock).
- In the window: a "Doors to close" button with "Open this setting" and "Check again".

**Home network check** (`--home-network`, asks first, looks only):
- Asks cameras on your own network whether their video can be watched without a password (no password is
  ever sent; only the stream's description is requested). `--no-camera-check` turns this off.
- Names each device's maker from the IEEE's public list (downloaded with `--update`, never shipped) and says
  when that maker has actively exploited flaws on the CISA list: keep its firmware up to date.
- Finds the home router even with a VPN on; never mistakes a VPN tunnel for the home network.
- Ports that this computer's own firewall blocks are reported as not checked, not as closed.
- A Wi-Fi extender is recognised and explained instead of looking like an impostor.
- A Pi-hole or a DNS filter that blocks a lookup is no longer reported as the router changing answers.

**Also new**
- **Check a link or message** (`--check-link`, `--check-message`, the start menu and "More checks"): paste a text,
  WhatsApp or Signal message or email; every link is judged offline against the spyware indicators and documented
  lure patterns (Signal device-linking links, WhatsApp QR and pairing-code lures, Predator-style login texts,
  Pegasus-style links, look-alike names, shorteners, app and profile downloads). Nothing is opened.
- **Was my phone plugged into a forensics tool?** (`--was-extracted`, start menu, "More checks"): reads an
  AndroidQF collection or an iPhone backup for authorised USB computers, USB debugging, unlocked bootloader or
  debug build, side-loaded apps with the accessibility permission, and Cellebrite's imitated USB hardware
  (Amnesty International) and iOS traces (Citizen Lab). Every report states that an extraction can leave no
  trace, so finding nothing is not proof; each sign says what it does and does not prove, and being copied is
  distinguished from being infected.
- **Check a suspicious email** (`--check-email`, start menu, "More checks"): the real sender against the one
  shown, SPF/DKIM/DMARC as the receiving server decided, Reply-To that leaves the conversation, display names
  imitating a company, look-alike letters, every link through the link check, and attachments - programs,
  double extensions, right-to-left name tricks, macro formats, archives - plus what kind of pressure the
  message applies. Nothing is opened. Tuned so newsletters, mailing lists and forwarded mail are not called
  forgeries.
- **Check a QR code** (`--check-qr`, start menu, "More checks"): a QR reader written into the toolkit - PNG,
  GIF (interlaced too), BMP and PPM, with no other software needed - that handles turned, mirrored, tiny and
  damaged codes, repairs damage up to the standard's limit and refuses to guess beyond it; then checks what the
  code says like a pasted link, so Signal/WhatsApp device-linking lures are named. Checked against codes made
  by an independent library at every size and error-correction level.
- **Hash look-up** (`--hash-lookup`, start menu "Check something you received", "More checks"): SHA-256 / SHA-1
  / MD5, file kind from content, imphash identical to pefile's (703 of 706 programs checked; the rest hit pefile's
  own limits), Authenticode signer name, offline indicator match; optional online look-up of unsigned files'
  fingerprints at CIRCL, MalwareBazaar, ThreatFox, VirusTotal and Hybrid Analysis with the person's own keys,
  consent first, answers cached.
- **Close the doors found open** (`--fix-it`, `--undo-fix`, start menu "Look closer", "More checks"):
  Remote Desktop off, automatic sign-in off, firewall on, SMB1 removed - each one asked for by name, with an
  undo record written and checked before anything runs, the result verified afterwards, and one visible
  permission prompt per command. Disk encryption, Secure Boot and account removal are explained, never
  automated; managed computers are left alone; no password is ever handled.
- **Look through Windows' own records** (`--hunt-windows`, start menu "Look closer", "More checks"): 30 rules
  written for this toolkit over PowerShell, Task Scheduler, WMI, Defender, System, CodeIntegrity, BITS, Remote
  Desktop, Security and Sysmon; hidden (base64) commands are decoded so what they did is matched and shown;
  findings are grouped with counts and each says what it means and what is normal; routine noise is held back as
  context. Calibrated against a working computer so ordinary records are not called an attack.
- **A reader for Windows log files (.evtx) in plain Python**, so a helper can read someone's records on Linux or
  a Mac: checked record for record against Windows' own wevtutil output - 21,712 records over four logs, 0
  missing, 0 extra, every event number, timestamp and field identical.
- **Send evidence to a helper** (`--package-for-helper`, start menu "Put it together", "More checks"): one
  package encrypted with age for the helper's key (AndroidQF collections kept as they are, plaintext never on
  disk), with an Ed25519-signed list of every file's SHA-256 and a safety number to read aloud;
  `--verify-package` for the helper. Encryption and signing written from the RFCs and checked against their test
  vectors and an independent implementation; no decryption code.
- **What starts automatically** (`--startup`, start menu "Look closer", "More checks"): every program set to
  start with the computer, with Task Manager's on/off state and an offline signature check; flags unsigned
  programs in user folders, hidden PowerShell, downloaders, remote-access tools, hijacks, missing targets and
  tasks whose unquoted path can never run. macOS launch items, background items and app permissions (TCC).
- **Start menu:** "Help and settings" items were listed under "Around you"; sections now match the window.
- **Check a network recording** (`--check-traffic`, start menu, "More checks"): reads a PCAPdroid / Wireshark
  recording and lists every server contacted and, for PCAPdroid, which app contacted it; indicator matches,
  clockwork contact, dynamic-DNS names, TLS on unusual ports. Offline; nothing is decrypted.
- **Android app audit:** every user-installed app is checked for the powers stalkerware needs, not only apps
  installed by hand; apps for which Android's "restricted settings" protection was switched off, device-owner apps
  and always-on VPN apps are named; Honor's store and phone-transfer installs no longer count as installed by hand
  (issue #43); apps listed by Cornell's ISDi research (MIT) as stalkerware or as often turned on a partner are named;
  advice says that removing stalkerware may alert whoever installed it.
- The start menu now lists every separate check in sections ("Check something you received", "Around you"),
  matching "More checks" in the window; results there open with a coloured verdict bar.
- Window: "More checks..." (home network, Bluetooth trackers, household report, DNS log) and "Restart as
  administrator for the full check" when Windows records need it.
- Bluetooth trackers: the same tracker heard in 3 or more separate checks over a day is marked IMPORTANT
  (the last day's tracker addresses are kept on this computer only).
- iPhone diagnostics: a process outside Apple's system folders that was still running at 3 or more restarts
  is worth a look (the iShutdown method, Kaspersky, MIT licence).
- After a confirmed phone finding, the next steps say to replace the phone rather than restore it, and to
  get a new SIM.
- Root certificates added by antivirus, VPN, game and developer programs are grouped into one calm item
  that names each, instead of one warning per certificate.
- `--make-iphone-backup` (Linux) and "Make an iPhone backup..." in the window; `--combine` / household report
  puts every device's saved report on one page.
- Linux: saved Wi-Fi names containing ':' are matched correctly.

**Check a suspicious file** (`--check-file`, drop a file onto the program, "More checks"): what a file really
is from its contents (a program named invoice.pdf, a shortcut that runs a hidden command, a password-locked ZIP
antivirus cannot open, a disk image hiding a program, HTML smuggling, OneNote and Office tricks, PDF JavaScript
including inside compressed streams), its signature, packing, Android app permissions in plain words, and any
spyware server written inside it. Never run, opened, moved or changed. "Save a sealed copy" makes the standard
ZIP with the password `infected` to send to an expert. Built to avoid false alarms on ordinary files:
a program file with an unusual extension (.pyd, .ax, .node) is not a "disguise", text that merely mentions curl
is not a script, random letters in binary data are not a command, and a blocklist or research report full of
spyware addresses is recognised as a list, not as spyware. A monitoring company's or advertiser's address in an
ordinary file is shown as a mention, not a finding (Microsoft Family Safety is on the stalkerware list).
Whatever it could not read in full - a file over 32 MB, a RAR or 7-Zip it cannot list, a document part too
large - is reported as incomplete, never as "nothing known was found".

**Also new for this release**
- **Live connections:** a "Who runs it" column (Google, Microsoft 365, Cloudflare, Meta, Apple, Amazon, Akamai -
  from the companies' own published address lists, built in - or your network / this computer), and
  right-click or double-click for details in plain words: the program's full path, signature, when it
  started and what started it, why a hidden one has no name, what the port and state mean. "Look up who owns
  this address" asks the internet registry (RDAP) only after saying exactly what is sent.
- **Terminal:** choose from the menu with the arrow keys and Enter (or type the number, as before); one
  progress line that updates in place; the result line in colour (red, amber or green) and headings in bold -
  only on a real terminal, never in saved reports, and off with NO_COLOR. Reports wrap at word boundaries
  instead of breaking words at the window edge. More checks is a tab in the window. The Python version offers
  to install the Bluetooth library when the tracker check needs it (one yes; pinned, ready-made packages only).
  The home network check names device makers from the built-in list, no update needed.
- **Every tool speaks your language:** the results of the smaller tools (file, link, email and QR checks,
  startup items, home network, Windows' records, the doors tool, trackers, the helper package and the rest)
  are now translated into all 27 languages, not just their buttons. Saved results stay in English, the
  record a helpline works from.
- **Fixes from team testing:** a "worth a look" result no longer looks like a clean one (its own amber
  headline). Windows' own built-in event-log subscription is no longer reported as an attack. The doors tool
  now lists every door the full check counted, and says that a full check finds more. Cloudflare's and
  Quad9's public DNS and Fastly addresses are named in "Who runs it". The household report says which button
  saves a computer check. The menu no longer hangs when its input is not a real terminal; an option given an
  empty value stops with a clear message instead of starting a full scan; `--check-message` takes the message
  text itself; saving over an existing file says so instead of crashing; a damaged picture is reported as
  damaged instead of crashing the QR check; "Look up who owns this address" no longer names the program in
  its request; the single-file version accepts every option the program does. The progress bar moves smoothly
  through the whole check, paced by how long each step usually takes.
- **Smaller tools, fleshed out:** repeated connections from one program to one address are one row
  ("6 connections"), and Telegram's addresses are named. Network recordings and DNS logs say which companies
  run the names contacted ("run by: Google (12), Meta (4)..."). Hidden Wi-Fi can follow one network's signal
  while you walk (Windows and Linux), to find the device. Startup items get a plain line for each kind of
  entry and the program file's date. A file check can also be looked up online (after a yes). The accounts
  checklist starts with the single best step - a physical security key, and why - opens each service's page,
  and keeps your answers until you finish. Hidden Wi-Fi, live connections and startup items can be saved, and
  the household report includes them (and the other smaller checks' saved results). Every tool that works in
  the background now shows a small "working" window, so nothing seems frozen. Help lists every tool.
- **Easier for people who are not technical:** every result starts with five lines IN PLAIN WORDS - what was
  found, what it means, what to do. A spyware file or app on the device is called that; an advertising network
  the browser loaded something from, or an address it contacted, is said NOT to be an infection, so one ad does
  not cause a panic. "What happened?" (shown once when the window first opens, then from a button, and as `?` in
  the terminal menu) leads to the right check. Each "worth a look" item says what it means in plain words;
  progress reads "Checking your browsers... (step 1 of 3)" with the usual time; one "Send this to someone who can
  help" button; and an iPhone backup started but not checked is offered again next time.
- **Hidden Wi-Fi networks nearby** (`--wifi-nearby`): who made each hidden network, whether it is part of your own
  router, a phone's hotspot, and how close it is. Joins nothing.
- **Two new doors:** no ad blocker in the browsers, and no DNS service that blocks harmful sites.
- **Android bug reports:** the running apps are now compared with the spyware lists.
- **File check:** 7-Zip archives are listed (including password-locked file names, said to be locked); a Windows
  program that claims a famous maker its signature does not back, or is a Windows tool saved under another name,
  is worth a look; who signed a Mac program is shown (developer and Team ID, ad hoc, or not signed).
- **iPhone backups from iOS 27:** installed apps are found from the backup's app folders when the old list is
  missing, diagnostic reports in newer formats are read, and long text fields (such as big Shortcuts) are
  searched whole instead of skipped. Reported by Natha (#47).
- **Remote-access programs:** 200+ recognised (LOLRMM, Apache-2.0), and a copy of AnyDesk-type software
  downloaded but never installed - the step a scam call asks for - is named.
- **Drivers with known holes:** 2,211 vulnerable or malicious driver fingerprints (LOLDrivers, Apache-2.0), plus
  whether Windows' vulnerable driver blocklist and memory integrity are on (with memory integrity running, the
  blocklist is enforced whatever its own setting says).
- **14 mercenary spyware lists built in** (MVT indicators, MIT) so they work offline; known-good lists, downloaded
  with `--update`, keep ordinary files from being matched by mistakes in published indicators.
- **Android without USB debugging:** check the bug report a phone makes itself (Developer options > Take bug
  report). It even shows apps installed and later removed. What a bug report cannot hold is listed as not checked.
- Remote-access programs waiting in Downloads are also found as Linux packages (.deb, .rpm, AppImage) and Mac
  installers (.pkg), in folders named in the desktop's own language, and in OneDrive's Desktop and Documents.
- **Check your online accounts** (`--accounts`, "More checks"): a guided list of twelve places to look - devices
  linked to WhatsApp, Signal, Telegram, Apple, Google and Microsoft accounts, email forwarding, location sharing,
  a lock on your phone number. Skipped steps are reported as not checked, never as fine.
- **If you got a threat warning** (`--threat-warning`, "More checks"): what to do, in the order that keeps the
  evidence.
- Text from outside - an email sender, a device name on the network, a startup entry - can no longer put terminal
  escape codes into any tool's result; in the file check, a name inside an archive can no longer add a fake line.

Every new sentence is translated into all 26 languages.

## 2.0.7

- A single malformed `.plist` no longer costs the whole out-of-date-program check. On a Mac holding one
  loosely-written `Info.plist`, the check stopped with "module error: XML declaration not well-formed" and no
  installed program was examined at all; such a file is now skipped and the rest are checked as usual. Found
  by Natha.
- Honor's App Market (`com.hihonor.appmarket`) is recognised as an app store, so apps installed from it are no
  longer reported as hand-installed. On one Honor phone 56 of the 65 such leads were ordinary store apps,
  burying the ones worth looking at. Honor split from Huawei in 2020, and `com.huawei.appmarket` is not
  present on these phones at all. Contributed by dhruv1220; reported by Verchiel666.
- The instructions for checking a release now say to import the signing key before verifying the checksums,
  and link the full steps. The key has always been published alongside every release, but the verify command
  on its own could never have worked without importing it first. Found by Natha.

## 2.0.6

- With the optional pattern check (`--patterns`), the pattern engine is first tried in a separate process. On
  some Macs yara-x stops Python with no message; the check is now skipped with an explanation and the rest of
  the scan finishes. Found by s3ba-b.
- When macOS refuses Safari's cookie file or a browser's bookmarks, the report gives the Full Disk Access advice
  instead of a raw error. Found by s3ba-b.
- Two tests no longer fail on Apple's Python: its Tk names the scrollbar differently, and one test now sets
  every value the Apple-Python check reads. Found by s3ba-b.
- Sample fingerprints published only as SHA-1 are now used. The file check, the record of programs Windows
  ran, and Android app files and file lists compare SHA-1 as well as SHA-256, from the same read of each
  file; the SHA-1 is only computed when such samples are loaded. Published feeds (STIX and MISP) now
  contribute their SHA-1 sample hashes too.
- New built-in indicators from Lookout: MOONSHINE (58), Hermit (8), BouldSpy (22), KoSpy (11 SHA-256,
  3 SHA-1 and its package name), DCHSpy (9) and Massistant (23), a phone-extraction tool used by Chinese
  police on seized phones.
- Memento Labs' Dante spyware (formerly Hacking Team), from Kaspersky: three sample fingerprints, and on
  Windows a check for the Windows component its loader hijacks and for the module folder layout the report
  describes. Both are reported as leads to check, not findings.

## 2.0.5 (unreleased)

- macOS: indicators are also searched in the system's record of downloaded files. A missing or
  unreadable record is reported as not checked. Contributed by s3ba-b.
- The actively exploited software list has the same protection as the indicator lists: a list
  below half the largest this computer has held is refused and the previous copy kept.
- Only this project's published blocklist files are treated as filter lists on its own sites; anything
  else cached from them is searched like any other page.
- Tests no longer run twice for the same branch. Contributed by zaccromero.
- `docs/VERIFYING.md` explains the signed checksums for the programs.

## 2.0.4 (unreleased)

- Macs no longer get a false warning that macOS is out of date: a CVE record's `lessThan: "2021"` was read as a version number. Thanks to the Mac tester who found it.
- On Windows, double-clicking no longer leaves a terminal in the taskbar that ends the check when closed.
- The report's date comparison names AdFection instead of implying the tool looks for one campaign.
- Safari folders macOS refuses give the plain privacy message, and Full Disk Access advice is left out when access is already on.
- A check that does not apply says why in the report's detail.
- A stopped check no longer says "nothing matched" in its next steps.
- Saved reports show their path on the Result tab, and the save dialog lists file types.
- Help scrolls and fills its tab. Japanese and Chinese wrap correctly in Help, and Chinese, Japanese and Korean use the matching Windows font. Right-to-left lines leave more room at small window sizes.
- Connections closing on Windows are labelled "System", not "System Idle". The Quick check estimate is now 5 to 15 minutes.

## 2.0.3 (unreleased)

**If you checked a phone with 2.0.0 to 2.0.2 and got green, please check it again.** Some results said
more than the check had done.

Results that said too much, found by a code review and fixed:

- A phone nothing could be read from showed green "No known spyware traces found" in the window: an
  empty folder with a phone type chosen, a damaged sysdiagnose, an Android collection with an empty app
  list. It now says "This phone could not be checked". Whether anything was read is now decided by
  records actually read, not by the name of a check.
- In the window, green now means nothing matched and every check ran. When some checks could not
  run, the window shows "Nothing found in what could be checked" in a neutral colour, as the
  terminal summary already did. A match to a withdrawn indicator has its own wording.
- Android crash records: `tombstone_NN.pb` files and the older `>>> name <<<` layout are now read, and a
  record that cannot be read is listed as not checked. Removed apps are now recognised in real battery
  history, which has no version on those lines.
- A file in a layout the tool does not recognise is listed as not checked instead of being counted as
  read: browser HSTS and network state, Safari lists, iPhone records and crash reports, and Windows
  program records. The same applies to a source that holds no usable records.
- The report says which file types the Standard check did not fingerprint in each folder, and a
  match in a phone log carries its line number and says that a mention is not proof of contact.
- A summary with a finding now lists the checks that could not run.

Other fixes from the same review:

- A folder pasted into the window is checked before it is opened, so a network path is refused
  without contacting that server. Browser profile discovery checks a path before following it.
- A named pipe planted in a browser folder can no longer hang the check on Linux or macOS, and the
  browser state files read this way have a size limit.
- Very long crafted text uses about a sixth of the memory it did. An address followed by an escaped dot
  (`example.test%2eevil`) no longer matches `example.test`.
- Indicator-file names and paths in the report are cleaned like other outside text, and a damaged
  language file falls back to English instead of crashing.
- Corrected file limits in the documentation (512 MiB for the hash check) and noted that the window
  always exits with 0, so scripts should use the terminal commands.

Window fixes found when the Windows program was tested by hand:

- "Update indicator lists" in the programs and the single file reported "name 'feeds' is not defined" after
  the update had run. The lists were downloaded; the error message was wrong. Thanks to the testers who reported it.
- The phone guides in the program describe the window's own steps ("A phone", then "Find iPhone
  backups" or "Choose...", the backup password, "Start check") instead of terminal commands, using the
  button names as written in the chosen language. Running the script keeps the command-line form. The
  Android answers are a plain list instead of columns lined up with spaces, and the guide window
  scrolls and keeps its Close button.
- Saving a report opens in Downloads, not Documents. When writing fails (Windows ransomware
  protection blocks an unsigned program from Documents, Desktop and Pictures) the message says what
  happened and what to do, with the system's own wording after it.
- Help names the buttons and result headlines exactly as they appear in the chosen language; it was
  one translated block that quoted them in English or by old names.
- Right-to-left text: lines are kept under 180 bytes in the Windows and macOS layout, where Tk drew
  longer lines in two swapped pieces; on Linux a full stop, comma or colon after a Latin word at the
  end of an Arabic sentence now sits on the reading side.
- The descriptions beside the check choices no longer move right when "A phone" or "Practise" is chosen.
- Updating the indicator lists shows plain lines ("Name: already up to date") instead of hashes and
  counts.
- A computer with no downloaded indicator lists says so on the Check tab: only the built-in
  indicators are in use until "Update indicator lists" is pressed.
- The report's sharing note says "your username" outside Windows.
- Not changed: the Windows terminal entry that stays in the taskbar, the Help tab having no
  scrollbar, and the right-to-left lines cut at the smallest window size.

## 2.0.2 (2026-11-01)

- On a Mac, opening the window can abort the whole program ("Python quit unexpectedly"): with no
  screen session (for example over SSH), and also on a normal desktop when Apple's own Python 3.9 is
  used, because its Tk refuses some macOS versions. The program now checks first whether a window can
  be opened (a throw-away child process on a Mac, so a crash costs nothing) and, if not, says so in
  one line ("The window could not be opened on this computer ...") and carries on in the terminal.
  On Apple's own Python it adds a second line pointing to python.org for the window. The same check
  makes the window tests skip instead of taking the test run down.
- Test suite: the release-check fixture no longer mistakes Apple's bytecode cache (or
  PYTHONPYCACHEPREFIX) for the scanner reading files; the write-ahead-log test builds its uncommitted
  tail from the file format instead of relying on how a given SQLite spills pages; a single test file
  can be run on its own (`pytest scan/tests/test_x.py`); `gate-out/` is ignored by git.
- German: "This is NOT a clean result" no longer leaves the English word "clean" in the sentence.

## 2.0.1 (2026-11-01)

- The programs now include the library needed to open encrypted iPhone backups; before, an
  encrypted backup could not be read and the result could wrongly look clean. A phone backup
  that cannot be read now shows as not checked, never as clean.

## 2.0.0 (2026-11-01)

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
