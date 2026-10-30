# Zero Breach Toolkit

A free, open-source check for traces of known mercenary spyware (Pegasus, Predator,
Graphite, Candiru and others) on computers, Android phones and iPhone backups.

- **Read-only.** It does not modify source evidence or system settings. It writes only
  temporary database snapshots and the reports you ask for.
- **No network requests during a scan.** It never looks up spyware addresses and has no
  upload feature. Python network calls are blocked and redirected paths are refused. This
  is not an operating-system network sandbox; see [PRIVACY.md](PRIVACY.md).
- **States its limits.** Every report says what was found, how strong the evidence is, and
  what could not be checked. A clean result is never presented as proof that you are safe.

Made by archivegenocide. Built on [Zero Breach](https://github.com/interplains/zero-breach).

> **If you think you are being targeted right now, get expert help first.** You do not
> need to run this tool before asking. Journalists, activists, human-rights defenders and
> civil society can contact the
> [Access Now Digital Security Helpline](https://www.accessnow.org/help/) (free, 24/7,
> many languages) or [Amnesty International's Security Lab](https://securitylab.amnesty.org/get-help/).

---

## Step-by-step guide (no technical experience needed)

You do not need a GitHub account or any technical knowledge. You need a Windows or Mac
computer and about 20 minutes. Phones are checked by connecting them to the computer.

**What do you want to check?**
[This Windows computer](#windows) ·
[This Mac](#mac) ·
[An Android phone](#android-phone) ·
[An iPhone](#iphone)

### Windows

**Set up (only the first time)**

1. Go to [python.org/downloads](https://www.python.org/downloads/) and click the yellow
   **Download Python** button. Open the downloaded file.
2. On the first screen of the installer, **tick "Add python.exe to PATH"** at the bottom,
   then click **Install Now**. Wait until it says "Setup was successful".
3. On this page, click the green **Code** button near the top, then **Download ZIP**.
4. Open your **Downloads** folder, right-click **Zero-Breach-Toolkit-main.zip** and choose
   **Extract All**, then **Extract**.

**Run the check**

5. Close your web browsers and chat apps (Chrome, Edge, WhatsApp, Signal…).
6. Open the **Zero-Breach-Toolkit-main** folder (if there is another folder with the same name
   inside, open that one too), then the **scan** folder, and double-click **run-scan.cmd**.
   If Windows shows a warning, click **Run** (or **More info**, then **Run anyway**).
7. A menu appears. Type the number next to **Update the indicator lists** and press Enter,
   then type `y` and press Enter. When it finishes, press Enter.
8. Press Enter again to start **This computer - standard check**. It takes about 15 minutes.
9. Read the result at the end (see [What the result means](#what-the-result-means)). A copy
   is saved in the **findings** folder inside Zero-Breach-Toolkit-main.

### Mac

**Set up (only the first time)**

1. Go to [python.org/downloads](https://www.python.org/downloads/), click **Download Python**,
   open the downloaded file and follow the installer. When it finishes, open **Finder →
   Applications → Python 3** and double-click **Install Certificates.command** (without it,
   updating the indicator lists fails).
2. On this page, click the green **Code** button, then **Download ZIP**. It appears in your
   **Downloads** folder as **Zero-Breach-Toolkit-main** (if it is still a .zip file,
   double-click it).
3. Open **System Settings → Privacy & Security → Full Disk Access**, click **+**, choose
   **Applications → Utilities → Terminal**, and turn it on. Without this, macOS hides
   Safari's records from the check.

**Run the check**

4. Close your web browsers and chat apps.
5. Open **Terminal** (press Cmd+Space, type `Terminal`, press Enter). Copy this line, paste it
   into Terminal and press Enter:
   ```
   cd ~/Downloads/Zero-Breach-Toolkit-main && python3 -X utf8 scan/zero-breach-toolkit.py
   ```
6. A menu appears. Type the number next to **Update the indicator lists** and press Enter,
   then type `y` and press Enter. When it finishes, press Enter.
7. Press Enter again to start **This computer - standard check**. It takes about 15 minutes.
8. To keep a copy of the result, type `3` and press Enter, type `report.txt` and press Enter.
   It is saved in the Zero-Breach-Toolkit-main folder. Type `0` to finish.

### Linux

**Set up (only the first time)**

1. Open a terminal (on most desktops, press Ctrl+Alt+T). Python 3 is usually already
   installed; check with `python3 --version`. If it is missing, install it with your
   package manager, for example `sudo dnf install python3` (Fedora),
   `sudo apt install python3` (Ubuntu, Debian, Mint) or `sudo pacman -S python` (Arch).
2. On this page, click the green **Code** button, then **Download ZIP**. In your
   **Downloads** folder, right-click the zip and choose **Extract Here**, so that you have a
   folder named **Zero-Breach-Toolkit-main**.

**Run the check**

3. Close your web browsers and chat apps.
4. Copy this line, paste it into the terminal and press Enter:
   ```
   cd ~/Downloads/Zero-Breach-Toolkit-main && python3 -X utf8 scan/zero-breach-toolkit.py
   ```
5. A menu appears. Type the number next to **Update the indicator lists** and press Enter,
   then type `y` and press Enter. When it finishes, press Enter.
6. Press Enter again to start **This computer - standard check**. It takes about 15 minutes.
7. To keep a copy of the result, type `3` and press Enter, type `report.txt` and press Enter.
   It is saved in the Zero-Breach-Toolkit-main folder. Type `0` to finish.

You do not need `sudo` to run the check. It reads your own account's records; run with
`sudo`, it may look at the root account's browsers instead of yours.

### Android phone

First do the **Set up** steps for [Windows](#windows) or [Mac](#mac) above.

**On the phone**

1. Open **Settings → About phone** and tap **Build number** seven times, until it says you are
   a developer. (On Samsung: **Settings → About phone → Software information → Build number**.)
2. Go back to **Settings**, open **Developer options** (often under **System**) and turn on
   **USB debugging**.
3. Connect the phone to the computer with a USB cable that carries data (some cables only
   charge). Unlock the phone. When it asks **Allow USB debugging?**, tick **Always allow** and
   tap **Allow**.

**On the computer**

4. Start Zero Breach (Windows: double-click **run-scan.cmd**; Mac: step 5 of the Mac guide).
5. In the menu, type the number next to **A phone** and press Enter, then type `2` (**Collect
   from an Android phone connected by USB now**) and press Enter.
6. Press Enter to save the collection on your Desktop, then type `YES` and press Enter.
7. The collector asks a few questions. Use the arrow keys and Enter to answer:

   | It asks | Choose |
   |---|---|
   | Backup | **Only SMS** |
   | Download copies of apps | **Only non-system packages** |
   | Remove copies of apps signed with a trusted certificate | **No** |
   | Intrusion Logs | **No** |
   | Hash files | **No** |
   | Anything else | **No** |

8. If the phone shows **Back up my data**, tap it (leave the password empty). Keep the phone
   unlocked until the collection finishes.
9. The check starts by itself and shows the result.
10. When you are done, turn **USB debugging** off again on the phone.

### iPhone

First do the **Set up** steps for [Windows](#windows) or [Mac](#mac) above.

These steps work the same way for an **iPad**. The check runs on a computer, not on the iPhone
or iPad itself: iOS and iPadOS do not let any app read other apps' data, so the device is backed
up to a computer and the backup is checked there.

1. **Make a backup on the computer.** Connect the iPhone with a cable and tap **Trust** on the
   phone.
   - Windows: install **Apple Devices** from the Microsoft Store, open it and select the iPhone.
   - Mac: open **Finder** and select the iPhone in the sidebar.
2. Choose **Back up all of the data on your iPhone to this computer**, tick **Encrypt local
   backup**, choose a password you will remember, and click **Back Up Now**. Wait until it
   finishes.
3. **Open the backup folder:**
   - Windows: press **Windows key + R**, paste `%USERPROFILE%\Apple\MobileSync\Backup` and press
     Enter.
   - Mac: in Finder, choose **Go → Go to Folder**, paste
     `~/Library/Application Support/MobileSync/Backup` and press Enter.

   Inside is a folder with a long name of letters and numbers: that is your backup.
4. Start Zero Breach. In the menu, type the number next to **A phone**, press Enter, type `1`
   and press Enter.
5. **Drag the backup folder** (the one with the long name) into the Zero Breach window and press
   Enter.
6. When asked whether the backup is password-protected, type `y` and press Enter, then type the
   backup password (nothing appears while you type) and press Enter.

### If something goes wrong

| What you see | What to do |
|---|---|
| `'python' is not recognized` or nothing happens on Windows | Run the Python installer again, choose **Modify**, and make sure **Add Python to environment variables** is ticked. Restart the computer. |
| `No such file or directory` on a Mac | Type `python3 -X utf8 ` (with a space at the end) in Terminal, then drag the file `zero-breach-toolkit.py` from the toolkit's `scan` folder into Terminal and press Enter. This works from any folder. |
| `Bad CPU type in executable`, or trying to run it on an iPad or iPhone | The check cannot run on an iPad or iPhone. Back the device up to a Windows PC or Mac (the iPhone steps above work for an iPad too) and check the backup on that computer. |
| A folder named `candiru` in the download | That is part of the toolkit: `third_party/candiru` holds the published detection rules for Candiru's spyware, not the spyware. Leave it in place; if it was deleted, download the toolkit again. |
| "encrypted iPhone backups require optional cryptography" after installing it | It went into a different Python. Install it with the same command you start the check with (`python3 -m pip install --require-hashes -r requirements-backups.txt` on a Mac), from the toolkit folder. |
| `command not found: python3` | Install Python from python.org (step 1), then close and reopen Terminal. |
| Updating the indicator lists fails on a Mac (`CERTIFICATE_VERIFY_FAILED`) | Open **Finder → Applications → Python 3** and double-click **Install Certificates.command**, then update again. Full Disk Access does not affect updating. |
| Android: the collector finds no phone | Unlock the phone, use a different cable or USB port, and check **Allow USB debugging** was accepted. Unplug and plug in again. |
| iPhone: "wrong password" | Use the password chosen when **Encrypt local backup** was first turned on. If it is forgotten, it can be reset on the iPhone (Settings → General → Transfer or Reset iPhone → Reset → Reset All Settings), then make a new backup. |
| Safari "could not be checked" on a Mac | Give Terminal Full Disk Access (Mac step 3), close Terminal, open it again and run the check again. |

Still stuck? Ask in the [issues](https://github.com/interplains/Zero-Breach-Toolkit/issues)
(do not post your report there; it contains private details).

### What the result means

- **"No known indicators found"**: nothing from the published spyware lists was found in
  the places the tool could check. It is not proof that the device is clean: read the list
  of places that could not be checked.
- **"Something matched"**: this means *look closer*, not *you are infected*. Do not delete
  anything and do not visit the address it names. Keep the report and contact the
  [Access Now Digital Security Helpline](https://www.accessnow.org/help/) (free, 24/7).
- The report never leaves your computer unless you send it to someone yourself.

---

## What it checks

### Windows

No administrator rights are needed.

| Where | What it looks for |
|---|---|
| Browsers at their default locations: Chrome, Edge and Brave (including beta, dev, canary and nightly channels), Chromium, Vivaldi, Opera, Opera GX, Arc, Yandex; Firefox, LibreWolf, Waterfox, Floorp, Zen, Pale Moon, Tor Browser | indicator addresses in history, cookies, connection records, HSTS, bookmarks, downloads, site storage and caches, per profile |
| Desktop apps with a built-in Chromium browser | supported history, cookie and storage records; raw app web caches are skipped and reported as a gap |
| Downloaded files | the website each file came from (the "Mark of the Web" stamp) |
| The Win+R box | commands people were tricked into pasting by fake "verify you are human" pages |
| Antivirus status and Microsoft Defender history | registered antivirus products and their reported status; past Defender detections, protection-off events and added exclusions |
| PowerShell log | scripts that named a spyware address, or downloaded and ran code |
| Programs listed by Windows | existing files named in the shim cache and the Windows 11 launch list, compared with published sample fingerprints; not a complete execution history |
| Prefetch and Amcache | supported Prefetch executable-name records and Amcache file inventory; the program files they name are never opened |
| Selected user folders | fingerprints of candidate files, within size and directory limits |
| DNS cache, DNS history, hosts file, COM and startup/task/service registrations | known indicators in supported network and persistence records; not a full persistence audit |

A Prefetch match (`execution-record`) does not identify the file's contents or full path;
an Amcache match (`inventory-record`) does not prove execution or that the file still
exists. Locked or unsupported records are gaps.

Antivirus status comes from Windows Security Center, including third-party products such
as Bitdefender that register there. An active registered product puts an old Defender-off
event in context; it does not mean protection is off now. Registration is not a health
test, some enterprise products do not register, and unavailable status is a gap. A desktop
app such as Slack is listed because its web records were checked, not because it is
suspicious.

The default hash check covers `.dll`, `.exe`, `.sys`, `.ocx`, `.cpl`, `.scr`, `.tmp`,
`.dat`, `.bin` and `.ax` files up to 120 MiB in selected folders, skipping cache and
dependency directories. Computer checks can find published infrastructure or file traces;
they cannot tell whether a phone is infected.

### macOS and Linux

The same browsers are checked at their default locations, plus common Snap and Flatpak
packages and Firefox's newer `~/.config/mozilla` profile folder on Linux. On a Linux desktop
in another language, the translated Downloads, Desktop and Documents folders are found from
`user-dirs.dirs`. File fingerprints, separate browser cache locations and bounded saved-record
checks run without administrator access.

- **Safari (macOS):** history and profile databases, open and iCloud tabs, the URL cache,
  WebKit's tracking-prevention list, cookies, HSTS records, bookmarks, downloads, Top Sites
  and recently closed tabs.
- **Startup configuration:** on Linux, standard autostart `.desktop` entries, systemd units
  and immediate `.conf` overrides, cron configuration and scheduled script directories; on
  macOS, standard LaunchAgent and LaunchDaemon property lists. A launch item's program is
  compared as an executable path and, by its file name, as a process name.
- **Shell and logs (both):** standard shell startup files, saved Bash/Zsh/fish history
  (including macOS Terminal's per-session history in `~/.zsh_sessions`), the hosts file and
  readable current text system logs. Paths inside `$( )` and backticks are recognised. Large
  history and log files are limited to recent records; the omitted part is a gap.

These read saved configuration, not which jobs are enabled or ran. Network strings are
references; exact known executable paths in supported launch configuration can be
findings, with activation and execution unverified.

File checks also cover extensionless files, executables, native libraries and scripts in
selected application, user and temporary folders (120 MiB limit). Windows-only live checks
do not run here; copied Prefetch and Amcache files can still be selected in targeted mode,
though compressed Prefetch needs Windows.

### Desktop apps

Apps with a built-in Chromium browser are found by their folder contents under AppData
(Windows), Application Support (macOS) or the user and Flatpak configuration folders
(Linux), including apps whose own folder is a Chromium profile, such as Signal on macOS.
The search has no fixed depth limit; it is bounded by folder count and time, and reaching
that bound is reported as a gap.

### Android

The tool reads a collection made with [AndroidQF](https://github.com/mvt-project/androidqf);
it never talks to the phone itself. It checks:

- installed and running apps, their fingerprints and signing certificates;
- the install history, so an app that was installed and later removed still shows;
- system records, logs and crash records;
- supported, already decrypted intrusion logs: DNS lookups, TCP connection attempts and
  process-start events (a connection attempt does not prove success);
- links in SMS and MMS messages, from the SMS backup AndroidQF offers to take;
- apps installed outside an app store, with what they can do (read SMS, use the
  microphone, read notifications, resist uninstalling) and when they arrived;
- signs of a modified phone: unlocked bootloader, debug build, security protection off.

It recognises the collection's own traces (USB debugging, the debugging shell's
permissions) and does not report them as suspicious.

### iPhone

Local Finder, Apple Devices or iTunes backups (encrypted or not), extracted file systems
and sysdiagnose archives. See
[Checking local iPhone evidence](#checking-local-iphone-evidence).

### Indicators

About 12,400 published indicators from 29 sources: Amnesty International's Security Lab,
the [Mobile Verification Toolkit](https://github.com/mvt-project/mvt-indicators) project,
the Citizen Lab and Echap's stalkerware research, and a hand-curated set from Citizen Lab
reports (Candiru / DevilsTongue and Paragon's Graphite) with every line cited. The curated
set works offline; `--update` downloads the rest from a fixed list of official sources.

---

## Install and run

You need Python 3.8 or newer ([python.org](https://www.python.org/downloads/); on Windows,
tick "Add python.exe to PATH" when installing). No administrator rights and no extra
packages. On macOS and Linux type `python3` instead of `python`.

1. **Get the toolkit.** On GitHub choose **Code → Download ZIP** and extract it, or:
   ```
   git clone https://github.com/interplains/Zero-Breach-Toolkit.git
   ```
2. **Open a terminal in the toolkit folder.** Windows: open the extracted
   folder (`Zero-Breach-Toolkit`, or `Zero-Breach-Toolkit-main` from a ZIP), click the address bar, type `powershell` and press
   Enter. macOS: open Terminal, type `cd ` (with a space), drag the folder into the window
   and press Enter. Run every command below from this folder.
3. **Recommended: download the latest indicator lists.** This is optional and is the only
   step that uses the internet; the checks themselves never do. Without it only a small
   built-in set is used. Repeat it every few weeks.
   ```
   python -X utf8 scan/zero-breach-toolkit.py --update
   ```
4. **On a Mac, give Terminal Full Disk Access first** (System Settings → Privacy & Security
   → Full Disk Access → add Terminal, then reopen it). Without it macOS blocks Safari's
   records and some folders, and the report lists them as not checked.
5. **Close your browsers and chat apps**, then run the check. A menu opens; press Enter for
   the standard check of this computer.
   ```
   python -X utf8 scan/zero-breach-toolkit.py
   ```
   On Windows you can instead double-click `scan\run-scan.cmd`. It saves the readable and
   JSON reports in a `findings` folder next to the toolkit.

Reports contain private details from your computer; keep them out of shared and synced
folders. Useful options:

```
python -X utf8 scan/zero-breach-toolkit.py --quick                     # faster: skips file fingerprints
python -X utf8 scan/zero-breach-toolkit.py --phone "FOLDER"            # a phone collection or backup
python -X utf8 scan/zero-breach-toolkit.py --json report.json          # machine-readable report
python -X utf8 scan/zero-breach-toolkit.py --share-json summary.json   # minimal summary for sharing
```

Put folder paths in quotes, especially if they contain spaces. On Linux or macOS,
`sh scan/run-scan.sh` takes the same options.

### Verify what you run

The project is anonymous, so do not take its word for anything. Verification rests on what
you can reproduce.

Running from source, as above, means every line the tool executes is in the clone: nothing
is compiled and nothing is fetched in order to run.

The single-file `zero-breach-toolkit.py` attached to a release is generated from the same
source. Rebuild it from the release's tag and compare:

```
git checkout v0.1.13
python build/bundle.py
python -c "import hashlib; print(hashlib.sha256(open('dist/zero-breach-toolkit.py','rb').read()).hexdigest())"
```

For v0.1.13 the file is 973,579 bytes, SHA-256
`bb0e6a7a36ee659c0494d02e9f7495d5fd4701f1ab7e57529e79925cb581ae15`. The size and SHA-256
published with each release are authoritative. The build is deterministic, so a matching
rebuild means the published file contains that source and nothing else. Releases are also
GPG-signed; see [docs/VERIFYING.md](docs/VERIFYING.md).

There is no signed Windows program, and none is planned while the project stays anonymous:
code-signing certificates require a named legal identity. An `.exe` you build yourself with
PyInstaller is unsigned, has no download reputation and is not byte-reproducible, so
SmartScreen will warn, some antivirus products will flag it, and the comparison above does
not apply. Running from source avoids all of that.

### Checking an Android phone

1. On the phone, turn on *Developer options* (Settings → About phone → tap *Build number*
   seven times), then turn on *USB debugging*.
2. Connect the phone by USB and tap *Allow* when it asks about this computer.
3. Download and run [AndroidQF](https://github.com/mvt-project/androidqf/releases) on the
   computer. Answer its questions like this:

   | AndroidQF asks | Answer |
   |---|---|
   | Take a backup of the device? | Only SMS |
   | Download copies of all apps or only non-system ones? | Only non-system packages |
   | Remove copies of apps signed with a trusted certificate? | No |
   | Take the Intrusion Logs? | No, unless you turned on Intrusion Logging |
   | Hash files on the device? | No (Yes also checks file fingerprints, but it is slow and can stop the collection on some phones) |
   | Browser history / Magisk modules? | No |

   On the phone, confirm the backup with *Back up my data*.
4. AndroidQF saves a `.zip` next to itself. Extract it.
5. From the toolkit folder, check the extracted folder (keep the quotes):
   ```
   python -X utf8 scan/zero-breach-toolkit.py --phone "PATH TO THE EXTRACTED FOLDER"
   ```
   Or run the tool with no options, choose *A phone*, and drag the folder into the window.
6. Turn USB debugging off again.

The collection holds private information about the phone. Keep it on your computer.

Use `--phone-guide android` for preparation steps and `--phone FOLDER --preview` to list
which artifacts are available. For an AES-encrypted `backup.ab`, add `--backup-password`;
the password is asked for privately at the terminal and never appears as an argument or in
a report. Age-encrypted acquisition archives must first be decrypted with the owner's
identity using the separate age tool; this scanner does not launch it.

**Guided acquisition (experimental).** `--collect-android LOCAL_OUTPUT_FOLDER` downloads
official AndroidQF v1.8.3, checks its pinned SHA-256, asks for the device owner's explicit
consent and runs the collector's interactive prompts. After a successful plaintext
acquisition it extracts the archive locally and checks the collection. Acquisition changes
phone state and saves private records; it is separate from read-only scanning.

This is the only point at which the tool runs a program it did not ship:

- the asset name and expected digest are fixed in the source;
- the file is fetched over HTTPS from the publisher's release, with redirects limited to an
  allow-list, and hashed while downloading;
- if the digest does not match, acquisition is refused and nothing is executed;
- the collector is written to a temporary directory and run directly, not through a shell,
  with `ADB_`, `ANDROID_ADB_`, `LD_` and `DYLD_` variables removed and `PATH` reset to the
  system directory, then deleted when the command finishes;
- nothing is downloaded or run unless you invoke the command and confirm consent.

The pinned digest verifies the publisher's release bytes; it is not an independent audit of
the collector. The publisher ships the Windows build unsigned, so a browser download shows
the usual "not commonly downloaded" warning and SmartScreen prompts on first run. If you
prefer, install AndroidQF yourself, follow the five steps above and skip this command.

`--age-recipient-file PATH` supplies public age1 recipients (private identity files are
refused). When encryption is requested, a plaintext result is refused. An encrypted result
must have a supported age envelope and no unexpected extra files, but these format checks
cannot authenticate it or verify the recipient. It is saved for separate decryption; the
command succeeds without producing a scan or an all-clear. After a failure, check the
reported folder: original or partial records are kept and may be unencrypted.

### Checking local iPhone evidence

1. Make a local backup with Finder (Mac) or Apple Devices / iTunes (Windows). Tick
   *Encrypt local backup*: encrypted backups include more of the records this tool checks.
2. Find the backup folder (one per device, with `Manifest.plist` inside): on a Mac
   `~/Library/Application Support/MobileSync/Backup/`, on Windows
   `%USERPROFILE%\Apple\MobileSync\Backup\`.
3. From the toolkit folder (keep the quotes; leave out `--backup-password` if the backup
   is not encrypted, and the password is asked for privately):
   ```
   python -X utf8 scan/zero-breach-toolkit.py --phone "PATH TO THE BACKUP FOLDER" --backup-password
   ```

`--phone-guide ios` and `--phone-guide android` print these steps in the terminal.

Encrypted backups need the optional `cryptography` package already installed in your Python
environment; nothing is installed automatically. Install it from the toolkit folder with the
same command you start the check with: `python3 -m pip install --require-hashes -r
requirements-backups.txt` on a Mac or Linux, `python -m pip ...` on Windows (every package
pinned by version and hash). If the check still says it needs cryptography, it was installed
for a different Python on the same computer. The supported version is cryptography 50.0.2, which needs Python 3.9 or
later. Intel Macs get 48.0.1, the last release published for them; its remaining advisories
concern certificate checking, which this tool does not use.

For evidence you already have, use `--phone ROOT --ios-input filesystem` for an extracted
file system, or `--phone PATH --ios-input sysdiagnose` for a directory or TAR/TAR.GZ archive.
Both are also in the phone menu. This does not acquire a device.

It reads messages (SMS, iMessage, WhatsApp), Safari and other browsers, data-usage
processes, app records, permissions, calls, calendar, interactions, Shortcuts,
configuration profiles, analytics and diagnostics (shutdown logs, crash and memory reports,
running processes, installation logs). Local browser visits are separated from synced or
imported ones; unknown origin stays a reference with a gap. Unusual paths alone are leads.

Committed SQLite WAL records, including encrypted backup sidecars, are validated and
replayed on temporary copies. JSON findings keep source hashes and record locators. While a
table's row index is readable, an unreadable message, visit or process row is skipped and
later rows are still checked; repeated gaps are grouped. Unsupported encodings or schemas,
damaged WALs, record caps, unavailable protection classes and encrypted `Manifest.db` WALs
are gaps. The test suite covers the table layouts
of iOS 15, 16, 17 and 18. See [docs/IPHONE.md](docs/IPHONE.md) for exact support and limits.

### Choosing the scope

- `--scan-type default` uses the computer checks and file candidates supported on your platform.
- `--scan-type full` also reads desktop-app raw web caches and hashes all file extensions
  in the usual roots, including subdirectories normally skipped. It is broader, not a scan
  of every drive, account or artifact. The 120 MiB file limit remains.
- `--scan-type targeted --target PATH` reads only the selected files, directories, drives
  or browser profiles; repeat `--target` for several. Selected files are hashed whatever
  their extension, within the same size and access limits. Copied Prefetch/Amcache files
  inside the selection are also read. Live registry and log checks are outside this scope.
- `--scan-type browser` reads only this account's browser profiles and desktop apps with a
  built-in Chromium browser (history, cookies, site storage, caches and connection records)
  against every loaded list, including ad-campaign addresses. Large caches can take several
  minutes. Files, startup entries, DNS, registry and system events are not read.
- `--preview` prints the proposed scope without scanning. File hashing reports progress.
  Ctrl+C stops the scan and reports what was collected, with an incomplete-coverage gap.
- `--extended-windows` adds existing Sysmon and Security process events. It does not enable
  logging or elevate privileges. If access is denied, a second run from an administrator
  terminal can read what the ordinary account could not.

On Windows, saved console and Explorer input is also read; it does not prove that anything
ran. Startup checks interpret recognisable batch commands, Internet Shortcut URLs and literal `.lnk` target and
argument metadata, without resolving or opening the target; anything they cannot interpret
is a gap. Related-record groups link the same indicator across artifacts with their dates
and original grades; they do not claim a causal attack sequence. Publisher validity,
platform and withdrawal labels are shown as context.

See [the coverage table](docs/COVERAGE.md) before relying on a particular check.

### Start menu and follow-up

Running the tool in a terminal without choosing a check shows a menu. Enter starts the
standard check; 0 quits without scanning. The same menu offers a full check, a
browsers-only check, selected files or folders, or a phone collection. Scripts with
non-interactive input do not see it; `--no-menu` turns menus off.

The browsers entry also offers a test of whether your browser blocks ads. That test only
works inside a browser, so the tool asks first and then opens the ArchiveGenocide test page
in your default browser. The browser goes online for it; the tool does not. See
[PRIVACY.md](PRIVACY.md).

After a menu-selected check you can inspect findings and references, review gaps and next
steps, save reports, or prepare a private evidence bundle. `--post-menu` offers the same
after a command-line scan. The report is shown before those choices. The Windows launcher
keeps prompts visible and saves both readable and JSON reports.

`--report PATH` saves the readable report, independently of `--json` and `--share-json`.
Reports never replace an existing file inside a selected evidence folder, a selected input
file, or the app data and app cache folders where desktop apps keep the records the scan
reads. Choose a new filename. No baseline snapshots are kept.

### Private evidence handoff

`--evidence-bundle PATH` creates a new, **unencrypted** private ZIP with the full JSON
report, readable report, minimal sharing summary and an integrity manifest. Repeat
`--evidence-file PATH` to add original local files you choose. Report text never chooses
files to copy, and nothing is uploaded or sent to a helpline.

```text
python scan/zero-breach-toolkit.py --scan-type targeted --target SUSPICIOUS_FILE --report report.txt --json report.json --evidence-bundle evidence.zip --evidence-file SUSPICIOUS_FILE
```

`SUSPICIOUS_FILE` is the path of one file; `--evidence-file` takes files, not folders.

The archive is previewed before it is created, never overwrites an existing file, and is
limited to 128 originals of up to 64 MiB each and 256 MiB in total. It records SHA-256
hashes, tool version, scope, times and fingerprints of the indicator sets used. Hashes show
later integrity, not authenticity to the original device. Originals are copied at export
time and may differ from what was scanned; live databases may need their sidecar files
selected too. Use the minimal summary for first contact, and share the full archive only
through a secure route agreed with the recipient.

---

## Reading the result

The report starts with a short summary: what was found, what it means, what to do, and what
could not be checked. The evidence follows.

- **Findings** carry an evidence grade. "A known spyware file is on this machine" or "an
  app researchers name is on this phone" is strong. "A saved web page mentions the address"
  is weak, and is usually an article about the spyware. The grade, not the number of
  matches, decides what to do.
- **Worth a look** lists things the tool cannot judge on its own (a sideloaded app, a
  command that downloaded code, an antivirus exclusion), each with its usual harmless
  explanation. They are not findings.
- **In time order** lists every dated finding and item.
- **What could not be checked.** Read this part. A check that could not run has not
  cleared anything.

Exit codes for scripts:

| Code | Meaning |
|---|---|
| `0` | no actionable matches and no recorded coverage gaps |
| `1` | setup, argument or output error |
| `2` | a match beyond a saved reference |
| `3` | no actionable matches, but checks or indicator sources were incomplete |
| `4` | the start menu was closed without scanning (no verdict or report) |

Reference-only matches stay visible and return `0` or `3`, depending on gaps. No exit code
proves a device is safe.

## What it cannot do

- It only finds published indicators. New or unpublished spyware will not be found.
- Spyware is often rebuilt for each target, and many traces expire within weeks.
- An Android check sees only what the collection contains; an iPhone check sees only
  supported artifacts in the local evidence supplied. Neither is a full phone examination.
- It does not replace a forensic examination by experts. If you are worried, ask for help.

## Privacy

`--update` downloads indicator sources. The separate `--collect-android` command downloads
a pinned official collector after consent. Ordinary scans stay offline. Full reports can
contain usernames, profile names, file paths, browsing details, SMS senders and message
excerpts; keep them private. `--share-json summary.json` writes counts, scope labels, the
verdict and fixed advice, and leaves out artifact text, indicator values and dates. It is an
initial summary, not forensic evidence; review it before sharing. See [PRIVACY.md](PRIVACY.md).

## For scripts and assistants

`--describe` prints, as JSON, every check the tool runs, what each reads and cannot see,
the exit codes and the rules for relaying a result. `--json` writes a machine-readable
report that marks the fields to relay to the person, the next steps that may be given, and
which fields hold untrusted text from the scanned machine. See
[scan/CONTRACT.md](scan/CONTRACT.md).

A [skill file](skills/zero-breach-toolkit/SKILL.md) is included for assistants that support
skills: add the `skills/zero-breach-toolkit` folder to the assistant's skill directory, or
have it read that file. It covers scope selection, encrypted-backup prompts, offline
operation, report interpretation and evidence privacy. Nothing is installed automatically.

## Tested platforms

Windows, macOS, Linux, Android (AndroidQF collections) and iPhone (local backups). See
[docs/COVERAGE.md](docs/COVERAGE.md) for what each check reads and its limits. Built-in
readers share one registry for platform selection, coverage descriptions and the
single-file build; see [scan/READERS.md](scan/READERS.md) to add one.

## Where the code is

There is no `src` folder; the code is under [`scan/`](scan/):

- [`scan/zero-breach-toolkit.py`](scan/zero-breach-toolkit.py): the entry point you run.
- [`scan/zbtriage/`](scan/zbtriage/): the scanner (indicator loading, the network block,
  reporting). The package keeps the project's earlier name so existing installs keep working.
- [`scan/zbtriage/modules/`](scan/zbtriage/modules/): one file per check (browsers, Windows
  records, macOS and Linux, Android, iPhone, file fingerprints).
- [`scan/tests/`](scan/tests/): the test suite.
- [`build/bundle.py`](build/bundle.py): builds the single file attached to each release from
  this source (see [Verify what you run](#verify-what-you-run)).

## Credits

Indicators are the work of Amnesty International's Security Lab, the Citizen Lab, the MVT
project and Echap.

## Licence

Code, including the generated scanner: Apache License 2.0 ([LICENSE](LICENSE)). The curated
indicator files in `iocs/` and generated indicator exports in `dist/`: CC0 1.0, public
domain ([iocs/LICENSE.md](iocs/LICENSE.md)). Optional bundled research rules keep their own
licences in [third_party/candiru](third_party/candiru/README.md). Indicator lists downloaded
by `--update` remain under their publishers' terms and are not part of this repository.
