# Zero Breach Toolkit

> **Version 2 is out:** now a double-click app for Windows, Mac and Linux, in 27 languages.
> [Download it from the latest release](https://github.com/interplains/Zero-Breach-Toolkit/releases/latest).

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

## Phone backup? Check it in your browser

To check an **iPhone backup** or an **Android collection** there is nothing to install: open
[archivegenocide.com/scan/phone](https://archivegenocide.com/scan/phone/) on the computer that holds
the backup, choose the backup folder, and you get the same result as the program, in your language.
Nothing is uploaded. The check runs inside a part of the page whose security settings forbid every
network connection, and before it opens your backup it proves this by trying to reach the site and
showing you that your browser blocked it. The page's code is in [`web/phone/`](web/phone/).

A web page cannot look at the computer itself (its programs, start-up items and connections). To
check a computer, use the program below.

## Easiest: download the program (no Python, no commands)

**You do not need to know anything technical to use this.** Download one file from the
[latest release](https://github.com/interplains/Zero-Breach-Toolkit/releases/latest), open it,
and follow the window. You do not need the source code on this page, and you do not need to
type any commands.

Once it is open: choose a check, press **Start check**, and read the result. It tells you in
plain words whether anything was found and what to do next. You can save the report if you
want to keep it or show it to someone helping you.

**Which check?** Use **Standard** unless you have a reason not to: it covers browsers, apps,
startup items, program files and out-of-date programs (usually 15 to 20 minutes). **Quick** looks
at browsers only (5 to 10 minutes). **Full** adds web caches and more file types (30 minutes or
more). You can press **Stop** at any time and keep what has been checked so far. To check a
phone, choose **A phone** in the window; the guides there explain what you need first.

**A green result is good news, not a guarantee.** It means this check found none of the published
traces it looks for, in the places it could read. It cannot find spyware nobody has published
traces of, and it does not prove a device is safe. If you think you are being targeted, ask a
digital-security helpline even if the result is green.

**Your antivirus may flag these programs.** Antivirus products often wrongly flag new programs that are not code-signed yet, and some flag these. If you downloaded the file from [the official release page](https://github.com/interplains/Zero-Breach-Toolkit/releases/latest), this is a false alarm and you can ignore it: the code is public, and each program has a public build record you can check. We have applied for free code signing and will report these false alarms to the antivirus companies. **If the file came from anywhere else, do not run it and trust the warning.**

### Windows

1. Download `zero-breach-toolkit-windows-x64.exe`.
2. Double-click it in your Downloads folder.
3. Windows may say it "protected your PC". Click **More info**, then **Run anyway**.

### Mac

1. Download `zero-breach-toolkit-macos-apple-silicon.dmg` for a newer Mac (M1, M2, M3, M4),
   or `zero-breach-toolkit-macos-intel.dmg` for an older Intel Mac. The Apple menu →
   **About This Mac** says which one you have.
2. Open it, drag **Zero Breach Toolkit** into Applications, then open it from Applications.
3. macOS will refuse the first time. Open **System Settings → Privacy & Security**, scroll
   down, click **Open Anyway**, then open the app again.

Open the app on the Mac itself, not through a remote or SSH session: it needs a desktop.

### Linux

1. Download `zero-breach-toolkit-linux-x64.tar.gz`.
2. Extract it (double-click it, or `tar -xzf zero-breach-toolkit-linux-x64.tar.gz`).
3. Run `./zero-breach-toolkit`, or right-click it and choose **Run in Terminal**.

The warnings appear because the programs are not signed by Microsoft or Apple yet. Each
program is built by GitHub from the published source, and you can check that before running it:
`gh attestation verify <file> --repo interplains/Zero-Breach-Toolkit` (see
[docs/VERIFYING.md](docs/VERIFYING.md)). Prefer to see exactly what runs? Use the Python
version in the guide below; it is the same check.

To let the check read Safari on a Mac, give **Zero Breach Toolkit** (or Terminal, for the Python
version) **Full Disk Access** in System Settings → Privacy & Security.

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
   After step 1, `python3` is the Python from python.org. If you skipped step 1, `python3` is
   the one Apple ships with the Command Line Tools: it still runs the check in the terminal, but
   on some macOS versions its window cannot open (it says so, and carries on in the terminal).
   For the window, finish step 1 or use the downloadable Mac app.
6. A menu appears. Type the number next to **Update the indicator lists** and press Enter,
   then type `y` and press Enter. When it finishes, press Enter.
7. Press Enter again to start **This computer - standard check**. It takes about 15 minutes.
8. To keep a copy of the result, type `3` and press Enter, then type `.` (a full stop) and
   press Enter. It is saved in the Zero-Breach-Toolkit-main folder with the date and time in
   its name, so every check gets its own file. Type `0` to finish.

### Linux

**Set up (only the first time)**

1. Open a terminal (on most desktops, press Ctrl+Alt+T). Python 3 is usually already
   installed; check with `python3 --version`. If it is missing, install it with your
   package manager, for example `sudo dnf install python3` (Fedora),
   `sudo apt install python3` (Ubuntu, Debian, Mint) or `sudo pacman -S python` (Arch).
2. On this page, click the green **Code** button, then **Download ZIP**. In your
   **Downloads** folder, right-click the zip and choose **Extract Here**, so that you have a
   folder named **Zero-Breach-Toolkit-main**.

If Chinese, Japanese or Korean text in the window shows as empty boxes, install a CJK font
(for example `sudo apt install fonts-noto-cjk`) and open the program again.

**Run the check**

3. Close your web browsers and chat apps.
4. Copy this line, paste it into the terminal and press Enter:
   ```
   cd ~/Downloads/Zero-Breach-Toolkit-main && python3 -X utf8 scan/zero-breach-toolkit.py
   ```
5. A menu appears. Type the number next to **Update the indicator lists** and press Enter,
   then type `y` and press Enter. When it finishes, press Enter.
6. Press Enter again to start **This computer - standard check**. It takes about 15 minutes.
7. To keep a copy of the result, type `3` and press Enter, then type `.` (a full stop) and
   press Enter. It is saved in the Zero-Breach-Toolkit-main folder with the date and time in
   its name, so every check gets its own file. Type `0` to finish.

You do not need `sudo` to run the check. It reads your own account's records; if you run with
`sudo`, it may look at the root account's browsers instead of yours.

### Android phone

**Cannot turn on USB debugging, or install anything? Use a bug report the phone makes itself.** Turn on
Developer options (Settings → About phone → tap **Build number** seven times), then **Settings → System →
Developer options → Take bug report** ("Full report" if it asks). When the notification says it is ready,
tap it and choose **Share > save to the phone's Files** (Android keeps bug reports where a cable cannot
reach), then copy the `.zip` to your computer the way you copy photos (a USB cable with the phone set to "File
transfer", which is not USB debugging, or a memory card). If your accounts may be watched, do not email it to yourself
or use a cloud folder: it holds private details about the phone. Check it as it is, without unzipping it:
in the window, **A phone → What
is it? → Android bug report**, or `--phone "the-bug-report.zip"`. A bug report holds the phone's system
state, settings, logs and the history of apps installed and **removed**, but not the apps' files, the
file list or text messages, so those parts are listed as not checked. For the fullest check, use the
cable steps below.

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
| A match inside an ad blocker such as uBlock Origin | Fixed in 0.1.15: ad-blocker filter lists contain these domains in order to block them, so a match in the browser's copy of a list is now a note, not a finding. Update to the latest download. |
| `CERTIFICATE_VERIFY_FAILED` on Windows (updating the lists or collecting from an Android phone) | Open **PowerShell** and run `Invoke-WebRequest https://github.com -UseBasicParsing \| Out-Null`, then try again: Windows downloads some certificates only when first needed. If it still fails, pause your antivirus's HTTPS scanning ("web shield") for a moment. |
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
test; some enterprise products do not register, and unavailable status is a gap. A desktop
app such as Slack is listed because its web records were checked, not because it is
suspicious.

The default hash check covers `.dll`, `.exe`, `.sys`, `.ocx`, `.cpl`, `.scr`, `.tmp`,
`.dat`, `.bin` and `.ax` files up to 512 MiB in selected folders, skipping cache and
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
selected application, user and temporary folders (512 MiB limit). Windows-only live checks
do not run here; copied Prefetch and Amcache files can still be selected in targeted mode,
though compressed Prefetch needs Windows.

### Out-of-date programs (Windows and macOS)

Prevention rather than detection: the check compares the versions of common programs (Chrome,
Firefox, Thunderbird, Adobe Acrobat and Reader, WinRAR, 7-Zip, Notepad++, Java, Office, Edge,
Windows itself, macOS and Safari) with CISA's list of
[Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog),
the flaws attackers are using right now. A program is called out of date only when the official
CVE record gives a fixed version and the installed one is older; otherwise you get plain update
advice. The lists are downloaded by the indicator update; the comparison happens offline and
your list of programs never leaves the computer. An out-of-date program is not a sign of spyware,
but it is a common way in.

Apple fixes a flaw separately in each supported release line (for example iOS 18.7.3 and 26.2).
Each installed version is compared with the fix for its own line; a version on a line the record
does not list is not called out of date. The same list is used for an iPhone backup: the check
says when the iOS version the backup records is older than such a fix.

### Wi-Fi settings (Windows, macOS, Linux)

Also prevention: the check reads the computer's saved Wi-Fi settings and points out the ones that
weaken it: open networks it joins by itself (anyone nearby can copy the name), WEP, the original
WPA or its TKIP cipher, and hidden networks it keeps calling out for. On Windows the saved networks
are exported without their passwords into a private temporary folder, three settings are read
from each, and the files are deleted. On Linux NetworkManager is asked only for each network's
security type; on macOS only the network in use is checked (the saved list needs administrator
rights). No network is joined, scanned or contacted, no password is read, and the router's own
settings are not checked, because that would mean contacting it.

It also warns when a network nearby (in the computer's last Wi-Fi scan; no scan is started) uses the
name of one you saved but has no password or uses WEP: the classic "evil twin" set up to watch
people's traffic.

### Certificates and network settings (Windows, macOS, Linux)

A trusted root certificate lets whoever holds its key read this computer's encrypted web traffic.
The check compares the trusted roots with the ones the major trust programs distribute (Microsoft
and Mozilla, from the public CCADB lists) and names the others by kind: security software that
checks encrypted pages, developer tools such as Fiddler or mitmproxy, VPN apps, game launchers, or
unknown. On macOS it lists certificates given custom trust; on Linux the locally added anchors. It
also reports a system proxy or automatic proxy script, DNS servers set by hand or in ranges used by
DNS-hijacking malware, and another address on the network claiming the router's hardware address
(a sign of ARP spoofing). All local reads; each is "worth a look" with its usual explanation.

### The whole network, from its DNS log

`--dns-log FILE` checks a DNS log instead of this computer: from a router (dnsmasq), Pi-hole (its
text log or its database), AdGuard Home (`querylog.json`), BIND, Unbound, a Windows DNS server's
debug log or Zeek. Every name any device looked up, and every address in a logged answer, is
compared with the indicators offline, so phones, tablets and TVs on the network are covered without
touching them. A lookup the filter blocked is reported as an attempt, with the device's address.
It sees only the period the log covers, and not devices that use their own DNS (browsers with DNS
over HTTPS, VPNs, mobile data).

### Doors to close

Besides looking for traces of spyware, every check lists the doors left open: settings and programs that
make spying easier if someone gets the chance. Each comes with why it matters and how to close it, and in
the window an **Open this setting** button takes you straight to the right page, with **Check again** to
confirm. They are prevention advice, never findings, and never change the result.

- **This computer:** remote-access and monitoring programs (over 200: our own list - TeamViewer, AnyDesk,
  Chrome Remote Desktop, keyloggers, employee and parental monitoring products... - plus remote-support
  and management agents hand-picked from LOLRMM), and the same programs **downloaded but never installed**
  (the "download AnyDesk and read me the code" scam: a copy waiting in Downloads, Desktop or Documents is
  named by its file name, never opened), Remote Desktop / SSH /
  Screen Sharing switched on, automatic sign-in (whether a password is stored for it is noted; the
  password is never read), no password after sleep, firewall off, disk not encrypted (BitLocker, device
  encryption, FileVault, LUKS), Secure Boot / System Integrity Protection / Gatekeeper off, old SMB1 file
  sharing, extra administrator accounts. On Windows also **drivers with a known security hole or known
  to be malicious** (the installed driver files fingerprinted against LOLDrivers' verified list - the
  holes attackers use to switch off antivirus, usually brought in by a hardware or tuning tool), whether
  Microsoft's vulnerable driver blocklist is on, and whether memory integrity is actually running, not
  just set to on.
- **Browsers:** extensions that can read and change every website, and extensions known to be malicious
  (chrome-mal-ids, CC BY 4.0). Each browser's signed-in account is shown masked (`s***@gmail.com`) under
  WORTH A LOOK: a browser syncing to someone else's account sends them your history and saved passwords.
- **iPhone:** no passcode, Lockdown Mode off. **Android:** old security updates, storage not encrypted,
  Play Protect off, wireless or USB debugging left on.
- **Accounts to check yourself:** what no tool can see without signing in - Apple Safety Check, Google
  Security Checkup, linked devices on WhatsApp/Signal/Telegram, email forwarding, recovery details,
  two-step sign-in and a SIM port-out lock.

### Home network check (separate, asks first)

`--home-network` is not part of the spyware check: it is the one part of the toolkit that talks to
other devices, so it explains what it will do and asks each time. On the local network this
computer is on (private addresses only, the 256 addresses around it) it finds the devices and their
names (Bonjour/mDNS and UPnP), tries to open a connection to a short list of ports on each and
closes it at once, and reads the router's UPnP description and its list of ports opened to the
internet. It reports risky doors - Android debugging left open on a TV or phone, Telnet, camera
recorders, remote desktop and VNC - cameras on the network, and ports your router has opened. It
never logs in, tries a password or changes anything. Only run it on a network you own or are
responsible for.

It also tests whether the router's lookups are being changed - the classic sign of a router whose DNS
setting was altered by someone or by malware - without logging into it. It asks the router to look up
`one.one.one.one` and `dns.google` (whose answers never change), a made-up name under `example.com`
(which must not exist), and two names that echo back the address of the resolver the router really
uses. A wrong answer, a made-up name that comes back with an address (often an internet provider's
advert page, sometimes a hijack), or a resolver in a range used by the DNSChanger malware is reported
with what to do. These five lookups are the only part of the check whose questions leave your network
(through the router, like any lookup); the consent screen names them and `--no-router-lookups` skips
them. If the router does not answer - a VPN usually blocks this on purpose - that is reported as not
checked.

Android TV and Google TV can be checked for spyware like a phone: see
[docs/ANDROID-TV.md](docs/ANDROID-TV.md).

### Check a link or message (separate, offline)

Got a text, a WhatsApp or Signal message, or an email with a link you are not sure about? Paste it into
"More checks" > "Check a link or message" in the window, or choose "A link or message" in the start menu, or run:

    zero-breach-toolkit --check-link "the message or link"
    zero-breach-toolkit --check-message saved-message.txt      (use - to paste instead)

Nothing is opened, looked up or sent anywhere: the text is only compared. Every link in it (including
"defanged" ones like hxxps://example[.]com) is checked against the spyware indicators the scan uses, and
against tricks from documented attacks on journalists and activists:

- Signal "link a new device" links (`sgnl://linkdevice`) and fake Signal sites, used to read people's messages;
- WhatsApp QR-code and pairing-code lures ("scan to join the group", "enter this code to see the photo");
- "New WhatsApp login - terminate it" texts and look-alike messenger addresses, as used to deliver Predator;
- Pegasus-style links: short links, random short paths, random sub-domains on unusual ports;
- link shorteners, raw IP addresses, look-alike letters from other alphabets, a fake name before "@", and links
  that download an app, a configuration profile or a program.

The result is one of four: known spyware infrastructure, dangerous, worth a look, or nothing known, with what
to do next. Dangerous links are shown "defanged" so they cannot be clicked by accident. "Nothing known" does
not prove a link is safe: targeted attacks use new addresses.

### Was my phone plugged into a forensics tool?

A different question from "is there spyware on my phone". When a phone is taken at a border, a police station or
a checkpoint, what usually happens is not spyware: it is plugged into a machine that copies everything off it.

    zero-breach-toolkit --was-extracted phone-collection/

**Finding nothing here is not proof**, and the report says so every time: a successful extraction can leave no
trace at all. If a phone was out of your hands and unlocked, treat what was on it as known to whoever had it.

What it reads, from a phone collection or an iPhone backup you already have:

- **Android:** which computers are allowed to control the phone over USB - each authorised key is one computer,
  approved once by tapping "Allow", and the approval never expires; whether USB debugging is on; whether the
  bootloader is unlocked or the phone is running a debug build; side-loaded apps holding the accessibility
  permission that lets them tap through their own consent prompts; and the **fake USB devices Cellebrite's
  unlocking hardware imitates**, published by Amnesty International and matched only together with the version
  number they all reported - so a real Microsoft mouse is not mistaken for one.
- **iPhone:** what the backup says about the phone and when it was last backed up, whether it was left
  unencrypted, and the Cellebrite traces published by the Citizen Lab. An iPhone keeps its list of trusted
  computers on the phone rather than in a backup, so the report says that and how to clear it.

Each sign says what it does and does not prove - USB debugging is listed as "worth knowing", because developers
turn it on too - and being copied is told apart from being infected: a tool that copies a phone usually leaves
nothing running on it.

### Check a suspicious email

Targeted spyware usually arrives as a message, and the giveaways are in the parts an email program hides. Save
the message ("Show original" in Gmail, "View message source" in Outlook, or the `.eml` file - forwarding it to
yourself does **not** work, it loses those parts) and check it:

    zero-breach-toolkit --check-email message.eml

It reads who really sent it (the envelope sender is often not the "From:" you see), what the **receiving** server
decided about it - SPF, DKIM and DMARC, the one part of an email a sender cannot forge - whether a reply would go
somewhere else, display names that imitate a company while the address does not, every link (through the same
check as "Check a link or message"), and every attachment: programs dressed as documents, names with a hidden
character that reverses how they read, old Office formats that can carry macros, archives that hide what is
inside. It also says when a message is pushing you to act quickly, and about what.

A message that passes every check can still be a lie told from a real account someone else has taken over, so
the report ends by saying what to do rather than declaring it safe.

### Check a QR code

A QR code is a link you cannot read before you follow it. The dangerous ones are printed on stickers over real
ones, or sent as a picture "to sign in" - and the worst of them link your **messaging account to someone else's
device**, so every message you get afterwards is theirs too.

    zero-breach-toolkit --check-qr screenshot.png

The code is read from a picture on your computer - no camera, nothing opened, nothing contacted - and then
checked exactly like a pasted link, so device-linking addresses, look-alike names and known spyware links are
all recognised. The reader is written into the toolkit (PNG, GIF, BMP and PPM, no other software needed): it
handles codes that are turned, mirrored, only a pixel or two per square, and damaged - and when a code is too
damaged to repair it says so rather than guessing at the text.

### Check a suspicious file

For a file you do not trust - an attachment, a download, an app someone sent you - before you open it or hand it
to an expert. Drop it onto the program, or:

    zero-breach-toolkit --check-file invoice.pdf

The file is read, never run, opened in another program, uploaded or moved (where it was found is evidence). It
tells you, answer first:

- whether its fingerprint or any spyware address written inside it is on the indicator lists;
- what it really is, whatever its name says - and names **built to deceive**: two endings (`invoice.pdf.exe`),
  invisible right-to-left characters that make `fdp.exe` display as `exe.pdf`, or the real ending pushed out of
  sight by spaces;
- for Windows programs: who signed it and whether Windows trusts the signature, and signs of packing;
- for **shortcuts** (`.lnk`): what they really start, and whether that is a command tool with an internet address,
  a hidden window or an encoded command;
- for **archives**: what is inside without unpacking it - programs, shortcuts and disk images, scripts at the top -
  and whether it is **locked with a password** so antivirus could not look inside;
- for **disk images** (ISO, VHD/VHDX, DMG): what is inside an ISO, and that files inside lose Windows'
  "downloaded from the internet" warning;
- for **documents**: macros (including old Excel 4.0 ones), embedded programs, a **remote template** or the
  **Follina** trick that fetches something when it is opened, DDE fields, Equation Editor objects used against old
  Word, and PDF JavaScript - also when it is hidden inside a compressed part;
- for **web pages and SVG pictures**: a file built inside the browser and downloaded ("HTML smuggling"), a whole file
  hidden as encoded text, and password boxes;
- for **OneNote** files: embedded programs and scripts;
- for Android apps: the package name and what it asks to do, in plain words.

"Save a sealed copy" writes it into a ZIP protected with the password `infected` - the usual way to pass a sample to
a researcher, so the copy cannot be run or removed by accident on the way.

### Look up a file's fingerprint (offline first, online only if you say so)

"A file's fingerprint" (start menu, "More checks", or `zero-breach-toolkit --hash-lookup FILE_OR_FOLDER`)
fingerprints files and tells you who knows them:

- For every file: SHA-256, SHA-1 and MD5, and what kind of file it really is (from its contents, not its name).
- For Windows programs: the **import hash** (imphash, computed exactly as the standard pefile library does, so it
  matches values published in reports; it often stays the same across re-packed variants of one malware), and the
  **name of whoever signed it**, read from its certificate; on Windows the signature is checked, offline.
- **Offline**, every fingerprint is compared with the spyware indicator lists.
- **Online, only if you add `--online` or say yes**: the fingerprints - never the files, their names or paths - of
  programs, scripts, documents and archives that are not validly signed are sent to the services you choose:
  CIRCL hashlookup (Luxembourg, no key: is it ordinary known software?), MalwareBazaar and ThreatFox (abuse.ch,
  Switzerland), VirusTotal (Google, USA) and Hybrid Analysis (CrowdStrike, USA), the last three with **your own
  free key** (saved with `--set-lookup-key` or "Keys for online look-ups"; never on the command line). Answers are
  cached on this computer. VirusTotal's free key allows 4 look-ups a minute, so 20 files per run unless you add
  `--lookup-all`.

Results say plainly: known malicious (with family and first seen), flagged by some tools, known good, or
**unknown - which is not the same as safe**.

    zero-breach-toolkit --hash-lookup Downloads/invoice.exe --online circl,malwarebazaar

### Close the doors found open

The scan's "Doors to close" tells you what is open. This closes the ones it is safe for a tool to close, and
explains the rest:

    zero-breach-toolkit --fix-it                      lists what can be done; changes nothing
    zero-breach-toolkit --fix-it windows:firewall     does that one, after asking
    zero-breach-toolkit --undo-fix 20261110T...       puts a setting back

It can switch **Remote Desktop** off, stop **automatic sign-in**, switch the **firewall** on and remove **old
file sharing (SMB1)**. The rules it follows:

- Nothing changes unless you name the fix and say yes to a plain description of what it does and what might
  break.
- The current setting is read and written to an **undo record first**. If it cannot be recorded, the fix is not
  offered at all.
- **One change, one command.** On Windows you see Windows' own permission prompt for that single command, so
  you can see what is being run. A password is never asked for, read or passed on.
- Afterwards the setting is **read back**, and the record says whether it actually took effect.
- Anything that could lock you out or lose your data - **disk encryption, Secure Boot, removing accounts** - is
  explained for you to do yourself, never done. On macOS and Linux the exact `sudo` command is printed for you
  to run.
- On a **work or school computer** (domain, Entra/Azure AD or MDM) it changes nothing and says to ask whoever
  supports it, because a change here would be undone or break something.

### Look through Windows' own records

Windows keeps a record of a great deal that happens on it. "Windows' own records" (start menu "Look closer",
"More checks", or `zero-breach-toolkit --hunt-windows`) reads those records and looks for the handful of things
that mean someone else had control:

- a PowerShell command whose text was **hidden** (base64) - and it **decodes it**, so the report shows what the
  command actually did, not just that something was hidden;
- commands that **fetched a program from the internet and ran it**, the commonest way a computer is taken over;
- attempts to switch off Windows' script checking (AMSI) or its own logging;
- programs loaded **straight into memory**, leaving nothing on disk;
- a **service or driver installed from a personal or temporary folder**;
- **exclusions** added to Windows' "do not scan" list;
- **cleared event logs** - which does not happen by itself;
- a document (Word, Excel, a PDF reader) **starting a command interpreter**;
- WMI subscriptions, new administrators, remote-desktop sessions, failed sign-ins.

Every finding says what the record was, **what it means, and what is normal** - because most of these have
innocent explanations, and the report is written so a person can judge their own case. Routine noise (Windows
Update downloads, driver signature messages) is kept back as context unless you add `--hunt-all`. The Security
log needs administrator rights: without them the check says so rather than staying quiet (`--with-security`).

A helper can read logs from someone else's computer **on any operating system**, because the toolkit has its own
reader for Windows log files:

    wevtutil epl "Microsoft-Windows-PowerShell/Operational" ps.evtx     (on the Windows computer)
    zero-breach-toolkit --hunt-windows ps.evtx                          (on any computer)

That reader was checked record for record against Windows' own output: 21,712 records across four logs, with
every event number, timestamp and field identical.

### Check your online accounts

No program can see inside your accounts without signing in, and this toolkit never signs in to anything. But a
computer still linked to your WhatsApp, a forwarding rule in your email or a location shared from a family app is
a more common way to be watched than spyware. **More checks → Check my online accounts** (or
`zero-breach-toolkit --accounts`) walks you through twelve places to look: the devices on your Apple, Google and
Microsoft accounts, Apple's Safety Check, linked devices in WhatsApp, Signal and Telegram, where your Instagram
and Facebook are logged in, email forwarding and rules, location sharing and a lock on your phone number. For
each one you answer *checked, fine*, *something is wrong or missing* or *skip*. The result says what to do about each
thing you found, warns that removing someone's access can alert them, and lists every skipped step as **not
checked**, never as fine. You can save it.

It starts with the single best thing you can do: sign in to your most important accounts (email first) with a
physical security key such as a YubiKey. A key only works on the real website, so a fake sign-in page gets
nothing; nobody can sign in from far away without holding it; and it cannot be stolen by moving your number to
another SIM, unlike text-message codes. Buy two and add both. In the window, each step with a web page has an
**Open this page** button, and your answers are kept (in the program's own folder) until you finish or press
**Start over**.

### If you got a threat warning

Apple, Google, WhatsApp and Meta warn people they believe were targeted by mercenary spyware or government-backed
attackers. **More checks → I got a threat warning** (or `zero-breach-toolkit --threat-warning`) says what to do,
in order: make sure the warning is real without clicking anything in it, do not erase the evidence, save a copy of
the phone and check it, *then* update and turn on Lockdown Mode or Advanced Protection, and get free help.

### Send evidence to a helper

When a helpline or expert offers to look at your case, they give you an **age public key** (one line starting
with `age1`). "Send evidence to a helper" (start menu, "More checks", or the command below) puts the reports,
phone collection, screenshots or files you choose into one package that only that key can open:

    zero-breach-toolkit --package-for-helper OUTFOLDER --helper-key age1... --add report.json --add phone-folder

- It is encrypted with the standard **age** format, so the helper opens it with `age`, `rage` or their usual
  tools. An AndroidQF phone collection is kept exactly as AndroidQF wrote it, so their tools work on it unchanged.
- A list of every file and its SHA-256 fingerprint is **signed with your own sender key**, made the first time and
  kept on this computer. Encryption alone does not show who sent a file; the signature does. Read your **safety
  number** to the helper by phone or in person and they can confirm the package is from you.
- No user name or computer name goes in, the unencrypted ZIP is never written to disk, and nothing is uploaded:
  you send the file yourself, by the route the helper gives you.
- A helper with this toolkit checks a decrypted package with `--verify-package package.zip`.

Keys that start with `AGE-SECRET-KEY` are secret and are refused. `--no-encryption` makes an unencrypted package,
only for a helper who asked for one.

### What starts automatically (separate, read only)

Spyware has to start again after every restart, so it has to register somewhere. "What starts automatically"
(start menu, "More checks", or `zero-breach-toolkit --startup`) lists every one of those places in plain words:

- **Windows:** Run and RunOnce keys (per user, all users, 32-bit, policy) and whether Task Manager has each one
  switched off, the Startup folders (shortcuts and batch files resolved to what they run), scheduled tasks,
  auto-start services and drivers, and the hijack points spyware likes (Winlogon shell, debugger redirects,
  AppInit DLLs). Each program's signature is checked with Windows' own verifier, **offline** (no revocation or
  certificate download).
- **macOS:** launch agents and daemons outside /System with their signing Team ID, login and background items,
  and which apps are allowed to record the screen, see key presses, control the computer, use the camera or
  microphone, or read all files. Background items and app permissions need sudo or Full Disk Access; without
  them they are reported as not read.
- **Linux:** desktop autostart entries, enabled systemd units and cron.

Every program is fingerprinted and compared with the indicator lists. It marks as worth a look: unsigned programs
or scripts in folders any program you run can change, hidden (encoded) PowerShell, start-up commands that
download something, remote-access programs, hijacks, and entries that point to a missing program or were set up
with a path that can never run. Signed Windows components are hidden unless you add `--startup-all`. Nothing is
changed: it tells you where to switch something off.

### A phone's network recording (separate, offline)

Spyware has to send what it collects somewhere, so a recording of a phone's internet traffic can show it even
when it hides on the phone. On Android, the free, open-source **PCAPdroid** app records without root: choose
"PCAP file" as the output, use the phone normally for a day, then copy the file to the computer. Check it with
"More checks" > "Check a network recording", "A phone's network recording" in the start menu, or:

    zero-breach-toolkit --check-traffic phone.pcap

It reads .pcap and .pcapng files (PCAPdroid, Wireshark, tcpdump) and lists every server contacted: the names
looked up, the names of encrypted connections (re-assembled across packets, as modern apps send them), plain
web requests; HTTP/3 (QUIC) connections are matched by address only, because their names are encrypted and the
toolkit never decrypts anything. PCAPdroid recordings name the app behind each connection, so a match says which app it was. Every
name and address is compared with the spyware indicator lists, and the traffic is checked for contact at
regular intervals like clockwork, dynamic-DNS names and encrypted connections on unusual ports. The recording is
only read; nothing is contacted. A recording covers only the time it ran, and encrypted DNS hides look-ups.

### Hidden Wi-Fi networks nearby (separate)

`--wifi-nearby` lists the Wi-Fi networks this computer already hears and says what a hidden one probably is:
who made the device (the IEEE's public list of manufacturer codes is built in), whether it is part of the
router you are connected to (mesh systems and internet providers' routers run hidden networks for their own
units), whether it is a phone sharing its connection (a made-up address), and roughly how close it is. A hidden
network's name cannot be read without connecting to it, which the tool never does. Windows 11 asks for location
access before it shows nearby networks; macOS hides their hardware addresses, so less can be said there.

On Windows and Linux it can then **find** one hidden network: choose it and walk slowly around with the
computer - the signal is re-read every few seconds and the line says stronger, weaker or about the same. The
device is where the signal is strongest. In the terminal, type the network's number when asked; Enter or Ctrl+C
stops. `--json PATH` saves the result for the household report.

### Bluetooth trackers (separate)

`--trackers [MINUTES]` listens for Bluetooth location trackers near you - AirTag and other Find My
items, Samsung SmartTag, Tile and Google Find Hub tags - and points out any that say they are away
from their owner and stay near you, which is what a tracker planted in a bag or car does. It only
receives. The double-click programs include the Bluetooth library it needs; with the Python version,
the tool offers to install it when you first run the check (one yes; the pinned `bleak==1.1.1`, ready-made
packages only) - or install it yourself with `python -m pip install -r requirements-bluetooth.txt`. On a Mac,
allow Bluetooth when asked.
Run it again after moving: a tracker heard in both places is the one travelling with you.

### One report for the whole household

`--combine REPORT [REPORT ...]` puts the saved JSON reports of several checks on one page: each
computer, each phone (from the program or from the phone-check web page's "Save JSON"), a DNS log and
the home network check - and the smaller checks' saved results (hidden Wi-Fi, live connections, startup
items, network recordings, Windows' records, file, link, email and QR checks). One line per device, worst first, with what was found, what is worth a look
and what could not be checked - and a list of the kinds of check the house is still missing (no phone
checked, no home network check, no DNS log). Name a device with `"Mum's iPhone=report.json"`; reports
older than 30 days are flagged; a file that is not a report is listed, never silently dropped. Add
`--html house.html` for a page to print or keep. It reads files only and never replaces an existing
file.

### Making an iPhone backup

On Windows and Mac, Apple's own app makes the backup. In the window, the phone screen's **Make an
iPhone backup...** button opens Apple Devices or iTunes (Windows; the Microsoft Store if neither is
installed) or Finder (Mac), shows the steps - including ticking "Encrypt local backup", which keeps far
more of what the check needs - then watches the usual backup folders and offers **Check this backup**
as soon as Apple's app has finished writing a new one.

Linux has no Apple app, so `--make-iphone-backup FOLDER` does it: after asking, it installs the
pymobiledevice3 backup helper (GPL-3.0-or-later; about 350 MB) into its own folder under
`~/.local/share/zero-breach-toolkit/`, with every file checked against the SHA-256 hashes in
[requirements-iphone-backup.txt](requirements-iphone-backup.txt) and nothing built from source. The
helper runs as a separate program, never inside the toolkit. It turns backup encryption on with a
password you type privately (handed to the helper on its standard input, never on a command line),
makes a full backup into FOLDER and the toolkit then checks it. It needs the `usbmuxd` service
(`sudo apt install usbmuxd` on Debian/Ubuntu). If encryption was already on, the backup keeps its
existing password and you are asked for that one to check it.

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
  microphone, read notifications, resist uninstalling) and when they arrived; app stores of
  Google, Samsung, Xiaomi, Huawei, Honor, OPPO/Realme, Vivo, Amazon, F-Droid and GrapheneOS
  count as stores, and apps copied from your old phone (Smart Switch, Google restore) are not
  treated as installed by hand;
- **any** app, even from a store, that holds two or more of the powers stalkerware needs
  (reading the screen, reading notifications, resisting uninstalling, seeing which apps you
  use, drawing over other apps, recording the screen), and apps for which someone switched off
  Android's "restricted settings" protection;
- apps Cornell University's intimate-partner-surveillance research lists as stalkerware, and
  ordinary apps that are often turned on a partner (location sharing, call recording);
- a "device owner" app managing the whole phone, and an always-on VPN app;
- signs of a modified phone: unlocked bootloader, debug build, security protection off;
- signs the phone was unlocked with **Cellebrite**, the phone-forensics tool police and
  security services use on seized phones: the fake USB devices its unlocking hardware
  imitates, which the phone's own logs record (published by Amnesty International). The
  phone keeps this record for a limited time, so check a phone soon after it comes back.

It recognises the collection's own traces (USB debugging, the debugging shell's
permissions) and does not report them as suspicious.

### iPhone

Local Finder, Apple Devices or iTunes backups (encrypted or not), extracted file systems
and sysdiagnose archives. See
[Checking local iPhone evidence](#checking-local-iphone-evidence).

Installed configuration profiles are read for what they can do. A profile that manages the
phone remotely (MDM), makes it trust a root certificate (which can be used to read encrypted
web traffic), sends traffic through a VPN, proxy or another DNS server, or cannot be removed is
listed as worth a look, with its name, issuer and install date. That is normal on a work or
school phone and for a DNS filter you installed yourself; on a personal phone nobody else should
have set one up.

Crash reports and diagnostic logs are also searched for traces of **Cellebrite** published by
the Citizen Lab: a process named `mnm` working on a task labelled `com.cellebrite.bruteforce`,
and, in an extracted file system, the identifiers of a Cellebrite computer in the phone's
records of computers it trusted. An ordinary backup does not contain these records, so a
backup alone cannot show whether the phone was accessed this way; a sysdiagnose archive or a
file-system extraction can.

### Indicators

About 13,300 published indicators from 29 downloadable sources and two built-in sets: Amnesty International's Security Lab,
the [Mobile Verification Toolkit](https://github.com/mvt-project/mvt-indicators) project,
the Citizen Lab and Echap's stalkerware research, and a hand-curated set from Citizen Lab
reports (Candiru / DevilsTongue and Paragon's Graphite, and Memento Labs' Dante from
Kaspersky) with every line cited. The curated
set works offline; `--update` downloads the rest from a fixed list of official sources.
The MVT project's own indicator files (Predator, QuaDream, Operation Triangulation, Candiru,
Cellebrite, DarkSword, Coruna and seven more; MIT licence) are also **built in**, so a computer that
never runs `--update` - offline, or where GitHub is blocked - still checks against them from the
first scan; a downloaded copy is used instead when there is one. `--update` also downloads a few
**known-good lists** (MISP warninglists: empty-file fingerprints, reserved
addresses, certificate-revocation and connectivity-check hosts ...): a published indicator that is
exactly one of those values can only be a mistake in the source, so it is set aside and counted,
never matched. Exact, so a listed provider such as `duckdns.org` never hides a real
`something.duckdns.org`. The lists published today contain no such mistake; this guards against
future ones.
A second built-in set holds about 1,040 file fingerprints and Android package names of
spyware used against journalists, activists and minorities (Arid Viper against Palestinians,
EvilBamboo, MOONSHINE, HenBox, DoNot, OceanLotus, KoSpy and others, and the Massistant
phone-extraction tool), copied from the indicator files and reports of ESET, Volexity, Cisco
Talos, Meta, Unit 42, Lookout and Amnesty International (and two package names from a
SentinelLabs report), every line cited. Fingerprints are SHA-256, or SHA-1 where a publisher
gives only that.
A few published phone traces that are not addresses or fingerprints (Cellebrite's, and the
Android settings and folder of Variston's Heliconia framework, published by Google) are
built into the phone checks, each with its source.

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
git checkout v3.0.1
python build/bundle.py
python -c "import hashlib; print(hashlib.sha256(open('dist/zero-breach-toolkit.py','rb').read()).hexdigest())"
```

For v3.0.1 the file is 7,861,765 bytes, SHA-256
`524f395a014ab233140a661bbc6e39809f9572f579b7eced5b1adb15a042142f`. The size and SHA-256
published with each release are authoritative. The build is deterministic, so a matching
rebuild means the published file contains that source and nothing else. Releases are also
GPG-signed; see [docs/VERIFYING.md](docs/VERIFYING.md).

The Windows program is being set up for signing through the SignPath Foundation, whose
certificate is issued to the Foundation rather than to a person, so the project stays
anonymous; see [docs/CODE-SIGNING.md](docs/CODE-SIGNING.md). Until that is in place the
program is unsigned. An `.exe` you build yourself with
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
  of every drive, account or artifact. The 512 MiB file limit remains.
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

### Practising with a training example

Trainers need a result to show, and real spyware cannot be used for that. `--training`
checks a made-up Android phone against made-up indicators, so people can learn to read a
report before they need to. It is also in the start menu as **Practise with a training
example**, and in the window as **Practise**, where the result carries an amber
**TRAINING EXAMPLE** bar.

```text
python scan/zero-breach-toolkit.py --training spyware        # findings and evidence grades
python scan/zero-breach-toolkit.py --training worth-a-look   # leads, but no findings
python scan/zero-breach-toolkit.py --training clean          # what "nothing found" means
python scan/zero-breach-toolkit.py --training cellebrite     # a phone seized and unlocked with Cellebrite
```

The report is the ordinary report, so what people learn carries over to a real check. It
opens with **TRAINING EXAMPLE - NOT A REAL CHECK** and ends with notes for the trainer; the
JSON report has a `training` field and its first `must_relay` rule says it is an example.

- Nothing on the computer, a real phone or a downloaded indicator list is read. Options
  that point a check at real evidence or real indicators are refused with `--training`.
- Every indicator is invented: the domain uses the reserved `.invalid` ending, which can
  never exist, and the family is named "Training example (not real spyware)".
- The `cellebrite` example is the exception, because its point is to show the real result.
  Its made-up phone log records one of the fake USB devices Cellebrite's unlocking hardware
  imitates, which the ordinary phone check recognises by itself. The serial number and the
  rest of the log are invented.
- A sharing summary or evidence bundle cannot be made from it, because both are meant to
  be sent to someone.
- The example is built in the temporary folder and deleted when the tool exits.

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

The window always exits with 0 when it is closed, whatever it showed; for scripts and
automation use the terminal commands, which return the exit codes below.

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

### Blocking advertising domains

The `dist/` folder of this repository holds the project's own blocklist of the advertising
and tracking domains named in the indicators, in three formats: `adfection.adblock.txt`
(for ad blockers such as uBlock Origin), `adfection.hosts.txt` (a hosts file) and
`adfection.dnsmasq.conf` (for dnsmasq, many routers and Pi-hole style resolvers). Blocking is
a stopgap: it does not detect infection. The page
[archivegenocide.com/scan](https://archivegenocide.com/scan/) has a test and setup steps for a
blocking DNS resolver.

## Privacy

`--update` downloads indicator sources, and also asks GitHub for the latest release number so
it can tell you when a newer version exists (`--no-version-check` turns that off; it never
happens during a scan). The separate `--collect-android` command downloads
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
licences in [third_party/candiru](third_party/candiru/README.md). Built-in copies of the MVT
project's indicator files (MIT), and data taken from LOLRMM and LOLDrivers (Apache License 2.0),
keep their notices in [NOTICE](NOTICE) and `third_party/`. Indicator and known-good lists downloaded
by `--update` remain under their publishers' terms and are not part of this repository.
