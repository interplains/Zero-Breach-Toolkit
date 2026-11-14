# Privacy

Zero Breach Toolkit runs entirely on your computer.

- **A scan makes no intentional network requests and has no upload feature.** A guard refuses
  Python socket calls, and local-path checks refuse redirected files and Windows remote drives.
  It never resolves or visits indicator addresses. These guards are not an operating-system
  network sandbox: POSIX network mounts and concurrent filesystem changes remain limitations.
  Use operating-system network isolation when strict offline execution is required.
- **`--home-network` is a separate check that does use the local network, and asks first.** It
  sends a small packet to each of the 256 addresses around this computer (private addresses only),
  asks for Bonjour/mDNS and UPnP announcements, opens and immediately closes a connection to a short
  list of ports on each device it finds, and reads the router's UPnP description and port-mapping
  list. It sends no data to those ports and tries no password. To test whether the router's lookups
  are being changed it asks the router to look up five fixed names (`one.one.one.one`, `dns.google`, a
  made-up name under `example.com`, `whoami.akamai.net`, `o-o.myaddr.l.google.com`); the router passes
  these on to the internet like any lookup, so they are the only part of the check that leaves your
  network, and `--no-router-lookups` skips them. Google's answer also contains part of your own
  address: the program discards that part and keeps only the resolver's address. Cameras with
  their video port open are asked, without any password, whether they hand out their video
  stream; only the stream's description is read, never the video (`--no-camera-check` skips it).
  Its report names the devices on your network; keep it private.
- **The scan's "Doors to close" checks read settings and never change them.** They read whether
  Remote Desktop, automatic sign-in, disk encryption and the firewall are on, which remote-access or
  monitoring programs are installed, which file names in your Downloads, Desktop and Documents folders
  belong to one (only names are compared; no file is opened), on Windows a fingerprint of each installed
  driver file (computed on your computer and compared with a built-in list; nothing is sent), and which
  browser extensions can read every site. For
  automatic sign-in only whether a password is stored is noted - the password is never read. Each
  browser's signed-in account is shown masked (`s***@gmail.com`) so you can tell whether it is yours.
- **`--combine` reads the saved reports you give it and contacts nothing.** The household report it
  makes repeats their findings; keep it as private as they are.
- **`--make-iphone-backup` (Linux) downloads a backup helper only when you run it and agree.** It
  installs pymobiledevice3 and its dependencies from the Python Package Index (pypi.org and
  files.pythonhosted.org), each file checked against a pinned SHA-256 hash, into its own folder. The
  helper then talks only to the iPhone connected by cable. The backup is a full private copy of the
  phone, written where you choose; delete it after checking if you do not want to keep it. The
  window's **Make an iPhone backup...** button (Windows and Mac) only opens Apple's own app and reads
  the backup folders; it downloads nothing.
- **`--trackers` only receives Bluetooth advertisements**; it sends nothing to the trackers and
  nothing leaves the computer.
- **`--check-link` / `--check-message` (and "Check a link or message") contact nothing.** The text you
  paste is only compared with the indicator lists and with known tricks: no link is opened, no name is
  looked up, and nothing is sent anywhere. The pasted text is not saved unless you ask for a JSON report.
- **`--hash-lookup` is offline unless you add `--online` (or say yes in the menu or window).** Online, only
  fingerprints (SHA-256, and SHA-1 for CIRCL) are sent - never files, file names or paths - and by default only for
  programs, scripts, documents and archives that are not validly signed, to the services you named: CIRCL
  (hashlookup.circl.lu, Luxembourg), abuse.ch (mb-api.abuse.ch / threatfox-api.abuse.ch, Switzerland), VirusTotal
  (www.virustotal.com, USA) and Hybrid Analysis (hybrid-analysis.com, USA). Each service sees your IP address and
  the fingerprints; a fingerprint of a file only you have tells the service you have it. Your keys and the answer
  cache are kept in your user settings folder.
- **`--package-for-helper` writes one file and sends nothing.** It reads only the files and folders you add,
  encrypts the package for the helper's key and signs its file list with a sender key it creates in your user
  settings folder (`ZeroBreach` / `zero-breach`); that key never leaves the computer and is never put in a
  package. The package holds private data: keep it private until it is sent, and delete it once received.
  `--verify-package` reads a package and contacts nothing.
- **`--was-extracted` reads the collection or backup you give it.** It never touches a phone and contacts
  nothing. Its report names the computers a phone was allowed to trust and the apps on it, so keep it private.
- **`--check-email` reads the message you give it and contacts nothing.** No link is opened or looked up, no
  address is checked with anyone, and the message is not sent anywhere. The report quotes the message's own
  headers and its links, so it is as private as the email.
- **`--check-qr` reads the picture you give it and contacts nothing.** It never uses a camera, never follows the
  code, and never looks up what it says.
- **`--fix-it` is the one part of the toolkit that changes this computer, and only when you name a fix and
  say yes.** It contacts nothing. The previous setting is saved in an undo record in your user settings folder
  (`ZeroBreach` / `zero-breach`, under `fixes`) so it can be put back; those records hold setting values, not
  personal data. No password is read, asked for or stored, and nothing is changed on a computer your
  organisation manages.
- **`--hunt-windows` reads Windows' records and contacts nothing.** Those records are a detailed history of
  this computer: commands that were run, programs that started, who signed in and when. The report quotes the
  records it flags, including command text, so keep it as private as the computer itself. Given log files, it
  reads only those files.
- **`--startup` reads start-up settings and contacts nothing.** Signatures are checked with the operating
  system's verifier with revocation and certificate downloads switched off (Windows) or with `codesign`, which
  does not ask Apple about notarization (Mac). On a Mac the app-permission databases are copied to a temporary
  folder, read, and deleted. Nothing is changed.
- **`--check-traffic` reads the recording you give it and contacts nothing.** A network recording holds a
  record of everything the device did online during it: keep the recording and the report private.
- **`--dns-log` reads the log files you give it and contacts nothing.** A DNS log is a record of
  what everyone on the network looked up: the report lists only the matches, but keep the log and
  the report private.
- **`--update` uses the network only when you run it.** It downloads published indicator
  lists from a fixed allow-list of sources (the MVT project, Amnesty International, Echap and the
  Citizen Lab on raw.githubusercontent.com), and known-good lists from the MISP warninglists project
  in the same place, used only to set aside published indicators that can only be mistakes. It also downloads CISA's list of actively exploited
  vulnerabilities from www.cisa.gov and, for a short list of common programs, the matching official
  CVE records from the CVE Program's repository on raw.githubusercontent.com, and the IEEE's public
  list of network-device manufacturers from standards-oui.ieee.org (used only by the home network
  check to name devices). It sends no information about you or your computer beyond what any web
  download sends (your IP address reaches GitHub, CISA and the IEEE); in particular it never sends
  the list of programs installed on your computer or the devices on your network. The
  update also asks GitHub (api.github.com) for the number of the latest release, and says so if
  a newer version exists; that is the only time it does, never during a scan, and
  `--no-version-check` turns it off.
- **`--collect-android DIR` is a separate acquisition command.** After explicit owner consent,
  it downloads a pinned official AndroidQF binary from GitHub's release hosts and verifies
  SHA-256 before launching it. AndroidQF communicates with the connected phone and has its
  own behavior and privacy terms. Acquisition changes phone state and saves records in the
  chosen output directory; this is outside the offline scan guard. Plaintext ZIPs are
  extracted locally for checking. With public age recipients, encrypted archives remain
  encrypted for separate analysis. No collection is uploaded by this toolkit.
- **The ad-blocking test in the start menu runs in your browser, not in this tool.** Only
  a browser can test what that browser blocks. After you say yes, the tool hands the page
  address (`https://archivegenocide.com/scan/`) to your default browser, and the browser
  loads it like any other site. The tool itself makes no request and passes the page
  nothing about you, this computer or any scan result.
- **The report is written to a local path you choose.** The launchers save it in a
  `findings` folder next to the toolkit; if that folder is inside OneDrive or iCloud, the
  scanner says so before the check starts, because the sync client would upload it. The
  report can contain your username, browser profile names, paths, browsing details, SMS
  senders and message excerpts. Share full evidence
  only with someone you trust, by a secure route. Avoid cloud-synced output folders if you want
  to keep it solely on the device; this tool does not control other software's syncing.
- **`--share-json PATH` writes a minimal sharing summary.** It contains counts, scope labels, verdict and fixed
  advice, without indicator values, artifact text, paths, profile names or timestamps. It does
  not replace the full report. Review the summary before sharing it.
- **`--report PATH` saves the readable report.** The interactive follow-up can save reports
  and summaries after displaying the check's results. Leaving the start menu produces no scan report.
- **Evidence bundles are private and unencrypted.** `--evidence-bundle PATH` writes a new
  local ZIP with the full report and manifest. Only explicitly selected `--evidence-file`
  originals are added; recorded paths never automatically select files. The interactive
  flow previews the selection and asks before exporting. Nothing is uploaded. Originals
  may contain complete browser or message databases; share them only with a trusted
  recipient through an agreed secure channel. Files reflect export-time bytes, not retained
  scan snapshots. SHA-256 hashes support integrity checks, not source authenticity.
- An offline scan does not reconfigure your system, quarantine evidence or install software.
  The separate acquisition command downloads its collector and writes the requested collection.
- Temporary snapshots can contain complete browser database bytes, including data not queried
  by the scanner. They are removed after use; interrupted runs or cleanup failures can leave
  copies in the system temporary directory. The standalone scanner also writes temporary
  embedded indicator files. Requested reports remain until you remove them.

Third-party tools the program can optionally point you to (for example MVT or AndroidQF) have their own
privacy terms; they run only if you choose to run them.

## The phone check web page (archivegenocide.com/scan/phone/)

- The page loads its checker (about 17 MB) from the site once, and checks every file against the
  SHA-256 values in `files.json` before using it. That download is the only network traffic.
- The check runs in a Web Worker that the site serves with its own security policy
  (`default-src 'none'; script-src 'self' 'wasm-unsafe-eval'`): the browser refuses its data
  requests (fetch, XMLHttpRequest, WebSocket and the like) to any address, including the site
  itself, and the worker removes those functions as well. The one kind of request that policy
  still allows is loading a script file from this same site, and nothing the checker reads is
  ever put into such a request. Before it opens anything you chose, the worker tries a request to
  the site and shows whether the browser blocked it; on a copy of the page served without that
  policy it says the lock is missing instead of claiming it.
- Your backup folder is read where it is, in pieces, only when a check needs a record. Nothing is
  copied off your computer. Decrypted records exist only in the worker's memory and are gone when
  the page is closed or the check is stopped.
- The backup password is typed into the page and used only inside the worker to unlock the backup.
  It is not stored, logged or sent anywhere.
- Your browser may describe choosing a folder as "uploading" it; that is its standard wording for
  letting a page read a folder.
- Reports you save are created in your browser and downloaded to your computer; nothing is sent.
- The page uses the indicator lists built into its version and the list of actively exploited
  vulnerabilities as of the page's build (its date is shown at the foot of the page).


Phone-backup passwords are entered through a private terminal prompt, not command-line
arguments, environment variables or report fields. They are used only to read the selected
local backup. Python cannot guarantee secure erasure of password or plaintext memory.
The iPhone reader creates temporary plaintext database copies on local disk
and removes them after use; interruption or cleanup failures can leave copies. No optional
snapshot retention was added. Acquisition and archive extraction are separate from scanning, described by `--phone-guide`
and available through the explicit `--collect-android` command.

Indicator-context and related-record fields belong to the full report and may contain
sensitive artifact locations. They are excluded from the minimal sharing summary.

Sharing summaries retain only fixed scope labels and cancellation state, without target paths.
Requested JSON outputs use temporary files beside the destination and complete-file replacement.
Acquisition encryption requests refuse plaintext results before extraction. Envelope checks
cannot authenticate ciphertext or prove recipient ownership; decryption is a separate step.
On acquisition failure, original/partial collector output is retained with its location reported
and may contain unencrypted records. The helper attempts to remove its newly created incomplete
analysis directory. Cleanup failure is reported; cleanup is not secure erasure.
