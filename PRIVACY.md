# Privacy

Zero Breach Toolkit runs entirely on your computer.

- **A scan makes no intentional network requests and has no upload feature.** A guard refuses
  Python socket calls, and local-path checks refuse redirected files and Windows remote drives.
  It never resolves or visits indicator addresses. These guards are not an operating-system
  network sandbox: POSIX network mounts and concurrent filesystem changes remain limitations.
  Use operating-system network isolation when strict offline execution is required.
- **`--update` uses the network only when you run it.** It downloads published indicator
  lists from a fixed allow-list of sources (the MVT project, Amnesty International, Echap and the
  Citizen Lab on raw.githubusercontent.com). It also downloads CISA's list of actively exploited
  vulnerabilities from www.cisa.gov and, for a short list of common programs, the matching official
  CVE records from the CVE Program's repository on raw.githubusercontent.com. It sends no information
  about you or your computer beyond what any web download sends (your IP address reaches GitHub and
  CISA); in particular it never sends the list of programs installed on your computer. The
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
