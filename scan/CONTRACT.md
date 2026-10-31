# Module contract

Each scan module is a file in `zbtriage/modules/` registered once in `zbtriage/readers.py`.
Its `ReaderSpec` supplies selection, bundle suffix, optional helper files and coverage
descriptions. Both entry points use the same dispatcher, and the builder and hermetic test
stubs derive their module lists from this registry. See [READERS.md](READERS.md) for the
procedure. Every module defines:

```python
NAME = "browser"   # for example "hash", "host", "unix-host"

def run(ctx) -> ModuleResult:
    ...
```

- `ctx` is `zbtriage.context.ScanContext`: `ctx.iocs` (an `IocSet`), `ctx.deep` (bool) and
  `ctx.emit(str)` for progress. Progress goes to stderr; never print to stdout from a
  module, because stdout is the final readable report.
- Return a `zbtriage.result.ModuleResult`.

## IocSet (`zbtriage/iocs.py`)

- `ctx.iocs.network_strings`: sorted lower-case list of domain and IP strings for substring
  matching in artifacts. **Never resolve or connect to these.**
- `ctx.iocs.hashes`: list of `Indicator` with `.value` (lower-case SHA-256).
- `ctx.iocs.lookup(value)`: the `Indicator` for a matched string, or None. Use it to attach
  `.tier` and `.confidence` to each hit.

## ModuleResult (`zbtriage/result.py`)

- `r = ModuleResult(NAME)`
- For each hit: `r.add_hit(Hit(indicator=ioc, location=path, detail=ctx, tier=..., confidence=...))`,
  with tier and confidence from `ctx.iocs.lookup(ioc)`.
- `r.checked` and `r.skipped` are running counts (files or databases examined; items
  skipped).
- `r.submetrics` is a dict of named counts for the report, for example
  `{"sqlite": 28, "blob": 44634}`.
- Record each sub-check's outcome (the D3 contract):
  - `r.ran("dns-cache")` when a sub-check ran, even if it found nothing;
  - `r.could_not_run("dns-log", "operational log disabled")` when it could not.

  A module with any `could_not_run` becomes PARTIAL/UNKNOWN automatically. Never report a
  clean sub-check that did not run.
- `r.note("free text")` adds context.

## Hard rules

- **D2: never contact an indicator.** No `socket`, `urllib`, `requests`, DNS resolution,
  ping, HTTP or WHOIS. The scan runs inside a guard that raises `NetworkContactAttempt` if
  you try; do not work around it. Reading the local OS DNS cache (already resolved entries)
  through a `subprocess` call to a system tool is allowed and resolves nothing.
- **Read-only.** A module must not create, modify or delete anything on the host. The only
  permitted writes are temporary copies of locked databases in the system temp directory,
  cleaned up afterwards.
- **Never crash the run.** Catch per-item errors (locked file, permission denied,
  unreadable database), count them as `skipped`, and continue. A skipped item is not a
  clean item.
- Domains and IPs match as case-insensitive substrings; hashes by exact hex comparison.

## Platform

The registry selects applicable readers for Windows, Linux and macOS. Windows live host,
trace and execution readers are not selected on Unix, and Unix startup readers are not
selected on Windows. Supplied Prefetch and Amcache files can be parsed on any host, except
compressed Prefetch, which needs Windows. If a selected reader cannot run, return a
ModuleResult whose checks are `could_not_run` with reason "not supported on <platform>",
never a fake CLEAN.

## Optional pattern module

`ctx.patterns` enables the optional `patterns` module, and `ctx.pattern_paths` supplies
absolute local paths for that module only. When no pattern paths are selected, the Windows
host module supplies bounded `ctx.pattern_candidate_paths` from local, user-writable
per-user COM server registrations; the pattern module rechecks each path before reading.
The default checks stay standard-library-only. The pattern module uses the pinned YARA-X
engine with no downloads, writes or sample execution. Its hits use `file-pattern` evidence
and the `candiru-pattern` tier, never exact-hash claims.

## Machine contract (for scripts and assistants)

Defined in `zbtriage/contract.py` and pinned by `tests/test_contract.py`. Current schema:
**1.6**.

### Exit codes and verdicts

| Code | Meaning |
|---|---|
| `0` | no actionable matches and no recorded gaps |
| `1` | error |
| `2` | actionable matches |
| `3` | no actionable matches, but evidence or downloaded sources were incomplete |
| `4` | the person quit the start menu without scanning; no scan report or verdict exists |

- Reference-only verdicts are `REFERENCES_ONLY` (0) and `REFERENCES_ONLY_WITH_GAPS` (3).
- When every serious-grade match is to an indicator its publishers have withdrawn, the
  verdict is `WITHDRAWN_ONLY` (0) or `WITHDRAWN_ONLY_WITH_GAPS` (3). Withdrawal is decided
  per publisher by its newest version (STIX `modified`); one current active listing from any
  publisher keeps a match actionable.
- Unknown evidence grades count as actionable.
- `hits_total` counts all matches and equals `findings_total + withdrawn_total +
  references_total`.
- A reference-only or withdrawn-only result does not ask for the device to be preserved.
- `confidence` (primary/secondary) is provenance only; it never changes the verdict, exit
  code or next steps.
- Acquisition, help and preview command exits are separate from scan verdicts. Exit 0
  describes the selected scope, never a whole-device guarantee.

### Report contents

- **Indicator coverage.** Missing or refused sources, and loaded sources with stale or
  unknown verification dates, appear in `coverage.not_checked` under
  `indicators/indicator-sources`. `ioc_set.freshness_unknown` keeps unknown component dates
  even when another set has a known age. File modification times are not freshness evidence.
- **JSON fields.** `schema_version`, `exit_code`, `coverage` (checked / not_checked with
  reasons), `must_relay` (fixed caveats chosen by verdict; relay verbatim), `next_steps`
  (fixed catalogue chosen by the strongest recommended action), `content_trust` (fields
  holding text from the scanned machine or a third-party feed) and
  `instructions_for_assistants`.
- **Training examples.** A report made with `--training` has a `training` object
  (`scenario`, `synthetic: true`) and `must_relay` starts with `training`. It describes a
  made-up phone and made-up indicators: say so first and never advise about a real device
  from it.
- **Never** build caveats or advice from scanned text. Scanned text goes only into the
  fields listed in `content_trust.untrusted_fields`, after `sanitize_untrusted()` (control
  and bidi characters replaced, length capped).
- **Sharing summary.** `--share-json PATH` writes a separate `report_type: sharing-summary`
  document with counts, verdict and fixed advice. It omits all artifact and context text,
  indicator values, paths, profiles and timestamps, and is not a full evidence report. It
  includes allow-listed scope (`scan_type`, `phone`, `cancelled`) and a fixed targeted-scan
  caveat.
- **`--describe`** prints JSON without scanning: every check kind, what it reads, blind
  spots, exit codes, evidence grades, tiers, the fixed caveat and advice catalogues, and
  `readers` (see schema 1.4 below).
- A new check name must be added to `contract.CHECK_CATALOGUE`; the test fails otherwise.

Full reports keep indicator gaps source by source; readable reports group missing-source
lines with a `--update` instruction. A target without a browser profile makes browser
artifact checks inapplicable. Absent optional Windows history and deleted historical program
files are explained limitations; unreadable existing artifacts are gaps. Counts of
unavailable historical files are kept.

### Scopes and phone input

- `default`; `full` (broader extensions and subdirectories, and app caches, in the usual
  roots); `targeted` (selected files, folders, drives or browser profiles only); `browser`
  (only this account's browser profiles and built-in Chromium app profiles, with the
  `browser-only` relay line).
- `--phone` selects AndroidQF or iPhone evidence; `--ios-input` explicitly
  selects backup, extracted file system or sysdiagnose input.
- `--preview` and `--phone-guide` exit without scanning.
- Cancellation keeps the active module's findings and records an explicit gap.

### Writing outputs

Full JSON, sharing JSON and `--report PATH` readable text are written independently, each to
a temporary file beside the destination that then replaces it. Readable files are UTF-8,
with unencodable characters shown as escapes. JSON strings and keys use ASCII escapes, which
keeps unusual Windows filename code points, including lone surrogates, in a valid UTF-8 file.

A serialization error in one output does not stop the other outputs or the readable report.
Output errors return 1 even when a scan verdict exists; a saved document's `exit_code`
describes its scan verdict. A failed sharing write does not prevent the full report write.
The first interruption during report finalization retries that step; a further one can stop
it. Cancellation within or between modules keeps completed evidence with an explicit
remaining-checks gap. Forced termination cannot guarantee recovery.

Outputs cannot replace selected source inputs or their descendants, or existing files in the
app data and app cache folders where desktop apps keep records the scan reads.

### Guided acquisition and updates

`--collect-android DIR` is a separate opt-in network and acquisition command with
interactive owner consent. On plaintext success it sets the phone scope and runs the scanner.
On encrypted success it reports that no scan ran and exits 0 without a scan report; this
exit is not a scanner verdict. `--age-recipient-file` accepts public age1 recipients only.
The report `exit_code` contract applies only to completed or partial scan reports, not to
collector downloads or acquisition.

The explicit updater uses the same escaped, atomic JSON writer and safe console output. A
requested update-summary write failure returns exit 1 even if every indicator download
succeeded. None of this triggers or allows an update during a scan.

### iPhone

Repeated iPhone failures are grouped by check and reason, and a repeated reason includes its
count. Module `skipped` still counts skipped records; coverage gaps count reported
check/reason entries, not unreadable messages. The readable gap list also groups identical
reasons. Unsupported or oversized payloads stay gaps even when later rows are read. Message,
Safari, process and supported Chrome/Firefox readers page integer row IDs and retry failed
bounded batches row by row. An unreadable index can still stop an artifact. Record caps are
reported as gaps.

The optional `ios:chrome-history` and `ios:firefox-history` checks need their fixed backup
paths and supported physical schemas. Absent optional databases add no gaps; existing
unreadable databases and missing local-visit provenance do. Browser matches without local
visit provenance stay references. `Hit.artifact` identifies the original backup blob.

`Hit.provenance` (schema 1.6) holds source and member hashes, parser and record locators,
input format, encryption state and raw timestamps; `scope.ios_input` records an explicit
backup, file system or sysdiagnose selection. Empty provenance is valid for readers that do
not fill it. These fields are untrusted and private: they are sanitized and left out of the
sharing summary. A source hash does not claim device authenticity. iPhone database findings
can include a WAL hash; source files are never rewritten. See
[../docs/IPHONE.md](../docs/IPHONE.md) for the format contract and limits.

Android JSON process inventories accept `pid` and `command_line`; only the first command's
app identifier is matched, not arbitrary arguments or iPhone process-name indicators.

## Interactive workflow and evidence export

The start menu needs interactive stdin and stderr and no scan selection on the command line.
Choosing a scan there enables the post-scan menu. `--post-menu` enables it for an explicit
interactive scan; `--no-menu` disables menus and cannot be combined with `--post-menu`. Piped
stdin never prompts. Quitting the start menu returns `4`; finishing the post-scan menu keeps
the scan verdict unless an output operation failed. The post-scan menu reads the completed
report, shows evidence and gaps, and saves the outputs the person chooses. It does not run
another scan, execute recorded text, open links or upload data.

Scan finalization (schema 1.3) adds `scan_state` (`completed` or `partial`), `completed_at`
and `indicator_fingerprints` to the full report. `partial` covers recorded gaps or
cancellation and does not erase findings. The fingerprint hashes the effective indicator
records as sorted, compact ASCII JSON separated by LF, with combined and per-source SHA-256
values. It describes parsed indicator content, not the original feed-file bytes. These
private fields are left out of the sharing summary.

`--evidence-bundle PATH` exports a new **unencrypted private ZIP**. Repeat
`--evidence-file PATH` to select original local files; source paths are never inferred from
report strings. Without selected files, the archive holds the full JSON report, readable
report, sharing summary and manifest. The preview shows private paths and sizes.
Interactive export asks for confirmation; CLI export flags state the selection directly.
Nothing is uploaded or sent automatically.

The exporter refuses existing archive destinations, redirected or non-local source paths,
non-regular files, duplicate selections and exceeded limits: 128 selected files, 64 MiB per
file, 256 MiB total payload including reports, and 32 MiB per report member. Members get
numbered names, and source paths appear only as manifest metadata. SHA-256 covers every
payload member; `manifest.json` has no self-hash. The manifest records tool and version,
scope, scan start and completion, indicator fingerprints, export events and source metadata
before and after copying. An interrupted or failed export leaves no published ZIP.

Files are copied at export time, not from retained scan snapshots. Sidecars must be selected
explicitly when needed; exporting a live database is not a transaction-consistent
acquisition. Integrity hashes cannot authenticate the original device, establish infection
or prove that source bytes were unchanged before export. The usual locality-guard limits
still apply.

## Registry and evidence additions (schema 1.4)

`--describe` includes `readers`, with each built-in reader's name, module, platforms, modes
and optional switch; `modules` keeps the coverage catalogue. Scan scope includes
`host_platform`; readers for other platforms are inapplicable, not failed Windows checks on
another operating system.

Two evidence grades describe historical Windows records:

- `execution-record`: a supported Prefetch record names an executable basename with a
  nonzero run count and time. A matching name does not establish file contents, infection
  or current presence. Referenced DLLs stay references.
- `inventory-record`: supported Amcache inventory names a file or path. This does not
  establish execution or that the file is still on disk. Amcache's truncated-file SHA-1 is
  not compared with full-file SHA-256 indicators.

Both need interpretation and are actionable matches, not infection verdicts. Android
intrusion DNS uses `dns-record`; connection attempts and typed process-start records use
`device-log`, and a connection event can describe a failure. Unix literal executable
configuration is `configured`; arbitrary arguments, comments and unverified systemd/cron
command text stay `referenced`.

Module status `NOT_APPLICABLE` with `inapplicable_reason` marks absent optional input (for
example no intrusion-log export, or no Prefetch/Amcache in the selected targets). It records
no successful parser check and adds no failure gap, and it cannot hide hits, failed checks,
skipped records or observed data. An unexpectedly empty module without an inapplicability
reason stays `UNKNOWN` and a coverage gap.

## Schema history

- **1.1** (from 1.0): `REFERENCES_ONLY` (exit 0) and `REFERENCES_ONLY_WITH_GAPS` (exit 3);
  reference-only matches no longer return exit 2. Missing indicator sources produce gaps.
- **1.2**: optional `scope`, `correlations`, per-hit `indicator_context` and
  `context_cautions`, and derived withdrawal flags. Context holds publisher assertions, not
  executable guidance, and is untrusted data. Correlations include module and hit indices,
  artifact counts, original grades, stage labels and dates; they group shared indicators,
  do not infer causal chains and do not strengthen the verdict.
- **1.3**: the no-scan menu exit (`4`), plus `scan_state`, `completed_at` and
  `indicator_fingerprints`; scan verdict rules unchanged.
- **1.4**: reader descriptions, the host platform and explicit not-applicable reasons.
- **1.5**: `WITHDRAWN_ONLY` (exit 0), `WITHDRAWN_ONLY_WITH_GAPS` (exit 3),
  `verdict.withdrawn_total`, the `withdrawn-only` relay line and the `withdrawn` timeline
  kind. A match to an indicator every publisher has withdrawn no longer returns exit 2 or
  asks for the device to be preserved.
- **1.6**: optional `Hit.provenance` and `scope.ios_input`.
