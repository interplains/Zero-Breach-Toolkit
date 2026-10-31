# Zero Breach Toolkit: scanner

A local, read-only check for published mercenary spyware indicators that reports missing
evidence and checks that could not run. See the [project README](../README.md) for
installation, phone support and scope, and [PATTERNS.md](../docs/PATTERNS.md) for the
optional Candiru pattern check.

On Linux and macOS, run `python3 scan/zero-breach-toolkit.py` from the project root, or
`sh scan/run-scan.sh`. Browser and file checks and native startup-configuration readers are
available there; Windows live checks run only on Windows. Copied Prefetch and Amcache files
can be checked in targeted scope; compressed Prefetch needs Windows.

## What it tells you, and what it cannot

It answers two questions:

1. Are published indicators present in the places this machine can actually be checked?
2. What evidence survives, and what could not be checked?

**A clean result means "no known indicators were found in the places that could be
checked." It does not mean the device is clean.** Spyware of this grade is built to defeat
this kind of check. The tool says so on every run, and a check that could not run is
reported as `UNKNOWN`, never as clean. A gap and a clean result are different answers and
are never merged.

If you have a concrete reason to suspect this machine, you need expert forensics, not this
tool:

- [Access Now Digital Security Helpline](https://www.accessnow.org/help/)
- [Amnesty International Security Lab](https://securitylab.amnesty.org/)
- [The Citizen Lab](https://citizenlab.ca/)

## Running it

No dependencies beyond Python 3.8+, and no installation.

```
cd scan
python -X utf8 zero-breach-toolkit.py
```

```
python zero-breach-toolkit.py [--quick] [--phone FOLDER] [--json PATH] [--share-json PATH] [--iocs PATH]
```

| Flag | Effect |
|---|---|
| *(none)* | interactive start menu; non-interactive input runs the standard check |
| `--no-menu` | disable the start and follow-up menus |
| `--post-menu` | inspect evidence, review gaps and export after an explicit interactive scan |
| `--report PATH` | also save the readable report |
| `--json PATH` | also write the machine-readable report |
| `--share-json PATH` | write counts, scope labels, verdict and fixed advice, without target paths, artifact text or indicator values |
| `--evidence-bundle PATH` | create a new private, unencrypted ZIP of reports and provenance |
| `--evidence-file PATH` | add an original local file to the evidence ZIP; repeatable |
| `--quick` | skip file fingerprinting (about half the runtime); the skip is reported as a gap, not as clean |
| `--scan-type default\|full\|targeted\|browser` | choose the scope; `targeted` takes one or more `--target PATH` |
| `--preview` | show the scope without scanning |
| `--extended-windows` | also read existing Sysmon and Security logs, without enabling them or elevating |
| `--iocs PATH` | use an explicit indicator file instead of the curated sets and downloaded cache; repeatable |
| `--update` | refresh published sources in the local cache (separate network step) |
| `--phone FOLDER` | read an AndroidQF folder or a local iPhone backup |
| `--phone-guide android\|ios` | print preparation steps |
| `--training [spyware\|worth-a-look\|clean]` | practise on a made-up phone with made-up indicators; reads nothing real, labels every output as training, deletes the example afterwards |
| `--backup-password` | prompt privately for an encrypted phone backup's password |
| `--patterns` | opt-in, bounded check against two published Candiru file rules; needs Python 3.9+ and the pinned optional YARA-X wheel |
| `--pattern-path ABSOLUTE_PATH` | file or folder for the pattern check; repeatable, requires `--patterns` |

Exit codes: `0` no actionable matches and no recorded gaps; `2` matches beyond saved
references; `3` no actionable matches but evidence or indicator sources were incomplete;
`1` setup, argument or output error; `4` the start menu was left without scanning or
creating a report. References stay visible and use `0` or `3`.

Default checks change no system settings and need no administrator. `--scan-type full`
broadens file and app-cache coverage in the usual roots. Locked SQLite databases may be
copied to temporary snapshots, which are removed after use. Only the reports you request
are written. See [coverage](../docs/COVERAGE.md) for what each check reads and its limits.

### Main modules

| Module | What it reads |
|---|---|
| `browser` | history, cookies, favicons, HTTP cache, LevelDB and Service Worker caches in every profile of the supported Chromium-based and Firefox-based browsers, Safari on macOS, and desktop apps with a built-in Chromium browser. Locked databases are copied before being opened. |
| `hash` | SHA-256 of candidate files, compared with the sample hashes in the indicator set. On Windows the roots are AppData, ProgramData, both Temp folders, Downloads, Desktop, Documents and Public. |
| `host` | on Windows, per-user COM registrations (this chain's documented persistence), the DNS resolver cache and up to 50,000 recent retained DNS-history events (older events are an explicit gap); the hosts file on Windows, macOS and Linux. |
| `patterns` (optional) | file bytes checked against two published Candiru research rules. Without an explicit pattern path, it first checks up to 128 local user-writable COM server files. A match needs investigation and cannot confirm infection. |

`--describe` lists every reader, including the Windows trace and execution readers, the
Linux/macOS startup and shell readers, and the Android and iPhone readers.

The browser module reads caches as well as history because history records only top-level
navigations. An ad is a subresource inside an iframe, so a real impression never appears in
history. Caches, cookie stores and LevelDB files do record subresource origins, and they are
short-lived, which limits how far back any of this can see.

## Turning on DNS history

On Windows, `Microsoft-Windows-DNS-Client/Operational` is disabled by default, so most
machines have no DNS history at all. That is why the 2024–2025 period in which devices at
Al Jazeera were targeted cannot be checked retrospectively. It cannot be fixed backwards,
but it can be fixed forwards with one command, which the report prints when it finds the
log disabled:

```
# in an Administrator PowerShell
wevtutil sl Microsoft-Windows-DNS-Client/Operational /e:true /ms:67108864
```

`/e:true` turns the log on; `/ms` sizes it to 64 MB so it holds months rather than hours.
Turn it off again with the same line and `/e:false`. This protects nothing and says nothing
about the past; it only gives a future scan a record to search.

The scanner does not enable DNS logging or change system configuration. The command above is
a separate manual choice and affects only future records.

## Rules the code is held to

- **Never contact an indicator.** No DNS resolution, ping, HTTP or WHOIS of any indicator.
  Resolving a command-and-control domain tells its operators about a possible victim. A
  runtime guard blocks Python network calls. Local-path guards reject redirected paths and
  Windows remote drives; POSIX network mounts can look local and may be read. Certificate
  verification that could fetch data is disabled. The guard is not an OS network sandbox.
  Automated checks reject network-capable imports; `urllib.parse` is allowed only for
  lexical URL parsing.
- **No telemetry** of any kind.
- **Measured, never inferred.** If a check could not run, it is `UNKNOWN`.
- **Precision over coverage.** An unsigned binary in a user-writable path is not a finding;
  plenty of honest software looks like that. Many alarming findings that mean nothing teach
  people to ignore the tool.
- **Read-only by default.** Nothing is written without an explicit flag.
- **No administrator** needed for the default scan.

## Tests

```
cd scan
python -X utf8 -m pytest -q
```

## Emitters

`../build/emit_stix.py` and `../build/emit_misp.py` turn the curated indicator file into a
STIX 2.1 bundle and a MISP event in `../dist/`. STIX because Amnesty's MVT already does
mobile forensics well and reads it, so the useful step is to give MVT users the indicators.
MISP because institutions deploy by policy: one newsroom administrator importing one event
protects everyone behind the gateway.

Delivery-tier ad infrastructure is deliberately not marked `to_ids` in the MISP event. An ad
impression is not proof of infection, and shipping it as a detection signature would bury
an analyst in false positives.

## Attribution

The curated AdFection indicators (`iocs/adfection_iocs.txt`) come from The Citizen Lab's
*Exposing AdFection* (2026-10-15) and Confiant's companion *ADINT* report. Neither
organisation is affiliated with this tool or endorses it. Other indicator sources are listed
in the [project README](../README.md#indicators).

## Guided Android acquisition

`--collect-android DIR` is an experimental, explicit network and acquisition command,
separate from scanning. It downloads a pinned official
AndroidQF collector, verifies its SHA-256 and asks for the owner's consent before running it.
Plaintext archives are extracted and checked locally. `--age-recipient-file PATH` supplies
public recipients for encrypted archives, which are kept for separate analysis; a successful
encrypted acquisition is not a completed scan. When encryption was requested, plaintext
output is refused before extraction. The age envelope's framing is checked, but verifying the
recipient or authenticity requires separate decryption. A failed acquisition keeps original
or partial output, which may be unencrypted; inspect the reported folder.
