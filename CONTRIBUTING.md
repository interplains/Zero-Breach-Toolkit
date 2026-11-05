# Contributing

This tool is used by people at real risk, so a few rules are strict. They are what keep it
trustworthy.

## Running the tests

The scanner itself uses only the standard library. The test tools are pinned by version and
hash. Python 3.8 and 3.9 use the legacy file, because current pytest needs 3.10 or later.

```
python -m pip install --require-hashes -r build/requirements-test.txt          # Python 3.10+
python -m pip install --require-hashes -r build/requirements-test-legacy.txt   # 3.8/3.9 only
cd scan && python -m pytest -q
```

Optional pattern and backup fixtures need their own pinned dependencies
(`requirements-patterns.txt`, `requirements-backups.txt`, both Python 3.9+). The Windows
executable's build tools are pinned the same way in `build/requirements-build.txt`.

Every push and pull request runs the suite, the release gate and a reproducibility check on
Windows, Linux and macOS (`.github/workflows/tests.yml`). Keep the suite green; new
behaviour needs a test.

## Releasing

Before publishing, run `python tools/release_check.py --require-patterns --require-backups`
in a virtual environment with the pinned pattern and backup dependencies installed. It
builds and tests the download against controlled fixtures without scanning your own
browser profiles.

- For a website release, add `--require-web --web-dir PATH_TO_SCAN_PAGE`. Website checks
  must not be skipped when publishing the page or its download instructions.
- To verify a separately saved public download, add `--downloaded-scanner DOWNLOADED_FILE`;
  the gate hashes that file without running it.
- Use `--scanner dist/zero-breach-toolkit.py` to verify the staged local download.

Then build, sign and verify the release files with `python tools/make_release.py` (see
[docs/VERIFYING.md](docs/VERIFYING.md)).

## Rebuilding the generated files

The STIX/MISP feeds, blocklists, indicator checksum and single-file build are generated from
`iocs/adfection_iocs.txt`. After changing indicators, regenerate everything and commit the
result:

```
python build/build.py
```

The build is deterministic: a fresh clone produces a byte-identical
`dist/zero-breach-toolkit.py`. `python build/build.py --check` reports drift in tracked
artifacts, and the release check verifies reproducibility.

## Adding artifact readers

Use the shared [reader registry](scan/READERS.md). A new reader supplies its interface,
platform and scope selection and coverage metadata in one registration; the builder and CLI
use the same definition. Synthetic regression tests must keep evidence distinctions intact
and show that hostile input stays bounded.

## Adding indicators

A bad indicator is worse than a missing one: a false match can send an innocent person to
a crisis helpline.

- **Only attacker-controlled infrastructure.** Never add a compromised victim site, or a
  domain that is or could be a real organisation's own. When in doubt, leave it out.
- **Verify against the primary report**, not news coverage, and put the source in the
  fourth column.
- **No IP addresses from old reporting.** Cloud IPs get reassigned to innocent tenants, so
  an undated IP match is noise. The existing `candiru-ip` tier carries this caveat.
- **Names that can change owner go in `reclaimable`:** hostnames on shared cloud platforms
  (`*.herokuapp.com`, `*.cloudapp.azure.com`) and domains registered again after their
  report. Check registry (RDAP) records, never the domain itself.
- **Hashes are SHA-256, or SHA-1 when the publisher gives no SHA-256.** The scanner computes
  both over the whole file. Never use a partial-file digest (such as Amcache's), and leave out
  MD5.
- **Update the `# as-of:` date** in the indicator file header when you change the set, and
  rerun `build/build.py`.

## Design rules

These are enforced by tests. A change that breaks one fails the suite.

- **Never contact an indicator.** The scan's Python socket guard blocks direct DNS and
  network calls. It is not an OS network sandbox: POSIX network mounts and concurrent file
  changes need OS isolation for strict offline use. `--update` downloads indicators from a
  fixed allow-list, and guided Android acquisition downloads and runs a pinned collector
  after consent. Neither runs during an offline scan.
- **Measured, never inferred.** A check that could not run is a reported gap, never a clean
  result.
- **Query only what is needed.** Cookie queries select host metadata and timestamps, not
  values. Temporary snapshots copy whole database files; the scanner does not decrypt
  browser credentials.
- **Precision over coverage.** An unsigned binary in a user-writable path is not a finding.
  Alarms that mean nothing teach people to ignore the tool.
- **Read-only default scanning, no administrator, no telemetry, Python 3.8+.** Pattern and
  encrypted-backup support have separate optional dependencies.

## Style

Match the surrounding code. Comments explain why, not what. Keep report text plain: a
frightened non-technical person reads it.

## Questions

To discuss a change before you build it, reach the project on Telegram:
https://t.me/+t9gq13mSKcE4NGI0.
