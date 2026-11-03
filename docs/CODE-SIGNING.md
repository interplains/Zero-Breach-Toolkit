# Code signing policy

Free code signing provided by [SignPath.io](https://about.signpath.io), certificate by
[SignPath Foundation](https://signpath.org).

## What is signed

Only the Windows program, `zero-breach-toolkit-windows-x64.exe`. It is built by GitHub Actions
from the tagged source in this repository (`.github/workflows/programs.yml`), sent to SignPath
for signing, checked again after signing, and only then attached to the release with a public
build attestation. Nothing built anywhere else is signed. A maintainer approves every release
before it is published.

The certificate is issued to the SignPath Foundation, not to a person, so the signature tells
you the file came from this project's build and was not changed afterwards. It is not a
statement that the program is free of bugs.

Until the production certificate is in place, releases stay unsigned and only test builds are
signed, with a test certificate that Windows does not trust.

## Team roles

- Committers and reviewers: [interplains](https://github.com/interplains)
- Approvers: [interplains](https://github.com/interplains)

## Privacy

This program does not send information about your computer or phone anywhere. It connects to
the internet only when you ask it to: updating the indicator and exploited-software lists,
checking for a newer version, and downloading the Android collector, each from the fixed
official sources listed in the [README](../README.md). Reports are saved only where you choose.
