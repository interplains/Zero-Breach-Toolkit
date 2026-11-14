"""ScanContext — what every module receives. Keeps modules decoupled from the CLI."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from contextlib import contextmanager
from typing import Callable

from .iocs import IocSet


@dataclass
class ScanContext:
    iocs: IocSet
    deep: bool = False
    # Skip the file-fingerprinting check, which is the slowest part of the scan
    # by far and the weakest signal in it. See cli.py for why.
    quick: bool = False
    # The FULL scan type (chosen in the terminal menu): also reads the bulky,
    # weak-evidence data the default skips, e.g. desktop apps' raw web caches.
    full: bool = False
    # The BROWSER scan type: run only the browser reader. It is the check that
    # covers the ad campaign, which reached people through browsers.
    browser_only: bool = False
    # --phone: a phone collection folder (AndroidQF) to check instead of this computer.
    phone_path: str = ""
    verbose: bool = True
    # progress sink; defaults to stderr so stdout stays the clean human report
    emit: Callable[[str], None] = field(
        default=lambda msg: print(msg, file=sys.stderr))
    # The result the running module is filling in, published here as soon as it
    # exists. A module that dies half way through has usually already found
    # something - a matching cookie read before a later, malformed artifact
    # raised - and that evidence must survive the crash. Without this the CLI
    # could only build a fresh empty result and the hits were thrown away.
    # Modules set it; nothing else should read it except the CLI's recovery path.
    partial: object = None
    # Optional research feature. Never installs a dependency or fetches rules.
    patterns: bool = False
    pattern_paths: tuple = ()
    # Local, per-user COM server files discovered by the host check. Only the
    # optional pattern module consumes these; explicit --pattern-path wins.
    pattern_candidate_paths: tuple = ()
    pattern_candidate_omitted: int = 0

    targets: tuple = ()
    backup_password: str = field(default="", repr=False)
    extended_windows: bool = False
    cancelled: bool = False
    completed: list = field(default_factory=list, repr=False)
    ios_input: str = ""
    # --dns-log: DNS logs from a router, Pi-hole, AdGuard Home or DNS server, checked instead of this computer.
    dns_logs: tuple = ()

    def __post_init__(self):
        # Progress lines can carry names read from the evidence (a browser
        # profile's display name, a file name). Terminal control sequences and
        # bidirectional overrides in them could clear or disguise the screen, so
        # every line is cleaned once here, whatever module produced it.
        raw = self.emit
        self.emit = lambda message: raw(_ctx_printable(message))


def _ctx_printable(message):
    text = str(message)
    return "".join("?" if (ord(c) < 32 and c not in "\t\n") or 0x7f <= ord(c) <= 0x9f
                   or c in "\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069"
                   else c for c in text)


@contextmanager
def scan_recovery(ctx):
    """Keep completed evidence even when interrupted between module calls."""
    from .result import ModuleResult
    try:
        yield
    except KeyboardInterrupt:
        ctx.cancelled = True
        if isinstance(ctx.partial, ModuleResult) and all(ctx.partial is not r for r in ctx.completed):
            ctx.completed.append(ctx.partial)
        result = ModuleResult("scan")
        result.could_not_run("scan-interrupted", "scan cancelled; remaining checks did not run")
        ctx.completed.append(result)
    finally:
        ctx.backup_password = ""
