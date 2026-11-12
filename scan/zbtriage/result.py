"""Shared result types — the contract every scan module implements.

Doctrine baked into these types (SPEC-scanner.md):

  D3  Measured, never inferred. A module reports CLEAN only for checks that
      actually ran and found nothing. A check that could not run is UNKNOWN,
      which is a DISTINCT outcome from CLEAN. Never collapse the two.

Status values
  CLEAN    every check this module was meant to run, ran, and found no hit
  HITS     at least one indicator matched
  UNKNOWN  no check in this module could run (nothing was actually observed)
  PARTIAL  some checks ran clean, at least one could not run (gaps remain)
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import Any, Dict, List

CLEAN = "CLEAN"
HITS = "HITS"
UNKNOWN = "UNKNOWN"
PARTIAL = "PARTIAL"
NOT_APPLICABLE = "NOT_APPLICABLE"

# Evidence grades, strongest first. See Hit.evidence for what each one means.
EV_ON_DISK = "on-disk"          # a known sample's fingerprint matched a file
EV_FILE_PATTERN = "file-pattern"  # a research rule matched; needs verification
EV_PERSISTENCE = "persistence"  # named in an auto-start registration
EV_COMMAND = "ran-command"      # named in a command/script that ran here
EV_EXECUTION = "execution-record"  # executable identity in a historical execution record
EV_INVENTORY = "inventory-record"  # file inventory identity; execution/present file unverified
EV_ON_DEVICE = "on-device"      # the named app/process/file/property is on the phone
EV_DEVICE_LOG = "device-log"    # named in the phone's own system logs
EV_RECEIVED = "received"        # in a message that arrived on the device
EV_CONTACTED = "contacted"      # the device demonstrably talked to the host
EV_DNS = "dns-record"           # a resolver record; endpoint contact unverified
EV_ATTEMPTED = "attempted"      # a lookup happened but a filter blocked it
EV_CONFIGURED = "configured"    # named in local config, NOT as a block
EV_REFERENCED = "referenced"    # the string appeared in saved content

EVIDENCE_ORDER = [EV_ON_DISK, EV_ON_DEVICE, EV_FILE_PATTERN, EV_PERSISTENCE, EV_COMMAND,
                  EV_EXECUTION, EV_INVENTORY,
                  EV_CONTACTED, EV_RECEIVED, EV_DEVICE_LOG, EV_DNS, EV_ATTEMPTED,
                  EV_CONFIGURED, EV_REFERENCED]

# Indicator kinds that are not network addresses: rendered as written (never # defanged) and excluded from blocklist export. Single source of truth — the
# report renders with this set and export.py filters with it, so a future kind
# added here cannot silently start appearing in a DNS sinkhole.
NOT_ADDRESSES = {"app-id", "app-cert", "file-path", "file-name", "android-property",
                 "process", "profile-id", "sha256"}


def net_value(hit) -> str:
    """The hit's indicator if it is (or may be) a network address, else ''.

    Empty kind is treated as network: an unknown kind from a future module is
    more dangerous rendered as a clickable address than as inert text.
    """
    if isinstance(hit, dict):
        kind, value = hit.get("kind"), hit.get("indicator", "")
    else:
        kind, value = getattr(hit, "kind", ""), getattr(hit, "indicator", "")
    return "" if kind in NOT_ADDRESSES else value


# Everything except `referenced` is a finding that needs a person to look at it.
# This is deliberately a DENY-list of the one benign grade rather than an
# allow-list of serious ones: a hit whose grade is missing or misspelled is then
# treated as serious, never as harmless. The opposite default is how a known
# sample on disk once came to be reported as "probably not a sign of compromise".
BENIGN_EVIDENCE = {EV_REFERENCED}


def is_serious(evidence: str) -> bool:
    return evidence not in BENIGN_EVIDENCE


@dataclass
class Hit:
    """A single indicator match. `indicator` is the IOC string that matched
    (domain, IP or hash); the tier/confidence come from the IOC set so every
    hit carries its own provenance, never a bare 'found something'."""

    indicator: str
    location: str
    detail: str
    tier: str = ""
    confidence: str = ""
    # Which published report this indicator came from. The file now carries more
    # than one source, so the citation has to travel with the hit.
    source: str = ""
    # How strong this hit is as evidence. The single most important field for
    # anyone triaging a result, because the artifact decides the meaning:
    #
    #   on-disk    - a file on this machine has the fingerprint of a published
    #                sample. Conclusive.
    #   persistence- the name appears in an auto-start/COM registration. Serious.
    #   contacted  - the browser or OS demonstrably talked to this host. A cookie
    #                it set, an HSTS header it sent, or a connection record.
    #   dns-record - the name or address appears in a DNS cache or event log.
    #                A lookup may fail, be prefetched, or never lead to a
    #                connection. Endpoint contact is unverified.
    #   attempted  - something on the device looked the name up, but a DNS filter
    #                answered with a block address, so no connection was made.
    #   configured - the name appears in local configuration (e.g. the hosts
    #                file) pointing somewhere REAL. A block entry (0.0.0.0) is
    #                protective and is not reported as a hit at all.
    #   referenced - the string appeared in cached page content or history text.
    #                That is often just a page ABOUT the indicator - a news
    #                article, a report, a blocklist. Usually NOT contact.
    #
    # Collapsing these would be the tool's most harmful bug in either direction:
    # over-grading sends people who merely read about this campaign to a
    # human-rights helpline; under-grading tells a real victim it is nothing.
    # Use the EV_* constants. An empty or unknown grade is treated as SERIOUS.
    evidence: str = ""
    # When the artifact says the contact happened, if it records that at all.
    observed: str = ""

    # Which browser profile / account this came from, by its DISPLAY name (e.g.
    # "Work"), not just the folder name ("Profile 1"). On a machine with
    # several profiles the folder number tells the reader nothing, and whoever
    # triages a finding needs to know whose browser it was.
    #
    # The signed-in email address is deliberately NOT collected: the display
    # name already answers "which account", and reports get forwarded.
    profile: str = ""

    # Which spyware family the publishing researchers tie the indicator to, when
    # the indicator came from a multi-vendor feed (e.g. "Pegasus", "Predator").
    # LAST on purpose: Hit is also built positionally, and a field inserted
    # before `evidence` would silently shift every grade into this slot.
    family: str = ""

    # The kind of indicator that matched (domain, ip, sha256, app-id, file-path...),
    # when the module knows it. Decides display: only network kinds are
    # defanged with "[.]" - an app id or a file path is not an address anyone
    # could click. Empty = unknown, treated as network (the safe side). LAST, as
    # above, because Hit is also built positionally.
    kind: str = ""
    artifact: str = ""  # physical record source for conservative correlation
    provenance: dict = field(default_factory=dict)  # optional bounded source/record metadata

    @property
    def is_contact(self) -> bool:
        return self.evidence == EV_CONTACTED

    @property
    def is_serious(self) -> bool:
        return is_serious(self.evidence)

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Lead:
    """Something worth a person's look that is NOT an indicator match.

    A heuristic: a sideloaded app, a command typed into Win+R that runs
    PowerShell against a web address, an antivirus exclusion. Such signs are
    usually harmless on an ordinary device, so a lead
    never touches the verdict, the module status or the exit code. It is shown
    in its own section with `usual_reason`: the ordinary explanation that is far
    more common, written by the module (fixed text, not read from the machine).
    """

    check: str
    location: str
    what: str
    usual_reason: str = ""
    observed: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


@dataclass
class Check:
    """One named sub-check inside a module (e.g. 'dns-cache'). `ran` records
    whether it actually executed; `reason` explains why it did not. This is how
    D3 (CLEAN != UNKNOWN) is enforced at the finest granularity."""

    name: str
    ran: bool
    reason: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return dataclasses.asdict(self)


HIT_LIST_LIMIT = 100


@dataclass
class ModuleResult:
    name: str
    checked: int = 0
    skipped: int = 0
    hits: List[Hit] = field(default_factory=list)
    checks: List[Check] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    submetrics: Dict[str, int] = field(default_factory=dict)
    # Wall-clock seconds this module took. Shown to the user because a scan that
    # prints nothing for ten minutes looks hung, and because it tells anyone
    # tuning the tool where the time actually goes.
    duration_s: float = 0.0
    # How far back in time this module's evidence actually reaches. A clean result
    # is only as meaningful as the window it covers: browser caches are recycled
    # within weeks, and the DNS log does not exist unless somebody turned it on.
    # Each entry is {label: {"earliest": ISO date or None, "basis": str,
    # "note": str}}. Reported to the user verbatim, because "we found nothing"
    # and "we could only look back 11 weeks" are the same sentence.
    reach: Dict[str, Any] = field(default_factory=dict)
    # 'Worth a look' items (see Lead). Never part of the status rollup.
    leads: List[Lead] = field(default_factory=list)
    # Explicit optional-input absence is distinct from failing to inspect an
    # expected input. Errors/hits/checks always take precedence over this label.
    inapplicable_reason: str = ""
    # Matches of one indicator at one grade beyond HIT_LIST_LIMIT are counted, not
    # listed. A tiny crafted input (a 399-byte backup holding 291,000 messages that
    # all name an indicator) otherwise produced gigabytes of findings and report.
    _hit_counts: Dict[Any, int] = field(default_factory=dict, repr=False)

    # --- builder helpers used by modules ------------------------------------

    def add_hit(self, hit: Hit) -> None:
        key = (hit.indicator, hit.evidence)
        count = self._hit_counts.get(key, 0) + 1
        self._hit_counts[key] = count
        if count <= HIT_LIST_LIMIT:
            self.hits.append(hit)
            return
        unlisted = self.submetrics.get("matching_records_not_listed", 0)
        if not unlisted:
            self.notes.append("{}: more than {} records matched the same indicator at the same "
                              "grade; the rest are counted in matching_records_not_listed, not "
                              "listed one by one".format(self.name, HIT_LIST_LIMIT))
        self.submetrics["matching_records_not_listed"] = unlisted + 1

    def add_lead(self, lead: Lead) -> None:
        self.leads.append(lead)

    def ran(self, name: str) -> None:
        self.checks.append(Check(name, True))

    def could_not_run(self, name: str, reason: str) -> None:
        self.checks.append(Check(name, False, reason))
        self.notes.append("{}: could not run ({})".format(name, reason))

    def note(self, text: str) -> None:
        self.notes.append(text)

    # --- status rollup ------------------------------------------------------

    @property
    def status(self) -> str:
        if self.hits:
            return HITS
        if not self.checks:
            if self.inapplicable_reason and not self.checked and not self.skipped and not self.leads:
                return NOT_APPLICABLE
            return UNKNOWN
        ran = [c for c in self.checks if c.ran]
        if not ran:
            return UNKNOWN
        if len(ran) == len(self.checks):
            return CLEAN
        return PARTIAL

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "inapplicable_reason": self.inapplicable_reason,
            "checked": self.checked,
            "skipped": self.skipped,
            "hits": [h.to_dict() for h in self.hits],
            "checks": [c.to_dict() for c in self.checks],
            "notes": list(self.notes),
            "submetrics": dict(self.submetrics),
            "reach": dict(self.reach),
            "duration_s": round(self.duration_s, 1),
            "leads": [l.to_dict() for l in self.leads],
        }
