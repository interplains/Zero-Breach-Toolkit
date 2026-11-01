"""IOC loading, type inference and freshness.

Data contract (SPEC-scanner.md, matching iocs/adfection_iocs.txt):

    indicator <TAB> tier <TAB> confidence

  tier       = cc | validator | delivery | historical | reclaimable | sample | ...
               (the full list, with what each means, is VALID_TIERS below)
  confidence = primary | secondary

`#` lines are comments. The schema deliberately carries more than AdFection: the
threat is the ADINT *technique*, so the same file holds other vendors (NSO,
Intellexa/Predator, Paragon, Cytrox) and sample hashes as they are added. A hit
without a citation is unusable, so the provenance (confidence) column is required.

Indicator *type* is inferred from shape, not stored, so the file stays 3 columns:
  - 64 hex chars            -> sha256 sample hash
  - looks like an IPv4/IPv6 -> ip
  - otherwise               -> domain
An Android package name is shaped exactly like a domain, so a row that holds one
says so in an optional 6th column (after source-tag and family): `app-id`, or
`app-cert` for a signing-certificate fingerprint. Only those two may be declared.
"""

from __future__ import annotations

import bisect
import io
import itertools
import json
import os
import ipaddress
import re
import datetime
from array import array
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

VALID_TIERS = {
    # Domains/IPs of commercial phone-monitoring ('stalkerware') companies, from
    # the Echap list: often just the company's public website or app dashboard.
    # On a computer they are 'worth a look', never a finding (report.py).
    "stalkerware",
    "cc",           # Candiru command-and-control (Citizen Lab, named in body)
    "validator",    # Candiru validator / target-selection servers
    "delivery",     # Discover-Tech / Controlium ad infrastructure
    "historical",   # older, separate Candiru campaigns
    # A published name that may have passed to someone else since: a hostname
    # on a shared cloud platform (Azure cloudapp, Heroku), which the platform
    # hands to the next customer, or a domain that registry records show was
    # registered again after the report. Contact with it is a lead, never a
    # finding by itself; only a match dated to the campaign period means much.
    "reclaimable",
    "sample",       # file hashes of the spyware itself
    # A legitimate, signed third-party driver or utility that this actor abuses
    # (bring-your-own-vulnerable-driver). The file is NOT spyware: it ships with
    # real products and is present on clean machines for innocent reasons. It is
    # tiered apart from `sample` precisely so a match can never be reported as
    # proof of infection - presence is a lead to investigate, nothing more.
    "vuln-driver",
    # Candiru-attributed server infrastructure whose individual ROLE is not stated
    # by the source. Recorded Future's Aug 2025 DevilsTongue report lists 8
    # clusters mixing victim-facing C2 and higher-tier operator infrastructure,
    # without saying which domain is which. Treating these as `cc` would claim
    # precision the source does not give, so they get their own tier.
    "candiru",
    # Same, but IP addresses. Separate because an IP indicator decays in a way a
    # domain does not: almost all of these are Vultr / DigitalOcean addresses
    # that are very likely reassigned to innocent tenants by now. A hit is only
    # meaningful if it is DATED (a DNS log entry from the period), which is why
    # the tier is distinguishable rather than mixed in with the domains.
    "candiru-ip",
    # Imported from a published STIX bundle (see stix.py): a domain the
    # researchers attribute to a spyware family, without saying what role it
    # played. Same reasoning as `candiru`, for every other vendor.
    "infrastructure",
    # Same, IP addresses - and the same decay caveat as `candiru-ip`.
    "infrastructure-ip",
    # A device artefact the researchers attribute to the family: an app id, a
    # signing certificate, an iOS process name, a configuration profile, a file
    # path or name, an Android system property. Used by phone/backup checks.
    "artifact",
    # A trace of a phone-forensics tool (Cellebrite): not spyware, but proof the
    # phone was unlocked, or an unlock attempted, while out of its owner's hands.
    # Built in (devicetraces.py) and used only by the phone checks.
    "forensic",
}
VALID_CONFIDENCE = {"primary", "secondary"}

# Tiers whose matches are IP addresses that are probably reassigned by now. A
# contact record naming one does not establish who ran the server at the time.
DECAYING_IP_TIERS = {"candiru-ip", "infrastructure-ip"}

# Characters that may not sit immediately beside a match. Without this the
# matching is plain substring, so 52.174.65.77 matches inside 152.174.65.771 and
# controlium.net matches inside notcontrolium.net or controlium.network. With 100+
# IP indicators that stops being theoretical.
#
# A dot on the RIGHT is the subtle case. "controlium.net." (the fully-qualified
# form, or the end of a sentence) is the indicator; "controlium.net.evil.example"
# is a different domain that merely starts with it. So a trailing dot is allowed
# only when what follows it does not continue the name (the `cont` sets below).
_LABEL = set("abcdefghijklmnopqrstuvwxyz0123456789-")
_LEFT_BAD = _LABEL | {"_"}
_RIGHT_BAD = _LABEL | {"_"}
_DIGIT = set("0123456789")
_DIGIT_DOT = _DIGIT | {"."}
_HEX = set("0123456789abcdef")
_HEX_COLON = _HEX | {":"}

TYPE_DOMAIN = "domain"
TYPE_IP = "ip"
TYPE_SHA256 = "sha256"

# Kinds that only phone, backup and mail checks can use. They are kept in the
# set (not dropped) but never take part in the network-string matching, which
# only ever sees TYPE_DOMAIN and TYPE_IP. Several look like domains - an Android
# app id "com.example.app" is shaped exactly like a hostname - so the set keys
# every indicator by (type, value), never by value alone.
TYPE_APP_ID = "app-id"              # Android package name
TYPE_APP_CERT = "app-cert"          # Android signing-certificate SHA-1 / SHA-256
TYPE_PROCESS = "process"            # iOS / Android process name (exact match only)
TYPE_PROFILE = "profile-id"         # iOS configuration profile UUID
TYPE_FILE_PATH = "file-path"        # absolute path on the phone
TYPE_FILE_NAME = "file-name"        # bare file name (weak on its own)
TYPE_ANDROID_PROP = "android-property"
TYPE_EMAIL = "email"                # sender / account address used by the operators

NETWORK_TYPES = {TYPE_DOMAIN, TYPE_IP}
COMPUTER_TYPES = {TYPE_DOMAIN, TYPE_IP, TYPE_SHA256}
DEVICE_TYPES = {TYPE_APP_ID, TYPE_APP_CERT, TYPE_PROCESS, TYPE_PROFILE,
                TYPE_FILE_PATH, TYPE_FILE_NAME, TYPE_ANDROID_PROP, TYPE_EMAIL}

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# Kinds a curated row may declare in its 6th column, with the exact shape each
# must have (the same shapes the STIX importer accepts for them).
CURATED_DECLARED_KINDS = {
    TYPE_APP_ID: re.compile(r"^(?=.{3,255}$)[a-z0-9_]+(\.[a-z0-9_]+)+$"),
    TYPE_APP_CERT: re.compile(r"^([0-9a-f]{40}|[0-9a-f]{64})$"),
}
_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_ASOF_RE = re.compile(r"^#\s*as-of:\s*(\d{4}-\d{2}-\d{2})\s*$")


def infer_type(indicator: str) -> str:
    s = indicator.strip().lower()
    if _SHA256_RE.match(s):
        return TYPE_SHA256
    if _IPV4_RE.match(s) or (":" in s and all(c in "0123456789abcdef:" for c in s)):
        return TYPE_IP
    return TYPE_DOMAIN


@dataclass(frozen=True)
class Indicator:
    value: str          # normalised: lower-case for domains/ips/hashes
    tier: str
    confidence: str
    type: str
    # Which published report this came from. Optional 4th column. With more than
    # one source in the file, "a hit without a citation is unusable" means the
    # citation has to travel per indicator, not per file.
    source: str = ""
    # Which spyware family the publishing researchers tie this to (e.g.
    # "Pegasus"). Empty for the curated file, whose tiers already say it.
    family: str = ""
    contexts: tuple = ()  # canonical JSON publisher assertions, retained across merges

    def to_dict(self) -> Dict[str, str]:
        return {
            "indicator": self.value,
            "tier": self.tier,
            "confidence": self.confidence,
            "type": self.type,
            "source": self.source,
            "family": self.family,
        }


def ioc_identity_values(indicator):
    """Original spellings of a case-sensitive artifact identity, if published."""
    originals = []
    for encoded in indicator.contexts:
        try:
            record = json.loads(encoded)
        except (ValueError, TypeError):
            continue
        value = record.get("case_sensitive_value", indicator.value) if isinstance(record, dict) else indicator.value
        if isinstance(value, str) and value not in originals:
            originals.append(value)
    return originals or [indicator.value]


def ioc_exact_identity(indicator, value):
    return isinstance(value, str) and value in ioc_identity_values(indicator)


def ioc_path_mentioned(indicator, text):
    """A complete literal Unix path token, never a prefix or folded spelling."""
    return any(re.search(r"(?:^|[\s\"'=:(])" + re.escape(value) + r"(?=$|[\s\"';,)])", text)
               for value in ioc_identity_values(indicator))


def _char_at(hay, pos):
    """One character of a str or bytes haystack, as a str, or None if out of range."""
    if pos < 0 or pos >= len(hay):
        return None
    c = hay[pos]
    return c if isinstance(c, str) else chr(c)


def _char_at16(hay: bytes, pos: int):
    """One UTF-16LE code unit of a bytes haystack starting at byte `pos`.

    Only ASCII matters for boundary decisions, so anything else comes back as a
    placeholder that is in none of the boundary sets.
    """
    if pos < 0 or pos + 1 >= len(hay):
        return None
    lo, hi = hay[pos], hay[pos + 1]
    return chr(lo) if hi == 0 and lo < 0x80 else "￿"


_DOT = re.compile(r"\.")


def _bad_sets(needle: str, ind_type: str):
    """(left_bad, right_bad, continues) for one indicator. `continues` is what
    may not follow a trailing dot - see the comment on _LABEL."""
    if ind_type == TYPE_IP:
        if ":" in needle:                      # IPv6
            return _HEX_COLON | {"."}, _HEX_COLON, _HEX
        return _DIGIT_DOT, _DIGIT, _DIGIT      # IPv4
    return _LEFT_BAD, _RIGHT_BAD, _LABEL


def _positions(hay, needle, ind_type: str, display: str, wide: bool = False):
    """Every offset at which `needle` occurs in `hay` as a whole indicator rather
    than as part of a longer name or number.

    Domains: the character before must not continue a label (so notcontrolium.net
    does not match controlium.net) and the character after must not either (so
    controlium.network does not match).
    IPs: neither side may continue the number, so 152.174.65.771 does not match
    52.174.65.77, and an IPv6 address may not sit inside a longer one.

    `display` is the indicator as text (for choosing boundary sets); `needle` is
    what is searched for, which differs when `wide` (UTF-16LE bytes).
    """
    out = []
    start = 0
    while True:
        idx = hay.find(needle, start)
        if idx == -1:
            return out
        if _valid_at(hay, idx, len(needle), ind_type, display, wide):
            out.append(idx)
        start = idx + 1


def _valid_at(hay, idx: int, nlen: int, ind_type: str, display: str,
              wide: bool = False) -> bool:
    """The boundary rule for ONE occurrence at `idx` spanning `nlen` units of
    `hay` (bytes when wide). The single definition both matchers use, so the
    tokenising matcher and the reference loop cannot disagree on precision."""
    left_bad, right_bad, cont = _bad_sets(display, ind_type)
    at = _char_at16 if wide else _char_at
    unit = 2 if wide else 1
    before = at(hay, idx - unit)
    after = at(hay, idx + nlen)
    ok = before is None or before not in left_bad
    if ok and after is not None:
        if after in right_bad:
            ok = False
        elif after == "%" and ind_type != TYPE_IP:
            # An escaped "." "-" or "_" continues the name (example.test%2eevil is
            # example.test.evil). Any other escape ends it: %2f, %26 and %3a are how
            # a link is normally written. Non-ASCII text ends a name as before.
            tail = "".join(c or "" for c in (at(hay, idx + nlen + unit * k) for k in range(1, 6)))
            if tail.startswith(("2e", "2d", "5f", "252e", "252d", "255f")):
                ok = False
        elif after == ".":
            nxt = at(hay, idx + nlen + unit)
            ok = nxt is None or nxt not in cont
    return ok


def _boundaries_ok(hay, needle, ind_type: str) -> bool:
    """True if `needle` occurs in `hay` at least once as a whole indicator."""
    display = needle if isinstance(needle, str) else needle.decode("ascii", "replace")
    return bool(_positions(hay, needle, ind_type, display))


# An IPv6-shaped run: hex groups and colons, not part of a longer hex/colon run,
# and not the start of an embedded IPv4 tail.
_IP6_CANDIDATE = re.compile(
    r"(?<![0-9a-f:.])[0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7}(?![0-9a-f:]|\.[0-9])")

# Escapes that hide a host inside a URL. Matching runs on lower-cased text, so
# the hex digits are lower case here.
_PCT_STR = re.compile(r"%([0-9a-f]{2})")
_JS_STR = re.compile(r"\\(?:x([0-9a-f]{2})|u00([0-9a-f]{2})|(/))")
_PCT_BYTES = re.compile(rb"%([0-9a-f]{2})")
_JS_BYTES = re.compile(rb"\\(?:x([0-9a-f]{2})|u00([0-9a-f]{2})|(/))")
# Four or more UTF-16LE printable characters in a row.
_WIDE_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def _printable(hex2):
    value = int(hex2, 16)
    return chr(value).lower() if 0x21 <= value <= 0x7e else None


def _unescape_str(text):
    for _ in range(2):          # twice: %252f is %2f is /
        text = _PCT_STR.sub(lambda m: _printable(m.group(1)) or m.group(0), text)
    return _JS_STR.sub(lambda m: "/" if m.group(3) else
                       (_printable(m.group(1) or m.group(2)) or m.group(0)), text)


def _narrow_wide_runs(data):
    """UTF-16LE text runs rewritten as single-byte text (other bytes kept)."""
    if b"\x00" not in data:
        return data
    return _WIDE_RUN.sub(lambda m: m.group(0)[::2], data)


# One escape that can hide part of a name, and the characters a name (or the
# URL text around it, or an IPv6 address) can continue through.
_ESCAPE_AT = re.compile(r"%[0-9a-f]{2}|\\(?:x[0-9a-f]{2}|u00[0-9a-f]{2}|/)")
_WINDOW_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789-_.%\\:/")


def _escaped_windows(text):
    """(decoded stretches of `text` around its escapes joined by newlines, and
    their (start, end) spans in `text`), or None when no escape decodes to
    anything.

    Each stretch is widened to the nearest character a name cannot continue
    through, on both sides, so its edges are boundaries exactly as they are in
    the full text: searching the stretches finds what searching the whole
    decoded text would, without decoding or searching everything again."""
    parts, spans = [], []
    covered = 0
    n = len(text)
    for m in _ESCAPE_AT.finditer(text):
        if m.start() < covered:
            continue
        start, end = m.start(), m.end()
        while start > 0 and text[start - 1] in _WINDOW_CHARS:
            start -= 1
        while end < n and text[end] in _WINDOW_CHARS:
            end += 1
        covered = end
        window = text[start:end]
        decoded = _unescape_str(window)
        if decoded != window:
            parts.append(decoded)
            spans.append((start, end))
    return ("\n".join(parts), spans) if parts else None


def _decoded_view(hay):
    """(view, spans, text) for the decoded stretches around percent and JS
    escapes (see _escaped_windows), or None when there are none: `view` is
    searched like the haystack, and `spans` are positions in `text`, the
    haystack as single-byte text. UTF-16LE runs are narrowed first so escapes
    stored as UTF-16 (Chromium storage) are decoded too."""
    if isinstance(hay, str):
        if "%" not in hay and "\\" not in hay:
            return None
        found = _escaped_windows(hay)
        return None if found is None else (found[0], found[1], hay)
    if b"%" not in hay and b"\\" not in hay:
        return None
    src = hay
    if b"%\x00" in hay or b"\\\x00" in hay:
        src = _narrow_wide_runs(hay)
    text = src.decode("latin-1")
    found = _escaped_windows(text)
    return None if found is None else (found[0].encode("latin-1"), found[1], text)


def _merge_views(main, extra, spans, text):
    """Union of the original and decoded-view results, original order first.

    A parent domain the original matched is dropped when the decoded stretches
    show a more specific name for it and every place the parent occurs in the
    original lies inside an escaped stretch (it was only that name's tail)."""
    if not extra:
        return main
    extra_values = {i.value for i in extra}
    out = []
    for ind in main:
        if (ind.type == TYPE_DOMAIN and ind.value not in extra_values and
                any(v.endswith("." + ind.value) for v in extra_values)):
            places = _positions(text, ind.value, TYPE_DOMAIN, ind.value)
            if all(any(a <= p < b for a, b in spans) for p in places):
                continue
        out.append(ind)
    have = {i.value for i in out}
    out += [i for i in extra if i.value not in have]
    return out


def _context_records(ind):
    out = []
    for raw in getattr(ind, "contexts", ()) or ():
        try:
            record = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if isinstance(record, dict):
            out.append(record)
    return out


def ios_only(ind) -> bool:
    """True when every publisher record for this indicator names only Apple
    platforms: an iPhone bundle id, which an Android package can share in form
    but never in meaning, so the Android checks must not match it."""
    records = _context_records(ind)
    if not records:
        return False
    apple = {"ios", "ipados", "iphone"}
    for record in records:
        platforms = record.get("platforms")
        if not isinstance(platforms, list) or not platforms:
            return False
        if not {str(p).lower() for p in platforms} <= apple:
            return False
    return True


def watchware(ind) -> bool:
    """True when the publisher classes this monitoring app as one that does not
    hide itself (often a family-safety app), as ECHAP's "watchware" does."""
    records = _context_records(ind)
    return bool(records) and all(r.get("monitoring") == "watchware" for r in records)


def _prune_parents(found, hay) -> list:
    """Drop a parent domain whose every occurrence is just the tail of a matched
    child. "noas.powerium.net" in a cookie also contains "powerium.net", and both
    are indicators - but it is ONE contact, and reporting it as two servers that
    reached the device doubles the alarm for no reason. A parent that also occurs
    on its own somewhere in the same artifact is kept."""
    by_value = {ind.value: (ind, occ) for ind, occ in found}
    keep = []
    for ind, occ in found:
        children = [c for c in by_value
                    if c != ind.value and c.endswith("." + ind.value)]
        if ind.type != TYPE_DOMAIN or not children:
            keep.append(ind)
            continue
        standalone = False
        for enc, pos in occ:
            tail_of_child = False
            for child in children:
                extra = len(child) - len(ind.value)
                if enc == "wide":
                    start = pos - 2 * extra
                    seg = hay[start:pos + 2 * len(ind.value)] if start >= 0 else b""
                    tail_of_child = seg == child.encode("utf-16-le")
                else:
                    start = pos - extra
                    seg = hay[start:pos + len(ind.value)] if start >= 0 else ""
                    want = child if isinstance(hay, str) else child.encode("ascii")
                    tail_of_child = seg == want
                if tail_of_child:
                    break
            if not tail_of_child:
                standalone = True
                break
        if standalone:
            keep.append(ind)
    return keep


class IocSet:
    def __init__(self, indicators: List[Indicator], source_path: str,
                 source_mtime: Optional[float]):
        self.indicators = indicators
        self.source_path = source_path
        self.source_mtime = source_mtime
        self.asof = None  # "YYYY-MM-DD" from the header, set by load()
        # One entry per file this set was built from: what each contributed and
        # what it could not (filled by load_any / merge).
        self.sets: List[Dict[str, object]] = []
        # lookup(value) serves the computer modules, so a domain / IP / hash
        # always wins over a device indicator that happens to share the string
        # (an app id "com.x.y" vs a domain "com.x.y").
        self._by_value = {}
        for i in indicators:
            if i.type in COMPUTER_TYPES or i.value not in self._by_value:
                self._by_value[i.value] = i
        self._by_type: Dict[str, List[Indicator]] = {}
        self._typed: Dict[Tuple[str, str], Indicator] = {}
        for i in indicators:
            self._by_type.setdefault(i.type, []).append(i)
            self._typed[(i.type, i.value)] = i
        self._net_cache = None
        self._needle_cache = {}
        self._gate_text_re = None
        self._gate_bytes_re = None

    # --- views used by modules ---------------------------------------------

    @property
    def domains(self) -> List[Indicator]:
        return [i for i in self.indicators if i.type == TYPE_DOMAIN]

    @property
    def ips(self) -> List[Indicator]:
        return [i for i in self.indicators if i.type == TYPE_IP]

    @property
    def hashes(self) -> List[Indicator]:
        return [i for i in self.indicators if i.type == TYPE_SHA256]

    @property
    def network_strings(self) -> List[str]:
        """Lower-case domain + IP strings, for substring matching in artifacts.
        Sorted for deterministic output. Never used to RESOLVE anything."""
        return sorted({i.value for i in self.indicators
                       if i.type in (TYPE_DOMAIN, TYPE_IP)})

    def lookup(self, value: str) -> Optional[Indicator]:
        return self._by_value.get(value.strip().lower())

    def of_type(self, kind: str) -> List[Indicator]:
        """Indicators of one kind, e.g. TYPE_APP_ID for the phone checks."""
        return list(self._by_type.get(kind, []))

    def lookup_typed(self, kind: str, value: str) -> Optional[Indicator]:
        """Exact (type, value) lookup - the only safe lookup for device kinds."""
        return self._typed.get((kind, value.strip().lower()))

    @property
    def computer_count(self) -> int:
        """Indicators a computer scan can match (domains, IPs, file hashes)."""
        return sum(len(self._by_type.get(k, [])) for k in COMPUTER_TYPES)

    # --- matching -----------------------------------------------------------
    #
    # All matching goes through here so the boundary rules exist in exactly one
    # place. Both methods take an ALREADY LOWER-CASED haystack, and neither ever
    # resolves or contacts anything: this is text comparison only.

    @property
    def _net_indicators(self) -> List[Indicator]:
        if self._net_cache is None:
            self._net_cache = [i for i in self.indicators
                               if i.type in (TYPE_DOMAIN, TYPE_IP)]
        return self._net_cache

    # MEASURED (twice). Read before changing.
    #
    # Zero Breach's note, still true: one regex ALTERNATION of all literals is 4x
    # SLOWER than one `in` pass per indicator (Python's `re` walks a large
    # alternation itself; `in` is optimised C). That held for ~260 indicators.
    #
    # With the multi-vendor feeds (~6,900 network indicators) one `in` pass per
    # indicator became ~17x slower (14.3 s vs 0.84 s per 5 MB; ~48 min per GB of
    # browser data). So DOMAINS are now matched by tokenising instead:
    #
    #   A domain match must start at the beginning of a maximal run of
    #   [a-z0-9_.-] characters or just after a '.', and end at the run's end or
    #   just before a '.' - because the boundary rules forbid a label character
    #   or '_' on either side, and indicators are validated hostnames. So ONE
    #   regex pass for runs of that (fixed, tiny) character class, then a set
    #   lookup of each candidate, finds every occurrence the old loop found.
    #   Every candidate is then confirmed by the SAME boundary check
    #   (_valid_at, identical to _positions), so precision cannot drift.
    #
    # IPv4 indicators use their own one-pass search (below); IPv6 keeps the
    # per-indicator loop. The original loops are kept as _search_reference /
    # _search_bytes_reference, and tests/test_matcher_equivalence.py proves the
    # fast paths give identical results.
    #
    # Only tokens that CONTAIN A DOT can hold a domain, so the token regexes
    # return only those: the lookbehind pins a match to the start of a run, and
    # the run is consumed to its end. Returning every word-like token instead
    # meant a Python-level loop over 162 million tokens for one 1.2 GB browser
    # profile. Linear: a dotless run fails after one pass.
    _TOKEN_STR = re.compile(r"(?<![a-z0-9_.\-])[a-z0-9_\-]*\.[a-z0-9_.\-]*")
    _TOKEN_NARROW = re.compile(rb"(?<![a-z0-9_.\-])[a-z0-9_\-]*\.[a-z0-9_.\-]*")
    _TOKEN_WIDE = re.compile(
        rb"(?<![a-z0-9_.\-]\x00)(?:[a-z0-9_\-]\x00)*\.\x00(?:[a-z0-9_.\-]\x00)*")

    # Every IPv4-shaped string, found in ONE pass (overlapping, so both addresses
    # in '1.2.3.4.5' are candidates). Looping over each IP indicator instead cost
    # 13 min/GB with the 800 published IPs, most of a scan's time. Every candidate is still confirmed by _valid_at, the
    # same rule the per-indicator loop used.
    # Runs of digits and dots long enough to hold an address are found first (a
    # cheap scan); candidate addresses are then read only inside those runs,
    # starting at the run's start or just after a dot - the same candidates a
    # lookahead at every byte would give, at a fraction of the cost.
    _IP4_RUN_STR = re.compile(r"[0-9.]{7,}")
    _IP4_RUN_NARROW = re.compile(rb"[0-9.]{7,}")
    _IP4_RUN_WIDE = re.compile(rb"(?:[0-9.]\x00){7,}")
    _IP4_AT = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}")
    _IP4_VALUE = re.compile(r"^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$")

    def _ip4_candidates(self, run: str):
        """(offset, candidate) for every address-shaped string inside one run."""
        for i, c in enumerate(run):
            if c != "." and (i == 0 or run[i - 1] == "."):
                m = self._IP4_AT.match(run, i)
                if m:
                    yield i, m.group(0)

    def _index(self):
        """Domain lookup table + limits, and the IP list. Built once."""
        if getattr(self, "_idx", None) is None:
            doms = {i.value: i for i in self._net_indicators if i.type == TYPE_DOMAIN}
            all_ips = [i for i in self._net_indicators if i.type == TYPE_IP]
            self._ip4 = {i.value: i for i in all_ips if self._IP4_VALUE.match(i.value)}
            # IPv6 and anything unusual keep the per-indicator loop (a handful).
            ips = [i for i in all_ips if i.value not in self._ip4]
            # IPv6 by canonical form, so 2001:db8:0:0::1 finds 2001:db8::1.
            self._ip6 = {}
            for i in ips:
                try:
                    self._ip6.setdefault(ipaddress.IPv6Address(i.value).compressed, i)
                except ValueError:
                    pass
            max_labels = max((v.count(".") + 1 for v in doms), default=0)
            max_len = max((len(v) for v in doms), default=0)
            order = {i.value: n for n, i in enumerate(self._net_indicators)}
            # Last labels ('com', 'net', 'xyz'...) any domain indicator ends with.
            self._tlds = {v.rsplit(".", 1)[-1] for v in doms}
            self._idx = (doms, ips, max_labels, max_len, order)
        return self._idx

    def _domain_hits(self, hay, token: str, base: int, wide: bool, enc: str,
                     occ: Dict[str, list]) -> None:
        """Record every valid domain-indicator occurrence inside one token.

        Only places _valid_at could ever accept are tried (same rule, fewer
        doomed lookups - profiled 2026-10-25 at 9.2 million calls per profile):
          start: the token's start or just after a dot (the left side may not
                 be a label character, '-' or '_');
          end:   the token's end, or a dot followed by a dot, '_' or the end
                 (anything else continues a label);
          the candidate's last label must be one some indicator ends with."""
        doms, _ips, max_labels, max_len, _order = self._index()
        tlds = self._tlds
        unit = 2 if wide else 1
        n = len(token)
        if n <= 4096:
            dots = [i for i, c in enumerate(token) if c == "."]
            ends = [n] + [d for d in dots if d + 1 == n or token[d + 1] in "._"]
        else:
            # One enormous run of name characters and dots ("a.a.a.a..." for megabytes) needs
            # one position per dot; as Python ints that was ~19x the input in memory (60 MB ->
            # 1.1 GB). Four bytes each, and no second list for the ends.
            dots = array("I")
            dots.extend(m.start() for m in _DOT.finditer(token))
            ends = itertools.chain((n,), (d for d in dots if d + 1 == n or token[d + 1] in "._"))
        for end in ends:
            last = token.rfind(".", 0, end)
            if last < 0 or token[last + 1:end] not in tlds:
                continue
            # Starts are tried nearest-first: after each dot before `end`, then
            # the token start. Only max_labels of them can ever match, so a
            # crafted token full of dots stays linear (it was quadratic when
            # every start was listed for every end).
            i = bisect.bisect_left(dots, end - 1) - 1
            labels = 0
            while True:
                start = dots[i] + 1 if i >= 0 else 0
                labels += 1
                if labels > max_labels or end - start > max_len:
                    break
                if start < end:
                    ind = doms.get(token[start:end])
                    idx = base + start * unit
                    if ind is not None and _valid_at(hay, idx, (end - start) * unit,
                                                     ind.type, ind.value, wide):
                        occ.setdefault(ind.value, []).append((enc, idx))
                if i < 0:
                    break
                i -= 1

    def _ordered(self, occ: Dict[str, list]) -> list:
        """(indicator, occurrences) in the same order the reference loop used."""
        order = self._index()[4]
        return [(self._by_value[v], sorted(o, key=lambda x: (x[0] != "narrow", x[1])))
                for v, o in sorted(occ.items(), key=lambda kv: order[kv[0]])]

    def search(self, haystack_lower: str) -> List[Indicator]:
        """Indicators genuinely present in the text, with type-aware boundaries.

        Also searches a decoded copy when the text holds percent or JS escapes,
        and finds IPv6 addresses written in any equivalent form."""
        return self._with_views(haystack_lower, self._search_plain)

    def _search_plain(self, haystack_lower: str) -> List[Indicator]:
        doms, ips, _ml, _mx, _o = self._index()
        occ: Dict[str, list] = {}
        if doms:
            for m in self._TOKEN_STR.finditer(haystack_lower):
                tok = m.group(0)
                if "." in tok:
                    self._domain_hits(haystack_lower, tok, m.start(), False, "str", occ)
        if self._ip4:
            for run in self._IP4_RUN_STR.finditer(haystack_lower):
                for off, cand in self._ip4_candidates(run.group(0)):
                    ind = self._ip4.get(cand)
                    idx = run.start() + off
                    if ind and _valid_at(haystack_lower, idx, len(cand), ind.type, ind.value):
                        occ.setdefault(ind.value, []).append(("str", idx))
        for ind in ips:
            if ind.value in haystack_lower:
                pos = _positions(haystack_lower, ind.value, ind.type, ind.value)
                if pos:
                    occ[ind.value] = [("str", p) for p in pos]
        return _prune_parents(self._ordered(occ), haystack_lower)

    def search_bytes(self, haystack_lower: bytes) -> List[Indicator]:
        """As search(), for raw binary artifacts (HTTP cache, LevelDB)."""
        return self._with_views(haystack_lower, self._search_bytes_plain)

    def _search_bytes_plain(self, haystack_lower: bytes) -> List[Indicator]:
        """The single-view byte search.

        Searches both single-byte text and UTF-16LE, because Chromium's storage
        and many Windows artifacts keep strings as UTF-16 - "c\\0o\\0n\\0..." -
        which a plain byte search walks straight past. bytes.lower() lower-cases
        the ASCII letters in both encodings, so the caller's lower-casing holds.
        """
        doms, ips, _ml, _mx, _o = self._index()
        occ: Dict[str, list] = {}
        if doms:
            for m in self._TOKEN_NARROW.finditer(haystack_lower):
                tok = m.group(0)
                if b"." in tok:
                    self._domain_hits(haystack_lower, tok.decode("ascii"), m.start(),
                                      False, "narrow", occ)
            if b"\x00" in haystack_lower:
                for m in self._TOKEN_WIDE.finditer(haystack_lower):
                    tok = m.group(0)[::2]
                    if b"." in tok:
                        self._domain_hits(haystack_lower, tok.decode("ascii"), m.start(),
                                          True, "wide", occ)
        if self._ip4:
            for run in self._IP4_RUN_NARROW.finditer(haystack_lower):
                for off, cand in self._ip4_candidates(run.group(0).decode("ascii")):
                    ind = self._ip4.get(cand)
                    idx = run.start() + off
                    if ind and _valid_at(haystack_lower, idx, len(cand), ind.type, ind.value):
                        occ.setdefault(ind.value, []).append(("narrow", idx))
            if b"\x00" in haystack_lower:
                for run in self._IP4_RUN_WIDE.finditer(haystack_lower):
                    text = run.group(0)[::2].decode("ascii")
                    for off, cand in self._ip4_candidates(text):
                        ind = self._ip4.get(cand)
                        idx = run.start() + off * 2
                        if ind and _valid_at(haystack_lower, idx, len(cand) * 2, ind.type,
                                             ind.value, True):
                            occ.setdefault(ind.value, []).append(("wide", idx))
        for ind in ips:
            o = []
            narrow, wide = self._needles(ind)
            if narrow in haystack_lower:
                o += [("narrow", p) for p in
                      _positions(haystack_lower, narrow, ind.type, ind.value)]
            if wide in haystack_lower:
                o += [("wide", p) for p in
                      _positions(haystack_lower, wide, ind.type, ind.value, wide=True)]
            if o:
                occ[ind.value] = o
        return _prune_parents(self._ordered(occ), haystack_lower)

    # --- reference implementation (the pre-2026-10-25 loops), for tests ------

    def _search_reference(self, haystack_lower: str) -> List[Indicator]:
        return self._with_views(haystack_lower, self._search_reference_plain)

    def _search_bytes_reference(self, haystack_lower: bytes) -> List[Indicator]:
        return self._with_views(haystack_lower, self._search_bytes_reference_plain)

    def _search_reference_plain(self, haystack_lower: str) -> List[Indicator]:
        found = []
        for ind in self._net_indicators:
            if ind.value in haystack_lower:
                pos = _positions(haystack_lower, ind.value, ind.type, ind.value)
                if pos:
                    found.append((ind, [("str", p) for p in pos]))
        return _prune_parents(found, haystack_lower)

    def _search_bytes_reference_plain(self, haystack_lower: bytes) -> List[Indicator]:
        found = []
        for ind in self._net_indicators:
            occ = []
            narrow, wide = self._needles(ind)
            if narrow in haystack_lower:
                occ += [("narrow", p) for p in
                        _positions(haystack_lower, narrow, ind.type, ind.value)]
            if wide in haystack_lower:
                occ += [("wide", p) for p in
                        _positions(haystack_lower, wide, ind.type, ind.value,
                                   wide=True)]
            if occ:
                found.append((ind, occ))
        return _prune_parents(found, haystack_lower)

    def _with_views(self, hay, plain):
        """Run one single-view search over the text and its decoded copy.

        Ad-click and redirect URLs carry their destination escaped
        ("u=https%3a%2f%2fevil.com", "https:\\/\\/evil.com"), where the escape
        letters sit against the name and hide it from the boundary rule. The
        decoded copy is searched too and the results merged. A parent domain the
        original only matched as the tail of a more specific escaped name is
        dropped, as _prune_parents does within one view."""
        found = plain(hay)
        decoded = _decoded_view(hay)
        if decoded is not None:
            view, spans, text = decoded
            found = _merge_views(found, plain(view), spans, text)
        if self._index() and self._ip6:
            have = {i.value for i in found}
            for view in (hay,) if decoded is None else (hay, decoded[0]):
                for ind in self._ip6_hits(view):
                    if ind.value not in have:
                        have.add(ind.value)
                        found.append(ind)
        return found

    def _ip6_hits(self, hay):
        """IPv6 indicators present in any written form (compressed, expanded,
        leading zeros), with the same boundary rule as every other IP."""
        if isinstance(hay, bytes):
            if b":" not in hay:
                return []
            hay = _narrow_wide_runs(hay).decode("latin-1")
        elif ":" not in hay:
            return []
        out = []
        for m in _IP6_CANDIDATE.finditer(hay):
            try:
                ind = self._ip6.get(ipaddress.IPv6Address(m.group(0)).compressed)
            except ValueError:
                continue
            if ind is not None and ind not in out:
                out.append(ind)
        return out

    def _needles(self, ind: Indicator):
        cache = self._needle_cache
        if ind.value not in cache:
            # Indicator values are ASCII by construction (load() converts IDN
            # domains to punycode), so this encode is exact, never lossy.
            cache[ind.value] = (ind.value.encode("ascii"),
                                ind.value.encode("utf-16-le"))
        return cache[ind.value]

    def most_specific(self, matched: List[Indicator]) -> List[Indicator]:
        """For ONE record (a cookie, an HSTS entry, a URL) that matched several
        indicators: keep only the most specific. A cookie for noas.powerium.net
        matches both noas.powerium.net and powerium.net, but it is one contact."""
        values = {i.value for i in matched}
        return [i for i in matched
                if not (i.type == TYPE_DOMAIN and
                        any(v != i.value and v.endswith("." + i.value)
                            for v in values))]

    def __len__(self) -> int:
        return len(self.indicators)

    # --- freshness ----------------------------------------------------------

    def _curated_at(self) -> Optional[datetime.datetime]:
        """When this set was last curated, as a datetime, or None if unknowable.

        The '# as-of:' date is preferred over the file's modification time
        because mtime is a property of the COPY, not of the data: a fresh clone,
        an unzip or a plain file copy resets it to now, so a set curated a year
        ago would report itself as zero days old and never trip the staleness
        warning. The header date is content, so it survives being copied.
        """
        if getattr(self, "verified_at", None) is not None:
            return self.verified_at
        if self.asof:
            try:
                return datetime.datetime.strptime(self.asof, "%Y-%m-%d")
            except ValueError:
                # A malformed date is unknown, never the age of the copy.
                pass
        return None

    def _freshness_dates(self):
        members = getattr(self, "_freshness_members", None)
        if members is not None:
            return [date for member in members for date in member._freshness_dates()]
        return [self._curated_at()]

    def has_unknown_age(self) -> bool:
        return any(date is None for date in self._freshness_dates())

    def age_days(self, now: Optional[datetime.datetime] = None) -> Optional[int]:
        dates = [date for date in self._freshness_dates() if date is not None]
        if not dates:
            return None
        now = now or datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        delta = now - min(dates)
        return max(0, delta.days)

    def is_stale(self, threshold_days: int = 30) -> bool:
        age = self.age_days()
        return age is not None and age > threshold_days


class IocError(Exception):
    pass


# Indicator values drive substring searches over every artifact and are printed
# into reports people forward, but only the file's schema was checked. A hostile
# or corrupted feed could pass: a lone "." normalises to the empty string, which
# matches between every pair of bytes (measured at ~31 MB of RAM per MB scanned);
# a lone ":" parses as an IP that matches every URL; "0.0.0.0" would match every
# BLOCKED lookup; and a value carrying control characters went straight into the
# report. Real indicators are hostnames, IP addresses and hex digests. Anything
# else is refused, loudly, rather than scanned for.
_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")
_MAX_INDICATORS = 20000
_MAX_CURATED_BYTES = 16 * 1024 * 1024
_MAX_CURATED_LINE = 65536
_MAX_IOC_CONTEXTS = 256


# UTS#46 deviation characters that survive the invisible-character checks. IDNA
# 2003, which str.encode("idna") implements, maps them away (ß becomes "ss", a
# final sigma becomes σ), while browsers following UTS#46 keep them and record a
# different xn-- name. Encoding them here would store the wrong ASCII name: it
# would miss the real domain and could match an unrelated one, as faß.de turns
# into fass.de, a different registrant. Such names are refused, never guessed.
_IDNA_DEVIATIONS = "ßς"

# RFC 5737 and RFC 3849 documentation ranges. See _value_problem.
_DOCUMENTATION_NETS = tuple(ipaddress.ip_network(n) for n in (
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"))


def idna_deviation(name: str) -> str:
    """The first character IDNA 2003 and browsers encode differently, or ''."""
    for c in name:
        if c in _IDNA_DEVIATIONS:
            return c
    return ""


def _ipv4_leading_zero(value):
    """True for a dotted IPv4 value with a zero-padded octet ("052.1.2.3").
    Python before 3.9.5 accepts these silently; they are ambiguous between
    decimal and octal, so they are refused on every Python version."""
    parts = value.split(".")
    return len(parts) == 4 and any(len(p) > 1 and p.startswith("0") and p.isdigit() for p in parts)


def _value_problem(value, kind):
    """Why an indicator value is unsafe to scan for, or an empty string."""
    if kind == TYPE_IP:
        try:
            if _ipv4_leading_zero(value):
                raise ValueError("leading zero")
            addr = ipaddress.ip_address(value)
        except ValueError:
            # Includes an octet over 255, and leading zeros ("052.1.2.3"),
            # which are ambiguous between decimal and octal.
            return "not a valid IP address"
        if addr.is_unspecified or len(value) < 7:
            return "would match far more than the intended host"
        if not addr.is_global and not any(addr in net for net in _DOCUMENTATION_NETS):
            # A spyware server is on the public internet. A loopback, private,
            # link-local, multicast or reserved address in a hand-written list
            # would match ordinary local traffic on every machine scanned.
            # Documentation ranges are the one exception: they never occur on a
            # real network, so they cannot cause that false alarm, and they are
            # what test lists use precisely because no real host has them.
            # Published feeds stay stricter (stix._ip_problem refuses those too),
            # since a feed shipping documentation addresses is corrupt.
            return "not a public internet address"
        return ""
    if kind == TYPE_DOMAIN:
        if not 4 <= len(value) <= 253:
            return "not the length of a hostname"
        labels = value.split(".")
        if len(labels) < 2:
            return "a hostname needs at least one dot"
        for label in labels:
            if not 1 <= len(label) <= 63 or not _DOMAIN_LABEL_RE.match(label):
                return "label {!r} is not a valid hostname label".format(label[:70])
        return ""
    return ""   # hashes are already pinned to 64 hex digits by infer_type


def _ioc_curated_lines(path):
    """Bound total bytes and individual rows, including comments and duplicates."""
    try:
        with io.open(path, "rb") as fh:
            if os.fstat(fh.fileno()).st_size > _MAX_CURATED_BYTES:
                raise IocError("curated indicator byte limit exceeded")
            total, lineno = 0, 0
            while True:
                raw = fh.readline(_MAX_CURATED_LINE + 1)
                if not raw:
                    return
                lineno += 1
                total += len(raw)
                if total > _MAX_CURATED_BYTES:
                    raise IocError("curated indicator byte limit exceeded while reading")
                if len(raw) > _MAX_CURATED_LINE:
                    raise IocError("line {}: curated indicator line limit exceeded".format(lineno))
                yield lineno, raw.decode("utf-8-sig" if lineno == 1 else "utf-8")
    except UnicodeError as exc:
        raise IocError("curated indicator file is not valid UTF-8") from exc
    except OSError as exc:
        raise IocError("curated indicator file could not be read ({})".format(type(exc).__name__)) from exc


# Whole shared public services. A publisher listing one of these (or its www.
# name) means one link or account on it was malicious, not the service: as a
# domain indicator it would match every ordinary visit to the service and to all
# its subdomains. Such indicators are skipped at load, for every list format,
# and counted as not applicable. A specific account's own subdomain (a blog on
# blogspot.com) is not on this list and stays.
SHARED_SERVICE_HOSTS = frozenset("""
bit.ly bitly.com j.mp tinyurl.com goo.gl t.co ow.ly is.gd v.gd buff.ly rebrand.ly
cutt.ly shorturl.at tiny.cc lnkd.in t.ly rb.gy s.id
google.com googleusercontent.com googleapis.com storage.googleapis.com docs.google.com
drive.google.com sites.google.com blogspot.com dropbox.com dropboxusercontent.com
dl.dropboxusercontent.com github.com gist.github.com api.github.com github.io
githubusercontent.com raw.githubusercontent.com gist.githubusercontent.com
objects.githubusercontent.com pastebin.com mediafire.com mega.nz wetransfer.com
facebook.com fb.com instagram.com twitter.com x.com t.me telegram.me telegram.org
wa.me whatsapp.com youtube.com youtu.be
""".split())
SHARED_SERVICE_REASON = "a whole shared public service (only specific links or accounts on it were malicious)"


def shared_service_domain(value: str) -> bool:
    host = (value or "").lower().rstrip(".")
    return host in SHARED_SERVICE_HOSTS or (host.startswith("www.") and host[4:] in SHARED_SERVICE_HOSTS)


def _ioc_drop_shared(indicators):
    """(indicators that are not whole shared services, number skipped)."""
    kept = [i for i in indicators if not (i.type == TYPE_DOMAIN and shared_service_domain(i.value))]
    return kept, len(indicators) - len(kept)


def load(path: str) -> IocSet:
    if not os.path.exists(path):
        raise IocError("IOC file not found: {}".format(path))
    # Keyed by (type, value): a package name and a domain may share a string.
    seen: Dict[Tuple[str, str], Indicator] = {}
    asof: Optional[str] = None
    # utf-8-sig, not utf-8: Windows editors save a byte-order mark, and U+FEFF is
    # not whitespace to str.strip(). With plain utf-8 the first indicator in a
    # user's own list silently became "\ufeffcontrolium.net", matched nothing,
    # and the scan then reported finding nothing without ever having looked.
    for lineno, raw in _ioc_curated_lines(path):
        line = raw.strip()
        if not line or line.startswith("#"):
            # The '# as-of: YYYY-MM-DD' header is the set's curated date. It
            # is the deterministic timestamp every generated artifact uses,
            # so the whole build is reproducible from committed content.
            m = _ASOF_RE.match(line)
            if m:
                asof = m.group(1)
            continue
        parts = [p.strip() for p in raw.rstrip("\r\n").split("\t")]
        if not 3 <= len(parts) <= 6:
            raise IocError(
                "line {}: expected 3 to 6 tab-separated columns, got {!r}"
                .format(lineno, line))
        value, tier, confidence = parts[0].lower(), parts[1], parts[2]
        # 4th column is an optional source tag; files written before it
        # existed stay valid.
        source = parts[3] if len(parts) > 3 else ""
        # Optional 5th column: the spyware family, for files that hold more
        # than one vendor (e.g. curated_mercenary.txt).
        family = parts[4] if len(parts) > 4 else ""
        if tier not in VALID_TIERS:
            raise IocError("line {}: unknown tier {!r}".format(lineno, tier))
        if confidence not in VALID_CONFIDENCE:
            raise IocError(
                "line {}: unknown confidence {!r}".format(lineno, confidence))
        if value.startswith("\ufeff") or any(
                c in value for c in "\u200b\u200c\u200d\u2060"):
            raise IocError("line {}: invisible character in {!r} - the "
                           "file was probably re-saved by an editor".format(
                               lineno, value))
        # Optional 6th column: the kind, for the two kinds that cannot be told
        # from their shape. Anything else stays inferred, so a typo cannot turn
        # a hash or an address into a phone-only indicator that is never checked.
        declared = parts[5] if len(parts) > 5 else ""
        if declared:
            if declared not in CURATED_DECLARED_KINDS:
                raise IocError("line {}: unknown kind {!r} (only {} may be declared)".format(
                    lineno, declared, ", ".join(sorted(CURATED_DECLARED_KINDS))))
            pattern = CURATED_DECLARED_KINDS[declared]
            if not pattern.match(value):
                raise IocError("line {}: {!r} is not a valid {}".format(lineno, value[:80], declared))
            kind = declared
        else:
            kind = infer_type(value)
        if kind == TYPE_DOMAIN:
            value = value.rstrip(".")
            if not value.isascii():
                deviant = idna_deviation(value)
                if deviant:
                    raise IocError(
                        "line {}: {!r} contains {!r}, which older IDNA and browsers "
                        "encode differently; write the name in its xn-- form "
                        "instead".format(lineno, value, deviant))
                # Store internationalised names in the punycode form that
                # browsers and DNS actually record, so matching is exact.
                try:
                    value = value.encode("idna").decode("ascii")
                except UnicodeError:
                    raise IocError("line {}: {!r} is not a valid domain "
                                   "name".format(lineno, value))
        problem = _value_problem(value, kind)
        if problem:
            raise IocError("line {}: {!r}: {}".format(
                lineno, value[:80], problem))
        ind = Indicator(value, tier, confidence, kind, source, family)
        prev = seen.get((kind, value))
        if prev is not None:
            if (prev.tier, prev.confidence) != (tier, confidence):
                raise IocError("line {}: conflicting duplicate classification for {!r}; "
                               "resolve the tier and confidence in this file".format(lineno, value))
            ind = _ioc_combine(prev, ind)
        seen[(kind, value)] = ind
        if len(seen) > _MAX_INDICATORS:
            raise IocError("more than {:,} indicators - refusing what looks "
                           "like a corrupted or hostile feed".format(
                               _MAX_INDICATORS))
    kept, skipped = _ioc_drop_shared(list(seen.values()))
    seen = {(i.type, i.value): i for i in kept}
    if not seen:
        # An empty list must never produce a report. A truncated download or an
        # emptied file would otherwise run a full scan, search for nothing, and
        # print a result that reads as reassurance.
        raise IocError("indicator file contains no indicators: {}".format(path))
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None
    s = IocSet(sorted(seen.values(), key=lambda i: (i.value, i.type)),
               os.path.abspath(path), mtime)
    s.asof = asof
    s.shared_skipped = skipped
    return s


# --- several indicator files at once ----------------------------------------
#
# The scanner can take the curated file plus any number of published STIX
# bundles (Amnesty, the MVT project, ...). They are merged into ONE set so every
# module keeps reading a single `ctx.iocs`. What each file contributed - and what
# it could not - is kept in `IocSet.sets` so the report can say so.

_MAX_MERGED = 100000


def _is_stix(path: str) -> bool:
    low = path.lower()
    if low.endswith((".stix2", ".stix", ".stix.json")):
        return True
    if low.endswith(".json"):
        return True
    return False


def load_any(path: str, source: str = "", family: str = "",
             allow_empty: bool = False) -> IocSet:
    """Load the curated tab-separated file or a STIX 2.x bundle by its name.
    `allow_empty` lets a phone-only bundle load as zero indicators when it is
    one of several files; merge() still refuses an all-empty result."""
    if _is_stix(path):
        from .stix import load_stix   # local import: stix imports this module
        imp = load_stix(path, source=source, family_fallback=family,
                        allow_empty=allow_empty)
        imp.indicators, skipped = _ioc_drop_shared(imp.indicators)
        if skipped:
            imp.not_applicable[SHARED_SERVICE_REASON] += skipped
        if not imp.indicators and not allow_empty:
            raise IocError("{}: no indicator in this bundle can be used by this tool".format(path))
        try:
            mtime = os.path.getmtime(path)
        except OSError:
            mtime = None
        s = IocSet(imp.indicators, os.path.abspath(path), mtime)
        s.sets = [imp.summary()]
        return s
    s = load(path)
    s.sets = [{"path": s.source_path, "format": "curated", "usable": len(s),
               "families": {}, "as_of": s.asof,
               "not_applicable_to_this_scan": ({SHARED_SERVICE_REASON: s.shared_skipped}
                                               if s.shared_skipped else {})}]
    return s


def _ioc_context_records(ind):
    return ind.contexts or (json.dumps({"source": ind.source, "artifact_type": ind.type,
                                       "role": ind.tier, "family": ind.family,
                                       "confidence": ind.confidence}, sort_keys=True),)


def _ioc_combine(prev, ind):
    """Retain publisher assertions while keeping the first file's classification."""
    contexts = _ioc_checked_contexts(_ioc_context_records(prev) + _ioc_context_records(ind))
    sources = "; ".join(dict.fromkeys(part for item in (prev.source, ind.source)
                                    for part in item.split("; ") if part))
    families = "; ".join(dict.fromkeys(part for item in (prev.family, ind.family)
                                     for part in item.split("; ") if part))
    return Indicator(prev.value, prev.tier, prev.confidence, prev.type, sources, families, contexts)


def _ioc_checked_contexts(records):
    """Never silently discard publisher versions or accept unbounded duplication."""
    unique = {}
    for record in records:
        unique[record] = None
        if len(unique) > _MAX_IOC_CONTEXTS:
            raise IocError("too many publisher assertions for one indicator; refusing ambiguous feed")
    return tuple(unique)


def merge(sets: List["IocSet"]) -> IocSet:
    """One IocSet from several. Where two files list the same value, keep one
    indicator and record BOTH attributions; the first file's tier wins, so the
    curated file (loaded first) keeps its more precise tiers."""
    if not sets:
        raise IocError("no indicator files were given")
    # The same rule load() enforces for one file, applied to the whole run: an
    # empty set must never produce a report, because "searched for nothing,
    # found nothing" reads exactly like reassurance.
    if not any(len(s) for s in sets):
        raise IocError("none of the indicator files holds an indicator that can "
                       "be checked on a computer")
    if len(sets) == 1:
        return sets[0]
    by_value: Dict[Tuple[str, str], Indicator] = {}   # keyed by (type, value)
    for s in sets:
        for ind in s.indicators:
            prev = by_value.get((ind.type, ind.value))
            if prev is None:
                by_value[(ind.type, ind.value)] = ind
                continue
            by_value[(ind.type, ind.value)] = _ioc_combine(prev, ind)
    if len(by_value) > _MAX_MERGED:
        raise IocError("more than {:,} indicators across all files - refusing"
                       .format(_MAX_MERGED))
    mtimes = [s.source_mtime for s in sets if s.source_mtime is not None]
    out = IocSet(sorted(by_value.values(), key=lambda i: (i.value, i.type)),
                 "; ".join(s.source_path for s in sets),
                 min(mtimes) if mtimes else None)
    # Freshness is only as good as the OLDEST file: a stale bundle among fresh
    # ones must still trip the warning.
    asofs = [s.asof for s in sets if s.asof]
    out.asof = min(asofs) if asofs and len(asofs) == len(sets) else None
    # Keep each component's date and unknown state. An undated file must not
    # erase an old curated date or make a new filesystem copy look fresh.
    out._freshness_members = list(sets)
    out.sets = [entry for s in sets for entry in getattr(s, "sets", [])]
    return out
