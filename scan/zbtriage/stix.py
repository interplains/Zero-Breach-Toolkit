"""Import STIX 2.x indicator bundles into the scanner's indicator model.

STIX is the format Amnesty International's Security Lab, the MVT project and
others publish mercenary-spyware indicators in. Every published bundle seen so
far (19 files, 11,632 indicators, surveyed 2026-10-25) uses exactly one simple
comparison per indicator:

    [domain-name:value='example.com']
    [ipv4-addr:value='203.0.113.7']
    [file:hashes.sha256='<64 hex>']
    [app:id='com.example'] / [process:name='x'] / [email-addr:value='x'] ...

and links each indicator to its malware family with an `indicates`
relationship. Domain, IP and SHA-256 indicators are matched on a computer.
Device kinds (Android app ids and signing certificates, iOS process names,
configuration profiles, file paths and names, Android properties, operator
email addresses) are KEPT for the phone-backup and mail checks. Anything else
is COUNTED as not applicable rather than dropped silently, so a report can say
how much of a published set it could not use.

Doctrine carried over from iocs.py:
  - A hostile or corrupt value is never scanned for. Unlike the curated file, a
    third-party bundle is not under our editorial control, so one bad value
    skips that indicator (counted, with its reason) instead of aborting the
    whole load. A bundle that yields nothing usable is still a hard error.
  - Nothing here resolves, fetches or contacts anything. Text in, objects out.
"""

from __future__ import annotations

import collections
import io
import ipaddress
import json
import os
import re
from typing import Dict, List, Optional, Tuple

from .iocs import (_ipv4_leading_zero, COMPUTER_TYPES, TYPE_ANDROID_PROP, TYPE_APP_CERT, TYPE_APP_ID,
                   TYPE_DOMAIN, TYPE_EMAIL, TYPE_FILE_NAME, TYPE_FILE_PATH, TYPE_IP,
                   TYPE_PROCESS, TYPE_PROFILE, TYPE_SHA1, TYPE_SHA256, Indicator, IocError,
                   _value_problem, _ioc_checked_contexts, idna_deviation, infer_type)

TIER_ARTIFACT = "artifact"           # a device artefact (app, process, profile, path ...)

# Size and count caps: a published bundle is a few MB at most. Anything far
# larger is a corrupted or hostile file, and parsing it would just burn memory.
STIX_MAX_BYTES = 64 * 1024 * 1024
MAX_OBJECTS = 200000

TIER_INFRA = "infrastructure"        # a domain the researchers attribute to the family
TIER_INFRA_IP = "infrastructure-ip"  # an IP address, which decays as hosting is reassigned
TIER_SAMPLE = "sample"               # a file hash of the spyware or its installer

# One comparison, optionally quoted property path: hashes.sha256 or hashes.'SHA-256'.
# String literals are single-quoted only, as in the OASIS pattern grammar
# (cti-stix2-json-schemas/pattern_grammar/STIXPattern.g4: QUOTE : '\''), so a
# double-quoted value is not valid STIX and is correctly counted as unparsed.
# Multi-clause patterns (AND, OR, FOLLOWEDBY) are valid but are also counted
# unparsed rather than split: an AND cannot be reduced to one value without
# over-matching. Re-checked 2026-10-26 across every set --update fetches: 11,975
# indicator objects, none dropped. Re-survey before relying on that for a new feed.
_PATTERN_RE = re.compile(
    r"^\[\s*([a-z0-9-]+)\s*:\s*([a-z0-9_.'-]+?)\s*=\s*'([^'\\]*)'\s*\]$", re.I)

_SHA256_PROPS = {"hashes.sha256", "hashes.'sha-256'", "hashes.sha-256", "hashes.'sha256'"}
_SHA1_PROPS = {"hashes.sha1", "hashes.'sha-1'", "hashes.sha-1", "hashes.'sha1'"}


_DEVICE_KINDS = {
    ("app", "id"): TYPE_APP_ID,
    ("app", "cert.sha1"): TYPE_APP_CERT,
    ("app", "cert.sha256"): TYPE_APP_CERT,
    ("process", "name"): TYPE_PROCESS,
    ("configuration-profile", "id"): TYPE_PROFILE,
    ("file", "path"): TYPE_FILE_PATH,
    ("file", "name"): TYPE_FILE_NAME,
    ("android-property", "name"): TYPE_ANDROID_PROP,
    ("email-addr", "value"): TYPE_EMAIL,
}


def _classify(obj_type: str, prop: str) -> Optional[str]:
    """Which of our indicator types this STIX comparison is, or None if the
    tool has no use for it (counted as not applicable)."""
    obj_type, prop = obj_type.lower(), prop.lower()
    if obj_type == "domain-name" and prop == "value":
        return TYPE_DOMAIN
    if obj_type in ("ipv4-addr", "ipv6-addr") and prop == "value":
        return TYPE_IP
    if obj_type == "file" and prop in _SHA256_PROPS:
        return TYPE_SHA256
    if obj_type == "file" and prop in _SHA1_PROPS:
        return TYPE_SHA1
    return _DEVICE_KINDS.get((obj_type, prop))


_APP_ID_RE = re.compile(r"^[a-z0-9_]+(\.[a-z0-9_]+)+$")
_PROCESS_RE = re.compile(r"^[a-z0-9._+ -]{1,64}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
_PROP_RE = re.compile(r"^[a-z0-9_.-]{3,128}$")
_EMAIL_RE = re.compile(r"^[a-z0-9._%+-]{1,64}@[a-z0-9.-]+\.[a-z]{2,}$")


def _device_problem(kind: str, value: str) -> str:
    """Why a device indicator is unusable, or ''. These are matched by EXACT
    equality against values the phone/backup checks read, never as substrings,
    so short real values (Pegasus used process names like 'bh') are fine."""
    if kind == TYPE_APP_ID:
        return "" if len(value) <= 255 and _APP_ID_RE.match(value) else "not an Android package name"
    if kind == TYPE_APP_CERT:
        return "" if re.match(r"^([0-9a-f]{40}|[0-9a-f]{64})$", value) else "not a certificate fingerprint"
    if kind == TYPE_PROCESS:
        return "" if _PROCESS_RE.match(value) else "not a process name"
    if kind == TYPE_PROFILE:
        return "" if _UUID_RE.match(value) else "not a profile UUID"
    if kind == TYPE_FILE_PATH:
        return "" if value.startswith("/") and 2 <= len(value) <= 512 else "not an absolute path"
    if kind == TYPE_FILE_NAME:
        return "" if 2 <= len(value) <= 255 and "/" not in value else "not a file name"
    if kind == TYPE_ANDROID_PROP:
        return "" if _PROP_RE.match(value) else "not an Android property name"
    if kind == TYPE_EMAIL:
        return "" if _EMAIL_RE.match(value) else "not an email address"
    return "unsupported type"


def _ip_problem(value: str) -> str:
    """Extra refusal for imported IPs: a spyware server is on the public
    internet. A private, loopback, link-local or multicast address in a feed is
    a corruption, and scanning for it would match ordinary local traffic."""
    try:
        if _ipv4_leading_zero(value):
            raise ValueError("leading zero")
        addr = ipaddress.ip_address(value)
    except ValueError:
        return "not a valid IP address"
    if not addr.is_global:
        return "not a public internet address"
    return ""


def _normalise(kind: str, raw: str) -> Tuple[str, str]:
    """(value, problem). Problem is empty when the value is safe to scan for."""
    value = raw.strip().lower()
    if any(c in value for c in "\ufeff\u200b\u200c\u200d\u2060") or any(
            ord(c) < 0x20 for c in value):
        return value, "contains invisible or control characters"
    if kind == TYPE_DOMAIN:
        value = value.rstrip(".")
        if value.startswith("*."):
            return value, "wildcard domains are not supported"
        if not value.isascii():
            if idna_deviation(value):
                # See iocs.idna_deviation: encoding it would store the wrong name.
                return value, "older IDNA and browsers encode this name differently"
            try:
                value = value.encode("idna").decode("ascii")
            except UnicodeError:
                return value, "not a valid domain name"
        if infer_type(value) != TYPE_DOMAIN:
            # Seen in published bundles: IP addresses filed under domain-name.
            # Those are handled by the caller as IPs; anything else that is not
            # hostname-shaped (e.g. a bare hex string) is refused.
            return value, "listed as a domain but shaped like an address or hash"
        return value, _value_problem(value, TYPE_DOMAIN)
    if kind == TYPE_IP:
        problem = _value_problem(value, TYPE_IP)
        return value, problem or _ip_problem(value)
    if kind == TYPE_SHA256:
        if not re.match(r"^[0-9a-f]{64}$", value):
            return value, "not a 64-digit SHA-256"
        return value, ""
    if kind == TYPE_SHA1:
        if not re.match(r"^[0-9a-f]{40}$", value):
            return value, "not a 40-digit SHA-1"
        return value, ""
    return value, _device_problem(kind, value)


class StixImport:
    """What one bundle contributed, and what it could not."""

    def __init__(self, path: str):
        self.path = path
        self.indicators: List[Indicator] = []
        self.total = 0                                         # indicator objects seen
        self.not_applicable: Dict[str, int] = collections.Counter()  # e.g. "app:id": 686
        self.invalid: Dict[str, int] = collections.Counter()         # reason -> count
        self.unparsed = 0                                      # patterns we could not read
        self.duplicates = 0
        self.families: Dict[str, int] = collections.Counter()

    def summary(self) -> Dict[str, object]:
        return {
            "path": self.path,
            "format": "stix2",
            "indicator_objects": self.total,
            "usable": sum(1 for i in self.indicators if i.type in COMPUTER_TYPES),
            "device_indicators": dict(sorted(collections.Counter(
                i.type for i in self.indicators if i.type not in COMPUTER_TYPES).items())),
            "not_applicable_to_this_scan": dict(sorted(self.not_applicable.items())),
            "refused_invalid": dict(sorted(self.invalid.items())),
            "unparsed_patterns": self.unparsed,
            "duplicates": self.duplicates,
            "families": dict(sorted(self.families.items())),
        }


def load_stix(path: str, source: str = "", confidence: str = "primary",
              family_fallback: str = "", allow_empty: bool = False) -> StixImport:
    """Read one STIX 2.x bundle. Raises IocError if the file is missing,
    oversized or not a STIX bundle. A bundle with no indicator this tool can use
    is an error on its own, but with `allow_empty` it is returned empty so a
    folder of bundles still loads - the caller must then make sure SOMETHING
    usable was loaded overall."""
    if not os.path.exists(path):
        raise IocError("indicator file not found: {}".format(path))
    size = os.path.getsize(path)
    if size > STIX_MAX_BYTES:
        raise IocError("{}: {:,} bytes is far larger than any published indicator "
                       "bundle - refusing it".format(path, size))
    try:
        with io.open(path, encoding="utf-8-sig") as fh:
            doc = json.load(fh)
    except (ValueError, UnicodeError, RecursionError) as exc:
        # RecursionError: absurdly deep nesting, never a real indicator bundle.
        raise IocError("{}: not valid STIX JSON ({})".format(path, type(exc).__name__ if
                       isinstance(exc, RecursionError) else exc))
    objects = doc.get("objects") if isinstance(doc, dict) else None
    if not isinstance(objects, list):
        raise IocError("{}: not a STIX bundle (no 'objects' list)".format(path))
    if len(objects) > MAX_OBJECTS:
        raise IocError("{}: {:,} objects - refusing what looks like a corrupted or "
                       "hostile bundle".format(path, len(objects)))

    result = StixImport(os.path.abspath(path))
    src = source or os.path.basename(path)

    # Family names: malware / intrusion-set objects, linked by `indicates`.
    names: Dict[str, str] = {}
    for o in objects:
        if isinstance(o, dict) and o.get("type") in ("malware", "intrusion-set", "tool"):
            name = str(o.get("name") or "").strip()
            if name and isinstance(o.get("id"), str):
                names[o["id"]] = _clean_label(name)
    linked: Dict[str, List[str]] = collections.defaultdict(list)
    for o in objects:
        if (isinstance(o, dict) and o.get("type") == "relationship"
                and o.get("relationship_type") == "indicates"
                and isinstance(o.get("target_ref"), str)
                and o.get("target_ref") in names):
            linked[str(o.get("source_ref"))].append(names[o["target_ref"]])
    only_family = next(iter(names.values())) if len(set(names.values())) == 1 else ""
    default_family = only_family or _clean_label(family_fallback)

    identities = {o.get("id"): _clean_label(o.get("name", "")) for o in objects
                  if isinstance(o, dict) and o.get("type") == "identity" and isinstance(o.get("id"), str)}
    seen: Dict[Tuple[str, str], Indicator] = {}
    families_by_value = {}
    for o in objects:
        if not (isinstance(o, dict) and o.get("type") == "indicator"):
            continue
        result.total += 1
        pattern = o.get("pattern")
        m = _PATTERN_RE.match(pattern) if isinstance(pattern, str) else None
        if not m:
            result.unparsed += 1
            continue
        obj_type, prop, raw = m.group(1), m.group(2), m.group(3)
        kind = _classify(obj_type, prop)
        if kind is None:
            result.not_applicable["{}:{}".format(obj_type.lower(), prop.lower())] += 1
            continue
        if kind == TYPE_DOMAIN and infer_type(raw.strip().lower().rstrip(".")) == TYPE_IP:
            kind = TYPE_IP          # an address filed under domain-name
        if kind == TYPE_FILE_NAME and raw.strip().startswith("/"):
            # Some publishers put a full path in file:name; it is used as a path.
            kind = TYPE_FILE_PATH
        value, problem = _normalise(kind, raw)
        if problem:
            result.invalid[problem] += 1
            continue
        # A linked name that cleans to nothing must not block the fallback family.
        family_names = {name for name in linked.get(str(o.get("id")), []) if name} or {default_family}
        family = "; ".join(sorted(name for name in family_names if name))
        if kind in (TYPE_SHA256, TYPE_SHA1):
            tier = TIER_SAMPLE
        elif kind == TYPE_IP:
            tier = TIER_INFRA_IP
        elif kind in (TYPE_DOMAIN, TYPE_EMAIL):
            tier = TIER_INFRA
        else:
            tier = TIER_ARTIFACT
        platforms = o.get("x_mvt_platforms", o.get("x_platforms", []))
        if isinstance(platforms, str):
            platforms = [platforms]
        if not isinstance(platforms, list):
            platforms = []
        context = {"source": _clean_label(src), "publisher": identities.get(o.get("created_by_ref"), "") if isinstance(o.get("created_by_ref"), str) else "",
                   "artifact_type": kind, "role": tier, "family": family, "revoked": o.get("revoked") is True,
                   "platforms": [_clean_label(v) for v in platforms[:10] if isinstance(v, str)]}
        if kind in (TYPE_FILE_PATH, TYPE_FILE_NAME, TYPE_PROCESS):
            # Typed lookup remains compatible with Windows/phone consumers.
            # Unix configuration readers need the publisher's exact case to
            # distinguish different files on case-sensitive filesystems.
            context["case_sensitive_value"] = raw.strip()
        for field in ("created", "modified", "valid_from", "valid_until"):
            if isinstance(o.get(field), str):
                context[field] = _clean_label(o[field])
        # Versions belong to one object id: revoking one indicator object does
        # not withdraw a different, still active object for the same value.
        if isinstance(o.get("id"), str):
            context["id"] = _clean_label(o["id"])
        encoded = json.dumps(context, sort_keys=True)
        # Keyed by (type, value): an app id is shaped like a domain.
        previous_families = families_by_value.setdefault((kind, value), set())
        previous_families.update(family_names)
        combined_family = "; ".join(sorted(name for name in previous_families if name))
        if (kind, value) in seen:
            result.duplicates += 1
            prev = seen[(kind, value)]
            seen[(kind, value)] = Indicator(prev.value, prev.tier, prev.confidence, prev.type,
                                           prev.source, combined_family, _ioc_checked_contexts(prev.contexts + (encoded,)))
            continue
        seen[(kind, value)] = Indicator(value, tier, confidence, kind, src, family, (encoded,))

    # Counted once all objects are merged: a value attributed to a family by any
    # object is not also counted as unattributed.
    for names in families_by_value.values():
        for name in ({name for name in names if name} or {""}):
            result.families[name or "(unattributed)"] += 1
    result.indicators = sorted(seen.values(), key=lambda i: (i.value, i.type))
    if not result.indicators and not allow_empty:
        raise IocError("{}: no indicator in this bundle can be used by this tool"
                       .format(path))
    return result


def _clean_label(text: str) -> str:
    """Family names come from a third-party file and are printed into reports
    and read by AI assistants. Keep them short, single-line and printable."""
    text = re.sub(r"[\x00-\x1f\x7f]+", " ", str(text)).strip()
    return text[:80]
