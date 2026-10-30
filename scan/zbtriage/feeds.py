"""Official published indicator sources, and the `--update` command.

The scan itself never touches the network (netguard.no_network). Updating the
indicator sets is a separate, explicit step that downloads ONLY from the fixed
list below - the sources Amnesty International's MVT project indexes, plus three
older Amnesty publications MVT does not list - into a per-user cache. Several of
these repositories carry no licence, so they are fetched from the original
source at the user's request (as MVT itself does) rather than redistributed.

Safety rules, each enforced in code and pinned by tests/test_feeds.py:
  - only https://raw.githubusercontent.com/<allow-listed owner>/... ; a redirect
    anywhere else is refused;
  - by default each source is downloaded at the commit pinned for this release
    (FEED_PINS), and must match the SHA-256 this release recorded for it
    (FEED_FILE_SHA256); `--update --latest` follows the upstream branch instead;
  - every download is size-capped, must not be an HTML page, and must parse
    into at least one usable indicator BEFORE it replaces the cached copy - a
    failed download keeps the previous good copy;
  - the SHA-256 of every cached file is recorded in a manifest and re-checked
    when a scan loads it. That detects accidental corruption; it cannot stop
    someone able to edit both the file and the manifest. A file from a pinned
    download is also compared with the hash recorded in the release itself;
  - an indicator is never resolved or contacted: these are text files.
"""

from __future__ import annotations

import csv
import dataclasses
import datetime
import hashlib
import io
import json
import os
import ssl
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, Dict, List, Optional, Tuple

from . import __version__
from .iocs import (SHARED_SERVICE_HOSTS, SHARED_SERVICE_REASON, TYPE_DOMAIN, TYPE_IP,
                   TYPE_SHA256, Indicator, IocError, IocSet, infer_type, load_any,
                   shared_service_domain)
from .localpaths import path_problem
from .stix import TIER_INFRA, TIER_INFRA_IP, TIER_SAMPLE, _normalise

RAW = "https://raw.githubusercontent.com/"
ALLOWED_OWNERS = ("mvt-project/mvt-indicators/", "AmnestyTech/investigations/",
                  "AssoEchap/stalkerware-indicators/", "citizenlab/malware-indicators/")
ALLOWED_PREFIXES = tuple(RAW + o for o in ALLOWED_OWNERS)
MAX_DOWNLOAD = 64 * 1024 * 1024
TIMEOUT_S = 60


def _src(sid, name, owner_repo_branch, path, fmt, cite, category="mercenary",
         family=""):
    owner, repo, _branch = owner_repo_branch.strip("/").split("/")
    return {"id": sid, "name": name, "url": RAW + owner_repo_branch + path,
            "repo": owner + "/" + repo, "path": path,
            "format": fmt, "cite": cite, "category": category, "family": family}


# --- pinned revisions: written by tools/pin_feeds.py --------------------------
# Each source repository at a reviewed commit, and the SHA-256 of every source
# file at that commit. Bumped in a release after the upstream changes are read.
FEED_PINS = {
    "AmnestyTech/investigations": "3d8f248a0d015f183724ae7d096a5c46a8bb5fc7",
    "AssoEchap/stalkerware-indicators": "426156175adc84af7fbdd41486c046f9ecb40436",
    "citizenlab/malware-indicators": "7a7ae9278fa2c0252e9e40faed9b498d6a8d5248",
    "mvt-project/mvt-indicators": "b22ddf05e1a31e7732b8895676987c5c3482ef65",
}
FEED_IOS_ONLY_APP_IDS = {
    "echap-stalkerware": [
        "com.contentwatch.ghoti.cp2.parent",
        "com.life360.safetymap",
        "com.qustodio.mdm.app.family.pro",
        "com.qustodio.par.qustodio-family-parental-control-app",
        "com.wheremychildren.ios",
    ],
}
FEED_FILE_SHA256 = {
    "amnesty-android-campaign-2023": "28da50042006281d56c17dff08f06bba3ba310bc18cc23040780850131b2efdb",
    "amnesty-cytrox-2021": "6fe92193d9e17c21a16eb7abe93a418a2e40c0176dcb56fb30539f84136391bb",
    "amnesty-finfisher-2020": "cc5d59d5f868984bae06df93989d95f49670d808dafbbefadd4bc0df0573b6de",
    "amnesty-novispy-2024": "02bfceea5a2c32b159f11569736448398e35e7f0fc7d137385b943ec60697360",
    "amnesty-nso-2018": "4e450de9219a6cb9a6888c352abb5e8b62fa33ebadd70238e5f69a5a08329579",
    "amnesty-nso-morocco-2019": "29c183256cee9c04147e09bd50d29094f85a8b40dec500aa00ffcf02b368f63e",
    "amnesty-pegasus-2021": "df1bcaa78abc7b85781b1ebc2daa3cc225371e2024d9ef96e84f80f927256586",
    "amnesty-wintego-helios-2024": "d0d546c388207e8a162eb3901259ee20c0ddd03efeff145d3cc9b3a0a02a5419",
    "citizenlab-cyberbit-2017": "3ca53475a3c96630b5c9fb42fba688b9123fcd21a236de41ef0f53ba419e70d1",
    "citizenlab-kingdom-2018": "835b1a105a4f16b994013955bc41bfedc32eff56f586bf3faadea9888498c506",
    "citizenlab-nso-2016": "7c005140f65b4043c7fad35a7c39ceeb51da5133810c2b0b4b57428f33a3ceed",
    "citizenlab-nso-insider-2017": "87cd4cb85b4a3808ff231f6c22e79f387328ba1b36ab576b61b455562f8afbc2",
    "citizenlab-nso-mexico-exploit-2017": "b260da1f4e1dd15cfc804be734431c602bb6abee00bf8c5cc4c4e41d3638280a",
    "citizenlab-nso-mexico-redux-2017": "62d614e4f11a1652ef8020676269b9cfc85b6b0db36e45b43a4d397776387c5d",
    "echap-stalkerware": "60307b49256d726a55e5b29e5243113021b26f2c91b492da4bcd2eb579739a98",
    "mvt-btmob": "6bada3d46e6ac53019d80ccea991611125e8eefdd00b5bd0ea23ac48f2dca15a",
    "mvt-candiru": "684f9e60da472ec938c7cd003adb3e3b97d29a0a43fed7565c9ef29c19bedb86",
    "mvt-cellebrite": "054436c35a1e715ff2ea55a9516364108239cde238afdd096b21c3da90f97d2a",
    "mvt-coruna": "653887014af347a107144036c9388af714f7a728661d6026dbe8b66db4acbfe4",
    "mvt-darksword": "a694a8f3a37866ae30d72aab84fffd3a89d848406adfc0eac3237805b1c6826c",
    "mvt-eaglemsgspy": "033af3e26f764ace084d8ed3cdb6eeba833b1d9d1f2708fd65289e12a45136b5",
    "mvt-morpheus": "fa327338e33b017f8633a33ddc2a0364a1ecfa8fd99b821e53a5c2e4cdb33094",
    "mvt-operation-triangulation": "320a3aa1147f7c87b92db46a6c977c75d721d74e8266978dc74d9ed2ca7383f5",
    "mvt-predator": "99938ba179216f73e54513c4c537e3951ae860bcc6eaa5a93055f4afbb689879",
    "mvt-quadream-kingspawn": "fd47acd30388738083fb1e4e09ce7f2032885ec1217a5edc75ef8e71a81fee3f",
    "mvt-rcs-lab": "db7473900259bc28ef20145c315af5bcb99451715703bc78563338f656b213b2",
    "mvt-residentbat": "d52ca6753a80578a25df2b907ae5dd3305b00e2345baa843d0c91dfac52c50c5",
    "mvt-spyrtacus": "44a7f68629cfeb5952a646986f5ef24395656631d6cca636bf283c024714ad4e",
    "mvt-wyrmspy-dragonegg": "b5495ca605b2150e76bb8322cfc6f484382db6070f806672f70edf3b0511e4f3",
}
# --- end of pinned revisions --------------------------------------------------


def _pinned_url(src):
    """The download URL at this release's pinned commit, or None."""
    pin = FEED_PINS.get(src.get("repo", ""))
    if not pin or not src.get("path"):
        return None
    return RAW + src["repo"] + "/" + pin + "/" + src["path"]


# Snapshot of mvt-project/mvt-indicators/indicators.yaml (19 entries, read
# 2026-10-25), plus four Amnesty folders that index does not include.
SOURCES: List[Dict[str, str]] = [
    _src("amnesty-pegasus-2021", "NSO Group Pegasus", "AmnestyTech/investigations/master/",
         "2021-07-18_nso/pegasus.stix2", "stix2", "Amnesty International (2021)"),
    _src("mvt-predator", "Intellexa Predator", "mvt-project/mvt-indicators/main/",
         "intellexa_predator/predator.stix2", "stix2",
         "Meta, Amnesty International, Citizen Lab, Cisco, Inside Story, iVerify"),
    _src("mvt-rcs-lab", "RCS Lab", "mvt-project/mvt-indicators/main/",
         "2022-06-23_rcs_lab/rcs.stix2", "stix2", "Google, Lookout"),
    _src("echap-stalkerware", "Stalkerware (154 apps)", "AssoEchap/stalkerware-indicators/master/",
         "generated/stalkerware.stix2", "stix2", "ECHAP", category="stalkerware"),
    _src("amnesty-android-campaign-2023", "Mercenary spyware campaign (Android)",
         "AmnestyTech/investigations/master/", "2023-03-29_android_campaign/malware.stix2",
         "stix2", "Amnesty International, Google"),
    _src("mvt-quadream-kingspawn", "QuaDream KingSpawn", "mvt-project/mvt-indicators/main/",
         "2023-04-11_quadream/kingspawn.stix2", "stix2", "Citizen Lab, Microsoft"),
    _src("mvt-operation-triangulation", "Operation Triangulation", "mvt-project/mvt-indicators/main/",
         "2023-06_01_operation_triangulation/operation_triangulation.stix2", "stix2",
         "Kaspersky Lab"),
    _src("mvt-wyrmspy-dragonegg", "WyrmSpy and DragonEgg", "mvt-project/mvt-indicators/main/",
         "2023-07-25_wyrmspy_dragonegg/wyrmspy_dragonegg.stix2", "stix2", "Lookout"),
    _src("amnesty-wintego-helios-2024", "Wintego Helios", "AmnestyTech/investigations/master/",
         "2024-05-02_wintego_helios/wintego_helios.stix2", "stix2", "Amnesty International"),
    _src("amnesty-novispy-2024", "NoviSpy (Serbia)", "AmnestyTech/investigations/master/",
         "2024-12-16_serbia_novispy/novispy.stix2", "stix2", "Amnesty International"),
    _src("mvt-eaglemsgspy", "EagleMsgSpy", "mvt-project/mvt-indicators/main/",
         "2024-12-25_eaglemsgspy/eaglemsgspy.stix2", "stix2", "Lookout"),
    _src("mvt-candiru", "Candiru (DevilsTongue)", "mvt-project/mvt-indicators/main/",
         "candiru/candiru.stix2", "stix2", "Microsoft, Recorded Future"),
    _src("mvt-residentbat", "ResidentBat", "mvt-project/mvt-indicators/main/",
         "ResidentBat/residentbat.stix2", "stix2", "Reporters Without Borders, RESIDENT.NGO"),
    _src("mvt-cellebrite", "Cellebrite", "mvt-project/mvt-indicators/main/",
         "cellebrite/cellebrite.stix2", "stix2", "Citizen Lab"),
    _src("mvt-darksword", "DarkSword", "mvt-project/mvt-indicators/main/",
         "2026-03-30_darksword/darksword.stix2", "stix2",
         "Google Threat Intelligence Group, iVerify, Lookout"),
    _src("mvt-coruna", "Coruna", "mvt-project/mvt-indicators/main/",
         "2026-03-03_coruna_cryptowaters/coruna.stix2", "stix2",
         "Google Threat Intelligence Group, iVerify"),
    _src("mvt-morpheus", "Morpheus", "mvt-project/mvt-indicators/main/",
         "2026-04-23_ips_morpheus/morpheus.stix2", "stix2", "Osservatorio Nessuno"),
    _src("mvt-btmob", "BTMOB", "mvt-project/mvt-indicators/main/",
         "2026-05-26_btmob/btmob.stix2", "stix2", "ESET, Cyble Research, Zimperium"),
    _src("mvt-spyrtacus", "Spyrtacus", "mvt-project/mvt-indicators/main/",
         "2026-04-09_sio_spyrtacus/spyrtacus.stix2", "stix2", "Osservatorio Nessuno"),
    # Not in MVT's index:
    _src("amnesty-nso-2018", "NSO Group (2018)", "AmnestyTech/investigations/master/",
         "2018-08-01_nso/indicators.csv", "csv-domain-ip",
         "Amnesty International (2018-08-01), NSO Group infrastructure", family="Pegasus"),
    _src("amnesty-nso-morocco-2019", "NSO Group (Morocco, 2019)",
         "AmnestyTech/investigations/master/", "2019-10-10_nso_morocco/domains.txt",
         "domains-txt", "Amnesty International (2019-10-10), Morocco", family="Pegasus"),
    _src("amnesty-cytrox-2021", "Cytrox (Predator, 2021)", "AmnestyTech/investigations/master/",
         "2021-12-16_cytrox/cytrox.stix2", "stix2",
         "Meta, Citizen Lab, Amnesty International (2021-12-16)", family="Predator"),
    _src("amnesty-finfisher-2020", "FinFisher / FinSpy (Gamma Group)",
         "AmnestyTech/investigations/master/", "2020-09-25_finfisher/domains.txt",
         "domains-txt",
         "Amnesty International (2020-09-25), FinSpy for Windows, Android and Linux",
         family="FinSpy"),
    # Citizen Lab's indicator repository (MISP CSV exports), Israeli vendors only:
    _src("citizenlab-nso-2016", "NSO Group (Trident / Ahmed Mansoor, 2016)",
         "citizenlab/malware-indicators/master/", "201608_NSO_Group/iocs.csv", "misp-csv",
         "The Citizen Lab, 'The Million Dollar Dissident' (2016-08)", family="Pegasus"),
    _src("citizenlab-cyberbit-2017", "Cyberbit (Ethiopia, 2017)",
         "citizenlab/malware-indicators/master/", "201712_Cyberbit/iocs.csv", "misp-csv",
         "The Citizen Lab, 'Champing at the Cyberbit' (2017-12)",
         family="Cyberbit PC Surveillance System"),
    _src("citizenlab-kingdom-2018", "NSO Group (The Kingdom Came to Canada, 2018)",
         "citizenlab/malware-indicators/master/", "201810_TheKingdomCameToCanada/iocs.csv",
         "misp-csv", "The Citizen Lab, 'The Kingdom Came to Canada' (2018-10)", family="Pegasus"),
    _src("citizenlab-nso-mexico-exploit-2017", "NSO Group (Reckless Exploit, Mexico, 2017)",
         "citizenlab/malware-indicators/master/", "201706_RecklessExploit/iocs.csv", "misp-csv",
         "The Citizen Lab, 'Reckless Exploit' (2017-06), Mexico", family="Pegasus"),
    _src("citizenlab-nso-mexico-redux-2017", "NSO Group (Reckless Redux, Mexico, 2017)",
         "citizenlab/malware-indicators/master/", "201706_RecklessRedux/iocs.csv", "misp-csv",
         "The Citizen Lab, 'Reckless Redux' (2017-06), Mexico", family="Pegasus"),
    _src("citizenlab-nso-insider-2017", "NSO Group (Insider Information, Mexico, 2017)",
         "citizenlab/malware-indicators/master/", "201707_InsiderInfo/indicators.csv", "misp-csv",
         "The Citizen Lab, 'Insider Information' (2017-07), Mexico", family="Pegasus"),
]

MANIFEST = "manifest.json"
_EXT = {"stix2": ".stix2", "csv-domain-ip": ".csv", "domains-txt": ".txt",
        "misp-csv": ".misp.csv"}

# MISP attribute types -> our kinds. URLs contribute their host name. MD5 and
# SHA-1 sample hashes are counted as not applicable: the file check computes
# SHA-256 only.
_MISP_KINDS = {"domain": TYPE_DOMAIN, "hostname": TYPE_DOMAIN, "ip-dst": TYPE_IP,
               "ip-src": TYPE_IP, "sha256": TYPE_SHA256, "url": "url"}

# A malicious LINK on a shared public service (a URL shortener, a file or page
# host) condemns that one link, not the service: Citizen Lab's Mexico sets list
# dozens of bit.ly and tinyurl.com links, and reducing them to their host would
# grade every ordinary bit.ly visit as contact with Pegasus infrastructure. Such
# URLs are counted as not applicable instead (the scan has no per-link matching).
_SHARED_LINK_HOSTS = SHARED_SERVICE_HOSTS  # one list for every loader (iocs.py)


def _shared_link_host(host: str) -> bool:
    host = (host or "").lower().rstrip(".")
    return any(host == h or host.endswith("." + h) for h in _SHARED_LINK_HOSTS)


# --- where the cache lives ----------------------------------------------------

def default_cache_dir() -> str:
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
        return os.path.join(base, "ZeroBreachTriage", "indicators")
    if sys.platform == "darwin":
        return os.path.expanduser("~/Library/Caches/zero-breach-triage/indicators")
    base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(base, "zero-breach-triage", "indicators")


# --- plain-list formats (the older Amnesty publications) ------------------------

def load_list(path: str, fmt: str, source: str, family: str) -> IocSet:
    """A domains.txt (one per line) or a 'domain_name,ip_address' CSV, with the
    same validation as STIX imports. Refused values are counted, not scanned."""
    found: Dict[Tuple[str, str], Indicator] = {}
    refused: Dict[str, int] = {}
    not_applicable: Dict[str, int] = {}

    def add(raw: str, kind: str) -> None:
        raw = (raw or "").strip().strip('"')
        if not raw:
            return
        if kind == TYPE_DOMAIN and infer_type(raw.lower().rstrip(".")) == TYPE_IP:
            kind = TYPE_IP
        value, problem = _normalise(kind, raw)
        if problem:
            refused[problem] = refused.get(problem, 0) + 1
            return
        if kind == TYPE_DOMAIN and shared_service_domain(value):
            not_applicable[SHARED_SERVICE_REASON] = not_applicable.get(SHARED_SERVICE_REASON, 0) + 1
            return
        tier = (TIER_INFRA_IP if kind == TYPE_IP else
                TIER_SAMPLE if kind == TYPE_SHA256 else TIER_INFRA)
        found.setdefault((kind, value), Indicator(value, tier, "primary", kind, source, family))

    with io.open(path, encoding="utf-8-sig", errors="replace") as fh:
        if fmt == "domains-txt":
            for line in fh:
                line = line.split("#", 1)[0]
                add(line, TYPE_DOMAIN)
        elif fmt == "csv-domain-ip":
            for row in csv.DictReader(fh):
                add(row.get("domain_name", ""), TYPE_DOMAIN)
                add(row.get("ip_address", ""), TYPE_IP)
        elif fmt == "misp-csv":
            for row in csv.DictReader(fh):
                mtype = (row.get("type") or "").strip().lower()
                kind = _MISP_KINDS.get(mtype)
                if kind is None:
                    not_applicable[mtype or "?"] = not_applicable.get(mtype or "?", 0) + 1
                elif kind == "url":
                    host = urllib.parse.urlsplit((row.get("value") or "").strip()).hostname
                    if _shared_link_host(host or ""):
                        reason = "link on a shared service (only that link was malicious)"
                        not_applicable[reason] = not_applicable.get(reason, 0) + 1
                    else:
                        add(host or "", TYPE_DOMAIN)
                else:
                    add(row.get("value", ""), kind)
        else:
            raise IocError("{}: unknown list format {!r}".format(path, fmt))
    if not found:
        raise IocError("{}: no usable indicator in this list".format(path))
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        mtime = None
    s = IocSet(sorted(found.values(), key=lambda i: (i.value, i.type)), os.path.abspath(path), mtime)
    s.sets = [{"path": os.path.abspath(path), "format": fmt, "usable": len(found),
               "device_indicators": {}, "refused_invalid": dict(sorted(refused.items())),
               "not_applicable_to_this_scan": dict(sorted(not_applicable.items())),
               "families": {family: len(found)}}]
    return s


def _stix_monitoring_kinds(path):
    """{indicator value: "watchware" | "stalkerware"} from the malware objects'
    descriptions in a stalkerware STIX bundle. A value tied to both kinds is
    treated as stalkerware, the stronger reading."""
    try:
        with open(path, "rb") as fh:
            doc = json.loads(fh.read(MAX_DOWNLOAD + 1).decode("utf-8"))
        objects = doc.get("objects") if isinstance(doc, dict) else None
        if not isinstance(objects, list):
            return {}
    except (OSError, ValueError, UnicodeDecodeError):
        return {}
    kind_of = {}
    for o in objects:
        if isinstance(o, dict) and o.get("type") == "malware" and isinstance(o.get("id"), str):
            text = str(o.get("description") or "").strip().lower()
            if text.startswith("watchware"):
                kind_of[o["id"]] = "watchware"
            elif text.startswith("stalkerware"):
                kind_of[o["id"]] = "stalkerware"
    patterns = {o.get("id"): o.get("pattern") for o in objects
                if isinstance(o, dict) and o.get("type") == "indicator"}
    out = {}
    for o in objects:
        if not (isinstance(o, dict) and o.get("type") == "relationship"):
            continue
        kind = kind_of.get(o.get("target_ref"))
        pattern = patterns.get(o.get("source_ref"))
        if not kind or not isinstance(pattern, str) or "='" not in pattern:
            continue
        value = pattern.split("='", 1)[1].rsplit("'", 1)[0].strip().lower()
        if out.get(value) != "stalkerware":
            out[value] = kind
    return out


def _mark_contexts(ind, kind, ios):
    """The indicator's publisher records with the monitoring kind and, for an
    iPhone-only bundle id, the platform added."""
    if not kind and not ios:
        return ind.contexts
    records = []
    for raw in ind.contexts or ():
        try:
            record = json.loads(raw)
        except (TypeError, ValueError):
            record = None
        if not isinstance(record, dict):
            return ind.contexts
        if kind:
            record["monitoring"] = kind
        if ios:
            record["platforms"] = ["ios"]
        records.append(json.dumps(record, sort_keys=True))
    return tuple(records)


def _load_source_file(src: Dict[str, str], path: str) -> IocSet:
    cite = "{} ({})".format(src["cite"], src["name"])
    if src["format"] == "stix2":
        loaded = load_any(path, source=cite, family=src.get("family", ""), allow_empty=False)
    else:
        loaded = load_list(path, src["format"], cite, src.get("family", ""))
    if src.get("category") == "stalkerware":
        # The list names commercial phone-monitoring apps - including
        # family-safety apps people install knowingly (Life360, Microsoft Family
        # Safety, Kaspersky Safe Kids, Bark, Qustodio) - and their companies'
        # ordinary websites. EVERY kind (domains, app ids, certificates,
        # samples) is tiered apart, so no match can be presented as mercenary
        # spyware; the report asks whether the person knows about the app
        # instead. Indicators are immutable:
        # rebuild the set, keeping what load() recorded about the file.
        # The publisher's own classification travels with each indicator:
        # "watchware" for apps that do not hide themselves (the report words
        # them accordingly), and iPhone bundle ids marked as such so the
        # Android checks never match them (the STIX export writes both kinds
        # as app ids; the pinned list comes from the publisher's YAML).
        kinds = _stix_monitoring_kinds(path) if src["format"] == "stix2" else {}
        ios_ids = set(FEED_IOS_ONLY_APP_IDS.get(src["id"], ()))
        retiered = IocSet([dataclasses.replace(
                               i, tier="stalkerware",
                               contexts=_mark_contexts(i, kinds.get(i.value), i.value in ios_ids))
                           for i in loaded.indicators],
                          loaded.source_path, loaded.source_mtime)
        retiered.asof = loaded.asof
        retiered.sets = getattr(loaded, "sets", [])
        return retiered
    return loaded


# --- downloading ----------------------------------------------------------------

def url_allowed(url: str) -> bool:
    return isinstance(url, str) and url.startswith(ALLOWED_PREFIXES) and ".." not in url


class _AllowListRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not url_allowed(newurl):
            raise urllib.error.URLError("refused redirect outside the allow-list: {}"
                                        .format(newurl[:120]))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch(url: str) -> bytes:
    if not url_allowed(url):
        raise IocError("refused: not an allow-listed indicator source: {}".format(url))
    opener = urllib.request.build_opener(_AllowListRedirect())
    # A generic label: the sources' servers need not learn that this is a spyware check.
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with opener.open(req, timeout=TIMEOUT_S) as resp:
        data = resp.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise IocError("download larger than {:,} bytes - refused".format(MAX_DOWNLOAD))
    return data


def _certificate_problem(exc) -> bool:
    """True when a download failed because this Python cannot check HTTPS
    certificates (common with the python.org installer on a Mac until its
    Install Certificates step has been run)."""
    reason = getattr(exc, "reason", None)
    return (isinstance(exc, ssl.SSLCertVerificationError)
            or isinstance(reason, ssl.SSLCertVerificationError)
            or "CERTIFICATE_VERIFY_FAILED" in str(exc))


def _certificate_help(outcome="nothing was downloaded and the previous indicator lists were kept",
                      platform=None) -> str:
    """What to do when HTTPS certificates cannot be checked, for this system.
    `outcome` says what the failure left unchanged."""
    platform = sys.platform if platform is None else platform
    start = "this Python cannot check website certificates, so " + outcome + ". "
    if platform == "darwin":
        return (start + "To fix it once: open Finder, go to Applications, open the Python 3 folder "
                "and double-click Install Certificates.command, then try again.")
    if platform == "win32":
        # Windows fetches some root certificates only when a Windows program first
        # needs them, which Python cannot trigger; and antivirus HTTPS scanning
        # replaces sites' certificates with its own.
        return (start + "On Windows this usually means a certificate Windows downloads only when "
                "needed is missing, or an antivirus is inspecting secure connections. Open "
                "PowerShell, run: Invoke-WebRequest https://github.com -UseBasicParsing | Out-Null "
                "then try again. If it still fails, pause your antivirus's HTTPS scanning "
                "('web shield') for a moment and try again.")
    return (start + "Install or update the system's root certificates (on Linux the "
            "ca-certificates package), then try again.")


def _looks_like_html(data: bytes) -> bool:
    head = data[:512].lstrip().lower()
    return head.startswith((b"<!doctype html", b"<html", b"<head", b"<body"))


def _feed_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_manifest(cache: str) -> Dict[str, Dict[str, object]]:
    path = _feed_local_path(cache, MANIFEST)
    try:
        with io.open(path, encoding="utf-8") as fh:
            raw = fh.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("manifest exceeds size limit")
        doc = json.loads(raw)
        sources = doc.get("sources") if isinstance(doc, dict) else None
        if not isinstance(sources, dict):
            raise ValueError("manifest sources must be an object")
        return sources
    except FileNotFoundError:
        return {}
    except (OSError, ValueError, RecursionError) as exc:
        raise IocError("indicator manifest could not be read: {}".format(exc))


def _feed_local_path(cache: str, name: str) -> str:
    path = os.path.join(os.path.abspath(cache), name)
    problem = path_problem(path)
    if problem:
        raise IocError("indicator cache path refused: " + problem)
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            raise IocError("indicator cache entry is not a regular file")
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise IocError("indicator cache entry cannot be inspected: {}".format(exc))
    return path


def _write_manifest(cache: str, entries: Dict[str, Dict[str, object]]) -> None:
    final = _feed_local_path(cache, MANIFEST)
    fd, tmp = tempfile.mkstemp(dir=cache, prefix=".manifest.")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump({"tool": "zero-breach-toolkit", "version": __version__,
                   "sources": entries}, fh, indent=2, ensure_ascii=False)
    os.replace(tmp, final)


def update(cache: Optional[str] = None, sources: Optional[List[Dict[str, str]]] = None,
           fetch: Callable[[str], bytes] = _fetch,
           emit: Callable[[str], None] = lambda s: None,
           accept_shrink: Optional[List[str]] = None,
           latest: bool = False) -> Dict[str, object]:
    """Download every source; keep the previous copy of any that fails.
    Returns a summary: per source ok / unchanged / failed, with counts.

    By default a source is fetched at this release's pinned commit and must
    match the SHA-256 recorded for it; `latest` follows the upstream branch."""
    cache = cache or default_cache_dir()
    problem = path_problem(os.path.abspath(cache))
    if problem:
        raise IocError("indicator cache {}: {}".format(cache, problem))
    os.makedirs(cache, exist_ok=True)
    manifest = read_manifest(cache)
    results = []
    for src in (sources if sources is not None else SOURCES):
        name = src["id"] + _EXT[src["format"]]
        pinned = None if latest else _pinned_url(src)
        url = pinned or src["url"]
        expected = FEED_FILE_SHA256.get(src["id"]) if pinned else None
        revision = FEED_PINS[src["repo"]] if pinned else ("branch head" if latest else "unpinned")
        entry = {"id": src["id"], "name": src["name"], "url": url, "revision": revision}
        try:
            final = _feed_local_path(cache, name)
            data = fetch(url)
            if _looks_like_html(data):
                raise IocError("got a web page, not an indicator file")
            digest = _feed_sha256(data)
            if expected and digest != expected:
                raise IocError("the file at the pinned revision does not match the SHA-256 recorded "
                               "in this release; the previous copy was kept")
            old = manifest.get(src["id"])
            checked = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).replace(microsecond=0).isoformat() + "Z"
            intact = False
            if isinstance(old, dict) and old.get("file") == name and old.get("sha256") == digest:
                try:
                    with open(final, "rb") as fh:
                        intact = _feed_sha256(fh.read(MAX_DOWNLOAD + 1)) == digest
                except OSError:
                    pass
            if intact:
                old["checked_utc"] = checked
                old["revision"] = revision
                old["url"] = url
                entry.update(status="unchanged", indicators=old.get("indicators"))
                results.append(entry)
                emit("[=] {}: {} indicators, unchanged (sha256 {})".format(src["name"], old.get("indicators"), digest[:16]))
                continue
            fd, tmp = tempfile.mkstemp(dir=cache, prefix=".dl.", suffix=_EXT[src["format"]])
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            try:
                parsed = _load_source_file(src, tmp)    # parse BEFORE replacing
                # A source that suddenly loses most of its indicators (a broken or
                # tampered upstream file) must not silently make scans look clean:
                # keep the previous copy and report why. Measured against the
                # highest count this cache has held, so repeated smaller drops
                # cannot empty a source either. A file matching the hash this
                # release recorded was reviewed, so it resets the measure.
                counts = [old.get(k) for k in ("indicators", "peak_indicators")] if isinstance(old, dict) else []
                peak = max([c for c in counts if type(c) is int], default=0)
                reviewed = bool(expected)
                if not reviewed and peak > 0 and (
                        len(parsed) == 0 or (peak >= 20 and len(parsed) < peak // 2)):
                    if src["id"] not in (accept_shrink or ()):
                        raise IocError("indicator count fell from {} to {} (measured against the most this cache "
                                       "has held); the previous copy was kept. Check the source; if the change is "
                                       "genuine, accept it with --update --accept-shrink {}".format(
                                           peak, len(parsed), src["id"]))
                    emit("[!] {}: indicator count fell from {} to {}; accepted as requested".format(
                        src["name"], peak, len(parsed)))
                    reviewed = True
                peak = len(parsed) if reviewed else max(peak, len(parsed))
            except Exception:
                os.unlink(tmp)
                raise
            os.replace(tmp, final)
            manifest[src["id"]] = {
                "file": name, "url": url, "revision": revision, "format": src["format"],
                "name": src["name"], "cite": src["cite"], "category": src["category"],
                "family": src.get("family", ""), "sha256": digest, "bytes": len(data),
                "fetched_utc": datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None).replace(microsecond=0).isoformat() + "Z",
                "checked_utc": checked,
                "indicators": len(parsed), "peak_indicators": peak}
            # Record each replaced file at once: an interrupted update then
            # leaves at most the source in progress out of step, and the next
            # --update re-downloads it.
            _write_manifest(cache, manifest)
            entry.update(status="updated", indicators=len(parsed))
            emit("[+] {}: {} indicators (sha256 {})".format(src["name"], len(parsed), digest[:16]))
        except Exception as exc:          # one bad source must not stop the rest
            if _certificate_problem(exc):
                # Every source would fail the same way: stop with what to do.
                _write_manifest(cache, manifest)
                raise IocError(_certificate_help())
            entry.update(status="failed", error=str(exc)[:300],
                         kept_previous=src["id"] in manifest)
            emit("[!] {} failed: {}".format(src["name"], str(exc)[:160]))
        results.append(entry)
    _write_manifest(cache, manifest)
    failed = [r for r in results if r["status"] == "failed"]
    return {"cache": cache, "sources": results, "failed": len(failed),
            "ok": len(results) - len(failed)}


# --- loading the cache for a scan ----------------------------------------------

def cached_sets(cache: Optional[str] = None,
                latest: bool = False) -> Tuple[List[IocSet], Dict[str, object]]:
    """IocSets from every verified cached source, plus a status block for the
    report. A file whose SHA-256 no longer matches the manifest is REFUSED (it
    was edited or corrupted after download) and reported, never scanned.

    A file that is not the copy pinned for this release is refused too, unless
    the scan itself was started with `latest` (--latest). The manifest cannot
    grant that: whoever could edit the file could also edit the manifest."""
    cache = cache or default_cache_dir()
    sets: List[IocSet] = []
    status = {"cache": cache, "downloaded": False, "loaded": [],
              "refused": [], "missing": []}
    by_id = {s["id"]: s for s in SOURCES}
    try:
        manifest = read_manifest(cache)
    except IocError as exc:
        status["refused"].append({"id": "manifest", "reason": str(exc)})
        status["missing"] = sorted(by_id)
        return sets, status
    status["downloaded"] = bool(manifest)
    status["missing"] = sorted(set(by_id) - set(manifest))
    for sid, meta in sorted(manifest.items()):
        src = by_id.get(sid)
        if src is None:
            status["refused"].append({"id": sid, "reason": "not a known source"})
            continue
        # The source catalogue, never the manifest, chooses the file to open.
        name = sid + _EXT[src["format"]]
        if not isinstance(meta, dict) or meta.get("file") != name:
            status["refused"].append({"id": sid, "reason": "invalid manifest entry or filename"})
            continue
        try:
            path = _feed_local_path(cache, name)
            with open(path, "rb") as fh:
                data = fh.read(MAX_DOWNLOAD + 1)
        except IocError as exc:
            status["refused"].append({"id": sid, "reason": str(exc)})
            continue
        except OSError:
            status["missing"].append(sid)
            continue
        if _feed_sha256(data) != meta.get("sha256"):
            status["refused"].append({"id": sid, "reason": "file changed since download"})
            continue
        # Judged by content against the hash the release itself carries, which
        # the cache cannot rewrite - never by the manifest's revision field.
        expected = FEED_FILE_SHA256.get(sid)
        pinned_here = bool(expected) and _feed_sha256(data) == expected
        if expected and not pinned_here and not latest:
            status["refused"].append({"id": sid, "reason": "not the copy pinned for this release; "
                                                           "update the indicator lists, or scan "
                                                           "with --latest to use newer lists"})
            continue
        try:
            loaded = _load_source_file(src, path)
            refreshed = meta.get("checked_utc") or meta.get("fetched_utc")
            try:
                when = datetime.datetime.strptime(refreshed, "%Y-%m-%dT%H:%M:%SZ")
                if when > datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None):
                    raise ValueError("future refresh time")
                loaded.verified_at = when
            except (TypeError, ValueError):
                loaded.verified_at = None
            sets.append(loaded)
            status["loaded"].append({"id": sid, "fetched_utc": meta.get("fetched_utc"),
                                     "revision": meta.get("revision") or "unrecorded",
                                     "pinned_for_this_release": pinned_here,
                                     "checked_utc": meta.get("checked_utc"),
                                     "age_days": loaded.age_days(),
                                     "freshness_unknown": loaded.has_unknown_age(),
                                     "stale": loaded.is_stale(),
                                     "indicators": len(loaded)})
        except Exception as exc:
            status["refused"].append({"id": sid, "reason": str(exc)[:200]})
    return sets, status


def update_command(cache: Optional[str], json_path: Optional[str],
                   accept_shrink: Optional[List[str]] = None, latest: bool = False) -> int:
    """The `--update` command for both entry points (source CLI and single
    file). Prints a short summary; exit 0 only if every source succeeded."""
    from .report import write_json, _report_console
    try:
        if json_path and path_problem(os.path.abspath(json_path)):
            raise IocError("--json must be a path on a local disk")
        unknown = sorted(set(accept_shrink or ()) - {src["id"] for src in SOURCES})
        if unknown:
            raise IocError("--accept-shrink: unknown source id {}; the ids are listed in "
                           "manifest.json in the indicator cache".format(", ".join(unknown)))
        extra = {"accept_shrink": accept_shrink} if accept_shrink else {}
        if latest:
            extra["latest"] = True
        summary = update(cache, emit=lambda s: _report_console(s, sys.stderr), **extra)
    except IocError as exc:
        _report_console("error: {}".format(exc), sys.stderr)
        return 1
    except OSError as exc:
        # Disk, not network: the cache folder could not be created or written.
        _report_console("error: the indicator cache could not be written ({}). Nothing was "
                        "changed; choose a writable folder with --indicator-cache.".format(
                            exc.strerror or type(exc).__name__), sys.stderr)
        return 1
    total = sum(r.get("indicators") or 0 for r in summary["sources"] if r["status"] != "failed")
    _report_console("Indicator sets in {}: {} up to date, {} failed; {:,} indicators. Full SHA-256 "
                    "and download times are in manifest.json there.".format(
                        summary["cache"], summary["ok"], summary["failed"], total), sys.stdout)
    for r in summary["sources"]:
        if r["status"] == "failed":
            _report_console("  FAILED {}: {}{}".format(r["name"], r.get("error", ""),
                  " (previous copy kept)" if r.get("kept_previous") else ""), sys.stdout)
    if json_path:
        try:
            write_json(summary, json_path)
        except (OSError, ValueError, TypeError) as exc:
            _report_console("could not write {}: {}".format(json_path, exc), sys.stderr)
            return 1
    return 0 if summary["failed"] == 0 else 1
