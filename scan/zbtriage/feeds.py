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

Two additions (v3):
  - the files hosted in mvt-project/mvt-indicators (MIT-licensed) are also built
    in (mvtdata.py), as the exact bytes this release pins: a scan with no
    downloaded copy of one of them uses the built-in copy, checked against the
    same SHA-256 first;
  - KNOWN_GOOD_SOURCES are MISP warninglists (empty-file
    hashes, reserved addresses, revocation hosts ...), downloaded with the rest
    and pinned the same way. An upstream indicator that EXACTLY equals one of
    their entries (or, for a few fixed address lists, falls inside one) is set
    aside and counted, never matched. Exact, so that listing "duckdns.org" can
    only drop a bad indicator "duckdns.org", never a real "evil.duckdns.org".
"""

from __future__ import annotations

import base64
import csv
import dataclasses
import datetime
import hashlib
import io
import ipaddress
import json
import os
import re
import ssl
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zlib
from typing import Callable, Dict, List, Optional, Tuple

from . import __version__
from .mvtdata import MVT_BUILTIN, MVT_BUILTIN_DATE
from .iocs import (SHARED_SERVICE_HOSTS, SHARED_SERVICE_REASON, TYPE_DOMAIN, TYPE_IP,
                   TYPE_SHA1, TYPE_SHA256, Indicator, IocError, IocSet, infer_type, load_any,
                   shared_service_domain)
from .i18n import T
from .localpaths import path_problem, tls_context, is_packaged
from .stix import TIER_INFRA, TIER_INFRA_IP, TIER_SAMPLE, _normalise

RAW = "https://raw.githubusercontent.com/"
ALLOWED_OWNERS = ("mvt-project/mvt-indicators/", "AmnestyTech/investigations/",
                  "AssoEchap/stalkerware-indicators/", "citizenlab/malware-indicators/",
                  "MISP/misp-warninglists/")
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
    "MISP/misp-warninglists": "40e2b570fda2e5443a2d6fa1d1db16c37ab0a956",
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
    "kg-apple-domains": "76a5bccc5d847a8e59e7cf39459e07d3b5b2fdbcc97134063e0ddc71a3bed222",
    "kg-captive-portals": "2caec46db1b853d2b087fb78c2e782029c3f514d5a974510edbbfed6d831e7ab",
    "kg-common-ioc-false-positive": "e6cd190993ebdea443cdac71adfd99a88bdfac53c41af6e228c0c601e3155e73",
    "kg-crl-hostname": "f70c6f75ea3d6e128a3d623d796b33c3ba566b9d36376f86007b8a7c0734341d",
    "kg-crl-ip": "6c4eae4599b23c2e52a6fb5964a8056d05c4b95f38bbae59c1961728075fdaf7",
    "kg-dynamic-dns": "505a54f47e207fc435f17a545d344cd4dfaa17c30936ac214f483bd721303e4b",
    "kg-empty-hashes": "449a1c0a24d447ecc3a4a6c4cb53a004e4d3cc39efa39ab583b3c6850ec5e6c6",
    "kg-google": "48d37729d8adab458848eb59bcea52ed78249f5e90537403a0b8e94c7f2c5742",
    "kg-ipv6-linklocal": "3d77b4c07ebb933724672d8f70a6534c14b7338af35256fca55e3ca762cc082f",
    "kg-microsoft": "f52c1cbe26258265f7f96dfb16a4126d400df769a3b276bb589c7a1e137c6679",
    "kg-microsoft-win10-connection-endpoints": "e347f5e6b4c75bbc8ced213e00ee07596e4726c9fe1da648bf29227e0f2d9c82",
    "kg-microsoft-win11-connection-endpoints": "1d0941f59df2ea68b02ac323828b1d0862c5d5bea545c853df40ce0331b97e7b",
    "kg-multicast": "4828edf98cd5fb053394988d4f824c6369de980aca17a81f0cbd07bd4930f53d",
    "kg-rfc1918": "ef1374626d6d98ddac70e6bcdc533e4f76eee744c46ba99e3e6eddbc14e169a3",
    "kg-rfc3849": "54a82c687e3efa5ab64cd33dd719bcd8f01c0f41f6bce43a1f82dbf10612b7d0",
    "kg-rfc5735": "a1708cad2ebb809d6c10932a87042b78f5679662f73e7a3fa6c73bcbf12a3b2c",
    "kg-rfc6598": "5f384ea12b562bd5ed683cec78ca76e41b22e4174581026eb8fb55007248e820",
    "kg-rfc6761": "d1a1d87ab67a2e08bd040bfa17270338effde7477e9e1b5cfb3ad3fa880f8b56",
    "kg-security-provider-blogpost": "0874106b22e325b01041c782be94cc51ff6dab96d4b8c722938cb484c6c3ad4f",
    "kg-sinkholes": "de791ba3fcbf7fe087ba6c55103212d781a538e574282716df60d8609d1b3c7f",
    "kg-ti-falsepositives": "0ce200662c09a1770fe4e371f29d4a46d8c2e4b0ef4da1fc7faebeae3dd12b78",
    "kg-umbrella-blockpage-hostname": "ce5f07060faaf8eb75b9ec56c2fa21aa6e1c84aba138465fa23d56aaaec58cf0",
    "kg-umbrella-blockpage-v4": "a9f6fe5f3bfe74d2e8dd90ca3fc03ebca57140864967507bb3615a98a215640d",
    "kg-umbrella-blockpage-v6": "b5e2c91d41aa88aa3c8d23001bdcf31b5f9575e5a94c35edc40d9b0226d338e1",
    "kg-url-shortener": "b3507004dfaf9bb15f8947990ba1a51526b685ad9e97dda94f9a210968bc640d",
    "kg-whats-my-ip": "403e9f70197c7ce360a0919162068c57594ccfbce50428682641a1884463b7c6",
    "kg-wikimedia": "03a1015c26965f170258211cfbdfae1fb0b3c4646367b09230a936ecdc3cd901",
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
    _src("echap-stalkerware", "Stalkerware (176 apps)", "AssoEchap/stalkerware-indicators/master/",
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
    # Citizen Lab's indicator repository (MISP CSV exports): Israeli vendors, and one
    # unattributed campaign (the last entry).
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
    # Not NSO Group, despite the id (kept so that existing downloads still
    # verify): the publisher describes this folder as an intrusion campaign
    # against Chinese-language news sites, with no spyware family named.
    _src("citizenlab-nso-insider-2017",
         "Intrusion campaign against Chinese-language news sites (Insider Information, 2017)",
         "citizenlab/malware-indicators/master/", "201707_InsiderInfo/indicators.csv", "misp-csv",
         "The Citizen Lab, 'Insider Information: An intrusion campaign targeting Chinese "
         "language news sites' (2017-07)"),
]


# Known-good lists (MISP warninglists; the repository states CC0 1.0 in its README but has no licence file, so
# they are downloaded at --update like the other unlicensed sources, never shipped). Only lists of specific,
# factual values that are never attacker-controlled were chosen; ranking lists ("top sites") and cloud, VPN, Tor
# and scanner address ranges were left out on purpose - real spyware servers live in cloud ranges.
def _kg(name, title, cidr=False):
    src = _src("kg-" + name, title, "MISP/misp-warninglists/main/", "lists/{}/list.json".format(name),
               "misp-warninglist", "MISP warninglists", category="known-good")
    src["cidr_ok"] = cidr        # whether address RANGES in this list may set an indicator aside
    return src


KNOWN_GOOD_SOURCES: List[Dict[str, str]] = [
    _kg("empty-hashes", "Fingerprints of empty files"),
    _kg("common-ioc-false-positive", "Fingerprints often listed by mistake"),
    _kg("ti-falsepositives", "Known threat-intelligence false positives"),
    # Not the public-DNS lists: ~97,000 addresses scraped from the internet (and whole ranges for v4/v6). A
    # spyware server that also answers DNS would be set aside by them.
    _kg("crl-hostname", "Certificate revocation hosts"),
    _kg("crl-ip", "Certificate revocation addresses", cidr=True),
    _kg("captive-portals", "Connectivity-check hosts"),
    _kg("whats-my-ip", "What-is-my-IP services"),
    _kg("sinkholes", "Researcher sinkhole addresses", cidr=True),
    _kg("umbrella-blockpage-v4", "Cisco Umbrella block page (IPv4)", cidr=True),
    _kg("umbrella-blockpage-v6", "Cisco Umbrella block page (IPv6)", cidr=True),
    _kg("umbrella-blockpage-hostname", "Cisco Umbrella block page (names)"),
    _kg("security-provider-blogpost", "Security researchers' blogs"),
    _kg("url-shortener", "Link shorteners (the service itself)"),
    _kg("dynamic-dns", "Dynamic-DNS providers (the provider itself)"),
    _kg("rfc1918", "Private network addresses", cidr=True),
    _kg("rfc5735", "Special-use IPv4 addresses", cidr=True),
    _kg("rfc6598", "Carrier-grade NAT addresses", cidr=True),
    _kg("rfc3849", "IPv6 documentation addresses", cidr=True),
    _kg("rfc6761", "Special-use domain names"),
    _kg("ipv6-linklocal", "IPv6 link-local addresses", cidr=True),
    _kg("multicast", "Multicast addresses", cidr=True),
    _kg("wikimedia", "Wikimedia addresses", cidr=True),
    _kg("google", "Google's own hosts"),
    _kg("microsoft", "Microsoft's own hosts"),
    _kg("apple-domains", "Apple's own domains"),
    _kg("microsoft-win10-connection-endpoints", "Windows 10 system endpoints"),
    _kg("microsoft-win11-connection-endpoints", "Windows 11 system endpoints"),
]

# Everything --update downloads and the cache verifies: indicator sources, then known-good lists. Built at
# call time, so a caller that replaces SOURCES (tests, a custom build) is followed.
def all_sources() -> List[Dict[str, str]]:
    return list(SOURCES) + list(KNOWN_GOOD_SOURCES)
KNOWN_GOOD_REASON = "on a known-good list (MISP warninglists)"

MANIFEST = "manifest.json"
_EXT = {"stix2": ".stix2", "csv-domain-ip": ".csv", "domains-txt": ".txt",
        "misp-csv": ".misp.csv", "misp-warninglist": ".warninglist.json"}


class KnownGood:
    """Values that can never be a spyware indicator. covers(indicator) -> the list's title, or ""."""

    def __init__(self):
        self.values: Dict[str, str] = {}            # exact value -> list title
        self.networks: List[Tuple[object, str]] = []  # (ip_network, list title), fixed-range lists only
        self.lists: List[Dict[str, object]] = []

    def __len__(self):
        return len(self.values) + len(self.networks)

    def merge(self, other: "KnownGood") -> None:
        for value, title in other.values.items():
            self.values.setdefault(value, title)
        self.networks.extend(other.networks)
        self.lists.extend(other.lists)

    def covers(self, ind: Indicator) -> str:
        value = (ind.value or "").lower().rstrip(".")
        if value in self.values:
            return self.values[value]
        if ind.type == TYPE_IP and self.networks:
            try:
                addr = ipaddress.ip_address(value)
            except ValueError:
                return ""
            for net, title in self.networks:
                if addr.version == net.version and addr in net:
                    return title
        return ""


def load_warninglist(path: str, title: str, cidr_ok: bool) -> KnownGood:
    """A MISP warninglist file -> KnownGood. 'string' and 'hostname' entries are kept as exact values (a
    leading '.' wildcard is dropped, so only the bare name is covered); 'cidr' entries become exact addresses,
    and wider ranges only for lists marked cidr_ok; 'substring' and 'regex' lists are not used."""
    with open(path, "rb") as fh:
        doc = json.loads(fh.read(MAX_DOWNLOAD + 1).decode("utf-8"))
    if not isinstance(doc, dict) or not isinstance(doc.get("list"), list):
        raise IocError("{}: not a warninglist".format(path))
    kind = str(doc.get("type") or "").lower()
    kg = KnownGood()
    skipped = 0
    for raw in doc["list"]:
        if not isinstance(raw, str):
            skipped += 1
            continue
        text = raw.strip().lower().lstrip(".").rstrip(".")
        if not text or len(text) > 256:
            skipped += 1
            continue
        if kind in ("string", "hostname"):
            kg.values.setdefault(text, title)
        elif kind == "cidr":
            try:
                net = ipaddress.ip_network(text, strict=False)
            except ValueError:
                skipped += 1
                continue
            if net.num_addresses == 1:
                kg.values.setdefault(str(net.network_address), title)
            elif cidr_ok:
                kg.networks.append((net, title))
            else:
                skipped += 1
        else:
            skipped += 1
    if not len(kg):
        raise IocError("{}: no usable entry in this warninglist".format(path))
    kg.lists.append({"title": title, "entries": len(kg), "skipped": skipped, "type": kind})
    return kg


def apply_known_good(sets: List[IocSet], known: KnownGood) -> int:
    """Set aside every indicator a known-good list covers, in place of each set; returns how many."""
    total = 0
    if not len(known):
        return 0
    for index, s in enumerate(sets):
        keep, dropped = [], 0
        for ind in s.indicators:
            if known.covers(ind):
                dropped += 1
            else:
                keep.append(ind)
        if not dropped:
            continue
        total += dropped
        rebuilt = IocSet(keep, s.source_path, s.source_mtime)
        rebuilt.asof = s.asof
        rebuilt.sets = [dict(meta) for meta in getattr(s, "sets", [])]
        if rebuilt.sets:
            na = dict(rebuilt.sets[0].get("not_applicable_to_this_scan") or {})
            na[KNOWN_GOOD_REASON] = na.get(KNOWN_GOOD_REASON, 0) + dropped
            rebuilt.sets[0]["not_applicable_to_this_scan"] = na
        if getattr(s, "verified_at", None) is not None:
            rebuilt.verified_at = s.verified_at
        sets[index] = rebuilt
    return total

# MISP attribute types -> our kinds. URLs contribute their host name. MD5 sample
# hashes are counted as not applicable: the file checks compute SHA-256 and SHA-1.
_MISP_KINDS = {"domain": TYPE_DOMAIN, "hostname": TYPE_DOMAIN, "ip-dst": TYPE_IP,
               "ip-src": TYPE_IP, "sha256": TYPE_SHA256, "sha1": TYPE_SHA1, "url": "url"}

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
                TIER_SAMPLE if kind in (TYPE_SHA256, TYPE_SHA1) else TIER_INFRA)
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


def _load_source_file(src: Dict[str, str], path: str):
    """An IocSet, or a KnownGood for a known-good list (both have len())."""
    if src["format"] == "misp-warninglist":
        return load_warninglist(path, src["name"], bool(src.get("cidr_ok")))
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
    opener = urllib.request.build_opener(_AllowListRedirect(),
                                      urllib.request.HTTPSHandler(context=tls_context()))
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
    if platform == "darwin" and is_packaged():
        # The app has no Python folder and no Install Certificates step; it reads
        # the Mac's own certificate list.
        return (start + "Check that the Mac's date and time are right and that the network or a security "
                "program is not replacing website certificates, then try again.")
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
    for src in (sources if sources is not None else all_sources()):
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
    grant that: whoever could edit the file could also edit the manifest.

    Then: an mvt-indicators source with no usable downloaded copy (missing or
    refused) is loaded from the copy built into this release, and every
    indicator a downloaded known-good list covers is set aside."""
    cache = cache or default_cache_dir()
    sets: List[IocSet] = []
    known = KnownGood()
    status = {"cache": cache, "downloaded": False, "loaded": [],
              "refused": [], "missing": [], "known_good": {"lists": [], "missing": [], "set_aside": 0}}
    by_id = {s["id"]: s for s in all_sources()}
    indicator_ids = {s["id"] for s in SOURCES}
    try:
        manifest = read_manifest(cache)
    except IocError as exc:
        status["refused"].append({"id": "manifest", "reason": str(exc)})
        manifest = None
    if manifest is None:
        status["missing"] = sorted(indicator_ids)
        status["known_good"]["missing"] = sorted(set(by_id) - indicator_ids)
        manifest = {}
    else:
        status["downloaded"] = bool(manifest)
        status["missing"] = sorted(indicator_ids - set(manifest))
        status["known_good"]["missing"] = sorted(set(by_id) - indicator_ids - set(manifest))
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
            if isinstance(loaded, KnownGood):
                known.merge(loaded)
                status["known_good"]["lists"].append({"id": sid, "entries": len(loaded),
                                                      "pinned_for_this_release": pinned_here})
                continue
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
    # A known-good list (false-alarm filter) that was refused is reported, but it is not missing indicator
    # coverage: tagged so the "checks were missing" verdict does not count it.
    for entry in status["refused"]:
        if entry.get("id") in by_id and entry.get("id") not in indicator_ids:
            entry["known_good"] = True
    _built_in_sets(sets, status, by_id)
    status["known_good"]["set_aside"] = apply_known_good(sets, known)
    return sets, status


def builtin_bytes(sid: str) -> Optional[bytes]:
    """The built-in copy of an mvt-indicators file, only if it is exactly the file this release pins."""
    entry = MVT_BUILTIN.get(sid)
    if not entry:
        return None
    digest, packed = entry[0], "".join(entry[1:])
    try:
        data = zlib.decompress(base64.b64decode(packed))
    except (ValueError, zlib.error):
        return None
    if _feed_sha256(data) != digest or FEED_FILE_SHA256.get(sid) != digest:
        return None
    return data


def builtin_sets() -> Tuple[List[IocSet], Dict[str, object]]:
    """Only the indicator lists built into this release (the pinned mvt-indicators copies) - for --no-feeds, which
    ignores downloaded sets but must still scan with everything the release itself carries."""
    sets: List[IocSet] = []
    status = {"loaded": [], "refused": [], "missing": []}
    _built_in_sets(sets, status, {s["id"]: s for s in all_sources()})
    return sets, status


def _built_in_sets(sets: List[IocSet], status: Dict[str, object], by_id) -> None:
    loaded_ids = {e["id"] for e in status["loaded"]}
    for sid in sorted(MVT_BUILTIN):
        if sid in loaded_ids or sid not in by_id:
            continue
        data = builtin_bytes(sid)
        if data is None:
            status["refused"].append({"id": sid, "reason": "built-in copy does not match this release's pin"})
            continue
        src = by_id[sid]
        fd, tmp = tempfile.mkstemp(prefix=".zb-builtin.", suffix=_EXT[src["format"]])
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            loaded = _load_source_file(src, tmp)
        except Exception as exc:  # noqa: BLE001 - a broken copy must not stop the scan
            status["refused"].append({"id": sid, "reason": "built-in copy: " + str(exc)[:160]})
            continue
        finally:
            try:
                os.unlink(tmp)
            except OSError:
                pass
        loaded.verified_at = datetime.datetime.strptime(MVT_BUILTIN_DATE, "%Y-%m-%d")
        sets.append(loaded)
        if sid in status["missing"]:
            status["missing"].remove(sid)
        status["loaded"].append({"id": sid, "fetched_utc": None, "revision": "built into this release",
                                 "built_in": True, "pinned_for_this_release": True, "checked_utc": None,
                                 "age_days": loaded.age_days(), "freshness_unknown": loaded.has_unknown_age(),
                                 "stale": loaded.is_stale(), "indicators": len(loaded)})


RELEASE_API ="https://api.github.com/repos/interplains/Zero-Breach-Toolkit/releases/latest"
RELEASE_PAGE = "https://github.com/interplains/Zero-Breach-Toolkit/releases/tag/"
# The newest-version line of the last update in this process (the window shows it).
LAST_VERSION_NOTICE = ""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.URLError("redirect refused")


def _release_tag() -> str:
    """The newest release's tag from GitHub: one plain request, no redirects."""
    opener = urllib.request.build_opener(_NoRedirect(),
                                         urllib.request.HTTPSHandler(context=tls_context()))
    req = urllib.request.Request(RELEASE_API, headers={"User-Agent": "Mozilla/5.0"})
    with opener.open(req, timeout=8) as resp:
        data = resp.read(200001)
    if len(data) > 200000:
        return ""
    tag = json.loads(data.decode("utf-8")).get("tag_name", "")
    return tag if isinstance(tag, str) else ""


def _version_tuple(text):
    m = re.fullmatch(r"v?(\d{1,4})\.(\d{1,4})\.(\d{1,4})", text or "")
    return tuple(int(g) for g in m.groups()) if m else None


def version_notice(current: str = __version__, fetch=None) -> str:
    """One line if a newer release exists, else "". Every failure (offline, rate
    limit, bad JSON, an unexpected tag) gives "": it must never affect an update."""
    try:
        tag = (fetch or _release_tag)()
        newer, mine = _version_tuple(tag), _version_tuple(current)
        if newer is None or mine is None or newer <= mine:
            return ""
        return T("Version {version} is available: {url}",
                 version=".".join(str(n) for n in newer),
                 url=RELEASE_PAGE + "v" + ".".join(str(n) for n in newer))
    except Exception:
        return ""


def update_command(cache: Optional[str], json_path: Optional[str],
                   accept_shrink: Optional[List[str]] = None, latest: bool = False,
                   version_check: bool = True) -> int:
    """The `--update` command for both entry points (source CLI and single
    file). Prints a short summary; exit 0 only if every source succeeded."""
    from .report import write_json, _report_console
    try:
        if json_path and path_problem(os.path.abspath(json_path)):
            raise IocError("--json must be a path on a local disk")
        unknown = sorted(set(accept_shrink or ()) - {src["id"] for src in all_sources()} - {"kev"})
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
    # The actively-exploited-software list: prevention advice, separate from the
    # indicators. A failure here is reported but never fails the indicator update.
    from .kevdata import KevError, kev_update
    try:
        kev = kev_update(summary["cache"], emit=lambda s: _report_console(s, sys.stderr),
                         accept_shrink="kev" in (accept_shrink or ()))
        _report_console("Actively exploited software list ({}): {:,} entries for the checked programs{}.".format(
            kev["catalogVersion"], kev["entries"],
            "; {} record(s) unavailable, advice only for those".format(kev["records_missing"])
            if kev["records_missing"] else ""), sys.stdout)
    except (KevError, OSError, ValueError) as exc:
        _report_console("  Actively exploited software list not updated: {} (the indicator lists above "
                        "are unaffected)".format(exc), sys.stdout)
    # The device manufacturer list (IEEE public listing), used only by the home network check to name devices.
    from .kevdata import oui_update
    try:
        count = oui_update(summary["cache"])
        _report_console("Device manufacturer list (IEEE): {:,} makers.".format(count), sys.stdout)
    except (KevError, OSError, ValueError, urllib.error.URLError) as exc:
        _report_console("  Device manufacturer list not updated: {} (everything else is unaffected)".format(
            str(exc)[:200]), sys.stdout)
    global LAST_VERSION_NOTICE
    LAST_VERSION_NOTICE = version_notice() if version_check else ""
    if LAST_VERSION_NOTICE:
        _report_console(LAST_VERSION_NOTICE, sys.stdout)
    if json_path:
        try:
            write_json(summary, json_path)
        except (OSError, ValueError, TypeError) as exc:
            _report_console("could not write {}: {}".format(json_path, exc), sys.stderr)
            return 1
    return 0 if summary["failed"] == 0 else 1
