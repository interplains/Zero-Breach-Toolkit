"""trust-settings: root certificates, proxy, DNS servers and gateway, as leads; local reads only."""
import json
from unittest.mock import patch

import pytest

from zbtriage.context import ScanContext
from zbtriage.iocs import IocSet
from zbtriage.modules import trust
from zbtriage.result import ModuleResult
from zbtriage.trustdata import TRUST_SHA1

KNOWN = sorted(TRUST_SHA1)[0]


def ctx():
    return ScanContext(IocSet([], "fixture", None), emit=lambda _m: None)


@pytest.mark.parametrize("subject,kind", [
    ("CN=DO_NOT_TRUST_FiddlerRoot, O=DO_NOT_TRUST, OU=Created by http://www.fiddler2.com", "interception-tool"),
    ("CN=mitmproxy, O=mitmproxy", "interception-tool"),
    ("CN=Superfish, Inc.", "known-bad"),
    ("CN=Kaspersky Anti-Virus Personal Root Certificate, O=AO Kaspersky Lab", "security-software"),
    ("CN=vpnNode CA, O=vpnNode, C=CH", "vpn"),
    ("CN=Blizzard Battle.net Local Cert, OU=Battle.net", "game"),
    ("CN=Patriot Bank Root", "unknown"),
    ("CN=Some Company Root CA", "unknown"),
])
def test_kinds(subject, kind):
    assert trust.trust_kind(subject)[0] == kind


def test_machine_named_root():
    assert trust.trust_kind("CN=DESKTOP-ABC123", "DESKTOP-ABC123")[0] == "this-computer"


def test_known_roots_are_silent_and_unknown_ones_are_leads():
    r = ModuleResult(trust.NAME)
    roots = [{"sha1": KNOWN, "subject": "CN=Public Root", "where": "LocalMachine Root"},
             {"sha1": "AB" * 20, "subject": "CN=mitmproxy", "where": "LocalMachine Root"},
             {"sha1": "AB" * 20, "subject": "CN=mitmproxy", "where": "CurrentUser Root"}]
    total, unknown = trust.trust_root_leads(r, roots, *trust.trust_known_roots())
    assert (total, unknown) == (2, 1)
    assert len(r.leads) == 1 and "mitmproxy" in r.leads[0].what


def test_windows_roots_user_view_duplicates_dropped():
    rows = [{"Thumbprint": KNOWN, "Subject": "CN=Public", "Store": "LocalMachine\\Root"},
            {"Thumbprint": KNOWN, "Subject": "CN=Public", "Store": "CurrentUser\\Root"},
            {"Thumbprint": "CD" * 20, "Subject": "CN=User Added", "Store": "CurrentUser\\Root"}]
    with patch("zbtriage.modules.host._ps_json", return_value=(rows, "")):
        roots = trust._tr_windows_roots()
    assert [r["subject"] for r in roots] == ["CN=Public", "CN=User Added"]


def test_mac_trust_settings_parse():
    text = "Number of trusted certs = 2\nCert 0: Charles Proxy CA (8 Nov 2026, laptop)\n   Number of trust settings : 0\nCert 1: Corp Root\n"
    assert trust.trust_parse_mac_trust_settings(text) == ["Charles Proxy CA (8 Nov 2026, laptop)", "Corp Root"]


def test_linux_anchor_folder_lists_added_roots(tmp_path):
    folder = tmp_path / "anchors"
    folder.mkdir()
    (folder / "corp.crt").write_text("-----BEGIN CERTIFICATE-----\n")
    with patch.object(trust, "_TR_LINUX_ANCHORS", (str(folder),)), patch.object(trust.sys, "platform", "linux"):
        r = ModuleResult(trust.NAME)
        trust._check_roots(r, ctx())
    assert len(r.leads) == 1 and "corp.crt" in r.leads[0].what
    assert any(c.ran and c.name == "root-certificates" for c in r.checks)


def test_unreadable_store_is_a_gap():
    with patch("zbtriage.modules.host._ps_json", return_value=([], "Access is denied")), \
            patch.object(trust.sys, "platform", "win32"):
        r = ModuleResult(trust.NAME)
        trust._check_roots(r, ctx())
    assert any(not c.ran and c.name == "root-certificates" for c in r.checks)


@pytest.mark.parametrize("address,kind", [
    ("85.255.112.10", "dnschanger"), ("8.8.8.8", "public"), ("1.1.1.1", "public"),
    ("192.168.1.1", "local"), ("127.0.0.1", "local"), ("80.80.80.80", "other"), ("not-an-ip", "invalid")])
def test_dns_labels(address, kind):
    assert trust.trust_dns_label(address)[0] == kind


def test_dns_leads_only_for_hijack_ranges_and_unknown_manual_servers():
    servers = [("IPv4 {a}", "85.255.112.10", False), ("IPv4 {b}", "80.80.80.80", True),
               ("IPv4 {c}", "80.80.81.81", False), ("IPv4 {d}", "8.8.8.8", True)]
    with patch.object(trust, "_tr_windows_dns", return_value=servers), patch.object(trust.sys, "platform", "win32"):
        r = ModuleResult(trust.NAME)
        trust._check_dns(r, ctx())
    texts = [l.what for l in r.leads]
    assert len(texts) == 2
    assert any("DNSChanger" in t for t in texts) and any("80.80.80.80" in t for t in texts)


def test_scutil_proxy_parse():
    text = "<dictionary> {\n  HTTPEnable : 1\n  HTTPPort : 8888\n  HTTPProxy : 127.0.0.1\n  ProxyAutoConfigEnable : 0\n}"
    assert trust.trust_parse_scutil_proxy(text) == [("HTTP proxy", "127.0.0.1:8888")]


def test_gateway_conflict():
    neighbours = [("192.168.1.1", "aa-bb-cc-dd-ee-ff"), ("192.168.1.66", "aa-bb-cc-dd-ee-ff"),
                  ("192.168.1.20", "11-22-33-44-55-66"), ("224.0.0.22", "aa-bb-cc-dd-ee-ff")]
    mac, others = trust.trust_gateway_conflicts("192.168.1.1", neighbours)
    assert mac == "aa-bb-cc-dd-ee-ff" and others == ["192.168.1.66"]
    assert trust.trust_gateway_conflicts("192.168.1.1", [("192.168.1.1", "aa-bb-cc-dd-ee-ff")])[1] == []


def test_run_isolates_failing_checks():
    def boom(r, c):
        raise RuntimeError("boom")
    with patch.object(trust, "_check_roots", boom), patch.object(trust, "_check_proxy", lambda r, c: r.ran("proxy-settings")), \
            patch.object(trust, "_check_dns", lambda r, c: r.ran("dns-settings")), \
            patch.object(trust, "_check_gateway", lambda r, c: r.ran("gateway")):
        r = trust.run(ctx())
    assert [c.name for c in r.checks if not c.ran] == ["root-certificates"]
    assert {c.name for c in r.checks if c.ran} == {"proxy-settings", "dns-settings", "gateway"}


def test_leads_never_change_the_verdict():
    from zbtriage.report import build_document
    r = ModuleResult(trust.NAME)
    trust.trust_root_leads(r, [{"sha1": "AB" * 20, "subject": "CN=mitmproxy", "where": "x"}], *trust.trust_known_roots())
    r.ran("root-certificates")
    document = build_document(IocSet([], "fixture", None), [r], __import__("datetime").datetime.now())
    assert document["verdict"]["status"] == "NO_KNOWN_INDICATORS"


def test_explained_roots_are_one_calm_item_but_still_named():
    r = ModuleResult(trust.NAME)
    roots = [{"sha1": "A1" * 20, "subject": "CN=Kaspersky Anti-Virus Personal Root Certificate, O=AO Kaspersky Lab"},
             {"sha1": "A2" * 20, "subject": "CN=Blizzard Battle.net Local Cert"},
             {"sha1": "A3" * 20, "subject": "CN=vpnNode CA"},
             {"sha1": "A4" * 20, "subject": "CN=Unexplained Root"},
             {"sha1": "A5" * 20, "subject": "CN=mitmproxy"}]
    trust.trust_root_leads(r, roots, *trust.trust_known_roots())
    whats = [l.what for l in r.leads]
    assert len(whats) == 3                                   # unexplained + mitmproxy + one grouped item
    grouped = [w for w in whats if w.startswith("Extra root certificates added by programs")][0]
    for name in ("Kaspersky Anti-Virus Personal Root Certificate", "Blizzard Battle.net Local Cert", "vpnNode CA"):
        assert name in grouped
    assert any("Unexplained Root" in w for w in whats) and any("mitmproxy" in w for w in whats)
