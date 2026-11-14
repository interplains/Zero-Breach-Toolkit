"""--home-network router lookups: a fake DNS server on this computer plays a clean, hijacking, redirecting
or silent router. Nothing leaves the computer."""
import socket
import struct
import threading

import pytest

from zbtriage import homenet


def _answer(query, answers, rcode=0):
    """Build a response to `query` with A/TXT answers [(type, value)]."""
    qid = struct.unpack_from(">H", query, 0)[0]
    end = 12
    while query[end] != 0:
        end += 1 + query[end]
    question = query[12:end + 5]
    out = struct.pack(">HHHHHH", qid, 0x8180 | rcode, 1, len(answers), 0, 0) + question
    for rtype, value in answers:
        if rtype == 1:
            rdata = socket.inet_aton(value)
        else:
            text = value.encode()
            rdata = bytes([len(text)]) + text
        out += struct.pack(">HHHIH", 0xC00C, rtype, 1, 60, len(rdata)) + rdata
    return out


def _qname(query):
    labels, i = [], 12
    while query[i]:
        labels.append(query[i + 1:i + 1 + query[i]].decode())
        i += 1 + query[i]
    return ".".join(labels)


class FakeRouter:
    def __init__(self, table, silent=False):
        self.table, self.silent, self.asked = table, silent, []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def serve(self):
        self.sock.settimeout(5)
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                return
            name = _qname(data)
            self.asked.append(name)
            if self.silent:
                continue
            rule = self.table(name)
            self.sock.sendto(_answer(data, *rule) if isinstance(rule, tuple) else _answer(data, rule), addr)

    def close(self):
        self.sock.close()


def _clean(name):
    if name == "one.one.one.one":
        return [(1, "1.1.1.1"), (1, "1.0.0.1")]
    if name == "dns.google":
        return [(1, "8.8.8.8"), (1, "8.8.4.4")]
    if name == "whoami.akamai.net":
        return [(1, "203.0.113.53")]
    if name == "o-o.myaddr.l.google.com":
        return [(16, "203.0.113.53"), (16, "edns0-client-subnet 198.51.100.0/24")]
    return ([], 3)


def _run(table, silent=False, monkeypatch=None):
    router = FakeRouter(table, silent)
    if monkeypatch:
        monkeypatch.setattr(homenet, "HN_DNS_TIMEOUT", 0.3)
    try:
        return homenet.hn_router_dns("127.0.0.1", port=router.port, nx_name="zbt-test.example.com"), router.asked
    finally:
        router.close()


def test_clean_router_gives_no_findings_and_names_its_resolver():
    result, asked = _run(_clean)
    assert all(f["ok"] for f in result["fixed"])
    assert result["nx"]["got"] == [] and result["nx"]["rcode"] == 3
    assert [u["address"] for u in result["upstream"]] == ["203.0.113.53"]
    assert homenet.hn_router_dns_findings(result) == []
    assert asked == ["one.one.one.one", "dns.google", "zbt-test.example.com", "whoami.akamai.net",
                     "o-o.myaddr.l.google.com"]


def test_client_subnet_text_is_never_stored():
    result, _ = _run(_clean)
    assert "198.51.100" not in repr(result)


def test_hijacked_router_is_named_with_the_wrong_answer():
    def hijack(name):
        return [(1, "93.188.161.7")] if name in ("one.one.one.one", "dns.google") else _clean(name)
    result, _ = _run(hijack)
    titles = [t for t, _d, _w in homenet.hn_router_dns_findings(result)]
    assert titles == ["Your router gave a wrong answer for one.one.one.one",
                      "Your router gave a wrong answer for dns.google"]


def test_made_up_names_answered_is_explained_as_usually_the_provider():
    def redirect(name):
        return [(1, "198.51.100.80")] if name.endswith("example.com") else _clean(name)
    result, _ = _run(redirect)
    findings = homenet.hn_router_dns_findings(result)
    assert len(findings) == 1
    assert "made-up names" in findings[0][0] and "usually harmless" in findings[0][2]


def test_dnschanger_upstream_is_a_finding():
    def changer(name):
        return [(1, "85.255.112.9")] if name == "whoami.akamai.net" else _clean(name)
    result, _ = _run(changer)
    titles = [t for t, _d, _w in homenet.hn_router_dns_findings(result)]
    assert any("router malware" in t for t in titles)


def test_silent_router_is_a_gap_not_an_all_clear(monkeypatch):
    result, _ = _run(_clean, silent=True, monkeypatch=monkeypatch)
    assert result["fixed"] == [] and homenet.hn_router_dns_findings(result) == []
    assert "did not answer" in result["gaps"][0] and "VPN" in result["gaps"][0]


def test_answer_with_wrong_id_is_ignored():
    query = homenet.hn_dns_query("dns.google", 1, 7)
    reply = bytearray(_answer(query, [(1, "8.8.8.8")]))
    reply[0:2] = b"\x00\x08"
    with pytest.raises(ValueError):
        homenet.hn_parse_dns_answer(bytes(reply), 7)


def test_render_shows_router_lookups():
    result, _ = _run(_clean)
    text = homenet.hn_render({"subnet": "192.168.1.0/24", "devices": [], "findings": [], "gaps": [],
                              "seconds": 1, "router_dns": result})
    assert "ROUTER LOOKUPS" in text and "correctly unknown" in text and "203.0.113.53" in text


def test_consent_names_the_lookups_and_the_opt_out():
    text = homenet.HN_CONSENT
    assert "leaves your network" in text and "--no-router-lookups" in text


def test_opt_out_consent_promises_nothing_leaves(monkeypatch):
    from types import SimpleNamespace
    monkeypatch.setattr(homenet, "hn_target", lambda: ("192.168.1.37", homenet.hn_subnet("192.168.1.37"), "192.168.1.1", ""))
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    lines = []
    code = homenet.homenet_command(SimpleNamespace(no_router_lookups=True, yes_my_network=False), out=lines.append)
    text = "\n".join(lines)
    assert code == 1 and "contacts nothing outside this local network" in text
    assert "--no-router-lookups to skip" not in text


def test_pihole_block_is_not_called_a_hijack():
    def pihole(name):
        return [(1, "0.0.0.0")] if name == "dns.google" else _clean(name)
    result, _ = _run(pihole)
    assert homenet.hn_router_dns_findings(result) == []
    text = homenet.hn_render({"subnet": "192.168.1.0/24", "devices": [], "findings": [], "gaps": [], "seconds": 1,
                              "router_dns": result})
    assert "blocked or failed" in text and "WRONG" not in text


def test_servfail_is_failed_not_wrong():
    def servfail(name):
        return ([], 2) if name == "one.one.one.one" else _clean(name)
    result, _ = _run(servfail)
    assert result["fixed"][0]["blocked"] is True
    assert homenet.hn_router_dns_findings(result) == []
