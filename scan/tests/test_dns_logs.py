"""dns-logs: router / Pi-hole / AdGuard Home / DNS server logs checked offline (--dns-log)."""
import json
import sqlite3

import pytest

from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import dnslogs
from zbtriage.readers import reader_select

DOMAIN = "spy-c2.test"
ADDRESS = "203.0.113.77"


def ctx(paths):
    iocs = IocSet([Indicator(DOMAIN, "cc", "primary", "domain", "fixture", "Family"),
                   Indicator(ADDRESS, "cc", "primary", "ip", "fixture", "Family")], "fixture", None)
    return ScanContext(iocs=iocs, emit=lambda _m: None, dns_logs=tuple(str(p) for p in paths))


def run(tmp_path, name, text):
    path = tmp_path / name
    path.write_text(text, encoding="utf-8")
    return dnslogs.run(ctx([path]))


def graded(r):
    return sorted((h.indicator, h.evidence) for h in r.hits)


def test_dnsmasq_pihole_text(tmp_path):
    log = ("Nov  8 10:00:01 dnsmasq[123]: query[A] www.example.org from 192.168.1.20\n"
           "Nov  8 10:00:02 dnsmasq[123]: query[A] api.spy-c2.test from 192.168.1.31\n"
           "Nov  8 10:00:02 dnsmasq[123]: reply api.spy-c2.test is 203.0.113.77\n"
           "Nov  8 10:05:00 dnsmasq[123]: gravity blocked cdn.spy-c2.test is 0.0.0.0\n")
    r = run(tmp_path, "pihole.log", log)
    assert graded(r) == [(ADDRESS, "dns-record"), (DOMAIN, "attempted"), (DOMAIN, "dns-record")]
    assert r.checked == 3
    assert any(c.ran and c.name == "dns-log:pihole.log" for c in r.checks)
    assert "192.168.1.31" in [h for h in r.hits if h.evidence == "dns-record" and h.indicator == DOMAIN][0].detail


def test_adguard_home_querylog(tmp_path):
    rows = [{"T": "2026-11-08T10:00:01.5Z", "QH": "mail.example.org", "IP": "192.168.1.20", "Result": {}},
            {"T": "2026-11-08T10:00:02.5Z", "QH": "spy-c2.test", "IP": "192.168.1.31", "Result": {"IsFiltered": True}}]
    r = run(tmp_path, "querylog.json", "\n".join(json.dumps(x) for x in rows) + "\n")
    assert graded(r) == [(DOMAIN, "attempted")]
    assert r.reach["dns-logs"]["earliest"] == "2026-11-08 10:00:01"


def test_bind_unbound_windows_dns(tmp_path):
    log = ("08-Nov-2026 10:00:01.123 client @0x7f 192.168.1.5#53412 (spy-c2.test): query: spy-c2.test IN A +E(0)\n"
           "Nov 08 10:00:02 unbound[1:0] info: 192.168.1.6 x.spy-c2.test. A IN\n"
           "11/8/2026 10:00:03 AM 0F2C PACKET  000001 UDP Rcv 192.168.1.7     a1b2   Q [0001   D   NOERROR] A      "
           "(3)www(6)spy-c2(4)test(0)\n")
    r = run(tmp_path, "dns.log", log)
    assert graded(r) == [(DOMAIN, "dns-record")] * 3


def test_zeek_dns_log(tmp_path):
    log = ("#separator \\x09\n#fields\tts\tuid\tid.orig_h\tquery\tanswers\n"
           "1762596001.5\tC1\t192.168.1.9\tspy-c2.test\t203.0.113.77\n"
           "1762596002.5\tC2\t192.168.1.9\texample.org\t93.184.216.34\n")
    r = run(tmp_path, "dns.log", log)
    assert graded(r) == [(ADDRESS, "dns-record"), (DOMAIN, "dns-record")]


def test_pihole_ftl_database(tmp_path):
    db = tmp_path / "pihole-FTL.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE queries(id INTEGER PRIMARY KEY, timestamp INTEGER, type INTEGER, status INTEGER, "
                "domain TEXT, client TEXT, forward TEXT)")
    con.executemany("INSERT INTO queries(timestamp, type, status, domain, client) VALUES(?,?,?,?,?)",
                    [(1762596001, 1, 2, "spy-c2.test", "192.168.1.31"), (1762596002, 1, 1, "spy-c2.test", "192.168.1.32"),
                     (1762596003, 1, 3, "example.org", "192.168.1.20")])
    con.commit()
    con.close()
    r = dnslogs.run(ctx([db]))
    assert graded(r) == [(DOMAIN, "attempted"), (DOMAIN, "dns-record")]
    assert r.submetrics["dns_log_clients"] == 3


def test_parent_domain_matching_but_not_lookalike(tmp_path):
    log = ("Nov  8 10:00:02 dnsmasq[1]: query[A] a.b.spy-c2.test from 192.168.1.2\n"
           "Nov  8 10:00:02 dnsmasq[1]: query[A] notspy-c2.test from 192.168.1.2\n")
    r = run(tmp_path, "pihole.log", log)
    assert graded(r) == [(DOMAIN, "dns-record")]


def test_unrecognised_file_is_a_gap_not_clean(tmp_path):
    r = run(tmp_path, "notes.txt", "hello\nthis is not a DNS log\n")
    assert not r.hits
    assert any(not c.ran and c.name == "dns-log:notes.txt" for c in r.checks)


def test_damaged_database_is_a_gap(tmp_path):
    db = tmp_path / "pihole-FTL.db"
    db.write_bytes(b"SQLite format 3\x00" + b"\x00" * 100)
    r = dnslogs.run(ctx([db]))
    assert any(not c.ran and c.name == "dns-log:pihole-FTL.db" for c in r.checks)


def test_windows_name_decoding():
    assert dnslogs.dl_windns_name("(3)www(7)example(3)com(0)") == "www.example.com"


def test_dns_log_mode_selects_only_this_reader(tmp_path):
    path = tmp_path / "pihole.log"
    path.write_text("x")
    assert [s.name for s in reader_select(ctx([path]))] == ["dns-logs"]


def test_cli_rejects_mixing_with_phone(tmp_path):
    from zbtriage.cli import _parse
    path = tmp_path / "pihole.log"
    path.write_text("x")
    with pytest.raises(SystemExit):
        _parse(["--dns-log", str(path), "--phone", str(tmp_path), "--no-menu"])
    with pytest.raises(SystemExit):
        _parse(["--dns-log", str(tmp_path / "missing.log"), "--no-menu"])


def test_blocked_line_is_attributed_to_the_device_that_asked(tmp_path):
    log = ("Nov  8 10:00:01 dnsmasq[1]: query[A] spy-c2.test from 192.168.1.44\n"
           "Nov  8 10:00:01 dnsmasq[1]: gravity blocked spy-c2.test is 0.0.0.0\n")
    r = run(tmp_path, "pihole.log", log)
    blocked = [h for h in r.hits if h.evidence == "attempted"]
    assert len(blocked) == 1 and "192.168.1.44" in blocked[0].detail
