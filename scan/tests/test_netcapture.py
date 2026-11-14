"""Network recording check: pcap / pcapng reading, DNS, TLS SNI (re-assembled), HTTP Host, PCAPdroid app names,
clockwork contact, indicator matches. Nothing may touch the network."""
import socket
import struct

import pytest

from zbtriage import netcapture as nc
from zbtriage.iocs import Indicator, IocSet


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("the recording check must never touch the network")
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


PHONE, DNS_SERVER = "192.168.1.20", "192.168.1.1"


def ipv4(src, dst, proto, payload):
    total = 20 + len(payload)
    return struct.pack(">BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, proto, 0, socket.inet_aton(src),
                       socket.inet_aton(dst)) + payload


def udp(sport, dport, payload):
    return struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload


def tcp(sport, dport, seq, payload, flags=0x18):
    return struct.pack(">HHIIBBHHH", sport, dport, seq, 0, 0x50, flags, 65535, 0, 0) + payload


def eth(ip, trailer=b""):
    return b"\x00" * 12 + b"\x08\x00" + ip + trailer


def dns_query(name, qtype=1, answers=()):
    q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack(">HH", qtype, 1)
    flags = 0x8180 if answers else 0x0100
    msg = struct.pack(">HHHHHH", 7, flags, 1, len(answers), 0, 0) + q
    for rtype, rdata in answers:
        msg += b"\xc0\x0c" + struct.pack(">HHIH", rtype, 1, 60, len(rdata)) + rdata
    return msg


def client_hello(server_name):
    sni = server_name.encode()
    ext_sni = struct.pack(">HHHBH", 0, len(sni) + 5, len(sni) + 3, 0, len(sni)) + sni
    padding = struct.pack(">HH", 21, 1200) + b"\x00" * 1200       # pushes the hello across segments
    exts = ext_sni + padding
    body = b"\x03\x03" + b"\x11" * 32 + b"\x00" + struct.pack(">H", 2) + b"\x13\x01" + b"\x01\x00" + \
        struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def pcap(frames, linktype=1):
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    for t, frame in frames:
        out += struct.pack("<IIII", int(t), int((t % 1) * 1e6), len(frame), len(frame)) + frame
    return out


def pcapng(frames_by_iface):
    def block(btype, body):
        body += b"\x00" * ((4 - len(body) % 4) % 4)
        return struct.pack("<II", btype, len(body) + 12) + body + struct.pack("<I", len(body) + 12)
    out = block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
    for linktype in (1, 101):
        out += block(1, struct.pack("<HHI", linktype, 0, 65535))
    for iface, t, frame in frames_by_iface:
        ts = int(t * 1e6)
        out += block(6, struct.pack("<IIIII", iface, ts >> 32, ts & 0xFFFFFFFF, len(frame), len(frame)) + frame)
    return out


def pcapdroid_trailer(app):
    return struct.pack(">Ii", nc.NC_PCAPDROID_MAGIC, 10123) + app.encode()[:19].ljust(20, b"\x00")


def tls_flow(t, src_port, dst, name, split=True, trailer=b""):
    hello = client_hello(name)
    frames = [(t, eth(ipv4(PHONE, dst, 6, tcp(src_port, 443, 1000, b"", flags=0x02)), trailer))]
    if split:
        frames += [(t + 0.1, eth(ipv4(PHONE, dst, 6, tcp(src_port, 443, 1001, hello[:700])), trailer)),
                   (t + 0.2, eth(ipv4(PHONE, dst, 6, tcp(src_port, 443, 1701, hello[700:])), trailer))]
    else:
        frames.append((t + 0.1, eth(ipv4(PHONE, dst, 6, tcp(src_port, 443, 1001, hello)), trailer)))
    return frames


def iocs_with(*values):
    return IocSet([Indicator(v, "infrastructure", "primary", "domain", "amnesty-test", "Pegasus") for v in values],
                  "t", 0)


def test_sni_reassembled_across_tcp_segments():
    r = nc.nc_analyse(pcap(tls_flow(1000, 50000, "93.184.216.34", "news.example.org")))
    assert r["stats"]["tls_names"] == 1
    assert "news.example.org" in r["contacted"][PHONE]


def test_dns_questions_answers_and_https_record_type_do_not_crash():
    frames = [(1, eth(ipv4(PHONE, DNS_SERVER, 17, udp(40000, 53, dns_query("c2.bad.example", qtype=65))))),
              (2, eth(ipv4(DNS_SERVER, PHONE, 17, udp(53, 40000, dns_query(
                  "c2.bad.example", answers=[(65, b"\x00\x01\x00"), (1, socket.inet_aton("151.101.1.9"))])))))]
    frames += tls_flow(3, 50001, "151.101.1.9", "c2.bad.example", split=False)
    r = nc.nc_analyse(pcap(frames), iocs_with("bad.example"))
    assert r["level"] == nc.NC_KNOWN
    assert r["findings"][0]["indicator"] == "bad.example" and r["findings"][0]["family"] == "Pegasus"


def test_ip_only_connection_matched_through_its_dns_answer():
    frames = [(1, eth(ipv4(DNS_SERVER, PHONE, 17, udp(53, 40000, dns_query(
        "x.evil.example", answers=[(1, socket.inet_aton("151.101.2.7"))])))))]
    frames += [(2, eth(ipv4(PHONE, "151.101.2.7", 6, tcp(50002, 8888, 5, b"", flags=0x02))))]
    r = nc.nc_analyse(pcap(frames), iocs_with("evil.example"))
    assert r["level"] == nc.NC_KNOWN


def test_pcapdroid_trailer_names_the_app():
    trailer = pcapdroid_trailer("com.spy.helper")
    r = nc.nc_analyse(pcap(tls_flow(1, 50003, "151.101.1.20", "sync.bad.example", trailer=trailer)),
                      iocs_with("bad.example"))
    assert r["findings"][0]["who"] == "com.spy.helper"
    assert r["stats"]["apps_named"] == 1


def test_plain_http_host_is_read():
    req = b"GET /p HTTP/1.1\r\nHost: plain.example.net:8080\r\nUser-Agent: x\r\n\r\n"
    frames = [(1, eth(ipv4(PHONE, "151.101.1.30", 6, tcp(50004, 8080, 1, b"", flags=0x02)))),
              (2, eth(ipv4(PHONE, "151.101.1.30", 6, tcp(50004, 8080, 2, req))))]
    r = nc.nc_analyse(pcap(frames))
    assert "plain.example.net" in r["contacted"][PHONE]
    assert any("without encryption" in n for n in r["notes"])


def test_pcapng_with_two_interfaces_and_raw_ip():
    hello_flow = tls_flow(5, 50005, "151.101.1.40", "a.example.com", split=False)
    raw = ipv4(PHONE, "151.101.1.41", 6, tcp(50006, 443, 1, client_hello("b.example.com")))
    frames = [(0, t, f) for t, f in hello_flow] + [(1, 6.0, raw)]
    r = nc.nc_analyse(pcapng(frames))
    assert {"a.example.com", "b.example.com"} <= set(r["contacted"][PHONE])


def test_clockwork_contact_is_worth_a_look():
    frames = []
    for i in range(8):
        frames += [(1000 + i * 60.0, eth(ipv4(PHONE, "151.101.1.50", 6, tcp(51000 + i, 443, 1, b"", flags=0x02))))]
    r = nc.nc_analyse(pcap(frames))
    assert r["level"] == nc.NC_LOOK
    assert "every 60 seconds" in r["leads"][0]["text"]


def test_dynamic_dns_name_is_worth_a_look():
    frames = [(1, eth(ipv4(PHONE, DNS_SERVER, 17, udp(40000, 53, dns_query("home.duckdns.org")))))]
    r = nc.nc_analyse(pcap(frames))
    assert any("dynamic-DNS" in l["text"] for l in r["leads"])


def test_not_a_capture_file_is_explained():
    with pytest.raises(nc.NcError):
        nc.nc_analyse(b"hello this is not a capture file at all")


def test_truncated_and_garbage_frames_do_not_crash():
    good = pcap(tls_flow(1, 50007, "151.101.1.60", "ok.example", split=False))
    junk = good + struct.pack("<IIII", 5, 0, 40, 40) + b"\xff" * 40 + struct.pack("<IIII", 6, 0, 99999, 99999)
    r = nc.nc_analyse(junk)
    assert "ok.example" in r["contacted"][PHONE]


def test_render_is_plain_and_defangs_findings():
    r = nc.nc_analyse(pcap(tls_flow(1, 50008, "151.101.1.70", "c.bad.example", split=False)), iocs_with("bad.example"))
    text = nc.nc_render(r)
    assert "c[.]bad[.]example" in text and "nothing was contacted" in text


# --- entry points --------------------------------------------------------------------------------------------
from test_followup_fixes import bundle  # noqa: E402,F401  (pytest fixture)


def test_bundle_runs_the_recording_check_not_a_scan(bundle, capsys, monkeypatch, tmp_path):
    rec = tmp_path / "phone.pcap"
    rec.write_bytes(pcap(tls_flow(1, 50010, "151.101.1.80", "x.example.org", split=False)))
    monkeypatch.setattr(bundle, "reader_run", lambda *a, **k: pytest.fail("a computer scan must not start"),
                        raising=False)
    assert bundle._bundle_main(["--no-menu", "--no-banner", "--no-feeds", "--check-traffic", str(rec)]) == 0
    assert "NETWORK RECORDING CHECK" in capsys.readouterr().out


def test_cli_refuses_a_missing_recording(capsys):
    from zbtriage import cli
    with pytest.raises(SystemExit):
        cli._parse(["--check-traffic", "no-such-recording.pcap"])
