"""Check a network recording (--check-traffic FILE): which servers a phone or computer contacted, offline.

Reads a capture file someone recorded - on Android with the free PCAPdroid app (no root), or with Wireshark /
tcpdump on a computer - and extracts the names and addresses the device talked to:

  * DNS questions and answers (including the HTTPS record type phones use constantly),
  * the server name in TLS connections (SNI), after re-assembling TCP (modern browsers split that first
    message across several packets),
  * the Host of plain HTTP requests,
  * QUIC connections (HTTP/3) are counted and their addresses matched; their server names are encrypted and
    this tool never decrypts anything, so they are not read.

PCAPdroid's capture trailer names the app behind each packet, so a match says WHICH APP contacted it.

Each name and address is compared with the spyware indicators the scan uses (with parent domains), and the
traffic is checked for behaviour that spyware shows (ideas from SpyGuard, Apache-2.0, re-implemented here):
contacting a server at regular intervals like clockwork, dynamic-DNS names, plain HTTP, TLS on unusual ports.

File formats: pcap (micro/nano-second, either byte order), pcapng (several interfaces), link types Ethernet,
raw IP, Linux cooked (SLL, SLL2), BSD loopback. Nothing is sent anywhere; the file is only read.
"""
from __future__ import annotations

import ipaddress
import statistics
import struct
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from .i18n import T
from .linkcheck import lc_say, lc_shown

NC_MAX_BYTES = 2 * 1024 * 1024 * 1024
NC_MAX_PACKETS = 5_000_000
NC_TCP_KEEP = 16384              # client bytes kept per TCP flow, enough for any ClientHello
NC_PCAPDROID_MAGIC = 0x01072021

NC_KNOWN, NC_LOOK, NC_NOTHING = "known-threat", "worth-a-look", "nothing-known"

# Dynamic-DNS services: free names that point at changing addresses (own curated list).
_NC_DYNDNS = ("duckdns.org", "no-ip.com", "no-ip.org", "noip.com", "ddns.net", "hopto.org", "zapto.org",
              "sytes.net", "myftp.biz", "myftp.org", "serveftp.com", "servebeer.com", "redirectme.net",
              "dynu.com", "dynu.net", "freedns.afraid.org", "mooo.com", "chickenkiller.com", "dyndns.org",
              "dynalias.com", "ngrok.io", "ngrok-free.app", "trycloudflare.com", "serveo.net", "portmap.io",
              "3utilities.com", "bounceme.net", "gotdns.ch", "kozow.com", "loseyourip.com")
# Encrypted-DNS servers: names are hidden from the recording when the device uses them.
_NC_DOH = ("dns.google", "cloudflare-dns.com", "mozilla.cloudflare-dns.com", "dns.quad9.net", "doh.opendns.com",
           "dns.adguard-dns.com", "dns.nextdns.io", "doh.cleanbrowsing.org", "chrome.cloudflare-dns.com")


class NcError(ValueError):
    pass


# --- reading the capture file ---------------------------------------------------------------------------------

def nc_packets(data: bytes):
    """Yield (timestamp_seconds, linktype, frame_bytes) from pcap or pcapng bytes."""
    if len(data) < 24:
        raise NcError(T("too short to be a capture file"))
    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        yield from _nc_pcap(data)
    elif magic == b"\x0a\x0d\x0d\x0a":
        yield from _nc_pcapng(data)
    else:
        raise NcError(T("not a pcap or pcapng file (PCAPdroid, Wireshark and tcpdump save these)"))


def _nc_pcap(data):
    little = data[:4] in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
    nano = data[:4] in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    e = "<" if little else ">"
    linktype = struct.unpack(e + "I", data[20:24])[0] & 0x0FFFFFFF
    pos, n = 24, 0
    while pos + 16 <= len(data) and n < NC_MAX_PACKETS:
        sec, frac, incl, _orig = struct.unpack(e + "IIII", data[pos:pos + 16])
        pos += 16
        if incl > 262144 or pos + incl > len(data):
            break
        yield sec + frac / (1e9 if nano else 1e6), linktype, data[pos:pos + incl]
        pos += incl
        n += 1


def _nc_pcapng(data):
    pos, n = 0, 0
    e = "<"
    ifaces: List[Tuple[int, float]] = []     # (linktype, seconds per tick)
    while pos + 12 <= len(data) and n < NC_MAX_PACKETS:
        btype_raw = data[pos:pos + 4]
        if btype_raw == b"\x0a\x0d\x0d\x0a":                       # section header: byte order, new interfaces
            bom = data[pos + 8:pos + 12]
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            ifaces = []
        btype, blen = struct.unpack(e + "II", data[pos:pos + 8])
        if blen < 12 or blen % 4 or pos + blen > len(data):
            break
        body = data[pos + 8:pos + blen - 4]
        if btype == 1 and len(body) >= 8:                          # interface description
            linktype = struct.unpack(e + "H", body[:2])[0]
            tick = 1e-6
            opt = 8
            while opt + 4 <= len(body):
                code, olen = struct.unpack(e + "HH", body[opt:opt + 4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:                         # if_tsresol
                    v = body[opt + 4]
                    tick = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                opt += 4 + ((olen + 3) & ~3)
            ifaces.append((linktype, tick))
        elif btype == 6 and len(body) >= 20:                       # enhanced packet
            iface, hi, lo, cap = struct.unpack(e + "IIII", body[:16])
            if iface < len(ifaces) and cap <= len(body) - 20:
                linktype, tick = ifaces[iface]
                yield ((hi << 32) | lo) * tick, linktype, body[20:20 + cap]
                n += 1
        elif btype == 3 and len(body) >= 4 and ifaces:              # simple packet (interface 0, no time)
            linktype, _tick = ifaces[0]
            yield 0.0, linktype, body[4:]
            n += 1
        pos += blen


def _nc_ip_of_frame(linktype: int, frame: bytes) -> Optional[Tuple[bytes, bytes]]:
    """(ip packet, bytes after it) for the supported link types; None if not IP."""
    if linktype == 1:                                  # Ethernet
        off, etype = 14, struct.unpack(">H", frame[12:14])[0] if len(frame) >= 14 else 0
        while etype in (0x8100, 0x88A8) and len(frame) >= off + 4:      # VLAN tags
            etype = struct.unpack(">H", frame[off + 2:off + 4])[0]
            off += 4
        if etype not in (0x0800, 0x86DD):
            return None
        ip = frame[off:]
    elif linktype in (101, 12, 14, 228, 229):          # raw IP
        ip = frame
    elif linktype == 113:                              # Linux cooked
        if len(frame) < 16 or struct.unpack(">H", frame[14:16])[0] not in (0x0800, 0x86DD):
            return None
        ip = frame[16:]
    elif linktype == 276:                              # Linux cooked v2
        if len(frame) < 20 or struct.unpack(">H", frame[0:2])[0] not in (0x0800, 0x86DD):
            return None
        ip = frame[20:]
    elif linktype == 0:                                # BSD loopback
        ip = frame[4:]
    else:
        return None
    if not ip:
        return None
    version = ip[0] >> 4
    if version == 4 and len(ip) >= 20:
        total = struct.unpack(">H", ip[2:4])[0]
        if 20 <= total <= len(ip):
            return ip[:total], ip[total:]
        return ip, b""
    if version == 6 and len(ip) >= 40:
        total = 40 + struct.unpack(">H", ip[4:6])[0]
        if total <= len(ip):
            return ip[:total], ip[total:]
        return ip, b""
    return None


def _nc_pcapdroid_app(trailer: bytes) -> Optional[str]:
    """App name from PCAPdroid's trailer (magic 0x01072021, uid, package name), if present."""
    if len(trailer) >= 8 and struct.unpack(">I", trailer[:4])[0] == NC_PCAPDROID_MAGIC:
        name = trailer[8:28].split(b"\x00", 1)[0].decode("ascii", "replace")
        uid = struct.unpack(">i", trailer[4:8])[0]
        return name or ("uid {}".format(uid) if uid >= 0 else None)
    return None


def _nc_transport(ip: bytes):
    """(src, dst, proto, sport, dport, payload, tcp_seq, tcp_flags) or None."""
    if ip[0] >> 4 == 4:
        ihl = (ip[0] & 0x0F) * 4
        if (struct.unpack(">H", ip[6:8])[0] & 0x1FFF) != 0:       # later fragment: no ports
            return None
        proto, src, dst, rest = ip[9], ipaddress.ip_address(ip[12:16]), ipaddress.ip_address(ip[16:20]), ip[ihl:]
    else:
        proto, src, dst, rest = ip[6], ipaddress.ip_address(ip[8:24]), ipaddress.ip_address(ip[24:40]), ip[40:]
        hops = 0
        while proto in (0, 43, 60) and len(rest) >= 8 and hops < 8:   # hop-by-hop, routing, destination opts
            proto, rest = rest[0], rest[(rest[1] + 1) * 8:]
            hops += 1
    if proto == 6 and len(rest) >= 20:
        sport, dport, seq = struct.unpack(">HHI", rest[:8])
        off = (rest[12] >> 4) * 4
        return str(src), str(dst), "tcp", sport, dport, rest[off:], seq, rest[13]
    if proto == 17 and len(rest) >= 8:
        sport, dport = struct.unpack(">HH", rest[:4])
        return str(src), str(dst), "udp", sport, dport, rest[8:], 0, 0
    return None


# --- protocols ---------------------------------------------------------------------------------------------------

def _nc_dns_name(msg: bytes, pos: int, depth: int = 0) -> Tuple[str, int]:
    labels, jumped, end = [], False, pos
    for _ in range(128):
        if pos >= len(msg):
            raise NcError(T("dns name runs past the message"))
        length = msg[pos]
        if length & 0xC0 == 0xC0:
            if pos + 1 >= len(msg) or depth > 10:
                raise NcError(T("bad dns pointer"))
            target = ((length & 0x3F) << 8) | msg[pos + 1]
            if not jumped:
                end = pos + 2
            jumped = True
            name, _ = _nc_dns_name(msg, target, depth + 1)
            if name:
                labels.append(name)
            return ".".join(labels), end
        pos += 1
        if length == 0:
            return ".".join(labels), (end if jumped else pos)
        labels.append(msg[pos:pos + length].decode("ascii", "replace"))
        pos += length
    raise NcError(T("dns name too long"))


def nc_parse_dns(msg: bytes) -> Tuple[List[str], List[Tuple[str, str]]]:
    """(question names, [(name, address)] from A/AAAA answers). Other record types (HTTPS, SVCB, ...) skipped."""
    if len(msg) < 12:
        return [], []
    qd, an = struct.unpack(">HH", msg[4:8])
    pos, questions, answers = 12, [], []
    try:
        for _ in range(min(qd, 16)):
            name, pos = _nc_dns_name(msg, pos)
            pos += 4
            questions.append(name.lower())
        for _ in range(min(an, 64)):
            name, pos = _nc_dns_name(msg, pos)
            if pos + 10 > len(msg):
                break
            rtype, _cls, _ttl, rdlen = struct.unpack(">HHIH", msg[pos:pos + 10])
            pos += 10
            rdata = msg[pos:pos + rdlen]
            pos += rdlen
            if rtype == 1 and rdlen == 4:
                answers.append((name.lower(), str(ipaddress.ip_address(rdata))))
            elif rtype == 28 and rdlen == 16:
                answers.append((name.lower(), str(ipaddress.ip_address(rdata))))
    except (NcError, ValueError, struct.error):
        pass
    return questions, answers


def nc_sni(data: bytes) -> Optional[str]:
    """The server name from a TLS ClientHello record stream (possibly several records)."""
    hs, pos = b"", 0
    while pos + 5 <= len(data) and data[pos] == 0x16:            # handshake records
        rlen = struct.unpack(">H", data[pos + 3:pos + 5])[0]
        hs += data[pos + 5:pos + 5 + rlen]
        pos += 5 + rlen
    return _nc_sni_handshake(hs)


def _nc_sni_handshake(hs: bytes) -> Optional[str]:
    if len(hs) < 4 or hs[0] != 1:
        return None
    p = 4 + 2 + 32
    if p >= len(hs):
        return None
    p += 1 + hs[p]                                                # session id
    if p + 2 > len(hs):
        return None
    p += 2 + struct.unpack(">H", hs[p:p + 2])[0]                   # cipher suites
    if p >= len(hs):
        return None
    p += 1 + hs[p]                                                # compression
    if p + 2 > len(hs):
        return None
    end = min(len(hs), p + 2 + struct.unpack(">H", hs[p:p + 2])[0])
    p += 2
    while p + 4 <= end:
        etype, elen = struct.unpack(">HH", hs[p:p + 4])
        ext = hs[p + 4:p + 4 + elen]
        if etype == 0 and len(ext) >= 5 and ext[2] == 0:
            nlen = struct.unpack(">H", ext[3:5])[0]
            return ext[5:5 + nlen].decode("ascii", "replace").lower() or None
        p += 4 + elen
    return None


def nc_http_host(data: bytes) -> Optional[str]:
    head = data[:4096]
    if not head[:8].split(b" ")[0] in (b"GET", b"POST", b"PUT", b"HEAD", b"OPTIONS", b"DELETE", b"PATCH", b"CONNECT"):
        return None
    for line in head.split(b"\r\n")[1:40]:
        if line[:5].lower() == b"host:":
            return line[5:].strip().decode("ascii", "replace").split(":")[0].lower() or None
    return None


# --- the check ---------------------------------------------------------------------------------------------------

def _nc_public(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return False
    return not (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved
                or ip.is_unspecified)


def nc_analyse(data: bytes, iocs=None) -> Dict[str, object]:
    """Read a capture and return what was contacted, matches, behaviour leads and coverage."""
    names_by_ip: Dict[str, set] = defaultdict(set)
    contacted: Dict[Tuple[str, str], dict] = {}     # (who, name-or-ip) -> info
    flows: Dict[tuple, dict] = {}
    quic_unread = set()
    stats = {"packets": 0, "ip_packets": 0, "dns_questions": 0, "tls_names": 0, "http_hosts": 0, "quic_names": 0,
             "apps_named": 0, "linktypes": set()}
    apps_seen = set()

    def note(who, target, how, when, port=None, proto=None):
        key = (who, target)
        rec = contacted.setdefault(key, {"who": who, "target": target, "how": set(), "times": [], "ports": set()})
        rec["how"].add(how)
        if when:
            rec["times"].append(when)
        if port:
            rec["ports"].add((proto, port))

    for when, linktype, frame in nc_packets(data):
        stats["packets"] += 1
        stats["linktypes"].add(linktype)
        got = _nc_ip_of_frame(linktype, frame)
        if not got:
            continue
        ip, trailer = got
        stats["ip_packets"] += 1
        app = _nc_pcapdroid_app(trailer)
        if app:
            apps_seen.add(app)
        t = _nc_transport(ip)
        if not t:
            continue
        src, dst, proto, sport, dport, payload, seq, flags = t
        client_side = _nc_public(dst) or dport < sport
        device, peer, pport = (src, dst, dport) if client_side else (dst, src, sport)
        who = app or device
        if proto == "udp" and 53 in (sport, dport) and payload:
            questions, answers = nc_parse_dns(payload)
            if dport == 53:
                for q in questions:
                    stats["dns_questions"] += 1
                    note(who, q, "dns", when)
            for name, addr in answers:
                names_by_ip[addr].add(name)
            continue
        if not _nc_public(peer):
            continue
        key = (proto, device, peer, pport, sport if client_side else dport)
        flow = flows.get(key)
        if flow is None:
            flow = flows[key] = {"who": who, "peer": peer, "port": pport, "proto": proto, "start": when,
                                 "chunks": {}, "kept": 0, "named": False, "plain_http": False}
            if proto == "tcp" and flags & 0x02 or proto == "udp":
                note(who, peer, "connect", when, pport, proto)
        if flow["named"]:
            continue
        if proto == "tcp" and client_side and payload and flow["kept"] < NC_TCP_KEEP:
            flow["chunks"].setdefault(seq, payload)
            flow["kept"] += len(payload)
            stream = b"".join(v for _k, v in sorted(flow["chunks"].items()))
            name = None
            if stream[:1] == b"\x16":
                name = nc_sni(stream)
                if name:
                    stats["tls_names"] += 1
                    note(who, name, "tls", flow["start"], pport, "tcp")
                    if pport not in (443, 8443, 853, 993, 995, 465, 5223, 5228, 4244, 5242):
                        flow["odd_tls"] = True
                        note(who, name, "tls-odd-port", flow["start"], pport, "tcp")
            else:
                name = nc_http_host(stream)
                if name:
                    stats["http_hosts"] += 1
                    note(who, name, "http", flow["start"], pport, "tcp")
            if name:
                flow["named"] = True
        elif proto == "udp" and client_side and pport == 443 and payload and payload[0] & 0xC0 == 0xC0:
            # QUIC (HTTP/3) encrypts its first message; this tool never decrypts anything, so the server name
            # of these connections is not read. The address is still matched.
            quic_unread.add(key)
    stats["apps_named"] = len(apps_seen)
    stats["linktypes"] = sorted(stats["linktypes"])
    stats["quic_unread"] = len(quic_unread)
    stats["flows"] = len(flows)
    return _nc_judge(contacted, names_by_ip, flows, stats, iocs)


def _nc_lookup(iocs, value: str):
    if iocs is None or not value:
        return None
    parts = value.split(".")
    for cand in [value] + [".".join(parts[i:]) for i in range(1, len(parts) - 1)]:
        ind = iocs.lookup(cand)
        if ind and ind.type in ("domain", "ip"):
            return ind
    return None


def _nc_judge(contacted, names_by_ip, flows, stats, iocs):
    findings, leads, notes = [], [], []
    seen = set()
    for (who, target), rec in contacted.items():
        names = {target} | names_by_ip.get(target, set())
        for value in sorted(names):
            ind = _nc_lookup(iocs, value)
            if ind and (who, ind.value) not in seen:
                seen.add((who, ind.value))
                findings.append({"who": who, "contacted": value, "indicator": ind.value,
                                 "family": ind.family or "spyware", "source": ind.source, "tier": ind.tier,
                                 "how": sorted(rec["how"]), "first": min(rec["times"]) if rec["times"] else 0})
        low = target.lower()
        if any(low == d or low.endswith("." + d) for d in _NC_DYNDNS):
            leads.append({"who": who, "target": target, "text": lc_say(
                "uses a dynamic-DNS name ({name}): free names that follow a changing address, popular with home "
                "servers and with spyware control servers", name=target)})
        if "http" in rec["how"] and "tls" not in rec["how"]:
            notes.append(lc_say("{who} talked to {target} without encryption (plain HTTP)", who=who, target=target))
        if "tls-odd-port" in rec["how"]:
            ports = sorted(p for proto, p in rec["ports"] if proto == "tcp")
            leads.append({"who": who, "target": target, "text": lc_say(
                "encrypted connection to {target} on an unusual port ({ports})", target=target,
                ports=", ".join(map(str, ports)))})
        if any(low == d or low.endswith("." + d) for d in _NC_DOH):
            notes.append(lc_say("{who} uses encrypted DNS ({target}): the names it looks up are hidden from this "
                                "recording", who=who, target=target))
    # Clockwork contact: at least 6 connections, regular interval >= 30 s, little jitter.
    starts = defaultdict(list)
    for f in flows.values():
        if f["start"]:
            starts[(f["who"], f["peer"])].append(f["start"])
    for (who, peer), times in starts.items():
        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:]) if b - a > 1]
        if len(gaps) >= 5:
            mean = statistics.mean(gaps)
            if mean >= 30 and statistics.pstdev(gaps) <= 0.1 * mean:
                name = sorted(names_by_ip.get(peer, set()))
                label = "{} ({})".format(peer, name[0]) if name else peer
                leads.append({"who": who, "target": peer, "text": lc_say(
                    "contacts {target} every {seconds} seconds, like clockwork ({n} times). Apps that sync do this "
                    "too; check you know which app it is", target=label, seconds="{:.0f}".format(mean),
                    n=len(times))})
    level = NC_KNOWN if findings else (NC_LOOK if leads else NC_NOTHING)
    if stats["quic_unread"]:
        notes.append(lc_say("{n} QUIC (HTTP/3) connection(s): their server names are encrypted and not read (their "
                            "addresses were still checked)", n=stats["quic_unread"]))
    who_targets = defaultdict(set)
    for (who, target), rec in contacted.items():
        if not target.replace(".", "").isdigit() and ":" not in target and \
                not target.endswith((".arpa", ".local", ".lan", ".home", ".internal", ".localdomain")):
            who_targets[who].add(target)
    return {"level": level, "findings": findings, "leads": leads, "notes": sorted(set(notes))[:40],
            "stats": stats, "contacted": {w: sorted(t) for w, t in who_targets.items()}}


_NC_HEAD = {NC_KNOWN: "KNOWN SPYWARE INFRASTRUCTURE was contacted", NC_LOOK: "WORTH A LOOK",
            NC_NOTHING: "NOTHING KNOWN was contacted"}


def nc_headline(result) -> str:
    return _NC_HEAD[result["level"]]


from .safetext import safe_render  # noqa: E402


@safe_render
def nc_render(result, limit=60) -> str:
    s = result["stats"]
    lines = ["=" * 72, "  " + T("NETWORK RECORDING CHECK") + "  -  " + T(_NC_HEAD[result["level"]]),
             "  " + T("The recording was only read: nothing was contacted or sent anywhere."), "=" * 72, "",
             "  " + T("Read {packets} packets: {dns_questions} name look-ups, {tls_names} encrypted connections "
                      "named, {http_hosts} plain web requests.",
                      **{k: "{:,}".format(s[k]) for k in ("packets", "dns_questions", "tls_names", "http_hosts")})]
    if s["apps_named"]:
        lines.append("  " + T("This recording names the app behind each connection ({n} apps).", n=s["apps_named"]))
    else:
        lines.append("  " + T("This recording does not say which app made each connection (PCAPdroid recordings "
                              "do)."))
    lines.append("")
    if result["findings"]:
        lines.append("  " + T("CONTACTED KNOWN SPYWARE INFRASTRUCTURE"))
        for f in result["findings"]:
            lines.append("    - " + T("{who} contacted {address} - listed as {family} infrastructure ({source})",
                                      who=f["who"], address=f["contacted"].replace(".", "[.]"), family=f["family"],
                                      source=f["source"] or T("built-in list")))
        lines += ["", "  " + T("WHAT TO DO"),
                  "    - " + T("Do not visit the address. Keep the recording and this report: they are evidence."),
                  "    - " + T("Get expert help: Access Now Helpline {url1} (24/7) or Amnesty Security Lab {url2}",
                               url1="https://www.accessnow.org/help/", url2="https://securitylab.amnesty.org/get-help/"),
                  "    - " + T("If the recording names an app, do not uninstall it yet - the helpline may need it."),
                  ""]
    if result["leads"]:
        lines.append("  " + T("WORTH A LOOK"))
        for l in result["leads"][:limit]:
            lines.append("    - {}: {}".format(l["who"], lc_shown(l["text"])))
        lines.append("")
    if result["notes"]:
        lines.append("  " + T("NOTES"))
        for n in result["notes"][:limit]:
            lines.append("    - " + lc_shown(n))
        lines.append("")
    lines.append("  " + T("WHAT WAS CONTACTED"))
    for who, targets in sorted(result["contacted"].items(), key=lambda x: -len(x[1]))[:40]:
        shown = ", ".join(targets[:12]) + (" " + T("and {n} more", n=len(targets) - 12) if len(targets) > 12
                                           else "")
        lines.append("    {}: {}".format(who, shown))
        from .ncinfo import nc_owner_summary
        owners = nc_owner_summary(targets)
        if owners and not owners.startswith("others ("):
            lines.append("      " + T("run by:") + " " + owners)
    if not result["contacted"]:
        lines.append("    " + T("No names were found (the recording may be empty, or all traffic encrypted DNS / "
                                "QUIC)."))
    lines += ["", "  " + T("A recording only shows the time it covers. Record for a day while using the phone "
                           "normally for the clearest result.")]
    return "\n".join(lines)


NC_HOW_TO = """  How to record a phone's traffic (no root needed):
    Android: install PCAPdroid (free, open source) from F-Droid or Google Play. In its settings choose
      "PCAP file" as the output, start it, use the phone normally for a day, stop it, and copy the
      .pcap file to the computer. PCAPdroid's recordings name the app behind every connection.
    iPhone: there is no app that can record without a computer; on a Mac, Apple's free "rvictl" tool and
      Wireshark can record an iPhone connected by cable.
    Computer: Wireshark or tcpdump save .pcap / .pcapng files."""


def nc_command(args, load_iocs, out=print) -> int:
    import json
    import os
    path = args.check_traffic
    size = os.path.getsize(path)
    if size > NC_MAX_BYTES:
        out(T("That recording is {size} GB; the limit is 2 GB. Record a shorter period.",
              size="{:.1f}".format(size / 1e9)))
        return 1
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        iocs = load_iocs(args)
    except Exception as exc:  # noqa: BLE001
        out(T("(Indicator lists could not be loaded: {why}. Checking behaviour only.)", why=str(exc)[:160]))
        iocs = None
    try:
        result = nc_analyse(data, iocs)
    except NcError as exc:
        out(T("That file could not be read: {why}.", why=exc) + "\n\n" + T(NC_HOW_TO))
        return 1
    out(nc_render(result))
    if getattr(args, "json", None):
        with open(args.json, "x", encoding="utf-8") as fh:
            json.dump(dict(result, tool="zero-breach-toolkit network recording check"), fh, indent=2,
                      ensure_ascii=False, default=list)
        out("\n" + T("Saved: {path}", path=args.json))
    return {NC_KNOWN: 3, NC_LOOK: 1, NC_NOTHING: 0}[result["level"]]
