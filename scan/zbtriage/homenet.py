"""Home network check (--home-network): who is on YOUR local network, and which doors they leave open.

This is a separate, opt-in command, not part of the spyware check: the spyware check contacts
nothing, this one has to talk to the devices on the local network. It asks first, every time.

What it does, and nothing more:
  * Works only on the local network this computer is on, and only on private addresses
    (10/8, 172.16/12, 192.168/16). It checks at most the 256 addresses around this computer.
  * Finds devices: one tiny packet to each address so the computer learns who is there (read
    back from its own neighbour table), plus the announcements devices answer to (mDNS/Bonjour
    and UPnP/SSDP), which give names like "Living Room TV".
  * Looks for risky doors: tries to open a connection to a short list of ports per device and
    closes it at once. No data is sent, nothing is logged into, no password is tried.
  * Reads the router's own UPnP description (model, firmware) and its list of ports opened to
    the internet - both are things the router publishes to every device on the network.
  * Asks the router to look up a few test names (unless --no-router-lookups): the router passes
    those lookups on to the internet, so this is the one part whose questions leave the house.
    It tells you which names, and nothing about you is sent beyond an ordinary lookup.

Every result is advice with its ordinary explanation. It does not say a device is infected.
"""
from __future__ import annotations

import concurrent.futures
import ipaddress
import os
import re
import socket
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET

from .contract import sanitize_untrusted


def _hn_text(value, limit=120):
    """Text a device sent us (names, models, UPnP descriptions): untrusted, so control and invisible
    characters are neutralised and line breaks removed before it reaches a terminal, report or JSON."""
    return re.sub(r"[\r\n\t]+", " ", sanitize_untrusted(str(value or "")))[:limit]

HN_MAX_HOSTS = 256
HN_CONNECT_TIMEOUT = 0.6
HN_WORKERS = 32
HN_HTTP_LIMIT = 256 * 1024

# port -> (what it is, risk text or None for "informational")
HN_PORTS = {
    21: ("FTP file sharing", "Files and passwords cross the network unencrypted."),
    22: ("SSH remote login", None),
    23: ("Telnet remote login", "Telnet sends passwords unencrypted and often still has the factory password; it is "
                                "how cameras and routers are commonly taken over."),
    80: ("web page (often a settings page)", None),
    443: ("secure web page", None),
    445: ("Windows file sharing (SMB)", None),
    548: ("Apple file sharing", None),
    554: ("video stream (RTSP)", "A camera or video recorder streams video here."),
    631: ("printer (IPP)", None),
    1883: ("smart-home messaging (MQTT)", "Smart-home messages often travel here without a password."),
    3389: ("Remote Desktop", "Anyone on this network can try to log in to this computer remotely."),
    5555: ("Android debugging over the network (ADB)", "Anyone on this network can install apps on, read from and "
                                                       "control this Android device (phone, TV or TV box) without a "
                                                       "password. If it is a TV, docs/ANDROID-TV.md shows how to "
                                                       "check it for spyware - then turn debugging off."),
    5900: ("VNC remote screen", "Someone on this network may be able to see and control this screen."),
    7547: ("internet provider management (TR-069)", None),
    8000: ("camera/recorder control (Hikvision)", "A camera or video recorder is controlled here."),
    8008: ("Chromecast / Google TV", None),
    8009: ("Chromecast / Google TV", None),
    8080: ("web page (often a settings page)", None),
    8443: ("secure web page", None),
    9100: ("printer", None),
    32400: ("Plex media server", None),
    34567: ("camera recorder control (XMEye)", "Cheap camera recorders use this port; it has well-known security "
                                               "flaws and is often left with no password."),
    37777: ("camera recorder control (Dahua)", "A camera or video recorder is controlled here."),
    62078: ("iPhone / iPad sync", None),
}
HN_CAMERA_PORTS = {554, 8000, 34567, 37777}

HN_SERVICE_TYPES = (
    (r"_googlecast", "Chromecast / Google TV"), (r"_androidtvremote", "Android TV"), (r"_airplay|_raop", "AirPlay (Apple TV or speaker)"),
    (r"_ipp|_printer|_pdl-datastream", "printer"), (r"_hap\b", "HomeKit accessory"), (r"_spotify-connect", "speaker"),
    (r"_sonos", "Sonos speaker"), (r"_amzn|_alexa", "Amazon device"), (r"_companion-link|_apple-mobdev", "Apple device"),
    (r"_smb|_afpovertcp", "computer or storage"), (r"_rtsp|_onvif", "camera"), (r"_hue", "Philips Hue bridge"),
)


class HomeNetError(Exception):
    pass


# --- where am I ---------------------------------------------------------------------------------

def hn_local_address(towards="192.0.2.1"):
    """This computer's address on the route towards `towards` (no packet is sent: a UDP 'connect' only picks a
    route). Towards the home router it is the home-network address, even while a VPN carries everything else."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect((towards, 9))
        return s.getsockname()[0]


def hn_target():
    """(this computer's home address, the /24 to check, the router, note) - or HomeNetError.

    Found from the home router, not from the default route: with a VPN on, the default route is the tunnel,
    and checking 'the network around' the tunnel address would mean contacting the VPN provider's network.
    """
    gateway = hn_gateway()
    if not gateway:
        raise HomeNetError("the home router could not be found on a Wi-Fi or Ethernet connection, so the check "
                           "will not run (with only a VPN or a virtual network, there is no home network to check)")
    local = hn_local_address(gateway)
    subnet = hn_subnet(local)
    if ipaddress.ip_address(gateway) not in subnet:
        raise HomeNetError("this computer ({}) and its router ({}) are not on the same local network, so the check "
                           "will not run".format(local, gateway))
    note = ""
    try:
        if hn_local_address() != local:
            note = ("A VPN or another tunnel carries this computer's internet traffic. The home network ({}) is "
                    "checked directly; the VPN may block the router lookups.".format(subnet))
    except OSError:
        pass
    return local, subnet, gateway, note


def hn_subnet(local):
    """The 256 addresses around this computer, or an explanation why the check refuses to run."""
    ip = ipaddress.ip_address(local)
    if ip.version != 4 or not ip.is_private or ip.is_loopback or ip.is_link_local or ip in ipaddress.ip_network("100.64.0.0/10"):
        raise HomeNetError("this computer's address ({}) is not on a private home or office network, so the check "
                           "will not run".format(local))
    return ipaddress.ip_network("{}/24".format(local), strict=False)


def hn_run(argv, timeout=60):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    p = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
                       timeout=timeout, creationflags=flags)
    return p.returncode, p.stdout or ""


def hn_neighbours():
    """{ip: mac} from this computer's own neighbour (ARP) table."""
    out = {}
    if sys.platform == "win32":
        rc, text = hn_run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                           "Get-NetNeighbor -AddressFamily IPv4 | Where-Object { $_.State -ne 'Unreachable' -and "
                           "$_.LinkLayerAddress } | ForEach-Object { $_.IPAddress + ' ' + $_.LinkLayerAddress }"])
        lines = text.splitlines()
    elif sys.platform.startswith("linux"):
        with open("/proc/net/arp", encoding="ascii") as fh:
            lines = [" ".join((p[0], p[3])) for p in (l.split() for l in fh.readlines()[1:]) if len(p) >= 4 and p[2] != "0x0"]
    else:
        rc, text = hn_run(["arp", "-an"])
        lines = [m.group(1) + " " + m.group(2) for m in re.finditer(r"\(([\d.]+)\) at ([0-9a-f:]+)", text)]
    for line in lines:
        parts = line.split()
        if len(parts) == 2:
            mac = parts[1].lower().replace("-", ":")
            if mac not in ("00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
                out[parts[0]] = mac
    return out


# Interface names that are tunnels or virtual networks, never the home network.
HN_TUNNEL_IF = re.compile(r"^(tun|tap|wg|utun|ppp|ipsec|gif|stf|zt|tailscale|nordlynx|proton|mullvad|docker|br-|"
                          r"veth|virbr|vmnet|vboxnet|lo)", re.I)


def hn_linux_tunnel(iface, sysfs="/sys/class/net"):
    """True for a tunnel (TUN/point-to-point) interface whatever it is called: type 65534 = 'none' (no
    hardware address, as TUN devices report), or a tun_flags file present."""
    base = os.path.join(sysfs, os.path.basename(iface))
    try:
        if os.path.exists(os.path.join(base, "tun_flags")):
            return True
        with open(os.path.join(base, "type"), encoding="ascii") as fh:
            return fh.read().strip() == "65534"
    except OSError:
        return False


def hn_pick_gateway(routes):
    """The home router from [(interface, next hop)] default routes: the first that is a private address on an
    interface that is not a tunnel or a virtual network."""
    for iface, hop in routes:
        try:
            ip = ipaddress.ip_address(hop)
        except ValueError:
            continue
        if ip.version == 4 and ip.is_private and not ip.is_unspecified and not HN_TUNNEL_IF.match(iface or ""):
            return str(ip)
    return None


def hn_gateway():
    """The home router: a default route through a physical Wi-Fi or Ethernet adapter, never through a VPN."""
    try:
        if sys.platform == "win32":
            # Get-NetAdapter -Physical leaves out VPN, Hyper-V/WSL and other virtual adapters.
            rc, text = hn_run(["powershell", "-NoProfile", "-NonInteractive", "-Command",
                               "$p = @(Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | "
                               "ForEach-Object ifIndex); Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "
                               "0.0.0.0/0 -ErrorAction SilentlyContinue | Where-Object { $p -contains $_.ifIndex } | "
                               "Sort-Object RouteMetric | ForEach-Object { 'eth ' + $_.NextHop }"])
            return hn_pick_gateway([tuple(l.split(None, 1)) for l in text.splitlines() if len(l.split()) == 2])
        if sys.platform.startswith("linux"):
            routes = []
            with open("/proc/net/route", encoding="ascii") as fh:
                for line in fh.readlines()[1:]:
                    p = line.split()
                    # A real default route has destination AND mask 0. VPNs install 0.0.0.0/1 + 128.0.0.0/1,
                    # whose destination is also 0 - the mask tells them apart.
                    if (len(p) > 7 and p[1] == "00000000" and p[7] == "00000000" and p[2] != "00000000"
                            and not hn_linux_tunnel(p[0])):
                        routes.append((p[0], str(ipaddress.IPv4Address(bytes.fromhex(p[2])[::-1]))))
            return hn_pick_gateway(routes)
        rc, text = hn_run(["netstat", "-rn", "-f", "inet"])
        routes = [(p[3], p[1]) for p in (l.split() for l in text.splitlines())
                  if len(p) >= 4 and p[0] == "default"]
        return hn_pick_gateway(routes)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


# --- discovery -------------------------------------------------------------------------------------

def hn_nudge(subnet, local):
    """One empty UDP packet to each address (discard port 9), so this computer learns who answers to ARP."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        for ip in list(subnet.hosts())[:HN_MAX_HOSTS]:
            if str(ip) != local:
                try:
                    s.sendto(b"\0", (str(ip), 9))
                except OSError:
                    pass
                time.sleep(0.004)


def _dns_name(data, offset, depth=0):
    labels = []
    while offset < len(data) and depth < 20:
        length = data[offset]
        if length == 0:
            return ".".join(labels), offset + 1
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack_from(">H", data, offset)[0] & 0x3FFF
            name, _ = _dns_name(data, pointer, depth + 1)
            labels.append(name)
            return ".".join(l for l in labels if l), offset + 2
        labels.append(data[offset + 1:offset + 1 + length].decode("utf-8", "replace"))
        offset += 1 + length
    raise ValueError("bad DNS name")


def hn_parse_mdns(data):
    """Names in an mDNS answer: PTR targets, SRV/TXT/A owners. Returns a set of strings."""
    names = set()
    _id, _flags, qd, an, ns, ar = struct.unpack_from(">HHHHHH", data, 0)
    offset = 12
    for _ in range(qd):
        _, offset = _dns_name(data, offset)
        offset += 4
    for _ in range(an + ns + ar):
        owner, offset = _dns_name(data, offset)
        rtype, _cls, _ttl, rdlen = struct.unpack_from(">HHIH", data, offset)
        offset += 10
        if rtype == 12:  # PTR
            target, _ = _dns_name(data, offset)
            names.add(target)
        elif rtype in (33, 16, 1, 28):  # SRV, TXT, A, AAAA
            names.add(owner)
        offset += rdlen
    return {n for n in names if n}


def _mdns_query(name):
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\0"
    return header + qname + struct.pack(">HH", 12, 0x8001)  # PTR, class IN with unicast-response bit


def hn_mdns(seconds=3.0):
    """{ip: set(names)} from mDNS/Bonjour answers on the local network."""
    found = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(0.3)
        types = ["_services._dns-sd._udp.local"]
        s.sendto(_mdns_query(types[0]), ("224.0.0.251", 5353))
        asked = set(types)
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                data, (ip, _port) = s.recvfrom(9000)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                names = hn_parse_mdns(data)
            except (ValueError, struct.error, IndexError):
                continue
            found.setdefault(ip, set()).update(names)
            for name in names:  # ask each advertised service type once for its instances (friendly names)
                if name.endswith((".local",)) and name.startswith("_") and name not in asked and len(asked) < 40:
                    asked.add(name)
                    s.sendto(_mdns_query(name), ("224.0.0.251", 5353))
    return found


HN_SSDP = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\n"
           "ST: ssdp:all\r\n\r\n").encode()


def hn_parse_ssdp(data):
    text = data.decode("utf-8", "replace")
    headers = {}
    for line in text.split("\r\n")[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().upper()] = value.strip()[:300]
    return headers


def hn_ssdp(seconds=3.0):
    """{ip: [headers]} from UPnP/SSDP answers."""
    found = {}
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.settimeout(0.3)
        s.sendto(HN_SSDP, ("239.255.255.250", 1900))
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            try:
                data, (ip, _port) = s.recvfrom(9000)
            except socket.timeout:
                continue
            except OSError:
                break
            found.setdefault(ip, []).append(hn_parse_ssdp(data))
    return found


# --- local HTTP (UPnP descriptions and the router's port-mapping list) ----------------------------

def _hn_local_url(url, subnet):
    try:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "http" or not parts.hostname or parts.username or parts.password or "@" in parts.netloc:
            return False
        parts.port            # raises ValueError on a non-numeric or out-of-range port
        return ipaddress.ip_address(parts.hostname) in subnet
    except ValueError:
        return False


def hn_http(url, subnet, data=None, headers=None, timeout=3):
    """GET/POST to a device on THIS local network only; refuses any other address and redirects."""
    if not _hn_local_url(url, subnet):
        raise HomeNetError("refused: not an address on this local network")

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *_a, **_k):
            return None
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.ProxyHandler({}))
    req = urllib.request.Request(url, data=data, headers=headers or {})
    with opener.open(req, timeout=timeout) as resp:
        return resp.read(HN_HTTP_LIMIT)


def hn_parse_description(xml_bytes):
    """friendlyName, manufacturer, modelName, modelNumber, deviceType and service control URLs."""
    root = ET.fromstring(xml_bytes)
    def find(tag):
        el = root.find(".//{*}device/{*}" + tag)
        return _hn_text(el.text.strip(), 120) if el is not None and el.text else ""
    info = {k: find(k) for k in ("friendlyName", "manufacturer", "modelName", "modelNumber", "deviceType")}
    base = root.find("{*}URLBase")
    info["URLBase"] = (base.text or "").strip() if base is not None and base.text else ""
    info["services"] = [((s.findtext("{*}serviceType") or "").strip(), (s.findtext("{*}controlURL") or "").strip())
                        for s in root.findall(".//{*}service")]
    return info


_HN_SOAP = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            '<u:GetGenericPortMappingEntry xmlns:u="{st}"><NewPortMappingIndex>{i}</NewPortMappingIndex>'
            '</u:GetGenericPortMappingEntry></s:Body></s:Envelope>')


def hn_parse_mapping(xml_bytes):
    root = ET.fromstring(xml_bytes)
    def get(tag):
        el = root.find(".//{*}" + tag)
        if el is None:
            el = root.find(".//" + tag)
        return _hn_text(el.text.strip(), 120) if el is not None and el.text else ""
    return {k: get(k) for k in ("NewRemoteHost", "NewExternalPort", "NewProtocol", "NewInternalPort",
                                "NewInternalClient", "NewEnabled", "NewPortMappingDescription")}


def hn_port_mappings(location, info, subnet, limit=64):
    """The router's own list of ports it has opened to the internet (UPnP IGD, read-only action)."""
    base = info.get("URLBase") or location
    out = []
    for service_type, control in info.get("services", []):
        if not re.search(r"WAN(IP|PPP)Connection:\d", service_type) or not control:
            continue
        url = urllib.parse.urljoin(base, control)
        for i in range(limit):
            body = _HN_SOAP.replace("{st}", service_type).replace("{i}", str(i)).encode()
            try:
                raw = hn_http(url, subnet, data=body, headers={
                    "Content-Type": 'text/xml; charset="utf-8"',
                    "SOAPAction": '"{}#GetGenericPortMappingEntry"'.format(service_type)})
            except (OSError, HomeNetError, urllib.error.URLError):
                break  # the router answers an error after the last entry
            try:
                entry = hn_parse_mapping(raw)
            except ET.ParseError:
                break
            if not entry.get("NewExternalPort"):
                break
            out.append(entry)
        break
    return out


# --- open ports --------------------------------------------------------------------------------------

# Errors that mean the port answered "closed" or did not answer: an ordinary result. Anything else
# (permission denied, network unreachable) means THIS computer stopped the attempt - a firewall or a VPN
# kill switch - and must not be reported as "nothing open".
_HN_NORMAL_ERRNOS = {10061, 111, 61, 10060, 110, 60, 10065, 113, 65}


def hn_port_state(ip, port):
    """"open", "closed" or "blocked" (this computer refused to try)."""
    try:
        with socket.create_connection((ip, port), timeout=HN_CONNECT_TIMEOUT):
            return "open"
    except socket.timeout:
        return "closed"
    except OSError as exc:
        return "closed" if (exc.errno in _HN_NORMAL_ERRNOS or getattr(exc, "winerror", None) in _HN_NORMAL_ERRNOS
                            or exc.errno is None) else "blocked"


def hn_port_open(ip, port):
    return hn_port_state(ip, port) == "open"


def hn_scan_ports(ips, ports=tuple(HN_PORTS), stats=None):
    """{ip: [open ports]} - connect and close at once; nothing is sent. `stats` (a dict) receives counts."""
    jobs = [(ip, port) for ip in ips for port in ports]
    found, blocked = {}, 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=HN_WORKERS) as pool:
        for (ip, port), state in zip(jobs, pool.map(lambda j: hn_port_state(*j), jobs)):
            if state == "open":
                found.setdefault(ip, []).append(port)
            elif state == "blocked":
                blocked += 1
    if stats is not None:
        stats.update(attempts=len(jobs), blocked=blocked)
    return found


# --- cameras: does the video need a password? ------------------------------------------------------
# One RTSP DESCRIBE with NO credentials, on the common stream paths. "200" = the camera hands its stream to
# anyone on this network; "401" = it asks for a password. Only the stream's description (SDP) is read - never
# the video - and no password, default or otherwise, is ever tried.
HN_RTSP_PATHS = ("/", "/live", "/stream1", "/h264", "/cam/realmonitor?channel=1&subtype=0",
                 "/Streaming/Channels/101", "/user=admin_password=_channel=1_stream=0.sdp", "/11", "/live/ch00_0")
HN_RTSP_TIMEOUT = 3.0


def hn_rtsp_status(response):
    """The RTSP status code from a response's first line, or None."""
    m = re.match(rb"RTSP/1\.[01] (\d{3})", response or b"")
    return int(m.group(1)) if m else None


def hn_rtsp_ask(ip, port, path, timeout=HN_RTSP_TIMEOUT):
    request = ("DESCRIBE rtsp://{}:{}{} RTSP/1.0\r\nCSeq: 2\r\nAccept: application/sdp\r\n"
               "User-Agent: zero-breach-home-check\r\n\r\n").format(ip, port, path).encode("ascii")
    with socket.create_connection((ip, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(request)
        data = b""
        while len(data) < 4096 and b"\r\n\r\n" not in data:
            chunk = s.recv(1024)
            if not chunk:
                break
            data += chunk
    return hn_rtsp_status(data)


def hn_camera_password(ip, port=554, ask=hn_rtsp_ask):
    """"open" (video without a password), "protected" (asks for one) or "unknown"."""
    protected = False
    for path in HN_RTSP_PATHS:
        try:
            code = ask(ip, port, path)
        except OSError:
            return "protected" if protected else "unknown"
        if code == 200:
            return "open"
        if code == 401:
            protected = True
    return "protected" if protected else "unknown"


# --- makers with actively exploited flaws (CISA KEV, saved by --update) -----------------------------

def hn_device_makers(devices, gaps, kev_doc=None, oui=None):
    """Name each device's maker (from its own UPnP description, else the manufacturer list saved by --update)
    and attach the maker's actively exploited flaws from CISA's list. Reads saved files only."""
    from .kevdata import kev_device_maker, kev_load
    from .feeds import default_cache_dir
    if kev_doc is None:
        kev_doc, _problem = kev_load(default_cache_dir())
    if oui is None:
        oui = hn_oui_load()
    vendors = (kev_doc or {}).get("device_vendors") or {}
    from .wifinearby import wn_private_address, wn_vendor
    for d in devices:
        if d.get("mac") and not d.get("maker"):
            # The list saved by --update when there is one, else the copy built into the program.
            org = (oui or {}).get(d["mac"].replace("-", ":").upper()[:8]) or \
                ("" if wn_private_address(d["mac"]) else wn_vendor(d["mac"]))
            if org:
                d["maker"] = _hn_text(org, 60)
        maker = kev_device_maker(" ".join(str(d.get(k, "")) for k in ("model", "name", "maker")))
        if maker and maker in vendors:
            d["exploited"] = dict(vendors[maker], vendor=maker)
    if devices and not vendors:
        gaps.append("routers and cameras were not compared with the list of actively exploited flaws: run "
                    "--update once to save it")
    if devices and not oui and not wn_vendor("00:00:0C:00:00:00"):
        gaps.append("device makers are not named from their hardware addresses: run --update once to save the "
                    "manufacturer list")


HN_OUI_FILE = "manufacturers.json"


def hn_oui_load():
    """{"AA:BB:CC": organisation} saved by --update from the IEEE public listing, or {}."""
    import json
    from .feeds import default_cache_dir
    try:
        with open(os.path.join(default_cache_dir(), HN_OUI_FILE), encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


# --- putting it together --------------------------------------------------------------------------

def hn_kind(names, ports, ssdp_types):
    text = " ".join(sorted(names)) + " " + " ".join(ssdp_types)
    for pattern, kind in HN_SERVICE_TYPES:
        if re.search(pattern, text, re.I):
            return kind
    if set(ports) & HN_CAMERA_PORTS:
        return "camera or video recorder"
    if "InternetGatewayDevice" in text:
        return "router"
    if "MediaRenderer" in text:
        return "TV or speaker"
    if 62078 in ports:
        return "iPhone or iPad"
    if 9100 in ports or 631 in ports:
        return "printer"
    if 5555 in ports:
        return "Android device"
    return ""


# --- router lookups (opt-in part of the check; the only part that reaches outside) --------------------
# The router is never logged into, so its DNS setting cannot be read. Instead we ask it to look up a
# few names and judge the answers: names whose answers never change, a name that cannot exist, and
# two names that echo back the address of whoever asked - the resolver the router really uses.
HN_FIXED_NAMES = (("one.one.one.one", frozenset({"1.1.1.1", "1.0.0.1"})),
                  ("dns.google", frozenset({"8.8.8.8", "8.8.4.4"})))
HN_WHOAMI = (("whoami.akamai.net", 1), ("o-o.myaddr.l.google.com", 16))
HN_NX_PARENT = "example.com"          # reserved by IANA (RFC 2606); has no wildcard, so made-up names must fail
HN_DNS_TIMEOUT = 3.0


def hn_dns_query(name, qtype, qid):
    """A standard recursive query (RD set) for one name."""
    header = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    qname = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".") if p) + b"\0"
    return header + qname + struct.pack(">HH", qtype, 1)


def hn_parse_dns_answer(data, qid):
    """(rcode, [(type, value)]) from a DNS response. A -> dotted address, TXT -> joined text."""
    rid, flags, qd, an, _ns, _ar = struct.unpack_from(">HHHHHH", data, 0)
    if rid != qid or not flags & 0x8000:
        raise ValueError("not the answer to our question")
    offset = 12
    for _ in range(qd):
        _, offset = _dns_name(data, offset)
        offset += 4
    answers = []
    for _ in range(an):
        _, offset = _dns_name(data, offset)
        rtype, _cls, _ttl, rdlen = struct.unpack_from(">HHIH", data, offset)
        offset += 10
        rdata = data[offset:offset + rdlen]
        if len(rdata) != rdlen:
            raise ValueError("truncated answer")
        if rtype == 1 and rdlen == 4:
            answers.append((1, socket.inet_ntoa(rdata)))
        elif rtype == 16:
            parts, i = [], 0
            while i < len(rdata):
                n = rdata[i]
                parts.append(rdata[i + 1:i + 1 + n].decode("utf-8", "replace"))
                i += 1 + n
            answers.append((16, "".join(parts)))
        offset += rdlen
    return flags & 0x000F, answers


def hn_dns_ask(server, name, qtype=1, port=53, timeout=HN_DNS_TIMEOUT, tries=2):
    """Ask one DNS server one question over UDP. Returns (rcode, answers); raises TimeoutError."""
    for _ in range(tries):
        qid = struct.unpack(">H", os.urandom(2))[0]
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(hn_dns_query(name, qtype, qid), (server, port))
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    data, addr = s.recvfrom(4096)
                except socket.timeout:
                    break
                if addr[0] != server:
                    continue
                try:
                    return hn_parse_dns_answer(data, qid)
                except (ValueError, struct.error):
                    continue
    raise TimeoutError("no answer from {}".format(server))


def hn_router_dns(server, port=53, nx_name=None):
    """Ask the router a few test questions. Returns a dict for the report (never raises)."""
    from .modules.trust import trust_dns_label
    result = {"asked": server, "fixed": [], "nx": None, "upstream": [], "gaps": []}
    try:
        for name, expected in HN_FIXED_NAMES:
            rcode, answers = hn_dns_ask(server, name, 1, port)
            got = sorted({v for t, v in answers if t == 1})
            # A filter (Pi-hole, AdGuard, parental controls) answers 0.0.0.0 / 127.0.0.1 or refuses: that is a
            # block, not a redirect to somewhere else - and SERVFAIL/REFUSED is a failure, not a wrong answer.
            blocked = (bool(got) and set(got) <= {"0.0.0.0", "127.0.0.1", "::"}) or (not got and rcode in (2, 3, 5))
            result["fixed"].append({"name": name, "got": got, "expected": sorted(expected),
                                    "ok": bool(got) and set(got) <= expected, "blocked": blocked, "rcode": rcode})
        nx_name = nx_name or "zbt-{}.{}".format(os.urandom(6).hex(), HN_NX_PARENT)
        rcode, answers = hn_dns_ask(server, nx_name, 1, port)
        result["nx"] = {"name": nx_name, "rcode": rcode, "got": sorted({v for t, v in answers if t == 1})}
        seen = set()
        for name, qtype in HN_WHOAMI:
            try:
                _rc, answers = hn_dns_ask(server, name, qtype, port)
            except TimeoutError:
                continue
            for _t, value in answers:
                value = value.strip()
                try:
                    ipaddress.ip_address(value)
                except ValueError:
                    continue          # e.g. Google's "edns0-client-subnet ..." text: never stored
                if value not in seen:
                    seen.add(value)
                    kind, owner = trust_dns_label(value)
                    result["upstream"].append({"address": value, "kind": kind, "owner": owner, "via": name})
        if not result["upstream"]:
            result["gaps"].append("the router's own resolver could not be identified")
    except TimeoutError:
        result["gaps"].append("the router at {} did not answer lookups. A VPN that is switched on usually "
                              "blocks this on purpose; some routers hand out a different DNS server instead. Run it again "
                              "with the VPN off to test the router. (This computer's own DNS settings are checked by the "
                              "spyware check.)".format(server))
    except OSError as exc:
        result["gaps"].append("the router could not be asked to look up names: {}".format(exc))
    return result


def hn_router_dns_findings(rd):
    """Advice items from hn_router_dns(): (title, detail, explanation)."""
    items = []
    if not rd:
        return items
    for f in rd.get("fixed", ()):
        if f["got"] and not f["ok"] and not f.get("blocked"):
            items.append(("Your router gave a wrong answer for {}".format(f["name"]),
                          "It answered {}; the real answer is {}.".format(", ".join(f["got"]), " or ".join(f["expected"])),
                          "Something between this computer and the internet is changing lookups. It can be a filtering "
                          "service you chose (parental controls, a company network) - or the router's DNS setting was "
                          "changed by someone or by malware. Check the DNS setting in the router's admin page, then "
                          "change the router's admin password. If unsure, reset the router to factory settings."))
    nx = rd.get("nx")
    if nx and nx["got"]:
        items.append(("Your router answers made-up names with an address",
                      "{} should not exist, but came back as {}.".format(nx["name"], ", ".join(nx["got"])),
                      "Many internet providers do this to show a search or advert page instead of an error - "
                      "annoying but usually harmless. It is also how a hijacked router sends people to fake pages, "
                      "so check that the router's DNS setting is what you or your provider set."))
    for u in rd.get("upstream", ()):
        if u["kind"] == "dnschanger":
            items.append(("Your router's lookups go to {}, an address used by router malware".format(u["address"]),
                          "This range was used by the DNSChanger malware to redirect whole households.",
                          "Change the router's DNS setting back to automatic, change its admin password, and update its "
                          "firmware. If you cannot, reset it to factory settings."))
    return items


def hn_mark_shared(devices):
    """Devices whose hardware address is shared with other addresses: what a Wi-Fi extender (repeater) does for
    everything connected through it. Marked, so they are understood rather than mistaken for something odd."""
    by_mac = {}
    for d in devices:
        if d.get("mac"):
            by_mac.setdefault(d["mac"], []).append(d)
    for group in by_mac.values():
        if len(group) > 1:
            for d in group:
                d["shared_mac"] = True
    return devices


def hn_findings(devices, mappings, gateway):
    """Advice items: (title, detail, explanation). Fixed wording; names come from the devices."""
    items = []
    for d in devices:
        # One item per device: a camera with three open ports is one thing to look at, not three.
        label = "{} ({})".format(d["ip"], d.get("name") or d.get("kind") or "unnamed device")
        risky = [(HN_PORTS[p][0], HN_PORTS[p][1], p) for p in d["ports"] if HN_PORTS[p][1]]
        if d.get("exploited"):
            e = d["exploited"]
            items.append(("Keep {}'s firmware up to date: {} ({} device)".format(e["vendor"], label, e["vendor"]),
                          "Attackers are actively using {} flaw(s) in {} devices (CISA list; newest {}, added {}).".format(
                              e["count"], e["vendor"], e["newest_cve"], e["newest_date"]),
                          "This does not mean this device is affected - it depends on the model and firmware. Open its "
                          "settings page or app, install any firmware update, and change the admin password if it was "
                          "never changed. Devices the maker no longer updates are best replaced."))
        if d.get("video_password") == "open":
            items.append(("ANYONE ON THIS WI-FI CAN WATCH THIS CAMERA: {}".format(label),
                          "It sent its video stream details without asking for a password.",
                          "Turn on a password for the video stream in the camera's settings (often 'RTSP "
                          "authentication' or 'Stream security'), change the admin password, and update its "
                          "firmware. If it is not yours, find out whose it is - especially in a rented or shared place."))
        if d.get("kind") == "camera or video recorder" or (set(d["ports"]) & HN_CAMERA_PORTS):
            extra = " ".join(risk for _w, risk, p in risky if p not in HN_CAMERA_PORTS)
            doors = ", ".join(what for what, _r, _p in risky)
            if d.get("video_password") == "protected":
                extra = (extra + " " if extra else "") + "Its video stream asks for a password."
            items.append(("A camera or video recorder is on this network: {}".format(label),
                          ("Open: {}. ".format(doors) if doors else "") + (extra + " " if extra else "") +
                          "Cameras can watch a home or office.",
                          "Usually a home security camera, doorbell or baby monitor. Make sure you know whose it is "
                          "and where it is, that it has its own strong password (never the factory one) and up-to-date "
                          "firmware - especially in a rented or shared place."))
        elif risky:
            title = ("Open door: {} on {}".format(risky[0][0], label) if len(risky) == 1 else
                     "Open doors on {}: {}".format(label, ", ".join(what for what, _r, _p in risky)))
            items.append((title, " ".join(risk for _w, risk, _p in risky),
                          "If you don't use it, turn it off in that device's settings, or ask whoever set the "
                          "device up. Never leave it with the factory password."))
    for m in mappings:
        port = m.get("NewExternalPort")
        client = m.get("NewInternalClient")
        items.append(("Your router has opened port {} {} to the internet, for {}".format(
            port, m.get("NewProtocol", ""), client),
            "Description: {}".format(m.get("NewPortMappingDescription") or "none given"),
            "Games, video calls and media servers do this through UPnP. If you don't recognise it, it can be "
            "how something on your network is reached from outside: turn UPnP off on the router if you don't need it."))
    return items


def hn_check(emit=lambda _m: None, router_lookups=True, camera_check=True):
    """Run the whole check. Returns a dict for the report."""
    started = time.time()
    local, subnet, gateway, note = hn_target()
    if note:
        emit("[home] " + note)
    emit("[home] local network {} (this computer {}, router {})".format(subnet, local, gateway or "?"))
    gaps = []
    emit("[home] finding devices")
    hn_nudge(subnet, local)
    ssdp, mdns = {}, {}
    try:
        ssdp = hn_ssdp()
    except OSError as exc:
        gaps.append("UPnP/SSDP announcements could not be read: {}".format(exc))
    try:
        mdns = hn_mdns()
    except OSError as exc:
        gaps.append("mDNS/Bonjour announcements could not be read: {}".format(exc))
    try:
        neighbours = hn_neighbours()
    except (OSError, subprocess.SubprocessError) as exc:
        neighbours = {}
        gaps.append("the neighbour table could not be read: {}".format(exc))
    ips = sorted({ip for ip in set(neighbours) | set(ssdp) | set(mdns)
                  if ipaddress.ip_address(ip) in subnet and ip != local}, key=ipaddress.ip_address)[:HN_MAX_HOSTS]
    emit("[home] {} devices; checking for open doors".format(len(ips)))
    port_stats = {}
    ports = hn_scan_ports(ips, stats=port_stats)
    if port_stats.get("attempts") and port_stats.get("blocked", 0) * 2 > port_stats["attempts"]:
        gaps.append("this computer blocked most of the door checks ({} of {}): a firewall or a VPN kill switch "
                    "probably stops it reaching other devices, so open doors may have been missed".format(
                        port_stats["blocked"], port_stats["attempts"]))
    descriptions, mappings = {}, []
    for ip, answers in ssdp.items():
        for headers in answers:
            location = headers.get("LOCATION", "")
            if location and ip not in descriptions and _hn_local_url(location, subnet):
                try:
                    descriptions[ip] = (location, hn_parse_description(hn_http(location, subnet)))
                except Exception:  # noqa: BLE001 - any device can answer anything; one must never end the check
                    pass
    if gateway in descriptions:
        try:
            mappings = hn_port_mappings(descriptions[gateway][0], descriptions[gateway][1], subnet)
        except Exception as exc:  # noqa: BLE001 - as above: a broken router answer is a gap, not a crash
            gaps.append("the router's list of opened ports could not be read: {}".format(
                sanitize_untrusted(str(exc))[:200]))
    router_dns = None
    if router_lookups and gateway:
        emit("[home] asking the router to look up {} test names".format(len(HN_FIXED_NAMES) + 1 + len(HN_WHOAMI)))
        router_dns = hn_router_dns(gateway)
        gaps += router_dns["gaps"]
    elif router_lookups:
        gaps.append("the router was not found, so its lookups were not tested")
    devices = []
    for ip in ips:
        info = descriptions.get(ip, (None, {}))[1]
        names = {n for n in mdns.get(ip, ()) if not n.startswith("_")}
        ssdp_types = [h.get("ST", "") + " " + h.get("SERVER", "") for h in ssdp.get(ip, [])] + [info.get("deviceType", "")]
        friendly = info.get("friendlyName") or next((n.split("._")[0] for n in sorted(names) if "._" in n), "")
        devices.append({"ip": ip, "mac": _hn_text(neighbours.get(ip, ""), 40), "name": _hn_text(friendly, 80),
                        "model": _hn_text(" ".join(str(v) for v in (info.get("manufacturer"), info.get("modelName"),
                                                                    info.get("modelNumber")) if v), 120),
                        "kind": "router" if ip == gateway else hn_kind(mdns.get(ip, set()), ports.get(ip, []), ssdp_types),
                        "ports": sorted(ports.get(ip, []))})
    hn_device_makers(devices, gaps)
    for d in devices:
        if camera_check and 554 in d["ports"]:
            emit("[home] asking the camera at {} whether its video needs a password".format(d["ip"]))
            d["video_password"] = hn_camera_password(d["ip"])
    hn_mark_shared(devices)
    return {"subnet": str(subnet), "this_computer": local, "router": gateway, "note": note, "devices": devices,
            "port_mappings": mappings, "router_dns": router_dns,
            "findings": hn_findings(devices, mappings, gateway) + hn_router_dns_findings(router_dns), "gaps": gaps,
            "seconds": round(time.time() - started)}


from .safetext import safe_render, st_wrap_lines  # noqa: E402
from .i18n import T, TX  # noqa: E402


@safe_render
def hn_render(result):
    out = ["=" * 72, "  " + T("HOME NETWORK CHECK") + "  -  {}".format(result["subnet"]),
           "  " + T("Looks only; nothing was logged into or changed. This is advice, not a spyware result."),
           "=" * 72, ""]
    if result.get("note"):
        out += ["  " + TX(result["note"]), ""]
    out.append("  " + T("DEVICES ON THIS NETWORK ({n})", n=len(result["devices"])))
    for d in result["devices"]:
        doors = ", ".join("{} ({})".format(p, T(HN_PORTS[p][0])) for p in d["ports"]) or T("none of the checked ports")
        out.append("    {:<15} {:<26} {}".format(d["ip"], (d["name"] or (T(d["kind"]) if d["kind"] else "") or
                                                          T("unnamed"))[:26],
                                              (d["model"] or d.get("maker", ""))[:40]))
        if d.get("shared_mac"):
            out.append("    {:<15} ".format("") + T("shares its hardware address with other devices: probably behind "
                                                     "a Wi-Fi extender or repeater"))
        out.append("    {:<15} ".format("") + T("open: {doors}", doors=doors))
    rd = result.get("router_dns")
    if rd and (rd["fixed"] or rd["upstream"]):
        out += ["", "  " + T("ROUTER LOOKUPS (asked {address})", address=rd["asked"])]
        for f in rd["fixed"]:
            out.append("    {:<26} {}".format(f["name"], T("correct") if f["ok"] else
                                              T("blocked or failed (a filter such as Pi-hole, or no answer)")
                                              if f.get("blocked") or not f["got"] else
                                              T("WRONG: {answers}", answers=", ".join(f["got"]))))
        if rd["nx"]:
            out.append("    {:<26} {}".format(T("a made-up name"), T("correctly unknown") if not rd["nx"]["got"]
                                              else T("answered with {answers}", answers=", ".join(rd["nx"]["got"]))))
        for u in rd["upstream"]:
            who = u["owner"] or {"dnschanger": T("KNOWN ROUTER-MALWARE RANGE"),
                                 "other": T("the resolver your router uses, often your internet provider's")}.get(
                u["kind"], u["kind"])
            out.append("    {:<26} {} ({})".format(T("lookups answered by"), u["address"], who))
    out.append("")
    out.append("  " + T("WORTH A LOOK ({n})", n=len(result["findings"])))
    for title, detail, why in result["findings"]:
        out += ["    - " + TX(title), "        " + TX(detail), "        " + TX(why)]
    if not result["findings"]:
        out.append("    " + T("Nothing stood out. That is not a guarantee: devices that were off or asleep were not "
                              "seen."))
    if result["gaps"]:
        out += ["", "  " + T("COULD NOT BE CHECKED")] + ["    - " + TX(g) for g in result["gaps"]]
    out += ["", "  " + T("Took {seconds} s. Devices that were off or asleep (phones often are) were not seen, nor "
                         "devices on another network: a guest network, or a Wi-Fi extender that makes its own network "
                         "instead of extending this one. Run it again from a computer connected to that network to "
                         "see them.", seconds=result["seconds"])]
    return "\n".join(st_wrap_lines(out))


HN_CONSENT = """
HOME NETWORK CHECK - please read
  This is separate from the spyware check. It will contact the devices on the local network this
  computer is on ({subnet}): a few packets to each address, a short connection attempt to some
  common ports on each device it finds, and the router's own UPnP information.
  It also asks the router to look up {names} test names ({examples} and a made-up name), to see
  whether lookups are being changed. The router passes these on to the internet - the only part
  of this check that leaves your network. Add --no-router-lookups to skip it.
  Cameras with their video port open are asked, without any password, whether they show their
  video to anyone: only the stream description is read, never the video (--no-camera-check skips it).
  It does not log into anything, try any password or change anything.
  Only run it on a network you own or are responsible for (your home, or with permission).
"""


def homenet_command(args, out=print):
    """--home-network for both entry points. Returns the exit code."""
    import json
    try:
        _local, subnet, _gateway, note = hn_target()
    except (OSError, HomeNetError) as exc:
        out(T("Home network check not started: {why}", why=TX(str(exc))))
        return 1
    lookups = not getattr(args, "no_router_lookups", False)
    consent = HN_CONSENT
    if not lookups:
        start = consent.index("  It also asks the router")
        end = consent.index("skip it.") + len("skip it.") + 1
        consent = consent[:start] + "  It contacts nothing outside this local network.\n" + consent[end:]
    out(T(consent, subnet=subnet, names=len(HN_FIXED_NAMES) + 1 + len(HN_WHOAMI),
          examples=", ".join(n for n, _ in HN_FIXED_NAMES + HN_WHOAMI)))
    if not getattr(args, "yes_my_network", False):
        if not sys.stdin.isatty():
            out(T("Not started: confirm in an interactive terminal, or add --yes-my-network."))
            return 1
        try:
            answer = input("  " + T("Type YES to check this network: "))
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer.strip().upper() != "YES":
            out(T("Not started. Nothing was contacted."))
            return 1
    try:
        result = hn_check(emit=lambda m: print(m, file=sys.stderr), router_lookups=lookups,
                          camera_check=not getattr(args, "no_camera_check", False))
    except (OSError, HomeNetError) as exc:
        out(T("Home network check stopped: {why}", why=TX(str(exc))))
        return 1
    out(hn_render(result))
    path = getattr(args, "json", None)
    if path:
        from .localpaths import path_problem
        problem = path_problem(os.path.abspath(path))
        if problem:
            out("[" + T("could not write JSON: {why}", why=TX(problem)) + "]")
            return 1
        if os.path.exists(path):
            out("[" + T("not written: {path} already exists - choose a new name", path=path) + "]")
            return 1
        with open(path, "x", encoding="utf-8") as fh:
            json.dump(dict(result, tool="zero-breach-toolkit home-network check",
                           timestamp=__import__("datetime").datetime.now().astimezone().replace(microsecond=0).isoformat()),
                      fh, indent=2, ensure_ascii=False)
        out("[" + T("wrote JSON report to {path}", path=path) + "]")
    return 0
