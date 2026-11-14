"""Who this computer trusts on the network: root certificates, proxy, DNS servers, gateway.

All four are local reads of the computer's own settings. Nothing is contacted, no
name is resolved and nothing is changed. Every result is a lead ("worth a look")
with its ordinary explanation; none of them changes the verdict.

root-certificates  A root certificate lets whoever holds its key create a valid
                   certificate for ANY website, so traffic to it can be read
                   ("HTTPS interception"). Roots are compared with the ones the
                   major trust programs distribute (iocs/known_public_roots.txt,
                   from the CCADB). The rest are listed, named by kind: security
                   software, developer tools, VPNs, or unknown.
                   Windows: the LocalMachine and CurrentUser Root and AuthRoot
                   stores. macOS: certificates with admin or user trust settings
                   (`security dump-trust-settings`). Linux: locally added
                   anchors (/usr/local/share/ca-certificates, /etc/pki/ca-trust/
                   source/anchors, /etc/ca-certificates/trust-source/anchors).
proxy-settings     A system proxy or automatic proxy script routes web traffic
                   through another program or server.
dns-settings       DNS servers set by hand, and servers in ranges that malware
                   (DNSChanger) used to hijack whole homes.
gateway            The router's hardware address also claimed by another address
                   in the neighbour table: a sign of ARP spoofing on the network.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys

from ..result import Lead, ModuleResult

NAME = "trust-settings"

_TR_TIMEOUT = 60


# Kinds of non-public roots, recognised by words in the certificate's subject. A
# subject is attacker-controlled text, so a match only chooses the explanation;
# it never makes a root "known".
_TR_KINDS = (
    ("interception-tool", "a developer tool that reads encrypted web traffic",
     r"fiddler|do_not_trust|mitmproxy|charles proxy|portswigger|burp|http toolkit|proxyman|telerik"),
    ("known-bad", "a certificate known to have been abused to read web traffic",
     r"superfish|edellroot|komodia|privdog|dsdtestprovider"),
    ("security-software", "security software that checks encrypted web traffic",
     r"kaspersky|avast|\bavg\b|eset|bitdefender|norton|symantec web|dr\.?web|sophos|fortinet|zscaler|netskope|"
     r"cisco umbrella|f-secure|trend micro|mcafee|webroot|malwarebytes|adguard|surfshark|nordvpn|windscribe"),
    ("vpn", "a VPN or network app", r"\bvpn|wireguard|tunnel"),
    ("game", "a game launcher or game service",
     r"battle\.net|blizzard|\bsteam\b|epic games|\briot games\b|ubisoft|\bea app\b|garena|tencent|game ?center|wegame"),
)


def _tr_run(argv, timeout=_TR_TIMEOUT):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, creationflags=flags)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def trust_known_roots():
    """(sha1 set, sha256 set) of the roots the major trust programs distribute (trustdata.py)."""
    from ..trustdata import TRUST_SHA1, TRUST_SHA256
    if len(TRUST_SHA1) < 300 or len(TRUST_SHA256) < 300:
        raise ValueError("the list of known public roots is missing or damaged")
    return TRUST_SHA1, TRUST_SHA256


def trust_kind(subject, computer=""):
    low = (subject or "").lower()
    for kind, words, pattern in _TR_KINDS:
        if re.search(pattern, low):
            return kind, words
    if computer and re.search(r"\bcn=" + re.escape(computer.lower()) + r"\b", low):
        return "this-computer", "a certificate made on this computer, usually by development or remote-desktop tools"
    return "unknown", ""


_TR_REASON = {
    "interception-tool": ("Fine while you use that tool on purpose. If you don't, remove the certificate: anyone "
                          "with its key can read this computer's encrypted web traffic."),
    "known-bad": ("This certificate has been abused before to read people's web traffic. Remove it, and get help if "
                  "you did not install it."),
    "security-software": ("Antivirus and filtering apps install one to check encrypted pages. Fine if that app is "
                          "installed and you trust it; if you uninstalled it, remove the leftover certificate."),
    "vpn": "VPN apps sometimes install one. Fine if you use that app; remove it if you don't.",
    "game": ("Some game launchers install one for their local services. If you use that game it is probably "
             "expected; if you don't recognise it, remove it: it can be used to read encrypted web traffic."),
    "this-computer": "Usually harmless. If you don't develop software or use remote desktop, look into what made it.",
    "unknown": ("Often installed by a company or school, a game launcher, a VPN or security software. If you don't "
                "recognise it, someone may be able to read this computer's encrypted web traffic: get it checked."),
}


# Kinds with an ordinary explanation (the program that adds them): grouped into ONE calm item that still names
# every certificate. Interception tools, known-abused certificates and unexplained roots stay one item each.
_TR_EXPLAINED = ("security-software", "vpn", "game", "this-computer")


def trust_root_leads(r, roots, known_sha1, known_sha256, computer=""):
    """roots: dicts with sha1/sha256 (either may be empty), subject, where."""
    seen, unknown, explained = set(), 0, []
    for root in roots:
        sha1 = (root.get("sha1") or "").upper()
        sha256 = (root.get("sha256") or "").upper()
        key = sha1 or sha256 or root.get("subject")
        if key in seen:
            continue
        seen.add(key)
        if sha1 in known_sha1 or sha256 in known_sha256:
            continue
        unknown += 1
        kind, words = trust_kind(root.get("subject"), computer)
        subject = (root.get("subject") or "?")[:200]
        if kind in _TR_EXPLAINED:
            explained.append("{} ({})".format(_tr_short_subject(subject), words))
            continue
        what = ("A root certificate that no major browser or operating system distributes is trusted here"
                + (" ({})".format(words) if words else "") + ": " + subject)
        r.add_lead(Lead("root-certificates", root.get("where", "") + " " + (sha1 or sha256)[:16], what,
                        _TR_REASON[kind], root.get("observed", "")))
    if explained:
        r.add_lead(Lead("root-certificates", "{} certificate(s) added by programs".format(len(explained)),
                        "Extra root certificates added by programs that usually add one: " + "; ".join(explained),
                        "Antivirus, VPN, game and developer tools add these for their own features. Fine if you use "
                        "those programs. If you don't recognise one, or uninstalled the program, remove the "
                        "certificate: whoever holds its key can read this computer's encrypted web traffic."))
    return len(seen), unknown


def _tr_short_subject(subject):
    """'CN=Kaspersky Anti-Virus Personal Root Certificate, O=AO Kaspersky Lab' -> the CN, else the start."""
    m = re.search(r"\bCN=([^,]+)", subject or "")
    return (m.group(1) if m else subject or "?").strip()[:80]


def _tr_windows_roots():
    from .host import _ps_json
    rows, err = _ps_json(
        "$s = 'Cert:\\LocalMachine\\Root','Cert:\\LocalMachine\\AuthRoot','Cert:\\CurrentUser\\Root';"
        " Get-ChildItem $s -ErrorAction Stop | Select-Object Thumbprint,Subject,NotBefore,"
        "@{n='Store';e={$_.PSParentPath -replace '^.*::',''}} | ConvertTo-Json -Depth 2 -Compress", timeout=90)
    if err:
        raise ValueError("the certificate stores could not be read: " + err)
    local = {str(row.get("Thumbprint", "")).upper() for row in rows
             if str(row.get("Store", "")).lower().startswith("localmachine")}
    roots = []
    for row in rows:
        thumb = str(row.get("Thumbprint", "")).upper()
        store = str(row.get("Store", ""))
        if store.lower().startswith("currentuser") and thumb in local:
            continue  # the user's view also shows the machine's roots
        roots.append({"sha1": thumb, "sha256": "", "subject": str(row.get("Subject", "")),
                      "where": store.replace("\\", " "), "observed": str(row.get("NotBefore", ""))[:40]})
    return roots


def trust_parse_mac_trust_settings(text):
    """Names of certificates in `security dump-trust-settings` output."""
    return [m.group(1).strip() for m in re.finditer(r"^Cert \d+: (.+)$", text, re.M)]


def _tr_mac_roots():
    roots = []
    for flag, where in (("-d", "admin trust settings"), (None, "user trust settings")):
        argv = ["security", "dump-trust-settings"] + ([flag] if flag else [])
        rc, out, err = _tr_run(argv)
        if rc != 0 and "No Trust Settings were found" not in (out + err):
            raise ValueError("macOS trust settings could not be read ({})".format(where))
        for name in trust_parse_mac_trust_settings(out):
            roots.append({"sha1": "", "sha256": "", "subject": "CN=" + name, "where": where})
    return roots


_TR_LINUX_ANCHORS = ("/usr/local/share/ca-certificates", "/etc/pki/ca-trust/source/anchors",
                     "/etc/ca-certificates/trust-source/anchors")


def _tr_linux_roots():
    roots = []
    for folder in _TR_LINUX_ANCHORS:
        if not os.path.isdir(folder):
            continue
        for dirpath, _dirs, files in os.walk(folder):
            for name in sorted(files):
                path = os.path.join(dirpath, name)
                roots.append({"sha1": "", "sha256": "", "subject": "file " + os.path.relpath(path, folder),
                              "where": folder})
    return roots


def _check_roots(r, ctx):
    try:
        known_sha1, known_sha256 = trust_known_roots()
        if sys.platform == "win32":
            roots = _tr_windows_roots()
        elif sys.platform == "darwin":
            roots = _tr_mac_roots()
        else:
            roots = _tr_linux_roots()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        r.could_not_run("root-certificates", str(exc)[:200])
        return
    computer = os.environ.get("COMPUTERNAME", "") if sys.platform == "win32" else ""
    if sys.platform == "win32":
        total, unknown = trust_root_leads(r, roots, known_sha1, known_sha256, computer)
        r.note("Root certificates: {} trusted, {} not distributed by any major trust program.".format(total, unknown))
    else:
        # On macOS and Linux only roots ADDED to the system are listed, so each one is a lead.
        for root in roots:
            kind, words = trust_kind(root["subject"])
            r.add_lead(Lead("root-certificates", root["where"],
                            "A root certificate was added to this computer's trusted list"
                            + (" ({})".format(words) if words else "") + ": " + root["subject"][:200],
                            _TR_REASON[kind]))
        r.note("Root certificates added locally: {}.".format(len(roots)))
    r.submetrics["root_certificates_unrecognised"] = len(r.leads)
    r.ran("root-certificates")


# --- proxy -------------------------------------------------------------------

def _tr_windows_proxy():
    import winreg  # type: ignore
    found = []
    path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
            def value(name):
                try:
                    return winreg.QueryValueEx(key, name)[0]
                except OSError:
                    return None
            if value("ProxyEnable") == 1 and value("ProxyServer"):
                found.append(("system proxy", str(value("ProxyServer"))[:200]))
            if value("AutoConfigURL"):
                found.append(("automatic proxy script", str(value("AutoConfigURL"))[:200]))
    except OSError:
        pass
    return found


def trust_parse_scutil_proxy(text):
    values = dict(re.findall(r"^\s*(\w+)\s*:\s*(.+?)\s*$", text, re.M))
    found = []
    for proto in ("HTTP", "HTTPS", "SOCKS"):
        if values.get(proto + "Enable") == "1" and values.get(proto + "Proxy"):
            found.append(("{} proxy".format(proto), "{}:{}".format(values[proto + "Proxy"], values.get(proto + "Port", "?"))))
    if values.get("ProxyAutoConfigEnable") == "1" and values.get("ProxyAutoConfigURLString"):
        found.append(("automatic proxy script", values["ProxyAutoConfigURLString"][:200]))
    return found


def _tr_posix_proxy():
    found = []
    if sys.platform == "darwin":
        rc, out, _err = _tr_run(["scutil", "--proxy"])
        if rc != 0:
            raise ValueError("macOS proxy settings could not be read")
        found += trust_parse_scutil_proxy(out)
    for name in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
        if os.environ.get(name):
            found.append(("environment " + name, os.environ[name][:200]))
    return found


def _check_proxy(r, ctx):
    try:
        found = _tr_windows_proxy() if sys.platform == "win32" else _tr_posix_proxy()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        r.could_not_run("proxy-settings", str(exc)[:200])
        return
    for label, value in found:
        local = re.match(r"^(https?://)?(127\.|localhost|\[?::1\]?)", value.strip().lower())
        r.add_lead(Lead("proxy-settings", label,
                        "Web traffic is sent through a {} ({}){}.".format(
                            label, value, ", a program on this computer" if local else ""),
                        "Common with company networks, some VPNs, ad blockers and security software. If you didn't "
                        "set it up, find out what did: a proxy can see and change your web traffic."))
    if not found:
        r.note("No system proxy or automatic proxy script was found in the settings read ({}).".format(
            "this user's Internet settings; the machine-wide WinHTTP proxy and policies were not read"
            if sys.platform == "win32" else
            "the system network settings" if sys.platform == "darwin" else
            "this program's environment; desktop (GNOME/KDE) proxy settings were not read"))
    r.ran("proxy-settings")


# --- DNS servers ----------------------------------------------------------------

# Ranges used by the DNSChanger malware to hijack DNS (FBI / DCWG notice, 2011-2012).
_TR_DNSCHANGER = ("85.255.112.0/20", "67.210.0.0/20", "93.188.160.0/21", "77.67.83.0/24",
                  "213.109.64.0/20", "64.28.176.0/20")
# Well-known public resolvers, named in the report so a person recognises them.
_TR_PUBLIC_DNS = {
    "Google": ("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844"),
    "Cloudflare": ("1.1.1.1", "1.0.0.1", "1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3",
                   "2606:4700:4700::1111", "2606:4700:4700::1001"),
    "Quad9": ("9.9.9.9", "149.112.112.112", "9.9.9.11", "149.112.112.11", "2620:fe::fe", "2620:fe::9"),
    "OpenDNS": ("208.67.222.222", "208.67.220.220", "208.67.222.123", "208.67.220.123"),
    "AdGuard": ("94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16"),
    "Mullvad": ("194.242.2.2", "194.242.2.3", "194.242.2.4"),
    "Control D": ("76.76.2.0", "76.76.10.0"),
    "CleanBrowsing": ("185.228.168.9", "185.228.169.9"),
}


# Public DNS services that refuse to look up known harmful (and, for some, advertising) domains. Plain resolvers
# such as 1.1.1.1 or 8.8.8.8 are not on it: they answer for every domain.
_TR_PROTECTIVE_DNS = {
    "Quad9": ("9.9.9.9", "149.112.112.112", "9.9.9.11", "149.112.112.11", "2620:fe::fe", "2620:fe::9"),
    "Cloudflare for Families": ("1.1.1.2", "1.0.0.2", "1.1.1.3", "1.0.0.3"),
    "AdGuard DNS": ("94.140.14.14", "94.140.15.15", "94.140.14.15", "94.140.15.16"),
    "Mullvad DNS": ("194.242.2.3", "194.242.2.4"),
    "CleanBrowsing": ("185.228.168.9", "185.228.169.9"),
    "OpenDNS FamilyShield": ("208.67.222.123", "208.67.220.123"),
}
_TR_PROTECTIVE_NETS = (("NextDNS", "45.90.28.0/24"), ("NextDNS", "45.90.30.0/24"))


def trust_dns_protection(servers):
    """("protected", service) when a configured server blocks harmful domains, ("local", "") when only the router
    or a program on this computer answers (what it does is not known), ("none", "") otherwise."""
    local = False
    for _where, address, _manual in servers:
        try:
            ip = ipaddress.ip_address(address.split("%")[0])
        except ValueError:
            continue
        for owner, values in _TR_PROTECTIVE_DNS.items():
            if str(ip) in values:
                return "protected", owner
        for owner, net in _TR_PROTECTIVE_NETS:
            if ip.version == 4 and ip in ipaddress.ip_network(net):
                return "protected", owner
        if ip.is_loopback or ip.is_private or ip.is_link_local:
            local = True
    return ("local", "") if local else ("none", "")


def trust_dns_door(r, servers):
    from ..result import DOOR_CLOSED, DOOR_OPEN, DOOR_UNKNOWN, Door
    state, owner = trust_dns_protection(servers)
    fix = ("Set your DNS to Quad9 (9.9.9.9 and 149.112.112.112) - free, run by a non-profit - in your network "
           "settings, or on your router so every device gets it. The page https://archivegenocide.com/scan has a "
           "test and steps.")
    setting = "ms-settings:network" if sys.platform == "win32" else ""
    if state == "protected":
        r.add_door(Door("network:protective-dns", DOOR_CLOSED,
                        "This computer uses a DNS service that blocks known harmful sites ({})".format(owner)))
    elif state == "local":
        r.add_door(Door("network:protective-dns", DOOR_UNKNOWN,
                        "Your router (or a program here) chooses the DNS service, so it is not known whether it "
                        "blocks harmful sites", "", fix, setting, "low"))
    elif servers:
        r.add_door(Door("network:protective-dns", DOOR_OPEN,
                        "This computer does not use a DNS service that blocks known harmful sites",
                        "Spyware has been delivered through ad networks and fake sites. A protective DNS service "
                        "quietly refuses to look up known bad addresses, for every app on the computer.",
                        fix, setting, "low"))


def trust_dns_label(address):
    try:
        ip = ipaddress.ip_address(address.split("%")[0])
    except ValueError:
        return "invalid", None
    for net in _TR_DNSCHANGER:
        if ip in ipaddress.ip_network(net):
            return "dnschanger", None
    for owner, values in _TR_PUBLIC_DNS.items():
        if str(ip) in values:
            return "public", owner
    if ip.is_loopback:
        return "local", "a program on this computer"
    if ip.is_private or ip.is_link_local:
        return "local", "local network, usually the router"
    return "other", None


def _tr_windows_dns():
    """[(interface, address, set_by_hand)] from the TCP/IP settings in the registry."""
    import winreg  # type: ignore
    out = []
    for family, path in (("IPv4", r"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"),
                         ("IPv6", r"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters\Interfaces")):
        try:
            root = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        except OSError:
            continue
        with root:
            for i in range(1024):
                try:
                    guid = winreg.EnumKey(root, i)
                except OSError:
                    break
                try:
                    with winreg.OpenKey(root, guid) as key:
                        for name, manual in (("NameServer", True), ("DhcpNameServer", False)):
                            try:
                                value = str(winreg.QueryValueEx(key, name)[0])
                            except OSError:
                                continue
                            for address in re.split(r"[ ,;]+", value.strip()):
                                if address:
                                    out.append(("{} {}".format(family, guid), address, manual))
                except OSError:
                    continue
    return out


def _tr_posix_dns():
    out = []
    try:
        with open("/etc/resolv.conf", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                m = re.match(r"\s*nameserver\s+(\S+)", line)
                if m:
                    out.append(("/etc/resolv.conf", m.group(1), None))
    except OSError as exc:
        raise ValueError("/etc/resolv.conf could not be read: {}".format(exc))
    # With systemd-resolved, resolv.conf only names the local stub (127.0.0.53); the servers it really
    # forwards to are in its own file - read them too, or a hijacked upstream would go unseen.
    if out and all(addr.startswith("127.0.0.53") for _src, addr, _m in out):
        try:
            with open("/run/systemd/resolve/resolv.conf", encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    m = re.match(r"\s*nameserver\s+(\S+)", line)
                    if m:
                        out.append(("/run/systemd/resolve/resolv.conf", m.group(1), None))
        except OSError:
            pass
    return out


def _check_dns(r, ctx):
    try:
        servers = _tr_windows_dns() if sys.platform == "win32" else _tr_posix_dns()
    except (OSError, ValueError) as exc:
        r.could_not_run("dns-settings", str(exc)[:200])
        return
    described = []
    for where, address, manual in servers:
        kind, owner = trust_dns_label(address)
        if kind == "dnschanger":
            r.add_lead(Lead("dns-settings", where,
                            "This computer uses the DNS server {}, in a range the DNSChanger malware used to "
                            "hijack people's internet traffic.".format(address),
                            "Those servers were shut down years ago, so this is most likely a leftover - but it "
                            "should be removed and the computer and router checked.", ""))
        elif kind == "other" and manual:
            r.add_lead(Lead("dns-settings", where,
                            "This computer's DNS server was set by hand to {}, which is not a well-known public "
                            "DNS service.".format(address),
                            "Often an internet provider's or company's server, or a filtering service. If you "
                            "didn't set it, find out who did: the DNS server sees every site you look up and can "
                            "send you to fake ones.", ""))
        described.append("{} ({}{})".format(address, owner or kind, ", set by hand" if manual else ""))
    trust_dns_door(r, servers)
    if described:
        r.note("DNS servers: " + "; ".join(sorted(set(described))[:12]) + ".")
    else:
        r.note("No DNS servers are configured on this computer's network connections.")
    r.ran("dns-settings")


# --- gateway / neighbour table ----------------------------------------------------

def trust_gateway_conflicts(gateway, neighbours):
    """Addresses other than the gateway that answer with the gateway's hardware address."""
    macs = {ip: mac for ip, mac in neighbours}
    gmac = macs.get(gateway)
    if not gmac or gmac in ("00-00-00-00-00-00", "ff-ff-ff-ff-ff-ff", "00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"):
        return gmac, []
    return gmac, sorted(ip for ip, mac in neighbours if mac == gmac and ip != gateway
                        and not ipaddress.ip_address(ip).is_multicast)


def _tr_windows_neighbours():
    from .host import _ps_json
    routes, err = _ps_json("Get-NetRoute -DestinationPrefix 0.0.0.0/0 -ErrorAction Stop | "
                           "Select-Object NextHop,RouteMetric | ConvertTo-Json -Compress")
    if err:
        raise ValueError("the default route could not be read: " + err)
    hops = sorted((r for r in routes if r.get("NextHop") not in (None, "", "0.0.0.0")),
                  key=lambda r: r.get("RouteMetric") or 0)
    rows, err = _ps_json("Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop | "
                         "Where-Object { $_.State -ne 'Unreachable' -and $_.LinkLayerAddress } | "
                         "Select-Object IPAddress,LinkLayerAddress | ConvertTo-Json -Compress")
    if err:
        raise ValueError("the neighbour table could not be read: " + err)
    neighbours = [(str(r.get("IPAddress")), str(r.get("LinkLayerAddress")).lower()) for r in rows]
    return (hops[0]["NextHop"] if hops else None), neighbours


def _tr_linux_neighbours():
    gateway = None
    with open("/proc/net/route", encoding="ascii") as fh:
        for line in fh.readlines()[1:]:
            parts = line.split()
            # a real default route: destination 0, mask 0 and a gateway address (not 'default dev wg0')
            if len(parts) > 7 and parts[1] == "00000000" and parts[7] == "00000000" and parts[2] != "00000000":
                gateway = str(ipaddress.IPv4Address(bytes.fromhex(parts[2])[::-1]))
                break
    neighbours = []
    with open("/proc/net/arp", encoding="ascii") as fh:
        for line in fh.readlines()[1:]:
            parts = line.split()
            if len(parts) >= 4 and parts[2] != "0x0":
                neighbours.append((parts[0], parts[3].lower()))
    return gateway, neighbours


def _check_gateway(r, ctx):
    try:
        if sys.platform == "win32":
            gateway, neighbours = _tr_windows_neighbours()
        elif sys.platform.startswith("linux"):
            gateway, neighbours = _tr_linux_neighbours()
        else:
            # A platform limitation (documented in COVERAGE.md), not a per-scan gap: a gap here would mark every
            # Mac scan as incomplete for a check that does not exist on macOS yet.
            r.note("gateway: not checked on macOS yet.")
            return
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        r.could_not_run("gateway", str(exc)[:200])
        return
    if not gateway:
        r.note("No default gateway: this computer is not on a routed network right now.")
        r.ran("gateway")
        return
    mac, others = trust_gateway_conflicts(gateway, neighbours)
    if others:
        r.add_lead(Lead("gateway", "router " + gateway,
                        "Another address on this network ({}) uses the router's hardware address ({}).".format(
                            ", ".join(others[:5]), mac),
                        ("Several addresses sharing one hardware address is what a Wi-Fi extender (repeater) does when "
                         "this computer is connected through it: it relays the router and everything else under its "
                         "own address. " if len(others) >= 2 else "") +
                        "Some routers and mesh systems answer on two addresses, which is harmless. It is also how "
                        "a device on the network pretends to be the router to watch traffic (ARP spoofing): if you "
                        "don't recognise the other address and use no extender or mesh, restart the router and check "
                        "again.", ""))
    r.note("Router {} ({}); {} neighbours known.".format(gateway, mac or "hardware address not known yet", len(neighbours)))
    r.ran("gateway")


def run(ctx) -> ModuleResult:
    r = ModuleResult(NAME)
    ctx.partial = r
    r.note("Network trust settings: read only; nothing is contacted or changed.")
    for check_name, check in (("root-certificates", _check_roots), ("proxy-settings", _check_proxy),
                              ("dns-settings", _check_dns), ("gateway", _check_gateway)):
        try:
            check(r, ctx)
        except Exception as exc:  # noqa: BLE001 - one check failing must not hide the others
            r.could_not_run(check_name, "module error: {}".format(str(exc)[:160]))
    return r
