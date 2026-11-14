"""What a live connection is, in plain words: the program behind it, what the address and port usually are, and
which big company runs the address - from the companies' own published lists, built in, so nothing is looked up.
One optional online step, only when the person asks: the internet registry's record of who owns the address (RDAP).
"""
import base64
import datetime
import ipaddress
import json
import lzma
import os
import subprocess
import sys
import urllib.request

_NC_RANGES = None

# What a port usually carries (the remote side's port). Plain words; "usually" because any port can carry anything.
NC_PORTS = {
    20: "file transfer (FTP data)", 21: "file transfer (FTP)", 22: "remote login (SSH)", 23: "remote login (Telnet)",
    25: "sending email (SMTP)", 53: "looking up website names (DNS)", 80: "web page (not encrypted)",
    110: "receiving email (POP3)", 123: "setting the clock (NTP)", 143: "receiving email (IMAP)",
    443: "secure web page or app traffic (HTTPS)", 465: "sending email (encrypted)", 587: "sending email",
    853: "private name lookups (DNS over TLS)", 993: "receiving email (encrypted IMAP)",
    995: "receiving email (encrypted POP3)", 1194: "VPN (OpenVPN)", 1723: "VPN (PPTP)",
    3389: "remote desktop (Windows)", 3478: "voice and video calls (STUN/TURN)", 4500: "VPN (IPsec)",
    5222: "chat (XMPP) - also used by WhatsApp", 5223: "Apple notifications", 5228: "Google notifications",
    5938: "remote access (TeamViewer)", 6568: "remote access (AnyDesk)", 7680: "Windows update sharing",
    8080: "web (alternative port)", 8443: "secure web (alternative port)", 51820: "VPN (WireGuard)",
}


# What a connection's state means, in plain words.
NCI_STATES = {
    "ESTABLISHED": "open and in use right now",
    "TIME_WAIT": "this connection has just been closed",
    "CLOSE_WAIT": "the other side has closed it; this program has not yet",
    "SYN_SENT": "this computer is trying to connect",
    "SYN_RECEIVED": "someone is connecting to this computer",
    "LISTEN": "waiting for connections from others",
    "FIN_WAIT_1": "being closed", "FIN_WAIT_2": "being closed", "LAST_ACK": "being closed", "CLOSING": "being closed",
}


# Well-known addresses the companies' published lists leave out (team test F7): the public DNS resolvers, and
# Fastly, which carries the traffic of many large websites. Added only where the built-in lists say nothing.
NC_EXTRA = (
    ("1.1.1.0/24", "Cloudflare"), ("1.0.0.0/24", "Cloudflare"), ("2606:4700:4700::/48", "Cloudflare"),
    ("9.9.9.0/24", "Quad9 - a public DNS service"), ("149.112.112.0/24", "Quad9 - a public DNS service"),
    ("2620:fe::/48", "Quad9 - a public DNS service"),
    ("151.101.0.0/16", "Fastly - it carries the traffic of many websites and apps"),
    ("199.232.0.0/16", "Fastly - it carries the traffic of many websites and apps"),
    ("146.75.0.0/16", "Fastly - it carries the traffic of many websites and apps"),
    ("23.235.32.0/20", "Fastly - it carries the traffic of many websites and apps"),
    ("185.31.16.0/22", "Fastly - it carries the traffic of many websites and apps"),
    ("199.27.72.0/21", "Fastly - it carries the traffic of many websites and apps"),
    ("157.52.64.0/18", "Fastly - it carries the traffic of many websites and apps"),
    ("167.82.0.0/17", "Fastly - it carries the traffic of many websites and apps"),
    ("2a04:4e40::/32", "Fastly - it carries the traffic of many websites and apps"),
    ("2a04:4e42::/32", "Fastly - it carries the traffic of many websites and apps"),
)


def nc_owner(address: str) -> str:
    """The company that runs an internet address, from the built-in lists, or ""."""
    global _NC_RANGES
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return ""
    if _NC_RANGES is None:
        _NC_RANGES = {4: {}, 6: {}}
        try:
            from .iprangedata import IPR_BLOB, IPR_OWNERS
            text = lzma.decompress(base64.b85decode("".join(IPR_BLOB))).decode("ascii")
            for line in text.split("\n"):
                prefix, code = line.split("\t")
                net = ipaddress.ip_network(prefix)
                table = _NC_RANGES[net.version].setdefault(net.prefixlen, {})
                table.setdefault(int(net.network_address), IPR_OWNERS[int(code)])   # the first (most specific) wins
        except (ImportError, ValueError, lzma.LZMAError):
            pass
        cloudflare = next((o for t in _NC_RANGES.values() for lv in t.values() for o in lv.values()
                           if o.startswith("Cloudflare")), "Cloudflare")
        for prefix, owner in NC_EXTRA:
            net = ipaddress.ip_network(prefix)
            table = _NC_RANGES[net.version].setdefault(net.prefixlen, {})
            table.setdefault(int(net.network_address), cloudflare if owner == "Cloudflare" else owner)
    bits = 32 if ip.version == 4 else 128
    value = int(ip)
    for length in sorted(_NC_RANGES[ip.version], reverse=True):
        key = value >> (bits - length) << (bits - length)
        owner = _NC_RANGES[ip.version][length].get(key)
        if owner:
            return owner
    return ""


# The big companies' own domains (a name ending in one of these is theirs). Short company names, as in the table.
NC_DOMAINS = {
    "Google": ("google.com", "googleapis.com", "gstatic.com", "gvt1.com", "gvt2.com", "youtube.com", "ytimg.com",
               "googlevideo.com", "doubleclick.net", "googlesyndication.com", "googleusercontent.com", "android.com",
               "gmail.com", "app-measurement.com", "firebaseio.com", "crashlytics.com", "googleadservices.com",
               "google-analytics.com", "googletagmanager.com"),
    "Meta": ("facebook.com", "fbcdn.net", "facebook.net", "instagram.com", "cdninstagram.com", "whatsapp.net",
             "whatsapp.com", "messenger.com", "meta.com", "fbsbx.com"),
    "Apple": ("apple.com", "icloud.com", "mzstatic.com", "apple-cloudkit.com", "cdn-apple.com", "aaplimg.com",
              "icloud-content.com", "apple-dns.net"),
    "Microsoft": ("microsoft.com", "windows.com", "msn.com", "live.com", "office.com", "office.net", "outlook.com",
                  "skype.com", "bing.com", "azure.com", "msedge.net", "windowsupdate.com", "xboxlive.com",
                  "microsoftonline.com", "sharepoint.com", "onedrive.com", "azureedge.net", "trafficmanager.net"),
    "Amazon": ("amazon.com", "amazonaws.com", "cloudfront.net", "media-amazon.com", "ssl-images-amazon.com",
               "amazon-adsystem.com"),
    "Cloudflare": ("cloudflare.com", "cloudflare-dns.com", "workers.dev", "cloudflareinsights.com"),
    "Telegram": ("telegram.org", "t.me", "telegra.ph", "tdesktop.com", "telegram.me"),
    "Akamai": ("akamai.net", "akamaiedge.net", "akamaihd.net", "akamaized.net", "edgekey.net", "edgesuite.net"),
    "Signal": ("signal.org", "whispersystems.org", "signal.group"),
    "ByteDance (TikTok)": ("tiktok.com", "tiktokv.com", "tiktokcdn.com", "byteoversea.com", "ibytedtos.com",
                           "ttwstatic.com", "tiktokcdn-us.com"),
    "X (Twitter)": ("twitter.com", "x.com", "twimg.com", "t.co"),
}
_NC_SUFFIX = {suffix: owner for owner, suffixes in NC_DOMAINS.items() for suffix in suffixes}


def nc_name_owner(name: str) -> str:
    """The company behind a website name or an address, or ""."""
    name = (name or "").strip().lower().rstrip(".")
    if not name:
        return ""
    try:
        import ipaddress as _ip
        _ip.ip_address(name.split("%", 1)[0])
        return nc_who(name) if nc_kind(name) == "the internet" else ""
    except ValueError:
        pass
    parts = name.split(".")
    for i in range(len(parts) - 1):
        owner = _NC_SUFFIX.get(".".join(parts[i:]))
        if owner:
            return owner
    return ""


def nc_owner_summary(names, top: int = 5) -> str:
    """"Google (12), Meta (4), Telegram (2), others (5)" for a list of names or addresses."""
    counts = {}
    for name in names:
        owner = nc_name_owner(name) or "others"
        counts[owner] = counts.get(owner, 0) + 1
    others = counts.pop("others", 0)
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    parts = ["{} ({})".format(o, n) for o, n in ranked[:top]]
    rest = others + sum(n for _o, n in ranked[top:])
    if rest:
        parts.append("others ({})".format(rest))
    return ", ".join(parts)


def nc_kind(address: str) -> str:
    """Where an address is, in plain words."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return "an address that could not be read"
    if ip.is_loopback:
        return "this computer itself (a program talking to another program here)"
    if ip.is_multicast:
        return "a local broadcast - devices on your network announcing themselves"
    if ip.is_link_local:
        return "a device directly on your network (automatic address)"
    if ip.is_private:
        return "your own network - your router or another device at home or at work"
    if ip.is_unspecified:
        return "no address yet (the connection is being set up)"
    return "the internet"


def nc_who(address: str) -> str:
    """One short word or two for the table's "Who runs it" column."""
    owner = nc_owner(address)
    if owner:
        return owner.split(" - ")[0].split(" (")[0]
    kind = nc_kind(address)
    if kind.startswith("this computer"):
        return "this computer"
    if kind.startswith("your own network") or kind.startswith("a device directly"):
        return "your network"
    if kind.startswith("a local broadcast"):
        return "local broadcast"
    return ""


def nc_process(pid):
    """{"path", "started", "parent"} for a running program, as far as this system shows it (any may be "")."""
    out = {"path": "", "started": "", "parent": ""}
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return out
    if pid <= 0:
        return out
    try:
        if sys.platform == "win32":
            out.update(_nc_win_process(pid))
        elif os.path.isdir("/proc/{}".format(pid)):
            out["path"] = os.path.realpath("/proc/{}/exe".format(pid))
            stat = open("/proc/{}/stat".format(pid)).read().rsplit(")", 1)[1].split()
            ppid = int(stat[1])
            ticks = os.sysconf("SC_CLK_TCK")
            boot = float(open("/proc/uptime").read().split()[0])
            started = datetime.datetime.now() - datetime.timedelta(seconds=boot - int(stat[19]) / ticks)
            out["started"] = started.strftime("%Y-%m-%d %H:%M")
            out["parent"] = open("/proc/{}/comm".format(ppid)).read().strip()
        else:
            p = subprocess.run(["ps", "-o", "ppid=,lstart=,comm=", "-p", str(pid)], capture_output=True, text=True,
                               timeout=10)
            parts = p.stdout.split()
            if len(parts) >= 7:
                out["started"] = " ".join(parts[1:6])
                out["path"] = " ".join(parts[6:])
                q = subprocess.run(["ps", "-o", "comm=", "-p", parts[0]], capture_output=True, text=True, timeout=10)
                out["parent"] = os.path.basename(q.stdout.strip())
    except (OSError, ValueError, IndexError, subprocess.SubprocessError):
        pass
    return out


def _nc_win_process(pid):
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.windll.kernel32
    out = {}
    handle = k32.OpenProcess(0x1000, False, pid)              # PROCESS_QUERY_LIMITED_INFORMATION
    if handle:
        try:
            buf = ctypes.create_unicode_buffer(1024)
            size = wintypes.DWORD(1024)
            if k32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                out["path"] = buf.value
            times = [wintypes.FILETIME() for _ in range(4)]
            if k32.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
                ft = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
                started = datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=ft // 10)
                out["started"] = (started.replace(tzinfo=datetime.timezone.utc).astimezone()
                                  .strftime("%Y-%m-%d %H:%M"))
        finally:
            k32.CloseHandle(handle)

    class ENTRY(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD), ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD), ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_wchar * 260)]
    snap = k32.CreateToolhelp32Snapshot(0x2, 0)
    if snap and snap != -1:
        try:
            names, parent = {}, None
            entry = ENTRY()
            entry.dwSize = ctypes.sizeof(ENTRY)
            ok = k32.Process32FirstW(snap, ctypes.byref(entry))
            while ok:
                names[entry.th32ProcessID] = entry.szExeFile
                if entry.th32ProcessID == pid:
                    parent = entry.th32ParentProcessID
                ok = k32.Process32NextW(snap, ctypes.byref(entry))
            if parent is not None:
                out["parent"] = names.get(parent, "")
        finally:
            k32.CloseHandle(snap)
    return out


def nc_details(row):
    """[(label, text)] about one connection, all from this computer and the built-in lists."""
    from .hashlook import hl_pe
    remote, port = row.get("remote", ""), row.get("remote_port")
    proc = nc_process(row.get("pid"))
    path = proc.get("path") or row.get("program") or ""
    out = []
    if path:
        out.append(("Program", path))
    elif row.get("pid"):
        out.append(("Program", "hidden by the system (process {}). Windows shows another account's or a system "
                               "service's programs only to administrators: open Zero Breach with \"Run as "
                               "administrator\" to see it.".format(row.get("pid"))))
    if path and os.path.isfile(path) and sys.platform == "win32":
        try:
            from .winsign import ws_status
            status = ws_status(path)
            with open(path, "rb") as fh:
                signer = hl_pe(fh.read(64 * 1024 * 1024)).get("signer", "")
            out.append(("Signed", {"signed": "yes" + (", by " + signer if signer else ""),
                                   "not-signed": "no - not signed"}.get(status, status)))
        except (OSError, ImportError):
            pass
    if proc.get("started"):
        out.append(("Running since", proc["started"]))
    if proc.get("parent"):
        out.append(("Started by", proc["parent"]))
    out.append(("Address", "{} - {}".format(remote, nc_kind(remote))))
    owner = nc_owner(remote)
    if owner:
        out.append(("Run by", owner + " (from the company's own published address list)"))
    elif nc_kind(remote) == "the internet":
        out.append(("Run by", "not one of the big companies on the built-in lists - \"Look up who owns this "
                              "address\" asks the internet registry"))
    if port:
        meaning = NC_PORTS.get(int(port))
        out.append(("Port", "{} - {}".format(port, meaning or "no common use; programs pick ports freely")))
    if row.get("state"):
        plain = NCI_STATES.get(str(row["state"]).upper().replace(" ", "_"), "")
        out.append(("State", row["state"] + (" - " + plain if plain else "")))
    if (row.get("count") or 1) > 1:
        out.append(("Connections", "{} to this address and port".format(row["count"])))
    return out


def nc_rdap(address: str, timeout: int = 20) -> str:
    """Who owns an address, from the internet registry (RDAP) - an online step the caller asks about first. Only
    the address is sent. The organisation's name, or "" when the registry does not say."""
    req = urllib.request.Request("https://rdap.org/ip/" + address.split("%", 1)[0],
                                 headers={"Accept": "application/rdap+json", "User-Agent": "Mozilla/5.0"})
    data = json.loads(urllib.request.urlopen(req, timeout=timeout).read(2 * 1024 * 1024))
    names = []
    for entity in data.get("entities") or []:
        for item in (entity.get("vcardArray") or [None, []])[1]:
            if item and item[0] == "fn" and len(item) > 3 and item[3]:
                names.append(str(item[3]))
    name = names[0] if names else str(data.get("name") or "")
    country = data.get("country") or ""
    return (name + (" ({})".format(country) if country else "")).strip()[:160]
