"""Wi-Fi networks nearby, and what a hidden one probably is.

A hidden network sends no name, so its name cannot be read without connecting to it or forcing devices off it -
neither of which this tool does. What it can say, from the radio announcements every network sends anyway:
  - who made the device, from the first half of its hardware address (the IEEE's public list, built in);
  - whether it is probably part of the router this computer is connected to - mesh systems and internet providers'
    routers run hidden networks to link their own units or TV boxes, by far the most common answer;
  - whether it uses a made-up (private) address, as phones and laptops sharing their connection do;
  - roughly how close it is, from the signal strength; and how it is secured.

Only what this computer already hears is read: no scan is forced, nothing is sent, nothing is joined.
  Windows  `netsh wlan show networks mode=bssid` (Windows 11 asks for location permission first)
  Linux    `nmcli device wifi list`
  macOS    `system_profiler SPAirPortDataType` (macOS hides hardware addresses, so less can be said)
"""
import base64
import json
import lzma
import re
import shutil
import subprocess
import sys

from .i18n import T
from .safetext import safe_render, st_line, st_wrap_lines

_WN_MAC = re.compile(r"(?i)\b([0-9a-f]{2}(?:[:-][0-9a-f]{2}){5})\b")
_WN_TIMEOUT = 30
_WN_VENDORS = None


def wn_vendor(mac: str) -> str:
    """The company a hardware address belongs to, from the built-in IEEE list, or ""."""
    global _WN_VENDORS
    if _WN_VENDORS is None:
        try:
            from .ouidata import OUI_BLOB
            text = lzma.decompress(base64.b85decode("".join(OUI_BLOB))).decode("utf-8")
            _WN_VENDORS = dict(line.split("\t", 1) for line in text.split("\n") if "\t" in line)
        except (ImportError, ValueError, lzma.LZMAError):
            _WN_VENDORS = {}
    return _WN_VENDORS.get(re.sub(r"[^0-9A-F]", "", mac.upper())[:6], "")


def wn_private_address(mac: str) -> bool:
    """A made-up ('locally administered') address: the second-lowest bit of the first byte is set."""
    try:
        return bool(int(re.sub(r"[^0-9a-fA-F]", "", mac)[:2], 16) & 0x02)
    except ValueError:
        return False


def _wn_mac_int(mac: str) -> int:
    return int(re.sub(r"[^0-9a-fA-F]", "", mac), 16)


def wn_same_router(mac: str, connected: str) -> bool:
    """Probably another radio of the router this computer is connected to: the first four bytes are the same and
    the address is within 16 of it (routers number their radios one after another)."""
    if not mac or not connected:
        return False
    a, b = _wn_mac_int(mac), _wn_mac_int(connected)
    return a != b and (a >> 16) == (b >> 16) and abs(a - b) <= 16


def wn_closeness(signal: int) -> str:
    if signal >= 70:
        return "very close (this room or the next)"
    if signal >= 40:
        return "nearby (probably the same building)"
    return "further away (probably a neighbour)"


# --- reading what this computer hears -------------------------------------------------------------------------------

def wn_parse_netsh(text: str):
    """[{ssid, bssid, signal, channel, band, security}] from `netsh wlan show networks mode=bssid`. Matched by the
    shape of each value, not its label, so a Windows in another language reads the same."""
    out, ssid, security = [], "", ""
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"^SSID \d+\s*:\s?(.*)$", line)
        if m:
            ssid, security, current = m.group(1).strip(), "", None
            continue
        mac = _WN_MAC.search(line) if re.match(r"^BSSID \d+\s*:", line) else None
        if mac:
            current = {"ssid": ssid, "bssid": mac.group(1).lower().replace("-", ":"), "signal": None,
                       "channel": None, "band": "", "security": security}
            out.append(current)
            continue
        if current is None:
            if re.search(r"(?i)\b(open|wpa\d?|wep|owe|personal|enterprise)\b", line.split(":", 1)[-1]) and \
                    ":" in line and not security:
                security = line.split(":", 1)[1].strip()
            continue
        value = line.split(":", 1)[1].strip() if ":" in line else ""
        if current["signal"] is None and re.fullmatch(r"\d{1,3}\s*%", value):
            current["signal"] = int(value.rstrip("% "))
        elif not current["band"] and re.fullmatch(r"[\d.,]+\s*GHz", value):
            current["band"] = value
        elif current["channel"] is None and re.fullmatch(r"\d{1,3}", value) and current["signal"] is not None:
            current["channel"] = int(value)
    return out


def wn_connected_netsh(text: str) -> str:
    """The hardware address of the network this computer is connected to, from `netsh wlan show interfaces`."""
    for line in text.splitlines():
        if "BSSID" in line.upper():
            m = _WN_MAC.search(line)
            if m:
                return m.group(1).lower().replace("-", ":")
    return ""


def _wn_nm_fields(line: str):
    """nmcli -t splits on ':' and escapes ':' inside values as '\\:'."""
    fields, cur, i = [], "", 0
    while i < len(line):
        c = line[i]
        if c == "\\" and i + 1 < len(line):
            cur += line[i + 1]
            i += 2
            continue
        if c == ":":
            fields.append(cur)
            cur = ""
        else:
            cur += c
        i += 1
    fields.append(cur)
    return fields


def wn_parse_nmcli(text: str):
    out, connected = [], ""
    for line in text.splitlines():
        f = _wn_nm_fields(line)
        if len(f) < 6:
            continue
        active, ssid, bssid, signal, chan, security = f[:6]
        if not _WN_MAC.fullmatch(bssid.strip()):
            continue
        row = {"ssid": ssid, "bssid": bssid.strip().lower(), "signal": int(signal) if signal.isdigit() else None,
               "channel": int(chan) if chan.isdigit() else None, "band": "", "security": security or "open"}
        out.append(row)
        if active.strip().lower() == "yes":
            connected = row["bssid"]
    return out, connected


def _wn_run(argv):
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    p = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=_WN_TIMEOUT,
                       creationflags=flags)
    return p.returncode, p.stdout or "", p.stderr or ""


def wn_scan():
    """{"networks": [...], "connected": bssid, "problem": "", "limited": ""}."""
    result = {"networks": [], "connected": "", "problem": "", "limited": ""}
    try:
        if sys.platform == "win32":
            rc, out, err = _wn_run(["netsh", "wlan", "show", "networks", "mode=bssid"])
            text = out + err
            if rc != 0 or re.search(r"(?i)location", text) and not _WN_MAC.search(text):
                result["problem"] = ("Windows did not show the networks nearby. On Windows 11 this needs location "
                                     "access: Settings > Privacy & security > Location - turn on Location services "
                                     "and \"Let desktop apps access your location\", then try again.")
                return result
            result["networks"] = wn_parse_netsh(out)
            result["connected"] = wn_connected_netsh(_wn_run(["netsh", "wlan", "show", "interfaces"])[1])
        elif sys.platform.startswith("linux"):
            if not shutil.which("nmcli"):
                result["problem"] = "NetworkManager (nmcli) is not available, so nearby networks could not be listed."
                return result
            rc, out, err = _wn_run(["nmcli", "-t", "-f", "ACTIVE,SSID,BSSID,SIGNAL,CHAN,SECURITY", "device",
                                    "wifi", "list", "--rescan", "no"])
            if rc != 0:
                result["problem"] = "nmcli could not list the networks nearby."
                return result
            result["networks"], result["connected"] = wn_parse_nmcli(out)
        elif sys.platform == "darwin":
            rc, out, _err = _wn_run(["system_profiler", "SPAirPortDataType", "-json"])
            result["limited"] = ("macOS hides the hardware addresses of nearby networks, so the maker of a hidden "
                                 "network cannot be named here.")
            data = json.loads(out or "{}") if rc == 0 else {}
            for item in data.get("SPAirPortDataType", []) or []:
                for iface in item.get("spairport_airport_interfaces", []) or []:
                    for net in iface.get("spairport_airport_other_local_wireless_networks", []) or []:
                        result["networks"].append({
                            "ssid": str(net.get("_name", "")), "bssid": str(net.get("spairport_network_bssid", "")),
                            "signal": None, "channel": None, "band": "",
                            "security": str(net.get("spairport_security_mode", ""))[:40]})
        else:
            result["problem"] = "Listing nearby Wi-Fi networks is not supported on this system."
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        result["problem"] = "Nearby networks could not be listed ({}).".format(type(exc).__name__)
    return result


# --- what each one probably is --------------------------------------------------------------------------------------

def wn_explain(net: dict, connected: str) -> str:
    """One plain sentence about a network - above all a hidden one."""
    mac = net.get("bssid") or ""
    if not mac:
        return "Its hardware address is not shown on this system, so its maker cannot be named."
    if wn_same_router(mac, connected):
        return ("This is almost certainly part of the router you are connected to - a second radio that mesh "
                "systems and internet providers' routers use to link their own units or TV boxes. Nothing to "
                "worry about.")
    if wn_private_address(mac):
        return ("It uses a made-up (private) address, as phones and laptops do when they share their connection. "
                "Usually a nearby phone's hotspot.")
    vendor = wn_vendor(mac)
    if vendor and connected and wn_vendor(connected) == vendor:
        return "Made by {vendor} - the same maker as your router, so possibly another unit of your own Wi-Fi system."
    if vendor:
        return "Made by {vendor}. Usually a router, smart TV, printer or speaker that hides its name."
    return "Its maker is not on the public list. Hidden networks are rarely a danger on their own."


def wn_report(scan: dict) -> dict:
    nets = scan.get("networks") or []
    hidden = [n for n in nets if not (n.get("ssid") or "").strip() or set(n.get("ssid") or "") == {"\x00"}]
    return {"connected": scan.get("connected", ""), "problem": scan.get("problem", ""), "limited": scan.get("limited", ""),
            "total": len(nets),
            "hidden": [dict(n, vendor=wn_vendor(n.get("bssid") or ""), explain=wn_explain(n, scan.get("connected", "")))
                       for n in sorted(hidden, key=lambda n: -(n.get("signal") or 0))],
            "named": sorted({n.get("ssid") for n in nets if n not in hidden})}


@safe_render
def wn_render(report: dict) -> str:
    lines = [T("WI-FI NETWORKS NEARBY"), ""]
    if report.get("problem"):
        lines.append(T(report["problem"]))
        return "\n".join(st_wrap_lines(lines))
    lines.append(T("This computer hears {n} network(s); {h} of them hide their name.", n=report["total"],
                   h=len(report["hidden"])))
    if report.get("limited"):
        lines.append(T(report["limited"]))
    if not report["hidden"]:
        lines += ["", T("No hidden network is nearby right now.")]
    for i, net in enumerate(report["hidden"], 1):
        lines.append("")
        lines.append(T("Hidden network {n}", n=i) + ("  ({})".format(st_line(net["bssid"])) if net.get("bssid") else ""))
        lines.append("  " + T(net["explain"], vendor=st_line(net.get("vendor") or "")))
        facts = []
        if net.get("signal") is not None:
            facts.append(T("signal {n}%, {where}", n=net["signal"], where=T(wn_closeness(net["signal"]))))
        if net.get("security"):
            facts.append(T("secured with {kind}", kind=st_line(net["security"])[:40]))
        if net.get("band") or net.get("channel"):
            facts.append(" ".join(x for x in (st_line(net.get("band") or ""),
                                              T("channel {n}", n=net["channel"]) if net.get("channel") else "") if x))
        if facts:
            lines.append("  " + "; ".join(facts))
    lines += ["", T("Its name cannot be read without connecting to it, which this tool never does. A hidden network "
                    "is almost never spying: spying equipment usually copies a name you know instead."),
              T("To find where it is, run this again in different rooms: the signal is strongest near the device."),
              T("To see which devices are connected to your own Wi-Fi, use \"Check my home network\".")]
    return "\n".join(st_wrap_lines(lines))


# --- find it: follow one network's signal ------------------------------------------------------------------------

def wn_rescan() -> None:
    """Ask the system for a fresh look at the networks around (best effort; the next read may still be a few seconds
    old). Windows: the WLAN API's WlanScan. Linux: nmcli rescan. Nothing is joined or sent to any network."""
    try:
        if sys.platform == "win32":
            import ctypes
            from ctypes import wintypes

            class GUID(ctypes.Structure):
                _fields_ = [("a", ctypes.c_ulong), ("b", ctypes.c_ushort), ("c", ctypes.c_ushort),
                            ("d", ctypes.c_ubyte * 8)]

            class IFACE(ctypes.Structure):
                _fields_ = [("guid", GUID), ("desc", ctypes.c_wchar * 256), ("state", wintypes.DWORD)]

            class IFACES(ctypes.Structure):
                _fields_ = [("count", wintypes.DWORD), ("index", wintypes.DWORD), ("items", IFACE * 1)]
            api = ctypes.WinDLL("wlanapi.dll")
            handle, version = wintypes.HANDLE(), wintypes.DWORD()
            if api.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(handle)):
                return
            try:
                ifaces = ctypes.POINTER(IFACES)()
                if api.WlanEnumInterfaces(handle, None, ctypes.byref(ifaces)):
                    return
                try:
                    count = ifaces.contents.count
                    items = ctypes.cast(ctypes.addressof(ifaces.contents.items), ctypes.POINTER(IFACE * count)).contents
                    for iface in items:
                        api.WlanScan(handle, ctypes.byref(iface.guid), None, None, None)
                finally:
                    api.WlanFreeMemory(ifaces)
            finally:
                api.WlanCloseHandle(handle, None)
        elif sys.platform.startswith("linux") and shutil.which("nmcli"):
            _wn_run(["nmcli", "device", "wifi", "rescan"])
    except (OSError, AttributeError, subprocess.SubprocessError):
        pass


def wn_signal_of(bssid: str):
    """The current signal (0-100) of one network, or None when it is not heard right now."""
    for net in wn_scan().get("networks") or []:
        if (net.get("bssid") or "").lower() == bssid.lower():
            return net.get("signal")
    return None


def wn_meter(signal, previous=None) -> str:
    """"██████░░░░ 62%  stronger - you are getting closer" for the find-it line."""
    if signal is None:
        return "not heard right now - move back the way you came"
    bars = max(0, min(10, int(round(signal / 10.0))))
    trend = ""
    if previous is not None:
        if signal >= previous + 5:
            trend = "  stronger - you are getting closer"
        elif signal <= previous - 5:
            trend = "  weaker - you are moving away"
        else:
            trend = "  about the same"
    return "{}{} {}%{}".format("#" * bars, "-" * (10 - bars), signal, trend)


def wn_can_find() -> bool:
    """Find-it needs each network's hardware address and its signal: Windows and Linux (macOS hides them)."""
    return sys.platform == "win32" or (sys.platform.startswith("linux") and bool(shutil.which("nmcli")))


def wn_find_terminal(report, out=print, seconds=3.0):
    """Terminal: pick a hidden network, then one line that updates while the person walks. Enter or Ctrl+C stops."""
    import time
    hidden = [n for n in report.get("hidden") or [] if n.get("bssid")]
    if not hidden or not wn_can_find():
        return
    try:
        if not sys.stdin.isatty():
            return
        choice = input("\n  Find one of them? Type its number (Enter to finish): ").strip()
    except (EOFError, KeyboardInterrupt):
        return
    if not choice.isdigit() or not 1 <= int(choice) <= len(hidden):
        return
    bssid = hidden[int(choice) - 1]["bssid"]
    out("  Walk slowly around; the signal is strongest near the device. Press Enter (or Ctrl+C) to stop.")
    previous, shown = None, 0
    try:
        while True:
            wn_rescan()
            time.sleep(seconds)
            signal = wn_signal_of(bssid)
            line = "  " + wn_meter(signal, previous)
            sys.stdout.write("\r" + line + " " * max(0, shown - len(line)))
            sys.stdout.flush()
            shown = len(line)
            previous = signal if signal is not None else previous
            if _wn_enter_pressed():
                break
    except KeyboardInterrupt:
        pass
    sys.stdout.write("\n")


def _wn_enter_pressed() -> bool:
    try:
        if sys.platform == "win32":
            import msvcrt
            pressed = False
            while msvcrt.kbhit():
                pressed = msvcrt.getwch() in ("\r", "\n") or pressed
            return pressed
        import select
        ready, _w, _x = select.select([sys.stdin], [], [], 0)
        if ready:
            sys.stdin.readline()
            return True
    except (OSError, ValueError, ImportError):
        pass
    return False


def wn_saved(report: dict) -> dict:
    """What a saved Wi-Fi result holds (it goes into the household report): the hidden networks only."""
    import datetime
    hidden = report.get("hidden") or []
    return {"tool": "zero-breach-toolkit wifi nearby",
            "made": datetime.datetime.now().astimezone().replace(microsecond=0).isoformat(),
            "level": "worth-a-look" if hidden else ("incomplete" if report.get("problem") else "clean"),
            "summary": "{} networks heard, {} hide their name".format(report.get("total", 0), len(hidden)),
            "findings": ["hidden network {} ({}), signal {}%".format(n.get("bssid") or "?", n.get("vendor") or
                                                                   "maker unknown", n.get("signal"))
                         for n in hidden],
            "hidden": [{k: n.get(k) for k in ("bssid", "vendor", "signal", "security", "channel")} for n in hidden]}


def wn_save(report: dict, path: str) -> None:
    import json
    with open(path, "x", encoding="utf-8") as fh:
        json.dump(wn_saved(report), fh, indent=2, ensure_ascii=False)


def wifi_nearby_command(args=None, out=print) -> int:
    report = wn_report(wn_scan())
    out(wn_render(report))
    if getattr(args, "json", None):
        wn_save(report, args.json)
        out("\nSaved: " + args.json)
    wn_find_terminal(report, out)
    return 0
