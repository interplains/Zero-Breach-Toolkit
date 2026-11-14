"""Saved Wi-Fi network settings (prevention advice, never a finding).

Some spyware and most surveillance of a person nearby starts on the network:
a computer that joins an open network by itself can be lured onto a look-alike
network with the same name, and WEP or the original WPA (TKIP) protect almost
nothing. This check reads the computer's own saved Wi-Fi settings and says
which ones weaken it. Nothing is changed, nothing is joined or scanned, no
network is contacted, and Wi-Fi passwords are never read:

  Windows  `netsh wlan export profile` into a private temporary folder, without
           the option that reveals keys; only the SSIDConfig, connectionMode and
           authEncryption elements of each exported XML are read, and the files
           are deleted at once. The XML schema is the same in every Windows
           language, unlike netsh's display text.
  Linux    NetworkManager's `nmcli`, asking only for the security type and the
           hidden-network setting of each saved Wi-Fi connection.
  macOS    `system_profiler SPAirPortDataType -json`: the security of the network
           in use. The list of saved networks is readable only by the
           administrator, so it is reported as not checked.

Everything is reported as a lead with its ordinary explanation; the verdict,
module status and exit code are never affected by a lead.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET

from ..localpaths import local_temp_dir
from ..result import Lead, ModuleResult

NAME = "wifi-settings"

_WIFI_TIMEOUT = 60
_WIFI_PROFILE_LIMIT = 500
_WIFI_NS = "{http://www.microsoft.com/networking/WLAN/profile/v1}"

# What each security type means, in the words the report uses.
_WIFI_OPEN = "open"
_WIFI_WEP = "wep"
_WIFI_TKIP = "wpa-tkip"
_WIFI_OK = "protected"
_WIFI_ENTERPRISE = "enterprise"


def _wifi_run(argv, timeout=_WIFI_TIMEOUT):
    """Run one local command without a console window. (returncode, out, err)."""
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) if sys.platform == "win32" else 0
    proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=timeout, creationflags=flags)
    return proc.returncode, proc.stdout or "", proc.stderr or ""


def wifi_classify(authentication, encryption):
    """Map a Windows profile's authentication/encryption to one security type."""
    auth = (authentication or "").strip().lower()
    enc = (encryption or "").strip().lower()
    if enc == "wep" or auth == "shared":
        return _WIFI_WEP
    if auth in ("open", "") and enc in ("none", ""):
        return _WIFI_OPEN
    if auth == "owe":
        return _WIFI_OK  # "Enhanced Open": encrypted, though anyone may join
    if enc == "tkip" or auth in ("wpa", "wpapsk"):
        return _WIFI_TKIP
    if auth in ("wpa2", "wpa3", "wpa3enterprise", "wpa3enterprise192"):
        return _WIFI_ENTERPRISE
    return _WIFI_OK


def wifi_windows_profile(xml_text):
    """{ssid, auto, hidden, security} from one exported WLANProfile document.

    Only these elements are read; the key material element (which the export
    leaves encrypted, because the key option is not used) is never looked at."""
    root = ET.fromstring(xml_text)
    if not root.tag.endswith("WLANProfile"):
        raise ValueError("not a Wi-Fi profile")
    ns = root.tag[:-len("WLANProfile")]
    ssid = root.findtext("{0}SSIDConfig/{0}SSID/{0}name".format(ns)) or root.findtext(ns + "name") or "?"
    hidden = (root.findtext("{0}SSIDConfig/{0}nonBroadcast".format(ns)) or "").strip().lower() == "true"
    auto = (root.findtext(ns + "connectionMode") or "").strip().lower() == "auto"
    auth = root.findtext("{0}MSM/{0}security/{0}authEncryption/{0}authentication".format(ns))
    enc = root.findtext("{0}MSM/{0}security/{0}authEncryption/{0}encryption".format(ns))
    return {"ssid": ssid[:64], "auto": auto, "hidden": hidden, "security": wifi_classify(auth, enc),
            "detail": "{}/{}".format(auth or "?", enc or "?")}


def _wifi_windows(r):
    folder = tempfile.mkdtemp(prefix="zbt_wifi_", dir=local_temp_dir())
    try:
        rc, out, err = _wifi_run(["netsh", "wlan", "export", "profile", "folder=" + folder])
        names = [n for n in os.listdir(folder) if n.lower().endswith(".xml")]
        if rc != 0 and not names:
            text = (out + " " + err).lower()
            if "wlansvc" in text or "wireless autoconfig" in text or "no wireless interface" in text:
                return None  # no Wi-Fi on this computer
            r.could_not_run(NAME, "the saved Wi-Fi settings could not be exported (netsh exit {})".format(rc))
            return []
        profiles = []
        for name in sorted(names)[:_WIFI_PROFILE_LIMIT]:
            path = os.path.join(folder, name)
            try:
                with open(path, "rb") as fh:
                    profiles.append(wifi_windows_profile(fh.read(256 * 1024)))
            except (OSError, ValueError, ET.ParseError):
                r.skipped += 1
            finally:
                try:
                    os.remove(path)
                except OSError:
                    pass
        if names and not profiles:
            r.could_not_run(NAME, "{} saved Wi-Fi network(s) were exported but none could be read".format(len(names)))
            return []
        if len(names) > _WIFI_PROFILE_LIMIT:
            r.note("Only the first {} saved Wi-Fi networks were checked.".format(_WIFI_PROFILE_LIMIT))
        return profiles
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def wifi_nm_security(key_mgmt, wep_type, has_security):
    key = (key_mgmt or "").strip().lower()
    if not has_security or key == "":
        return _WIFI_OPEN if not (wep_type or "").strip() else _WIFI_WEP
    if key == "none" or (wep_type or "").strip():
        return _WIFI_WEP
    if key in ("wpa-eap", "ieee8021x", "wpa-eap-suite-b-192"):
        return _WIFI_ENTERPRISE
    if key == "owe":
        return _WIFI_OK
    return _WIFI_OK  # wpa-psk (WPA2/WPA3 transition) and sae (WPA3)


def _wifi_linux(r):
    if not shutil.which("nmcli"):
        r.could_not_run(NAME, "NetworkManager (nmcli) is not available, so saved Wi-Fi settings were not "
                        "read; other network managers are not supported")
        return []
    rc, out, err = _wifi_run(["nmcli", "-t", "-f", "UUID,TYPE", "connection", "show"])
    if rc != 0:
        r.could_not_run(NAME, "nmcli could not list saved connections: " + (err.strip().splitlines() or ["?"])[0][:200])
        return []
    uuids = [line.split(":", 1)[0] for line in out.splitlines()
             if line.endswith(":802-11-wireless")][:_WIFI_PROFILE_LIMIT]
    profiles = []
    for uuid in uuids:
        rc, out, _err = _wifi_run(["nmcli", "-g", "802-11-wireless.ssid,connection.autoconnect,"
                                   "802-11-wireless.hidden,802-11-wireless-security.key-mgmt,"
                                   "802-11-wireless-security.wep-key-type", "connection", "show", uuid])
        if rc != 0:
            r.skipped += 1
            continue
        lines = out.splitlines() + [""] * 5
        ssid, auto, hidden, key_mgmt, wep = (v.strip() for v in lines[:5])
        # nmcli's terse output escapes ':' and '\' inside values; undo it so the name matches the nearby list
        ssid = re.sub(r"\\(.)", r"\1", ssid)
        profiles.append({"ssid": ssid[:64] or "?", "auto": auto.lower() == "yes",
                         "hidden": hidden.lower() == "yes",
                         "security": wifi_nm_security(key_mgmt, wep, bool(key_mgmt or wep)),
                         "detail": key_mgmt or "none"})
    if uuids and not profiles:
        r.could_not_run(NAME, "{} saved Wi-Fi connection(s) are listed but none could be read".format(len(uuids)))
        return []
    return profiles


def wifi_mac_security(mode):
    mode = (mode or "").lower()
    if "wep" in mode:
        return _WIFI_WEP
    if mode.endswith("_none") or mode.endswith("mode_none") or mode in ("none", "open"):
        return _WIFI_OPEN
    if "wpa_personal" in mode and "wpa2" not in mode and "wpa3" not in mode:
        return _WIFI_TKIP
    if "enterprise" in mode:
        return _WIFI_ENTERPRISE
    return _WIFI_OK


def _wifi_mac(r):
    rc, out, _err = _wifi_run(["system_profiler", "SPAirPortDataType", "-json"], timeout=90)
    if rc != 0:
        r.could_not_run(NAME, "macOS did not report the Wi-Fi settings (system_profiler exit {})".format(rc))
        return []
    try:
        doc = json.loads(out)
    except ValueError:
        r.could_not_run(NAME, "the Wi-Fi report from macOS could not be read")
        return []
    profiles = []
    for item in doc.get("SPAirPortDataType", []) or []:
        for iface in item.get("spairport_airport_interfaces", []) or []:
            current = iface.get("spairport_current_network_information")
            if isinstance(current, dict):
                profiles.append({"ssid": str(current.get("_name", "?"))[:64], "auto": True, "hidden": False,
                                 "security": wifi_mac_security(current.get("spairport_security_mode")),
                                 "detail": str(current.get("spairport_security_mode", "?"))[:80],
                                 "current": True})
    r.note("macOS: only the network in use was checked; the list of saved networks can only be read by "
           "an administrator.")
    return profiles


def wifi_leads(r, profiles):
    """Turn the saved networks into leads (fixed wording; names are data)."""
    counts = {}
    for p in profiles:
        counts[p["security"]] = counts.get(p["security"], 0) + 1
        where = "Wi-Fi network \"{}\"".format(p["ssid"])
        if p["security"] == _WIFI_OPEN and p.get("auto"):
            r.add_lead(Lead(NAME, where,
                            "This computer joins this open Wi-Fi network (no password) by itself. Anyone nearby "
                            "can set up a network with the same name, and the computer will join theirs too.",
                            "Common for cafe, hotel and airport networks and usually harmless. Set it to connect "
                            "only when you choose, or forget it, and use a VPN on open networks.",
                            p.get("detail", "")))
        elif p["security"] == _WIFI_WEP:
            r.add_lead(Lead(NAME, where,
                            "This network uses WEP, which has been breakable in minutes since the early 2000s: "
                            "anyone nearby can read and change the traffic on it.",
                            "Usually a very old router. If it is yours, switch it to WPA2 (AES) or WPA3, or "
                            "replace it.", p.get("detail", "")))
        elif p["security"] == _WIFI_TKIP:
            r.add_lead(Lead(NAME, where,
                            "This network uses the original WPA or its TKIP cipher, which are outdated and weak.",
                            "Usually an old router setting. If it is yours, switch it to WPA2 (AES) or WPA3.",
                            p.get("detail", "")))
        if p.get("hidden") and p.get("auto") and p["security"] != _WIFI_WEP:
            r.add_lead(Lead(NAME, where,
                            "This is a hidden network that the computer joins by itself, so the computer keeps "
                            "calling out its name wherever it goes. That tells people nearby which networks "
                            "it knows.",
                            "Hiding a network name is a common setting that does not add security. Make the "
                            "network visible, or set it to connect only when you choose.", p.get("detail", "")))
    return counts


def run(ctx) -> ModuleResult:
    r = ModuleResult(NAME)
    ctx.partial = r
    r.note("Saved Wi-Fi settings: read only; no network is joined, scanned or contacted and no password is read.")
    try:
        if sys.platform == "win32":
            profiles = _wifi_windows(r)
        elif sys.platform == "darwin":
            profiles = _wifi_mac(r)
        else:
            profiles = _wifi_linux(r)
    except (OSError, subprocess.SubprocessError, ValueError) as exc:
        r.could_not_run(NAME, "the saved Wi-Fi settings could not be read: {}".format(str(exc)[:200]))
        return r
    if profiles is None:
        r.note("This computer has no Wi-Fi, so there were no Wi-Fi settings to check.")
        r.ran(NAME)
        return r
    if any(not c.ran for c in r.checks):
        return r
    counts = wifi_leads(r, profiles)
    r.checked = len(profiles)
    r.submetrics["wifi_networks_checked"] = len(profiles)
    if profiles:
        names = {_WIFI_OPEN: "open (no password)", _WIFI_WEP: "WEP", _WIFI_TKIP: "WPA/TKIP",
                 _WIFI_OK: "WPA2/WPA3", _WIFI_ENTERPRISE: "work/enterprise"}
        r.note("Saved Wi-Fi networks checked: {} ({}).".format(len(profiles), ", ".join(
            "{} {}".format(counts[k], names[k]) for k in names if counts.get(k))))
    else:
        r.note("No saved Wi-Fi networks were found.")
    r.ran(NAME)
    _check_lookalikes(r, profiles)
    return r


# --- look-alike networks nearby --------------------------------------------------

_WIFI_RANK = {_WIFI_OPEN: 0, _WIFI_WEP: 1, _WIFI_TKIP: 2, _WIFI_OK: 3, _WIFI_ENTERPRISE: 3}
# Windows DOT11_AUTH_ALGORITHM and DOT11_CIPHER_ALGORITHM values (wlantypes.h).
_WIFI_WIN_AUTH = {1: "open", 2: "shared", 3: "WPA", 4: "WPAPSK", 5: "WPA", 6: "WPA2", 7: "WPA2PSK",
                  8: "WPA3", 9: "WPA3SAE", 10: "OWE", 11: "WPA3"}
_WIFI_WIN_CIPHER = {0: "none", 1: "WEP", 5: "WEP", 0x101: "WEP", 2: "TKIP", 4: "AES", 8: "AES", 9: "AES",
                    6: "AES", 0x100: "AES"}


def wifi_real_name(ssid):
    """False for names the system hid from us: recent macOS returns '<redacted>' without Location access, and
    an empty name is a hidden network. Matching hidden names would make every open network a 'look-alike'."""
    name = str(ssid or "").strip()
    return bool(name) and name.lower() not in ("<redacted>", "redacted", "<hidden>", "<unknown ssid>")


def wifi_lookalikes(saved, visible):
    """Saved networks whose name is broadcast nearby open or with WEP, while the saved one is protected."""
    best = {}
    for p in saved:
        if p["security"] in (_WIFI_OK, _WIFI_ENTERPRISE, _WIFI_TKIP) and wifi_real_name(p["ssid"]):
            best[p["ssid"]] = max(best.get(p["ssid"], 0), _WIFI_RANK[p["security"]])
    found = []
    for ssid, security in visible:
        if not wifi_real_name(ssid):
            continue
        if ssid in best and security in (_WIFI_OPEN, _WIFI_WEP) and _WIFI_RANK[security] < best[ssid]:
            found.append((ssid, security))
    return sorted(set(found))


def _wifi_visible_windows():
    """(ssid, security) of the networks in Windows' last scan, via the WLAN API. No scan is started."""
    import ctypes
    from ctypes import wintypes

    class GUID(ctypes.Structure):
        _fields_ = [("Data1", ctypes.c_ulong), ("Data2", ctypes.c_ushort), ("Data3", ctypes.c_ushort),
                    ("Data4", ctypes.c_ubyte * 8)]

    class IFACE(ctypes.Structure):
        _fields_ = [("InterfaceGuid", GUID), ("strInterfaceDescription", ctypes.c_wchar * 256),
                    ("isState", wintypes.DWORD)]

    class IFACES(ctypes.Structure):
        _fields_ = [("dwNumberOfItems", wintypes.DWORD), ("dwIndex", wintypes.DWORD), ("InterfaceInfo", IFACE * 1)]

    class SSID(ctypes.Structure):
        _fields_ = [("uSSIDLength", ctypes.c_ulong), ("ucSSID", ctypes.c_ubyte * 32)]

    class NETWORK(ctypes.Structure):
        _fields_ = [("strProfileName", ctypes.c_wchar * 256), ("dot11Ssid", SSID), ("dot11BssType", wintypes.DWORD),
                    ("uNumberOfBssids", ctypes.c_ulong), ("bNetworkConnectable", wintypes.BOOL),
                    ("wlanNotConnectableReason", wintypes.DWORD), ("uNumberOfPhyTypes", ctypes.c_ulong),
                    ("dot11PhyTypes", wintypes.DWORD * 8), ("bMorePhyTypes", wintypes.BOOL),
                    ("wlanSignalQuality", ctypes.c_ulong), ("bSecurityEnabled", wintypes.BOOL),
                    ("dot11DefaultAuthAlgorithm", wintypes.DWORD), ("dot11DefaultCipherAlgorithm", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD), ("dwReserved", wintypes.DWORD)]

    class NETWORKS(ctypes.Structure):
        _fields_ = [("dwNumberOfItems", wintypes.DWORD), ("dwIndex", wintypes.DWORD), ("Network", NETWORK * 1)]

    api = ctypes.WinDLL("wlanapi.dll")
    handle, version = wintypes.HANDLE(), wintypes.DWORD()
    err = api.WlanOpenHandle(2, None, ctypes.byref(version), ctypes.byref(handle))
    if err:
        raise OSError("WlanOpenHandle failed ({})".format(err))
    visible = []
    try:
        ifaces = ctypes.POINTER(IFACES)()
        err = api.WlanEnumInterfaces(handle, None, ctypes.byref(ifaces))
        if err:
            raise OSError("WlanEnumInterfaces failed ({})".format(err))
        try:
            count = ifaces.contents.dwNumberOfItems
            items = ctypes.cast(ctypes.addressof(ifaces.contents.InterfaceInfo), ctypes.POINTER(IFACE * count)).contents
            for iface in items:
                nets = ctypes.POINTER(NETWORKS)()
                err = api.WlanGetAvailableNetworkList(handle, ctypes.byref(iface.InterfaceGuid), 0, None,
                                                      ctypes.byref(nets))
                if err:
                    continue
                try:
                    n = nets.contents.dwNumberOfItems
                    rows = ctypes.cast(ctypes.addressof(nets.contents.Network), ctypes.POINTER(NETWORK * n)).contents
                    for row in rows:
                        length = min(row.dot11Ssid.uSSIDLength, 32)
                        ssid = bytes(row.dot11Ssid.ucSSID[:length]).decode("utf-8", "replace")
                        auth = _WIFI_WIN_AUTH.get(row.dot11DefaultAuthAlgorithm, "?")
                        cipher = _WIFI_WIN_CIPHER.get(row.dot11DefaultCipherAlgorithm, "?")
                        if not row.bSecurityEnabled:
                            auth, cipher = "open", "none"
                        visible.append((ssid, wifi_classify(auth, cipher)))
                finally:
                    api.WlanFreeMemory(nets)
        finally:
            api.WlanFreeMemory(ifaces)
    finally:
        api.WlanCloseHandle(handle, None)
    return visible


def wifi_nm_visible_security(security):
    text = (security or "").strip().upper()
    if not text or text == "--":
        return _WIFI_OPEN
    if "WEP" in text:
        return _WIFI_WEP
    if "WPA2" in text or "WPA3" in text or "802.1X" in text:
        return _WIFI_OK
    return _WIFI_TKIP


def _wifi_visible_linux():
    rc, out, err = _wifi_run(["nmcli", "-t", "-f", "SSID,SECURITY", "device", "wifi", "list", "--rescan", "no"])
    if rc != 0:
        raise OSError("nmcli could not list visible networks")
    visible = []
    for line in out.splitlines():
        ssid, _sep, security = line.rpartition(":")
        ssid = ssid.replace("\\:", ":")
        if ssid:
            visible.append((ssid, wifi_nm_visible_security(security)))
    return visible


def _wifi_visible_mac():
    rc, out, _err = _wifi_run(["system_profiler", "SPAirPortDataType", "-json"], timeout=90)
    if rc != 0:
        raise OSError("macOS did not report nearby networks")
    visible = []
    for item in json.loads(out).get("SPAirPortDataType", []) or []:
        for iface in item.get("spairport_airport_interfaces", []) or []:
            for net in iface.get("spairport_airport_other_local_wireless_networks", []) or []:
                visible.append((str(net.get("_name", "")), wifi_mac_security(net.get("spairport_security_mode"))))
    return visible


def _check_lookalikes(r, saved):
    if not saved:
        return
    try:
        if sys.platform == "win32":
            visible = _wifi_visible_windows()
        elif sys.platform == "darwin":
            visible = _wifi_visible_mac()
        else:
            visible = _wifi_visible_linux()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        r.could_not_run("wifi-lookalike", "nearby networks could not be listed: {}".format(str(exc)[:160]))
        return
    for ssid, security in wifi_lookalikes(saved, visible):
        r.add_lead(Lead("wifi-lookalike", "Wi-Fi network \"{}\"".format(ssid[:64]),
                        "A network nearby uses the same name as one you saved, but {} - while yours has a "
                        "password.".format("with no password at all" if security == _WIFI_OPEN else "with old WEP"),
                        "Sometimes a guest network or an old router with the same name. It is also exactly how "
                        "people are tricked into joining a copy of a network to have their traffic watched "
                        "(an \"evil twin\"). Don't join it, and check the network name before connecting.", ""))
    r.note("Nearby networks in the last scan: {}.".format(len({v[0] for v in visible})))
    r.ran("wifi-lookalike")
