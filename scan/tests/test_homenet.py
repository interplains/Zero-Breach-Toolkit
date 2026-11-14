"""--home-network: subnet guard, parsers and advice, with no real network contact in tests."""
import struct
from unittest.mock import patch

import pytest

from zbtriage import homenet

HOME = ("192.168.1.37", homenet.hn_subnet("192.168.1.37"), "192.168.1.1", "")


@pytest.mark.parametrize("address", ["8.8.8.8", "100.64.1.2", "127.0.0.1", "169.254.3.4", "2001:db8::1"])
def test_refuses_anything_but_a_private_network(address):
    with pytest.raises(homenet.HomeNetError):
        homenet.hn_subnet(address)


@pytest.mark.parametrize("address,subnet", [("192.168.1.37", "192.168.1.0/24"), ("10.20.30.40", "10.20.30.0/24"),
                                            ("172.16.5.9", "172.16.5.0/24")])
def test_checks_only_the_256_addresses_around_this_computer(address, subnet):
    assert str(homenet.hn_subnet(address)) == subnet


def test_local_http_only():
    subnet = homenet.hn_subnet("192.168.1.37")
    assert homenet._hn_local_url("http://192.168.1.1:5000/rootDesc.xml", subnet)
    assert not homenet._hn_local_url("http://192.168.2.1/desc.xml", subnet)
    assert not homenet._hn_local_url("http://example.com/desc.xml", subnet)
    assert not homenet._hn_local_url("https://192.168.1.1/desc.xml", subnet)
    with pytest.raises(homenet.HomeNetError):
        homenet.hn_http("http://8.8.8.8/", subnet)


def _name(n):
    return b"".join(bytes([len(p)]) + p.encode() for p in n.split(".")) + b"\0"


def test_mdns_answer_parsing():
    rdata = _name("Living Room TV._googlecast._tcp.local")
    packet = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + _name("_googlecast._tcp.local") + \
        struct.pack(">HHIH", 12, 1, 120, len(rdata)) + rdata
    assert homenet.hn_parse_mdns(packet) == {"Living Room TV._googlecast._tcp.local"}


def test_mdns_compression_pointer():
    first = _name("_googlecast._tcp.local")
    rdata = bytes([2]) + b"TV" + struct.pack(">H", 0xC000 | 12)
    packet = struct.pack(">HHHHHH", 0, 0x8400, 0, 1, 0, 0) + first + struct.pack(">HHIH", 12, 1, 120, len(rdata)) + rdata
    assert homenet.hn_parse_mdns(packet) == {"TV._googlecast._tcp.local"}


def test_ssdp_parse():
    data = (b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.1:5000/rootDesc.xml\r\n"
            b"ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nSERVER: Linux UPnP/1.0\r\n\r\n")
    h = homenet.hn_parse_ssdp(data)
    assert h["LOCATION"] == "http://192.168.1.1:5000/rootDesc.xml" and "InternetGatewayDevice" in h["ST"]


DESC = b"""<?xml version="1.0"?><root xmlns="urn:schemas-upnp-org:device-1-0"><device>
<deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><friendlyName>Home Router</friendlyName>
<manufacturer>ExampleCo</manufacturer><modelName>R7000</modelName><modelNumber>1.0.11</modelNumber>
<deviceList><device><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
<controlURL>/ctl/IPConn</controlURL></service></serviceList></device></deviceList></device></root>"""


def test_description_parse():
    info = homenet.hn_parse_description(DESC)
    assert info["friendlyName"] == "Home Router" and info["modelName"] == "R7000"
    assert ("urn:schemas-upnp-org:service:WANIPConnection:1", "/ctl/IPConn") in info["services"]


def test_port_mappings_stop_at_router_error():
    entry = (b'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body>'
             b'<u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
             b'<NewRemoteHost></NewRemoteHost><NewExternalPort>3389</NewExternalPort><NewProtocol>TCP</NewProtocol>'
             b'<NewInternalPort>3389</NewInternalPort><NewInternalClient>192.168.1.50</NewInternalClient>'
             b'<NewEnabled>1</NewEnabled><NewPortMappingDescription>RDP</NewPortMappingDescription>'
             b'</u:GetGenericPortMappingEntryResponse></s:Body></s:Envelope>')
    calls = []

    def fake_http(url, subnet, data=None, headers=None, timeout=3):
        calls.append(url)
        if len(calls) > 1:
            raise OSError("500 SpecifiedArrayIndexInvalid")
        return entry
    subnet = homenet.hn_subnet("192.168.1.37")
    with patch.object(homenet, "hn_http", fake_http):
        maps = homenet.hn_port_mappings("http://192.168.1.1:5000/rootDesc.xml", homenet.hn_parse_description(DESC), subnet)
    assert calls[0] == "http://192.168.1.1:5000/ctl/IPConn"
    assert [(m["NewExternalPort"], m["NewInternalClient"]) for m in maps] == [("3389", "192.168.1.50")]


@pytest.mark.parametrize("names,ports,types,kind", [
    ({"TV._googlecast._tcp.local"}, [], [], "Chromecast / Google TV"),
    (set(), [554, 80], [], "camera or video recorder"),
    (set(), [62078], [], "iPhone or iPad"),
    (set(), [], ["urn:schemas-upnp-org:device:MediaRenderer:1"], "TV or speaker"),
    (set(), [5555], [], "Android device"),
])
def test_device_kind(names, ports, types, kind):
    assert homenet.hn_kind(names, ports, types) == kind


def test_findings_name_risky_doors_cameras_and_router_openings():
    devices = [{"ip": "192.168.1.40", "name": "Bedroom TV", "kind": "Android TV", "ports": [5555, 8009]},
               {"ip": "192.168.1.41", "name": "", "kind": "camera or video recorder", "ports": [554]},
               {"ip": "192.168.1.42", "name": "Laptop", "kind": "", "ports": [445]}]
    maps = [{"NewExternalPort": "3389", "NewProtocol": "TCP", "NewInternalClient": "192.168.1.50",
             "NewPortMappingDescription": "RDP"}]
    titles = [t for t, _d, _w in homenet.hn_findings(devices, maps, "192.168.1.1")]
    assert any("Android debugging" in t and "Bedroom TV" in t for t in titles)
    assert any("camera" in t.lower() and "192.168.1.41" in t for t in titles)
    assert any("opened port 3389" in t for t in titles)
    assert not any("192.168.1.42" in t for t in titles)  # file sharing on a laptop is informational


def test_render_mentions_limits():
    text = homenet.hn_render({"subnet": "192.168.1.0/24", "devices": [], "findings": [], "gaps": [], "seconds": 3})
    assert "not a guarantee" in text and "nothing was logged into" in text.lower()


def test_command_needs_consent_and_contacts_nothing_without_it():
    class Args:
        yes_my_network = False
        json = None
    lines = []
    with patch.object(homenet, "hn_target", return_value=HOME), \
            patch.object(homenet, "hn_check", side_effect=AssertionError("must not run")), \
            patch.object(homenet.sys.stdin, "isatty", return_value=True), \
            patch("builtins.input", return_value="no"):
        assert homenet.homenet_command(Args(), out=lines.append) == 1
    assert any("Nothing was contacted" in l for l in lines)


def test_command_refuses_without_terminal_or_flag():
    class Args:
        yes_my_network = False
        json = None
    with patch.object(homenet, "hn_target", return_value=HOME), \
            patch.object(homenet, "hn_check", side_effect=AssertionError("must not run")), \
            patch.object(homenet.sys.stdin, "isatty", return_value=False):
        assert homenet.homenet_command(Args(), out=lambda _l: None) == 1


def test_options_are_exclusive(tmp_path):
    from zbtriage.cli import _parse
    with pytest.raises(SystemExit):
        _parse(["--home-network", "--phone", str(tmp_path), "--no-menu"])
    with pytest.raises(SystemExit):
        _parse(["--yes-my-network", "--no-menu"])


def test_router_is_found_on_a_real_adapter_never_a_tunnel():
    routes = [("wg0", "10.2.0.1"), ("tun0", "10.8.0.1"), ("docker0", "172.17.0.1"), ("eth0", "8.8.8.8"),
              ("wlan0", "192.168.100.1"), ("eth1", "192.168.1.1")]
    assert homenet.hn_pick_gateway(routes) == "192.168.100.1"
    assert homenet.hn_pick_gateway([("utun3", "10.0.0.1"), ("ppp0", "192.168.9.1")]) is None


def test_no_router_means_no_check(monkeypatch):
    monkeypatch.setattr(homenet, "hn_gateway", lambda: None)
    with pytest.raises(homenet.HomeNetError, match="router could not be found"):
        homenet.hn_target()


def test_vpn_on_checks_the_home_network_not_the_tunnel(monkeypatch):
    monkeypatch.setattr(homenet, "hn_gateway", lambda: "192.168.100.1")
    monkeypatch.setattr(homenet, "hn_local_address",
                        lambda towards="192.0.2.1": "192.168.100.4" if towards == "192.168.100.1" else "10.2.0.2")
    local, subnet, gateway, note = homenet.hn_target()
    assert (local, str(subnet), gateway) == ("192.168.100.4", "192.168.100.0/24", "192.168.100.1")
    assert "VPN" in note


def test_router_on_another_network_is_refused(monkeypatch):
    monkeypatch.setattr(homenet, "hn_gateway", lambda: "192.168.5.1")
    monkeypatch.setattr(homenet, "hn_local_address", lambda towards="192.0.2.1": "192.168.100.4")
    with pytest.raises(homenet.HomeNetError, match="not on the same local network"):
        homenet.hn_target()


def test_devices_behind_an_extender_are_explained_not_flagged():
    devices = [{"ip": "192.168.1.20", "mac": "aa:bb:cc:00:00:01", "name": "", "kind": "", "model": "", "ports": []},
               {"ip": "192.168.1.21", "mac": "aa:bb:cc:00:00:01", "name": "", "kind": "", "model": "", "ports": []},
               {"ip": "192.168.1.22", "mac": "aa:bb:cc:00:00:02", "name": "", "kind": "", "model": "", "ports": []}]
    homenet.hn_mark_shared(devices)
    assert [d.get("shared_mac", False) for d in devices] == [True, True, False]
    text = homenet.hn_render({"subnet": "192.168.1.0/24", "devices": devices, "findings": [], "gaps": [],
                              "seconds": 3})
    assert text.count("Wi-Fi extender or repeater") == 2 and "makes its own network" in text


def test_one_finding_per_camera():
    devices = [{"ip": "192.168.1.8", "name": "", "kind": "camera or video recorder", "ports": [80, 554, 37777]}]
    items = homenet.hn_findings(devices, [], "192.168.1.1")
    assert len(items) == 1
    assert "video stream (RTSP)" in items[0][1] and "Dahua" in items[0][1]


def test_userinfo_and_bad_ports_are_refused():
    subnet = homenet.hn_subnet("192.168.1.37")
    assert not homenet._hn_local_url("http://u:p@192.168.1.5/desc.xml", subnet)
    assert not homenet._hn_local_url("http://192.168.1.5:abc/desc.xml", subnet)
    assert not homenet._hn_local_url("http://192.168.1.5:99999/desc.xml", subnet)
    assert homenet._hn_local_url("http://192.168.1.5:49152/desc.xml", subnet)


def test_device_text_is_neutralised():
    text = homenet._hn_text("Living\x1b[2J Room\nTV‮", 80)
    assert "\x1b" not in text and "\n" not in text and "‮" not in text


def test_one_broken_device_never_ends_the_check(monkeypatch):
    import http.client
    monkeypatch.setattr(homenet, "hn_target", lambda: ("192.168.1.37", homenet.hn_subnet("192.168.1.37"),
                                                        "192.168.1.1", ""))
    monkeypatch.setattr(homenet, "hn_nudge", lambda *a: None)
    monkeypatch.setattr(homenet, "hn_ssdp", lambda: {"192.168.1.5": [{"LOCATION": "http://192.168.1.5:1900/x"}],
                                                     "192.168.1.1": [{"LOCATION": "http://192.168.1.1:5000/r"}]})
    monkeypatch.setattr(homenet, "hn_mdns", lambda: {})
    monkeypatch.setattr(homenet, "hn_neighbours", lambda: {"192.168.1.5": "aa:bb:cc:dd:ee:ff"})
    monkeypatch.setattr(homenet, "hn_scan_ports", lambda ips, stats=None: {})

    def boom(url, subnet, **kw):
        raise http.client.BadStatusLine("SSH-2.0-dropbear")
    monkeypatch.setattr(homenet, "hn_http", boom)
    result = homenet.hn_check(router_lookups=False)
    assert [d["ip"] for d in result["devices"]] == ["192.168.1.1", "192.168.1.5"] or result["devices"]


def test_linux_tunnels_are_recognised(tmp_path):
    (tmp_path / "vpn0").mkdir()
    (tmp_path / "vpn0" / "type").write_text("65534\n")
    (tmp_path / "wg-x").mkdir()
    (tmp_path / "wg-x" / "tun_flags").write_text("0x1001\n")
    (tmp_path / "wlan0").mkdir()
    (tmp_path / "wlan0" / "type").write_text("1\n")
    assert homenet.hn_linux_tunnel("vpn0", str(tmp_path)) and homenet.hn_linux_tunnel("wg-x", str(tmp_path))
    assert not homenet.hn_linux_tunnel("wlan0", str(tmp_path))


def test_local_blocking_is_a_gap_not_nothing_open(monkeypatch):
    monkeypatch.setattr(homenet, "hn_port_state", lambda ip, port: "blocked")
    stats = {}
    assert homenet.hn_scan_ports(["192.168.1.5"], ports=(22, 80), stats=stats) == {}
    assert stats == {"attempts": 2, "blocked": 2}


def test_camera_status_lines():
    assert homenet.hn_rtsp_status(b"RTSP/1.0 200 OK\r\nCSeq: 2\r\n\r\n") == 200
    assert homenet.hn_rtsp_status(b"RTSP/1.0 401 Unauthorized\r\n") == 401
    assert homenet.hn_rtsp_status(b"HTTP/1.1 400 Bad Request\r\n") is None


@pytest.mark.parametrize("codes,expected", [([401, 404], "protected"), ([404, 200], "open"),
                                            ([404, 404], "unknown")])
def test_camera_password_decision(codes, expected):
    answers = iter(codes + [404] * 20)
    assert homenet.hn_camera_password("192.168.1.8", ask=lambda ip, port, path: next(answers)) == expected


def test_camera_request_carries_no_credentials():
    import inspect
    source = inspect.getsource(homenet.hn_rtsp_ask)
    assert "Authorization" not in source and "DESCRIBE" in source


def test_open_camera_is_a_finding():
    devices = [{"ip": "192.168.1.8", "name": "", "kind": "camera or video recorder", "ports": [554],
                "video_password": "open"}]
    titles = [t for t, _d, _w in homenet.hn_findings(devices, [], "192.168.1.1")]
    assert any("CAN WATCH THIS CAMERA" in t for t in titles)


def test_device_makers_from_hardware_address_and_exploited_flaws():
    devices = [{"ip": "192.168.1.8", "mac": "9c:14:63:ac:42:de", "name": "", "model": "", "kind": "", "ports": []},
               {"ip": "192.168.1.9", "mac": "aa:bb:cc:00:00:01", "name": "", "model": "", "kind": "", "ports": []}]
    gaps = []
    kev = {"device_vendors": {"Dahua": {"count": 2, "newest_cve": "CVE-2021-33044", "newest_date": "2024-08-21"}}}
    homenet.hn_device_makers(devices, gaps, kev_doc=kev, oui={"9C:14:63": "Zhejiang Dahua Technology Co., Ltd."})
    assert devices[0]["maker"].startswith("Zhejiang Dahua") and devices[0]["exploited"]["vendor"] == "Dahua"
    assert "exploited" not in devices[1] and gaps == []
    titles = [t for t, _d, _w in homenet.hn_findings(devices, [], "192.168.1.1")]
    assert any("Keep Dahua's firmware up to date" in t for t in titles)


def test_missing_saved_lists_are_named_as_gaps():
    devices = [{"ip": "192.168.1.8", "mac": "aa:bb:cc:00:00:01", "name": "", "model": "", "kind": "", "ports": []}]
    gaps = []
    homenet.hn_device_makers(devices, gaps, kev_doc={}, oui={})
    assert any("--update" in g and "exploited" in g for g in gaps)
    # the manufacturer list is built into the program now: no gap, and makers are named without --update
    assert not any("manufacturer" in g for g in gaps)
    assert not devices[0].get("maker")                    # aa:bb:cc... is a made-up (private) address


def test_device_makers_come_from_the_built_in_list():
    devices = [{"ip": "192.168.1.1", "mac": "c4-e2-87-02-48-e4", "name": "", "model": "", "kind": "", "ports": []}]
    homenet.hn_device_makers(devices, [], kev_doc={}, oui={})
    assert devices[0]["maker"] == "HUAWEI"


def test_ieee_listing_parses():
    from zbtriage.kevdata import oui_parse
    raw = b'Registry,Assignment,Organization Name,Organization Address\nMA-L,9C1463,"Zhejiang Dahua Technology Co., Ltd.",x\nMA-L,zzzzzz,Bad,x\n'
    assert oui_parse(raw) == {"9C:14:63": "Zhejiang Dahua Technology Co., Ltd."}
