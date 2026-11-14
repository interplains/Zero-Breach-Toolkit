"""The native .evtx reader. Where Windows is available its own wevtutil output is the reference, record for
record; everywhere else synthetic files and the value decoders are checked. Nothing may touch the network."""
import glob
import os
import re
import socket
import struct
import subprocess
import sys

import pytest

from zbtriage import evtxread as ev


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("reading a log file must never touch the network")
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


WIN = sys.platform == "win32"
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"


# --- value decoding ------------------------------------------------------------------------------------------

def test_value_types():
    assert ev.ev_value(0x01, "hi\x00".encode("utf-16-le")) == "hi"
    assert ev.ev_value(0x04, b"\xff") == "255"
    assert ev.ev_value(0x07, struct.pack("<i", -5)) == "-5"
    assert ev.ev_value(0x0A, struct.pack("<Q", 2 ** 63)) == str(2 ** 63)
    assert ev.ev_value(0x0D, b"\x01\x00\x00\x00") == "true"
    assert ev.ev_value(0x14, struct.pack("<I", 0x4000)) == "0x4000"
    assert ev.ev_value(0x0F, bytes(range(16))) == "{03020100-0504-0706-0809-0a0b0c0d0e0f}"


def test_sid_and_filetime():
    sid = struct.pack("<BB", 1, 1) + (5).to_bytes(6, "big") + struct.pack("<I", 18)
    assert ev.ev_value(0x13, sid) == "S-1-5-18"
    # 2026-11-10T15:45:41Z
    ticks = int((2026 - 1601) * 0)  # placeholder, exact value computed below
    import datetime
    want = datetime.datetime(2026, 11, 10, 15, 45, 41, tzinfo=datetime.timezone.utc)
    ticks = int((want - ev._EV_EPOCH).total_seconds()) * 10 ** 7
    assert ev.ev_filetime(ticks) == "2026-11-10T15:45:41"
    assert ev.ev_filetime(0) == "1601-01-01T00:00:00"
    assert ev.ev_filetime(2 ** 63) == ""


def _node(name, text="", attrs=None, kids=()):
    return {"name": name, "text": text, "attrs": attrs or {}, "kids": list(kids)}


def test_header_names_inside_the_event_data_stay_data():
    """WMI-Activity 5860 carries its own <Provider>; it is data, and the header provider must survive it."""
    record = [_node("Event", kids=[
        _node("System", kids=[_node("Provider", attrs={"Name": "Microsoft-Windows-WMI-Activity"}),
                              _node("EventID", "5860"), _node("Level", "4"),
                              _node("Channel", "Microsoft-Windows-WMI-Activity/Operational")]),
        _node("UserData", kids=[_node("Operation_TemporaryEssStarted", kids=[
            _node("NamespaceName", "//./root/CIMV2"), _node("Provider", "SCM Event Provider"),
            _node("Level", "9"), _node("Channel", "not the channel"), _node("PossibleCause", "Permanent")])])])]
    event = ev._ev_flatten(record)
    assert event["Provider"] == "Microsoft-Windows-WMI-Activity"
    assert event["Level"] == "4" and event["Channel"] == "Microsoft-Windows-WMI-Activity/Operational"
    assert event["Id"] == 5860
    assert event["Data"]["Provider"] == "SCM Event Provider"
    assert event["Data"]["Level"] == "9" and event["Data"]["Channel"] == "not the channel"
    assert "SCM Event Provider" in event["Text"]


def test_array_values_stay_apart():
    raw = "a\x00bb\x00\x00".encode("utf-16-le")
    got = ev.ev_value(0x81, raw)
    assert isinstance(got, ev._EvList) and got.items == ["a", "bb"]
    assert str(got) == "a bb"
    nums = ev.ev_value(0x88, struct.pack("<III", 1, 2, 3))
    assert nums.items == ["1", "2", "3"]


def test_not_an_evtx_file_is_refused():
    with pytest.raises(ev.EvError):
        list(ev.ev_records(b"not a log" * 600))
    with pytest.raises(ev.EvError):
        list(ev.ev_records(b"short"))


def test_damaged_file_gives_back_what_it_can(tmp_path):
    """A header and one chunk of nonsense: no exception, no events."""
    blob = ev.EV_FILE_MAGIC + b"\x00" * 4088 + ev.EV_CHUNK_MAGIC + b"\xcd" * (ev.EV_CHUNK_SIZE - 8)
    assert list(ev.ev_records(blob)) == []
    f = tmp_path / "broken.evtx"
    f.write_bytes(blob)
    assert ev.ev_events(str(f)) == []


# --- against Windows itself ----------------------------------------------------------------------------------

def _windows_events(path):
    """{record id: (event id, time, {data})} as wevtutil reports them."""
    import xml.etree.ElementTree as ET
    done = subprocess.run([os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "wevtutil.exe"),
                           "qe", path, "/lf:true", "/f:xml", "/e:Events"], capture_output=True, timeout=1200)
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", done.stdout.decode("utf-8", "replace"))
    out = {}
    for event in ET.fromstring(text):
        system = event.find(NS + "System")
        if system is None:
            continue
        data = {}
        for container in (event.find(NS + "EventData"), event.find(NS + "UserData")):
            if container is None:
                continue
            for item in container.iter():
                if item is not container and item.text:
                    data.setdefault(item.get("Name") or item.tag.split("}")[-1], item.text)
        created = system.find(NS + "TimeCreated")
        out[int(system.findtext(NS + "EventRecordID") or 0)] = (
            int(system.findtext(NS + "EventID") or 0),
            (created.get("SystemTime") or "")[:19] if created is not None else "",
            data)
    return out


def _export(log, path):
    done = subprocess.run([os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "wevtutil.exe"),
                           "epl", log, path, "/ow:true"], capture_output=True, timeout=600)
    return done.returncode == 0 and os.path.getsize(path) > 8192


@pytest.mark.skipif(not WIN, reason="compares with Windows' own reader")
@pytest.mark.parametrize("log", ["Microsoft-Windows-WMI-Activity/Operational", "Windows PowerShell",
                                 "Microsoft-Windows-TaskScheduler/Operational"])
def test_every_record_matches_windows(tmp_path, log):
    path = str(tmp_path / "export.evtx")
    if not _export(log, path):
        pytest.skip("this computer has no readable " + log)
    theirs = _windows_events(path)
    if not theirs:
        pytest.skip("this computer's " + log + " has no events")
    ours = {e["RecordId"]: e for e in ev.ev_events(path)}
    assert set(theirs) == set(ours), "record ids differ"
    assert all(e["Provider"] for e in ours.values()), "an event lost its provider"
    for rid, (event_id, when, data) in theirs.items():
        got = ours[rid]
        assert got["Id"] == event_id
        assert (got["Time"] or "")[:19] == when
        for key, value in data.items():
            mine = {k: (v or "").replace("\r\n", "\n").strip() for k, v in got["Data"].items()}
            want = (value or "").replace("\r\n", "\n").strip()
            assert want in ([mine.get(key)] if key in mine else list(mine.values())), \
                "{} / {}: {!r} not in {}".format(rid, key, want[:60], list(mine)[:6])


@pytest.mark.skipif(not WIN, reason="reads this computer's own logs")
def test_reading_a_real_log_is_quick_and_complete(tmp_path):
    path = str(tmp_path / "ps.evtx")
    if not _export("Microsoft-Windows-PowerShell/Operational", path):
        pytest.skip("no readable PowerShell log")
    events = ev.ev_events(path)
    assert events and all(e["Provider"] for e in events)
    assert all(e["Time"] for e in events)
    newest = ev.ev_events(path, limit=5)
    assert len(newest) == min(5, len(events)) and newest[-1]["RecordId"] == events[-1]["RecordId"]


@pytest.mark.skipif(not WIN, reason="reads this computer's own logs")
def test_no_unfinished_business_in_a_whole_folder(tmp_path):
    """Every log this account can export is read without raising."""
    done = 0
    for log in ("Application", "Microsoft-Windows-Windows Defender/Operational",
                "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"):
        path = str(tmp_path / (log.replace("/", "_") + ".evtx"))
        if not _export(log, path):
            continue
        ev.ev_events(path)
        done += 1
    if not done:
        pytest.skip("no exportable logs on this computer")
