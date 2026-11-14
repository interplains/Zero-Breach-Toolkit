"""--trackers: Bluetooth tracker advertisements, summarised; no Bluetooth needed for these tests."""
import builtins
from unittest.mock import patch

import pytest

from zbtriage import trackers

TILE = "0000feed-0000-1000-8000-00805f9b34fb"
SMARTTAG = "0000fd5a-0000-1000-8000-00805f9b34fb"
EDDY = "0000feaa-0000-1000-8000-00805f9b34fb"


@pytest.mark.parametrize("manu,svc,uuids,expected", [
    ({0x004C: bytes([0x12, 0x19]) + bytes(25)}, {}, [], ("Apple Find My item (AirTag or similar)", True)),
    ({0x004C: bytes([0x12, 0x02, 0x00, 0x00])}, {}, [], ("Apple Find My item (AirTag or similar)", False)),
    ({0x004C: bytes([0x10, 0x05, 0x01])}, {}, [], None),          # an iPhone's ordinary "nearby" message
    ({}, {SMARTTAG: b"\x01\x02"}, [], ("Samsung SmartTag", None)),
    ({}, {}, [TILE], ("Tile tracker", None)),
    ({}, {EDDY: bytes([0x41]) + bytes(20)}, [], ("Google Find Hub tracker", True)),
    ({}, {EDDY: bytes([0x40]) + bytes(20)}, [], ("Google Find Hub tracker", False)),
    ({}, {EDDY: bytes([0x10]) + bytes(5)}, [], None),               # an ordinary Eddystone URL beacon
    ({0x0006: b"\x01\x09"}, {}, [], None),                           # Microsoft swift pair, not a tracker
])
def test_classify(manu, svc, uuids, expected):
    assert trackers.tk_classify(manu, svc, uuids) == expected


def test_summary_flags_a_separated_tracker_that_stays():
    t0 = 1000.0
    sightings = [("AA", "Apple Find My item (AirTag or similar)", True, -60, t0 + 30 * i) for i in range(11)]
    sightings += [("BB", "Tile tracker", None, -90, t0 + 5)]
    out = trackers.tk_summarise(sightings, minutes=5)
    assert out[0]["address"] == "AA" and out[0]["separated"] and out[0]["persistent"] and out[0]["near"]
    text = trackers.tk_render(out, 5)
    assert "AWAY FROM ITS OWNER" in text and "stopstalkerware" in text
    assert "Tile tracker" in text


def test_a_passing_tracker_is_listed_but_not_flagged():
    out = trackers.tk_summarise([("CC", "Apple Find My item (AirTag or similar)", True, -85, 1000.0)], minutes=5)
    text = trackers.tk_render(out, 5)
    assert "WORTH A LOOK" not in text and "AWAY FROM OWNER" in text


def test_no_trackers_says_what_it_cannot_hear():
    assert "not heard" in trackers.tk_render([], 3)


def test_without_bleak_it_explains_and_does_not_listen():
    real_import = builtins.__import__

    def no_bleak(name, *a, **k):
        if name == "bleak":
            raise ImportError("no bleak")
        return real_import(name, *a, **k)

    class Args:
        trackers = 3
    lines = []
    with patch("builtins.__import__", no_bleak):
        assert trackers.trackers_command(Args(), out=lines.append) == 1
    # not at a terminal (as in a test): it says exactly what to install, and installs nothing
    assert any("bleak==1.1.1" in l and "pip install" in l for l in lines)


class _Done:
    def __init__(self, code, text=""):
        self.returncode, self.stdout, self.stderr = code, text, ""


def test_the_install_says_what_went_wrong():
    for text, words in (("error: externally-managed-environment", "does not allow installing"),
                        ("No module named pip", "has no pip"),
                        ("ERROR: Could not find a version that satisfies", "No ready-made Bluetooth package"),
                        ("network unreachable", "Check the internet connection")):
        lines = []
        assert trackers.tk_install_bleak(lines.append, run=lambda c, t=text: _Done(1, t)) is False
        assert any(words in l for l in lines), (text, lines)


def test_a_successful_install_carries_on(monkeypatch):
    import importlib
    monkeypatch.setattr(importlib, "import_module", lambda name: object())
    lines = []
    assert trackers.tk_install_bleak(lines.append, run=lambda c: _Done(0)) is True
    assert lines[-1].startswith("Installed")


def test_the_install_is_pinned_and_ready_made_only():
    cmd = trackers.tk_install_command()
    assert "bleak==1.1.1" in cmd and "--only-binary=:all:" in cmd


def test_option_is_separate(tmp_path):
    from zbtriage.cli import _parse
    with pytest.raises(SystemExit):
        _parse(["--trackers", "--home-network", "--no-menu"])
    assert _parse(["--trackers", "--no-menu"]).trackers == 3
    assert _parse(["--trackers", "10", "--no-menu"]).trackers == 10


def test_tile_state_unknown_is_never_owner_nearby_and_is_flagged_when_it_stays():
    from zbtriage import trackers as tk
    sightings = [("AA:BB", "Tile tracker", None, -50, 1000.0), ("AA:BB", "Tile tracker", None, -50, 1170.0)]
    summary = tk.tk_summarise(sightings, 3)
    assert summary[0]["separated"] is None
    text = tk.tk_render(summary, 3)
    assert "owner nearby" not in text and "owner unknown" in text
    assert "WORTH A LOOK" in text and "cannot say whether its owner is nearby" in text


def test_owner_nearby_find_hub_is_not_flagged():
    from zbtriage import trackers as tk
    sightings = [("CC:DD", "Google Find Hub tracker", False, -60, 0.0), ("CC:DD", "Google Find Hub tracker", False,
                                                                        -60, 200.0)]
    text = tk.tk_render(tk.tk_summarise(sightings, 3), 3)
    assert "WORTH A LOOK" not in text and "owner nearby" in text


def test_same_tracker_in_three_separate_checks_is_important():
    from zbtriage import trackers as tk
    t0 = 1_700_000_000.0
    history = []
    for when in (t0, t0 + 1800, t0 + 3600):
        summary = tk.tk_summarise([("AA:BB", "Tile tracker", None, -60, when), ("AA:BB", "Tile tracker", None, -60,
                                                                                  when + 200)], 3)
        history = tk.tk_history_update(summary, history, when + 200)
    assert summary[0]["checks_seen"] == 3
    text = tk.tk_render(summary, 3)
    assert "IMPORTANT" in text and "3 separate checks" in text


def test_checks_minutes_apart_count_once_and_history_expires():
    from zbtriage import trackers as tk
    t0 = 1_700_000_000.0
    tracker = [{"address": "AA:BB", "kind": "Tile tracker"}]
    history = tk.tk_history_update([dict(tracker[0])], [], t0)
    history = tk.tk_history_update([dict(tracker[0])], history, t0 + 60)
    probe = [dict(tracker[0])]
    tk.tk_history_update(probe, history, t0 + 120)
    assert probe[0]["checks_seen"] == 1                 # all within 10 minutes: one place
    probe = [dict(tracker[0])]
    tk.tk_history_update(probe, history, t0 + 2 * 86400)
    assert probe[0]["checks_seen"] == 1                 # older than a day: forgotten
