"""The tracker check speaks plainly: the answer first, and what to do when Bluetooth cannot be used."""
from zbtriage import trackers


def _t(separated, persistent, checks=1):
    return {"address": "A", "kind": "Apple Find My item (AirTag or similar)", "separated": separated,
            "persistent": persistent, "checks_seen": checks, "count": 5, "seen_minutes": 3.0, "strongest": -60,
            "near": True}


def test_answer_first_in_three_levels():
    assert trackers.tk_headline([_t(True, True, checks=3)])[1] == "dangerous"
    assert trackers.tk_headline([_t(True, True)]) == ("A tracker stayed near you - worth a look", "worth-a-look")
    assert trackers.tk_headline([_t(False, True)]) == ("No tracker seems to be following you", "clean")
    assert trackers.tk_headline([_t(True, False)])[1] == "clean"       # heard once in passing
    assert trackers.tk_headline([]) == ("No trackers were heard nearby", "clean")


def test_the_answer_leads_the_report():
    text = trackers.tk_render([_t(True, True, checks=3)], 3)
    assert "RESULT: A tracker may be travelling with you" in text
    assert text.index("RESULT:") < text.index("IMPORTANT")


def test_bluetooth_problems_are_explained_for_each_system():
    off = trackers.tk_plain_error(RuntimeError("Bluetooth device is turned off"), "win32")
    assert off.startswith("Bluetooth is switched off") and "Settings > Bluetooth & devices" in off
    # The messages the library really gives on machines without usable Bluetooth:
    win = trackers.tk_plain_error(RuntimeError("Failed to start scanner. Is Bluetooth turned on?"), "win32")
    assert win.startswith("Bluetooth is switched off, or this computer has no Bluetooth.")
    assert trackers.tk_plain_error(RuntimeError("BLE is unsupported"), "darwin").startswith("No Bluetooth was found")
    bluez = trackers.tk_plain_error(RuntimeError("[org.freedesktop.DBus.Error.ServiceUnknown] The name org.bluez "
                                                 "was not provided by any .service files"), "linux")
    assert bluez.startswith("The Bluetooth service is not running") and "systemctl start bluetooth" in bluez
    mac = trackers.tk_plain_error(RuntimeError("BLE is not authorized - check macOS privacy settings"), "darwin")
    assert mac.startswith("This computer did not allow") and "Privacy & Security > Bluetooth" in mac
    linux = trackers.tk_plain_error(RuntimeError("No Bluetooth adapters found."), "linux")
    assert linux.startswith("No Bluetooth was found") and "systemctl start bluetooth" in linux
    assert "Details:" in trackers.tk_plain_error(RuntimeError("something odd"), "linux")
