"""Live connection details: who runs an address, what it and its port are (2026-11-14)."""
from zbtriage import ncinfo as n


def test_who_runs_an_address_from_the_built_in_lists():
    assert n.nc_who("142.250.185.78") == "Google"
    assert n.nc_who("104.16.132.229") == "Cloudflare"
    assert n.nc_who("157.240.1.35") == "Meta"
    assert n.nc_who("17.253.144.10") == "Apple"
    assert n.nc_who("192.168.1.1") == "your network"
    assert n.nc_who("127.0.0.1") == "this computer"
    assert n.nc_who("224.0.0.251") == "local broadcast"
    assert n.nc_who("not an address") == ""


def test_details_say_what_the_address_port_and_state_are():
    rows = dict(n.nc_details({"remote": "142.250.185.78", "remote_port": 443, "state": "TIME_WAIT", "pid": 0}))
    assert "the internet" in rows["Address"] and rows["Run by"].startswith("Google")
    assert "secure web" in rows["Port"] and "just been closed" in rows["State"]


def test_a_hidden_program_says_why_and_what_to_do():
    rows = dict(n.nc_details({"remote": "10.0.0.5", "remote_port": 9999, "state": "ESTABLISHED", "pid": 999999999}))
    assert "administrator" in rows["Program"] and "your own network" in rows["Address"]
    assert "no common use" in rows["Port"]
