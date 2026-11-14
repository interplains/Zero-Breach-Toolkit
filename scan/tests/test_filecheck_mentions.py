"""An address written inside a file: what counts as a finding, and what is only a mention or a list.

Found 2026-11-13: Edge's own language files mention family.microsoft.com (Microsoft Family Safety,
on the Echap stalkerware list) and were called "known spyware"; the toolkit's own Candiru blocklist was told
"do not open it". Neither is spyware."""
from zbtriage import filecheck as fc
from zbtriage.iocs import Indicator, IocSet


def _iocs(extra=()):
    base = [Indicator("family.microsoft.com", "stalkerware", "primary", "domain", "t", "MicrosoftFamilySafe"),
            Indicator("ads.example-delivery.com", "delivery", "primary", "domain", "t", "AdNet"),
            Indicator("c2.spy-example.net", "cc", "primary", "domain", "t", "Spyfam")]
    return IocSet(base + list(extra), "t.txt", None)


def test_a_monitoring_company_website_in_an_ordinary_file_is_only_a_mention(tmp_path):
    path = tmp_path / "lt.pak"
    path.write_bytes(b"\x05\x00 Edge strings ... https://family.microsoft.com/ ... ads.example-delivery.com")
    rec = fc.fc_examine(str(path), _iocs())
    assert rec["level"] == fc.FC_CLEAN and not rec["inside"]
    assert {m["value"] for m in rec["mentions"]} == {"family.microsoft.com", "ads.example-delivery.com"}
    text = fc.fc_render(rec)
    assert "not a finding" in text and "known spyware" not in text


def test_a_spyware_server_inside_a_script_is_a_finding_with_honest_words(tmp_path):
    path = tmp_path / "update.js"
    path.write_bytes(b"var u='https://c2.spy-example.net/x'; fetch(u);")
    rec = fc.fc_examine(str(path), _iocs())
    assert rec["level"] == fc.FC_KNOWN
    assert fc.fc_headline(rec) == ("This file contains an address used by known spyware - do not open it or "
                                   "follow its links")


def test_a_list_of_many_spyware_addresses_is_a_list_not_spyware(tmp_path):
    many = [Indicator("c2-{}.spy-example.net".format(i), "cc", "primary", "domain", "t", "Spyfam") for i in range(12)]
    path = tmp_path / "blocklist.txt"
    path.write_text("! blocklist\n" + "\n".join("||{}^".format(i.value) for i in many), encoding="utf-8")
    rec = fc.fc_examine(str(path), _iocs(many))
    assert rec["indicator_list"] and not rec["inside"] and rec["level"] == fc.FC_CLEAN
    text = fc.fc_render(rec)
    assert "A LIST OF SPYWARE ADDRESSES" in text and "do not open it" not in text


def test_a_program_with_many_spyware_servers_is_still_a_finding(tmp_path):
    many = [Indicator("c2-{}.spy-example.net".format(i), "cc", "primary", "domain", "t", "Spyfam") for i in range(12)]
    path = tmp_path / "svc.exe"
    body = b"".join(i.value.encode() + b"\x00" for i in many)
    path.write_bytes(b"MZ" + b"\x00" * 58 + b"\x40\x00\x00\x00" + b"PE\x00\x00" + b"\x00" * 200 + body)
    rec = fc.fc_examine(str(path), _iocs(many))
    assert rec["kind"] == "windows-program"
    assert rec["level"] == fc.FC_KNOWN and not rec["indicator_list"]
