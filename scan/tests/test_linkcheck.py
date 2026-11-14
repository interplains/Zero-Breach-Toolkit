"""Link and message check: offline judgement of links people receive. Nothing may ever be fetched."""
import socket

import pytest

from zbtriage import linkcheck as lc
from zbtriage.iocs import Indicator, IocSet


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("the link check must never touch the network")
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def iocs_with(*values):
    inds = [Indicator(v, "infrastructure", "primary", "domain", "citizenlab-test", "Intellexa Predator") for v in values]
    return IocSet(inds, "test", 0)


def level(text, iocs=None):
    return lc.lc_check_text(text, iocs)["level"]


# --- extraction --------------------------------------------------------------------------------------------
def test_extracts_plain_defanged_and_bare_links():
    text = ("see https://example.org/a, hxxps://bad-site[.]top/x and www.news.example.com plus "
            "evil[.]com/path and file.txt and e.g. this")
    found = lc.lc_extract(text)
    assert "https://example.org/a" in found
    assert "https://bad-site.top/x" in found
    assert "www.news.example.com" in found
    assert "evil.com/path" in found
    assert not any("file.txt" in f for f in found)


def test_extracts_messenger_schemes():
    found = lc.lc_extract("tap sgnl://linkdevice?uuid=abc&pub_key=xyz now")
    assert found == ["sgnl://linkdevice?uuid=abc&pub_key=xyz"]


# --- documented attacks --------------------------------------------------------------------------------------
def test_signal_linkdevice_is_dangerous():
    r = lc.lc_check_link("sgnl://linkdevice?uuid=AAA&pub_key=BBB")
    assert r["level"] == lc.LC_DANGER
    assert "SOMEONE ELSE'S device" in r["reasons"][0]["text"]


@pytest.mark.parametrize("url", ["https://signal-groups.tech/join", "https://group-signal.com/x",
                                 "https://signal-security.online", "https://whatssapp.co/login",
                                 "https://wa-whatsapp-info.com", "https://login-whatsapp.com.verify.site/a"])
def test_messenger_lookalikes_are_dangerous(url):
    assert lc.lc_check_link(url)["level"] == lc.LC_DANGER, url


@pytest.mark.parametrize("url", ["https://signal.org/download", "https://signal.group/#CjQKIA",
                                 "https://wa.me/447700900123", "https://web.whatsapp.com",
                                 "https://www.aljazeera.com/news/2026/11/10/x", "https://archivegenocide.com/scan/",
                                 "https://t.me/somechannel", "https://accounts.google.com/signin"])
def test_real_sites_stay_clean(url):
    r = lc.lc_check_link(url)
    assert r["level"] == lc.LC_NOTHING, (url, r["reasons"])


def test_known_indicator_domain_and_subdomain():
    iocs = iocs_with("wts-app.info")
    r = lc.lc_check_link("https://x7.wts-app.info/abc", iocs)
    assert r["level"] == lc.LC_KNOWN
    assert "Intellexa Predator" in r["reasons"][0]["text"]


def test_pegasus_style_random_subdomains_on_high_port():
    r = lc.lc_check_link("https://k3x9q2.m8z7r1.free247downloads.com:30495/szev4hz")
    assert r["level"] == lc.LC_DANGER
    assert any("unusual port" in x["text"] for x in r["reasons"])


def test_predator_sms_with_shortener_is_worth_a_look_at_least():
    msg = "New WhatsApp login on another device. If this wasn't you, terminate it: https://bit.ly/3xYz9Qa"
    assert lc._LC_ORDER[level(msg)] <= lc._LC_ORDER[lc.LC_LOOK]


def test_whatsapp_pairing_lure_with_suspicious_link_is_dangerous():
    msg = "Someone shared a photo of you! Enter your pairing code 1234-5678 at https://view-photo.top/p"
    assert level(msg) == lc.LC_DANGER


# --- general tricks ------------------------------------------------------------------------------------------
def test_at_sign_trick_names_the_real_host():
    r = lc.lc_check_link("https://www.google.com@evil.example/login")
    assert r["level"] == lc.LC_DANGER
    assert any("really goes to evil.example" in x["text"] for x in r["reasons"])


def test_punycode_shows_the_real_name():
    r = lc.lc_check_link("https://xn--pple-43d.com/")   # "аpple" with a Cyrillic a
    assert r["level"] == lc.LC_DANGER
    assert r["shown_host"] != r["host"]


def test_raw_ip_and_android_app_download():
    r = lc.lc_check_link("http://185.12.34.56/update.apk")
    texts = " ".join(x["text"] for x in r["reasons"])
    assert r["level"] == lc.LC_DANGER and "IP address" in texts and "Android app" in texts


def test_mobileconfig_download_is_dangerous():
    assert lc.lc_check_link("https://secure-vpn.example/profile.mobileconfig")["level"] == lc.LC_DANGER


def test_advertising_tier_is_not_called_spyware():
    iocs = IocSet([Indicator("ads.example", "delivery", "primary", "domain", "adfection", "")], "t", 0)
    r = lc.lc_check_link("https://ads.example/x", iocs)
    assert r["level"] == lc.LC_LOOK and "advertising" in r["reasons"][0]["text"]


def test_no_links_message():
    r = lc.lc_check_text("hello, are we still meeting at 6?")
    assert r["level"] == lc.LC_NOTHING and r["link_count"] == 0
    assert "No links" in lc.lc_render(r)


def test_render_defangs_dangerous_links():
    text = lc.lc_render(lc.lc_check_text("https://signal-groups.tech/join"))
    assert "hxxps://signal-groups[.]tech" in text
    assert "Nothing was opened" in text


@pytest.mark.parametrize("url", ["https://pineapple.com", "https://signalfire.com/about", "https://amazonas.gov.br",
                                 "https://youtu.be/XR4q4uAsDTs", "https://t.co/7rt8Bk226r"])
def test_brand_inside_ordinary_words_and_platform_wrappers_stay_clean(url):
    assert lc.lc_check_link(url)["level"] == lc.LC_NOTHING, (url, lc.lc_check_link(url)["reasons"])


@pytest.mark.parametrize("url", ["https://whatsappweb.site", "https://applesupport-id.com", "https://signal-login.net",
                                 "https://wh4tsapp.com/x", "https://micr0soft-secure.com"])
def test_brand_glued_to_lure_words_is_caught(url):
    assert lc.lc_check_link(url)["level"] in (lc.LC_DANGER, lc.LC_LOOK), url


# --- the terminal menu -------------------------------------------------------------------------------------
class _Terminal:
    def __init__(self, text=""):
        import io
        self._buf = io.StringIO(text)
        self.out = []

    def isatty(self):
        return True

    def readline(self):
        return self._buf.readline()

    def write(self, s):
        self.out.append(s)

    def flush(self):
        pass


def test_terminal_menu_link_entry_checks_pasted_text(monkeypatch):
    from zbtriage import cli, menu
    args = cli._parse(["--no-feeds"])
    items = [i for i in menu._MN_ITEMS]
    number = [i.label for i in items if i.available(menu._MnSession(args, None, None, None, True))].index(
        "A link or message") + 1
    keys = "{}\nNew WhatsApp login, terminate it: https://whatssapp.co/x\n\n\n0\n".format(number)
    err = _Terminal()
    chosen = menu.choose_scan(args, lambda: None, stdin=_Terminal(keys), stderr=err, stdout_visible=True,
                              load_iocs=cli._load_iocs)
    shown = "".join(err.out)
    assert chosen is False
    assert "LINK AND MESSAGE CHECK" in shown and "do not open it" in shown
    assert "CHECK SOMETHING YOU RECEIVED" in shown and "AROUND YOU" in shown


# --- the single-file program must dispatch it too (it has its own entry point) -------------------------------
from test_followup_fixes import bundle  # noqa: E402,F401  (pytest fixture)


def test_bundle_runs_the_link_check_not_a_scan(bundle, capsys, monkeypatch):
    monkeypatch.setattr(bundle, "reader_run", lambda *a, **k: pytest.fail("a computer scan must not start"),
                        raising=False)
    code = bundle._bundle_main(["--no-menu", "--no-banner", "--no-feeds", "--check-link",
                                "sgnl://linkdevice?uuid=a&pub_key=b"])
    assert code == 2
    assert "LINK AND MESSAGE CHECK" in capsys.readouterr().out
