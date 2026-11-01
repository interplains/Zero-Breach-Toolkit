"""Wording that depends on how the tool is run (packaged program or script), the
certificate fallback for a bundled OpenSSL, and the window's fall-back to the
terminal when it cannot be built."""
import os
import ssl
import sys
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from zbtriage import feeds, gui, kevdata, localpaths, phoneguide  # noqa: E402
from zbtriage.modules import browser, hashscan  # noqa: E402
from zbtriage.report import _gap_lines  # noqa: E402


def _packaged(monkeypatch, value):
    if value:
        monkeypatch.setattr(sys, "frozen", True, raising=False)
    elif hasattr(sys, "frozen"):
        monkeypatch.delattr(sys, "frozen", raising=False)


# --- Full Disk Access names the app when packaged, Terminal for a script ----------

def test_browser_gap_names_the_app_or_terminal(monkeypatch):
    monkeypatch.setattr(browser.sys, "platform", "darwin")
    exc = PermissionError(1, "Operation not permitted")
    path = "/Users/x/Library/Safari/SafariTabs.db"
    _packaged(monkeypatch, True)
    note = browser._locked_note(path, exc)
    assert "Zero Breach Toolkit Full Disk Access" in note and "Terminal" not in note
    _packaged(monkeypatch, False)
    note = browser._locked_note(path, exc)
    assert "Terminal Full Disk Access" in note and "Zero Breach Toolkit" not in note


def test_hash_gap_names_the_app_or_terminal(monkeypatch):
    monkeypatch.setattr(hashscan.sys, "platform", "darwin")
    reasons = {"denied": 2, "large": 0, "unreadable": 0}
    _packaged(monkeypatch, True)
    text = hashscan._hs_reasons(reasons)
    assert "give Zero Breach Toolkit Full Disk Access" in text and "Terminal" not in text
    _packaged(monkeypatch, False)
    assert "give Terminal Full Disk Access" in hashscan._hs_reasons(reasons)


def test_summary_advice_names_the_app_or_terminal(monkeypatch):
    private_gap = ["browser/safari:safari-tabs: macOS privacy protection blocked Safari (SafariTabs.db), "
                   "so it was not checked. Give Terminal Full Disk Access, then run again."]
    folder_gap = ["hash/root: 3 folder(s) or item(s) could not be opened, so nothing in them was compared "
                  "(3 permission denied); give Terminal Full Disk Access and run again"]
    _packaged(monkeypatch, True)
    assert "Give Zero Breach Toolkit Full Disk Access" in _gap_lines(private_gap)[0]
    assert "Full Disk Access for Zero Breach Toolkit" in " ".join(_gap_lines(folder_gap))
    _packaged(monkeypatch, False)
    assert "Give Terminal Full Disk Access" in _gap_lines(private_gap)[0]
    assert "Full Disk Access for Terminal" in " ".join(_gap_lines(folder_gap))


def test_mac_certificate_hint_for_the_app_has_no_install_certificates_step(monkeypatch):
    _packaged(monkeypatch, True)
    app = feeds._certificate_help(platform="darwin")
    assert "Install Certificates" not in app and "date and time" in app
    _packaged(monkeypatch, False)
    assert "Install Certificates.command" in feeds._certificate_help(platform="darwin")
    # Other systems are unchanged whether packaged or not.
    _packaged(monkeypatch, True)
    assert "ca-certificates" in feeds._certificate_help(platform="linux")


# --- A bundled OpenSSL that found no certificates falls back to the system's ------

class _FakeContext:
    def __init__(self, loaded):
        self.loaded, self.calls = loaded, []
        self.verify_mode, self.check_hostname = ssl.CERT_REQUIRED, True

    def cert_store_stats(self):
        return {"x509_ca": self.loaded}

    def load_verify_locations(self, cafile=None, **kw):
        self.calls.append(cafile)
        self.loaded += 1


def test_empty_default_context_loads_a_system_bundle(monkeypatch):
    ctx = _FakeContext(0)
    monkeypatch.setattr(localpaths.ssl, "create_default_context", lambda *a, **k: ctx)
    wanted = "/etc/pki/tls/certs/ca-bundle.crt"
    monkeypatch.setattr(localpaths.os.path, "isfile", lambda p: p == wanted)
    result = localpaths.tls_context()
    assert result is ctx and ctx.calls == [wanted]
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True


def test_context_with_certificates_is_left_alone(monkeypatch):
    ctx = _FakeContext(140)
    monkeypatch.setattr(localpaths.ssl, "create_default_context", lambda *a, **k: ctx)
    monkeypatch.setattr(localpaths.os.path, "isfile", lambda p: True)
    localpaths.tls_context()
    assert ctx.calls == []


def test_unreadable_bundle_is_skipped_and_verification_stays_on(monkeypatch):
    ctx = _FakeContext(0)
    seen = []

    def load(cafile=None, **kw):
        seen.append(cafile)
        if cafile.endswith("ca-certificates.crt"):
            raise ssl.SSLError("bad bundle")
        ctx.loaded += 1
    ctx.load_verify_locations = load
    monkeypatch.setattr(localpaths.ssl, "create_default_context", lambda *a, **k: ctx)
    monkeypatch.setattr(localpaths.os.path, "isfile", lambda p: True)
    localpaths.tls_context()
    assert len(seen) == 2 and ctx.loaded == 1
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True


def test_real_context_still_verifies():
    ctx = localpaths.tls_context()
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True


def test_bundle_list_covers_the_common_systems():
    for path in ("/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/certs/ca-certificates.crt",
                 "/etc/ssl/ca-bundle.pem", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
                 "/etc/ssl/cert.pem", "/usr/local/etc/openssl/cert.pem",
                 "/opt/homebrew/etc/openssl@3/cert.pem"):
        assert path in localpaths.TLS_CA_BUNDLES


@pytest.mark.parametrize("module, build", [
    (feeds, lambda: feeds._fetch(feeds.SOURCES[0]["url"])),
    (kevdata, lambda: kevdata._kev_fetch(kevdata.KEV_URL, 10)),
])
def test_every_download_uses_the_fallback_context(monkeypatch, module, build):
    handlers = []

    class Boom(Exception):
        pass

    def fake_build_opener(*h):
        handlers.extend(h)
        raise Boom()
    monkeypatch.setattr(module.urllib.request, "build_opener", fake_build_opener)
    sentinel = object()
    monkeypatch.setattr(module, "tls_context", lambda: sentinel)
    with pytest.raises(Exception):
        try:
            build()
        except Boom:
            raise
    https = [h for h in handlers if isinstance(h, module.urllib.request.HTTPSHandler)]
    assert len(https) == 1 and https[0]._context is sentinel


def test_collector_download_uses_the_fallback_context(monkeypatch, tmp_path):
    handlers = []

    class Boom(Exception):
        pass

    def fake_build_opener(*h):
        handlers.extend(h)
        raise Boom()
    monkeypatch.setattr(phoneguide.urllib.request, "build_opener", fake_build_opener)
    sentinel = object()
    monkeypatch.setattr(phoneguide, "tls_context", lambda: sentinel)
    with pytest.raises(Boom):
        phoneguide._phone_download("androidqf_x.zip", "0" * 64, str(tmp_path / "x.zip"))
    https = [h for h in handlers if isinstance(h, phoneguide.urllib.request.HTTPSHandler)]
    assert len(https) == 1 and https[0]._context is sentinel


# --- The window falls back to the terminal on any start-up failure ----------------

def test_window_start_failure_falls_back_to_the_terminal(monkeypatch):
    class FakeRoot:
        destroyed = False

        def destroy(self):
            FakeRoot.destroyed = True

        def mainloop(self):
            raise AssertionError("must not run")

    fake_tk = types.SimpleNamespace(Tk=FakeRoot, TclError=type("TclError", (Exception,), {}))
    monkeypatch.setitem(sys.modules, "tkinter", fake_tk)

    def broken(self, root, hooks):
        raise RuntimeError("cannot load font")
    monkeypatch.setattr(gui.GuiApp, "__init__", broken)
    monkeypatch.setattr(gui, "gui_launched_by_double_click", lambda: False)
    assert gui.gui_main({"lang": "en"}) is None
    assert FakeRoot.destroyed


# --- The "newer version" line during an explicit update ---------------------------

from zbtriage import cli, report  # noqa: E402
from zbtriage.i18n import i18n_set  # noqa: E402


@pytest.mark.parametrize("tag, expect", [
    ("v2.0.1", True), ("2.1.0", True), ("v10.0.0", True),
    ("v2.0.0", False), ("v1.9.9", False), ("v0.1.15", False),
    ("v2.0.1-rc1", False), ("latest", False), ("", False), ("v2.0", False),
    ("v2.0.1; rm -rf", False), (None, False), (7, False),
])
def test_version_notice_compares_strictly(tag, expect):
    note = feeds.version_notice("2.0.0", fetch=lambda: tag)
    assert bool(note) is expect
    if expect:
        assert "is available" in note and "github.com/interplains/Zero-Breach-Toolkit/releases/tag/v" in note


def test_version_notice_is_silent_on_any_failure():
    def boom():
        raise OSError("offline")
    assert feeds.version_notice("2.0.0", fetch=boom) == ""
    assert feeds.version_notice("2.0.0", fetch=lambda: (_ for _ in ()).throw(ValueError("bad json"))) == ""


def test_version_notice_is_translated():
    try:
        i18n_set("de")
        note = feeds.version_notice("2.0.0", fetch=lambda: "v2.0.1")
        assert "2.0.1" in note and "Version 2.0.1 is available" not in note
    finally:
        i18n_set("en")


def _stub_update(monkeypatch):
    summary = {"cache": "c", "ok": 1, "failed": 0, "sources": [{"status": "updated", "indicators": 5}]}
    monkeypatch.setattr(feeds, "update", lambda *a, **k: summary)
    from zbtriage import kevdata

    def no_kev(*a, **k):
        raise kevdata.KevError("skipped")
    monkeypatch.setattr(kevdata, "kev_update", no_kev)


def test_update_prints_the_notice_and_exit_code_is_unchanged(monkeypatch, capsys):
    _stub_update(monkeypatch)
    monkeypatch.setattr(feeds, "_release_tag", lambda: "v99.0.0")
    assert feeds.update_command(None, None) == 0
    assert "Version 99.0.0 is available" in capsys.readouterr().out
    assert "Version 99.0.0 is available" in feeds.LAST_VERSION_NOTICE


def test_update_survives_a_failing_version_check(monkeypatch, capsys):
    _stub_update(monkeypatch)

    def boom():
        raise OSError("rate limited")
    monkeypatch.setattr(feeds, "_release_tag", boom)
    assert feeds.update_command(None, None) == 0
    assert "is available" not in capsys.readouterr().out


def test_flag_turns_the_version_check_off(monkeypatch, capsys):
    _stub_update(monkeypatch)
    calls = []
    monkeypatch.setattr(feeds, "_release_tag", lambda: calls.append(1) or "v99.0.0")
    assert feeds.update_command(None, None, version_check=False) == 0
    assert calls == [] and feeds.LAST_VERSION_NOTICE == ""
    assert "is available" not in capsys.readouterr().out
    assert cli._parse(["--update", "--no-version-check"]).no_version_check is True


def test_a_scan_never_asks_for_the_version(monkeypatch, capsys):
    calls = []
    monkeypatch.setattr(feeds, "_release_tag", lambda: calls.append(1) or "v99.0.0")
    cli.main(["--training", "clean", "--no-banner", "--no-gui"])
    assert calls == []


# --- Advertising-network traces get protective steps ------------------------------

def _ad_hit():
    return {"tier": "delivery", "evidence": "contacted", "indicator": "ads.invalid", "role": "ad",
            "kind": "domain", "sources": []}


def _steps_text(hits):
    lines = []
    report._next_steps(lines.append, hits)
    return "\n".join(lines)


def test_report_gives_blocking_steps_for_ad_traces_only():
    text = _steps_text([_ad_hit()])
    assert "uBlock Origin" in text and "dnsmasq" in text and "archivegenocide.com/scan" in text
    assert "does not call for a spyware helpline referral" in text.replace("\n", " ").replace("    ", " ").replace("  ", " ")


def test_a_real_finding_does_not_get_the_blocking_text():
    real = {"tier": "primary", "evidence": "contacted", "indicator": "bad.invalid", "role": "c2",
            "kind": "domain", "sources": []}
    assert "uBlock Origin" not in _steps_text([real])
    assert "uBlock Origin" not in _steps_text([real, _ad_hit()])
