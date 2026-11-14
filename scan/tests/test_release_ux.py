"""Plain words for people who are not technical (2026-11-14): meanings, progress, sending for help, welcome back."""
import json
import os

from zbtriage import report
from zbtriage import resume


# 3. what a worth-a-look item means, in plain words
def test_common_items_have_a_plain_meaning():
    cases = [({"check": "android:settings", "what": "apps with accessibility access: com.x"}, "screen"),
             ({"check": "android:settings", "what": "apps that are device admins: com.x"}, "lock the phone"),
             ({"check": "android:packages", "what": "com.example installed by hand"}, "app store"),
             ({"check": "android:packages", "what": "all internet traffic is set to go through this app's VPN: x"},
              "internet traffic"),
             ({"check": "defender-history", "what": "2 Defender exclusion(s) added"}, "skip"),
             ({"check": "root-certificates", "what": "A root certificate was added"}, "secure web traffic"),
             ({"check": "browser-accounts", "what": "A browser here is signed in"}, "sign it out")]
    for item, word in cases:
        assert word in report.plain_meaning(item), item


def test_an_unknown_item_gets_no_made_up_meaning():
    assert report.plain_meaning({"check": "something-new", "what": "x"}) == ""


def test_meanings_never_name_the_project_or_ai():
    for _p, _w, meaning in report.PLAIN_MEANINGS:
        low = meaning.lower()
        assert " ai " not in " " + low + " " and "zero breach" not in low


# 13. welcome back: the unfinished step is remembered, expires, and is cleared
def test_an_unfinished_step_is_remembered_and_cleared(tmp_path):
    path = str(tmp_path / "step.json")
    resume.resume_save("iphone-backup", {"baseline": {"C:/b/1": 1.5}}, path)
    step = resume.resume_load(path)
    assert step["kind"] == "iphone-backup" and step["data"]["baseline"] == {"C:/b/1": 1.5}
    resume.resume_clear(path)
    assert resume.resume_load(path) == {} and not os.path.exists(path)


def test_an_old_or_damaged_step_is_forgotten(tmp_path):
    path = str(tmp_path / "step.json")
    resume.resume_save("iphone-backup", {"baseline": {}}, path)
    started = json.load(open(path))["started"]
    assert resume.resume_load(path, now=started + (resume.RS_MAX_AGE_DAYS + 1) * 86400) == {}
    assert not os.path.exists(path)
    open(path, "w").write("{not json")
    assert resume.resume_load(path) == {}


def test_remembering_never_fails_the_caller(tmp_path):
    blocked = tmp_path / "file"
    blocked.write_text("x")
    resume.resume_save("iphone-backup", {"baseline": {}}, str(blocked / "inside" / "step.json"))   # cannot be made


# 7. the helpers listed: the MOD-channel instruction is there, files are never to be posted in the group
def test_the_telegram_line_says_ask_a_moderator_and_never_post_files():
    from zbtriage import gui
    tg = [h for h in gui.GUI_HELPERS if "t.me" in h[2]][0]
    assert "MOD channel" in tg[1] and "Never post files" in tg[1]
    assert gui.HELPLINE in [h[2] for h in gui.GUI_HELPERS]


# 4. progress: every step has a plain name and every check an expected time
def test_every_step_and_check_has_plain_words():
    from zbtriage import gui
    assert all(name.startswith(("Checking", "Looking", "Reading", "Running")) for name in gui.GUI_STEP_NAMES.values())
    assert {c for c, _l, _d in gui.GUI_CHECKS} <= set(gui.GUI_DURATIONS)


# the two protection doors: an ad blocker in the browsers, and a DNS service that blocks harmful sites
def test_the_ad_blocker_door():
    from zbtriage.modules import doors
    from zbtriage.result import ModuleResult
    r = ModuleResult("doors")
    doors.dr_ad_blocker_door(r, 5, ["uBlock Origin"], None)
    assert r.doors[0].state == doors.DOOR_CLOSED
    r = ModuleResult("doors")
    doors.dr_ad_blocker_door(r, 5, [], None)
    assert r.doors[0].state == doors.DOOR_OPEN and "uBlock Origin" in r.doors[0].fix
    r = ModuleResult("doors")
    doors.dr_ad_blocker_door(r, 0, [], True)                  # Brave blocks ads by itself
    assert r.doors[0].state == doors.DOOR_CLOSED
    r = ModuleResult("doors")
    doors.dr_ad_blocker_door(r, 0, [], None)                  # no browser read: say nothing
    assert not r.doors


def test_the_protective_dns_door():
    from zbtriage.modules import trust
    assert trust.trust_dns_protection([("e", "9.9.9.9", True)]) == ("protected", "Quad9")
    assert trust.trust_dns_protection([("e", "1.1.1.1", True)]) == ("none", "")          # plain, not filtering
    assert trust.trust_dns_protection([("e", "192.168.0.1", False)]) == ("local", "")   # the router decides
    assert trust.trust_dns_protection([("e", "45.90.30.7", True)])[0] == "protected"     # NextDNS


# the plain block: the strength of the evidence decides the words
def _doc(hits=(), gaps=(), doors=(), looks=()):
    return {"verdict": {"status": "hits" if hits else "none", "gaps": list(gaps)},
            "modules": {"m": {"hits": list(hits), "checks": []}}, "doors": list(doors), "worth_a_look": list(looks)}


def _said(doc):
    return {label: text for label, text in report.plain_summary(doc)}


def test_a_spyware_file_on_the_device_is_said_to_be_that():
    said = _said(_doc([{"tier": "primary", "evidence": "on-disk", "indicator": "x"}]))
    assert "found on this device itself" in said["Result"] and "wipe" in said["Do this now"]


def test_an_ad_network_alone_is_said_not_to_be_an_infection():
    doors = [{"door": "browser:ad-blocker", "state": "open"}, {"door": "network:protective-dns", "state": "open"}]
    said = _said(_doc([{"tier": "delivery", "evidence": "contacted", "indicator": "ads.example"}], doors=doors))
    assert "advertising network" in said["Result"] and "does NOT mean this device is infected" in said["What it means"]
    assert "uBlock Origin" in said["Do this next"] and "Quad9" in said["Do this next"]
    calm = _said(_doc([{"tier": "delivery", "evidence": "contacted", "indicator": "ads.example"}]))
    assert "Nothing urgent" in calm["Do this next"]          # protection already in place: no nagging


def test_a_contacted_address_is_not_called_an_infection():
    said = _said(_doc([{"tier": "cc", "evidence": "contacted", "indicator": "c2.example"}]))
    assert "contacted or looked up" in said["Result"] and "NOT proof of infection" in said["What it means"]


def test_a_trace_in_records_is_not_called_contact():
    said = _said(_doc([{"tier": "primary", "evidence": "device-log", "indicator": "x"}]))
    assert "trace" in said["Result"] and "contacted" not in said["Result"]


def test_cellebrite_and_stalkerware_get_their_own_words():
    said = _said(_doc([{"tier": "forensic", "evidence": "device-log", "indicator": "cellebrite"}]))
    assert "Cellebrite" in said["Result"] and "not spyware" in said["What it means"]
    said = _said(_doc([{"tier": "stalkerware", "evidence": "on-device", "indicator": "app"}]))
    assert "stalkerware" in said["Result"] and "stopstalkerware.org" in said["Get help"]


def test_only_a_mention_and_the_clean_cases():
    assert "mention" in _said(_doc([{"tier": "primary", "evidence": "referenced", "indicator": "x"}]))["Result"]
    assert "every check ran" in _said(_doc())["Result"]
    assert "could not be checked" in _said(_doc(gaps=["browser: locked"]))["Result"]


# what happened? - one list for the window and the terminal, every answer leads somewhere real
def test_every_situation_leads_to_a_real_menu_entry():
    from zbtriage import intake, menu
    labels = {i.label for i in menu._MN_ITEMS}
    for key, said, next_, label in intake.INTAKE:
        assert label in labels, label
    assert "stopstalkerware.org" in intake.INTAKE_PARTNER_NOTE


def test_the_terminal_menu_has_the_file_check_and_the_question_mark():
    import io
    from zbtriage import menu
    assert any(i.label == "A suspicious file" for i in menu._MN_ITEMS)
    out = io.StringIO()

    class S:
        def say(self, text):
            out.write(text + "\n")
    menu._mn_render([i for i in menu._MN_ITEMS], S())
    assert "Not sure where to start? Tell me what happened" in out.getvalue()


def test_the_first_open_flag(tmp_path):
    path = str(tmp_path / "flags.json")
    assert not resume.resume_flag("asked-what-happened", path)
    resume.resume_set_flag("asked-what-happened", path)
    assert resume.resume_flag("asked-what-happened", path)


# every separate tool the command line hands off to must be handed off by the single-file build too: once it was
# not, and `--wifi-nearby` in the build silently started a full computer scan instead
def test_the_build_dispatches_every_separate_tool_the_source_does():
    import re
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    cli = open(os.path.join(root, "scan", "zbtriage", "cli.py"), encoding="utf-8").read()
    bundle = open(os.path.join(root, "build", "bundle.py"), encoding="utf-8").read()
    main = cli[cli.index("def _main("):cli.index("def main(")]
    commands = set(re.findall(r"return (\w+_command)\(", main))
    assert "wifi_nearby_command" in commands and len(commands) > 8
    missing = sorted(c for c in commands if c + "(" not in bundle)
    assert not missing, missing


def test_the_wifi_explanations():
    from zbtriage import wifinearby as w
    assert w.wn_vendor("c4:e2:87:00:00:01") == "HUAWEI"
    assert w.wn_private_address("da:a1:19:00:00:01") and not w.wn_private_address("c4:e2:87:00:00:01")
    assert w.wn_same_router("c4:e2:87:02:48:e6", "c4:e2:87:02:48:e4")
    assert not w.wn_same_router("c4:e2:87:02:58:e6", "c4:e2:87:02:48:e4")
    netsh = ("SSID 1 : Home\n    Network type : Infrastructure\n    Authentication : WPA2-Personal\n"
             "    Encryption : CCMP\n    BSSID 1 : c4:e2:87:02:48:e4\n         Signal : 60%\n"
             "         Band : 5 GHz\n         Channel : 48\n"
             "SSID 2 : \n    Network type : Infrastructure\n    Authentication : WPA2-Personal\n"
             "    BSSID 1 : c4:e2:87:02:48:e6\n         Signal : 72%\n         Channel : 36\n")
    nets = w.wn_parse_netsh(netsh)
    assert [n["ssid"] for n in nets] == ["Home", ""] and nets[1]["signal"] == 72 and nets[1]["channel"] == 36
    report = w.wn_report({"networks": nets, "connected": "c4:e2:87:02:48:e4"})
    assert len(report["hidden"]) == 1 and "part of the router you are connected to" in report["hidden"][0]["explain"]
    nm = r"yes:Home:C4\:E2\:87\:02\:48\:E4:60:48:WPA2" + "\n" + r"no::DA\:A1\:19\:00\:00\:01:40:1:WPA2"
    rows, connected = w.wn_parse_nmcli(nm)
    assert connected == "c4:e2:87:02:48:e4" and rows[1]["ssid"] == ""


# the result card's title follows the strength of the evidence, like IN PLAIN WORDS
def test_the_card_title_follows_the_evidence():
    from zbtriage import gui
    def title(hits):
        return gui.gui_headline({"verdict": {"status": gui.V_HITS, "gaps": []}, "modules": {"m": {"hits": hits}}})[1]
    assert title([{"tier": "primary", "evidence": "on-disk"}]) == "Spyware found on this device"
    assert title([{"tier": "stalkerware", "evidence": "on-device"}]).startswith("A phone-monitoring")
    assert title([{"tier": "cc", "evidence": "contacted"}]).startswith("Contact with a spyware address")
    assert title([{"tier": "cc", "evidence": ""}]) == "Something needs a closer look"     # unknown grade stays serious


# hidden Wi-Fi: find it
def test_the_find_it_meter():
    from zbtriage import wifinearby as w
    assert w.wn_meter(72, 60).startswith("#######") and "stronger" in w.wn_meter(72, 60)
    assert "weaker" in w.wn_meter(40, 60) and "about the same" in w.wn_meter(61, 60)
    assert "not heard" in w.wn_meter(None, 60)


def test_the_signal_of_one_network(monkeypatch):
    from zbtriage import wifinearby as w
    monkeypatch.setattr(w, "wn_scan", lambda: {"networks": [{"bssid": "aa:bb:cc:dd:ee:ff", "signal": 55}]})
    assert w.wn_signal_of("AA:BB:CC:DD:EE:FF") == 55 and w.wn_signal_of("11:22:33:44:55:66") is None


# who runs the names in a recording or a DNS log
def test_name_owners():
    from zbtriage import ncinfo as n
    assert n.nc_name_owner("mmg.whatsapp.net") == "Meta" and n.nc_name_owner("api.telegram.org") == "Telegram"
    assert n.nc_name_owner("notgoogle.com") == "" and n.nc_name_owner("149.154.167.51") == "Telegram"
    assert n.nc_owner_summary(["a.google.com", "b.google.com", "x.example"]) == "Google (2), others (1)"


# accounts: the security key comes first, steps link to their pages, answers are kept
def test_the_security_key_advice_comes_first():
    from zbtriage import accounts as a
    assert "physical security key" in a.AC_KEY_ADVICE and "YubiKey" in a.AC_KEY_ADVICE
    assert "fake sign-in page" in a.AC_KEY_ADVICE and "another SIM" in a.AC_KEY_ADVICE
    text = a.ac_render(a.ac_result({}))
    assert text.index("physical security key") < text.index("CHECKED") if "CHECKED" in text else "security" in text
    said = []
    a.ac_terminal(lambda _p: "q", said.append)
    assert "physical security key" in said[0]


def test_steps_link_to_real_pages():
    from zbtriage import accounts as a
    ids = {sid for sid, *_rest in a.AC_STEPS}
    assert set(a.AC_LINKS) <= ids and all(u.startswith("https://") for u in a.AC_LINKS.values())


def test_checklist_answers_are_kept_and_cleared(tmp_path):
    from zbtriage import accounts as a
    path = str(tmp_path / "answers.json")
    a.ac_save_answers({"whatsapp": a.AC_CHECKED, "signal": "nonsense"}, path)
    assert a.ac_load_answers(path) == {"whatsapp": a.AC_CHECKED}
    a.ac_save_answers({}, path)
    assert a.ac_load_answers(path) == {}


# household: the smaller checks' saved results are included
def test_household_reads_smaller_checks(tmp_path):
    import json
    from zbtriage import household as h, wifinearby as w, startup as s
    wifi = tmp_path / "wifi.json"
    w.wn_save({"total": 5, "hidden": [{"bssid": "aa:bb:cc:dd:ee:ff", "vendor": "Espressif", "signal": 70}]}, str(wifi))
    start = tmp_path / "startup.json"
    s.su_save({"entries": [], "grants": [], "gaps": [], "level": "nothing-known", "platform": "win32"}, str(start))
    other = tmp_path / "x.json"
    other.write_text(json.dumps({"tool": "zero-breach-toolkit something else", "level": "clean"}))
    doc = h.hh_combine([str(wifi), str(start), str(other)])
    by_label = {e["label"]: e for e in doc["entries"]}
    assert by_label["Hidden Wi-Fi networks nearby"]["colour"] == h.AMBER
    assert "Espressif" in by_label["Hidden Wi-Fi networks nearby"]["worth_a_look"][0]
    assert by_label["What starts automatically"]["colour"] == h.GREEN
    assert len(doc["unreadable"]) == 1 and "Hidden Wi-Fi" in h.hh_render(doc)


def test_the_build_takes_every_option_the_source_does():
    """The single-file build keeps its own copy of the option list; a missing option is an "unrecognized arguments"
    error for anyone using the .py (found by the terminal sweep: --no-version-check)."""
    import re
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    cli = open(os.path.join(root, "scan", "zbtriage", "cli.py"), encoding="utf-8").read()
    bundle = open(os.path.join(root, "build", "bundle.py"), encoding="utf-8").read()
    pattern = r'add_argument\(\s*"(--[a-z0-9-]+)"'
    missing = sorted(set(re.findall(pattern, cli)) - set(re.findall(pattern, bundle)))
    assert not missing, missing


def test_a_damaged_picture_is_said_plainly():
    import pytest
    """Found by the testing pass: a 6-byte GIF crashed the QR check with struct.error."""
    from zbtriage.qrcheck import QrError, qr_load_image
    for data in (b"GIF89a", b"GIF87a\x01\x00", b"\x89PNG\r\n\x1a\n", b"BM\x00"):
        with pytest.raises(QrError):
            qr_load_image(data)


def test_windows_own_wmi_subscription_is_not_called_an_attack():
    """Team test F2: Windows' built-in "SCM Event Log Filter" was labelled THIS IS HOW AN ATTACK LOOKS."""
    from zbtriage.huntrules import HR_RULES
    from zbtriage.huntwin import hw_match
    rule = next(r for r in HR_RULES if r["id"] == "wmi-persistence")
    builtin = ('Eventfilter = SCM Event Log Filter (refer to its activate eventid:5859); '
               'Consumer = NTEventLogEventConsumer="SCM Event Log Consumer"')
    assert not hw_match({"Id": 5861, "Text": builtin}, rule)
    assert hw_match({"Id": 5861, "Text": builtin + " CommandLineEventConsumer"}, rule)
    assert hw_match({"Id": 5861, "Text": 'Consumer = CommandLineEventConsumer="Updater"'}, rule)


def test_well_known_addresses_have_an_owner():
    """Team test F7: 1.1.1.1 (Cloudflare) and Fastly addresses had no "Who runs it"."""
    from zbtriage import ncinfo as n
    assert n.nc_who("1.1.1.1") == "Cloudflare" and n.nc_who("9.9.9.9").startswith("Quad9")
    assert n.nc_who("151.101.1.140").startswith("Fastly") and n.nc_who("8.8.8.8") == "Google"


def test_the_progress_bar_moves_smoothly_and_never_back():
    """Team test: the bar was choppy - equal shares per step although browsers take most of the time, and it
    flipped between a percentage and a bouncing bar."""
    from zbtriage import gui
    st = {"steps": ["browser", "hash", "host", "traces", "doors"]}
    assert gui.gui_progress_smooth(st) is None                       # before the first step: a bouncing bar
    gui.gui_progress("[*] running check: browser", st)
    st["since"] = 0
    seen = [gui.gui_progress_smooth(st, now=t) for t in (0, 60, 300, 600, 3000)]
    assert seen == sorted(seen) and seen[-1] < 99 and seen[2] > 25     # steady, weighted, never "done" early
    gui.gui_progress("[*]   browser finished in 600s", st)
    after = gui.gui_progress_smooth(st, now=600)
    gui.gui_progress("[*] running check: hash", st)
    assert gui.gui_progress_smooth(st, now=600) >= after               # never backwards across a step change
