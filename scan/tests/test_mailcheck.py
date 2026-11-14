"""Checking a suspicious email: the forgeries must be caught, and ordinary mail - newsletters, mailing lists,
forwarded messages, calendar invites - must not be called dangerous. Nothing may touch the network."""
import os
import socket
import textwrap

import pytest

from zbtriage import mailcheck as mc
from zbtriage.iocs import Indicator, IocSet


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def refuse(*a, **k):
        raise AssertionError("checking an email must never touch the network")
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)


def mail(headers, body="Hello.", content_type="text/plain; charset=utf-8", extra_parts=()):
    lines = [h for h in headers]
    if extra_parts:
        lines.append('Content-Type: multipart/mixed; boundary="BB"')
        text = "\r\n".join(lines) + "\r\n\r\n--BB\r\nContent-Type: " + content_type + "\r\n\r\n" + body
        for part in extra_parts:
            text += "\r\n--BB\r\n" + part
        text += "\r\n--BB--\r\n"
    else:
        lines.append("Content-Type: " + content_type)
        text = "\r\n".join(lines) + "\r\n\r\n" + body
    return text.encode("utf-8")


PASSES = ("Authentication-Results: mx.example.org; spf=pass smtp.mailfrom=news@bbc.co.uk; "
          "dkim=pass header.i=@bbc.co.uk; dmarc=pass header.from=bbc.co.uk")


# --- forgeries -----------------------------------------------------------------------------------------------

def test_a_domain_that_says_it_is_not_from_them_is_dangerous():
    raw = mail(["From: \"Microsoft Account Team\" <security@microsoft.com>",
                "Return-Path: <bounce@cheap-host.example>",
                "Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=bounce@cheap-host.example; "
                "dkim=fail header.i=@microsoft.com; dmarc=fail header.from=microsoft.com",
                "Subject: Verify your account"])
    result = mc.mc_check(raw)
    assert result["level"] == mc.MC_DANGER
    assert any("not from them" in f["what"] for f in result["findings"])
    assert "microsoft.com" in mc.mc_render(result)


def test_an_address_written_into_the_display_name_is_dangerous():
    raw = mail(["From: \"support@apple.com\" <billing@random-host.example>", PASSES, "Subject: Receipt"])
    result = mc.mc_check(raw)
    assert result["level"] == mc.MC_DANGER
    assert any("name shown is an email address" in f["what"] for f in result["findings"])


def test_a_link_that_shows_one_address_and_goes_to_another_is_dangerous():
    html = '<a href="http://login-help.example/x">https://login.microsoftonline.com</a>'
    raw = mail(["From: <no-reply@login-help.example>", PASSES, "Subject: Sign in"], body=html,
               content_type="text/html; charset=utf-8")
    result = mc.mc_check(raw)
    assert any("shows one address and goes to another" in f["what"] for f in result["findings"])
    assert result["level"] == mc.MC_DANGER


@pytest.mark.parametrize("name", ["Statement.pdf.exe", "invoice.docx.scr", "photo.jpg.lnk", "setup.msi"])
def test_an_attachment_that_runs_is_dangerous(name):
    part = ("Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"{}\"\r\n"
            "\r\nTVo=\r\n".format(name))
    raw = mail(["From: <someone@example.org>", PASSES, "Subject: Document"], extra_parts=(part,))
    result = mc.mc_check(raw)
    assert result["level"] == mc.MC_DANGER
    assert any("program, not a document" in f["what"] or "hides what it really is" in f["what"]
               for f in result["findings"])
    assert result["attachments"][0]["name"] == name


def test_a_right_to_left_trick_in_an_attachment_name_is_caught():
    part = ("Content-Type: application/octet-stream\r\nContent-Disposition: attachment; "
            "filename=\"CV‮gnp.exe\"\r\n\r\nTVo=\r\n")
    raw = mail(["From: <someone@example.org>", PASSES, "Subject: My CV"], extra_parts=(part,))
    result = mc.mc_check(raw)
    assert any("hidden character" in f["what"] for f in result["findings"])


def test_a_macro_document_and_an_archive_are_worth_a_look():
    parts = ("Content-Type: application/vnd.ms-word.document.macroEnabled.12\r\nContent-Disposition: "
             "attachment; filename=\"Report.docm\"\r\n\r\nUEs=\r\n",
             "Content-Type: application/zip\r\nContent-Disposition: attachment; filename=\"files.zip\"\r\n"
             "\r\nUEs=\r\n")
    result = mc.mc_check(mail(["From: <a@example.org>", PASSES, "Subject: Report"], extra_parts=parts))
    whats = " ".join(f["what"] for f in result["findings"])
    assert "macros" in whats and "compressed folder" in whats
    assert result["level"] == mc.MC_LOOK


def test_a_reply_that_goes_somewhere_else_and_pressure_are_noticed():
    raw = mail(["From: \"Finance\" <ap@supplier.example>", "Reply-To: <ap@supplier-payments.example>", PASSES,
                "Subject: Invoice attached - our bank details have changed"])
    result = mc.mc_check(raw)
    whats = " ".join(f["what"] for f in result["findings"])
    assert "reply would go to a different place" in whats and "act quickly" in whats


def test_a_known_indicator_in_a_link_is_a_known_threat():
    iocs = IocSet([Indicator("bad.example", "infrastructure", "primary", "domain", "citizenlab-test",
                             "Predator")], "t", 0)
    raw = mail(["From: <news@example.org>", PASSES, "Subject: Photos"],
               body="Have a look: https://share.bad.example/p/7fK2")
    result = mc.mc_check(raw, iocs)
    assert result["level"] == mc.MC_KNOWN
    assert "KNOWN SPYWARE" in mc.mc_render(result)


def test_a_brand_name_from_an_unrelated_domain_is_worth_a_look():
    raw = mail(["From: \"PayPal Service\" <service@billing-notice.example>", PASSES, "Subject: Your receipt"])
    result = mc.mc_check(raw)
    assert any("name shown does not match the address" in f["what"] for f in result["findings"])


# --- ordinary mail that must stay quiet ----------------------------------------------------------------------

def test_a_normal_newsletter_is_not_called_dangerous():
    raw = mail(["From: \"BBC News\" <news@bbc.co.uk>", "Return-Path: <bounce-123@mail.bbc.co.uk>", PASSES,
                "Subject: Your morning briefing", "List-Unsubscribe: <https://bbc.co.uk/unsub>"],
               body='<p>Top stories <a href="https://www.bbc.co.uk/news/1">Read more</a></p>',
               content_type="text/html; charset=utf-8")
    result = mc.mc_check(raw)
    assert result["level"] in (mc.MC_NOTHING, mc.MC_LOOK)
    assert not any(f["level"] == mc.MC_DANGER for f in result["findings"])


def test_a_mailing_list_that_breaks_spf_honestly_is_only_worth_a_look():
    raw = mail(["From: \"A Person\" <person@their-own-domain.example>",
                "Return-Path: <list-bounces@lists.example.org>",
                "Authentication-Results: mx.example.net; spf=fail smtp.mailfrom=list-bounces@lists.example.org; "
                "dkim=pass header.i=@lists.example.org; dmarc=none header.from=their-own-domain.example",
                "Sender: <list-bounces@lists.example.org>", "List-Id: <dev.lists.example.org>",
                "Subject: Re: the patch"])
    result = mc.mc_check(raw)
    assert result["level"] == mc.MC_LOOK
    assert not any(f["level"] == mc.MC_DANGER for f in result["findings"])
    assert any("not proof" in f["why"] for f in result["findings"])


def test_a_plain_personal_email_says_nothing_stood_out():
    raw = mail(["From: \"Sam\" <sam@example.org>", "Return-Path: <sam@example.org>",
                "Authentication-Results: mx.example.net; spf=pass smtp.mailfrom=sam@example.org; dkim=pass "
                "header.i=@example.org; dmarc=pass header.from=example.org", "Subject: lunch?"],
               body="Are you free on Tuesday?")
    result = mc.mc_check(raw)
    assert result["level"] == mc.MC_NOTHING and result["findings"] == []
    assert "Nothing in the message itself stood out" in mc.mc_render(result)


def test_a_link_shown_as_the_same_site_is_fine():
    html = '<a href="https://www.bbc.co.uk/news/world">https://bbc.co.uk/news</a>'
    raw = mail(["From: <news@bbc.co.uk>", PASSES, "Subject: News"], body=html,
               content_type="text/html; charset=utf-8")
    result = mc.mc_check(raw)
    assert not any("goes to another" in f["what"] for f in result["findings"])


def test_a_pdf_or_image_attachment_is_not_flagged():
    parts = ("Content-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"Ticket.pdf\"\r\n"
             "\r\nJVBE\r\n",
             "Content-Type: image/jpeg\r\nContent-Disposition: attachment; filename=\"photo.jpg\"\r\n\r\n/9j=\r\n")
    result = mc.mc_check(mail(["From: <a@example.org>", PASSES, "Subject: Tickets"], extra_parts=parts))
    assert not any(f["level"] in (mc.MC_DANGER, mc.MC_KNOWN) for f in result["findings"])


def test_a_copy_without_the_provider_line_says_so_rather_than_guessing():
    raw = mail(["From: <someone@example.org>", "Subject: Hello"])
    result = mc.mc_check(raw)
    assert result["notes"] and "Show original" in result["notes"][0]
    assert result["level"] == mc.MC_NOTHING


# --- reading the message -------------------------------------------------------------------------------------

def test_headers_are_decoded_and_the_path_is_read():
    raw = mail(["From: =?utf-8?B?2KPYrdmF2K8=?= <ahmed@example.org>", PASSES,
                "Subject: =?utf-8?Q?Caf=C3=A9_meeting?=",
                "Received: from relay2.example.org (relay2.example.org [198.51.100.2]) by mx.example.net",
                "Received: from phone.example.org (phone [198.51.100.9]) by relay2.example.org"])
    result = mc.mc_check(raw)
    assert result["header"]["subject"] == "Café meeting"
    assert result["header"]["from_name"] == "أحمد"
    assert result["header"]["hops"] and "phone.example.org" in result["header"]["hops"][0]


def test_a_header_cannot_smuggle_extra_lines_into_the_report():
    raw = mail(["From: \"Bad\\r\\nX-Injected: yes\" <a@example.org>", PASSES, "Subject: Hi"])
    result = mc.mc_check(raw)
    assert "\n" not in result["header"]["from_name"] and "\r" not in result["header"]["from_name"]


def test_rubbish_and_empty_files_are_explained():
    for raw in (b"\x00\x01\x02 this is not an email at all" * 10, b"", b"just some text I pasted"):
        result = mc.mc_check(raw)
        assert result["level"] == mc.MC_NOTHING
        assert result["notes"] and "may not be a saved message" in result["notes"][0]


def test_a_very_large_file_is_refused():
    with pytest.raises(mc.McError, match="64 MB"):
        mc.mc_check(b"x" * (mc.MC_MAX_BYTES + 1))


def test_the_report_tells_you_what_to_do_and_how_to_save_a_message():
    raw = mail(["From: \"Microsoft\" <a@elsewhere.example>",
                "Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail header.from=microsoft.com",
                "From: \"Microsoft Account\" <security@microsoft.com>", "Subject: Act now"])
    text = mc.mc_render(mc.mc_check(raw))
    assert "Do not reply" in text and "accessnow.org" in text
    assert "Show original" in mc.MC_HOW_TO and "Forwarding the email to yourself does NOT work" in mc.MC_HOW_TO


def test_domain_helpers():
    assert mc.mc_domain("a.b@Sub.Example.CO.UK") == "sub.example.co.uk"
    assert mc._mc_parent("mail.bbc.co.uk") == "bbc.co.uk"
    assert mc._mc_parent("sub.example.com") == "example.com"
    assert mc._mc_parent("example.com") == "example.com"
    assert mc._mc_parent("localhost") == "localhost"


# --- entry points --------------------------------------------------------------------------------------------
from test_followup_fixes import bundle  # noqa: E402,F401  (pytest fixture)


def test_bundle_checks_an_email_and_does_not_scan(bundle, capsys, monkeypatch, tmp_path):
    monkeypatch.setattr(bundle, "reader_run", lambda *a, **k: pytest.fail("a computer scan must not start"),
                        raising=False)
    path = tmp_path / "message.eml"
    path.write_bytes(mail(["From: <a@example.org>", PASSES, "Subject: Hi"]))
    assert bundle._bundle_main(["--no-menu", "--no-banner", "--no-feeds", "--check-email", str(path)]) == 0
    assert "EMAIL CHECK" in capsys.readouterr().out


def test_a_missing_email_file_is_refused():
    from zbtriage import cli
    with pytest.raises(SystemExit):
        cli._parse(["--check-email", "no-such-message.eml"])
