"""Check a suspicious email (--check-email FILE): who really sent it, and what it is trying to get you to do.

Targeted spyware usually arrives as a message, and the giveaways are in the parts an email program hides. Save
the message ("Show original" in Gmail, "View source" in Outlook, or the .eml file) and this reads:

  * who it really came from - the envelope sender and the "From:" a person sees are often different;
  * what the receiving mail server decided: SPF, DKIM and DMARC, read from the Authentication-Results the
    person's own provider added, which is the one line in an email an attacker cannot write;
  * a Reply-To that goes somewhere else, so a reply leaves the conversation;
  * display names that look like a person or company while the address does not;
  * the path it travelled, and whether it ever left the sender's own servers;
  * every link and attachment, checked the same way as "Check a link or message" - look-alike names, install
    files, the tricks used to take over an account;
  * attachments that are programs, or documents that can carry macros.

Nothing is opened, no link is visited and nothing is sent anywhere. Levels: known-threat, dangerous,
worth-a-look, nothing-known.
"""
from __future__ import annotations

import email
import email.header
import email.policy
import email.utils
import os
import re
from typing import Dict, List, Tuple

from .i18n import T
from .linkcheck import lc_list, lc_para, lc_say, lc_shown

MC_KNOWN, MC_DANGER, MC_LOOK, MC_NOTHING = "known-threat", "dangerous", "worth-a-look", "nothing-known"
MC_MAX_BYTES = 64 * 1024 * 1024
MC_MAX_PARTS = 200

# Attachment kinds that run, or that can carry something that runs.
_MC_RUNS = (".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf",
            ".wsh", ".hta", ".msi", ".msp", ".cpl", ".jar", ".apk", ".app", ".dmg", ".pkg", ".deb", ".appimage",
            ".lnk", ".url", ".scf", ".reg", ".iso", ".img", ".vhd", ".vhdx", ".mobileconfig", ".desktop")
_MC_MACROS = (".docm", ".dotm", ".xlsm", ".xltm", ".xlam", ".pptm", ".potm", ".ppam", ".sldm", ".xls", ".doc",
              ".ppt", ".rtf", ".pub", ".one", ".chm", ".xll", ".wll", ".ppa")
_MC_ARCHIVES = (".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz", ".cab", ".ace", ".arj", ".lzh", ".z")

# Words used to make a person act without thinking.
_MC_PRESSURE = (
    ("account closure", r"(?i)\b(account will be (closed|suspended|deleted|terminated)|suspend your account|"
                        r"within 24 hours|final (warning|notice)|immediate(ly)? action)"),
    ("password or sign-in", r"(?i)\b(verify your (account|identity|password)|confirm your password|"
                            r"re-?enter your (password|credentials)|unusual sign.?in|sign.?in attempt was blocked)"),
    ("payment", r"(?i)\b(invoice attached|payment (is )?(overdue|pending|failed)|update your (payment|billing)|"
                r"wire transfer|bank details have changed)"),
    ("secrecy", r"(?i)\b(do not (tell|share|discuss)|keep this (confidential|between us)|"
                r"only you can handle this)"),
    ("a document to open", r"(?i)\b(enable (editing|content|macros)|view the (attached|document) to continue|"
                           r"protected document|scanned document attached)"),
)


class McError(ValueError):
    pass


def mc_parse(raw: bytes):
    if len(raw) > MC_MAX_BYTES:
        raise McError(T("that file is larger than 64 MB"))
    try:
        return email.message_from_bytes(raw, policy=email.policy.default)
    except Exception:  # noqa: BLE001 - a broken message is still read as far as it goes
        try:
            return email.message_from_bytes(raw)
        except Exception as exc:  # noqa: BLE001
            raise McError(T("that does not look like a saved email ({why})", why=str(exc)[:80]))


def _mc_text(value) -> str:
    """A header as text, with any encoded words decoded, and never more than one line of trouble."""
    if value is None:
        return ""
    try:
        parts = email.header.decode_header(str(value))
        out = []
        for chunk, charset in parts:
            if isinstance(chunk, bytes):
                out.append(chunk.decode(charset or "utf-8", "replace"))
            else:
                out.append(chunk)
        text = "".join(out)
    except Exception:  # noqa: BLE001
        text = str(value)
    return re.sub(r"[\r\n\t]+", " ", text).strip()[:1000]


def mc_address(value) -> Tuple[str, str]:
    """(display name, address) from a From/Reply-To header."""
    text = _mc_text(value)
    name, addr = email.utils.parseaddr(text)
    return _mc_text(name), (addr or "").strip().lower()


def mc_domain(address: str) -> str:
    return address.rpartition("@")[2].strip("<>[] ").lower()


def _mc_parent(domain: str) -> str:
    """The registered part of a name, roughly: good enough to compare From with the envelope."""
    parts = [p for p in (domain or "").split(".") if p]
    if len(parts) < 2:
        return domain or ""
    if len(parts) >= 3 and len(parts[-1]) == 2 and len(parts[-2]) <= 3:
        return ".".join(parts[-3:])          # co.uk, com.au and the like
    return ".".join(parts[-2:])


def mc_auth_results(message) -> Dict[str, str]:
    """{spf, dkim, dmarc, compauth} as the RECEIVING server decided, from the newest Authentication-Results."""
    out: Dict[str, str] = {}
    headers = message.get_all("Authentication-Results") or []
    headers += message.get_all("ARC-Authentication-Results") or []
    for header in headers:
        text = _mc_text(header).lower()
        for key in ("spf", "dkim", "dmarc", "compauth"):
            if key in out:
                continue
            found = re.search(r"\b" + key + r"\s*=\s*([a-z]+)", text)
            if found:
                out[key] = found.group(1)
    for header, key in (("Received-SPF", "spf"), ("X-MS-Exchange-Organization-AuthAs", "exchange_auth")):
        if key not in out and message.get(header):
            word = _mc_text(message.get(header)).split()[0].lower() if _mc_text(message.get(header)) else ""
            if word:
                out[key] = word.strip(":;,")
    return out


def mc_envelope_sender(message) -> str:
    """The address the sending server gave, from Return-Path or the oldest Received line."""
    for header in ("Return-Path", "X-Envelope-From", "X-Original-Sender"):
        value = message.get(header)
        if value:
            _name, addr = mc_address(value)
            if addr:
                return addr
    received = message.get_all("Received") or []
    for header in reversed(received):
        found = re.search(r"envelope-from\s+<?([^\s>;]+@[^\s>;]+)>?", _mc_text(header), re.I)
        if found:
            return found.group(1).lower()
    return ""


def mc_hops(message) -> List[str]:
    out = []
    for header in reversed(message.get_all("Received") or []):
        text = _mc_text(header)
        found = re.match(r"(?i)\s*from\s+([^\s;(]+)", text)
        out.append((found.group(1) if found else text.split(";")[0])[:120])
    return out[:20]


def _mc_bodies(message) -> Tuple[str, str, List[dict]]:
    """(plain text, html, attachments) - attachments are described, never opened or written out."""
    text_parts, html_parts, attachments = [], [], []
    count = 0
    for part in message.walk():
        count += 1
        if count > MC_MAX_PARTS or part.is_multipart():
            continue
        name = ""
        try:
            name = _mc_text(part.get_filename() or "")
        except Exception:  # noqa: BLE001
            name = ""
        disposition = (part.get_content_disposition() or "").lower()
        ctype = (part.get_content_type() or "").lower()
        try:
            payload = part.get_payload(decode=True) or b""
        except Exception:  # noqa: BLE001
            payload = b""
        if name or disposition == "attachment":
            attachments.append({"name": name or "(no name)", "type": ctype, "size": len(payload),
                                "inline": disposition == "inline"})
            continue
        if ctype == "text/plain":
            text_parts.append(payload.decode(part.get_content_charset() or "utf-8", "replace"))
        elif ctype == "text/html":
            html_parts.append(payload.decode(part.get_content_charset() or "utf-8", "replace"))
    return "\n".join(text_parts)[:400000], "\n".join(html_parts)[:400000], attachments


def mc_links_in_html(html: str) -> List[Tuple[str, str]]:
    """[(address, the text the person sees)] for every link, so a hidden mismatch can be seen."""
    out = []
    for match in re.finditer(r"(?is)<a\b[^>]*href\s*=\s*(\"([^\"]*)\"|'([^']*)'|([^\s>]+))[^>]*>(.*?)</a>",
                             html or ""):
        href = (match.group(2) or match.group(3) or match.group(4) or "").strip()
        shown = re.sub(r"(?s)<[^>]+>", " ", match.group(5) or "")
        shown = re.sub(r"\s+", " ", shown).strip()[:200]
        if href:
            out.append((href, shown))
        if len(out) > 400:
            break
    return out


def mc_check(raw: bytes, iocs=None) -> Dict[str, object]:
    from .linkcheck import LC_DANGER, LC_KNOWN, LC_LOOK, lc_check_text, lc_refang
    message = mc_parse(raw)
    from_name, from_addr = mc_address(message.get("From"))
    reply_name, reply_addr = mc_address(message.get("Reply-To"))
    envelope = mc_envelope_sender(message)
    auth = mc_auth_results(message)
    text, html, attachments = _mc_bodies(message)
    links = mc_links_in_html(html)
    findings: List[dict] = []
    notes: List[str] = []

    def add(level, what, why):
        findings.append({"level": level, "what": what if isinstance(what, str) and hasattr(what, "tpl")
                         else lc_say(what), "why": why if hasattr(why, "tpl") else lc_say(why)})

    from_domain = mc_domain(from_addr)
    # 1. what the receiving server decided
    spf, dkim, dmarc = auth.get("spf", ""), auth.get("dkim", ""), auth.get("dmarc", "")
    if dmarc == "fail" and dkim != "pass":
        add(MC_DANGER, "the sender's own domain says this is not from them",
            lc_say("The server that received it checked with {sender} and the answer was: SPF {spf}, DKIM {dkim}, "
                   "DMARC fail. {domain} publishes a rule saying who may send mail for it, and this message breaks "
                   "that rule: it claims to be from them and was not sent by them.",
                   sender=from_domain or lc_say("the sender"), spf=spf or lc_say("not checked"),
                   dkim=dkim or lc_say("not checked"), domain=from_domain or lc_say("That domain")))
    elif spf in ("fail", "softfail") or dkim == "fail" or dmarc == "fail":
        add(MC_LOOK, "part of the sender check did not pass",
            lc_say("SPF {spf}, DKIM {dkim}, DMARC {dmarc}. Mailing lists and forwarded mail break these honestly "
                   "- and a passing DKIM means the sender's own signature survived - so this alone is not proof. "
                   "With anything else here, treat it as a forgery.", spf=spf or lc_say("not checked"),
                   dkim=dkim or lc_say("not checked"), dmarc=dmarc or lc_say("not checked")))
    elif not auth:
        notes.append(lc_say("This copy has no Authentication-Results line, so there is no record of what the "
                            "receiving server decided. Save the message from your own mailbox ('Show original') to "
                            "get it."))
    if auth.get("compauth") == "fail":
        add(MC_LOOK, "the mail provider marked the sender as not genuine",
            "Microsoft's own composite check (compauth) failed, which it uses when a message imitates someone.")

    # 2. who it says it is, against who sent it
    if envelope and from_domain and _mc_parent(mc_domain(envelope)) != _mc_parent(from_domain):
        add(MC_LOOK, "it was sent by one domain and signed as another",
            lc_say("The sending server gave {envelope} as the sender, but the message shows {shown}. Newsletters "
                   "and ticket systems do this legitimately; a message about money or passwords should not.",
                   envelope=mc_domain(envelope), shown=from_domain))
    if reply_addr and from_addr and _mc_parent(mc_domain(reply_addr)) != _mc_parent(from_domain):
        add(MC_LOOK, "a reply would go to a different place than the sender",
            lc_say("It is from {sender} but a reply goes to {reply}. This is how a conversation gets moved "
                   "somewhere the real sender cannot see.", sender=from_addr, reply=reply_addr))
    if from_name:
        looks_like = re.search(r"[\w.+-]+@[\w.-]+\.\w+", from_name)
        if looks_like and looks_like.group(0).lower() != from_addr:
            add(MC_DANGER, "the name shown is an email address that is not the real one",
                lc_say("Your email program shows \"{name}\", but the message actually comes from {address}. "
                       "Writing an address in the display name is done to hide the real one.", name=from_name,
                       address=from_addr or lc_say("(no address)")))
        elif from_domain and _mc_name_claims_elsewhere(from_name, from_domain):
            add(MC_LOOK, "the name shown does not match the address",
                lc_say("It is shown as \"{name}\" but sent from {address}. Check it against an address you "
                       "already have for them.", name=from_name, address=from_addr))
    if from_addr and _mc_unicode_trick(from_addr + " " + from_name):
        add(MC_DANGER, "the sender's address or name uses look-alike letters",
            "Letters from another alphabet that look like English ones are used to imitate a real address.")

    # 3. the links and the words, through the link check
    body_for_links = "\n".join([text] + [a for a, _s in links] + [_mc_text(message.get("Subject"))])
    link_result = lc_check_text(body_for_links, iocs)
    for shown_href, shown_text in links:
        # A link whose visible text is itself an address, pointing somewhere else, is the oldest trick there is.
        if not (shown_text and re.match(r"(?i)^(https?://|www\.)", shown_text.strip())):
            continue
        real = re.sub(r"(?i)^https?://", "", lc_refang(shown_href)).split("/")[0].lower().strip("@")
        claimed = re.sub(r"(?i)^(https?://|www\.)", "", shown_text.strip()).split("/")[0].lower()
        if claimed and real and _mc_parent(claimed) != _mc_parent(real.replace("www.", "")):
            add(MC_DANGER, "a link shows one address and goes to another",
                lc_say("It is written as {claimed} but goes to {real}. Hover over a link before following it: "
                       "what is written is just text, and anyone can write anything there.", claimed=claimed,
                       real=real))
            break

    # 4. attachments
    for item in attachments:
        low = item["name"].lower()
        stem = os.path.splitext(low)[0]
        if low.endswith(_MC_RUNS):
            add(MC_DANGER, "an attachment is a program, not a document",
                lc_say("\"{name}\" is a file that runs when it is opened. No ordinary message needs to send one. "
                       "Do not open it.", name=item["name"]))
        elif low.endswith(_MC_MACROS):
            add(MC_LOOK, "an attachment can carry hidden instructions (macros)",
                lc_say("\"{name}\" is an older Office format that can run code when opened. If you were not "
                       "expecting it, do not open it - and never click \"Enable content\".", name=item["name"]))
        elif low.endswith(_MC_ARCHIVES):
            add(MC_LOOK, "an attachment is a compressed folder",
                lc_say("\"{name}\" has to be unpacked to be seen, which is how a program is slipped past a mail "
                       "filter. Check what is inside with the file check before opening anything.",
                       name=item["name"]))
        if stem.endswith(_MC_RUNS) or re.search(r"\.(pdf|docx?|jpe?g|png|txt)\s*\.", low):
            add(MC_DANGER, "an attachment's name hides what it really is",
                lc_say("\"{name}\" is built to look like a document while being something else.",
                       name=item["name"]))
        if _mc_unicode_trick(item["name"]):
            add(MC_DANGER, "an attachment's name uses a hidden character to disguise it",
                lc_say("\"{name}\" contains a character that reverses how the name is shown, a trick for making "
                       "a program look like a document.", name=item["name"]))

    # 5. pressure
    subject = _mc_text(message.get("Subject"))
    whole = subject + "\n" + text + "\n" + re.sub(r"(?s)<[^>]+>", " ", html or "")
    pressure = [name for name, pattern in _MC_PRESSURE if re.search(pattern, whole)]
    if pressure:
        add(MC_LOOK, lc_say("it pushes you to act quickly about {topics}", topics=lc_list(pressure)),
            "Urgency is the oldest part of this: it is there so you act before you check. Whatever it asks, go "
            "to the service yourself, the way you normally do, instead of using anything in this message.")

    if not from_addr and not message.get("Received") and not auth and not message.get("Subject"):
        notes.insert(0, lc_say("This file has none of an email's headers - no sender, no subject, no record of "
                               "being delivered. It may not be a saved message, or only its text was saved. See the "
                               "instructions for saving one properly."))
    level = MC_NOTHING
    order = {MC_KNOWN: 0, MC_DANGER: 1, MC_LOOK: 2, MC_NOTHING: 3}
    link_level = {LC_KNOWN: MC_KNOWN, LC_DANGER: MC_DANGER, LC_LOOK: MC_LOOK}.get(link_result["level"],
                                                                                  MC_NOTHING)
    for candidate in [f["level"] for f in findings] + [link_level]:
        if order[candidate] < order[level]:
            level = candidate
    findings.sort(key=lambda f: order[f["level"]])
    return {"level": level, "findings": findings, "notes": notes, "links": link_result,
            "header": {"from_name": from_name, "from": from_addr, "reply_to": reply_addr,
                       "envelope": envelope, "subject": subject, "date": _mc_text(message.get("Date")),
                       "to": _mc_text(message.get("To")), "message_id": _mc_text(message.get("Message-ID")),
                       "auth": auth, "hops": mc_hops(message)},
            "attachments": attachments, "link_count": len(links)}


_MC_TRICK_CHARS = "‪‫‬‭‮‎‏⁦⁧⁨⁩​­"


def _mc_unicode_trick(text: str) -> bool:
    if any(c in (text or "") for c in _MC_TRICK_CHARS):
        return True
    letters = [c for c in (text or "") if c.isalpha()]
    if not letters:
        return False
    latin = sum(1 for c in letters if c.isascii())
    return 0 < latin < len(letters) and latin >= len(letters) * 0.4


_MC_BRANDS = ("microsoft", "office365", "outlook", "google", "gmail", "apple", "icloud", "amazon", "paypal",
              "facebook", "meta", "instagram", "whatsapp", "signal", "telegram", "dropbox", "docusign",
              "linkedin", "netflix", "bank", "revolut", "wise", "binance", "coinbase", "proton", "zoom",
              "adobe", "github", "oracle", "unhcr", "unicef", "amnesty", "reuters", "bbc")


def _mc_name_claims_elsewhere(name: str, domain: str) -> bool:
    low = (name or "").lower()
    for brand in _MC_BRANDS:
        if re.search(r"\b" + re.escape(brand) + r"\b", low) and brand not in domain:
            return True
    return False


_MC_HEAD = {MC_KNOWN: "THIS EMAIL MATCHES KNOWN SPYWARE", MC_DANGER: "THIS EMAIL IS DANGEROUS",
            MC_LOOK: "WORTH A LOOK", MC_NOTHING: "NOTHING KNOWN"}
_MC_WORD = {MC_KNOWN: "KNOWN SPYWARE", MC_DANGER: "DANGEROUS", MC_LOOK: "WORTH A LOOK", MC_NOTHING: ""}


def mc_headline(result) -> str:
    return _MC_HEAD[result["level"]]


from .safetext import safe_render  # noqa: E402


@safe_render
def mc_render(result) -> str:
    from .linkcheck import lc_render
    head = result["header"]
    auth = head["auth"]
    lines = ["=" * 72, "  " + T("EMAIL CHECK") + "  -  " + T(_MC_HEAD[result["level"]]),
             "  " + T("Nothing was opened, visited or sent anywhere."), "=" * 72, "",
             "  " + T("Subject:") + "   " + (head["subject"] or T("(none)")),
             "  " + T("Shown as:") + "  " + ("{} <{}>".format(head["from_name"], head["from"]) if head["from_name"]
                                            else (head["from"] or T("(no sender)"))),
             "  " + T("Really from (the sending server said):") + " " + (head["envelope"] or
                                                                         T("not recorded in this copy"))]
    if head["reply_to"]:
        lines.append("  " + T("A reply goes to:") + " " + head["reply_to"])
    if head["date"]:
        lines.append("  " + T("Sent:") + "      " + head["date"])
    if auth:
        lines.append("  " + T("Sender checks:") + " " + ", ".join("{} {}".format(k.upper(), v)
                                                                  for k, v in sorted(auth.items())))
    lines.append("")
    if result["findings"]:
        for finding in result["findings"]:
            lines.append("  [{}] {}".format(T(_MC_WORD[finding["level"]] or "NOTE"), lc_shown(finding["what"])))
            lines.append("      " + lc_shown(finding["why"]))
            lines.append("")
    else:
        lines += ["  " + T("Nothing in the message itself stood out."), ""]
    if result["attachments"]:
        lines.append("  " + T("ATTACHMENTS (not opened)"))
        for item in result["attachments"]:
            lines.append("    - {}  ({}, {})".format(item["name"], item["type"] or T("unknown type"),
                                                     T("{n} bytes", n="{:,}".format(item["size"]))))
        lines.append("")
    if result["link_count"]:
        lines.append("  " + T("LINKS: {n} in the message. The link check says:", n=result["link_count"]))
        for line in lc_render(result["links"]).splitlines():
            if line.strip() and not line.startswith("="):
                lines.append("  " + line)
        lines.append("")
    for note in result["notes"]:
        lines.append("  " + T("note:") + " " + lc_shown(note))
    if result["level"] in (MC_KNOWN, MC_DANGER):
        lines += ["", "  " + T("WHAT TO DO"),
                  "    - " + T("Do not open the attachments and do not follow the links."),
                  "    - " + T("Do not reply: a reply tells the sender the address is real and read.")]
        lines += lc_para(["Keep the message. If you may be a target, get help: Access Now Helpline",
                          "https://www.accessnow.org/help/ (24/7)."], "    - ", "      ")
    else:
        lines.append("")
        lines += lc_para(["Whatever it asks for, go to the service yourself the way you normally do, rather than",
                          "using anything in the message. A message that passes every check can still be a lie told",
                          "from a real account someone else has taken over."], "  ", "  ")
    return "\n".join(lines)


MC_HOW_TO = """  How to save the message:
    Gmail:        open it, the three dots > "Show original" > "Download original" (.txt is fine)
    Outlook.com:  open it, the three dots > "View" > "View message source", copy it into a text file
    Outlook app:  drag the message onto your desktop (.msg), or File > Save As > Text
    Apple Mail:   open it, View > Message > Raw Source, then save
    Thunderbird:  right-click the message > "Save As" (.eml)
  Forwarding the email to yourself does NOT work: it loses the lines that say who really sent it."""


def mc_command(args, load_iocs, out=print) -> int:
    import json
    path = args.check_email
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MC_MAX_BYTES + 1)
    except OSError as exc:
        out(T("That file could not be read: {why}", why=exc))
        return 1
    try:
        iocs = load_iocs(args)
    except Exception as exc:  # noqa: BLE001
        out(T("(Indicator lists could not be loaded: {why}. Checking the message itself only.)",
              why=str(exc)[:160]))
        iocs = None
    try:
        result = mc_check(raw, iocs)
    except McError as exc:
        out("{}\n\n{}".format(exc, T(MC_HOW_TO)))
        return 1
    out(mc_render(result))
    if getattr(args, "json", None):
        with open(args.json, "x", encoding="utf-8") as fh:
            json.dump(dict(result, tool="zero-breach-toolkit email check"), fh, indent=2, ensure_ascii=False)
        out("\n" + T("Saved: {path}", path=args.json))
    return {MC_KNOWN: 3, MC_DANGER: 2, MC_LOOK: 1, MC_NOTHING: 0}[result["level"]]
