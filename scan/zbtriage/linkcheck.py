"""Check a suspicious link or message (--check-link / --check-message): offline, never opens anything.

A person pastes a text message, a WhatsApp/Signal message, an email body or a single link. This finds every link
and address in it (including "defanged" ones such as hxxp://example[.]com), and judges each one:

  * against the spyware indicators the scan uses (built-in and downloaded lists), including parent domains;
  * against patterns from documented attacks on journalists and activists:
      - Signal "link a device" phishing: sgnl://linkdevice links and Signal-branded sites that are not Signal's own
        (Google Threat Intelligence, Feb 2025);
      - WhatsApp account-linking lures: QR codes or pairing codes "to join a group / view a photo"
        (Microsoft on Star Blizzard, Jan 2025; Gen Digital "GhostPairing", Dec 2025);
      - Predator-style SMS ("new WhatsApp login - terminate it") and look-alike messenger domains
        (Citizen Lab, Sep 2023);
      - Pegasus-style links: short links, random short paths, random sub-domains on high ports
        (Amnesty International forensic methodology, 2021);
  * and against general phishing signs: link shorteners, raw IP addresses, look-alike and mixed-script names,
    a fake address before "@", downloads of apps / profiles / programs.

Nothing is opened, resolved, fetched or sent anywhere: this is text comparison only.
All code and lists here are this project's own work.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Dict, List, Optional, Tuple

from .i18n import T


class LcText(str):
    """English text that remembers the sentence it was made from, so a result is stored (and saved as JSON) in
    English but shown in the chosen language. Used by the separate checks' results (link, email, QR, recording,
    Windows records)."""
    tpl = None
    vals = None


def lc_say(template: str, **values) -> "LcText":
    """An English sentence with {name} placeholders filled in, which lc_shown() can translate later."""
    text = LcText(template.format(**values) if values else template)
    text.tpl, text.vals = template, values
    return text


def lc_shown(text):
    """Text in the chosen language: an lc_say() sentence is translated with its values (themselves translated
    when they are lc_say() sentences too); any other text is looked up as it is, and left as it is if unknown."""
    if isinstance(text, LcText) and text.tpl is not None:
        return T(text.tpl, **{k: lc_shown(v) if isinstance(v, LcText) else v for k, v in text.vals.items()})
    return T(text) if isinstance(text, str) and text else text


def lc_list(words) -> "LcText":
    """"a, b, c" from English words, each translated on its own when shown."""
    words = list(words)
    return lc_say(", ".join("{w%d}" % i for i in range(len(words))),
                  **{"w%d" % i: lc_say(w) for i, w in enumerate(words)})


def lc_para(lines, first="  ", rest="  ", width=78) -> List[str]:
    """A paragraph written over several report lines: unchanged in English; in another language the whole
    sentence is translated (the catalogue holds it joined) and wrapped again."""
    from .i18n import i18n_lang
    if i18n_lang() == "en":
        return [(first if i == 0 else rest) + line for i, line in enumerate(lines)]
    import textwrap
    return textwrap.wrap(T(" ".join(line.strip() for line in lines)), width, initial_indent=first,
                         subsequent_indent=rest, break_long_words=False, break_on_hyphens=False)


LC_KNOWN, LC_DANGER, LC_LOOK, LC_NOTHING = "known-threat", "dangerous", "worth-a-look", "nothing-known"
_LC_ORDER = {LC_KNOWN: 0, LC_DANGER: 1, LC_LOOK: 2, LC_NOTHING: 3}

# --- "defanged" spellings people use when sharing suspicious links -------------------------------------------
_LC_FANG = [
    (re.compile(r"\bhxxp(s?)://", re.I), r"http\1://"),
    (re.compile(r"\bhxxp(s?)\[:\]//", re.I), r"http\1://"),
    (re.compile(r"\bh\[tt\]p(s?)://", re.I), r"http\1://"),
    (re.compile(r"\[\s*(?:\.|dot)\s*\]|\(\s*(?:\.|dot)\s*\)|\{\s*(?:\.|dot)\s*\}", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
]

# Schemes worth reporting even without a web address.
_LC_URL = re.compile(
    r"""(?ix)
    (?:\b(?:https?|ftp|sgnl|whatsapp|tg|intent|market|itms-services|javascript|data|file)
       :(?://)?[^\s<>"'​]+)
    |(?:\bwww\.[^\s<>"'​]+)
    """)
# A bare host name: labels of letters/digits/hyphens (any script), a known top-level domain, optional port/path.
_LC_BARE = re.compile(r"(?<![@\w.-])((?:[\w-]{1,63}\.)+([a-z¡-￿-]{2,24}|xn--[a-z0-9-]{2,30}))"
                      r"(:\d{1,5})?(/[^\s<>\"']*)?", re.I)

# Common top-level domains. A bare word like "file.txt" or "e.g" is not treated as an address: names ending in a
# file-type extension are skipped below, and bare names need a known ending (all two-letter country endings count).
_LC_TLDS = set("""com net org info biz io co me tv cc app dev page site online store shop xyz top club live news
blog cloud tech link click space website fun icu buzz vip work life world today email support help services
center group digital agency media network systems solutions host host press studio ltd gov edu mil int
mobi name pro asia tel travel jobs museum xxx sbs cfd rest cyou quest bond mov zip lol pics ink one global
social chat pw ws run tk ml ga cf gq""".split())
_LC_FILE_EXT = set("""txt pdf doc docx xls xlsx ppt pptx csv json xml yml yaml md html htm js ts py sh bat ps1 exe
dll msi apk ipa dmg pkg zip rar 7z gz tar jpg jpeg png gif webp heic mp4 mov mp3 wav log ini cfg conf""".split())

# Link shorteners hide the real destination (curated by this project).
# (t.co and lnkd.in are left out: X and LinkedIn wrap EVERY shared link in them, so they say nothing.)
_LC_SHORTENERS = set("""bit.ly bitly.com tinyurl.com goo.gl ow.ly buff.ly is.gd v.gd cutt.ly rb.gy shorturl.at
t.ly tiny.cc rebrand.ly s.id bl.ink short.gy soo.gd qr.ae adf.ly shorte.st bc.vc gg.gg u.to cli.re
shorturl.com tiny.one rotf.lol shrtco.de urlz.fr x.gd 2u.pw clck.ru vk.cc did.li tny.im""".split())

# Endings that are cheap and widely abused. Weak on their own.
_LC_RISKY_TLDS = set("zip mov top xyz click link quest cfd sbs rest icu cyou buzz tk ml ga cf gq pw bond lol".split())

# Downloads that install something.
_LC_INSTALLS = {
    "apk": "an Android app (installing apps from outside the Play Store is how most phone stalkerware arrives)",
    "xapk": "an Android app bundle", "apks": "an Android app bundle",
    "mobileconfig": "an iPhone/Mac configuration profile (it can route your traffic or let someone manage the device)",
    "ipa": "an iPhone app", "exe": "a Windows program", "msi": "a Windows installer", "scr": "a Windows program",
    "bat": "a Windows script", "cmd": "a Windows script", "ps1": "a PowerShell script", "vbs": "a Windows script",
    "js": "a script that Windows can run", "hta": "a Windows program disguised as a web page", "lnk": "a shortcut "
    "that runs a command", "iso": "a disk image (often used to slip programs past warnings)", "img": "a disk image",
    "vhd": "a disk image", "vhdx": "a disk image", "dmg": "a Mac disk image", "pkg": "a Mac installer",
    "jar": "a Java program", "docm": "a Word file with macros", "xlsm": "an Excel file with macros",
}

# Who is commonly impersonated, and their real domains. A host that uses one of these names but is not one of the
# real domains (or a sub-domain of one) is a look-alike.
_LC_BRANDS = {
    "signal": ("signal.org", "signal.group", "signal.me", "signal.art"),
    "whatsapp": ("whatsapp.com", "whatsapp.net", "wa.me", "whatsapp.org"),
    "telegram": ("telegram.org", "t.me", "telegram.me", "telesco.pe", "telegra.ph"),
    "google": ("google.com", "google.co.uk", "googleusercontent.com", "goo.gl", "g.co", "youtube.com", "youtu.be", "gmail.com",
               "gstatic.com", "googleapis.com", "withgoogle.com", "google.org"),
    "gmail": ("gmail.com", "google.com"),
    "apple": ("apple.com", "icloud.com", "apple.news", "me.com"),
    "icloud": ("icloud.com", "apple.com"),
    "microsoft": ("microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com", "office365.com",
                  "msn.com", "windows.com", "azure.com", "sharepoint.com", "onedrive.com", "aka.ms"),
    "outlook": ("outlook.com", "live.com", "office.com", "microsoft.com"),
    "office365": ("office.com", "microsoft.com"),
    "facebook": ("facebook.com", "fb.com", "fb.me", "meta.com", "messenger.com"),
    "instagram": ("instagram.com",),
    "twitter": ("twitter.com", "x.com", "t.co"),
    "tiktok": ("tiktok.com",),
    "linkedin": ("linkedin.com", "lnkd.in"),
    "proton": ("proton.me", "protonmail.com", "proton.ch", "pm.me"),
    "protonmail": ("protonmail.com", "proton.me"),
    "tutanota": ("tutanota.com", "tuta.com", "tuta.io"),
    "paypal": ("paypal.com", "paypal.me"),
    "dropbox": ("dropbox.com", "db.tt"),
    "amazon": ("amazon.com", "amazon.co.uk", "amazon.de", "amzn.to", "aws.amazon.com"),
    "aljazeera": ("aljazeera.com", "aljazeera.net"),
    "reuters": ("reuters.com",),
    "bbc": ("bbc.com", "bbc.co.uk"),
    "archivegenocide": ("archivegenocide.com", "archivegenocide.org", "archivegenocide.is"),
}
_LC_ALL_BRAND_DOMAINS = {d for ds in _LC_BRANDS.values() for d in ds}
_LC_BRAND_NAMES = {"whatsapp": "WhatsApp", "icloud": "iCloud", "protonmail": "ProtonMail", "office365": "Office 365",
                   "linkedin": "LinkedIn", "tiktok": "TikTok", "paypal": "PayPal", "aljazeera": "Al Jazeera",
                   "bbc": "BBC", "archivegenocide": "Archive Genocide"}

# Second-level endings where the registrable name is one label further left (curated subset).
_LC_SLD = set("""co.uk org.uk ac.uk gov.uk com.au net.au org.au co.nz co.il org.il ac.il com.br com.ar com.mx co.za
co.jp ne.jp or.jp co.kr com.tr com.eg com.sa com.pk com.ng co.in com.cn com.hk com.tw com.sg com.my co.id
com.ph com.ua com.lb com.jo com.qa com.kw ae.org""".split())

# Characters that look like Latin letters (own curated map: Cyrillic, Greek, digits and common tricks).
_LC_CONFUSE = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i", "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    "Α": "a", "α": "a", "ε": "e", "ο": "o", "ρ": "p", "ι": "i", "κ": "k",
    "ν": "v", "τ": "t", "υ": "u", "χ": "x", "ɡ": "g", "ı": "i", "ɩ": "i",
    "0": "o", "1": "l", "3": "e", "5": "s", "@": "a",
}

# Phrases seen in account-takeover and spyware lures (English; matched case-insensitively).
# Kind "linking" = device-linking / account-takeover lures (Signal, WhatsApp); "lure" = general pressure.
_LC_PHRASES = [
    ("lure", r"\b(?:new|unusual|suspicious)\s+(?:whatsapp\s+|signal\s+|telegram\s+)?(?:login|log-in|sign[- ]in|device)\b",
     "talks about a new or unusual login - a classic lure used to make people tap a link quickly"),
    ("lure", r"\bterminate\s+(?:it|this|the\s+)?(?:session|login|device)?\b", "asks you to 'terminate' a session"),
    ("lure", r"\b(?:verify|confirm|re-?activate|unlock)\s+(?:your\s+)?(?:account|number|identity|device|phone)\b",
     "asks you to verify or unlock an account"),
    ("linking", r"\b(?:pairing|verification|security|login)\s+code\b|\b\d{4}[- ]\d{4}\b",
     "mentions a code - never type a code someone sends you into a page they link to"),
    ("linking", r"\b(?:scan|use)\s+(?:the|this)\s+qr\b|\bqr\s*code\b",
     "asks you to scan a QR code - scanning one can add someone else's device to your account"),
    ("linking", r"\blink(?:ed)?\s+(?:a\s+|your\s+)?device\b|\blinked\s+devices\b", "mentions linking a device"),
    ("lure", r"\bjoin\s+(?:the\s+|our\s+|my\s+)?(?:group|chat)\b", "invites you to join a group"),
    ("lure", r"\b(?:urgent|immediately|within\s+\d+\s+(?:hours?|minutes?)|act\s+now|last\s+warning)\b",
     "pushes you to act urgently"),
]


def lc_refang(text: str) -> str:
    """hxxp://example[.]com -> http://example.com, so defanged links are recognised too."""
    for rx, rep in _LC_FANG:
        text = rx.sub(rep, text)
    return text


def lc_extract(text: str) -> List[str]:
    """Every link or bare address in the text, in order, without duplicates."""
    text = lc_refang(unicodedata.normalize("NFC", text or ""))
    found, seen = [], set()

    def add(u):
        u = u.rstrip(".,;:!?)]}>\"'’”")
        key = u.lower()
        if u and key not in seen:
            seen.add(key)
            found.append(u)
    spans = []
    for m in _LC_URL.finditer(text):
        add(m.group(0))
        spans.append(m.span())
    for m in _LC_BARE.finditer(text):
        if any(a <= m.start() < b for a, b in spans):
            continue
        tld = m.group(2).lower()
        if tld in _LC_FILE_EXT and not m.group(4):
            continue
        if tld.startswith("xn--") or tld in _LC_TLDS or (len(tld) == 2 and tld.isascii() and tld.isalpha()) \
                or not tld.isascii():
            add(m.group(0))
    return found


def _lc_split(url: str) -> Dict[str, object]:
    """Pull scheme, user part, host, port and path out of a link without any library that might fetch things."""
    raw = url.strip()
    m = re.match(r"(?i)^([a-z][a-z0-9+.-]*):(//)?", raw)
    scheme = m.group(1).lower() if m else ""
    rest = raw[m.end():] if m else raw
    if scheme in ("javascript", "data", "sgnl", "whatsapp", "tg", "intent", "market", "itms-services", "file") \
            and not (m and m.group(2)):
        return {"scheme": scheme, "user": "", "host": "", "port": None, "path": rest, "raw": raw}
    if not scheme and raw.lower().startswith("www."):
        scheme = "http"
    authority, _, tail = rest.partition("/")
    path = "/" + tail if tail else ""
    for sep in ("?", "#"):
        if sep in authority:
            authority, _, extra = authority.partition(sep)
            path = sep + extra + path
    user = ""
    if "@" in authority:
        user, _, authority = authority.rpartition("@")
    port = None
    host = authority
    if host.startswith("["):
        host, _, portpart = host[1:].partition("]")
        if portpart.startswith(":") and portpart[1:].isdigit():
            port = int(portpart[1:])
    elif host.count(":") == 1:
        host, _, p = host.partition(":")
        if p.isdigit():
            port = int(p)
    return {"scheme": scheme or "http", "user": user, "host": host.lower().strip("."), "port": port,
            "path": path, "raw": raw}


def lc_host_unicode(host: str) -> str:
    """Show what a punycode name (xn--...) really says."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label[4:].encode("ascii").decode("punycode"))
                continue
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def lc_registered(host: str) -> str:
    """The registrable name (example.co.uk, not mail.example.co.uk), from a small curated list of endings."""
    parts = host.split(".")
    if len(parts) >= 3 and ".".join(parts[-2:]) in _LC_SLD:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def _lc_is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r"\d+", host)) or bool(re.fullmatch(r"0x[0-9a-f]+", host))  # decimal / hex IPs


def _lc_skeleton(text: str) -> str:
    out = "".join(_LC_CONFUSE.get(ch, ch) for ch in unicodedata.normalize("NFKC", text.lower()))
    return out.replace("rn", "m").replace("vv", "w").replace("-", "")


def _lc_distance(a: str, b: str, limit: int = 2) -> int:
    """Edit distance (insert, delete, change, swap neighbours), stopping early past `limit`."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev2, prev = None, list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            if prev2 is not None and i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        if min(cur) > limit:
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1]


def _lc_mixed_script(label: str) -> bool:
    scripts = set()
    for ch in label:
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            scripts.add(name.split(" ")[0] if name else "?")
    return len(scripts) > 1


# Words attackers glue to a brand name (whatsappweb, applesupport, signal-login).
_LC_LURE_WORDS = ("login", "logins", "signin", "secure", "security", "verify", "verification", "support", "help",
                  "group", "groups", "app", "apps", "web", "info", "update", "updates", "account", "accounts",
                  "official", "chat", "desk", "center", "centre", "protect", "protection", "confirm", "auth", "id",
                  "pay", "service", "services", "online", "invite", "join", "link", "device", "devices", "safe",
                  "mail", "cloud", "sync", "check", "alert", "alerts", "notice", "team", "admin", "recovery")


def _lc_brand_word(label: str, brand: str) -> bool:
    """True when `brand` appears in a host label as a word: alone, split off by hyphens or digits, glued to a
    known lure word, or spelled with look-alike characters."""
    for candidate in (label, _lc_skeleton(label)):
        tokens = [t for t in re.split(r"[-_\d]+", candidate) if t]
        if brand in tokens:
            return True
        for t in tokens:
            if t.startswith(brand) and t[len(brand):] in _LC_LURE_WORDS:
                return True
            if t.endswith(brand) and t[:-len(brand)] in _LC_LURE_WORDS:
                return True
    return False


def _lc_official(host: str, domains) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _lc_lookalike(host: str) -> Optional[str]:
    """The brand a host imitates, if it uses or imitates a brand name without being one of its real domains."""
    if not host or _lc_is_ip(host) or _lc_official(host, _LC_ALL_BRAND_DOMAINS):
        return None
    shown = lc_host_unicode(host)
    reg = lc_registered(shown)
    reg_name = reg.split(".")[0]
    labels = shown.split(".")
    for brand, domains in _LC_BRANDS.items():
        if len(brand) < 4:
            continue
        # brand used as a word in any label (signal-groups.tech, whatsapp.com.login.info, whatsappweb.site), but not
        # hidden inside an ordinary word (pineapple, signalfire, amazonas)
        for label in labels[:-1]:
            if _lc_brand_word(label, brand):
                return brand
        # misspelled brand as the registrable name (whatssapp.co, wh4tsapp.com, signa1.org)
        sk = _lc_skeleton(reg_name)
        if sk != brand and len(brand) >= 5 and _lc_distance(sk, brand) <= (1 if len(brand) < 7 else 2):
            return brand
        if sk == brand and reg_name != brand:
            return brand
    return None


def _lc_random_path(path: str) -> bool:
    """A single short path segment of mixed letters and digits (/ikXFZ34ca): typical of one-click exploit links."""
    seg = path.split("?")[0].strip("/")
    if not re.fullmatch(r"[A-Za-z0-9]{6,12}", seg or ""):
        return False
    kinds = sum(bool(re.search(p, seg)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]"))
    return kinds >= 2 and not seg.isdigit()


def _lc_ioc_hits(iocs, host: str, url: str) -> List[Dict[str, str]]:
    hits, seen = [], set()
    if iocs is None:
        return hits
    candidates = []
    if host:
        parts = host.split(".")
        candidates += [".".join(parts[i:]) for i in range(len(parts) - 1)]
        candidates.append(host)
    for value in candidates:
        ind = iocs.lookup(value)
        if ind and ind.value not in seen:
            seen.add(ind.value)
            hits.append(ind.to_dict())
    try:
        for ind in iocs.search(url.lower()):
            if ind.value not in seen and ind.type in ("domain", "ip", "url"):
                seen.add(ind.value)
                hits.append(ind.to_dict())
    except Exception:  # noqa: BLE001 - a matcher problem must not hide the other checks
        pass
    return hits


_LC_AD_TIERS = ("delivery", "historical", "reclaimable", "candiru", "candiru-ip", "cc")


def lc_check_link(url: str, iocs=None) -> Dict[str, object]:
    """Judge one link. Returns {link, host, shown_host, level, reasons:[{level, text}], indicators:[...]}."""
    p = _lc_split(url)
    host, scheme, path = p["host"], p["scheme"], p["path"]
    shown = lc_host_unicode(host) if host else ""
    reasons: List[Tuple[str, str]] = []

    def why(level, template, **values):
        reasons.append((level, lc_say(template, **values)))

    hits = _lc_ioc_hits(iocs, host, p["raw"])
    for h in hits:
        family = h.get("family") or "spyware"
        if h.get("tier") in _LC_AD_TIERS and not h.get("family"):
            why(LC_LOOK, "this address belongs to an advertising network in our lists ({indicator}). An ad link "
                         "is not spyware, but some spyware has been delivered through ads", indicator=h["indicator"])
        else:
            why(LC_KNOWN, "{indicator} is on a published list of {family} infrastructure (source: {source})",
                indicator=h["indicator"], family=family if h.get("family") else lc_say("spyware"),
                source=h.get("source") or lc_say("built-in list"))

    raw_lower = p["raw"].lower()
    if scheme == "sgnl" or "sgnl://" in raw_lower:
        if "linkdevice" in raw_lower:
            why(LC_DANGER, "this is a Signal 'link a new device' link. Opening it adds SOMEONE ELSE'S device to your "
                           "Signal account, letting them read your messages. Signal never sends these")
        else:
            why(LC_LOOK, "a Signal link; real group invites look like https://signal.group/...")
    if scheme in ("javascript", "data"):
        why(LC_DANGER, "a {scheme}: link runs code or hides content instead of opening a page", scheme=scheme)
    if scheme == "itms-services":
        why(LC_DANGER, "installs an iPhone app from outside the App Store")
    if scheme == "intent" or scheme == "market":
        why(LC_LOOK, "opens an Android app or store page directly")
    if p["user"]:
        why(LC_DANGER, "the part before '@' ({user}) is decoration: the link really goes to {host}",
            user=p["user"], host=shown)
    if host:
        if _lc_is_ip(host):
            why(LC_LOOK, "goes to a raw IP address instead of a name - real services almost never do this")
        if "xn--" in host:
            why(LC_DANGER, "the name uses look-alike letters from another alphabet: it really reads '{host}'",
                host=shown)
        elif any(_lc_mixed_script(lbl) for lbl in shown.split(".")):
            why(LC_DANGER, "the name mixes letters from different alphabets, a look-alike trick")
        brand = _lc_lookalike(host)
        if brand:
            real = ", ".join(_LC_BRANDS[brand][:3])
            level = LC_DANGER if brand in ("signal", "whatsapp", "telegram", "apple", "icloud", "google", "gmail",
                                           "microsoft", "outlook", "proton", "protonmail") else LC_LOOK
            why(level, "imitates {brand} but is not one of its real sites ({real})",
                brand=_LC_BRAND_NAMES.get(brand, brand.capitalize()), real=real)
        reg = lc_registered(host)
        if reg in _LC_SHORTENERS or host in _LC_SHORTENERS:
            why(LC_LOOK, "a link shortener: it hides where the link really goes. Spyware links are often sent "
                         "this way")
        tld = host.rsplit(".", 1)[-1]
        if tld in _LC_RISKY_TLDS and not hits:
            why(LC_LOOK, "uses the .{ending} ending, which is cheap and often abused (weak on its own)", ending=tld)
        if p["port"] and p["port"] not in (80, 443, 8080, 8443):
            sub = host.split(".")[:-2]
            randomish = sum(1 for s in sub if re.fullmatch(r"[a-z0-9]{5,}", s) and re.search(r"\d", s))
            if randomish:
                why(LC_DANGER, "random-looking sub-domains on an unusual port ({port}): the pattern of documented "
                               "one-click spyware links", port=p["port"])
            else:
                why(LC_LOOK, "uses an unusual port ({port})", port=p["port"])
        if len(host.split(".")) > 5:
            why(LC_LOOK, "an unusually long chain of sub-domains")
    ext = re.search(r"\.([a-z0-9]{2,12})(?:$|[?#])", path.lower())
    if ext and ext.group(1) in _LC_INSTALLS:
        what = _LC_INSTALLS[ext.group(1)]
        level = LC_DANGER if ext.group(1) in ("apk", "xapk", "apks", "mobileconfig", "ipa", "exe", "msi", "scr",
                                              "hta", "lnk", "vbs", "js", "ps1", "bat", "cmd", "jar") else LC_LOOK
        why(level, "downloads {what}", what=lc_say(what))
    if host and _lc_random_path(path) and not _lc_official(host, _LC_ALL_BRAND_DOMAINS) and \
            lc_registered(host) not in _LC_SHORTENERS:
        why(LC_LOOK, "a short random-looking path ({path}) - typical of single-use exploit links",
            path=path.split("?")[0])
    if "/stadium/pop2.html" in raw_lower or "pop2.html?key=" in raw_lower:
        why(LC_DANGER, "matches a path used by Pegasus delivery links")

    level = min((lv for lv, _ in reasons), key=_LC_ORDER.get, default=LC_NOTHING)
    seen, uniq = set(), []
    for lv, text in sorted(reasons, key=lambda r: _LC_ORDER[r[0]]):
        if text not in seen:
            seen.add(text)
            uniq.append({"level": lv, "text": text})
    return {"link": url, "host": host, "shown_host": shown, "level": level, "reasons": uniq, "indicators": hits}


def lc_check_text(text: str, iocs=None) -> Dict[str, object]:
    """Judge a whole message: every link in it, plus the wording around them."""
    links = [lc_check_link(u, iocs) for u in lc_extract(text)]
    low = (text or "").lower()
    found = [(kind, meaning) for kind, rx, meaning in _LC_PHRASES if re.search(rx, low)]
    phrases = [lc_say(meaning) for _kind, meaning in found]
    level = min([l["level"] for l in links] or [LC_NOTHING], key=_LC_ORDER.get)
    # Wording alone never decides. With a link: any lure phrase makes it at least worth a look, and a
    # device-linking lure (code / QR / link a device) next to a link that already looks wrong is dangerous -
    # that is how Signal and WhatsApp accounts were taken over in the documented campaigns.
    if links and found and level == LC_NOTHING:
        level = LC_LOOK
    if links and any(kind == "linking" for kind, _m in found) and level == LC_LOOK:
        if any(l["level"] == LC_LOOK and l["reasons"] for l in links):
            level = LC_DANGER
    return {"level": level, "links": links, "phrases": phrases, "link_count": len(links)}


_LC_HEAD = {
    LC_KNOWN: "KNOWN SPYWARE INFRASTRUCTURE - do not open it",
    LC_DANGER: "DANGEROUS - do not open it",
    LC_LOOK: "WORTH A LOOK - be careful",
    LC_NOTHING: "NOTHING KNOWN",
}

_LC_ADVICE = {
    LC_KNOWN: ["Do not open the link, and do not forward it to people who might open it.",
               "Keep the message: it is evidence. Take a screenshot that shows the sender and the time.",
               "Get expert help now: Access Now Helpline https://www.accessnow.org/help/ (24/7) or Amnesty Security "
               "Lab https://securitylab.amnesty.org/get-help/",
               "If you already opened it on a phone, check that phone with this toolkit and tell the helpline."],
    LC_DANGER: ["Do not open the link or scan any QR code that came with it.",
                "Never type a code you were sent into a page that a message links to.",
                "If it claims to be from a company or app, open that app or type its real address yourself.",
                "Signal / WhatsApp: open Settings > Linked devices and remove any device you do not recognise."],
    LC_LOOK: ["Do not open it until you have confirmed it with the sender some other way (a call, a different app).",
              "Link shorteners can be expanded safely by a person you trust who is not the target."],
    LC_NOTHING: ["Nothing here matched known spyware or common tricks. That does not prove a link is safe: targeted "
                 "attacks use new addresses. If you did not expect the message, confirm it with the sender first."],
}


def lc_headline(result: Dict[str, object]) -> str:
    """The one-line verdict, for the window's coloured bar."""
    return _LC_HEAD[result["level"]]


from .safetext import safe_render  # noqa: E402


@safe_render
def lc_render(result: Dict[str, object]) -> str:
    lines = ["=" * 72, "  " + T("LINK AND MESSAGE CHECK") + "  -  " + T(_LC_HEAD[result["level"]]),
             "  " + T("Nothing was opened, looked up or sent anywhere: the text was only compared."), "=" * 72, ""]
    if not result["links"]:
        lines.append("  " + T("No links or web addresses found in the text."))
    for i, link in enumerate(result["links"], 1):
        shown = link["link"]
        lines.append("  {}. {}".format(i, shown.replace("http", "hxxp", 1).replace(".", "[.]") if
                                        link["level"] in (LC_KNOWN, LC_DANGER) else shown))
        if link["shown_host"] and link["shown_host"] != link["host"]:
            lines.append("     " + T("really goes to: {host}", host=link["shown_host"]))
        lines.append("     {}".format(T(_LC_HEAD[link["level"]])))
        for r in link["reasons"]:
            lines.append("       - {}".format(lc_shown(r["text"])))
        lines.append("")
    if result["phrases"]:
        lines.append("  " + T("ABOUT THE WORDING"))
        for p in result["phrases"]:
            lines.append("    - " + T("It {what}.", what=lc_shown(p)))
        lines.append("")
    lines.append("  " + T("WHAT TO DO"))
    for a in _LC_ADVICE[result["level"]]:
        lines.append("    - " + T(a))
    if any(l["level"] in (LC_KNOWN, LC_DANGER) for l in result["links"]):
        lines += ["", "  " + T("Dangerous links are shown 'defanged' (hxxp, [.]) so they cannot be clicked by "
                               "accident.")]
    return "\n".join(lines)


def lc_command(args, load_iocs, out=print) -> int:
    """--check-link TEXT (repeatable) and/or --check-message FILE ('-' reads what you paste). Exit 0 / 2 / 3."""
    import json
    import sys
    parts = list(getattr(args, "check_link", None) or [])
    msg = getattr(args, "check_message", None)
    if msg:
        from .scope import scope_message_is_text
        if msg == "-":
            out(T("Paste the message, then press Ctrl+D (Mac/Linux) or Ctrl+Z then Enter (Windows):"))
            parts.append(sys.stdin.read())
        elif scope_message_is_text(msg):
            parts.append(msg)
        else:
            with open(msg, encoding="utf-8", errors="replace") as fh:
                parts.append(fh.read(2_000_000))
    text = "\n".join(parts)
    try:
        iocs = load_iocs(args)
    except Exception as exc:  # noqa: BLE001 - still check the patterns without the lists
        out(T("(Indicator lists could not be loaded: {why}. Checking the patterns only.)", why=str(exc)[:160]))
        iocs = None
    result = lc_check_text(text, iocs)
    out(lc_render(result))
    if getattr(args, "json", None):
        with open(args.json, "x", encoding="utf-8") as fh:
            json.dump(dict(result, tool="zero-breach-toolkit link check"), fh, indent=2, ensure_ascii=False)
        out("\n" + T("Saved: {path}", path=args.json))
    return {LC_KNOWN: 3, LC_DANGER: 2, LC_LOOK: 1, LC_NOTHING: 0}[result["level"]]
