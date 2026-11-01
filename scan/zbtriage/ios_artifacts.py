"""Independent, bounded iPhone artifact readers and discovery.

Schema selection is explicit and conservative. A matching string is not promoted
to contact or execution merely because it occurs in a cache, plist or attachment.
Format/availability references are documented in docs/IPHONE.md.
"""
import datetime
import json
import os
import plistlib
import re
import sqlite3
import time

from .devicetraces import DT_IOS_PROCESS, dt_ios_process_indicator, dt_ios_strings_in
from .ios_sources import _is_plist
from .result import Lead, EV_REFERENCED, EV_RECEIVED, EV_DEVICE_LOG, EV_CONFIGURED, EV_ON_DEVICE, EV_CONTACTED

# What an installed configuration profile can do, by payload type. A profile is
# how an employer, a school - or an abusive partner or stalkerware seller -
# takes control of an iPhone: managing it remotely, trusting their own root
# certificate (which lets them read encrypted web traffic), or sending traffic
# through their VPN, proxy or DNS. The payload types are Apple's documented
# identifiers; MVT reads profiles the same way.
_IA_PROFILE_POWERS = (
    ("com.apple.mdm", "lets an organisation manage this phone remotely (device management)"),
    ("com.apple.security.root", "makes the phone trust a root certificate, which can be used to read encrypted web traffic"),
    ("com.apple.vpn.managed", "sends traffic through a VPN"),
    ("com.apple.proxy.http.global", "sends web traffic through a proxy"),
    ("com.apple.dnsSettings.managed", "sets which DNS server the phone uses"),
    ("com.apple.dnsProxy.managed", "sends DNS lookups to an app"),
    ("com.apple.webcontent-filter", "filters web content through an app"),
)
_IA_PROFILE_USUAL = (
    "Normal on a work or school phone, and for a DNS or ad filter you set up yourself (for example "
    "AdGuard DNS). If nobody who uses this phone installed it, see Settings > General > VPN & Device "
    "Management, do not remove it yet (it is evidence), and get expert help.")


def _ia_profile_lead(doc):
    """(what, observed) describing an installed profile that can control the
    phone or its traffic, or None for one that cannot."""
    if not isinstance(doc, dict):
        return None
    payloads = doc.get("PayloadContent")
    types = {str(p.get("PayloadType", "")) for p in payloads if isinstance(p, dict)} if isinstance(payloads, list) else set()
    types.add(str(doc.get("PayloadType", "")))
    powers = [text for kind, text in _IA_PROFILE_POWERS if any(t == kind or t.startswith(kind + ".") for t in types)]
    locked = doc.get("PayloadRemovalDisallowed") is True
    if not powers and not locked:
        return None
    name = str(doc.get("PayloadDisplayName") or doc.get("PayloadIdentifier") or "unnamed profile")[:120]
    org = str(doc.get("PayloadOrganization") or "")[:120]
    installed = doc.get("InstallDate")
    observed = installed.isoformat(timespec="seconds") if isinstance(installed, datetime.datetime) else ""
    what = "Installed configuration profile \"{}\"{} that {}.".format(
        name, " from " + org if org else "", "; ".join(powers) if powers else "cannot be removed by the user")
    if powers and locked:
        what += " It cannot be removed by the user."
    return what, observed

_IA_ARTIFACT_LIMIT = 2048
# When a cap is reached, what was already read should be what matters most:
# per-app caches and crash reports, which a phone has hundreds of, come last.
_IA_KIND_ORDER = {"url-cache": 3, "crashes": 2, "app-metadata": 1, "webkit-statistics": 1}
# Per-report caps; reaching one is always a reported gap, never a silent cut.
_IA_RECORD_LIMIT = 5000
_IA_LINE_LIMIT = 200000
# Report types that always name the processes they describe: crash (109 legacy,
# 309), Jetsam memory-pressure event (298) and stackshot (288).
_IA_IDENTITY_REPORTS = ("109", "309", "298", "288")


def ios_exact_identity(indicator, value):
    """Respect publisher case for Unix names, even after feed normalization."""
    if not isinstance(value, str):
        return False
    return value in ios_identity_values(indicator)


def ios_identity_values(indicator):
    """The publisher's original spellings of an identity (case preserved)."""
    originals = []
    for context in indicator.contexts:
        try:
            record = json.loads(context)
            original = record.get("case_sensitive_value", indicator.value) if isinstance(record, dict) else indicator.value
            if isinstance(original, str):
                originals.append(original)
        except (ValueError, TypeError):
            continue
    return originals or [indicator.value]


def ios_history_specs(source, base_specs, gap):
    """Discover known profile layouts; never follow paths taken from app rows."""
    specs = list(base_specs) if source.kind == "backup" else []
    seen = {(s[1], s[2]) for s in specs}
    found = set()
    for domain, path in source.entries:
        match = None
        if source.kind == "backup":
            safari_domain = domain in ("HomeDomain", "AppDomain-com.apple.mobilesafari",
                                        "AppDomainGroup-group.com.apple.safari")
            if safari_domain and re.fullmatch(r"Library/Safari/(?:Profiles/[^/]+/)?History\.db", path):
                match = base_specs[1]
            elif domain == "AppDomain-com.google.chrome" and re.fullmatch(
                    r"Library/Application Support/Google/Chrome/(?:Default|Profile \d+)/History", path):
                match = base_specs[3]
            elif domain.startswith("AppDomainGroup-group.org.mozilla.ios.Firefox") and re.fullmatch(
                    r"(?:profile\.[^/]+|Profiles/[^/]+)/browser\.db", path):
                match = base_specs[4]
        elif source.kind == "filesystem":
            clean = path.removeprefix("private/") if hasattr(path, "removeprefix") else path[8:] if path.startswith("private/") else path
            if clean == "var/mobile/Library/SMS/sms.db":
                match = base_specs[0]
            elif re.fullmatch(r"var/mobile/Library/Safari/(?:Profiles/[^/]+/)?History\.db", clean):
                match = base_specs[1]
            elif clean in ("var/wireless/Library/Databases/DataUsage.sqlite", "var/networkd/netusage.sqlite",
                           "var/networkd/db/netusage.sqlite"):
                match = base_specs[2]
            elif re.fullmatch(r"var/mobile/Containers/Data/Application/[^/]+/Library/Application Support/Google/Chrome/(?:Default|Profile \d+)/History", clean):
                match = base_specs[3]
        if match:
            found.add(match[0])
            if (domain, path) not in seen:
                if len(specs) >= _IA_ARTIFACT_LIMIT:
                    gap("ios:input", "browser/process artifact discovery limit reached")
                    break
                seen.add((domain, path))
                specs.append((match[0], domain, path) + match[3:-1] + (True,))
    # A modern Safari profile can replace the legacy location. Do not manufacture
    # a missing legacy-artifact gap when a supported alternate has been found.
    if source.kind == "backup" and "ios:safari" in found:
        specs = [s for s in specs if s[0] != "ios:safari" or (s[1], s[2]) in source.entries]
    if source.kind == "filesystem":
        for check in ("ios:messages", "ios:safari", "ios:processes"):
            if check not in found:
                gap(check, "supported artifact was not present in this filesystem extraction")
    return specs


def _ia_iso(value):
    if isinstance(value, datetime.datetime):
        return value.isoformat() if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc).isoformat()
    if not isinstance(value, str) or len(value) > 128:
        return ""
    try:
        text = value.strip().replace("Z", "+00:00")
        parsed = datetime.datetime.fromisoformat(text)
        # Do not silently interpret a timezone-free log as local scanner time.
        return parsed.isoformat() if parsed.tzinfo else ""
    except ValueError:
        return ""


def _ia_walk(obj):
    pending, count = [((), obj)], 0
    while pending:
        path, value = pending.pop()
        count += 1
        if count > 20000 or len(path) > 24:
            raise ValueError("structured artifact node/depth limit reached")
        if isinstance(value, dict):
            pending.extend((path + (str(k),), v) for k, v in value.items())
        elif isinstance(value, list):
            pending.extend((path + (str(n),), v) for n, v in enumerate(value))
        elif isinstance(value, (str, datetime.datetime, int, float)):
            yield path, value


def _ia_unix_iso(value):
    try:
        return datetime.datetime.fromtimestamp(float(value), datetime.timezone.utc).isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


def _ia_webkit_name_host(name):
    """'https_www.example.com_0' (scheme, host, port joined by '_') -> host.
    "" for a local page inside the app (file, asset... schemes); None when the
    name is not in this layout at all."""
    scheme, sep, rest = name.partition("_")
    host, sep2, port = rest.rpartition("_")
    if not sep or not sep2 or not port.isdigit() or not scheme:
        return None
    return host if scheme in ("http", "https") else ""


def _ia_webkit_origin_hosts(raw):
    """Hosts in a WebKit "origin" file: the top page's and the frame's origin,
    each a scheme string, a host string and a port flag (plus a 16-bit port).
    A string is a 32-bit length, a byte saying 8-bit (1) or UTF-16 (0), then text."""
    hosts, pos = [], 0
    if not raw:
        raise ValueError("empty web view origin record")

    def text():
        nonlocal pos
        if pos + 5 > len(raw):
            raise ValueError("truncated web view origin record")
        length = int.from_bytes(raw[pos:pos + 4], "little")
        latin = raw[pos + 4]
        pos += 5
        size = length if latin else length * 2
        if length > 2048 or pos + size > len(raw):
            raise ValueError("unsupported web view origin record")
        value = raw[pos:pos + size].decode("latin-1" if latin else "utf-16-le")
        pos += size
        return value

    while pos < len(raw) and len(hosts) < 4:
        scheme, host = text(), text()
        if pos >= len(raw):
            raise ValueError("truncated web view origin record")
        has_port = raw[pos]
        pos += 1 + (2 if has_port else 0)
        if scheme in ("http", "https") and host:
            hosts.append(host)
    return hosts


def _ia_artifact_kind(domain, path, kind):
    base = path.rsplit("/", 1)[-1]
    if base.startswith("._"):
        return ""  # macOS AppleDouble metadata added when an archive is re-packed on a Mac
    low = path.lower()
    # Backup domains constrain app-owned formats. Direct extractions supply
    # physical paths instead; their interpretation still requires a schema.
    mobile = kind != "backup" or domain in ("HomeDomain", "RootDomain", "WirelessDomain",
                                            "SysSharedContainerDomain-systemgroup.com.apple.configurationprofiles")
    if mobile and base == "sms.db":
        return "messages-extra"
    # Security-framework analytics in a file-system extraction (MVT: Analytics):
    # failure and note records name the calling process and sometimes a host.
    if "keychains/analytics/" in low and base.endswith(".db"):
        return "keychain-analytics"
    if (kind != "backup" or "safari" in domain.lower() or domain == "HomeDomain") and base in (
            "BrowserState.db", "SafariTabs.db", "CloudTabs.db"):
        return "browser-state"
    if (kind != "backup" or "safari" in domain.lower() or domain == "HomeDomain") and base == "Bookmarks.db":
        return "safari-bookmarks"
    if base == "observations.db" and ("webkit" in low or "resourceloadstatistics" in low):
        return "webkit-statistics"
    if base == "Cache.db":
        return "url-cache"
    # Chromium-based iPhone browsers (Edge, Chrome, Opera...) keep the servers
    # they connected to; Brave keeps a record per site visited.
    if base == "Network Persistent State":
        return "browser-connections"
    if base == "Brave.sqlite" and (kind != "backup" or "brave" in domain.lower()):
        return "brave-sites"
    if base == "ChatStorage.sqlite" and (kind != "backup" or "whatsapp" in domain.lower()):
        return "whatsapp"
    if mobile and base == "TCC.db":
        return "permissions"
    if mobile and base == "CallHistory.storedata":
        return "calls"
    if mobile and base in ("Calendar.sqlitedb", "Calendar.sqlite"):
        return "calendar"
    if mobile and base == "interactionC.db":
        return "interactions"
    if mobile and base == "Shortcuts.sqlite":
        return "shortcuts"
    if mobile and base == "com.apple.osanalytics.addaily.plist":
        return "analytics"
    if mobile and base == "clients.plist" and "locationd" in low:
        return "location-clients"
    if mobile and base == ".GlobalPreferences.plist":
        return "preferences"
    # iMessage/FaceTime lookups of other people's accounts (MVT: IDStatusCache).
    # iOS 14.7 moved it from Preferences to IdentityServices.
    if mobile and base in ("com.apple.identityservices.idstatuscache.plist", "idstatuscache.plist"):
        return "id-status-cache"
    # Pages whose icons the browser stored: Safari's Favicons.db and the
    # Chromium "Favicons" database of Chrome, Edge and other iPhone browsers.
    if base == "Favicons.db" and "favicons" in low:
        return "favicons"
    if base == "Favicons" and any(name in domain.lower() or name in low
                                  for name in ("chrome", "edge", "brave", "opera", "chromium")):
        return "favicons"
    if "configurationprofiles" in low and base.endswith((".plist", ".mobileconfig", ".stub")):
        # Installed profiles are stored as profile-<hash>.stub; install and
        # removal history is MCProfileEvents.plist. The folder's other plists
        # (ProfileTruth, MCSettingsEvents, UserSettings...) are device settings.
        if base == "MCProfileEvents.plist":
            return "profile-events"
        if base.startswith("profile-") or base.endswith((".mobileconfig", ".stub")):
            return "profiles"
        return "profile-settings"
    if base == "iTunesMetadata.plist":
        return "app-metadata"
    # Sites that stored data in an app's web view (MVT: WebkitIndexedDB,
    # WebkitLocalStorage, WebkitSafariViewService). Before iOS 16 the site is
    # in the file or folder name; later each site folder holds an "origin" file.
    if "/websitedata/" in "/" + low and (
            base == "origin" or base.endswith(".localstorage")
            or (base == "IndexedDB.sqlite3" and "/indexeddb/v1/" in low)):
        return "webkit-origins"
    if ("webkit" in low or "safari" in low) and base.endswith(".plist") and "resource" in base.lower():
        return "webkit-session"
    # The phone's records of computers it was connected to and trusted. Citizen Lab
    # found the Host ID and System BUID of a Cellebrite computer in them.
    if kind != "backup" and "/library/lockdown/" in "/" + low and base.endswith(".plist"):
        return "lockdown"
    if re.fullmatch(r"shutdown\.log(?:\.\d+)?", base, re.I):
        return "shutdown"
    if kind == "sysdiagnose" and base == "ps.txt":
        return "process-list"
    if re.fullmatch(r"mobile_installation\.log(?:\.\d+)?", base):
        return "installations"
    if base.endswith((".ips", ".crash")):
        # Apps keep their own files with these names in their containers
        # (one photo-vault app stores "invalidWriteDetection.crash"); only
        # system diagnostic locations hold Apple crash reports.
        app_owned = (domain.startswith("AppDomain") or "containers/data/application/" in low
                     or "containers/shared/appgroup/" in low)
        return "" if app_owned else "crashes"
    return ""


def _ia_ips_field(line, names):
    """The value of a "Name:  value" header line, or "" (plain string handling:
    the regular expressions this replaced backtracked quadratically on long
    runs of spaces in crafted reports)."""
    for name in names:
        if line.startswith(name + ":"):
            rest = line[len(name) + 1:]
            return rest.strip() if rest[:1].isspace() else ""
    return ""


def _ia_ips_process(line):
    """Process or Command name, without a trailing " [pid]"."""
    value = _ia_ips_field(line, ("Process", "Command"))
    if value.endswith("]"):
        head, _sep, pid = value.rpartition("[")
        if pid[:-1].isdecimal() and head and head != head.rstrip():
            value = head.rstrip()
    return value


def _ia_ips_path(line):
    value = _ia_ips_field(line, ("Path",))
    return value if len(value) > 1 and value[0] == "/" and not value[1].isspace() else ""


def ios_additional_artifacts(source, ctx, r, gap, query, tables, columns, records, hit, apple_time):
    """Parse selected input artifacts, retaining each readable neighbour on error."""
    processed = 0
    found = set()
    deadline = time.monotonic() + 90

    def emit(ind, key, check, record_id, detail, grade=EV_REFERENCED, observed="", raw_time=""):
        if ind is None:
            return
        origin = source.provenance.get(key, {})
        before = len(r.hits)
        hit(r, ind, key[0] + "/" + key[1] + ":record " + str(record_id), detail,
            grade, observed, origin.get("source", source.root))
        if len(r.hits) == before:
            return  # counted past the listing limit, not listed: nothing to annotate
        r.hits[-1].provenance = dict(origin, record_id=str(record_id),
            parser=check + "/1", raw_timestamp=str(raw_time)[:128])
        if (key[0], key[1] + "-wal") in source.provenance:
            r.hits[-1].provenance["wal_sha256"] = source.provenance[(key[0], key[1] + "-wal")]["sha256"]

    def text_matches(text, key, check, record_id, detail, grade=EV_REFERENCED, observed="", raw_time=""):
        if not isinstance(text, str):
            if text is not None:
                r.skipped += 1
                gap(check, "unsupported non-text field")
            return
        try:
            size = len(text.encode("utf-8"))
        except UnicodeError:
            r.skipped += 1
            gap(check, "undecodable text field was not searched")
            return
        if size > 65536:
            r.skipped += 1
            gap(check, "artifact text field exceeds the limit")
            return
        for ind in ctx.iocs.search(text.lower()):
            emit(ind, key, check, record_id, detail, grade, observed, raw_time)
        for ind in ctx.iocs.of_type("email"):
            if re.search(r"(?<![\w.+-])" + re.escape(ind.value) + r"(?![\w.-])", text, re.I):
                emit(ind, key, check, record_id, detail, grade, observed, raw_time)

    def typed(value, types, key, check, record_id, detail, grade, observed="", raw_time=""):
        if not isinstance(value, str) or len(value) > 65536:
            return
        if "process" in types and value == DT_IOS_PROCESS:
            emit(dt_ios_process_indicator(), key, check, record_id,
                 "a process named 'mnm' ran: Citizen Lab attributes this process to Cellebrite's "
                 "phone-unlocking tool with high confidence", grade, observed, raw_time)
        for typ in types:
            for ind in ctx.iocs.of_type(typ):
                if typ in ("file-path", "file-name", "process"):
                    matches = ios_exact_identity(ind, value)
                else:
                    matches = value.lower() == ind.value.lower()
                if matches:
                    emit(ind, key, check, record_id, detail, grade, observed, raw_time)

    def sql_rows(key, check, table, required, optional=(), alternatives=()):
        con = source.open_database(*key, check)
        try:
            # Apple renames tables and columns between iOS releases. Use the
            # first known layout that is fully present; never guess columns.
            for candidate in ((table, required, optional),) + tuple(alternatives):
                with query(con, "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                           (candidate[0],)) as cur:
                    if cur.fetchone() is None:
                        continue
                if {x.lower() for x in candidate[1]} <= columns(con, candidate[0]):
                    table, required, optional = candidate
                    break
            tables(con, (table,))
            cols = columns(con, table)
            if not {x.lower() for x in required} <= cols:
                raise ValueError("unsupported " + table + " schema; required columns missing")
            selected = list(required) + [x if x.lower() in cols else "NULL" for x in optional]
            sql = "SELECT " + ",".join(selected) + " FROM " + table
            byte_count = 0
            for row_id, row in records(con, sql, table, cols, r, gap,
                                       min(deadline, time.monotonic() + 10), check, "record"):
                byte_count += sum(len(v) if isinstance(v, bytes) else len(v.encode("utf-8", "replace")) if isinstance(v, str) else 8 for v in row)
                if byte_count > 16 * 1024 * 1024:
                    raise ValueError("artifact row payload budget reached")
                yield row_id, row
        finally:
            con.close()

    def sql_artifact(key, kind, check):
        layouts = {
            "safari-bookmarks": ("bookmarks", ("url",), ()),
            # BrowserState.db before iOS 15; then SafariTabs.db (tabs are rows of its
            # bookmarks table) and CloudTabs.db (tabs open on the owner's other devices).
            "browser-state": ("tabs", ("url",), ("title",),
                              (("bookmarks", ("url",), ("title",)), ("cloud_tabs", ("url",), ("title",)))),
            "webkit-statistics": ("ObservedDomains", ("registrableDomain",), ("lastSeen",),
                                  (("observed_domains", ("registrableDomain",), ("lastSeen",)),)),
            "url-cache": ("cfurl_cache_response", ("request_key",), ("time_stamp",)),
            "favicons": ("page_url", ("url",), (), (("icon_mapping", ("page_url",), ()),)),
            "brave-sites": ("ZDOMAIN", ("ZURL",), ("ZVISITS",)),
            "whatsapp": ("ZWAMESSAGE", ("ZTEXT", "ZISFROMME"), ("ZMESSAGEDATE", "ZFROMJID")),
            "permissions": ("access", ("client", "service"), ("auth_value", "allowed", "last_modified")),
            "calls": ("ZCALLRECORD", ("ZADDRESS",), ("ZDATE", "ZORIGINATED")),
            "calendar": ("CalendarItem", ("summary",), ("description", "url", "start_date"),
                         (("CalendarItem", ("title",), ("notes", "url", "start_date")),)),
            "interactions": ("ZINTERACTIONS", ("ZBUNDLEID",), ("ZSTARTDATE", "ZENDDATE")),
            # Before iOS 15 actions are a column; later they move to ZSHORTCUTACTIONS.
            "shortcuts": ("ZSHORTCUT", ("ZNAME", "ZWORKFLOWACTIONS"), ("ZCREATIONDATE",),
                          (("ZSHORTCUT", ("ZNAME",), ("ZACTIONSDESCRIPTION", "ZCREATIONDATE")),)),
        }
        if kind == "url-cache":
            # Several system stores are also called Cache.db (backup state,
            # telemetry queues). Only a CFNetwork cache is this artifact.
            con = source.open_database(*key, check)
            try:
                with query(con, "SELECT 1 FROM sqlite_master WHERE type='table' AND name LIKE 'cfurl_cache_%'") as cur:
                    if cur.fetchone() is None:
                        # Not a CFNetwork cache, so nothing of this artifact was read:
                        # neither "ran" nor a gap (backups carry other Cache.db files).
                        return False
            finally:
                con.close()
        actions_table = False
        for row_id, row in sql_rows(key, check, *layouts[kind]):
            try:
                if kind == "calls" and isinstance(row[0], bytes):
                    # CallHistory keeps the number or address as UTF-8 bytes.
                    row = (row[0].decode("utf-8"),) + tuple(row[1:])
                if kind == "whatsapp":
                    if type(row[1]) is not int or row[1] not in (0, 1):
                        raise ValueError("message direction is unsupported")
                    text_matches(row[0], key, check, row_id, "message text; opening is unverified",
                                 EV_RECEIVED if row[1] == 0 else EV_REFERENCED, apple_time(row[2]), row[2])
                    typed(row[3], ("email",), key, check, row_id, "message sender identifier", EV_DEVICE_LOG)
                elif kind == "permissions":
                    granted = row[2] == 2 if row[2] is not None else row[3] == 1
                    detail = "TCC client record for " + str(row[1])[:100] + "; consent and execution unverified"
                    grade = EV_CONFIGURED if granted else EV_REFERENCED
                    # A client is a bundle ID, an executable path or a bare
                    # process name; a path's file name is also a process name.
                    typed(row[0], ("app-id", "file-path", "process"), key, check, row_id, detail, grade)
                    if isinstance(row[0], str) and row[0].startswith("/"):
                        typed(row[0].rsplit("/", 1)[-1], ("process",), key, check, row_id, detail, grade)
                    if row[2] is None and row[3] is None:
                        gap(check, "permission decision column unavailable; records remain references")
                elif kind == "interactions":
                    typed(row[0], ("app-id",), key, check, row_id,
                          "application identifier in interaction records", EV_DEVICE_LOG, apple_time(row[1]), row[1])
                elif kind == "shortcuts":
                    text_matches(row[0], key, check, row_id, "saved Shortcut name; execution unverified")
                    if row[1] is None or isinstance(row[1], str):
                        # iOS 15+: row[1] is the action description; the actions
                        # themselves are read from ZSHORTCUTACTIONS below.
                        actions_table = True
                        text_matches(row[1], key, check, row_id, "saved Shortcut description; execution unverified")
                    else:
                        shortcut_actions(row[1], key, check, row_id)
                else:
                    for field_index, value in enumerate(row):
                        if field_index == 0 or isinstance(value, (str, bytes)):
                            text_matches(value, key, check, row_id,
                                         "stored " + kind + " field; local contact/execution is unverified")
                    if kind == "calls":
                        typed(row[0], ("email",), key, check, row_id, "identifier in a call record",
                              EV_DEVICE_LOG, apple_time(row[1]), row[1])
                r.checked += 1
            except (ValueError, UnicodeError, plistlib.InvalidFileException, RecursionError) as exc:
                r.skipped += 1
                gap(check, str(exc))
        if kind == "calendar":
            # Invitees and organisers: an invitation from an unknown address
            # is one way a link reaches a phone.
            con = source.open_database(*key, check)
            try:
                with query(con, "SELECT 1 FROM sqlite_master WHERE type='table' AND name='Participant'") as cur:
                    participants = cur.fetchone() is not None
            finally:
                con.close()
            if participants:
                for row_id, row in sql_rows(key, check, "Participant", ("email",), ()):
                    # text_matches covers email indicators and domains inside the address.
                    text_matches(row[0], key, check, "participant " + str(row_id),
                                 "calendar participant address; the invitation's content is unverified")
        if kind == "favicons":
            # The icon's own address: icon_info (Safari) or favicons (Chromium).
            con = source.open_database(*key, check)
            try:
                with query(con, "SELECT name FROM sqlite_master WHERE type='table' "
                                "AND name IN ('icon_info', 'favicons')") as cur:
                    icon_tables = [row[0] for row in cur.fetchall()]
            finally:
                con.close()
            for table in icon_tables:
                for row_id, row in sql_rows(key, check, table, ("url",), ()):
                    text_matches(row[0], key, check, table + " " + str(row_id),
                                 "icon address stored by the browser; the visit itself is unverified")
                    r.checked += 1
        if actions_table:
            for row_id, row in sql_rows(key, check, "ZSHORTCUTACTIONS", ("ZDATA",), ("ZSHORTCUT",)):
                try:
                    if row[0] is not None:
                        shortcut_actions(row[0], key, check, "actions " + str(row_id))
                except (ValueError, UnicodeError, plistlib.InvalidFileException, RecursionError) as exc:
                    r.skipped += 1
                    gap(check, str(exc))

    def shortcut_actions(raw, key, check, row_id):
        if not isinstance(raw, bytes):
            raise ValueError("unsupported Shortcut actions encoding")
        actions = _is_plist(raw)
        for field, value in _ia_walk(actions):
            if isinstance(value, str):
                text_matches(value, key, check, str(row_id) + "/" + "/".join(field),
                             "saved Shortcut action text; activation and execution unverified")

    def message_extras(key):
        specs = (("ios:message-handles", "handle", ("id",), ("service",)),
                 ("ios:message-attachments", "attachment", ("filename",), ("mime_type", "created_date")))
        for check, table, required, optional in specs:
            try:
                # Older/plain fixture schemas may genuinely not have these
                # optional tables. Unsupported present schemas remain gaps.
                con = source.open_database(*key, check)
                try:
                    with query(con, "SELECT 1 FROM sqlite_master WHERE name=?", (table,)) as cur:
                        exists = cur.fetchone() is not None
                finally:
                    con.close()
                if not exists:
                    continue
                for row_id, row in sql_rows(key, check, table, required, optional):
                    try:
                        text_matches(row[0], key, check, row_id,
                                     "message metadata; receipt, opening and execution are unverified")
                        if table == "handle":
                            typed(row[0], ("email",), key, check, row_id,
                                  "identifier in message handle records", EV_DEVICE_LOG)
                        else:
                            typed(row[0], ("file-path",), key, check, row_id,
                                  "attachment path recorded in metadata; file contents unverified", EV_REFERENCED)
                        r.checked += 1
                    except (ValueError, UnicodeError) as exc:
                        r.skipped += 1
                        gap(check, str(exc))
                r.ran(check)
            except (ValueError, OSError, sqlite3.Error) as exc:
                gap(check, "message metadata unreadable: " + str(exc))

    def keychain_analytics(key, check):
        con = source.open_database(*key, check)
        try:
            with query(con, "SELECT name FROM sqlite_master WHERE type='table' "
                            "AND name IN ('hard_failures', 'soft_failures', 'notes')") as cur:
                event_tables = [row[0] for row in cur.fetchall()]
        finally:
            con.close()
        if not event_tables:
            # No event records: some other store with this name. Nothing was read,
            # so the check is neither "ran" nor a gap.
            return False
        unreadable = 0
        for table in event_tables:
            for row_id, row in sql_rows(key, check, table, ("data",), ("timestamp",)):
                try:
                    doc = _is_plist(row[0]) if isinstance(row[0], bytes) else None
                except (ValueError, plistlib.InvalidFileException):
                    doc = None
                if not isinstance(doc, dict):
                    unreadable += 1
                    continue
                observed = _ia_unix_iso(row[1])
                record = table + " " + str(row_id)
                for field, value in _ia_walk(doc):
                    if not isinstance(value, str):
                        continue
                    name = field[-1] if field else ""
                    text_matches(value, key, check, record,
                                 "string in a security analytics record; contact and execution unverified",
                                 EV_DEVICE_LOG, observed, str(row[1] or ""))
                    if name in ("Caller", "process", "processName", "bundleID", "bundleId", "appBundleId"):
                        typed(value, ("process", "app-id"), key, check, record,
                              "calling process in a security analytics record; executable contents unverified",
                              EV_DEVICE_LOG, observed, str(row[1] or ""))
                r.checked += 1
        if unreadable:
            gap(check, "{} analytics record(s) in an unsupported format were not read".format(unreadable))

    def webkit_origin(key, check):
        path = key[1]
        low = path.lower()
        base = path.rsplit("/", 1)[-1]
        if base == "origin":
            hosts = _ia_webkit_origin_hosts(source.artifact(*key))
        elif base.lower().endswith(".localstorage"):
            hosts = [_ia_webkit_name_host(base[:-len(".localstorage")])]
        else:
            segment = path[low.index("/indexeddb/v1/") + len("/indexeddb/v1/"):].split("/", 1)[0]
            hosts = [_ia_webkit_name_host(segment)]
        if None in hosts:
            raise ValueError("unsupported web view site record")
        # Local pages inside the app (file:, app-defined schemes) are not sites.
        for host in dict.fromkeys(h for h in hosts if h):
            text_matches(host, key, check, base,
                         "site that stored data in an app's web view, so its page was loaded there",
                         EV_CONTACTED)
        r.checked += 1

    def connection_artifact(key, check):
        """Chromium's Network Persistent State (JSON): servers this browser
        connected to, under net.http_server_properties.servers[].server."""
        try:
            doc = json.loads(source.artifact(*key).decode("utf-8"))
        except (UnicodeError, ValueError) as exc:
            raise ValueError("unsupported Network Persistent State: " + str(exc)[:80])
        net = doc.get("net") if isinstance(doc, dict) else None
        props = net.get("http_server_properties") if isinstance(net, dict) else None
        servers = props.get("servers") if isinstance(props, dict) else None
        if not isinstance(servers, list):
            raise ValueError("unsupported Network Persistent State layout")
        for n, entry in enumerate(servers[:_IA_RECORD_LIMIT]):
            server = entry.get("server") if isinstance(entry, dict) else None
            if not isinstance(server, str):
                continue
            host = re.sub(r"^[a-z]+://", "", server.lower()).split("/")[0].rsplit(":", 1)[0].strip("[]")
            for ind in ctx.iocs.search(host):
                if host == ind.value or host.endswith("." + ind.value):
                    emit(ind, key, check, "server " + str(n),
                         "server this browser connected to (Chromium connection record)", EV_CONTACTED)
            r.checked += 1
        if len(servers) > _IA_RECORD_LIMIT:
            gap(check, "connection record lists more than {:,} servers; the rest were not compared".format(_IA_RECORD_LIMIT))

    def plist_artifact(key, kind, check):
        doc = _is_plist(source.artifact(*key))
        if not isinstance(doc, (dict, list)):
            raise ValueError("unsupported property-list root")
        recognized = 0
        if kind == "profiles":
            lead = _ia_profile_lead(doc)
            if lead:
                r.add_lead(Lead("ios:configuration-profiles", key[1], lead[0], _IA_PROFILE_USUAL, lead[1]))
        # ADDaily's process map stores a plist date first in each usage tuple.
        # Treat other layouts as unsupported, rather than guessing an epoch.
        if kind == "analytics" and isinstance(doc, dict) and "netUsageBaseline" in doc:
            baseline = doc["netUsageBaseline"]
            if not isinstance(baseline, dict):
                gap(check, "unsupported netUsageBaseline map")
            else:
                for name, usage in baseline.items():
                    if not isinstance(usage, list) or not usage or not isinstance(usage[0], datetime.datetime):
                        gap(check, "unsupported netUsageBaseline record")
                        continue
                    recognized += 1
                    typed(name, ("process",), key, check, "netUsageBaseline/" + name,
                          "process identity in recorded network-usage baseline; executable contents unverified",
                          EV_DEVICE_LOG, _ia_iso(usage[0]), str(usage[0]))
        if kind == "location-clients" and isinstance(doc, dict):
            for name, client in doc.items():
                if not isinstance(client, dict):
                    if isinstance(client, (int, float, str)):
                        continue  # file metadata such as MigrationVersionNumber
                    gap(check, "unsupported location client record")
                    continue
                recognized += 1
                stopped = client.get("LocationTimeStopped")
                detail = "identifier in location-service client metadata; execution unverified"
                # Keys join "<type><identifier>:" segments: i = bundle ID, p = path.
                for segment in name.split(":"):
                    if segment[:1] == "i":
                        typed(segment[1:], ("app-id",), key, check, name, detail, EV_DEVICE_LOG,
                              apple_time(stopped), stopped or "")
                    elif segment[:1] == "p":
                        typed(segment[1:], ("file-path",), key, check, name, detail, EV_DEVICE_LOG,
                              apple_time(stopped), stopped or "")
                typed(name, ("app-id",), key, check, name, detail, EV_DEVICE_LOG, apple_time(stopped), stopped or "")
        if kind == "id-status-cache" and isinstance(doc, dict):
            # {service: {"mailto:..." | "tel:...": {"IDStatus": n, "LookupDate": t}}}
            for service, entries in doc.items():
                if not isinstance(entries, dict):
                    if isinstance(entries, (int, float, str)):
                        continue  # file metadata
                    gap(check, "unsupported lookup cache service record")
                    continue
                for handle, info in entries.items():
                    if not isinstance(handle, str) or ":" not in handle:
                        gap(check, "unsupported lookup cache entry")
                        continue
                    recognized += 1
                    stamp = info.get("LookupDate") if isinstance(info, dict) else None
                    account = handle.split(":", 1)[1]
                    typed(account, ("email",), key, check, str(service) + "/" + handle,
                          "account looked up by this phone's iMessage or FaceTime; the lookup "
                          "does not show who started the contact", EV_DEVICE_LOG,
                          _ia_iso(stamp) if isinstance(stamp, datetime.datetime) else apple_time(stamp),
                          str(stamp or ""))
        if kind == "profile-events" and isinstance(doc, dict) and isinstance(doc.get("ProfileEvents"), list):
            # [{profile identifier: {"operation": ..., "process": ..., "timestamp": ...}}]
            for n, event in enumerate(doc["ProfileEvents"]):
                if not isinstance(event, dict):
                    gap(check, "unsupported profile event record")
                    continue
                for ident, detail in event.items():
                    if not isinstance(detail, dict) or "operation" not in detail:
                        gap(check, "unsupported profile event record")
                        continue
                    recognized += 1
                    stamp = detail.get("timestamp")
                    observed = _ia_iso(stamp)
                    operation = str(detail.get("operation"))[:40]
                    text_matches(ident, key, check, "ProfileEvents/" + str(n),
                                 "profile identifier in a recorded profile " + operation + " event",
                                 EV_DEVICE_LOG, observed, str(stamp or ""))
                    typed(ident, ("profile-id",), key, check, "ProfileEvents/" + str(n),
                          "profile identifier in a recorded profile " + operation + " event", EV_DEVICE_LOG,
                          observed, str(stamp or ""))
        for field, value in _ia_walk(doc):
            name = field[-1] if field else ""
            location = "/".join(field)
            if isinstance(value, str):
                text_matches(value, key, check, location, "stored " + kind + " text; execution/contact unverified")
            if kind in ("profiles", "profile-events", "profile-settings") and name in ("PayloadUUID", "PayloadIdentifier"):
                recognized += 1
                typed(value, ("profile-id",), key, check, location,
                      "profile identifier in supplied configuration records; current activation unverified",
                      EV_DEVICE_LOG if kind == "profile-events" else EV_CONFIGURED)
            elif kind == "analytics" and name in ("processName", "procName", "process"):
                recognized += 1
                typed(value, ("process",), key, check, location,
                      "process identity in analytics record; executable contents unverified", EV_DEVICE_LOG)
            elif kind in ("analytics", "app-metadata", "location-clients") and name in (
                    "bundleID", "bundleId", "BundleId", "softwareVersionBundleId"):
                recognized += 1
                typed(value, ("app-id",), key, check, location,
                      "application identifier in " + kind + " records", EV_DEVICE_LOG)
            elif kind == "preferences" and name == "LDMGlobalEnabled" and type(value) in (int, bool):
                recognized += 1
                r.note("Backup records Lockdown Mode as " + ("enabled" if value else "disabled")
                       + "; backup-time metadata does not establish current protection.")
            elif kind == "webkit-session" and isinstance(value, str) and name.lower() in ("url", "requesturl", "resourceurl"):
                recognized += 1
            r.checked += 1
        # Settings files and the global preferences have no required typed
        # field: every string in them was searched, and an absent Lockdown
        # Mode key only means it was never configured.
        # A lookup cache with no service records (only CacheVersion, or nothing
        # at all) is a phone that looked nobody up: fully read, not a new layout.
        empty_cache = (kind == "id-status-cache" and isinstance(doc, dict)
                       and not any(isinstance(v, dict) for v in doc.values()))
        if not recognized and not empty_cache and kind not in ("profile-settings", "preferences"):
            # Raised, not recorded beside a "ran": a layout nobody documented was
            # not read as this artifact. The literal text was still searched above.
            raise ValueError("unrecognized typed property-list schema; only literal references were searched")

    def forensic_strings(text, key, check, where):
        for ind, what in dt_ios_strings_in(text):
            emit(ind, key, check, ind.type, "this " + where + " contains " + what + " ('" + ind.value
                 + "'), which Citizen Lab attributes to Cellebrite's phone-unlocking tool",
                 EV_DEVICE_LOG)

    def lockdown_artifact(key, check):
        raw = source.artifact(*key)
        if len(raw) > 8 * 1024 * 1024:
            raise ValueError("lockdown record byte limit reached")
        # A pair record is a property list. Empty or damaged bytes searched as
        # text would read as "looked and found nothing".
        if not isinstance(_is_plist(raw), (dict, list)):
            raise ValueError("unsupported property-list root")
        # Binary and XML property lists both keep these identifiers as plain text.
        text = raw.decode("latin-1")
        for ind, what in dt_ios_strings_in(text):
            emit(ind, key, check, ind.type, "the phone's record of a computer it was connected to "
                 "names " + what + " ('" + ind.value + "'): the phone was plugged into a Cellebrite "
                 "computer", EV_ON_DEVICE)
        r.checked += 1

    def process_name(value, key, check, record_id, detail, observed="", raw_time="", truncated_at=0,
                     grade=EV_DEVICE_LOG):
        typed(value, ("process",), key, check, record_id, detail, grade, observed, raw_time)
        # Memory-pressure reports cut names to a fixed width; a name of exactly
        # that width may be the start of a longer indicator.
        if truncated_at and isinstance(value, str) and len(value) == truncated_at:
            for ind in ctx.iocs.of_type("process"):
                if len(ind.value) > truncated_at and any(v.startswith(value) for v in ios_identity_values(ind)):
                    emit(ind, key, check, record_id, detail + " (name recorded truncated to "
                         + str(truncated_at) + " characters)", grade, observed, raw_time)

    def ips_report(text, key, check, binary_body=False):
        """Apple .ips: one JSON metadata line, then a JSON or text body that
        depends on bug_type (crash, Jetsam memory event, stackshot, CPU use...)."""
        forensic_strings(text, key, check, "diagnostic report")
        decoder = json.JSONDecoder()
        meta, pos = decoder.raw_decode(text, len(text) - len(text.lstrip()))
        if not isinstance(meta, dict):
            raise ValueError("unsupported IPS root")
        rest = text[pos:].strip()
        when = meta.get("timestamp", "")
        bug_type = str(meta.get("bug_type", ""))
        found = 0
        detail = "identity recorded in a diagnostic report; a report alone is not an exploit"

        def identities(index, obj):
            nonlocal found
            stamp = obj.get("captureTime", obj.get("timestamp", when))
            for field, types in (("procName", ("process",)), ("procPath", ("file-path",)), ("bundleID", ("app-id",))):
                if isinstance(obj.get(field), str):
                    found += 1
                    typed(obj[field], types, key, check, str(index) + "/" + field, detail,
                          EV_DEVICE_LOG, _ia_iso(stamp), stamp)
            r.checked += 1

        # The metadata line is kept even when the body after it is damaged.
        identities(0, meta)
        body = None
        if rest[:1] == "{":
            body, end = decoder.raw_decode(rest)
            if rest[end:].strip():
                raise ValueError("unsupported IPS document sequence")
            if not isinstance(body, dict):
                raise ValueError("unsupported IPS root")
            identities(1, body)
        if body is not None:
            processes = body.get("processes")
            if isinstance(processes, list):        # JetsamEvent (bug_type 298)
                if len(processes) > _IA_RECORD_LIMIT:
                    gap(check, "memory-pressure report lists more than {:,} processes; the rest were not "
                               "compared".format(_IA_RECORD_LIMIT))
                for n, proc in enumerate(processes[:_IA_RECORD_LIMIT]):
                    if isinstance(proc, dict) and isinstance(proc.get("name"), str):
                        found += 1
                        process_name(proc["name"], key, check, "processes/" + str(n),
                                     "process running at a recorded memory-pressure event", _ia_iso(when), when, 32)
            by_pid = body.get("processByPid")
            if isinstance(by_pid, dict):           # stackshot (bug_type 288)
                if len(by_pid) > _IA_RECORD_LIMIT:
                    gap(check, "stackshot lists more than {:,} processes; the rest were not "
                               "compared".format(_IA_RECORD_LIMIT))
                for pid, proc in list(by_pid.items())[:_IA_RECORD_LIMIT]:
                    if isinstance(proc, dict) and isinstance(proc.get("procname"), str):
                        found += 1
                        process_name(proc["procname"], key, check, "processByPid/" + str(pid),
                                     "process present in a recorded stackshot", _ia_iso(when), when)
        elif rest:
            # Text bodies (CPU and wakeup reports, older crashes, update logs).
            lines = rest.splitlines()
            if len(lines) > _IA_LINE_LIMIT:
                gap(check, "diagnostic report longer than {:,} lines; the rest was not searched".format(_IA_LINE_LIMIT))
            for line_no, line in enumerate(lines[:_IA_LINE_LIMIT], 1):
                if time.monotonic() > deadline:
                    gap(check, "time limit reached in a diagnostic report; the rest was not searched")
                    break
                if len(line) > 65536:
                    gap(check, "oversized diagnostic record was not searched")
                    continue
                text_matches(line, key, check, line_no, "text in a diagnostic report; execution unverified")
                process, path = _ia_ips_process(line), _ia_ips_path(line)
                if process:
                    found += 1
                    process_name(process, key, check, line_no, detail, _ia_iso(when), when)
                elif path:
                    found += 1
                    typed(path, ("file-path",), key, check, line_no, detail, EV_DEVICE_LOG,
                          _ia_iso(when), when)
        if binary_body and bug_type in _IA_IDENTITY_REPORTS:
            raise ValueError("crash report body is not text and was not read")
        # Crash (109 legacy, 309), memory-pressure (298) and stackshot (288)
        # reports must name a process. Other report kinds - Siri feedback, update
        # logs - legitimately carry no identity. A 298 or 288 whose process list
        # is renamed, empty or a different shape read nothing, so it is a gap.
        if not found and bug_type in _IA_IDENTITY_REPORTS:
            raise ValueError("unsupported IPS identity schema")

    def process_list(text, key, check):
        """sysdiagnose ps.txt: `ps axwww -o ...,command` at capture time."""
        lines = text.splitlines()
        header = lines[0].split() if lines else []
        if not header or header[-1] != "COMMAND" or "PID" not in header:
            raise ValueError("unsupported process list layout")
        detail = "process running when the diagnostic report was captured"
        if len(lines) - 1 > _IA_LINE_LIMIT:
            gap(check, "process list longer than {:,} lines; the rest was not compared".format(_IA_LINE_LIMIT))
        for line_no, line in enumerate(lines[1:_IA_LINE_LIMIT + 1], 2):
            # Columns are right-aligned to varying widths, so split on fields:
            # everything after the last fixed column is the command line.
            fields = line.split(None, len(header) - 1)
            if len(fields) < len(header):
                continue
            command = fields[-1].strip()
            text_matches(command, key, check, line_no, "command line of a running process")
            # The executable path may itself contain spaces; try each prefix.
            words = command.split(" ")
            for n in range(1, min(len(words), 8) + 1):
                prefix = " ".join(words[:n])
                if prefix.startswith("/"):
                    typed(prefix, ("file-path",), key, check, line_no, detail, EV_ON_DEVICE)
                    process_name(prefix.rsplit("/", 1)[-1], key, check, line_no, detail, grade=EV_ON_DEVICE)
            if not command.startswith("/"):
                process_name(words[0], key, check, line_no, detail, grade=EV_ON_DEVICE)
            r.checked += 1

    def installation_log(text, key, check):
        """mobile_installation.log: installd records of installs and containers."""
        developer = set()
        lines = text.splitlines()
        if not text.strip():
            raise ValueError("the installation log is empty")
        if len(lines) > _IA_LINE_LIMIT:
            gap(check, "installation log longer than {:,} lines; the rest was not searched".format(_IA_LINE_LIMIT))
        for line_no, line in enumerate(lines[:_IA_LINE_LIMIT], 1):
            for pattern, what in ((r"Install Successful for \((\w+):([A-Za-z0-9._-]+)\)", "install"),
                                  (r"Installing <MIInstallableBundle ID=([A-Za-z0-9._-]+);", "install"),
                                  (r"Made container live for ([A-Za-z0-9._-]+) at (/\S+)", "container")):
                match = re.search(pattern, line)
                if not match:
                    continue
                if pattern.startswith("Install Successful"):
                    install_type, bundle = match.group(1), match.group(2)
                    if install_type == "Developer":
                        developer.add(bundle)
                else:
                    bundle = match.group(1)
                when = line[:24].strip()
                typed(bundle, ("app-id",), key, check, line_no,
                      "application identifier in an installation log " + what + " record", EV_DEVICE_LOG, "", when)
                if what == "container":
                    typed(match.group(2), ("file-path",), key, check, line_no,
                          "container path in an installation log record", EV_DEVICE_LOG, "", when)
            r.checked += 1
        for bundle in sorted(developer)[:20]:
            r.add_lead(Lead(check, key[1], "The app " + bundle + " was installed as a developer build, not from the App Store.",
                            "Developers install their own apps this way, and some testing and enterprise tools do "
                            "too. It matters only if nobody who uses this phone installed it."))

    def log_artifact(key, kind, check):
        raw = source.artifact(*key)
        if len(raw) > 32 * 1024 * 1024:
            raise ValueError("diagnostic log byte limit reached")
        if kind == "crashes" and key[1].endswith(".ips"):
            head, newline, body = raw.partition(b"\n")
            try:
                text = raw.decode("utf-8", "strict")
            except UnicodeDecodeError:
                # Some report kinds (Wi-Fi link-quality metrics...) follow the
                # JSON metadata line with a binary payload that names no process.
                text = None
            if text is None:
                ips_report(head.decode("utf-8", "strict"), key, check, binary_body=bool(body.strip()))
            else:
                ips_report(text, key, check)
            return
        text = raw.decode("utf-8", "strict")
        forensic_strings(text, key, check, "diagnostic log")
        if kind == "process-list":
            process_list(text, key, check)
            return
        if kind == "installations":
            installation_log(text, key, check)
            return
        recognized, heuristic = 0, False
        pending_shutdown_hits = []
        for index, line in enumerate(text.splitlines()):
            if index >= 200000 or time.monotonic() > deadline:
                raise ValueError("diagnostic log record/time limit reached")
            if len(line) > 65536:
                gap(check, "oversized diagnostic record was not searched")
                continue
            if kind == "crashes":
                match = re.fullmatch(r"Process:\s+(.+?)\s+\[\d+\]\s*", line)
                path = re.fullmatch(r"Path:\s+(/\S+)\s*", line)
                if match or path:
                    recognized += 1
                    typed((match or path).group(1), ("process",) if match else ("file-path",),
                          key, check, index + 1, "identity in a crash record; exploitation unverified", EV_DEVICE_LOG)
            else:
                flush = re.fullmatch(r"\s*SIGTERM:\s*\[(\d+(?:\.\d+)?)\]\s*All buffers flushed\s*", line)
                if flush:
                    recognized += 1
                    try:
                        when = datetime.datetime.fromtimestamp(float(flush.group(1)), datetime.timezone.utc).isoformat()
                    except (ValueError, OverflowError, OSError):
                        when = ""
                        gap(check, "shutdown timestamp outside supported range")
                    for item in pending_shutdown_hits:
                        item.observed = when
                        item.provenance["raw_timestamp"] = flush.group(1)
                    pending_shutdown_hits.clear()
                client = re.fullmatch(r"\s*(?:-\s*)?remaining client pid:\s*\d+\s+\((/[^\r\n]+)/[0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12}\)\s*", line)
                if client:
                    recognized += 1
                    value, before = client.group(1), len(r.hits)
                    typed(value, ("file-path",), key, check, index + 1,
                          "path in a shutdown client record; current presence and executable contents unverified", EV_DEVICE_LOG)
                    typed(value.rsplit("/", 1)[-1], ("process",), key, check, index + 1,
                          "process basename in a shutdown client record; executable contents unverified", EV_DEVICE_LOG)
                    pending_shutdown_hits.extend(r.hits[before:])
                    heuristic = heuristic or value.startswith(("/private/var/db/", "/private/var/tmp/"))
                elif "remaining client pid:" in line:
                    gap(check, "unsupported shutdown client record; it was not searched")
            r.checked += 1
        if not recognized:
            raise ValueError("no supported diagnostic identity records; log schema may differ")
        if pending_shutdown_hits:
            gap(check, "shutdown records have no following supported flush timestamp; identities retained without dates")
        if heuristic:
            r.add_lead(Lead(check, key[1], "Shutdown records contain a process path under a research-relevant temporary/database directory.",
                           "Legitimate services also use these directories. A shutdown delay or path alone does not establish spyware."))

    ordered = []
    for key in source.entries:
        kind = _ia_artifact_kind(*key, source.kind)
        if kind:
            ordered.append((_IA_KIND_ORDER.get(kind, 0), key, kind))
    ordered.sort(key=lambda item: item[0])
    for _rank, key, kind in ordered:
        check = "ios:" + kind
        found.add(kind)
        if processed >= _IA_ARTIFACT_LIMIT or time.monotonic() > deadline:
            gap("ios:input", "additional artifact count/time limit reached; remaining artifacts were not searched")
            break
        processed += 1
        try:
            if kind == "messages-extra":
                message_extras(key)
                continue
            if kind in ("shutdown", "crashes", "process-list", "installations"):
                log_artifact(key, kind, check)
            elif kind == "lockdown":
                lockdown_artifact(key, check)
            elif kind == "browser-connections":
                connection_artifact(key, check)
            elif kind == "webkit-origins":
                webkit_origin(key, check)
            elif kind == "keychain-analytics":
                if keychain_analytics(key, check) is False:
                    continue
            elif kind in ("analytics", "profiles", "profile-events", "profile-settings", "location-clients",
                          "preferences", "app-metadata", "webkit-session", "id-status-cache"):
                plist_artifact(key, kind, check)
            else:
                if sql_artifact(key, kind, check) is False:
                    continue
            r.ran(check)
        except (ValueError, OSError, sqlite3.Error, TypeError, AttributeError, IndexError,
                plistlib.InvalidFileException, RecursionError) as exc:
            r.skipped += 1
            gap(check, "artifact unreadable or unsupported: " + str(exc))
    if source.kind == "sysdiagnose" and not found:
        gap("ios:input", "no supported diagnostic artifacts were present; archive inventory is not a forensic all-clear")
    r.submetrics["ios_additional_artifacts"] = processed
