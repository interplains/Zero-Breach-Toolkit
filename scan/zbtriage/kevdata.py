"""Actively exploited software: CISA's Known Exploited Vulnerabilities (KEV)
list, plus the fixed versions from each vulnerability's official CVE record.

KEV says which flaws attackers are using right now, but not which versions are
affected. The CVE record (published by the vendor through the CVE Program)
usually does, as "affected below version X". The update step downloads both,
for a short list of common programs only, and keeps a small summary; the scan
then compares installed versions offline. Where a record has no usable version
range, the scan gives update advice and never claims a version is affected.

Network is used only in kev_update(), which runs as part of the explicit
indicator update, never during a scan. Only two locations are allowed: CISA's
official KEV file and the CVE Program's own record repository.
"""
import datetime
import hashlib
import io
import json
import os
import re
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

from .localpaths import path_problem, tls_context

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CVE_PREFIX = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/"
KEV_FILE = "exploited-software.json"
KEV_MANIFEST = "exploited-software.sha256"
KEV_SINCE = "2022-01-01"          # older entries concern versions long out of use
KEV_MAX_BYTES = 32 * 1024 * 1024
KEV_RECORD_MAX = 4 * 1024 * 1024
KEV_TIMEOUT = 45

# The programs checked. kev: which KEV entries concern it (vendor, product
# regex). cna: which "affected" entries in the CVE record give its versions.
# windows/mac: how to find it installed. compare=False means its records do
# not carry comparable versions, so only update advice is given.
KEV_TARGETS = (
    {"key": "chrome", "label": "Google Chrome", "kev": ("Google", r"chrom"),
     "cna": (r"^google$", r"^chrome$"), "windows": r"^Google Chrome$", "mac": ("com.google.Chrome",)},
    {"key": "firefox", "label": "Mozilla Firefox", "kev": ("Mozilla", r"firefox"),
     "cna": (r"^mozilla$", r"^firefox$"), "windows": r"^Mozilla Firefox(?! ESR)", "mac": ("org.mozilla.firefox",)},
    {"key": "firefox-esr", "label": "Mozilla Firefox ESR", "kev": ("Mozilla", r"firefox"),
     "cna": (r"^mozilla$", r"^firefox esr$"), "windows": r"^Mozilla Firefox ESR", "mac": ()},
    {"key": "thunderbird", "label": "Mozilla Thunderbird", "kev": ("Mozilla", r"thunderbird"),
     "cna": (r"^mozilla$", r"^thunderbird$"), "windows": r"^Mozilla Thunderbird", "mac": ("org.mozilla.thunderbird",)},
    {"key": "acrobat", "label": "Adobe Acrobat / Reader", "kev": ("Adobe", r"acrobat|reader"),
     "cna": (r"^adobe$", r"acrobat"), "windows": r"^Adobe Acrobat",
     "mac": ("com.adobe.Reader", "com.adobe.Acrobat.Pro")},
    {"key": "winrar", "label": "WinRAR", "kev": ("RARLAB", r"winrar"),
     "cna": (r"^rarlab$", r"^winrar$"), "windows": r"^WinRAR", "mac": ()},
    {"key": "7zip", "label": "7-Zip", "kev": ("7-Zip", r"7-zip"),
     "cna": (r"^7-zip$", r"^7-zip$"), "windows": r"^7-Zip", "mac": ()},
    {"key": "notepadpp", "label": "Notepad++", "kev": ("Notepad++", r"notepad"),
     "cna": (r"notepad", r"notepad"), "windows": r"^Notepad\+\+", "mac": ()},
    {"key": "java", "label": "Oracle Java", "kev": ("Oracle", r"java|jre"),
     "cna": (r"^oracle", r"java"), "windows": r"^Java( \d+)? Update|^Java\(TM\)|^Java SE", "mac": (),
     "compare": False},
    {"key": "office", "label": "Microsoft Office", "kev": ("Microsoft", r"office|word|excel|outlook|powerpoint"),
     "cna": (r"^microsoft$", r"office|365 apps"), "windows": r"^Microsoft (Office|365)", "mac": (),
     "compare": False},
    {"key": "edge", "label": "Microsoft Edge", "kev": ("Microsoft", r"^edge$"),
     "cna": (r"^microsoft$", r"edge"), "windows": r"^Microsoft Edge$", "mac": ("com.microsoft.edgemac",),
     "compare": False},
    {"key": "windows", "label": "Windows", "kev": ("Microsoft", r"windows|win32k|smartscreen|wordpad|\.net framework"),
     "cna": (r"^microsoft$", r"^windows 1[01] version "), "windows": None, "mac": ()},
    {"key": "macos", "label": "macOS", "kev": ("Apple", r"macos|multiple products"),
     "cna": (r"^apple$", r"^macos$"), "windows": None, "mac": ()},
    {"key": "safari", "label": "Safari", "kev": ("Apple", r"safari|webkit|multiple products"),
     "cna": (r"^apple$", r"^safari$"), "windows": None, "mac": ("com.apple.Safari",)},
)


class KevError(Exception):
    pass


def kev_url_allowed(url):
    return isinstance(url, str) and ".." not in url and (
        url == KEV_URL or (url.startswith(KEV_CVE_PREFIX) and re.fullmatch(
            r"\d{4}/\d+xxx/CVE-\d{4}-\d{4,7}\.json", url[len(KEV_CVE_PREFIX):]) is not None))


class _KevRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not kev_url_allowed(newurl):
            raise urllib.error.URLError("refused redirect: {}".format(newurl[:120]))
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _kev_fetch(url, limit):
    if not kev_url_allowed(url):
        raise KevError("refused: not an allowed address: " + url[:120])
    opener = urllib.request.build_opener(_KevRedirect(),
                                      urllib.request.HTTPSHandler(context=tls_context()))
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with opener.open(req, timeout=KEV_TIMEOUT) as resp:
        data = resp.read(limit + 1)
    if len(data) > limit:
        raise KevError("download larger than {:,} bytes - refused".format(limit))
    return data


def kev_record_url(cve):
    m = re.fullmatch(r"CVE-(\d{4})-(\d{4,7})", cve)
    if not m:
        raise KevError("not a CVE id: " + cve[:40])
    return "{}{}/{}xxx/{}.json".format(KEV_CVE_PREFIX, m.group(1), int(m.group(2)) // 1000, cve)


def kev_target_for(entry):
    """The targets a KEV entry concerns (a WebKit flaw is both macOS and Safari)."""
    vendor, product = str(entry.get("vendorProject", "")).strip(), str(entry.get("product", ""))
    return [t for t in KEV_TARGETS
            if vendor.lower() == t["kev"][0].lower() and re.search(t["kev"][1], product, re.I)]


def kev_ranges(record, target):
    """The record's version ranges for one target's product(s)."""
    cna_vendor, cna_product = target["cna"]
    out = []
    containers = record.get("containers", {}) if isinstance(record, dict) else {}
    blocks = [containers.get("cna", {})] + list(containers.get("adp", []) or [])
    for block in blocks:
        for aff in (block.get("affected") or []) if isinstance(block, dict) else []:
            if not isinstance(aff, dict):
                continue
            if not (re.search(cna_vendor, str(aff.get("vendor", "")).strip(), re.I)
                    and re.search(cna_product, str(aff.get("product", "")).strip(), re.I)):
                continue
            for v in aff.get("versions") or []:
                if isinstance(v, dict) and v.get("status") == "affected":
                    out.append({"product": str(aff.get("product", ""))[:80],
                                "version": str(v.get("version", ""))[:60],
                                "lessThan": str(v.get("lessThan", ""))[:60],
                                "lessThanOrEqual": str(v.get("lessThanOrEqual", ""))[:60]})
        if out:
            break  # the vendor's own data first; enrichment only if it gave none
    return out


def kev_update(cache, emit=lambda _m: None, fetch=None):
    """Download the KEV list and the CVE records for the checked programs, and
    write the summary into the indicator cache. Returns a short status dict."""
    fetch = fetch or _kev_fetch
    raw = fetch(KEV_URL, KEV_MAX_BYTES)
    try:
        catalog = json.loads(raw.decode("utf-8"))
        vulns = catalog["vulnerabilities"]
        if not isinstance(vulns, list) or len(vulns) < 100:
            raise ValueError("implausible vulnerability list")
    except (ValueError, KeyError, UnicodeError) as exc:
        raise KevError("the exploited-vulnerability list could not be read: {}".format(exc))
    wanted = []
    for entry in vulns:
        if not isinstance(entry, dict) or str(entry.get("dateAdded", "")) < KEV_SINCE:
            continue
        targets = kev_target_for(entry)
        if targets and re.fullmatch(r"CVE-\d{4}-\d{4,7}", str(entry.get("cveID", ""))):
            wanted.append((entry, targets))
    emit("Exploited-vulnerability list: {:,} entries; reading {} records for the checked programs..."
         .format(len(vulns), len(wanted)))

    def one(item):
        entry, targets = item
        try:
            record = json.loads(fetch(kev_record_url(entry["cveID"]), KEV_RECORD_MAX).decode("utf-8"))
        except (OSError, ValueError, KevError, urllib.error.URLError, UnicodeError):
            record = None
        rows = []
        for t in targets:
            rows.append({"cve": entry["cveID"], "target": t["key"],
                         "dateAdded": str(entry.get("dateAdded", ""))[:10],
                         "name": str(entry.get("vulnerabilityName", ""))[:200],
                         "ransomware": str(entry.get("knownRansomwareCampaignUse", "")) == "Known",
                         "record": record is not None,
                         "ranges": kev_ranges(record, t) if record is not None else []})
        return rows

    with ThreadPoolExecutor(max_workers=8) as pool:
        rows = [row for rows in pool.map(one, wanted) for row in rows]
    missing = sum(1 for r in rows if not r["record"])
    doc = {"tool": "zero-breach-toolkit", "source": KEV_URL,
           "catalogVersion": str(catalog.get("catalogVersion", ""))[:40],
           "dateReleased": str(catalog.get("dateReleased", ""))[:40],
           "downloaded_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
           "entries": rows}
    data = json.dumps(doc, ensure_ascii=False, indent=1).encode("utf-8")
    _kev_write(cache, KEV_FILE, data)
    _kev_write(cache, KEV_MANIFEST, (hashlib.sha256(data).hexdigest() + "  " + KEV_FILE + "\n").encode("ascii"))
    return {"entries": len(rows), "records_missing": missing, "catalogVersion": doc["catalogVersion"]}


def _kev_write(cache, name, data):
    os.makedirs(cache, exist_ok=True)
    final = os.path.join(os.path.abspath(cache), name)
    problem = path_problem(final)
    if problem:
        raise KevError("cache path refused: " + problem)
    fd, tmp = tempfile.mkstemp(dir=cache, prefix=".kev.")
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    os.replace(tmp, final)


def kev_load(cache):
    """(document, problem). The summary is refused if it changed since it was
    written (the hash beside it no longer matches)."""
    try:
        path = os.path.join(os.path.abspath(cache), KEV_FILE)
        with io.open(path, "rb") as fh:
            data = fh.read(KEV_MAX_BYTES + 1)
        with io.open(os.path.join(os.path.abspath(cache), KEV_MANIFEST), encoding="ascii") as fh:
            expected = fh.read(200).split()[0]
    except FileNotFoundError:
        return None, ""
    except (OSError, IndexError, UnicodeError) as exc:
        return None, "the exploited-software list could not be read: {}".format(exc)
    if hashlib.sha256(data).hexdigest() != expected:
        return None, "the exploited-software list changed since it was downloaded, so it was not used"
    try:
        doc = json.loads(data.decode("utf-8"))
        if not isinstance(doc.get("entries"), list):
            raise ValueError("no entries")
    except (ValueError, UnicodeError, AttributeError) as exc:
        return None, "the exploited-software list is damaged: {}".format(exc)
    return doc, ""


def kev_version(text):
    """A comparable tuple from a version string, or None if it has no digits
    or is a placeholder such as "unspecified" or a web address."""
    text = str(text or "").strip()
    if not text or text.lower() in ("unspecified", "n/a", "*", "-") or "://" in text:
        return None
    parts = re.findall(r"\d+", text)
    return tuple(int(p) for p in parts) if parts else None


def _kev_year_bound(bound, have):
    """True when a bound is a year rather than a version: some CVE records give
    `lessThan: "2021"` for a product numbered 27.2, and read as a version that
    makes every current release look out of date. A product that really is
    numbered by year (Office 2019) still compares."""
    return bool(bound) and len(bound) == 1 and 1990 <= bound[0] <= 2100 and have[0] < 1000


def _kev_cmp(a, b):
    n = max(len(a), len(b))
    a, b = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a > b) - (a < b)


def kev_affected(installed, ranges, product=None):
    """True if the installed version falls in an affected range, False if
    comparable ranges exist and it is outside all of them, None if the record
    gives nothing comparable (then only update advice is possible)."""
    have = kev_version(installed)
    if have is None:
        return None
    comparable = False
    for r in ranges:
        if product and r.get("product") and r["product"].lower() != product.lower():
            continue
        start = kev_version(r.get("version"))
        lt, le = kev_version(r.get("lessThan")), kev_version(r.get("lessThanOrEqual"))
        lt, le = (None if _kev_year_bound(lt, have) else lt), (None if _kev_year_bound(le, have) else le)
        if lt is None and le is None:
            continue
        comparable = True
        # Some vendors (Chrome's records, for one) repeat the fixed version as
        # the start, meaning "everything below it"; only a start below the end
        # of the range narrows it.
        end = lt if lt is not None else le
        if (start is not None and start != (0,) and _kev_cmp(start, end) < 0
                and _kev_cmp(have, start) < 0):
            continue
        if (lt is not None and _kev_cmp(have, lt) < 0) or (le is not None and _kev_cmp(have, le) <= 0):
            return True
    return False if comparable else None
