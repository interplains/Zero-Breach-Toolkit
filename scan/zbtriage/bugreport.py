"""An Android bug report, read as a phone collection - for people who cannot connect the phone to a computer.

Any Android phone can make a bug report by itself: Settings > About phone > tap "Build number" seven times to turn
on Developer options, then Settings > System > Developer options > "Take bug report" (or "Bug report"), and share
the .zip it makes to this computer. No USB debugging and no program to install on either side.

A bug report holds the phone's own account of itself: every system service's state (dumpsys), the system
properties, the settings tables, recent logs and crash records. It does NOT hold the apps' files, so their
fingerprints and signing certificates cannot be compared, nor the file list, text messages or a root-tool check.
This module turns the parts it does hold into the shapes the AndroidQF reader already understands, in a temporary
folder, so the same checks run on both. What a bug report cannot hold is reported as not checked, never as clean.

Read only: the bug report is opened as a ZIP (or a plain .txt from older phones), never unpacked as a whole, every
member read is size-capped, and nothing is contacted.
"""
import json
import os
import re
import shutil
import zipfile

BR_MAX_TEXT = 128 * 1024 * 1024        # the main bug report text (real ones are tens of MB)
BR_MAX_COPY = 1024 * 1024 * 1024       # a bug report copied for its crash records (real ones are under 200 MB)
ZIP_MAX_ENTRIES = 100000               # any ZIP opened by this tool (a bug report, an archive, an app)
# The size of the ZIP's list of contents. zipfile reads and parses the whole list, however many entries the ZIP
# CLAIMS to hold, so this - not the declared count, which a crafted file can set to 0 - is what bounds the work.
# Real ZIPs with 100,000 files have a list of about 10 MB.
ZIP_MAX_DIRECTORY = 16 * 1024 * 1024


def zip_directory(path: str):
    """(declared entry count, size in bytes of the list of contents), read from the ZIP's end records the same way
    zipfile finds them, or None when there is no end record (zipfile then refuses the file itself)."""
    import struct
    with open(path, "rb") as fh:
        fh.seek(0, 2)
        size = fh.tell()
        tail_len = min(size, 65536 + 22)
        fh.seek(size - tail_len)
        tail = fh.read(tail_len)
        # As zipfile: a record exactly at the end with no comment first, then the last one in the tail. A fake
        # signature written inside the real record must not be taken for it.
        if len(tail) >= 22 and tail[-22:-18] == b"PK\x05\x06" and tail[-2:] == b"\x00\x00":
            at = len(tail) - 22
        else:
            at = tail.rfind(b"PK\x05\x06")
        if at < 0 or at + 22 > len(tail):
            return None
        count, cd_size = struct.unpack_from("<HI", tail, at + 10)
        loc = at - 20                                     # ZIP64: the locator sits just before the end record
        if loc >= 0 and tail[loc:loc + 4] == b"PK\x06\x07":
            z64 = struct.unpack_from("<Q", tail, loc + 8)[0]
            if z64 + 56 <= size:
                fh.seek(z64)
                rec = fh.read(56)
                if rec[:4] == b"PK\x06\x06":
                    count, cd_size = struct.unpack_from("<QQ", rec, 32)
        # zipfile does not follow the locator's offset: it reads the ZIP64 record from just before the locator.
        # A crafted file can make the two places disagree, so the end record zipfile itself will use is read too
        # and the larger answer bounds the work.
        try:
            fh.seek(0)
            endrec = zipfile._EndRecData(fh)
            if endrec:
                count = max(count, int(endrec[zipfile._ECD_ENTRIES_TOTAL]))
                cd_size = max(cd_size, int(endrec[zipfile._ECD_SIZE]))
        except (AttributeError, IndexError, TypeError, ValueError, OSError, zipfile.BadZipFile):
            pass
        return count, cd_size


def zip_entry_count(path: str):
    """How many entries a ZIP says it holds (None if unknown)."""
    info = zip_directory(path)
    return info[0] if info else None


def zip_open(path: str) -> zipfile.ZipFile:
    """zipfile.ZipFile(path), refusing a ZIP whose list of contents is too large to read safely - by its size,
    which zipfile obeys, and by its declared count."""
    info = zip_directory(path)
    if info is not None:
        count, cd_size = info
        if cd_size > ZIP_MAX_DIRECTORY or count > ZIP_MAX_ENTRIES:
            raise ValueError("the ZIP's list of contents is too large to read safely ({:,} files declared, {:,} "
                             "bytes)".format(count, cd_size))
    return zipfile.ZipFile(path)
_BR_HEADER = re.compile(rb"^== dumpstate: (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)", re.M)
_BR_SECTION = re.compile(r"^------ (.+?) ------$", re.M)
_BR_SERVICE = re.compile(r"^DUMP OF SERVICE ([^:\n]+):\n", re.M)
_BR_SERVICE_END = re.compile(r"^-{9} [\d.]+s was the duration of dumpsys ", re.M)
_BR_SETTING = re.compile(r"\bname:(\S+)\s.*?\bvalue:(.*?)(?:\s+default:|\s+defaultSystemSet:|"
                         r"\s+preserve_in_restore:|\s*$)")
_BR_LOG_SECTIONS = ("SYSTEM LOG", "EVENT LOG", "RADIO LOG", "LAST LOGCAT", "SECURITY LOG", "CRASH LOG")
_BR_SYSTEM_CODE = ("/system/", "/product/", "/vendor/", "/system_ext/", "/apex/", "/odm/", "/oem/")


def br_main_member(z: zipfile.ZipFile):
    """The ZipInfo of the main bug report text inside a bug report ZIP, or None."""
    infos = z.infolist()[:20000]
    by_name = {i.filename: i for i in infos}
    entry = by_name.get("main_entry.txt")
    if entry is not None and entry.file_size < 4096:
        name = z.read(entry).decode("utf-8", "replace").strip()
        if name in by_name:
            return by_name[name]
    candidates = [i for i in infos if "/" not in i.filename and
                  re.match(r"(?i)(bugreport|dumpstate)[^/]*\.txt$", i.filename)]
    return max(candidates, key=lambda i: i.file_size) if candidates else None


def br_is_bugreport(path: str) -> bool:
    """A bug report ZIP (or an older phone's bug report .txt), recognised by its contents, not its name."""
    try:
        if not os.path.isfile(path):
            return False
        with open(path, "rb") as fh:
            head = fh.read(4096)
        if head[:2] == b"PK":
            with zip_open(path) as z:
                member = br_main_member(z)
                if member is None:
                    return False
                with z.open(member) as fh:
                    return bool(_BR_HEADER.search(fh.read(4096)))
        return bool(_BR_HEADER.search(head))
    except (OSError, zipfile.BadZipFile, RuntimeError, NotImplementedError, ValueError):
        return False


def br_read_text(path: str):
    """(the main bug report text, size-capped; True when the text was longer than the cap and was cut)."""
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head[:2] == b"PK":
        with zip_open(path) as z:
            member = br_main_member(z)
            if member is None:
                raise ValueError("no bug report text inside the ZIP")
            with z.open(member) as fh:
                raw = fh.read(BR_MAX_TEXT + 1)
    else:
        with open(path, "rb") as fh:
            raw = fh.read(BR_MAX_TEXT + 1)
    cut = len(raw) > BR_MAX_TEXT
    return raw[:BR_MAX_TEXT].decode("utf-8", "replace").replace("\r\n", "\n"), cut


def br_made_at(text: str) -> str:
    m = _BR_HEADER.search(text[:4096].encode("utf-8", "replace"))
    return m.group(1).decode("ascii").replace(" ", "T") if m else ""


def br_sections(text: str):
    """{section title: body} for the '------ TITLE (command) ------' blocks of a bug report."""
    out = {}
    marks = list(_BR_SECTION.finditer(text))
    for i, m in enumerate(marks):
        title = m.group(1)
        if " was the duration of " in title:
            continue
        end = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        out.setdefault(title.split(" (", 1)[0].strip(), []).append(text[m.end():end])
    return {k: "\n".join(v) for k, v in out.items()}


def br_dumpsys(text: str) -> str:
    """Every 'DUMP OF SERVICE' block, each cut where the bug report closes it - the shape of `dumpsys` output."""
    blocks = []
    marks = list(_BR_SERVICE.finditer(text))
    for i, m in enumerate(marks):
        limit = marks[i + 1].start() if i + 1 < len(marks) else len(text)
        body = text[m.end():limit]
        stop = _BR_SERVICE_END.search(body)
        if stop:
            body = body[:stop.start()]
        else:
            top = _BR_SECTION.search(body)
            if top:
                body = body[:top.start()]
        blocks.append("DUMP OF SERVICE {}:\n{}".format(m.group(1), body.rstrip("\n") + "\n"))
    return "".join(blocks)


def br_settings(dumpsys_settings: str):
    """{'global': {...}, 'secure': {...}, 'system': {...}} for the main user, from dumpsys settings."""
    out = {"global": {}, "secure": {}, "system": {}}
    current = None
    for line in dumpsys_settings.splitlines():
        head = re.match(r"^(GLOBAL|SECURE|SYSTEM) SETTINGS \(user (\d+)\)", line)
        if head:
            current = head.group(1).lower() if head.group(2) == "0" else None   # the phone's main user only
            continue
        if not line.startswith("_id:"):
            if line and not line[0].isspace():
                current = None                  # any other top-level line closes the table
            continue
        if current:
            m = _BR_SETTING.search(line)
            if m and m.group(1) not in out[current]:
                value = m.group(2).strip()
                out[current][m.group(1)] = "" if value == "null" else value
    return out


def br_packages(package_section: str):
    """The app list from dumpsys package, in the shape of AndroidQF's packages.json - without app files, which a
    bug report does not contain."""
    apps, current = [], None
    in_list = False
    for line in package_section.splitlines():
        if re.match(r"^Packages:\s*$", line):
            in_list = True
            continue
        if in_list and line and not line[0].isspace():
            in_list = False                     # the next top-level table (Hidden system packages, Queries ...)
        if not in_list:
            continue
        m = re.match(r"^\s+Package \[([^\]]+)\]", line)
        if m:
            current = {"name": m.group(1), "files": [], "installer": "", "system": False, "third_party": True,
                       "first_install_time": ""}
            apps.append(current)
            continue
        if current is None:
            continue
        s = line.strip()
        if s.startswith("codePath=") and s[len("codePath="):].startswith(_BR_SYSTEM_CODE):
            current["system"], current["third_party"] = True, False
        elif re.match(r"(pkgFlags|flags)=\[.*\bSYSTEM\b", s):
            current["system"], current["third_party"] = True, False
        elif s.startswith("installerPackageName=") and not current["installer"]:
            value = s.split("=", 1)[1].strip()
            current["installer"] = "" if value == "null" else value
        elif s.startswith("initiatingPackageName=") and not current["installer"]:
            value = s.split("=", 1)[1].strip()
            current["installer"] = "" if value == "null" else value
        elif s.startswith("firstInstallTime=") and not current["first_install_time"]:
            current["first_install_time"] = s.split("=", 1)[1].strip()
    return apps


# A running process in `dumpsys activity`: "ProcessRecord{1a2b3c 4321:com.example.app:remote/u0a123}" and the LRU
# list's "4321:com.example.app/u0a123". On Android a process is named after its app (plus ":part"), so these are the
# running apps by app id - what the AndroidQF process list holds.
_BR_PROCESS = re.compile(r"(?<![\w.:])(\d{1,7}):([A-Za-z][\w]*(?:\.[\w]+)+(?::[\w.]+)?)/(?:u\d+[a-z]?\d*|\d{1,6})\b")
BR_MAX_PROCESSES = 20000


def br_processes(dumpsys: str):
    """[(pid, process name)] of the running processes named in the activity manager's part of the bug report."""
    m = re.search(r"^DUMP OF SERVICE activity:\n(.*?)(?=^DUMP OF SERVICE |\Z)", dumpsys, re.M | re.S)
    body = m.group(1) if m else ""
    seen, out = set(), []
    for pid, name in _BR_PROCESS.findall(body):
        if name not in seen:
            seen.add(name)
            out.append((int(pid), name))
            if len(out) >= BR_MAX_PROCESSES:
                break
    return out


def br_to_collection(path: str, out_dir: str):
    """Write the parts of a bug report the AndroidQF reader understands into out_dir. Returns what was found."""
    text, cut = br_read_text(path)
    sections = br_sections(text)
    dumpsys = br_dumpsys(text)
    services = {}
    for m in re.finditer(r"^DUMP OF SERVICE ([^:\n]+):\n", dumpsys, re.M):
        services.setdefault(m.group(1).strip(), m.end())
    found = {"made": br_made_at(text), "services": len(services), "properties": 0, "settings": 0, "apps": 0,
             "log_bytes": 0, "cut": cut}
    with open(os.path.join(out_dir, "dumpsys.txt"), "w", encoding="utf-8") as fh:
        fh.write(dumpsys)
    props = sections.get("SYSTEM PROPERTIES", "")
    prop_lines = [ln.strip() for ln in props.splitlines() if ln.strip().startswith("[") and "]: [" in ln]
    found["properties"] = len(prop_lines)
    if prop_lines:
        with open(os.path.join(out_dir, "getprop.txt"), "w", encoding="utf-8") as fh:
            fh.write("\n".join(prop_lines) + "\n")
    settings_body = ""
    m = re.search(r"^DUMP OF SERVICE settings:\n(.*?)(?=^DUMP OF SERVICE |\Z)", dumpsys, re.M | re.S)
    if m:
        settings_body = m.group(1)
    tables = br_settings(settings_body)
    for kind, values in tables.items():
        if values:
            found["settings"] += len(values)
            with open(os.path.join(out_dir, "settings_{}.txt".format(kind)), "w", encoding="utf-8") as fh:
                fh.write("".join("{}={}\n".format(k, v) for k, v in values.items()))
    logs = "\n".join(sections[name] for name in _BR_LOG_SECTIONS if name in sections)
    found["log_bytes"] = len(logs)
    if logs:
        with open(os.path.join(out_dir, "logcat.txt"), "w", encoding="utf-8") as fh:
            fh.write(logs)
    m = re.search(r"^DUMP OF SERVICE package:\n(.*?)(?=^DUMP OF SERVICE |\Z)", dumpsys, re.M | re.S)
    apps = br_packages(m.group(1)) if m else []
    found["apps"] = len(apps)
    with open(os.path.join(out_dir, "packages.json"), "w", encoding="utf-8") as fh:
        json.dump(apps, fh)
    processes = br_processes(dumpsys)
    found["processes"] = len(processes)
    if processes:
        with open(os.path.join(out_dir, "processes.txt"), "w", encoding="utf-8") as fh:
            fh.write("PID NAME\n" + "".join("{} {}\n".format(pid, name) for pid, name in processes))
    with open(os.path.join(out_dir, "acquisition.json"), "w", encoding="utf-8") as fh:
        json.dump({"started": found["made"], "source": "Android bug report"}, fh)
    with open(path, "rb") as fh:
        is_zip = fh.read(2) == b"PK"
    if is_zip and os.path.getsize(path) <= BR_MAX_COPY:
        shutil.copyfile(path, os.path.join(out_dir, "bugreport.zip"))     # crash records are read from it
    elif is_zip:
        found["too_big_to_copy"] = True
    return found


# What each AndroidQF-only part means when the input was a bug report (shown instead of the collection file name).
BR_NOT_IN_A_BUG_REPORT = {
    "android:processes": "this bug report did not include the list of running apps (the activity manager part "
                         "is missing or empty)",
    "android:files": "a bug report does not include the phone's file list",
    "android:root": "a bug report does not include the root-tool check",
    "android:messages": "a bug report does not include text messages",
    "android:app-fingerprints": "a bug report does not include the apps' files, so their fingerprints were "
                                "not compared",
    "android:app-certificates": "a bug report does not include the apps' files, so their signing certificates "
                                "were not compared",
    "android:device-security": "the SELinux and storage-mount records are not read from a bug report",
}
