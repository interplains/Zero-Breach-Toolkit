"""Read decrypted Android Intrusion Logging exports, without device access.

Format facts (not parser code): AndroidQF v1.8.3 modules/intrusion_logs.go
copies intrusion_logs/*; docs.mvt.re/en/latest/android/intrusion_logs/ documents
the .txt newline-JSON wrappers. Android's SecurityLog, DnsEvent, ConnectEvent
and developer.android.com/work/dpc/logging define their payloads and meaning.
ConnectEvent includes failed connections: it does NOT prove successful contact.
"""
import datetime
import hashlib
import io
import ipaddress
import json
import os
import re
import stat
import struct
import time
import zipfile
import zlib

from ..bugreport import br_is_bugreport
from ..iocs import ios_only
from ..localpaths import path_problem
from ..result import EV_DEVICE_LOG, EV_DNS, Hit, ModuleResult

NAME = "android-intrusion"
_IL_FILE_LIMIT = 32 * 1024 * 1024
_IL_TOTAL_LIMIT = 128 * 1024 * 1024
_IL_LINE_LIMIT = 128 * 1024
_IL_EVENT_LIMIT = 200000
_IL_ENTRY_LIMIT = 2048
_IL_SECONDS = 30
_IL_CHECKS = {"dns_event": "android-intrusion:dns",
              "connect_event": "android-intrusion:connections",
              "security_event": "android-intrusion:processes"}


def _il_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key] = value
    return out


def _il_timestamp(value):
    if type(value) is not int or not 0 <= value <= 253402300799999:
        raise ValueError("invalid event timestamp")
    return (datetime.datetime(1970, 1, 1, tzinfo=datetime.timezone.utc) +
            datetime.timedelta(milliseconds=value)).isoformat(timespec="milliseconds")


def _il_string(value, limit=1024, empty=False):
    if (not isinstance(value, str) or len(value) > limit or
            (not empty and not value) or any(ord(c) < 32 for c in value)):
        raise ValueError("invalid string field")
    return value


def _il_address(value):
    value = _il_string(value, 64)
    if "%" in value:
        raise ValueError("scoped address is unsupported")
    return str(ipaddress.ip_address(value))


def _il_hostname(value):
    value = _il_string(value, 254).lower()
    value = value[:-1] if value.endswith(".") else value
    try:
        return _il_address(value)
    except ValueError:
        pass
    value = value.encode("idna").decode("ascii")
    if (len(value) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p)
                               for p in value.split("."))):
        raise ValueError("invalid DNS hostname")
    return value


def _il_zip_guard(raw):
    """Bound central-directory allocation before ZipFile constructs its index."""
    at = raw.rfind(b"PK\x05\x06", max(0, len(raw) - 65557))
    if at < 0 or at + 22 > len(raw):
        raise ValueError("unsupported or malformed ZIP trailer")
    disk, start, count_disk, count, size, offset, comment = struct.unpack_from("<4H2IH", raw, at + 4)
    if (disk or start or count_disk != count or count > _IL_ENTRY_LIMIT or
            size > 2 * 1024 * 1024 or offset + size != at or
            at + 22 + comment != len(raw) or b"PK\x06\x07" == raw[max(0, at - 20):at - 16]):
        raise ValueError("split, ZIP64, oversized or malformed ZIP index")


class _IlReader:
    def __init__(self, ctx, result):
        self.ctx, self.result = ctx, result
        self.gaps, self.ran, self.seen = {}, set(), set()
        self.entries = self.total = self.events = self.duplicates = 0
        self.deadline = time.monotonic() + _IL_SECONDS

    def gap(self, check, reason):
        key = (check, reason)
        self.gaps[key] = self.gaps.get(key, 0) + 1
        self.result.skipped += 1

    def budget(self):
        if time.monotonic() > self.deadline:
            raise ValueError("processing time limit reached")
        if self.entries > _IL_ENTRY_LIMIT or self.total > _IL_TOTAL_LIMIT:
            raise ValueError("input entry or byte limit reached")
        if self.events >= _IL_EVENT_LIMIT:
            raise ValueError("event limit reached")

    def hit(self, ind, grade, where, original, observed, detail):
        if ind is not None:
            self.result.add_hit(Hit(ind.value, where, detail, ind.tier, ind.confidence,
                                   ind.source, grade, observed, family=ind.family,
                                   kind=ind.type, artifact=original))

    def event(self, record, where, original):
        if not isinstance(record, dict) or len(record) != 1:
            raise ValueError("unsupported event wrapper")
        kind, data = next(iter(record.items()))
        if kind not in _IL_CHECKS or not isinstance(data, dict):
            raise ValueError("unsupported event wrapper")
        observed = _il_timestamp(data.get("event_time"))
        matches = []
        if kind in ("dns_event", "connect_event"):
            package = data.get("package_name")
            if package is not None:
                _il_string(package, 1024, empty=True)
            if kind == "dns_event":
                host = _il_hostname(data.get("hostname"))
                addresses = data.get("ip_addresses")
                if not isinstance(addresses, list) or len(addresses) > 64:
                    raise ValueError("invalid DNS address list")
                addresses = [_il_address(value) for value in addresses]
                ind = self.ctx.iocs.lookup_typed("ip", host)
                labels = host.split(".")
                for n in range(len(labels)):
                    if ind is None:
                        ind = self.ctx.iocs.lookup_typed("domain", ".".join(labels[n:]))
                matches.append((ind, EV_DNS, "DNS lookup; endpoint contact is unverified"))
                for address in set(addresses):
                    matches.append((self.ctx.iocs.lookup_typed("ip", address), EV_DNS,
                                    "address returned in a DNS event; endpoint contact is unverified"))
            else:
                address = _il_address(data.get("ip_address"))
                port = data.get("port")
                if type(port) is not int or not 1 <= port <= 65535:
                    raise ValueError("invalid TCP port")
                matches.append((self.ctx.iocs.lookup_typed("ip", address), EV_DEVICE_LOG,
                                "TCP connection attempt to port {}; successful contact is unverified".format(port)))
            if package:
                matches.append((self.ctx.iocs.lookup_typed("app-id", package), EV_DEVICE_LOG,
                                "app identity recorded for a {}".format(kind.replace("_", " "))))
        else:
            tag, fields = data.get("tag"), data.get("data")
            if type(tag) is not int or tag != 210005:
                self.gap("android-intrusion:security-events", "security event tag is unsupported; payload was not interpreted")
                return
            if (not isinstance(fields, list) or len(fields) != 6 or
                    type(fields[2]) is not int or fields[2] < 0 or
                    type(fields[3]) is not int or fields[3] <= 0):
                raise ValueError("unsupported process-start payload")
            name = _il_string(fields[0])
            observed = _il_timestamp(fields[1])
            _il_string(fields[4], empty=True)
            digest = _il_string(fields[5], 64, empty=True).lower()
            if digest and not re.fullmatch("[0-9a-f]{64}", digest):
                raise ValueError("invalid process APK hash")
            # Generic process indicators include names published for iOS. Their
            # presence in an Android process-start event cannot establish the
            # platform association, so match only app IDs and APK fingerprints.
            for typ, value in (("app-id", name.split(":", 1)[0]), ("sha256", digest)):
                matches.append((self.ctx.iocs.lookup_typed(typ, value), EV_DEVICE_LOG,
                                "historical app process start; current presence is unverified"))
        # Only fully validated payloads contribute observations.
        identity = hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).digest()
        if identity in self.seen:
            self.duplicates += 1
            return
        self.seen.add(identity)
        for ind, grade, detail in matches:
            if ind is not None and ios_only(ind):
                continue        # an iPhone bundle id, not an Android package
            self.hit(ind, grade, where, original, observed, detail)
        self.ran.add(_IL_CHECKS[kind])
        self.result.checked += 1

    def content(self, stream, name, original, depth=0):
        self.entries += 1
        self.budget()
        suffix = os.path.splitext(name)[1].lower()
        if suffix not in (".txt", ".zip"):
            raise ValueError("unsupported or encrypted file; only decrypted .txt logs and ZIP containers are supported")
        raw = stream.read(_IL_FILE_LIMIT + 1)
        self.total += len(raw)
        if len(raw) > _IL_FILE_LIMIT:
            raise ValueError("file size limit reached")
        self.budget()
        if suffix == ".zip":
            if depth >= 2:
                raise ValueError("nested ZIP depth limit reached")
            _il_zip_guard(raw)
            with zipfile.ZipFile(io.BytesIO(raw)) as archive:
                for entry in archive.infolist():
                    self.budget()
                    if entry.is_dir():
                        continue
                    try:
                        parts = entry.filename.replace("\\", "/").split("/")
                        mode = entry.external_attr >> 16
                        # BZIP2/LZMA codecs can allocate input-controlled native
                        # state before the decompressed output bound is applied.
                        if (entry.flag_bits & 1 or entry.file_size > _IL_FILE_LIMIT or
                                entry.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED) or
                                entry.filename.startswith(("/", "\\")) or
                                any(p in ("", ".", "..") or ":" in p for p in parts) or
                                stat.S_ISLNK(mode)):
                            raise ValueError("encrypted, oversized or unsafe ZIP member")
                        with archive.open(entry) as member:
                            self.content(member, name + "!" + entry.filename, original, depth + 1)
                    except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, NotImplementedError, zlib.error):
                        self.gap("android-intrusion:files", "ZIP member unreadable, encrypted, unsupported or beyond limits")
            return
        lines = io.BytesIO(raw)
        line_number = 0
        while True:
            self.budget()
            line = lines.readline(_IL_LINE_LIMIT + 1)
            if not line:
                break
            line_number += 1
            self.events += 1
            if len(line) > _IL_LINE_LIMIT:
                while line and not line.endswith(b"\n"):
                    line = lines.readline(_IL_LINE_LIMIT + 1)
                    self.budget()
                self.gap("android-intrusion:files", "oversized event line")
                continue
            if not line.strip():
                continue
            try:
                record = json.loads(line.decode("utf-8-sig" if line_number == 1 else "utf-8"),
                                    object_pairs_hook=_il_object,
                                    parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
                self.event(record, name + ":" + str(line_number), original)
            except (ValueError, UnicodeError, RecursionError, OverflowError):
                self.gap("android-intrusion:files", "malformed or unsupported event record")

    def directory(self, root):
        pending = [(root, 0)]
        while pending:
            folder, depth = pending.pop()
            self.budget()
            if path_problem(folder):
                self.gap("android-intrusion:files", "a log directory was refused")
                continue
            try:
                with os.scandir(folder) as entries:
                    for entry in entries:
                        self.entries += 1
                        self.budget()
                        try:
                            if path_problem(entry.path):
                                raise ValueError("refused path")
                            mode = entry.stat(follow_symlinks=False).st_mode
                            if stat.S_ISDIR(mode):
                                if depth >= 8:
                                    raise ValueError("directory depth limit reached")
                                pending.append((entry.path, depth + 1))
                            elif stat.S_ISREG(mode):
                                with open(entry.path, "rb") as handle:
                                    self.content(handle, entry.path, entry.path)
                            else:
                                raise ValueError("special file refused")
                        except (OSError, ValueError, RuntimeError, zipfile.BadZipFile, NotImplementedError, zlib.error):
                            self.gap("android-intrusion:files", "a log file was refused, unreadable, encrypted, unsupported or beyond limits")
            except OSError:
                self.gap("android-intrusion:files", "a log directory could not be enumerated")

    def finish(self):
        for check in sorted(self.ran):
            self.result.ran(check)
        for (check, reason), count in self.gaps.items():
            self.result.could_not_run(check, "{} ({} occurrence{})".format(reason, count, "s" if count != 1 else ""))
        self.result.submetrics.update(intrusion_events=self.result.checked,
                                      intrusion_duplicate_events=self.duplicates,
                                      intrusion_bytes_read=self.total)


def run(ctx) -> ModuleResult:
    r = ModuleResult(NAME)
    ctx.partial = r
    reader = _IlReader(ctx, r)
    supplied = getattr(ctx, "phone_path", "")
    try:
        if not supplied:
            raise ValueError("no local phone collection selected")
        root = os.path.abspath(supplied)
        if not path_problem(root) and os.path.isfile(root) and br_is_bugreport(root):
            reason = "A bug report does not contain Intrusion Logging; no intrusion events were examined."
            r.note(reason)
            r.inapplicable_reason = reason
            return r
        if path_problem(root) or not os.path.isdir(root):
            raise ValueError("collection path unavailable or refused")
        roots = [root] if os.path.basename(root).lower() in ("intrusion_logs", "intrusion-logs") else [
            os.path.join(root, part) for part in ("intrusion_logs", "intrusion-logs")]
        found = False
        for folder in roots:
            if path_problem(folder):
                raise ValueError("intrusion log path refused")
            if os.path.lexists(folder):
                found = True
                reader.directory(folder)
        if not found:
            r.note("Optional Intrusion Logging export is absent; no intrusion events were examined.")
            r.inapplicable_reason = "Optional Intrusion Logging export is absent; no intrusion events were examined."
        elif not r.checked and not reader.gaps:
            reader.gap("android-intrusion:files", "no supported intrusion events were available")
    except (OSError, ValueError):
        reader.gap("android-intrusion:files", "log input unavailable, refused or a processing limit was reached")
    finally:
        reader.finish()
    return r
