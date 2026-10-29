"""Bounded iOS evidence sources. Never write to an input or resolve its links.

Backup file keys and artifact names come from the manifest. Filesystem and
sysdiagnose inputs are explicit, already acquired local evidence. Archive names
are inventory keys only: members are never extracted to their supplied paths.
"""
import contextlib
import hashlib
import io
import os
import plistlib
import re
import shutil
import sqlite3
import stat
import struct
import tarfile
import tempfile
import time

from .backupcrypto import backup_cbc, backup_ios_keys, backup_ios_file_key
from .localpaths import local_temp_dir, open_evidence_db, path_problem

# Sized for a full backup of a current phone: a 512 GB phone with a large photo
# library has a Manifest.db over 300 MB with 240,000 or more rows, and an
# Info.plist over 16 MiB. The limits still bound what a crafted input can make
# the check hold in memory, but they no longer stop it on ordinary phones.
_IS_FILE_LIMIT = 1024 * 1024 * 1024
_IS_TOTAL_LIMIT = 8 * 1024 * 1024 * 1024
_IS_ENTRIES = 1000000
_IS_WALK_ENTRIES = 5000000
_IS_ARCHIVE_LIMIT = 4 * 1024 * 1024 * 1024
_IS_PLIST_LIMIT = 64 * 1024 * 1024


def _is_size_text(size):
    """A byte count as people say it: '312 MB', '1.5 GB'."""
    if size >= 1024 * 1024 * 1024:
        return "{:.1f} GB".format(size / (1024.0 * 1024 * 1024))
    if size >= 1024 * 1024:
        return "{:.0f} MB".format(size / (1024.0 * 1024))
    return "{:,} bytes".format(size)


def _is_over_limit(name, size, limit):
    """Gap text that names the file, its size and the limit it went over."""
    return "{} is {}, over the {} limit for one file".format(name, _is_size_text(size), _is_size_text(limit))


def _is_safe_parts(value):
    if not isinstance(value, str) or len(value) > 4096 or "\\" in value or "\0" in value:
        raise ValueError("unsupported evidence path")
    parts = value.split("/")
    if any(p in ("", ".", "..") or ":" in p or p.endswith((".", " ")) for p in parts):
        raise ValueError("unsafe evidence path")
    return parts


def _is_plist(raw):
    # plistlib rejects XML external entities; no object classes are instantiated.
    from xml.parsers.expat import ExpatError
    if not isinstance(raw, bytes):
        raise ValueError("property-list byte limit reached")
    if len(raw) > _IS_PLIST_LIMIT:
        raise ValueError("property list is {}, over the {} limit (property-list byte limit reached)".format(
            _is_size_text(len(raw)), _is_size_text(_IS_PLIST_LIMIT)))
    try:
        doc = plistlib.loads(raw)
    except (ExpatError, RecursionError) as exc:
        raise ValueError("malformed or excessively nested property list") from exc
    pending, count = [(doc, 0)], 0
    while pending:
        obj, depth = pending.pop()
        count += 1
        if count > 100000 or depth > 32:
            raise ValueError("property-list structure limit reached")
        if isinstance(obj, dict):
            pending.extend((v, depth + 1) for v in obj.values())
        elif isinstance(obj, (list, tuple)):
            pending.extend((v, depth + 1) for v in obj)
    return doc


def _is_wal_prefix(raw, database, max_bytes=None):
    """Validate SQLite's published WAL format; return committed prefix + issues.

SQLite does the replay on disposable copies. This validation prevents silent
discard of a damaged WAL from being reported as complete coverage. Stale frames
from an earlier salt epoch and valid uncommitted tails are not committed data.
"""
    # The caller's own size policy: a phone extraction is capped at
    # _IS_FILE_LIMIT, a desktop browser snapshot at its own larger limit.
    max_bytes = _IS_FILE_LIMIT if max_bytes is None else max_bytes
    if not raw:
        return b"", []
    if len(raw) < 32 or len(database) < 100:
        return b"", ["truncated WAL or database header"]
    magic, version, page, sequence, salt1, salt2, c0, c1 = struct.unpack_from(">8I", raw)
    db_page = struct.unpack_from(">H", database, 16)[0]
    db_page = 65536 if db_page == 1 else db_page
    if (magic not in (0x377f0682, 0x377f0683) or version != 3007000
            or page != db_page or not 512 <= page <= 65536 or page & (page - 1)):
        return b"", ["unsupported or mismatched WAL header"]
    order = "<II" if magic == 0x377f0682 else ">II"
    def checksum(data, a=0, b=0):
        for x, y in struct.iter_unpack(order, data):
            a = (a + x + b) & 0xffffffff
            b = (b + y + a) & 0xffffffff
        return a, b
    if checksum(raw[:24]) != (c0, c1):
        return b"", ["WAL header checksum failed"]
    position, committed, issues = 32, 0, []
    deadline = time.monotonic() + 20
    view = memoryview(raw)
    while position < len(raw):
        if time.monotonic() > deadline:
            issues.append("WAL validation time limit reached")
            break
        if position + 24 + page > len(raw):
            issues.append("truncated WAL frame")
            break
        number, size, s1, s2, expected0, expected1 = struct.unpack_from(">6I", raw, position)
        if (s1, s2) != (salt1, salt2):
            break  # old epoch after a WAL reset; SQLite ignores this tail too
        if not number or number * page > max_bytes or size * page > max_bytes:
            issues.append("WAL page or database size exceeds the limit")
            break
        c0, c1 = checksum(view[position:position + 8], c0, c1)
        c0, c1 = checksum(view[position + 24:position + 24 + page], c0, c1)
        if (c0, c1) != (expected0, expected1):
            issues.append("WAL frame checksum failed")
            break
        position += 24 + page
        if size:
            committed = position
    return raw[:committed] if committed else b"", issues


class _IsLimitedStream:
    """Bound decompressed TAR traversal, including metadata and skipped members."""
    def __init__(self, stream):
        self.stream, self.total = stream, 0
        self.deadline = time.monotonic() + 60

    def read(self, size=-1):
        if time.monotonic() > self.deadline or self.total >= _IS_ARCHIVE_LIMIT:
            raise ValueError("archive expansion/time limit reached")
        data = self.stream.read(min(size if size >= 0 else 65536,
                                    _IS_ARCHIVE_LIMIT - self.total + 1))
        self.total += len(data)
        if self.total > _IS_ARCHIVE_LIMIT:
            raise ValueError("archive expansion limit reached")
        return data


class _IsTarInfo(tarfile.TarInfo):
    def _proc_member(self, archive):
        if self.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME,
                         tarfile.GNUTYPE_LONGLINK) and self.size > 65536:
            raise ValueError("archive extended header exceeds the limit")
        if self.type == tarfile.GNUTYPE_SPARSE:
            raise ValueError("sparse archive headers are unsupported")
        return super()._proc_member(archive)


class IosEvidenceSource:
    """Owns plaintext lifetime, inventory, snapshots and per-artifact provenance."""
    def __init__(self, folder, kind, password, gap, emit, read, query, tables, unarchive,
                 inventory_limit=_IS_ENTRIES, keep_names=frozenset()):
        self.root, self.kind = os.path.abspath(folder), kind
        self.gap, self.emit, self.read_file = gap, emit, read
        self.query, self.tables, self.unarchive = query, tables, unarchive
        self.tmp, self.connections, self.entries = None, [], []
        self.database_serial = 0
        self.index, self.keys, self.encrypted = None, {}, False
        self.total, self.provenance, self.cached = 0, {}, {}
        self.inventory_complete = False
        self.info = {}
        self.password = password
        self.inventory_limit = min(inventory_limit, _IS_ENTRIES)
        # Lower-case file names that loaded file-name indicators name: such
        # files are inventoried (by name only) even when no reader opens them.
        self.keep_names = keep_names

    def start(self):
        if path_problem(self.root):
            raise ValueError("refused iPhone evidence root")
        self.tmp = tempfile.mkdtemp(prefix="zbt_ios_", dir=local_temp_dir())
        if self.kind == "backup":
            try:
                manifest = _is_plist(self.read_file(os.path.join(self.root, "Manifest.plist"), 4 * 1024 * 1024))
            except FileNotFoundError:
                # A partial copy can lack Manifest.plist. A Manifest.db that is
                # already readable SQLite can only be an unencrypted backup.
                if self._read(os.path.join(self.root, "Manifest.db"))[:16] != b"SQLite format 3\x00":
                    raise
                self.gap("ios:manifest", "Manifest.plist is missing; the backup was read as unencrypted "
                         "because its file list is readable without a key")
                manifest = {}
            if not isinstance(manifest, dict):
                raise ValueError("Manifest.plist is not a dictionary")
            self.encrypted = manifest.get("IsEncrypted") is True
            self.keys = backup_ios_keys(manifest.get("BackupKeyBag"), self.password) if self.encrypted else {}
            self.password = ""
            path = os.path.join(self.root, "Manifest.db")
            raw = self._read(path)
            self._remember(("", "Manifest.db"), path, raw)
            if self.encrypted:
                self.emit("[ios] unlocking the local backup manifest")
                raw = backup_cbc(backup_ios_file_key(self.keys, manifest.get("ManifestKey")), raw, unpad=True)
            wal = b""
            sidecar = path + "-wal"
            if path_problem(sidecar) or os.path.lexists(sidecar):
                if self.encrypted:
                    self.gap("ios:manifest", "encrypted manifest WAL has no independent key metadata; not replayed")
                else:
                    try:
                        wal = self._read(sidecar)
                        self._remember(("", "Manifest.db-wal"), sidecar, wal)
                    except (OSError, ValueError) as exc:
                        self.gap("ios:manifest", "manifest WAL unreadable: " + str(exc))
            self.index = self.database(raw, "ios:manifest", wal)
            self.tables(self.index, ("Files",))
            try:
                with self.query(self.index, "SELECT fileID,domain,relativePath,flags FROM Files") as rows:
                    for n, row in enumerate(rows):
                        if n >= self.inventory_limit:
                            raise ValueError("Manifest.db lists more than {:,} files, the most this "
                                             "check reads (manifest row limit reached)".format(self.inventory_limit))
                        fid, domain, relative, flags = row
                        if flags != 1:
                            continue
                        if (not isinstance(fid, str) or not re.fullmatch(r"[0-9a-f]{40}", fid)
                                or not isinstance(domain, str) or not isinstance(relative, str)):
                            self.gap("ios:manifest", "invalid manifest record")
                            continue
                        self.entries.append((domain, relative))
                self.inventory_complete = True
            except (sqlite3.Error, ValueError) as exc:
                self.gap("ios:manifest", "manifest inventory incomplete: " + str(exc))
            try:
                info = _is_plist(self.read_file(os.path.join(self.root, "Info.plist"), 32 * 1024 * 1024))
                if isinstance(info, dict):
                    self.info = info
            except (OSError, ValueError, plistlib.InvalidFileException):
                pass
        elif self.kind in ("filesystem", "sysdiagnose"):
            if os.path.isdir(self.root):
                self._directory()
            elif self.kind == "sysdiagnose":
                try:
                    self._archive()
                except (OSError, ValueError, tarfile.TarError, EOFError) as exc:
                    self.gap("ios:input", "archive inventory incomplete: " + str(exc))
            else:
                raise ValueError("filesystem evidence must be an extracted local directory")
        else:
            raise ValueError("unsupported iPhone input format")
        return self

    def _read(self, path, limit=_IS_FILE_LIMIT):
        data = self.read_file(path, limit)
        self.total += len(data)
        if self.total > _IS_TOTAL_LIMIT:
            raise ValueError("iPhone total read budget reached ({} read)".format(_is_size_text(self.total)))
        return data

    def _remember(self, key, path, raw, member=""):
        self.provenance[key] = {"source": path, "member": member,
            "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw),
            "input_format": self.kind, "encrypted_source": self.encrypted,
            "parser": "ios-evidence/1", "integrity": "hash of bytes read; not device authenticity"}

    def _directory(self):
        # A full file system has a million or more entries; only files a reader
        # can open are inventoried, so the walk itself has a larger bound.
        pending, count, kept = [(self.root, 0)], 0, 0
        deadline = time.monotonic() + 600
        while pending:
            folder, depth = pending.pop()
            if time.monotonic() > deadline:
                self.gap("ios:input", "directory discovery time limit reached")
                return
            try:
                if path_problem(folder):
                    raise ValueError("redirected evidence directory")
                with os.scandir(folder) as entries:
                    for entry in entries:
                        count += 1
                        if count > _IS_WALK_ENTRIES:
                            self.gap("ios:input", "directory discovery entry limit reached")
                            return
                        info = entry.stat(follow_symlinks=False)
                        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                            self.gap("ios:input", "link or reparse entry was not followed")
                        elif stat.S_ISDIR(info.st_mode):
                            if depth >= 32:
                                self.gap("ios:input", "directory discovery depth limit reached")
                            else:
                                pending.append((entry.path, depth + 1))
                        elif stat.S_ISREG(info.st_mode):
                            if not (_is_archive_candidate(entry.name) or entry.name == "History"
                                    or entry.name.lower() in self.keep_names):
                                continue
                            kept += 1
                            if kept > _IS_ENTRIES:
                                self.gap("ios:input", "directory discovery entry limit reached")
                                return
                            self.entries.append(("", os.path.relpath(entry.path, self.root).replace(os.sep, "/")))
                        else:
                            self.gap("ios:input", "special filesystem entry was not opened")
            except (OSError, ValueError) as exc:
                self.gap("ios:input", "directory unreadable: " + str(exc))
        self.inventory_complete = True

    def _archive(self):
        import gzip
        # Streaming traversal avoids allocating an unbounded member index. Only
        # recognized forensic filenames are retained, under opaque local names.
        info = os.stat(self.root, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _IS_ARCHIVE_LIMIT:
            raise ValueError("sysdiagnose archive is not a bounded regular file")
        with open(self.root, "rb") as disk:
            info = os.fstat(disk.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > _IS_ARCHIVE_LIMIT:
                raise ValueError("sysdiagnose archive is not a bounded regular file")
            magic = disk.read(2)
            disk.seek(0)
            with contextlib.ExitStack() as stack:
                stream = stack.enter_context(gzip.GzipFile(fileobj=disk)) if magic == b"\x1f\x8b" else disk
                limited = _IsLimitedStream(stream)
                with tarfile.open(fileobj=limited, mode="r|", tarinfo=_IsTarInfo) as archive:
                    seen = {}
                    for n, entry in enumerate(archive):
                        # Streaming tarfile still keeps every header it has read;
                        # with maximum-length names that grew to ~0.8 GB inside
                        # the member cap. Earlier headers are never needed again.
                        archive.members = []
                        if n >= _IS_ENTRIES:
                            raise ValueError("sysdiagnose archive member limit reached")
                        # "./" is how tar records a re-packed folder; it names the same place.
                        name = entry.name
                        while name.startswith("./"):
                            name = name[2:]
                        try:
                            name = name.rstrip("/")
                            # Files this reader never opens are not inventoried, so
                            # their names (battery logs carry ':' timestamps) are
                            # not refused either; nothing is written under them.
                            named = name.rsplit("/", 1)[-1].lower() in self.keep_names
                            if entry.isfile() and not _is_archive_candidate(name) and not named:
                                continue
                            _is_safe_parts(name)
                            name_key = hashlib.sha256(name.encode("utf-8", "surrogatepass")).digest()
                            if name_key in seen:
                                # Repeated directory headers are harmless, but a
                                # path with different types has no unambiguous
                                # payload. Refused links still reserve the name.
                                if seen[name_key] and entry.isdir():
                                    continue
                                seen[name_key] = False
                                key = ("", name)
                                self.cached.pop(key, None)
                                self.provenance.pop(key, None)
                                if key in self.entries:
                                    self.entries.remove(key)
                                raise ValueError("duplicate archive member")
                            seen[name_key] = entry.isdir()
                            if entry.isdir():
                                continue
                            if not entry.isfile() or entry.sparse:
                                raise ValueError("links, sparse and special archive entries are refused")
                            if not _is_archive_candidate(name):
                                self.entries.append(("", name))  # inventoried by name only
                                continue
                            if entry.size > _IS_FILE_LIMIT or self.total + entry.size > _IS_TOTAL_LIMIT:
                                raise ValueError("archive artifact byte limit reached")
                            member = archive.extractfile(entry)
                            if member is None:
                                raise ValueError("archive member unavailable")
                            with member:
                                raw = member.read(_IS_FILE_LIMIT + 1)
                            if len(raw) != entry.size:
                                raise ValueError("truncated archive artifact")
                            self.total += len(raw)
                            key = ("", name)
                            dest = os.path.join(self.tmp, "member-" + str(n))
                            with open(dest, "xb") as fh:
                                fh.write(raw)
                            self.cached[key] = dest
                            self._remember(key, self.root, raw, name)
                            self.entries.append(key)
                        except (OSError, ValueError) as exc:
                            self.gap("ios:input", "archive member refused: " + str(exc))
        self.inventory_complete = True

    def lookup(self, domain, relative):
        if self.kind != "backup":
            key = (domain, relative)
            if key not in self.entries:
                raise KeyError(relative)
            return key
        try:
            with self.query(self.index, "SELECT fileID,file FROM Files WHERE domain=? AND relativePath=? AND flags=1 LIMIT 2",
                            (domain, relative)) as cursor:
                rows = cursor.fetchall()
        except ValueError as exc:
            raise ValueError("backup index lookup: " + str(exc)) from exc
        if not rows:
            raise KeyError(relative)
        if len(rows) != 1 or not isinstance(rows[0][0], str) or not re.fullmatch(r"[0-9a-f]{40}", rows[0][0]):
            raise ValueError("invalid or ambiguous manifest artifact")
        return rows[0]

    def artifact(self, domain, relative):
        key = (domain, relative)
        if key in self.cached:
            return self.read_file(self.cached[key])
        if self.kind == "backup":
            fid, metadata = self.lookup(domain, relative)
            path = os.path.join(self.root, fid[:2], fid)
            if not path_problem(path) and not os.path.lexists(path):
                path = os.path.join(self.root, fid)
            try:
                data = self._read(path)
            except FileNotFoundError:
                raise ValueError("artifact indexed but its backup payload is missing")
            self._remember(key, path, data)
            if self.encrypted:
                record = self.unarchive(metadata)
                size = record.get("Size")
                if type(size) is not int or not 0 <= size <= _IS_FILE_LIMIT:
                    raise ValueError("unsupported backup file size")
                wrapped = record.get("EncryptionKey")
                if ("ProtectionClass" in record and isinstance(wrapped, bytes) and len(wrapped) >= 4
                        and record["ProtectionClass"] != int.from_bytes(wrapped[:4], "little")):
                    raise ValueError("inconsistent backup protection class")
                # Payloads carry PKCS#7 padding. The recorded Size is taken when
                # the backup lists the file; a live database (DataUsage, call
                # history) often changes before it is copied, so real backups
                # record sizes that differ from the stored payload. The padded
                # payload is what was copied and is authoritative.
                if not data:
                    # An empty payload has nothing to decrypt: an empty file, or
                    # an iCloud Drive file whose content was never on the phone.
                    if size:
                        raise ValueError("file content is not in the backup (iCloud-only or not downloaded)")
                    return data
                data = backup_cbc(backup_ios_file_key(self.keys, wrapped), data, unpad=True)
            return data
        self.lookup(domain, relative)
        path = os.path.join(self.root, *_is_safe_parts(relative))
        data = self._read(path)
        self._remember(key, path, data)
        return data

    def open_database(self, domain, relative, check):
        raw = self.artifact(domain, relative)
        wal = b""
        try:
            self.lookup(domain, relative + "-wal")
        except KeyError:
            pass
        except (ValueError, sqlite3.Error) as exc:
            self.gap(check, "WAL index lookup failed: " + str(exc))
        else:
            try:
                wal = self.artifact(domain, relative + "-wal")
            except (OSError, ValueError, sqlite3.Error) as exc:
                self.gap(check, "WAL sidecar unreadable: " + str(exc))
        return self.database(raw, check, wal)

    def database(self, raw, check, wal=b""):
        if not raw.startswith(b"SQLite format 3\0"):
            raise ValueError("artifact is not a readable SQLite database")
        # Reserve a new name even if writing or opening this copy fails. A
        # partial copy must not prevent a later artifact from being opened.
        dest = os.path.join(self.tmp, "db-" + str(self.database_serial))
        self.database_serial += 1
        with open(dest, "xb") as fh:
            fh.write(raw)
        prefix, issues = _is_wal_prefix(wal, raw)
        for issue in issues:
            self.gap(check, issue + "; only earlier validated committed data can be read")
        if prefix:
            with open(dest + "-wal", "xb") as fh:
                fh.write(prefix)
        con = open_evidence_db(dest)
        self.connections.append(con)
        return con

    def close(self):
        self.password, self.keys = "", {}
        for con in self.connections:
            try:
                con.close()
            except sqlite3.Error:
                pass
        if self.tmp:
            try:
                shutil.rmtree(self.tmp)
            except OSError:
                self.gap("ios:input", "temporary plaintext cleanup failed; private records may remain in the local temporary directory")


def _is_archive_candidate(name):
    base = name.rsplit("/", 1)[-1].lower()
    if base.startswith("._"):
        return False  # macOS AppleDouble metadata, not evidence
    return (base.endswith((".ips", ".crash", ".plist", ".mobileconfig", ".stub", ".sqlite", ".db", ".storedata", ".sqlitedb",
                           ".db-wal", ".sqlite-wal", ".storedata-wal", ".sqlitedb-wal"))
            or base.startswith(("shutdown.log", "mobile_installation.log")) or base == "ps.txt"
            or base in ("network persistent state", "favicons", "origin", "indexeddb.sqlite3")
            or base.endswith(".localstorage"))
