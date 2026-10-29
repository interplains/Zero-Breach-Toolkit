"""Local Finder/iTunes backup reader, independently implemented.

Supported schemas are deliberately narrow. All source paths are opaque hex file
IDs from Manifest.db, never paths requested by a backed-up app. Temporary copies
are confined to a private temporary directory and removed after use.
"""
import datetime
import contextlib
import os
import plistlib
import re
import shutil
import sqlite3
import stat
import tempfile
import time

from ..backupcrypto import backup_cbc, backup_ios_keys, backup_ios_file_key
from ..localpaths import path_problem, local_temp_dir
from ..result import Hit, ModuleResult, EV_RECEIVED, EV_REFERENCED, EV_CONTACTED, EV_DEVICE_LOG
from ..iocs import TYPE_PROCESS, TYPE_FILE_NAME, TYPE_APP_ID
from ..ios_sources import IosEvidenceSource, _is_plist, _is_over_limit
from ..ios_messages import ios_message_text
from ..ios_artifacts import ios_additional_artifacts, ios_history_specs, ios_exact_identity, ios_identity_values

NAME = "ios"
# Sized for a full backup of a current phone (see ios_sources): large message
# histories need more rows, text and time than older phones did.
_IOS_LIMIT = 1024 * 1024 * 1024
_IOS_ROWS = 1000000
_IOS_TEXT_LIMIT = 64 * 1024
_IOS_TEXT_TOTAL = 256 * 1024 * 1024
_IOS_QUERY_SECONDS = 120
_IOS_QUERY_STEPS = 20000  # Progress callbacks, each after 1,000 VM operations.


class _IosQueryLimit(ValueError):
    pass


@contextlib.contextmanager
def _ios_query(con, sql, params=()):
    """Bound one query, including iteration; idle time between queries is free.

    Each artifact has a fixed number of queries, plus row/byte processing caps.
    A failed query cannot spend the budget of a later artifact's index lookup.
    """
    deadline = time.monotonic() + _IOS_QUERY_SECONDS
    steps = [0]
    exhausted = [False]
    cursor = None
    def progress():
        steps[0] += 1
        exhausted[0] = steps[0] > _IOS_QUERY_STEPS or time.monotonic() > deadline
        return int(exhausted[0])
    con.set_progress_handler(progress, 1000)
    try:
        cursor = con.execute(sql, params)
        yield cursor
    except sqlite3.Error as exc:
        if exhausted[0]:
            raise _IosQueryLimit("SQLite query budget exceeded; remaining records were not searched") from exc
        raise
    finally:
        if cursor is not None:
            cursor.close()
        con.set_progress_handler(None, 0)


def _ios_tables(con, names):
    """Only physical tables with ordinary columns, never executable schema views."""
    for name in names:
        with _ios_query(con, "SELECT type,sql FROM sqlite_master WHERE name=?", (name,)) as rows:
            row = rows.fetchone()
        if not row or row[0] != "table" or not isinstance(row[1], str) or not re.match(r"\s*CREATE\s+TABLE\b", row[1], re.I):
            raise ValueError("unsupported database table")
        with _ios_query(con, 'PRAGMA table_xinfo("' + name + '")') as rows:
            columns = rows.fetchall()
        if not columns or any(len(col) > 6 and col[6] for col in columns):
            raise ValueError("generated or hidden database columns are unsupported")


def _ios_read(path, limit=_IOS_LIMIT):
    problem = path_problem(os.path.abspath(path))
    if problem:
        raise ValueError("refused backup path: " + problem)
    st = os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(st.st_mode):
        raise ValueError("backup artifact is not a regular file")
    if st.st_size > limit:
        raise ValueError(_is_over_limit(os.path.basename(path), st.st_size, limit))
    with open(path, "rb") as fh:
        raw = fh.read(min(limit, st.st_size) + 1)
    if len(raw) != st.st_size or len(raw) > limit:
        raise ValueError("backup artifact changed during reading or exceeds the read limit")
    return raw


def _ios_unarchive(raw):
    if not isinstance(raw, bytes) or len(raw) > 1024 * 1024:
        raise ValueError("archived metadata exceeds the size limit")
    doc = _is_plist(raw)
    if not isinstance(doc, dict):
        raise ValueError("invalid archived metadata")
    nodes = [0]
    objects = doc.get("$objects", [])
    if not isinstance(objects, list) or len(objects) > 10000 or not isinstance(doc.get("$top", {}), dict):
        raise ValueError("invalid archived metadata object table/root")
    def resolve(value, depth=0):
        nodes[0] += 1
        if nodes[0] > 10000 or depth > 16:
            raise ValueError("archived record nesting limit exceeded")
        if isinstance(value, plistlib.UID):
            if not 0 <= value.data < len(objects):
                raise ValueError("invalid archived reference")
            return resolve(objects[value.data], depth + 1)
        if isinstance(value, dict):
            if "NS.data" in value:
                return resolve(value["NS.data"], depth + 1)
            return {k: resolve(v, depth + 1) for k, v in value.items() if k != "$class"}
        return value
    result = resolve(doc.get("$top", {}).get("root", doc))
    if not isinstance(result, dict):
        raise ValueError("invalid archived metadata root")
    return result


def _ios_timestamp(raw, nanos=False):
    try:
        value = float(raw)
        if nanos and abs(value) > 100000000000:
            value /= 1000000000
        return (datetime.datetime(2001, 1, 1, tzinfo=datetime.timezone.utc)
                + datetime.timedelta(seconds=value)).isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError):
        return ""


def _ios_browser_timestamp(raw, chrome=False):
    try:
        epoch = datetime.datetime(1601 if chrome else 1970, 1, 1,
                                  tzinfo=datetime.timezone.utc)
        return (epoch + datetime.timedelta(microseconds=float(raw))).isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError):
        return ""


def _ios_columns(con, table):
    with _ios_query(con, 'PRAGMA table_info("' + table + '")') as rows:
        return {row[1].lower() for row in rows}


def _ios_hit(r, ind, location, detail, grade, observed="", artifact=""):
    r.add_hit(Hit(ind.value, location, detail, ind.tier, ind.confidence,
                  ind.source, grade, observed, family=ind.family, kind=ind.type,
                  artifact=artifact))


def _ios_message_rows(con, query, columns, r, gap, deadline):
    yield from _ios_record_rows(con, query, "message", columns, r, gap, deadline,
                                "ios:messages", "message")


def _ios_record_rows(con, query, table, columns, r, gap, deadline, check,
                     label="record", alias=""):
    """Read small payload batches; isolate every row when a batch cannot decode.

    SQLite/Python can fail while advancing a cursor, before yielding the previous
    row. Nothing from a failed batch is yielded before each row is retried.
    Choose an unshadowed SQLite row-id alias; never assume a user column is unique.
    Table, alias and query are fixed reader definitions, never artifact text.
    """
    key = next((name for name in ("_rowid_", "rowid", "oid") if name not in columns), None)
    if key is None:
        gap(check, label + " table has no supported row identifier; records were not searched")
        return
    qualified = (alias + "." if alias else "") + key
    last, count = None, 0
    while True:
        if time.monotonic() > deadline:
            gap(check, "record processing budget reached; remaining records were not searched")
            return
        sql = "SELECT " + key + " FROM " + table
        params = ()
        if last is not None:
            sql += " WHERE " + key + ">?"
            params = (last,)
        sql += " ORDER BY " + key + " LIMIT " + str(min(256, _IOS_ROWS - count + 1))
        try:
            with _ios_query(con, sql, params) as cursor:
                ids = cursor.fetchall()
        except sqlite3.Error:
            gap(check, label + " row index unreadable; remaining records were not searched")
            return
        if not ids:
            return
        if any(not isinstance(row[0], int) for row in ids):
            gap(check, "unsupported " + label + " row identifier; remaining records were not searched")
            return
        for start in range(0, len(ids), 16):
            batch = [row[0] for row in ids[start:start + 16]]
            recovered = None
            try:
                sql = ("SELECT " + qualified + "," + query[7:] + " WHERE " + qualified
                       + " IN (" + ",".join("?" for _ in batch) + ") LIMIT 17")
                with _ios_query(con, sql, tuple(batch)) as cursor:
                    payloads = cursor.fetchall()
                recovered = {row[0]: row[1:] for row in payloads}
                if len(payloads) != len(recovered) or len(payloads) > len(batch):
                    raise ValueError("ambiguous joined record identifiers")
            except (sqlite3.Error, ValueError):
                # An ambiguous batch escaped this handler and ended the reader,
                # losing every later record. It is now treated like a failed
                # batch. `recovered` was filled before the check raised, so it is
                # cleared: each row is then read on its own, where the per-row
                # isolation keeps later records.
                recovered = None
            for row_id in batch:
                if count >= _IOS_ROWS:
                    gap(check, "artifact row limit reached")
                    return
                if time.monotonic() > deadline:
                    gap(check, "record processing budget reached; remaining records were not searched")
                    return
                last = row_id
                ordinal = count
                count += 1
                try:
                    if recovered is None:
                        with _ios_query(con, query + " WHERE " + qualified + "=? LIMIT 2", (row_id,)) as cursor:
                            payloads = cursor.fetchall()
                        if len(payloads) > 1:
                            raise ValueError("ambiguous joined record identifier")
                        row = payloads[0] if payloads else None
                    else:
                        row = recovered.get(row_id)
                except ValueError:
                    # One record that joins to several rows cannot be read
                    # unambiguously. It used to escape both handlers and end the
                    # reader; now only that record is skipped, as a gap.
                    r.skipped += 1
                    gap(check, label + " row is ambiguous and was not searched")
                    continue
                except sqlite3.Error as exc:
                    r.skipped += 1
                    if (getattr(exc, "sqlite_errorcode", None) == getattr(sqlite3, "SQLITE_TOOBIG", 18)
                            or "string or blob too big" in str(exc).lower()):
                        reason = label + " exceeds the database field size limit and was not searched"
                    elif "could not decode to utf-8" in str(exc).lower():
                        reason = label + " contains undecodable text and was not searched"
                    else:
                        reason = label + " row unreadable and was not searched"
                    gap(check, reason)
                    continue
                if row is None:
                    r.skipped += 1
                    gap(check, label + " row unavailable and was not searched")
                    continue
                yield row_id, row


def run(ctx) -> ModuleResult:
    r = ModuleResult(NAME)
    ctx.partial = r
    folder = os.path.abspath(ctx.phone_path)
    r.note("Local iPhone evidence readers.")
    source = None
    gaps = {}
    def gap(check, reason):
        key = (check, reason)
        gaps[key] = gaps.get(key, 0) + 1
    try:
        source = IosEvidenceSource(folder, getattr(ctx, "ios_input", "") or "backup",
                                   ctx.backup_password, gap, ctx.emit, _ios_read,
                                   _ios_query, _ios_tables, _ios_unarchive, inventory_limit=_IOS_ROWS,
                                   keep_names=frozenset(v.lower() for ind in ctx.iocs.of_type(TYPE_FILE_NAME)
                                                        for v in ios_identity_values(ind)))
        source.start()
        r.ran("ios:manifest" if source.kind == "backup" else "ios:input")
        r.submetrics["ios_inventory_files"] = len(source.entries)
        for domain, relative in source.entries:
            for ind in ctx.iocs.of_type(TYPE_FILE_NAME):
                if ios_exact_identity(ind, relative.rsplit("/", 1)[-1]):
                    _ios_hit(r, ind, domain + "/" + relative,
                             "filename in supplied evidence inventory; names alone are not proof of compromise", EV_REFERENCED,
                             artifact=os.path.join(folder, "Manifest.db") if source.kind == "backup" else folder)
        version = source.info.get("Product Version")
        if isinstance(version, str):
            r.note("iOS version recorded by backup: " + version[:64] + "; schema support is checked per artifact.")
        if source.kind == "backup" and not source.encrypted:
            r.note("This backup is unencrypted; some website/call history and other protected records may be unavailable. An owner-created encrypted local backup can provide more coverage.")
        # Paths documented by the browser producers and MVT's artifact catalogue.
        # Optional app databases are selected by fixed domain/path pairs, never
        # by traversing a path stored inside an app's database.
        base_specs = (
            ("ios:messages", "HomeDomain", "Library/SMS/sms.db", "SELECT text,date,is_from_me FROM message", "message", "", ("message",), False),
            ("ios:safari", "HomeDomain", "Library/Safari/History.db", "SELECT i.url,v.visit_time FROM history_visits v LEFT JOIN history_items i ON i.id=v.history_item", "history_visits", "v", ("history_items", "history_visits"), False),
            ("ios:processes", "WirelessDomain", "Library/Databases/DataUsage.sqlite", "SELECT ZPROCNAME FROM ZPROCESS", "ZPROCESS", "", ("ZPROCESS",), False),
            ("ios:chrome-history", "AppDomain-com.google.chrome", "Library/Application Support/Google/Chrome/Default/History", "", "visits", "v", ("urls", "visits"), True),
            ("ios:firefox-history", "AppDomainGroup-group.org.mozilla.ios.Firefox", "profile.profile/browser.db", "", "visits", "v", ("history", "visits"), True),
        )
        specs = ios_history_specs(source, base_specs, gap)
        for check, domain, relative, query, table, alias, tables, optional in specs:
            before = len(r.hits)
            try:
                if optional:
                    try:
                        source.lookup(domain, relative)
                    except KeyError:
                        continue
                con = source.open_database(domain, relative, check)
                _ios_tables(con, tables)
                cols = _ios_columns(con, table)
                if check == "ios:messages":
                    # x'' marks a row that stores neither text nor an encoded body
                    # (group renames, member changes and other system events):
                    # there is nothing to search, so it is not a gap.
                    encoded = ("CASE WHEN attributedBody IS NULL THEN x'' WHEN length(attributedBody)<=1048576 "
                               "THEN attributedBody ELSE x'00' END") if "attributedbody" in cols else "NULL"
                    query = "SELECT text,date,is_from_me," + encoded + " FROM message"
                elif check == "ios:processes":
                    extra = [name if name.lower() in cols else "NULL" for name in
                             ("ZBUNDLENAME", "ZFIRSTTIMESTAMP", "ZTIMESTAMP")]
                    query = "SELECT ZPROCNAME," + ",".join(extra) + " FROM ZPROCESS"
                elif check == "ios:chrome-history":
                    with _ios_query(con, "SELECT 1 FROM sqlite_master WHERE name='visit_source'") as rows:
                        have_sources = rows.fetchone() is not None
                    visit_source, source_join = "NULL", ""
                    if have_sources:
                        _ios_tables(con, ("visit_source",))
                        # No source row denotes a normal visit; an explicit NULL
                        # source is damaged/unknown metadata, not that default.
                        visit_source = "CASE WHEN s.id IS NULL THEN 1 ELSE s.source END"
                        source_join = " LEFT JOIN visit_source s ON s.id=v.id"
                    else:
                        gap(check, "visit-source metadata unavailable; URLs remain references without proof of local contact")
                    originator = "v.originator_cache_guid" if "originator_cache_guid" in cols else "''"
                    query = ("SELECT u.url,v.visit_time," + visit_source + "," + originator
                             + " FROM visits v LEFT JOIN urls u ON u.id=v.url" + source_join)
                elif check == "ios:safari":
                    # history_visits.origin: 0 = visited on this phone, 1 = synced
                    # from another device on the same iCloud account. Without it
                    # the visit cannot be placed on this phone, so it stays a
                    # reference and the missing metadata is a gap.
                    origin = "v.origin" if "origin" in cols else "NULL"
                    if "origin" not in cols:
                        gap(check, "visit-origin metadata unavailable; URLs remain references without proof of local contact")
                    query = ("SELECT i.url,v.visit_time," + origin +
                             " FROM history_visits v LEFT JOIN history_items i ON i.id=v.history_item")
                elif check == "ios:firefox-history":
                    local = "v.is_local" if "is_local" in cols else "NULL"
                    if "is_local" not in cols:
                        gap(check, "local-visit metadata unavailable; URLs remain references without proof of local contact")
                    query = "SELECT h.url,v.date," + local + " FROM visits v LEFT JOIN history h ON h.id=v.siteID"
                total_text = 0
                deadline = time.monotonic() + _IOS_QUERY_SECONDS
                # All supported tables use the same isolated recovery mechanism.
                with contextlib.ExitStack() as stack:
                    if check == "ios:messages":
                        records = _ios_message_rows(con, query, cols, r, gap, deadline)
                    else:
                        records = _ios_record_rows(con, query, table, cols, r, gap, deadline, check,
                                                   "record", alias)
                    stack.callback(records.close)
                    for n, row in records:
                        if row[0] is not None and not isinstance(row[0], str):
                            r.skipped += 1
                            gap(check, "a record has binary or unsupported field content and was not searched")
                            continue
                        text = row[0] or ""
                        if check == "ios:messages" and not text:
                            if row[3] == b"":
                                continue
                            try:
                                text = ios_message_text(row[3])
                            except (ValueError, UnicodeError, plistlib.InvalidFileException, RecursionError):
                                r.skipped += 1
                                if row[3] is None or row[3]:
                                    gap(check, "a message has no plain text; encoded or unsupported message content was not searched")
                                continue
                        if not text:
                            r.skipped += 1
                            gap(check, "a record has no supported text and was not searched")
                            continue
                        size = len(text.encode("utf-8", "replace"))
                        if size > _IOS_TEXT_LIMIT:
                            r.skipped += 1
                            gap(check, "a record exceeds the text limit and was not searched")
                            continue
                        total_text += size
                        if total_text > _IOS_TEXT_TOTAL or time.monotonic() > deadline:
                            gap(check, "record processing budget reached; remaining records were not searched")
                            break
                        r.checked += 1
                        location = domain + "/" + relative + ":record " + str(n)
                        physical = source.provenance.get((domain, relative), {}).get("source", folder)
                        row_before = len(r.hits)
                        if check == "ios:processes":
                            for ind in ctx.iocs.of_type(TYPE_PROCESS):
                                if ios_exact_identity(ind, text):
                                    _ios_hit(r, ind, location, "process name in data-usage records: " + text + "; identity is not file-content verification", EV_DEVICE_LOG,
                                             _ios_timestamp(row[3]), artifact=physical)
                            if isinstance(row[1], str):
                                ind = ctx.iocs.lookup_typed(TYPE_APP_ID, row[1])
                                if ind:
                                    _ios_hit(r, ind, location, "bundle identifier in data-usage records", EV_DEVICE_LOG,
                                             _ios_timestamp(row[3]), artifact=physical)
                        else:
                            grade = EV_REFERENCED
                            if check == "ios:messages":
                                if type(row[2]) is int and row[2] in (0, 1):
                                    grade = EV_RECEIVED if row[2] == 0 else EV_REFERENCED
                                else:
                                    gap(check, "message direction is unsupported; text remains a reference")
                            when = _ios_timestamp(row[1], check == "ios:messages")
                            browser_record = check != "ios:messages"
                            if browser_record:
                                from .browser import _browser_url_evidence
                                # Chromium VisitSource values 0..7 include synced,
                                # extension, imported and actor records. Keep the
                                # established contact grade only for browsed (1).
                                supported_origins = range(8) if check == "ios:chrome-history" else (0, 1)
                                origin_known = type(row[2]) is int and row[2] in supported_origins
                                if check == "ios:chrome-history" and row[3] is not None and not isinstance(row[3], str):
                                    origin_known = False
                                if not origin_known:
                                    gap(check, "visit-origin metadata unsupported; URL remains a reference without proof of local contact")
                                local_visit = (check == "ios:safari" and type(row[2]) is int and row[2] == 0 or
                                               check == "ios:firefox-history" and type(row[2]) is int and row[2] == 1 or
                                               check == "ios:chrome-history" and type(row[2]) is int and row[2] == 1 and row[3] in (None, ""))
                                local_visit = local_visit and origin_known
                                if check != "ios:safari":
                                    when = _ios_browser_timestamp(row[1], check == "ios:chrome-history")
                                for ind, grade in _browser_url_evidence(text, ctx.iocs,
                                                        EV_CONTACTED if local_visit else EV_REFERENCED):
                                    _ios_hit(r, ind, location, "backup browser record: " + text[:200], grade,
                                             when, physical)
                            else:
                                for ind in ctx.iocs.search(text.lower()):
                                    _ios_hit(r, ind, location, "backup record: " + text[:200], grade, when, physical)
                        for hit in r.hits[row_before:]:
                            hit.provenance = dict(source.provenance.get((domain, relative), {}),
                                record_id=n, table=table, raw_timestamp=str(row[3] if check == "ios:processes" else row[1])[:128])
                            if (domain, relative + "-wal") in source.provenance:
                                hit.provenance["wal_sha256"] = source.provenance[(domain, relative + "-wal")]["sha256"]
                r.ran(check)
            except _IosQueryLimit as exc:
                gap(check, str(exc))
            except KeyError:
                gap(check, "artifact not included in this collection; it was not checked")
            except (ValueError, OSError, sqlite3.Error, TypeError, plistlib.InvalidFileException) as exc:
                gap(check, "artifact unreadable or unsupported: " + str(exc))
        ios_additional_artifacts(source, ctx, r, gap, _ios_query, _ios_tables,
                                 _ios_columns, _ios_record_rows, _ios_hit, _ios_timestamp)
        try:
            if source.kind != "backup":
                return r
            info = source.info
            apps = info.get("Installed Applications")
            if not isinstance(apps, list) or not all(isinstance(a, str) for a in apps):
                raise ValueError("unsupported installed-application list")
            for ind in ctx.iocs.of_type(TYPE_APP_ID):
                if ind.value in apps:
                    _ios_hit(r, ind, "Info.plist", "application identifier recorded in backup metadata", EV_DEVICE_LOG,
                             artifact=os.path.join(folder, "Info.plist"))
            r.ran("ios:applications")
        except (ValueError, OSError, AttributeError, plistlib.InvalidFileException) as exc:
            gap("ios:applications", "installed-application list missing or unreadable: {}".format(exc))
    except (ValueError, OSError, TypeError, KeyError, sqlite3.Error, plistlib.InvalidFileException) as exc:
        gap("ios:manifest" if getattr(ctx, "ios_input", "") in ("", "backup") else "ios:input",
            "evidence unavailable: " + str(exc))
    finally:
        if source:
            source.close()
        for (check, reason), count in gaps.items():
            suffix = " ({} occurrences)".format(count) if count > 1 else ""
            r.could_not_run(check, reason + suffix)
    return r
