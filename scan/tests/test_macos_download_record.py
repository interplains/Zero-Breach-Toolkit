"""macOS's record of downloaded files: evidence meaning, private rows and gaps.

Hermetic: the record is a synthetic database in a temp dir, passed through _ux_roots,
so no test reads the tester's own download history.
"""
import datetime
import os
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest

from zbtriage.context import ScanContext
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import posix

CHECK = "macos-download-record"
DOMAIN = "fixture.invalid"
PRIVATE = "https://private-unrelated.invalid/secret-file.zip"
# 2024-01-01T00:00:00 UTC as seconds since 2001-01-01.
STAMP = 725760000.0


def local_iso(stamp):
    return datetime.datetime.fromtimestamp(stamp + 978307200).isoformat(timespec="seconds")


@pytest.fixture
def record(tmp_path, monkeypatch):
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    for key in ("TMPDIR", "TEMP", "TMP"):
        monkeypatch.setenv(key, str(scratch))
    path = tmp_path / "QuarantineEventsV2"
    monkeypatch.setattr(posix, "_ux_roots",
                        lambda: [(CHECK, str(path), "download-record-file")])
    return path


def fill(path, *rows):
    con = sqlite3.connect(str(path))
    con.execute("CREATE TABLE LSQuarantineEvent (LSQuarantineEventIdentifier TEXT, "
                "LSQuarantineDataURLString TEXT, LSQuarantineOriginURLString TEXT, "
                "LSQuarantineTimeStamp REAL, LSQuarantineAgentName TEXT)")
    con.executemany("INSERT INTO LSQuarantineEvent VALUES ('id', ?, ?, ?, 'SENTINEL-AGENT')", rows)
    con.commit()
    con.close()


def scan():
    ctx = ScanContext(IocSet([Indicator(DOMAIN, "fixture", "primary", "domain", "fixture")],
                             "fixture", None), emit=lambda text: None)
    return posix.run(ctx)


def checks(result, ran):
    return [c for c in result.checks if c.name == CHECK and c.ran is ran]


def test_file_address_on_the_host_is_dated_contact(record):
    fill(record, ("https://{}/a.zip".format(DOMAIN), None, STAMP))
    result = scan()
    assert [(h.indicator, h.evidence) for h in result.hits] == [(DOMAIN, "contacted")]
    assert result.hits[0].observed == local_iso(STAMP)
    assert checks(result, True) and not checks(result, False)


def test_page_address_on_the_host_is_only_a_reference(record):
    fill(record, ("https://cdn.invalid/a.zip", "https://{}/page".format(DOMAIN), STAMP))
    hit = scan().hits[0]
    assert hit.evidence == "referenced"
    assert hit.observed == ""


def test_mention_in_a_file_address_is_only_a_reference(record):
    fill(record, ("https://cdn.invalid/a.zip?ref=" + DOMAIN, None, STAMP))
    assert [h.evidence for h in scan().hits] == ["referenced"]


def test_unmatched_rows_and_other_columns_never_reach_the_output(record):
    fill(record, (PRIVATE, PRIVATE, STAMP), ("https://{}/secret-name.zip".format(DOMAIN), None, STAMP))
    text = repr(scan().to_dict())
    assert DOMAIN in text
    for private in ("private-unrelated", "secret-name", "SENTINEL-AGENT"):
        assert private not in text


def test_repeats_collapse_to_the_oldest_date(record):
    url = "https://{}/a".format(DOMAIN)
    fill(record, (url, None, STAMP + 500), (url, None, STAMP), (url, None, STAMP + 900))
    result = scan()
    assert len(result.hits) == 1
    assert result.hits[0].observed == local_iso(STAMP)
    assert result.submetrics["download_records"] == 3


def test_oldest_record_sets_the_time_window(record):
    fill(record, (PRIVATE, None, STAMP + 100), (PRIVATE, None, STAMP), (PRIVATE, None, None))
    reach = scan().reach[CHECK]
    assert reach["earliest"] == local_iso(STAMP)
    assert "3 macOS download records" in reach["basis"]


@pytest.mark.parametrize("stamp", [1e300, -5.0, 0, None, "not a date"])
def test_impossible_date_is_ignored_not_fatal(record, stamp):
    fill(record, ("https://{}/a".format(DOMAIN), None, stamp))
    result = scan()
    assert result.hits[0].observed == ""
    assert CHECK not in result.reach
    assert checks(result, True)


def test_empty_record_ran_and_found_nothing(record):
    fill(record)
    result = scan()
    assert checks(result, True) and not result.hits and CHECK not in result.reach


def test_missing_record_is_not_checked(record):
    result = scan()
    assert not checks(result, True)
    assert "no record of downloaded files" in checks(result, False)[0].reason


def test_refused_record_is_not_checked_with_the_real_reason(record, monkeypatch):
    fill(record, ("https://{}/a".format(DOMAIN), None, STAMP))

    def refuse(_path):
        raise PermissionError(1, "Operation not permitted", str(record))

    monkeypatch.setattr(posix, "copy_locked", refuse)
    monkeypatch.setattr(sys, "platform", "darwin")
    result = scan()
    assert not checks(result, True) and not result.hits
    assert "was running" not in checks(result, False)[0].reason
    assert "Full Disk Access" in checks(result, False)[0].reason


@pytest.mark.parametrize("content", [b"not a database", b""])
def test_damaged_record_is_a_gap_and_leaves_no_copy(record, content):
    record.write_bytes(content)
    result = scan()
    assert not checks(result, True) and checks(result, False)
    assert "unreadable or unsupported" in checks(result, False)[0].reason
    assert os.listdir(os.environ["TMPDIR"]) == []


def test_unexpected_schema_is_a_gap(record):
    con = sqlite3.connect(str(record))
    con.execute("CREATE TABLE LSQuarantineEvent (other TEXT)")
    con.commit()
    con.close()
    result = scan()
    assert not checks(result, True) and checks(result, False)


def test_view_cannot_stand_in_for_the_table(record):
    con = sqlite3.connect(str(record))
    con.execute("CREATE VIEW LSQuarantineEvent AS SELECT 'x' AS LSQuarantineDataURLString, "
                "'y' AS LSQuarantineOriginURLString, 1.0 AS LSQuarantineTimeStamp")
    con.commit()
    con.close()
    result = scan()
    assert not checks(result, True) and checks(result, False)


def test_row_limit_keeps_earlier_hits_and_reports_the_gap(record, monkeypatch):
    monkeypatch.setattr(posix, "_UX_DOWNLOAD_ROW_CAP", 1)
    fill(record, ("https://{}/a".format(DOMAIN), None, STAMP), (PRIVATE, None, STAMP + 1))
    result = scan()
    assert len(result.hits) == 1
    assert "record limit" in checks(result, False)[0].reason
    assert result.submetrics["download_records"] == 1


def test_source_is_unchanged_and_no_copy_remains(record):
    fill(record, (PRIVATE, None, STAMP))
    before = record.read_bytes()
    scan()
    assert record.read_bytes() == before
    assert os.listdir(os.environ["TMPDIR"]) == []


def test_only_macos_reads_it(monkeypatch):
    monkeypatch.undo()
    monkeypatch.setattr(sys, "platform", "darwin")
    assert CHECK in [check for check, _root, _kind in posix._ux_roots()]
    monkeypatch.setattr(sys, "platform", "linux")
    assert CHECK not in [check for check, _root, _kind in posix._ux_roots()]
