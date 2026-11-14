"""A backup copy that lost Manifest.plist must still reach the iPhone reader.

Before the fix only Manifest.plist marked a folder as an iPhone backup, so a
partial copy holding a readable Manifest.db went to the Android reader and was
reported as "not an AndroidQF collection": nothing in it was checked.
"""
import sqlite3

from zbtriage.context import ScanContext
from zbtriage.iocs import IocSet
from zbtriage.readers import reader_select


def _ctx(path):
    return ScanContext(IocSet([], "fixture", None), phone_path=str(path), emit=lambda _m: None)


def _names(path):
    return {spec.name for spec in reader_select(_ctx(path))}


def test_manifest_db_only_backup_goes_to_ios(tmp_path):
    con = sqlite3.connect(tmp_path / "Manifest.db")
    con.execute("CREATE TABLE Files(fileID TEXT, domain TEXT, relativePath TEXT, flags INTEGER, file BLOB)")
    con.commit()
    con.close()
    assert "ios" in _names(tmp_path)
    assert "android" not in _names(tmp_path)


def test_manifest_plist_backup_goes_to_ios(tmp_path):
    (tmp_path / "Manifest.plist").write_bytes(b"<plist></plist>")
    assert "ios" in _names(tmp_path)


def test_unreadable_manifest_db_without_plist_is_not_ios(tmp_path):
    # An encrypted Manifest.db is not SQLite without its key; with no
    # Manifest.plist there is no key either, so it is not routed as a backup.
    (tmp_path / "Manifest.db").write_bytes(b"\x8f" * 64)
    assert "ios" not in _names(tmp_path)


def test_android_collection_still_goes_to_android(tmp_path):
    (tmp_path / "packages.json").write_text("[]")
    assert "android" in _names(tmp_path)
    assert "ios" not in _names(tmp_path)
