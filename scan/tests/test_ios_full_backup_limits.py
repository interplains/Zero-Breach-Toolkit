"""A full backup of a current phone fits inside the iPhone check's limits, and
a file over a limit is named with its size (issue: the check read nothing on a
512 GB phone because Manifest.db was over 300 MB)."""
import pytest

from zbtriage import ios_sources
from zbtriage.modules import ios

MB = 1024 * 1024
# Measured on a full, unencrypted backup of a current 512 GB phone.
CURRENT_PHONE = {"manifest_bytes": 330 * MB, "manifest_rows": 240000, "info_plist": 17 * MB}


def test_a_current_phone_fits_every_limit():
    assert ios._IOS_LIMIT >= 2 * CURRENT_PHONE["manifest_bytes"]
    assert ios_sources._IS_FILE_LIMIT >= 2 * CURRENT_PHONE["manifest_bytes"]
    assert ios._IOS_ROWS >= 2 * CURRENT_PHONE["manifest_rows"]
    assert ios_sources._IS_ENTRIES >= 2 * CURRENT_PHONE["manifest_rows"]
    assert ios_sources._IS_PLIST_LIMIT >= 2 * CURRENT_PHONE["info_plist"]
    assert ios_sources._IS_TOTAL_LIMIT >= 4 * ios_sources._IS_FILE_LIMIT


def test_limits_still_bound_what_a_crafted_backup_can_load():
    assert ios._IOS_LIMIT <= 1024 * MB
    assert ios_sources._IS_FILE_LIMIT <= 1024 * MB
    assert ios_sources._IS_PLIST_LIMIT <= 64 * MB


def test_an_oversized_file_is_named_with_its_size(tmp_path, monkeypatch):
    path = tmp_path / "Manifest.db"
    path.write_bytes(b"x" * (3 * MB))
    monkeypatch.setattr(ios, "_IOS_LIMIT", 2 * MB)
    with pytest.raises(ValueError) as caught:
        ios._ios_read(str(path), ios._IOS_LIMIT)
    assert str(caught.value) == "Manifest.db is 3 MB, over the 2 MB limit for one file"


def test_an_oversized_property_list_says_how_big(monkeypatch):
    monkeypatch.setattr(ios_sources, "_IS_PLIST_LIMIT", 1 * MB)
    with pytest.raises(ValueError) as caught:
        ios_sources._is_plist(b"x" * (2 * MB))
    assert "property list is 2 MB, over the 1 MB limit" in str(caught.value)
