"""Large ordinary files (installers, app data) were listed as unfingerprinted
gaps at 120 MB, which worried people. Reading is chunked, so the limit only
bounds time; it is now 512 MB, and the report says why the rest is left out."""
from zbtriage.modules import hashscan


def test_limit_covers_large_ordinary_files():
    assert hashscan.MAX_BYTES >= 512 * 1024 * 1024


def test_reason_names_the_limit():
    text = hashscan._hs_reasons({"denied": 0, "large": 3, "unreadable": 0})
    assert "3 over 512 MB" in text
