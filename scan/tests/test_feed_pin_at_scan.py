"""A cached list that is not the copy pinned for this release is refused at
scan time, whatever its manifest says, unless the scan itself asks for
--latest. Whoever could rewrite the list could also rewrite the manifest."""
import hashlib
import json

from zbtriage import feeds
from test_followup_fixes import bundle  # noqa: F401  (fixture)


def _cache(root, revision):
    src = next(s for s in feeds.SOURCES if s["format"] == "stix2" and s["id"] in feeds.FEED_FILE_SHA256)
    name = src["id"] + feeds._EXT[src["format"]]
    raw = json.dumps({"type": "bundle", "id": "bundle--11111111-1111-4111-8111-111111111111", "objects": [{
        "type": "indicator", "id": "indicator--22222222-2222-4222-8222-222222222222",
        "pattern_type": "stix", "pattern": "[domain-name:value = 'swapped-list.invalid']",
        "valid_from": "2026-10-28T00:00:00Z", "created": "2026-10-28T00:00:00Z",
        "modified": "2026-10-28T00:00:00Z"}]}).encode()
    (root / name).write_bytes(raw)
    meta = {"file": name, "sha256": hashlib.sha256(raw).hexdigest(),
            "checked_utc": "2026-10-28T00:00:00Z", "revision": revision}
    (root / feeds.MANIFEST).write_text(json.dumps({"sources": {src["id"]: meta}}))
    return src, raw


def test_a_swapped_list_is_refused_whatever_the_manifest_says(tmp_path, bundle):
    for api in (feeds, bundle):
        for revision in ("branch head", "unpinned", "anything"):
            src, _raw = _cache(tmp_path, revision)
            sets, status = api.cached_sets(str(tmp_path))
            downloaded = [e for e in status["loaded"] if not e.get("built_in")]
            assert downloaded == [] and src["id"] not in {e["id"] for e in status["loaded"]}, (api, revision)
            assert "not the copy pinned" in status["refused"][0]["reason"]


def test_latest_at_scan_time_uses_it_and_says_so(tmp_path, bundle):
    for api in (feeds, bundle):
        _cache(tmp_path, "branch head")
        sets, status = api.cached_sets(str(tmp_path), latest=True)
        downloaded = [e for e in status["loaded"] if not e.get("built_in")]
        assert len(downloaded) == 1 and downloaded[0]["pinned_for_this_release"] is False


def test_the_pinned_copy_loads_by_content(tmp_path, monkeypatch):
    src, raw = _cache(tmp_path, "branch head")
    monkeypatch.setitem(feeds.FEED_FILE_SHA256, src["id"], hashlib.sha256(raw).hexdigest())
    sets, status = feeds.cached_sets(str(tmp_path))
    downloaded = [e for e in status["loaded"] if not e.get("built_in")]
    assert len(downloaded) == 1 and downloaded[0]["pinned_for_this_release"] is True
