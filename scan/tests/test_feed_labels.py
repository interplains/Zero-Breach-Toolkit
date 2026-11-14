"""Each indicator source is labelled as its publisher describes it. The
Citizen Lab folder 201707_InsiderInfo is an intrusion campaign against
Chinese-language news sites, not NSO Group, Pegasus or Mexico: a match from it
must never be reported as Pegasus."""
import hashlib
import json

from zbtriage import feeds
from test_followup_fixes import bundle  # noqa: F401  (fixture)

SID = "citizenlab-nso-insider-2017"


def _source(api):
    return next(s for s in api.SOURCES if s["id"] == SID)


def test_the_insider_information_list_is_not_called_nso_or_pegasus(bundle):
    for api in (feeds, bundle):
        src = _source(api)
        assert src["family"] == ""
        for field in ("name", "cite"):
            assert "NSO" not in src[field] and "Pegasus" not in src[field], src[field]
            assert "Mexico" not in src[field], src[field]
        assert "Chinese-language news sites" in src["name"]
        assert "Chinese language news sites" in src["cite"]
        assert src["path"] == "201707_InsiderInfo/indicators.csv"
        # The id and pinned file are unchanged, so existing downloads verify.
        assert api.FEED_FILE_SHA256[SID] == (
            "87cd4cb85b4a3808ff231f6c22e79f387328ba1b36ab576b61b455562f8afbc2")


def test_an_existing_download_takes_the_corrected_label(tmp_path, bundle):
    # The manifest written by an older version still says Pegasus; the label
    # comes from the catalogue in this release, never from the cache.
    raw = b"uuid,event_id,category,type,value,comment,to_ids,date\n" \
          b"x,1,Network activity,domain,insider-label.invalid,,1,20170704\n"
    name = SID + feeds._EXT["misp-csv"]
    (tmp_path / name).write_bytes(raw)
    meta = {"file": name, "sha256": hashlib.sha256(raw).hexdigest(), "revision": "old",
            "checked_utc": "2026-10-28T00:00:00Z", "family": "Pegasus",
            "name": "NSO Group (Insider Information, Mexico, 2017)"}
    (tmp_path / feeds.MANIFEST).write_text(json.dumps({"sources": {SID: meta}}))
    for api in (feeds, bundle):
        sets, status = api.cached_sets(str(tmp_path), latest=True)
        mine = [s for s in sets if any(i.value == "insider-label.invalid" for i in s.indicators)]
        assert len(mine) == 1, status
        (ind,) = mine[0].indicators
        assert ind.value == "insider-label.invalid"
        assert ind.family == ""
        assert "NSO" not in ind.source and "Chinese-language news sites" in ind.source


def test_every_pegasus_label_names_an_nso_report():
    for src in feeds.SOURCES:
        if src["family"] == "Pegasus":
            assert "NSO" in src["name"] or "Amnesty" in src["cite"], src["id"]
