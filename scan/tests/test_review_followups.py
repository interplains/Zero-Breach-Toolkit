"""Follow-ups from the code review (issues #6 to #9 and #11): names that can
change owner, crafted evidence that could stall a scan, private temporary copies
and synced report folders, pinned indicator downloads, and the release tooling."""
import hashlib
import importlib.util
import json
import os
import stat
import sys
import threading
import time
import types

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import feeds, ios_artifacts, localpaths, report, workflow
from zbtriage.iocs import load_any
from zbtriage.modules import hashscan
from zbtriage.result import EV_CONTACTED, EV_REFERENCED

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# --- #6 names that may have changed owner ------------------------------------

def test_reclaimable_contact_is_a_lead_not_a_serious_finding():
    hit = {"tier": "reclaimable", "evidence": EV_CONTACTED}
    assert report._recommended_action(hit) == 1
    assert "MAY HAVE CHANGED OWNER" in report._headline_for(hit)
    assert report._recommended_action({"tier": "reclaimable", "evidence": EV_REFERENCED}) == 0
    assert "reclaimable" in report.TIER_MEANING


def test_shared_platform_names_and_reregistered_domains_are_reclaimable():
    iocs = load_any(os.path.join(ROOT, "iocs", "adfection_iocs.txt"))
    tier = {i.value: i.tier for i in iocs.indicators}
    for name in ("archer.westeurope.cloudapp.azure.com", "bd-mainserver.herokuapp.com",
                 "hetq.org", "armradio.org", "static-doubleclick.net"):
        assert tier[name] == "reclaimable", name
    assert tier["185.181.8.155"] == "candiru-ip"
    # Not shown by the registry to be re-registered: unchanged.
    assert tier["armenpress.org"] == "historical"


# --- #7 crafted evidence ------------------------------------------------------

@pytest.mark.parametrize("line,process", [
    ("Process:         SpringBoard [57]", "SpringBoard"),
    ("Command: bh", "bh"),
    ("Process:   my app [12]  ", "my app"),
    ("Process: [123]", "[123]"),
    ("Process:x", ""),
    ("Path:  /private/var/x", ""),
])
def test_ips_process_lines(line, process):
    assert ios_artifacts._ia_ips_process(line) == process


@pytest.mark.parametrize("line,path", [
    ("Path:            /private/var/containers/Bundle/x", "/private/var/containers/Bundle/x"),
    ("Path: / x", ""),
    ("Path:/x", ""),
])
def test_ips_path_lines(line, path):
    assert ios_artifacts._ia_ips_path(line) == path


def test_crafted_ips_line_is_read_in_linear_time():
    line = "Process: a" + " " * 60000 + "b"
    started = time.perf_counter()
    for _ in range(20):
        ios_artifacts._ia_ips_process(line)
        ios_artifacts._ia_ips_path("Path: /a" + " " * 60000 + "b")
    assert time.perf_counter() - started < 1.0


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFOs are a POSIX feature")
def test_fifo_swapped_in_after_the_stat_does_not_block(tmp_path, monkeypatch):
    regular = tmp_path / "regular"
    regular.write_bytes(b"x")
    fifo = tmp_path / "swapped"
    os.mkfifo(str(fifo))
    real_stat = os.stat

    def stat_as_if_regular(path, *a, **k):
        return real_stat(str(regular) if os.fspath(path) == str(fifo) else path, *a, **k)

    monkeypatch.setattr(hashscan.os, "stat", stat_as_if_regular)
    outcome = []
    worker = threading.Thread(target=lambda: outcome.append(_try(hashscan._sha256, str(fifo))),
                              daemon=True)
    worker.start()
    worker.join(5)
    assert not worker.is_alive(), "the hash read blocked on a FIFO"
    assert isinstance(outcome[0], OSError)


def _try(fn, *args):
    try:
        return fn(*args)
    except Exception as exc:  # noqa: BLE001 - the test inspects it
        return exc


# --- #8 private data on disk ---------------------------------------------------

def test_stale_temp_folders_are_swept_and_fresh_ones_kept(tmp_path):
    old = time.time() - 2 * localpaths.STALE_TEMP_AGE
    for name in ("zbt_ios_old", "bscan_old", "adint_ioc_old", "zbt_ioc2_old", "unrelated_old"):
        (tmp_path / name).mkdir()
        (tmp_path / name / "copy.db").write_bytes(b"private")
        os.utime(str(tmp_path / name), (old, old))
    (tmp_path / "zbt_ios_running").mkdir()                 # a scan in progress
    (tmp_path / "bscan_file").write_bytes(b"not a folder")
    os.utime(str(tmp_path / "bscan_file"), (old, old))
    result = localpaths.sweep_stale_temp(base=str(tmp_path))
    assert result == {"removed": 4, "failed": []}
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "bscan_file", "unrelated_old", "zbt_ios_running"]


def test_report_in_a_synced_folder_is_named(tmp_path, monkeypatch, capsys):
    synced = tmp_path / "OneDrive"
    (synced / "findings").mkdir(parents=True)
    monkeypatch.setenv("OneDrive", str(synced))
    assert localpaths.synced_folder(str(synced / "findings" / "scan.txt")) == str(synced)
    assert localpaths.synced_folder(str(tmp_path / "elsewhere" / "scan.txt")) == ""
    monkeypatch.setattr(workflow, "sweep_stale_temp", lambda: {"removed": 1, "failed": ["/t/zbt_ios_x"]})
    iocs = types.SimpleNamespace()
    args = types.SimpleNamespace(report=str(synced / "findings" / "scan.txt"), json=None,
                                 share_json=None, evidence_bundle=None)
    workflow.workflow_before_scan(args, iocs)
    err = capsys.readouterr().err
    assert "synced to the cloud" in err and "Removed 1 leftover" in err and "/t/zbt_ios_x" in err
    assert report._housekeeping_block(iocs.housekeeping) == {
        "stale_temp_removed": 1, "stale_temp_not_removed": ["/t/zbt_ios_x"]}


# --- #9 pinned indicator downloads ---------------------------------------------

def _stix(n):
    objects = [{"type": "malware", "id": "malware--1", "name": "Pegasus"}]
    for k in range(n):
        objects += [{"type": "indicator", "id": "indicator--%d" % k,
                     "pattern": "[domain-name:value='feed-%d.example']" % k},
                    {"type": "relationship", "relationship_type": "indicates",
                     "source_ref": "indicator--%d" % k, "target_ref": "malware--1"}]
    return json.dumps({"type": "bundle", "objects": objects}).encode()


BRANCH_URL = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/main/x/test.stix2"
PIN = "a" * 40
PINNED_URL = "https://raw.githubusercontent.com/mvt-project/mvt-indicators/" + PIN + "/x/test.stix2"
SRC = {"id": "test-src", "name": "Test source", "format": "stix2", "cite": "Test",
       "category": "mercenary", "family": "", "url": BRANCH_URL,
       "repo": "mvt-project/mvt-indicators", "path": "x/test.stix2"}


@pytest.fixture
def pinned(monkeypatch):
    data = _stix(3)
    monkeypatch.setattr(feeds, "FEED_PINS", {"mvt-project/mvt-indicators": PIN})
    monkeypatch.setattr(feeds, "FEED_FILE_SHA256", {"test-src": hashlib.sha256(data).hexdigest()})
    monkeypatch.setattr(feeds, "SOURCES", [SRC])
    monkeypatch.setattr(feeds, "KNOWN_GOOD_SOURCES", [])     # only the test source is downloaded
    monkeypatch.setattr(feeds, "MVT_BUILTIN", {})            # and only it can load
    return data


def test_update_downloads_the_pinned_revision(tmp_path, pinned):
    seen = []
    summary = feeds.update(str(tmp_path), fetch=lambda url: seen.append(url) or pinned)
    assert seen == [PINNED_URL] and summary["failed"] == 0
    meta = feeds.read_manifest(str(tmp_path))["test-src"]
    assert meta["revision"] == PIN and meta["url"] == PINNED_URL
    sets, status = feeds.cached_sets(str(tmp_path))
    assert [e["revision"] for e in status["loaded"]] == [PIN]
    assert status["loaded"][0]["pinned_for_this_release"] is True


def test_pinned_download_must_match_the_release_hash(tmp_path, pinned):
    summary = feeds.update(str(tmp_path), fetch=lambda url: _stix(4))
    assert summary["failed"] == 1
    assert "does not match the SHA-256 recorded" in summary["sources"][0]["error"]


def test_latest_follows_the_branch(tmp_path, pinned):
    seen = []
    feeds.update(str(tmp_path), fetch=lambda url: seen.append(url) or _stix(4), latest=True)
    assert seen == [BRANCH_URL]
    assert feeds.read_manifest(str(tmp_path))["test-src"]["revision"] == "branch head"


def test_cache_edited_together_with_its_manifest_is_still_refused(tmp_path, pinned):
    feeds.update(str(tmp_path), fetch=lambda url: pinned)
    edited = _stix(1)
    (tmp_path / "test-src.stix2").write_bytes(edited)
    manifest_path = tmp_path / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["sources"]["test-src"]["sha256"] = hashlib.sha256(edited).hexdigest()
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    _sets, status = feeds.cached_sets(str(tmp_path))
    assert status["loaded"] == []
    assert "pinned for this release" in status["refused"][0]["reason"]


def test_repeated_smaller_drops_cannot_empty_a_source(tmp_path, monkeypatch):
    unpinned = dict(SRC)
    del unpinned["repo"]
    for count, expect_failed in ((40, 0), (25, 0), (15, 1)):
        summary = feeds.update(str(tmp_path), sources=[unpinned], fetch=lambda url, n=count: _stix(n))
        assert summary["failed"] == expect_failed, count
    assert "fell from 40 to 15 (measured against the most this cache has held)" in summary["sources"][0]["error"]


def test_recorded_pins_cover_every_source():
    every = feeds.all_sources()                              # indicator sources and known-good lists
    repos = {src["repo"] for src in every}
    assert repos <= set(feeds.FEED_PINS)
    assert set(feeds.FEED_FILE_SHA256) == {src["id"] for src in every}
    for src in every:
        assert feeds.url_allowed(feeds._pinned_url(src)), src["id"]


# --- #11 release tooling ---------------------------------------------------------

def test_withdrawals_feed_names_the_same_producer_as_the_active_feed():
    def identities(name):
        with open(os.path.join(ROOT, "dist", name), encoding="utf-8") as fh:
            return {o["id"]: o for o in json.load(fh)["objects"] if o["type"] == "identity"}
    active, withdrawn = identities("adfection.stix.json"), identities("adfection.withdrawals.stix.json")
    for ident, obj in withdrawn.items():
        assert obj["name"] == active[ident]["name"]


def test_make_release_refuses_uncommitted_changes(monkeypatch):
    spec = importlib.util.spec_from_file_location("_make_release", os.path.join(ROOT, "tools", "make_release.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "git", lambda *a: " M scan/zbtriage/iocs.py" if a[0] == "status" else "")
    with pytest.raises(SystemExit, match="uncommitted"):
        module.refuse_unless_releasable("v0.0.0")
