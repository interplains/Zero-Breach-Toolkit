"""2.0.5: the live exploited-software list and the exemption for this project's own sites."""
import json

import pytest

from zbtriage import kevdata
from zbtriage.modules import browser


def _catalog(n):
    return json.dumps({"catalogVersion": "2026.11.02", "dateReleased": "2026-11-02",
                       "vulnerabilities": [{"cveID": "CVE-2020-{:04d}".format(i), "dateAdded": "2020-01-01",
                                            "vendorProject": "None", "product": "None"} for i in range(n)]}).encode()


def _update(cache, n, **kw):
    return kevdata.kev_update(str(cache), fetch=lambda url, limit: _catalog(n), **kw)


def _size(cache):
    doc, problem = kevdata.kev_load(str(cache))
    assert not problem
    return doc["catalog_size"], doc["peak_catalog_size"]


def test_a_list_below_half_the_peak_is_refused_and_the_old_copy_kept(tmp_path):
    _update(tmp_path, 1400)
    with pytest.raises(kevdata.KevError, match="fell from 1,400 to 600"):
        _update(tmp_path, 600)
    assert _size(tmp_path) == (1400, 1400)


def test_small_changes_pass_and_the_peak_stays(tmp_path):
    _update(tmp_path, 1400)
    _update(tmp_path, 1300)
    assert _size(tmp_path) == (1300, 1400)
    _update(tmp_path, 1500)
    assert _size(tmp_path) == (1500, 1500)


def test_repeated_small_drops_cannot_empty_it(tmp_path):
    _update(tmp_path, 1400)
    _update(tmp_path, 800)
    with pytest.raises(kevdata.KevError):
        _update(tmp_path, 690)


def test_a_genuine_drop_can_be_accepted_and_resets_the_measure(tmp_path):
    _update(tmp_path, 1400)
    _update(tmp_path, 600, accept_shrink=True)
    assert _size(tmp_path) == (600, 600)
    _update(tmp_path, 500)


def test_a_first_download_or_older_cache_has_nothing_to_compare(tmp_path):
    _update(tmp_path, 150)
    assert _size(tmp_path) == (150, 150)


@pytest.mark.parametrize("url", (
    "https://raw.githubusercontent.com/interplains/zero-breach/main/dist/adfection.adblock.txt",
    "https://raw.githubusercontent.com/interplains/Zero-Breach-Toolkit/main/dist/adfection.hosts.txt",
    "https://archivegenocide.com/scan/",
    "https://archivegenocide.org/scan/index.html",
    "https://archivegenocide.is/scan/scan.js?v=39",
))
def test_our_published_lists_are_still_filter_lists(url):
    assert browser._filter_list_url(url)


@pytest.mark.parametrize("url", (
    "https://raw.githubusercontent.com/interplains/war-crimes-archive/main/page.html",
    "https://raw.githubusercontent.com/interplains/zero-breach/main/README.md",
    "https://raw.githubusercontent.com/interplains/zero-breach/other-branch/dist/a.txt",
    "https://archivegenocide.com/",
    "https://archivegenocide.com/scan/other.html",
    "https://archivegenocide.com/scan/sub/scan.js",
    "https://github.com/interplains/Zero-Breach-Toolkit",
    "https://evil.invalid/scan/scan.js",
))
def test_nothing_else_of_ours_is_exempt(url):
    assert not browser._filter_list_url(url)
