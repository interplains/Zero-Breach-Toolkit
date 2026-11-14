"""Installed apps when a backup's Info.plist has no usable list (issue #47, an iOS 27 backup).

The app list comes from Info.plist "Installed Applications" when that list is usable; the
app containers in the backup's file index (AppDomain-<bundle id>) are added to it, and are
the only source when Info.plist has no usable list. Neither present is still a gap.
"""
import plistlib

from zbtriage.modules import ios

from test_followup_fixes import bundle  # noqa: F401  (fixture used by `reader`)
from test_ios_upgrade import APP, backup, ctx, reader  # noqa: F401


def _info(root, **values):
    (root / "Info.plist").write_bytes(plistlib.dumps(dict({"Product Version": "fixture-version"}, **values)))


def _check(result, name="ios:applications"):
    return [c for c in result.checks if c.name == name]


def test_apps_come_from_containers_when_info_plist_has_no_list(tmp_path, reader):
    root = tmp_path / "backup"
    backup(root, [("AppDomain-" + APP, "Library/Preferences/" + APP + ".plist", b"prefs")])
    _info(root)                                   # no "Installed Applications" key at all
    result = reader(ctx(root))
    assert _check(result) and all(c.ran for c in _check(result))
    hits = [h for h in result.hits if h.indicator == APP]
    assert hits and hits[0].location == "Manifest.db"
    assert any("identified from their data folders" in n for n in result.notes)


def test_wrong_type_list_falls_back_to_containers(tmp_path, reader):
    root = tmp_path / "backup"
    backup(root, [("AppDomain-" + APP, "Documents/x", b"x")])
    _info(root, **{"Installed Applications": {"not": "a list"}})
    result = reader(ctx(root))
    assert all(c.ran for c in _check(result))
    assert any(h.indicator == APP for h in result.hits)


def test_info_plist_list_is_still_used_and_preferred(tmp_path, reader):
    root = tmp_path / "backup"
    backup(root, [("AppDomain-" + APP, "Documents/x", b"x")])
    _info(root, **{"Installed Applications": [APP]})
    result = reader(ctx(root))
    hits = [h for h in result.hits if h.indicator == APP and "application" in h.detail]
    assert len(hits) == 1 and hits[0].location == "Info.plist"
    assert not any("identified from their data folders" in n for n in result.notes)


def test_no_list_and_no_containers_is_still_a_gap(tmp_path, reader):
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/Preferences/x.plist", b"x")])
    _info(root)
    result = reader(ctx(root))
    assert _check(result) and not any(c.ran for c in _check(result))


def test_empty_list_on_a_stock_phone_still_runs(tmp_path, reader):
    root = tmp_path / "backup"
    backup(root, [("HomeDomain", "Library/Preferences/x.plist", b"x")])   # backup() writes an empty list
    result = reader(ctx(root))
    assert all(c.ran for c in _check(result))


def test_only_appdomain_names_an_installed_app():
    entries = [("AppDomain-com.a.app", "x"), ("AppDomainGroup-group.com.a", "y"),
               ("AppDomainPlugin-com.a.app.share", "z"), ("HomeDomain", "w"), ("AppDomain-", "v"), (None, "u")]
    assert ios._ios_container_app_ids(entries) == {"com.a.app"}
