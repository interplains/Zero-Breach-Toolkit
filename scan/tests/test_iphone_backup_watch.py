"""The window's "Make an iPhone backup" watcher: a backup is offered only once Apple's app has finished it."""
import os
import plistlib
import time

from zbtriage import iphonebackup as ib


def _backup(root, name, state="finished", manifest=True, age=60, device="Sara's iPhone"):
    path = root / name
    path.mkdir(parents=True, exist_ok=True)
    status = path / "Status.plist"
    status.write_bytes(plistlib.dumps({"SnapshotState": state, "IsFullBackup": True}))
    when = time.time() - age
    os.utime(status, (when, when))
    if manifest:
        (path / "Manifest.db").write_bytes(b"SQLite format 3\x00")
    (path / "Info.plist").write_bytes(plistlib.dumps({"Device Name": device, "Product Type": "iPhone15,2",
                                                       "Product Version": "18.6"}))
    return str(path)


def test_old_backups_are_not_offered(tmp_path):
    _backup(tmp_path, "old")
    baseline = ib.ib_snapshot([str(tmp_path)])
    assert ib.ib_new_finished(baseline, [str(tmp_path)]) == []


def test_new_finished_backup_is_offered(tmp_path):
    baseline = ib.ib_snapshot([str(tmp_path)])
    path = _backup(tmp_path, "new")
    assert ib.ib_new_finished(baseline, [str(tmp_path)]) == [path]
    assert ib.ib_device_name(path) == "Sara's iPhone (iPhone15,2, 18.6)"


def test_fresh_backup_into_an_existing_folder_is_offered(tmp_path):
    path = _backup(tmp_path, "same", age=3600)
    baseline = ib.ib_snapshot([str(tmp_path)])
    _backup(tmp_path, "same", age=30)
    assert ib.ib_new_finished(baseline, [str(tmp_path)]) == [path]


def test_backup_still_being_written_is_not_offered(tmp_path):
    baseline = ib.ib_snapshot([str(tmp_path)])
    _backup(tmp_path, "busy", state="uploading")
    _backup(tmp_path, "just-finished", age=2)
    _backup(tmp_path, "no-manifest", manifest=False)
    assert ib.ib_new_finished(baseline, [str(tmp_path)]) == []


def test_damaged_status_file_is_ignored(tmp_path):
    baseline = ib.ib_snapshot([str(tmp_path)])
    path = tmp_path / "broken"
    path.mkdir()
    (path / "Status.plist").write_bytes(b"not a plist")
    assert ib.ib_new_finished(baseline, [str(tmp_path)]) == []


def test_missing_roots_are_fine(tmp_path):
    assert ib.ib_snapshot([str(tmp_path / "nope")]) == {}
    assert ib.ib_new_finished({}, [str(tmp_path / "nope")]) == []


def test_steps_tell_people_to_encrypt_and_warn_about_the_password():
    for steps in ib.IB_STEPS.values():
        assert any("Encrypt local backup" in s for s in steps)
    assert any("cannot be opened by anyone" in w for w in ib.IB_WARNINGS)
    assert any("Reset All Settings" in w for w in ib.IB_WARNINGS)


def test_half_written_xml_status_is_ignored(tmp_path):
    baseline = ib.ib_snapshot([str(tmp_path)])
    path = tmp_path / "writing"
    path.mkdir()
    (path / "Status.plist").write_bytes(b'<?xml version="1.0"?><plist version="1.0"><dict><key>Snapsh')
    (path / "Info.plist").write_bytes(b"<?xml version")
    assert ib.ib_new_finished(baseline, [str(tmp_path)]) == []
    assert ib.ib_device_name(str(path)) == ""
