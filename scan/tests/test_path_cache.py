"""path_problem_cached gives path_problem's answer with far fewer disk lookups."""
import os

import pytest

from zbtriage import localpaths
from zbtriage.localpaths import path_problem, path_problem_cached


def _deep(tmp_path, depth=8):
    folder = tmp_path
    for n in range(depth):
        folder = folder / "level{}".format(n)
    folder.mkdir(parents=True)
    return folder


def test_same_answer_as_the_full_check(tmp_path):
    folder = _deep(tmp_path)
    names = ["a.bin", "b.bin", "c.ldb"]
    for name in names:
        (folder / name).write_bytes(b"x")
    cache = [None]
    for path in [str(folder / n) for n in names] + [str(folder / "missing.bin"),
                                                    "relative/file.bin", str(folder) + os.sep + ".."]:
        assert path_problem_cached(path, cache) == path_problem(path), path


def test_checks_each_folder_once_not_once_per_file(tmp_path, monkeypatch):
    folder = _deep(tmp_path)
    files = []
    for n in range(50):
        (folder / "f{}.bin".format(n)).write_bytes(b"x")
        files.append(str(folder / "f{}.bin".format(n)))
    calls = []
    real = os.lstat
    monkeypatch.setattr(localpaths.os, "lstat", lambda p, *a, **k: calls.append(p) or real(p, *a, **k))
    for full in files:
        assert path_problem(full) == ""
    full_check = len(calls)
    calls.clear()
    cache = [None]
    for full in files:
        assert path_problem_cached(full, cache) == ""
    # One lookup per folder level once, then one per file - not one per level per file.
    assert len(calls) < full_check / 5
    assert len(calls) <= len(files) + len(folder.parts) + 1


def test_a_problem_folder_is_reported_for_every_file_in_it(tmp_path, monkeypatch):
    folder = _deep(tmp_path, 3)
    (folder / "a.bin").write_bytes(b"x")
    (folder / "b.bin").write_bytes(b"x")
    real = localpaths.path_problem
    monkeypatch.setattr(localpaths, "path_problem",
                        lambda p: "refused for test" if p == str(folder) else real(p))
    cache = [None]
    assert path_problem_cached(str(folder / "a.bin"), cache) == "refused for test"
    assert path_problem_cached(str(folder / "b.bin"), cache) == "refused for test"


def test_a_link_in_place_of_a_file_gets_the_full_refusal(tmp_path):
    folder = _deep(tmp_path, 3)
    (folder / "real.bin").write_bytes(b"x")
    link = folder / "link.bin"
    try:
        os.symlink(str(folder / "real.bin"), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("this account cannot create symbolic links")
    cache = [None]
    answer = path_problem_cached(str(link), cache)
    assert answer and answer == path_problem(str(link))


def test_the_cache_follows_the_folder(tmp_path):
    one, two = _deep(tmp_path / "one", 2), _deep(tmp_path / "two", 2)
    (one / "a.bin").write_bytes(b"x")
    (two / "a.bin").write_bytes(b"x")
    cache = [None]
    assert path_problem_cached(str(one / "a.bin"), cache) == ""
    assert cache[0][0] == str(one)
    assert path_problem_cached(str(two / "a.bin"), cache) == ""
    assert cache[0][0] == str(two)


def _tree(tmp_path):
    for a in range(3):
        for b in range(4):
            folder = tmp_path / "root" / "a{}".format(a) / "b{}".format(b) / "c" / "d"
            folder.mkdir(parents=True)
            (folder / "f.bin").write_bytes(b"x")
    return tmp_path / "root"


def test_walk_lists_the_same_tree_with_fewer_lookups(tmp_path, monkeypatch):
    root = _tree(tmp_path)
    expected = sorted((d, sorted(fs)) for d, _ds, fs in os.walk(str(root)))
    calls = []
    real = os.lstat
    monkeypatch.setattr(localpaths.os, "lstat", lambda p, *a, **k: calls.append(p) or real(p, *a, **k))
    walked = sorted((d, sorted(fs)) for d, _ds, fs in localpaths.walk_local(str(root)))
    assert walked == expected
    folders = len(expected)
    depth = len(root.parts)
    # Full check once for the root, then one lookup per folder - not one per level per folder.
    assert len(calls) <= depth + 1 + folders


def test_walk_still_refuses_a_linked_folder(tmp_path):
    root = _tree(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.bin").write_bytes(b"x")
    try:
        os.symlink(str(outside), str(root / "a0" / "linked"), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this account cannot create symbolic links")
    refused = []
    walked = [d for d, _ds, _fs in localpaths.walk_local(str(root), onerror=refused.append)]
    assert not any("outside" in d or "linked" in d for d in walked)
    assert any(getattr(e, "strerror", "") == localpaths.WALK_LINK_REFUSED for e in refused)
