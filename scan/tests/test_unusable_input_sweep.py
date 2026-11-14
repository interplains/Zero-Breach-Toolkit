"""No check may report "ran" from input it could not use.

Why this file exists (2.0.3): a
check that calls ``ran`` without proof that anything was read reads, in a
report, as "looked and found nothing". Most of the older tests feed in a trace
and assert it is found; few feed in unusable input and assert the check does not
claim success. This file does the second thing for every check, and makes it
impossible to add a check without deciding which of three kinds it is.

Three registries, filled in by the sweep_* modules next to this file:

  UNUSABLE        check name -> [(case id, factory)]. Each factory(tmp_path)
                  builds unusable input (empty, truncated, garbage, a layout
                  nobody documented), runs the reader and returns its
                  ModuleResult. The check must NOT appear as ran.
  LEGIT_EMPTY     check name -> (reason, factory). A recognised, valid, genuinely
                  empty input is a legitimate clean read (an empty browser
                  history). The factory builds exactly that and the check must be
                  ran. The one-line reason says why it is not a false all-clear.
  NOT_FILE_BASED  check name -> reason. The check reads live system state or has
                  no input file the sweep could damage.

A literal check name passed to ``.ran(...)`` / ``mark_ok(...)`` that is in none of
the three fails the test, so a new check must be classified. Names built at run
time cannot be seen by the source scan; every such call site is listed in DYNAMIC
as (file, argument text) with the check names it covers.

Fixtures: each sweep module cites, per fixture, the format source its layout
comes from (AOSP, Chromium, MVT, Apple documentation). A fixture whose fields
were invented by the author is a bug (the repo's old ``Uninstall <app> vers=3``
was one).
"""
import ast
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PACKAGE = Path(__file__).resolve().parents[1] / "zbtriage"
SWEEPS = ("sweep_android", "sweep_ios", "sweep_host")


def _load():
    unusable, legit, not_file, dynamic = {}, {}, {}, {}
    for name in SWEEPS:
        try:
            module = __import__(name)
        except ImportError:        # a sweep module that does not exist yet
            continue
        for key, cases in getattr(module, "UNUSABLE", {}).items():
            unusable.setdefault(key, []).extend(cases)
        legit.update(getattr(module, "LEGIT_EMPTY", {}))
        not_file.update(getattr(module, "NOT_FILE_BASED", {}))
        dynamic.update(getattr(module, "DYNAMIC", {}))
    return unusable, legit, not_file, dynamic


UNUSABLE, LEGIT_EMPTY, NOT_FILE_BASED, DYNAMIC = _load()


def _call_sites():
    """[(file, literal name or None, argument text)] for every ran()/mark_ok() call."""
    found = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if path.name in ("result.py", "i18n_data.py"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8-sig"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
            if name not in ("ran", "mark_ok"):
                continue
            # mark_ok(label, kind): the check is named by its second argument.
            arg = node.args[1] if name == "mark_ok" and len(node.args) > 1 else node.args[0]
            literal = arg.value if isinstance(arg, ast.Constant) and isinstance(arg.value, str) else None
            text = ast.unparse(arg) if hasattr(ast, "unparse") else ""   # Python 3.9 and later
            found.append((str(path.relative_to(PACKAGE)).replace("\\", "/"), literal, text))
    return found


def _classified(name):
    return name in UNUSABLE or name in LEGIT_EMPTY or name in NOT_FILE_BASED


def test_every_literal_check_is_classified():
    missing = sorted({"{} ({})".format(literal, where)
                      for where, literal, _text in _call_sites()
                      if literal and not _classified(literal.replace(" (scanned subset)", ""))})
    assert not missing, ("these checks report ran but are in no sweep registry (add them to "
                         "UNUSABLE, LEGIT_EMPTY or NOT_FILE_BASED in tests/sweep_*.py): "
                         + ", ".join(missing))


@pytest.mark.skipif(not hasattr(ast, "unparse"), reason="needs Python 3.9 to compare the text")
def test_every_dynamic_call_site_is_listed():
    missing = sorted({"{}: ran({})".format(where, text)
                      for where, literal, text in _call_sites()
                      if literal is None and (where, text) not in DYNAMIC})
    assert not missing, ("these ran()/mark_ok() call sites build the check name at run time; list "
                         "them in DYNAMIC as (file, argument text): note naming the checks they "
                         "cover and where each is swept: " + ", ".join(missing))


@pytest.mark.skipif(not hasattr(ast, "unparse"), reason="needs Python 3.9 to compare the text")
def test_no_stale_dynamic_entries():
    live = {(where, text) for where, literal, text in _call_sites() if literal is None}
    stale = sorted(str(k) for k in DYNAMIC if k not in live)
    assert not stale, "DYNAMIC lists call sites that no longer exist: " + ", ".join(stale)


def _cases(registry):
    for name, cases in sorted(registry.items()):
        for case_id, factory in cases:
            yield pytest.param(name, factory, id="{}:{}".format(name, case_id))


@pytest.mark.parametrize("name,factory", list(_cases(UNUSABLE)))
def test_unusable_input_never_reports_ran(name, factory, tmp_path):
    result = factory(tmp_path)
    ran = [c for c in result.checks if c.ran and (c.name == name or c.name.startswith(name + ":"))]
    assert not ran, "{} reported ran on input it could not use: {}".format(name, [c.name for c in ran])


@pytest.mark.parametrize("name", sorted(LEGIT_EMPTY))
def test_legitimate_empty_input_is_a_clean_read(name, tmp_path):
    reason, factory = LEGIT_EMPTY[name]
    assert reason.strip() and len(reason) < 240, "give the one-line reason"
    result = factory(tmp_path)
    assert any(c.ran and c.name == name for c in result.checks), (
        "{} is listed as a legitimate empty read but did not run".format(name))
