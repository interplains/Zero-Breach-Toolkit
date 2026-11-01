"""2.0.3: smaller review items that each fail on the 2.0.2 code.

Sources: the sanitiser's behaviour is read from contract.py itself (it keeps LF
and TAB on purpose and must go on doing so); the locale checker's rules are
those stated in build/locales.py; the caps named in the documents are the
constants in the modules.
"""
import ast
import base64
import copy
import datetime
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import contract, i18n, report
from zbtriage.iocs import Indicator, IocSet
from zbtriage.result import ModuleResult

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime.datetime(2026, 11, 2, 12, 0, 0)


# --- 24: nothing in the report carries an escape or an override ---------------------

ESC, RLO, LF = "\x1b", "‮", "\n"


def _walk(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for k, v in value.items():
            yield from _walk(k)
            yield from _walk(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _walk(v)


def _document_with_hostile_set():
    ind = Indicator("spy-c2.test", "cc", "primary", "domain", "fixture", "Fam" + RLO + "ily")
    iocs = IocSet([ind], "feed" + ESC + "[31m.txt", None)
    iocs.sets = [{"path": "/feeds/a" + ESC + "[2Jb" + RLO + "c.stix2", "format": "stix2", "usable": 1,
                  "families": ["Evil" + RLO + "Fam", "Other" + ESC + "x"]}]
    module = ModuleResult("browser")
    module.ran("history")
    return report.build_document(iocs, [module], NOW)


def test_importer_paths_and_families_carry_no_escape_or_override():
    doc = _document_with_hostile_set()
    for block in (doc["ioc_set"]["sets"], doc["ioc_set"]["families"], doc["ioc_set"]["path"]):
        for text in _walk(block):
            assert ESC not in text and RLO not in text, repr(text)
    # What is kept is kept readable: the name is still there.
    assert any("Evil" in t and "Fam" in t for t in _walk(doc["ioc_set"]["sets"]))


def test_the_sanitiser_still_keeps_line_feed_and_tab():
    # LF and TAB are allowed on purpose (multi-line notes and detail). Do not change this.
    assert contract.sanitize_untrusted("a" + LF + "b\tc") == "a" + LF + "b\tc"
    assert contract.sanitize_untrusted("a" + ESC + RLO + "b") == "a��b"


def test_the_content_trust_rule_says_what_the_sanitiser_does():
    rule = contract.CONTENT_TRUST["rule"].lower()
    assert "line break" in rule and "tab" in rule, "the rule must say LF and TAB are kept"
    assert "control characters are replaced and length" not in rule     # the old, wider claim


# --- 25: a damaged embedded catalogue never stops the program ------------------------

def test_a_damaged_language_blob_falls_back_to_english():
    garbage = [base64.b85encode(b"not an xz stream at all").decode("ascii")]
    with patch.dict(i18n.I18N_DATA, {"de": garbage}):
        try:
            assert i18n.i18n_set("de") == "de"
            assert i18n.T("Close") == "Close"        # English, not a crash
        finally:
            i18n.i18n_set("en")


# --- 26: the locale checker fails on a missing string, only warns on a stale one -----

def _locales_module():
    sys.path.insert(0, str(ROOT / "build"))
    try:
        import locales
    finally:
        sys.path.pop(0)
    return locales


def _check(tmp_path, english, translated):
    locales = _locales_module()
    (tmp_path / "en.json").write_text(json.dumps(english), encoding="utf-8")
    (tmp_path / "de.json").write_text(json.dumps(translated), encoding="utf-8")
    with patch.object(locales, "LOCALES", str(tmp_path)):
        return locales.check()


def test_a_missing_translation_fails_the_check(tmp_path):
    assert _check(tmp_path, {"One": "One", "Two": "Two"}, {"One": "Eins"}) == 1


def test_a_stale_translation_only_warns(tmp_path):
    assert _check(tmp_path, {"One": "One"}, {"One": "Eins", "Gone": "Weg"}) == 0


def test_a_complete_catalogue_passes(tmp_path):
    assert _check(tmp_path, {"One": "One"}, {"One": "Eins"}) == 0


# --- 27: no test hides behind `if __name__ == "__main__"` ------------------------------

def test_no_test_function_is_defined_inside_a_main_guard():
    stranded = []
    for path in sorted(Path(__file__).parent.glob("test_*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8-sig"))
        for node in tree.body:
            if isinstance(node, ast.If) and "__main__" in ast.dump(node.test):
                for inner in ast.walk(node):
                    if isinstance(inner, ast.FunctionDef) and inner.name.startswith("test"):
                        stranded.append("{}::{}".format(path.name, inner.name))
    assert not stranded, "these tests are never collected: " + ", ".join(stranded)


# --- 29: the documents state the cap the code applies ----------------------------------

def test_the_per_file_hash_cap_is_stated_as_it_is():
    from zbtriage.modules import hashscan
    assert hashscan.MAX_BYTES == 512 * 1024 * 1024
    stale = []
    for name in ("README.md", "docs/METHODOLOGY.md", "docs/COVERAGE.md", "scan/zbtriage/readers.py",
                 "scan/zbtriage/scope.py"):
        text = (ROOT / name).read_text(encoding="utf-8")
        if "120 MiB" in text or "120 MB" in text:
            stale.append(name)
    assert not stale, "still say 120 MiB: " + ", ".join(stale)
    traces = (ROOT / "scan/zbtriage/modules/traces.py").read_text(encoding="utf-8")
    assert "same cap as the hash check" not in traces


# --- 30 and 9: documentation lines ------------------------------------------------------

def test_the_readme_says_the_window_always_exits_zero():
    text = " ".join((ROOT / "README.md").read_text(encoding="utf-8").split())
    assert "window always exits with 0" in text and "terminal" in text


def test_the_methodology_states_the_hsts_limit():
    text = " ".join((ROOT / "docs" / "METHODOLOGY.md").read_text(encoding="utf-8").split())
    assert "exact host name" in text and "subdomains" in text and "HSTS" in text
