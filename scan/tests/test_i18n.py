"""Translations: English is unchanged, a translation is used whole, anything
missing or damaged falls back to the English facts, and every shipped language
keeps the parts that must never change."""
import base64
import json
import os
import re
import sys
import zlib

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from zbtriage import i18n, report  # noqa: E402
from zbtriage.i18n import I18N_CODES, T, TN, TX, i18n_as, i18n_lang, i18n_rtl, i18n_set  # noqa: E402
from zbtriage.i18n_data import I18N_DATA  # noqa: E402


@pytest.fixture(autouse=True)
def english_after():
    yield
    i18n_set("en")


def _catalog(monkeypatch, lang, entries):
    monkeypatch.setitem(i18n._i18n_state, "lang", lang)
    monkeypatch.setitem(i18n._i18n_state, "catalog", dict(entries))
    monkeypatch.setitem(i18n._i18n_state, "templates", None)


def test_english_is_the_text_itself():
    i18n_set("en")
    assert T("Saved: {path}", path="C:/x") == "Saved: C:/x"
    assert TN("{n} check could not run.", "{n} checks could not run.", 1) == "1 check could not run."
    assert TN("{n} check could not run.", "{n} checks could not run.", 3) == "3 checks could not run."
    assert TX("anything at all") == "anything at all"


def test_unknown_language_falls_back_to_english():
    assert i18n_set("xx") == "en"
    assert i18n_set("pt-BR") == "pt"
    assert i18n_set("zh_CN.UTF-8") == "zh"


def test_translation_is_used_and_placeholders_filled(monkeypatch):
    _catalog(monkeypatch, "es", {"Saved: {path}": "Guardado: {path}"})
    assert T("Saved: {path}", path="C:/x") == "Guardado: C:/x"
    assert T("Not in the catalog") == "Not in the catalog"


def test_a_damaged_translation_never_hides_the_facts(monkeypatch):
    _catalog(monkeypatch, "es", {"Saved: {path}": "Guardado: {ruta}"})
    assert T("Saved: {path}", path="C:/x") == "Saved: C:/x"


def test_check_messages_match_their_template(monkeypatch):
    _catalog(monkeypatch, "es", {"{} could not be read: {}": "no se pudo leer {}: {}",
                                 "only the newest 10000 events were checked": "solo los 10000 más recientes"})
    assert TX("C:/a.db could not be read: locked") == "no se pudo leer C:/a.db: locked"
    assert TX("only the newest 10000 events were checked") == "solo los 10000 más recientes"
    assert TX("something nobody translated") == "something nobody translated"


def test_rendering_in_another_language_and_back(monkeypatch):
    with i18n_as("es"):
        assert i18n_lang() == "es"
    assert i18n_lang() == "en"
    assert i18n_rtl() is False
    i18n_set("ar")
    assert i18n_rtl() is True


def test_say_keeps_english_lines_and_translates_whole_paragraphs(monkeypatch):
    lines = ["  RESULT: no known indicator was found in anything that could be",
             "          checked."]
    out = []
    report._say(out.append, lines)
    assert out == lines
    _catalog(monkeypatch, "es", {
        "RESULT: no known indicator was found in anything that could be checked.":
            "RESULTADO: no se encontró ningún indicador conocido en lo que se pudo comprobar."})
    out = []
    report._say(out.append, lines)
    assert out[0].startswith("  RESULTADO:")
    assert "comprobar." in " ".join(out)


def test_summary_uses_whole_sentence_translations(monkeypatch):
    from zbtriage.training import TRAINING_SCENARIOS
    assert TRAINING_SCENARIOS
    document = {
        "tool": {"version": "0"}, "timestamp": "2026-01-01T00:00:00", "platform": {"system": "X", "release": "1"},
        "modules": {}, "verdict": {"status": "no-hits", "gaps": [], "hits_total": 0},
        "ioc_set": {"count": 1, "age_days": 1, "stale": False}, "doctrine_line": "x",
    }
    english = report.render_summary(document)
    assert "RESULT: no known indicator was found in anything that could be" in english
    _catalog(monkeypatch, "fr", {
        "RESULT: no known indicator was found in anything that could be checked.":
            "RÉSULTAT : aucun indicateur connu n'a été trouvé.",
        "SUMMARY  —  read this part": "RÉSUMÉ  —  à lire"})
    french = report.render_summary(document)
    assert "RÉSULTAT : aucun indicateur connu n'a été trouvé." in french
    assert "RÉSUMÉ  —  à lire" in french
    # Untranslated sentences stay in English rather than disappearing.
    assert "This is NOT a clean bill of health." in french


def test_saved_report_carries_the_english_original(monkeypatch):
    from zbtriage import gui
    document = {
        "tool": {"version": "0"}, "timestamp": "2026-01-01T00:00:00", "platform": {"system": "X", "release": "1"},
        "modules": {}, "verdict": {"status": "no-hits", "gaps": [], "hits_total": 0},
        "ioc_set": {"count": 1, "age_days": 1, "stale": False}, "doctrine_line": "x",
    }
    i18n_set("en")
    assert "English original" not in gui.gui_report_text(document)
    _catalog(monkeypatch, "de", {"SUMMARY  —  read this part": "ZUSAMMENFASSUNG"})
    text = gui.gui_report_text(document)
    assert "ZUSAMMENFASSUNG" in text
    assert text.index("SUMMARY  —  read this part") > text.index("ZUSAMMENFASSUNG")


_KEEP = (re.compile(r"--scan-type (?:default|full|targeted|browser)|--ios-input (?:backup|filesystem|sysdiagnose)|--training (?:spyware|worth-a-look|clean|cellebrite)|--phone-guide (?:android|ios)|--training spyware \| worth-a-look \| clean"),
         re.compile(r"\{[^{}]*\}"), re.compile(r"https?://[A-Za-z0-9._~:/?#@!$&*+;=%{}-]+"),
         re.compile(r"(?<![A-Za-z0-9_-])--[a-z][A-Za-z0-9_-]*"), re.compile(r"`[^`]+`"))
_NUMBER = re.compile(r"(?<![0-9])[0-9]+(?:[.,][0-9]+)*")


def _faithful(source, translation):
    if sorted(t for p in _KEEP for t in p.findall(source)) != sorted(t for p in _KEEP for t in p.findall(translation)):
        return False
    found = _NUMBER.findall(translation)
    for number in _NUMBER.findall(source):
        if number not in found:
            return False
        found.remove(number)
    return True


@pytest.mark.parametrize("lang", sorted(k for k in I18N_DATA if k != "_keys"))
def test_shipped_catalogs_keep_what_must_not_change(lang):
    catalog = i18n._i18n_blob(lang)
    assert lang in I18N_CODES and len(catalog) > 1000
    damaged = [k for k, v in catalog.items() if not _faithful(k, v)]
    assert damaged == []


@pytest.mark.parametrize("lang", I18N_CODES)
def test_every_language_renders_the_training_reports(lang, tmp_path, monkeypatch):
    from zbtriage import training
    i18n_set(lang)
    for scenario in training.TRAINING_SCENARIOS:
        top, bottom = training.training_banner({"training": {"scenario": scenario}})
        assert top and bottom
    i18n_set("en")


def test_both_entry_points_offer_the_same_languages():
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    cli = open(os.path.join(root, "scan", "zbtriage", "cli.py"), encoding="utf-8").read()
    bundle = open(os.path.join(root, "build", "bundle.py"), encoding="utf-8").read()
    for text in (cli, bundle):
        assert '"--lang", metavar="CODE", default=None, choices=I18N_CODES' in text
