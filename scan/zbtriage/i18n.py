"""Translations of what a person reads: the window, the report and its advice.

English is the source and the record. Every other language is a lookup from the
English sentence to its translation; anything without a translation is shown
in English, never dropped, so a missing entry can only ever cost readability,
not meaning. Indicator values, paths, commands and numbers are never
translated: they arrive as placeholders and are put back as they were.

The catalogs are stored compressed in i18n_data.py (generated from
locales/<lang>.json by build/locales.py) so the single-file download carries
them without a second file to lose.
"""
import base64
import locale
import os
import re
import sys

from .i18n_data import I18N_DATA

# (code, name in its own language). English first; the rest follow the website.
I18N_LANGUAGES = (
    ("en", "English"), ("ar", "العربية"), ("de", "Deutsch"), ("el", "Ελληνικά"),
    ("es", "Español"), ("fa", "فارسی"), ("fr", "Français"), ("he", "עברית"),
    ("hr", "Hrvatski"), ("it", "Italiano"), ("ja", "日本語"), ("ko", "한국어"),
    ("ku", "Kurdî"), ("ms", "Bahasa Melayu"), ("pa", "ਪੰਜਾਬੀ"), ("pl", "Polski"),
    ("pt", "Português"), ("ro", "Română"), ("ru", "Русский"), ("sv", "Svenska"),
    ("sw", "Kiswahili"), ("ta", "தமிழ்"), ("te", "తెలుగు"), ("tl", "Tagalog"),
    ("tr", "Türkçe"), ("uk", "Українська"), ("zh", "中文"),
)
I18N_CODES = tuple(code for code, _name in I18N_LANGUAGES)
I18N_RTL = frozenset(("ar", "fa", "he"))

_i18n_state = {"lang": "en", "catalog": {}, "templates": None}


def _i18n_unpack(blob):
    import lzma   # standard in Python; a build without it simply offers English only
    return lzma.decompress(base64.b85decode("".join(blob))).decode("utf-8").split("\x1e")


def _i18n_blob(lang):
    blob = I18N_DATA.get(lang)
    if not blob:
        return {}
    try:
        keys, values = _i18n_unpack(I18N_DATA["_keys"]), _i18n_unpack(blob)
    except Exception:  # noqa: BLE001 - a damaged embedded catalogue (lzma.LZMAError is not a
        return {}      # ValueError) must never stop the program: English is shown instead
    return {k: v for k, v in zip(keys, values) if v}


def i18n_available():
    """Languages that can actually be shown here (English always)."""
    try:
        import lzma  # noqa: F401
    except ImportError:
        return ("en",)
    return tuple(code for code in I18N_CODES if code == "en" or code in I18N_DATA)


def i18n_set(lang):
    """Choose the language for everything rendered afterwards. Unknown codes
    fall back to English. Returns the code actually in use."""
    lang = (lang or "en").strip().lower().replace("_", "-").split("-")[0]
    if lang not in I18N_CODES:
        lang = "en"
    _i18n_state.update(lang=lang, catalog=_i18n_blob(lang) if lang != "en" else {}, templates=None)
    return lang


def i18n_lang():
    return _i18n_state["lang"]


def i18n_rtl():
    return _i18n_state["lang"] in I18N_RTL


def i18n_default():
    """The computer's own language, if one of ours; otherwise English."""
    candidates = []
    if sys.platform == "win32":
        try:
            import ctypes
            lcid = ctypes.windll.kernel32.GetUserDefaultUILanguage()
            candidates.append(locale.windows_locale.get(lcid, ""))
        except (AttributeError, OSError, ValueError):
            pass
    for name in ("LC_ALL", "LC_MESSAGES", "LANGUAGE", "LANG"):
        candidates.append(os.environ.get(name, "").split(":")[0])
    try:
        candidates.append(locale.getlocale()[0] or "")
    except ValueError:
        pass
    for value in candidates:
        code = (value or "").lower().replace("-", "_").split("_")[0].split(".")[0]
        if code in I18N_CODES:
            return code
    return "en"


def T(text, **values):
    """The current language's version of an English sentence, with {name}
    placeholders filled in after translation."""
    out = _i18n_state["catalog"].get(text, text) if _i18n_state["lang"] != "en" else text
    if values:
        try:
            return out.format(**values)
        except (KeyError, IndexError, ValueError):
            return text.format(**values)   # a damaged translation never hides the facts
    return out


def TN(one, other, n, **values):
    """Singular/plural pair; other languages translate both forms."""
    return T(one if n == 1 else other, n=n, **values)


# A replacement field with an optional conversion and format spec: {}, {name}, {:,}, {:.1f}
_I18N_FIELD = re.compile(r"\{(\w*)(?:![rsa])?(?::[^{}]*)?\}")


def _i18n_compile():
    """Templates with placeholders, as patterns, longest first: messages built by
    the checks themselves ("{} could not be read: {}") are matched back to the
    sentence they were made from."""
    compiled = []
    for source, target in _i18n_state["catalog"].items():
        if "{" not in source or not _I18N_FIELD.search(source):
            continue
        names, parts, pos = [], [], 0
        for m in _I18N_FIELD.finditer(source):
            parts.append(re.escape(source[pos:m.start()]))
            parts.append("(.+?)")
            names.append(m.group(1))
            pos = m.end()
        parts.append(re.escape(source[pos:]))
        literal = len(_I18N_FIELD.sub("", source))
        if literal < 12:      # too little fixed text to recognise safely
            continue
        # Values come back as the text already shown, so the translation's
        # format specs ("{:.1f}") are dropped before filling them in.
        plain = _I18N_FIELD.sub(lambda m: "{" + m.group(1) + "}", target)
        compiled.append((literal, re.compile("^" + "".join(parts) + "$", re.S), names, plain))
    compiled.sort(key=lambda item: -item[0])
    return compiled


def TX(text):
    """Translate a finished message from a check, when it is a known sentence or
    an instance of a known template; otherwise return it unchanged."""
    if _i18n_state["lang"] == "en" or not text:
        return text
    catalog = _i18n_state["catalog"]
    if text in catalog:
        return catalog[text]
    if _i18n_state["templates"] is None:
        _i18n_state["templates"] = _i18n_compile()
    for _literal, pattern, names, target in _i18n_state["templates"]:
        m = pattern.match(text)
        if not m:
            continue
        values = m.groups()
        try:
            if names and all(names):
                return target.format(**dict(zip(names, values)))
            return target.format(*values)
        except (KeyError, IndexError, ValueError):
            return text
    return text


class i18n_as:
    """Render something in another language for a moment, e.g. the English
    original that is always saved beside a translated report."""

    def __init__(self, lang):
        self.lang, self.saved = lang, None

    def __enter__(self):
        self.saved = dict(_i18n_state)
        i18n_set(self.lang)
        return self

    def __exit__(self, *_exc):
        _i18n_state.clear()
        _i18n_state.update(self.saved)
        return False
