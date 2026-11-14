"""Collect the English text people read, and pack finished translations.

    python build/locales.py extract   write locales/en.json: every sentence the
                                      window and the report can show, keyed by
                                      itself (the catalog translators work from)
    python build/locales.py build     pack locales/<lang>.json into
                                      scan/zbtriage/i18n_data.py for the bundle
    python build/locales.py check     every translation keeps its placeholders,
                                      numbers, addresses and commands

The English text is the key, so a sentence that changes in the code simply
stops being translated (it shows in English) until the catalog is refreshed;
it can never show a stale translation of different words.
"""
import ast
import base64
import io
import itertools
import json
import lzma
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PKG = os.path.join(ROOT, "scan", "zbtriage")
LOCALES = os.path.join(ROOT, "locales")

# Files whose sentences are shown directly (window, report, guides, training).
SHOWN = ("gui.py", "report.py", "training.py", "scope.py", "contract.py")
# Files whose messages reach the report as notes, gaps and details.
MESSAGES = ("result.py", "context.py", "workflow.py", "feeds.py", "heuristics.py", "iocs.py", "evidence.py",
            "devicetraces.py", "ios_artifacts.py", "ios_messages.py", "ios_sources.py",
            "winrecords.py", "netconns.py", "shelllinks.py", "security_products.py",
            "backupcrypto.py", "localpaths.py",
            # the window translates these tools' text (T() in the tool, or T(label) in gui.py)
            "wifinearby.py", "household.py", "accounts.py", "ncinfo.py",
            # the smaller tools' results (translated when shown; saved JSON stays English)
            "filecheck.py", "sevenzip.py", "hashlook.py", "startup.py", "homenet.py", "fixit.py",
            "linkcheck.py", "mailcheck.py", "qrcheck.py", "netcapture.py", "huntwin.py", "huntrules.py",
            "extracted.py", "trackers.py", "helperpack.py")
_WORDS = re.compile(r"[A-Za-z]{2,}")
_FIELD = re.compile(r"\{[^{}]*\}")


def _prose(text):
    """Text a person reads: at least two words, not an identifier or a pattern."""
    if not isinstance(text, str) or len(text) < 4 or len(text) > 8000:
        return False
    bare = _FIELD.sub("", text).strip()
    if " " not in bare or len(_WORDS.findall(bare)) < 2:
        return False
    if re.match(r"\s*(SELECT|PRAGMA|INSERT|CREATE|UPDATE|DELETE|WITH)\b", text):   # SQL
        return False
    if text.startswith(("http://", "https://")) and " " not in text.strip():
        return False
    if re.search(r"\\[dswbSWD]|\(\?[:P!=]|\[\^|\$\)|\^\(", text):   # a regular expression
        return False
    return True


def _docstrings(tree):
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.ClassDef, ast.AsyncFunctionDef)):
            body = getattr(node, "body", [])
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                found.add(id(body[0].value))
    return found


def _options(node):
    """Every string an expression can produce: a constant, either side of an
    if-expression, or nothing."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.IfExp):
        return _options(node.body) + _options(node.orelse)
    return []


def _call_name(node):
    f = node.func
    return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else ""


def _joined(lines):
    return " ".join(line.strip() for line in lines)


def _from_file(path, everything):
    src = io.open(path, encoding="utf-8").read()
    tree = ast.parse(src)
    docs = _docstrings(tree)
    # Lines of a multi-line paragraph are translated as the whole paragraph.
    pieces = {id(element) for node in ast.walk(tree) if isinstance(node, ast.Call)
              and _call_name(node) == "_say" and len(node.args) >= 2 and isinstance(node.args[1], ast.List)
              for element in ast.walk(node.args[1])}
    out = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in ("T", "TX", "_advice_paragraph", "_wrap_t") and node.args:
                arg = node.args[1] if name == "_advice_paragraph" and len(node.args) > 1 else node.args[0]
                out.extend(_options(arg))
            elif name == "TN" and len(node.args) >= 2:
                out.extend(_options(node.args[0]) + _options(node.args[1]))
            elif name == "_say" and len(node.args) >= 2 and isinstance(node.args[1], ast.List):
                choices = [_options(element) or [""] for element in node.args[1].elts]
                for combo in itertools.product(*choices):
                    out.append(_joined(combo))
        if (everything and isinstance(node, ast.Constant) and id(node) not in docs
                and id(node) not in pieces and _prose(node.value)):
            out.append(node.value)
    return out


def _training_notes():
    sys.path.insert(0, os.path.join(ROOT, "scan"))
    from zbtriage.training import _TRN_NOTES
    return ["\n".join(lines) for lines in _TRN_NOTES.values()]


def _metric_labels():
    sys.path.insert(0, os.path.join(ROOT, "scan"))
    from zbtriage.report import _METRIC_LABELS
    return [label.strip() for label in _METRIC_LABELS.values()]


def _gui_tables():
    """Labels the window keeps in tables and translates through a variable."""
    sys.path.insert(0, os.path.join(ROOT, "scan"))
    from zbtriage import gui, report
    out = []
    for _value, label, note in gui.GUI_CHECKS:
        out += [label, note]
    out += list(gui.GUI_STEP_NAMES.values())
    out += [label for label, _k in gui.GUI_TRAINING_LABELS]
    out += [label for label, _k in gui.GUI_PHONE_KINDS]
    out += ["Program", "Remote address", "Port", "State", "Known spyware address?",
            "ON", "OFF (the Windows default)", "unknown"]
    out += list(report._APP_NAMES.values())
    return out


def _field_labels(paths):
    """The words of report field labels such as "at     : " (translated alone)."""
    out = []
    for path in paths:
        for m in re.finditer(r'_field\("([^"]+)"\)', io.open(path, encoding="utf-8").read()):
            out.append(m.group(1).split(":")[0].strip())
    return out


def extract():
    shown = [os.path.join(PKG, f) for f in SHOWN]
    messages = ([os.path.join(PKG, f) for f in MESSAGES if os.path.exists(os.path.join(PKG, f))] +
                sorted(os.path.join(PKG, "modules", f) for f in os.listdir(os.path.join(PKG, "modules"))
                       if f.endswith(".py")))
    units = []
    for path in shown:
        units += _from_file(path, everything=True)
    for path in messages:
        units += _from_file(path, everything=True)
    units += _training_notes() + _metric_labels() + _field_labels(shown) + _gui_tables()
    units += ["FINDING", "REF", "look", "HIT"]
    catalog = {}
    for text in units:
        if text and text.strip() and text not in catalog:
            catalog[text] = text
    os.makedirs(LOCALES, exist_ok=True)
    path = os.path.join(LOCALES, "en.json")
    tmp = path + ".tmp"
    with io.open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(dict(sorted(catalog.items())), fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    os.replace(tmp, path)
    print("{} sentences, {:,} characters -> {}".format(
        len(catalog), sum(len(k) for k in catalog), os.path.relpath(path, ROOT)))


# What must survive translation unchanged: placeholders, numbers, addresses,
# command-line options, paths and code in backticks.
_URL_CHARS = r"[A-Za-z0-9._~:/?#@!$&*+;=%{}-]"
_KEEP = (re.compile(r"--scan-type (?:default|full|targeted|browser)|--ios-input (?:backup|filesystem|sysdiagnose)|--training (?:spyware|worth-a-look|clean|cellebrite)|--phone-guide (?:android|ios)|--training spyware \| worth-a-look \| clean"),
         re.compile(r"\{[^{}]*\}"), re.compile(r"https?://" + _URL_CHARS + "+"),
         re.compile(r"(?<![A-Za-z0-9_-])--[a-z][A-Za-z0-9_-]*"), re.compile(r"`[^`]+`"))
_NUMBER = re.compile(r"(?<![0-9])[0-9]+(?:[.,][0-9]+)*")


def keep_tokens(text):
    """Placeholders, links, options and code must match exactly."""
    tokens = []
    for pattern in _KEEP:
        tokens += pattern.findall(text)
    return sorted(tokens)


def numbers_kept(source, translation):
    """Every number in the English must still be there; a translation may add
    one (Japanese writes "one command" with a digit), never lose or change one."""
    found = _NUMBER.findall(translation)
    for number in _NUMBER.findall(source):
        if number not in found:
            return False
        found.remove(number)
    return True


def faithful(source, translation):
    return keep_tokens(source) == keep_tokens(translation) and numbers_kept(source, translation)


def check():
    english = json.load(io.open(os.path.join(LOCALES, "en.json"), encoding="utf-8"))
    bad = 0
    for name in sorted(os.listdir(LOCALES)):
        if not name.endswith(".json") or name == "en.json":
            continue
        catalog = json.load(io.open(os.path.join(LOCALES, name), encoding="utf-8"))
        missing = [k for k in english if k not in catalog]
        damaged = [k for k, v in catalog.items() if k in english and not faithful(k, v)]
        stale = [k for k in catalog if k not in english]
        print("{:8} {:5} translated, {:4} missing, {:3} damaged, {:3} stale".format(
            name[:-5], len(catalog) - len(stale), len(missing), len(damaged), len(stale)))
        for k in damaged[:3]:
            print("    damaged:", repr(k[:70]))
        for k in missing[:3]:
            print("    missing:", repr(k[:70]))
        # A missing or damaged translation fails the check; a stale key (a
        # sentence the code no longer has) only warns, `build` drops it.
        bad += len(damaged) + len(missing)
    return 1 if bad else 0


def _pack(strings):
    raw = "\x1e".join(strings).encode("utf-8")
    return base64.b85encode(lzma.compress(raw, preset=9 | lzma.PRESET_EXTREME)).decode("ascii")


def build():
    english = list(json.load(io.open(os.path.join(LOCALES, "en.json"), encoding="utf-8")))
    data = {"_keys": _pack(english)}
    for name in sorted(os.listdir(LOCALES)):
        if not name.endswith(".json") or name == "en.json":
            continue
        catalog = json.load(io.open(os.path.join(LOCALES, name), encoding="utf-8"))
        # Only sentences whose protected parts survived are shipped; the rest
        # stay empty and show in English.
        values = [catalog[k] if catalog.get(k) and faithful(k, catalog[k]) else "" for k in english]
        data[name[:-5]] = _pack(values)
    path = os.path.join(PKG, "i18n_data.py")
    lines = ['"""Generated by build/locales.py from locales/<lang>.json - do not edit by hand.',
             "",
             "_keys holds the English sentences once; each language holds its translations in",
             "the same order (empty = shown in English). Each is lzma-compressed, base85-encoded",
             'text with one sentence per \\x1e-separated field."""',
             "I18N_DATA = {"]
    for code in sorted(data):
        lines.append("    {!r}: (".format(code))
        blob = data[code]
        for i in range(0, len(blob), 96):
            lines.append("        {!r}".format(blob[i:i + 96]))
        # (base85 never produces a quote or backslash, so repr is plain.)
        lines.append("    ),")
    lines.append("}")
    tmp = path + ".tmp"
    with io.open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    os.replace(tmp, path)
    print("packed {} languages, {:,} bytes".format(len(data), os.path.getsize(path)))


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "extract":
        extract()
    elif command == "build":
        build()
    elif command == "check":
        sys.exit(check())
    else:
        print(__doc__)
        sys.exit(2)
