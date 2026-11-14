"""No top-level name may be defined by two different parts of the single file.

The bundle puts every module in one namespace (only each scan module's NAME and run are renamed). When two
modules define the same top-level name, the one bundled last silently replaces the other for BOTH, so the
downloaded program behaves differently from the source the tests run. That is how the file check's
`KNOWN, LOOK, CLEAN = ...` turned every module status into "clean" instead of "CLEAN" in the program, and how a
second `_ps` (one argument, two results) would have broken the host check's PowerShell calls (two arguments,
three results). Prefix module-private names with the module's own short code (FC_, _dr_, HL_ ...).
"""
import ast
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# The same module imported in two places binds the same object: not a collision.
_SAME_OBJECT = {"winreg"}


def _bound(node):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
        return [node.name]
    targets = node.targets if isinstance(node, ast.Assign) else \
        [node.target] if isinstance(node, (ast.AnnAssign, ast.AugAssign)) else []
    return [sub.id for t in targets for sub in ast.walk(t) if isinstance(sub, ast.Name)]


def collisions(source):
    """{name: [sections]} for every top-level name bound in more than one '# --- <section>' part."""
    section_at, current = [], "(top)"
    for line in source.split("\n"):
        m = re.match(r"^# --- (.+?) -*$", line)
        if m:
            current = m.group(1).strip()
        section_at.append(current)
    seen = {}

    def visit(body):
        for node in body:
            if isinstance(node, (ast.If, ast.Try)):
                for part in (node.body, getattr(node, "orelse", []), getattr(node, "finalbody", [])):
                    visit(part)
                for handler in getattr(node, "handlers", []):
                    visit(handler.body)
                continue
            for name in _bound(node):
                seen.setdefault(name, set()).add(section_at[node.lineno - 1])

    visit(ast.parse(source).body)
    return {n: sorted(s) for n, s in seen.items() if len(s) > 1 and n not in _SAME_OBJECT}


def _built():
    out = Path(tempfile.mkdtemp()) / "bundle.py"
    subprocess.run([sys.executable, "-B", str(ROOT / "build" / "bundle.py"), str(ROOT), str(out)], check=True,
                   capture_output=True, cwd=str(ROOT))
    return out.read_text(encoding="utf-8")


def test_no_top_level_name_is_defined_by_two_modules():
    found = collisions(_built())
    assert found == {}, "names defined in more than one part of the single file: {}".format(found)


def test_the_check_catches_a_tuple_assignment():
    source = ("# --- result -----\nCLEAN = 'CLEAN'\n"
              "# --- filecheck -----\nKNOWN, LOOK, CLEAN = 'known-threat', 'worth-a-look', 'clean'\n")
    assert collisions(source) == {"CLEAN": ["filecheck", "result"]}


def test_the_check_catches_a_function_defined_twice():
    source = "# --- host -----\ndef _ps(cmd, timeout=60):\n    pass\n# --- modules/doors -----\ndef _ps(s):\n    pass\n"
    assert collisions(source) == {"_ps": ["host", "modules/doors"]}
