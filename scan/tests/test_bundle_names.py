"""Every name the single file and the programs use must exist there.

The bundle removes package imports and puts everything in one module. Code that
says `from . import feeds` and then `feeds.X` works in the package, where the
tests run, and raises NameError in what people download. That is how "Update
indicator lists" in the window came to report an error after every update in
2.0.0 to 2.0.2, and how a try/except hid the same mistake in a new note.

So look at the built file itself: every global name read by any of its code must
be assigned somewhere in that file or be a builtin.
"""
import builtins
import dis
import subprocess
import sys
import tempfile
import types
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_OPTIONAL = {"WindowsError", "unicode", "_MEIPASS", "__file__", "__name__", "__doc__", "__package__",
             "__spec__", "__loader__", "__builtins__", "__cached__", "__annotations__"}


def _code_objects(code):
    yield code
    for const in code.co_consts:
        if isinstance(const, types.CodeType):
            yield from _code_objects(const)


def undefined_globals(source):
    """Global names read somewhere in `source` and bound nowhere in it."""
    bound, read = set(), {}
    for code in _code_objects(compile(source, "bundle", "exec")):
        for ins in dis.get_instructions(code):
            if ins.opname in ("STORE_NAME", "STORE_GLOBAL", "DELETE_NAME", "DELETE_GLOBAL"):
                bound.add(ins.argval)
            elif ins.opname in ("LOAD_GLOBAL", "LOAD_NAME"):
                read.setdefault(ins.argval, code.co_name)
    return {name: where for name, where in read.items()
            if name not in bound and not hasattr(builtins, name) and name not in _OPTIONAL}


def _built():
    out = Path(tempfile.mkdtemp()) / "bundle.py"
    subprocess.run([sys.executable, "-B", str(ROOT / "build" / "bundle.py"), str(ROOT), str(out)], check=True,
                   capture_output=True, cwd=str(ROOT))
    return out.read_text(encoding="utf-8")


def test_the_built_file_uses_no_undefined_name():
    assert undefined_globals(_built()) == {}


def test_the_check_itself_catches_the_mistake():
    source = "def update():\n    from os import sep\n    return feeds.NOTICE, sep\n"
    assert undefined_globals(source) == {"feeds": "update"}
