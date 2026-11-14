"""A calmer, clearer terminal: colour for the result, and one progress line that updates in place.

Only what is shown on a real terminal changes - saved reports, files and anything piped are never touched. Off when
the output is not a terminal, NO_COLOR is set (https://no-color.org), TERM=dumb, or (on Windows) the console does not
accept colour codes. Colour is used sparingly: the one line that says what was found, and the section headings.
"""
import os
import re
import shutil
import sys

_RESET, _BOLD, _RED, _AMBER, _GREEN = "\x1b[0m", "\x1b[1m", "\x1b[1;31m", "\x1b[1;33m", "\x1b[1;32m"


def ts_enabled(stream) -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb" or os.environ.get("ZB_PLAIN_MENU"):
        return False
    try:
        if not stream.isatty():
            return False
    except (AttributeError, ValueError):
        return False
    if sys.platform == "win32":
        return _ts_windows_vt(stream)
    return True


def _ts_windows_vt(stream) -> bool:
    """Ask the Windows console to accept colour codes (Windows 10 and later); False if it will not."""
    try:
        import ctypes
        import msvcrt
        kernel = ctypes.windll.kernel32
        handle = msvcrt.get_osfhandle(stream.fileno())
        mode = ctypes.c_ulong()
        if not kernel.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(kernel.SetConsoleMode(handle, mode.value | 0x0004))     # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except (AttributeError, OSError, ValueError, ImportError):
        return False


def ts_level(document) -> str:
    """"red" (spyware, stalkerware or Cellebrite on the device), "amber" (anything else found, or not everything
    checked) or "green" (nothing found and every check ran) - the same judgement as IN PLAIN WORDS."""
    from .report import PLAIN_STRONG, result_kind
    hits = [h for m in document.get("modules", {}).values() for h in m.get("hits", [])
            if not h.get("withdrawn_only") and h.get("evidence") != "referenced"]
    if any(h.get("evidence") in PLAIN_STRONG or h.get("tier") == "forensic" for h in hits):
        return "red"
    if hits or document.get("verdict", {}).get("gaps") or result_kind(document) != "none":
        return "amber"
    return "green"


def ts_colour_report(text: str, document) -> str:
    """The report with its plain-words result line coloured by ts_level and the section headings in bold."""
    from .i18n import T
    colour = {"red": _RED, "amber": _AMBER, "green": _GREEN}[ts_level(document)]
    lines = text.split("\n")
    heading = "  " + T("IN PLAIN WORDS")
    out, result_from = [], None
    for i, line in enumerate(lines):
        if line == heading:
            result_from = i + 2                           # the rule under the heading, then the result line
        if result_from is not None and i >= result_from and result_from >= 0:
            if line.strip() and (i == result_from or line.startswith("  " + " " * 8)):
                out.append(colour + line + _RESET)
                continue
            result_from = -1
        if re.match(r"^ {2}[A-Z][A-Z0-9 ,.'()/-]{3,}(\s{2}.*)?$", line) and line.strip() == line.strip().upper()[:len(line.strip())]:
            out.append(_BOLD + line + _RESET)
            continue
        out.append(line)
    return "\n".join(out)


class TsProgress:
    """A progress sink for the scan: one line, updated in place, in the same plain words as the window. Warnings
    and errors are still written on their own lines so nothing important scrolls away unseen."""

    def __init__(self, stream):
        self.stream, self.state, self.shown = stream, {}, 0
        self.width = max(40, min(120, shutil.get_terminal_size((80, 24)).columns) - 1)

    def __call__(self, message):
        from .gui import gui_progress
        message = str(message)
        if re.match(r"(?i)^\s*(warning|error|!!)", message):
            self._line("")
            self.stream.write(message + "\n")
            self.stream.flush()
            return
        text, _percent = gui_progress(message, self.state)
        if "current" not in self.state:
            text = re.sub(r"^\[\*\]\s*", "", message.strip())
        self._line("  " + text)

    def _line(self, text):
        text = text[:self.width]
        self.stream.write("\r" + text + " " * max(0, self.shown - len(text)))
        self.stream.flush()
        self.shown = len(text)

    def finish(self):
        """End the progress line before the report is printed."""
        if self.shown:
            self._line("")
            self.stream.write("\r")
            self.stream.flush()
            self.shown = 0
