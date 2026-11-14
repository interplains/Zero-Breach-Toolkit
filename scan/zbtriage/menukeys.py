"""Choosing from the terminal menu with the arrow keys, as well as by typing a number.

The numbered list is printed as before; one line under it shows the highlighted entry. Up/Down move the highlight,
Enter chooses it, and typing a number (or ? or 0) works exactly as it always did. Only that one line is redrawn -
with a carriage return and spaces, no terminal codes - so it works in the Windows console, macOS Terminal and Linux
terminals alike, a screen reader still reads it, and a long list needs no scrolling.

Off (the plain typed prompt instead) whenever keys cannot be read one at a time: input or output not a terminal,
TERM=dumb, or ZB_PLAIN_MENU set. No library is needed: msvcrt on Windows, termios elsewhere.
"""
import os
import shutil
import sys


def mk_supported(stdin, stderr) -> bool:
    if os.environ.get("ZB_PLAIN_MENU") or os.environ.get("TERM") == "dumb":
        return False
    try:
        if stdin is not sys.stdin or not stdin.isatty() or not stderr.isatty():
            return False
        # Keys are read from the console itself (msvcrt / termios), so the input must BE the console: a stand-in
        # that only says it is a terminal (a test, a wrapper) would leave the menu waiting for a key forever.
        if not os.isatty(stdin.fileno()):
            return False
    except (AttributeError, ValueError, OSError):
        return False
    if sys.platform == "win32":
        try:
            import msvcrt  # noqa: F401
            return True
        except ImportError:
            return False
    try:
        import termios  # noqa: F401
        import tty  # noqa: F401
        return True
    except ImportError:
        return False


def mk_keys(stdin):
    """Key presses as tokens: "up", "down", "enter", "backspace", "interrupt", "end", or the character typed."""
    if sys.platform == "win32":
        import msvcrt
        while True:
            c = msvcrt.getwch()
            if c in ("\x00", "\xe0"):
                code = msvcrt.getwch()
                yield {"H": "up", "P": "down", "G": "home", "O": "end_key"}.get(code, "")
            elif c in ("\r", "\n"):
                yield "enter"
            elif c == "\x08":
                yield "backspace"
            elif c == "\x03":
                yield "interrupt"
            elif c in ("\x1a", "\x04"):
                yield "end"
            else:
                yield c
        return
    import termios
    import tty
    fd = stdin.fileno()
    saved = termios.tcgetattr(fd)
    try:
        tty.setcbreak(fd)
        while True:
            c = os.read(fd, 1).decode("utf-8", "replace")
            if c == "\x1b":
                seq = os.read(fd, 2).decode("utf-8", "replace")
                yield {"[A": "up", "[B": "down", "OA": "up", "OB": "down", "[H": "home", "[F": "end_key"}.get(seq, "")
            elif c in ("\r", "\n"):
                yield "enter"
            elif c in ("\x7f", "\x08"):
                yield "backspace"
            elif c == "\x03":
                yield "interrupt"
            elif c in ("\x04", ""):
                yield "end"
            else:
                yield c
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)


def mk_select(labels, write, keys, hint="", start=1):
    """The choice as the typed prompt would give it: "1".."N", "?", "0", or None at end of input.

    labels: the entries, numbered from 1 as printed above. write: puts text on the terminal. keys: key tokens."""
    count = len(labels)
    current, typed, shown = max(1, min(start, count)), "", 0
    width = max(30, min(120, shutil.get_terminal_size((80, 24)).columns) - 1)

    def draw():
        nonlocal shown
        if typed:
            text = "  > {}{}".format(typed, "  " + labels[int(typed) - 1] if typed.isdigit() and
                                     1 <= int(typed) <= count else "")
        else:
            text = "  > {:>2}  {}".format(current, labels[current - 1])
        text = (text + "   " + hint) if hint and len(text) + len(hint) + 3 <= width else text
        text = text[:width]
        write("\r" + text + " " * max(0, shown - len(text)))
        shown = len(text)

    draw()
    for key in keys:
        if key == "interrupt":
            write("\n")
            raise KeyboardInterrupt
        if key == "end":
            write("\n")
            return None
        if key == "up":
            typed, current = "", count if current <= 1 else current - 1
        elif key == "down":
            typed, current = "", 1 if current >= count else current + 1
        elif key == "home":
            typed, current = "", 1
        elif key == "end_key":
            typed, current = "", count
        elif key == "backspace":
            typed = typed[:-1]
        elif key == "enter":
            write("\n")
            return typed if typed else str(current)
        elif key in ("?", "q", "Q"):
            write("\n")
            return "?" if key == "?" else "0"
        elif key.isdigit():
            typed = (typed + key)[:4]
            if typed == "0":
                write("\n")
                return "0"
        draw()
    write("\n")
    return None
