"""Where someone stopped, so the window can say "welcome back" next time.

One small file in the program's own folder (next to the downloaded indicator lists), holding only what is needed to
pick up the step - for an iPhone backup, the backups that already existed when it was started. It is removed as soon
as the step is done or the person declines it, and it is ignored after RS_MAX_AGE_DAYS. Nothing in it is a result.
"""
import json
import os
import time

from .feeds import default_cache_dir

RS_MAX_AGE_DAYS = 14
RS_FILE = "unfinished-step.json"


def resume_path() -> str:
    return os.path.join(os.path.dirname(default_cache_dir()), RS_FILE)


def resume_save(kind: str, data: dict, path: str = "") -> None:
    """Remember an unfinished step. Never fails the caller: a step that cannot be remembered is just not offered."""
    path = path or resume_path()
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"kind": kind, "started": time.time(), "data": data}, fh)
        os.replace(tmp, path)
    except (OSError, TypeError, ValueError):
        pass


def resume_load(path: str = "", now: float = None) -> dict:
    """The remembered step, or {} when there is none, it is unreadable, or it is older than RS_MAX_AGE_DAYS (then it
    is removed)."""
    path = path or resume_path()
    now = time.time() if now is None else now
    try:
        with open(path, encoding="utf-8") as fh:
            step = json.load(fh)
    except (OSError, ValueError):
        return {}
    if not isinstance(step, dict) or not isinstance(step.get("data"), dict) or \
            not isinstance(step.get("started"), (int, float)) or now - step["started"] > RS_MAX_AGE_DAYS * 86400:
        resume_clear(path)
        return {}
    return step


def _flags_path() -> str:
    return os.path.join(os.path.dirname(default_cache_dir()), "window-choices.json")


def resume_flag(name: str, path: str = "") -> bool:
    """True once resume_set_flag(name) was called (for example: the first-open question was shown)."""
    try:
        with open(path or _flags_path(), encoding="utf-8") as fh:
            return bool(json.load(fh).get(name))
    except (OSError, ValueError, AttributeError):
        return False


def resume_set_flag(name: str, path: str = "") -> None:
    path = path or _flags_path()
    try:
        try:
            with open(path, encoding="utf-8") as fh:
                flags = json.load(fh)
        except (OSError, ValueError):
            flags = {}
        if not isinstance(flags, dict):
            flags = {}
        flags[name] = True
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path + ".tmp", "w", encoding="utf-8") as fh:
            json.dump(flags, fh)
        os.replace(path + ".tmp", path)
    except OSError:
        pass


def resume_clear(path: str = "") -> None:
    try:
        os.remove(path or resume_path())
    except OSError:
        pass
