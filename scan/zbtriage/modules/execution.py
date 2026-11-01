"""Windows Prefetch execution names and Amcache inventory, without target access."""
import os
import stat
import sys
import time

from ..localpaths import path_problem
from ..result import EV_EXECUTION, EV_INVENTORY, EV_REFERENCED, Hit, ModuleResult
from ..winrecords import read_prefetch, read_amcache


NAME = "windows-execution"
_WX_ENTRY_CAP = 20000
_WX_ARTIFACT_CAP = 2048
_WX_DEPTH_CAP = 6
_WX_TOTAL_CAP = 256 * 1024 * 1024
_WX_CHECKS = ("windows-prefetch", "windows-amcache")


def _wx_files(roots, errors):
    pending = [(os.path.abspath(os.fspath(root)), 0) for root in roots]
    seen, examined, artifacts = set(), 0, 0
    deadline = time.monotonic() + 20
    while pending:
        path, depth = pending.pop()
        key = os.path.normcase(path)
        if key in seen:
            continue
        seen.add(key)
        if time.monotonic() > deadline:
            errors.append("artifact discovery exceeded 20 seconds")
            return
        try:
            problem = path_problem(path)
            if problem:
                raise OSError(problem)
            info = os.lstat(path)
            if stat.S_ISREG(info.st_mode):
                lower = os.path.basename(path).lower()
                kind = "windows-prefetch" if lower.endswith(".pf") else (
                    "windows-amcache" if lower == "amcache.hve" or (depth == 0 and lower.endswith(".hve")) else "")
                if kind:
                    artifacts += 1
                    if artifacts > _WX_ARTIFACT_CAP:
                        errors.append("execution artifact count exceeded 2048")
                        return
                    yield kind, path
                continue
            if not stat.S_ISDIR(info.st_mode):
                raise OSError("special filesystem entry was not opened")
            with os.scandir(path) as entries:
                for entry in entries:
                    examined += 1
                    if examined > _WX_ENTRY_CAP:
                        errors.append("execution artifact discovery exceeded 20000 entries")
                        return
                    entry_info = entry.stat(follow_symlinks=False)
                    if stat.S_ISLNK(entry_info.st_mode) or getattr(entry_info, "st_file_attributes", 0) & 0x400:
                        errors.append("symlink/reparse entry was not followed: " + entry.path)
                        continue
                    if stat.S_ISDIR(entry_info.st_mode) and depth >= _WX_DEPTH_CAP:
                        errors.append("execution artifact discovery depth exceeded 6: " + entry.path)
                    else:
                        pending.append((entry.path, depth + 1))
        except OSError as exc:
            errors.append(path + ": " + str(exc))


def _wx_live_reason(text):
    """Windows lets only administrators read these live records; say so."""
    lowered = text.lower()
    if "access is denied" in lowered or "winerror 5]" in lowered or "permission denied" in lowered:
        return text + " (Windows lets only administrators read this; run the check as administrator to include it)"
    return text


def _wx_matches(r, ctx, text, artifact, location, detail, grade, observed="", identity=False):
    matches = list(ctx.iocs.search(text.lower()))
    if identity:
        for kind, value in (("file-path", text), ("file-name", text.replace("/", "\\").rsplit("\\", 1)[-1])):
            ind = ctx.iocs.lookup_typed(kind, value)
            if ind is not None:
                matches.append(ind)
    for ind in matches:
        evidence = grade if identity and ind.type in ("file-name", "file-path") else EV_REFERENCED
        r.add_hit(Hit(ind.value, location, detail, ind.tier, ind.confidence, ind.source,
                      evidence=evidence, observed=observed, family=ind.family, kind=ind.type, artifact=artifact))


def _wx_prefetch(r, ctx, raw, path):
    row = read_prefetch(raw)
    trustworthy_name = bool(row["runs"] and row["times"] and not row["truncated_name"])
    detail = "Prefetch executable basename; recorded run count {}. Full executable path is not inferred.".format(row["runs"])
    _wx_matches(r, ctx, row["name"], path, path + " :: executable", detail,
                EV_EXECUTION if trustworthy_name else EV_REFERENCED,
                row["times"][0] if row["times"] else "", identity=True)
    for index, value in enumerate(row["references"]):
        _wx_matches(r, ctx, value, path, path + " :: file-metric[{}]".format(index),
                    "Prefetch referenced file; this does not identify the launched executable or prove DLL execution.",
                    EV_REFERENCED, identity=True)
    r.checked += 1
    if not trustworthy_name:
        return "Prefetch executable name may be truncated or lacks a nonzero run count/time"
    return ""


def _wx_amcache(r, ctx, raw, path):
    errors, count, usable = [], 0, 0
    for row in read_amcache(raw):
        count += 1
        if row["error"]:
            errors.append(row["error"])
            continue
        usable += 1
        detail = "Amcache file inventory; does not prove execution or that the file is still present. No referenced file was opened."
        _wx_matches(r, ctx, row["path"], path, path + " :: " + row["key"], detail, EV_INVENTORY, identity=True)
        if row["name"] and row["name"].lower() != row["path"].replace("/", "\\").rsplit("\\", 1)[-1].lower():
            # Inconsistent optional display names are text, not file identity.
            _wx_matches(r, ctx, row["name"], path, path + " :: " + row["key"] + " :: Name",
                        "Amcache Name differs from the recorded path basename.", EV_REFERENCED, identity=True)
            errors.append("Amcache Name differs from path basename")
        r.checked += 1
    if count and not usable:
        # Records were there but not one could be read: that is not a read store.
        raise ValueError("no usable Amcache record: {}".format("; ".join(sorted(set(errors))[:3])))
    return "{} unsupported Amcache record(s): {}".format(len(errors), "; ".join(sorted(set(errors))[:3])) if errors else ""


def run(ctx):
    r = ModuleResult("windows-execution")
    ctx.partial = r
    targets = tuple(getattr(ctx, "targets", ()) or ())
    if not targets and sys.platform != "win32":
        for check in _WX_CHECKS:
            r.could_not_run(check, "Windows live records unavailable on this platform; select copied artifacts explicitly")
        return r
    if targets:
        groups = [(tuple(targets), None)]
    else:
        system = os.environ.get("SystemRoot") or r"C:\Windows"
        # Each live location belongs to one check, so a problem finding one of
        # them is reported against that check only.
        groups = [((os.path.join(system, "Prefetch"),), "windows-prefetch"),
                  ((os.path.join(system, "AppCompat", "Programs", "Amcache.hve"),), "windows-amcache")]
    discovery, errors = [], {name: [] for name in _WX_CHECKS}
    group_errors = []

    def walk():
        for roots, owner in groups:
            local = []
            group_errors.append((owner, local))
            for item in _wx_files(roots, local):
                yield item
    found, completed = {name: 0 for name in _WX_CHECKS}, {name: 0 for name in _WX_CHECKS}
    total = 0
    for check, path in walk():
        found[check] += 1
        limit = (16 if check == "windows-prefetch" else 64) * 1024 * 1024
        try:
            problem = path_problem(path)
            if problem:
                raise OSError(problem)
            with open(path, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("execution artifact is not a regular file")
                size = info.st_size
                if size > limit or total + size > _WX_TOTAL_CAP:
                    raise ValueError("execution artifact byte limit exceeded (16 MiB Prefetch/64 MiB hive/256 MiB total)")
                raw = stream.read(limit + 1)
                total += len(raw)
                if len(raw) > limit or total > _WX_TOTAL_CAP:
                    raise ValueError("execution artifact byte limit exceeded during read")
            reader = _wx_prefetch if check == "windows-prefetch" else _wx_amcache
            reason = reader(r, ctx, raw, path)
            completed[check] += 1
            if reason:
                errors[check].append(path + ": " + reason)
        except (OSError, ValueError, UnicodeError, AttributeError) as exc:
            errors[check].append(path + ": " + str(exc))
            r.skipped += 1
    for owner, local in group_errors:
        if owner is None:
            discovery.extend(local)
        else:
            errors[owner].extend(_wx_live_reason(text) for text in local)
    for check in _WX_CHECKS:
        if completed[check]:
            r.ran(check)
        if not found[check]:
            if targets and not discovery:
                r.note(check + ": no applicable artifact in the selected scope; live Windows records were not requested")
            else:
                errors[check].append("no supported artifact found in the selected scope; missing/disabled/deleted records cannot be excluded")
        combined = errors[check] + discovery
        if combined:
            r.could_not_run(check, "{} coverage issue(s): {}".format(len(combined), "; ".join(combined[:3])))
        r.submetrics[check + "-artifacts"] = completed[check]
    r.note("Prefetch identifies recorded executable names, not resolved full paths. Amcache is inventory, not execution proof. Logs, deleted records and newer schemas remain outside coverage.")
    if targets and not any(found.values()) and not discovery:
        r.inapplicable_reason = "No Prefetch or Amcache artifact was present in the selected targets; no live Windows records were requested."
    return r
