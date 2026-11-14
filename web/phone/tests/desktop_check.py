"""Run the desktop engine on a phone folder and print the parts the browser
check must reproduce exactly (parity reference).

    python web/phone/tests/desktop_check.py FOLDER   (password from ZBT_TEST_PASSWORD)
"""
import datetime
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(HERE))), "scan"))
# The page ships an exploited-vulnerability list; the reference run uses the same
# one when ZBT_TEST_KEV_CACHE names the folder holding it.
if os.environ.get("ZBT_TEST_KEV_CACHE"):
    import zbtriage.feeds as _feeds  # noqa: E402
    _feeds.default_cache_dir = lambda: os.environ["ZBT_TEST_KEV_CACHE"]

from zbtriage.cli import _parse, _load_iocs, _run_modules  # noqa: E402
from zbtriage.context import ScanContext  # noqa: E402
from zbtriage.report import prepare_document, result_kind  # noqa: E402


def parity(document):
    hits = sorted((name, h.get("indicator"), h.get("evidence"), h.get("location"))
                  for name, m in document.get("modules", {}).items() for h in m.get("hits", []))
    leads = sorted((name, l.get("check"), l.get("location"))
                   for name, m in document.get("modules", {}).items() for l in m.get("leads", []))
    return {"kind": result_kind(document), "status": document["verdict"]["status"],
            "gaps": sorted(document["verdict"].get("gaps", [])), "hits": hits, "leads": leads}


def main(folder):
    args = _parse(["--phone", folder, "--no-feeds", "--no-banner", "--no-menu", "--no-version-check"])
    iocs = _load_iocs(args)
    ctx = ScanContext(iocs=iocs, phone_path=folder, backup_password=os.environ.get("ZBT_TEST_PASSWORD", ""),
                      emit=lambda _m: None)
    ctx.completed = _run_modules(ctx)
    document = prepare_document(iocs, ctx.completed, datetime.datetime.now(), args)
    print(json.dumps(parity(document), indent=1, default=str))


if __name__ == "__main__":
    main(sys.argv[1])
