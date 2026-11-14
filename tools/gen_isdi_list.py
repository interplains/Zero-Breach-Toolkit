"""Regenerate scan/zbtriage/isdidata.py from Cornell ISDi's app-flags.csv (MIT licence).

    python tools/gen_isdi_list.py path/to/app-flags.csv

Source: https://github.com/stopipv/isdi  (src/isdi/data/app-flags.csv, MIT, Copyright (c) 2018 Cornell University).
Some rows originate from the Echap stalkerware-indicators project (CC BY 4.0); both are credited in NOTICE.
Only Android app ids are kept (Play Store and off-store rows), with their flag; titles are dropped.
"""
import csv
import hashlib
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "scan", "zbtriage", "isdidata.py")
KEEP_FLAGS = {"dual-use", "stalkerware", "spyware"}


def main(path):
    raw = open(path, "rb").read()
    rows = csv.DictReader(raw.decode("utf-8", "replace").splitlines())
    keep = {}
    for row in rows:
        app = (row.get("appId") or "").strip()
        flag = (row.get("flag") or "").strip().lower()
        if row.get("store") in ("playstore", "offstore") and flag in KEEP_FLAGS and app and "." in app \
                and len(app) < 200 and all(c.isalnum() or c in "._" for c in app):
            # a stronger flag wins if an app is listed twice
            key = app.lower()
            if keep.get(key) in ("stalkerware", "spyware") and flag == "dual-use":
                continue
            keep[key] = flag
    lines = ["{}|{}".format(app, flag) for app, flag in sorted(keep.items())]
    body = "\n".join(lines)
    with open(OUT, "w", encoding="utf-8", newline="\n") as fh:
        fh.write('"""Android apps that can be used to watch someone, from Cornell ISDi (MIT; generated - do not edit).\n\n')
        fh.write("Source app-flags.csv sha256 {}; regenerate with tools/gen_isdi_list.py.\n".format(
            hashlib.sha256(raw).hexdigest()))
        fh.write("Flags: dual-use (legitimate apps that can be turned on a partner), stalkerware, spyware.\n")
        fh.write('Some entries originate from Echap stalkerware-indicators (CC BY 4.0). See NOTICE."""\n\n')
        fh.write("ISDI_APP_FLAGS_TEXT = '''\n" + body + "\n'''\n\n")
        fh.write("ISDI_APP_FLAGS = dict(line.split('|', 1) for line in ISDI_APP_FLAGS_TEXT.split() if '|' in line)\n")
    print("wrote", OUT, len(keep), "Android apps")


if __name__ == "__main__":
    main(sys.argv[1])
