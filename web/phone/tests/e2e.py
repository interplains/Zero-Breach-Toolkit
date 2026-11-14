"""End-to-end test of the browser phone check in Chromium, Firefox and WebKit.

    python web/phone/tests/e2e.py FIXTURES_DIR [--browsers chromium,firefox,webkit] [--no-csp]

FIXTURES_DIR comes from make_fixtures.py. For every fixture the page's result
must equal the desktop engine's (desktop_check.py): same result kind, same
verdict status, same gaps and the same hits (indicator, evidence grade,
location). It also checks that the worker reports itself sealed, that the
seal probe never reached the server, and that the server received no request
at all between pressing Start and the result.
"""
import argparse
import functools
import http.server
import json
import os
import subprocess
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import serve  # noqa: E402
from desktop_check import parity  # noqa: E402

DIST = os.path.join(os.path.dirname(HERE), "dist")
PASSWORD = "fixture-pass"
CASES = [
    # (name, folder, password, choose label containing, expected kind)
    ("clean backup", "plain-clean", "", None, "none"),
    ("planted indicator", "plain-hit", "", None, "found"),
    ("encrypted, right password", "encrypted-hit", PASSWORD, None, "found"),
    ("encrypted, wrong password", "encrypted-hit", "not-the-password", None, "unread"),
    ("parent folder, newer phone", "parent", "", "New phone", "found"),
    ("not a backup", "not-a-backup", "", None, "unread"),
    # Real-format public sample (MVT's test backup); expected result is the desktop's.
    ("MVT public sample backup", os.environ.get("ZBT_MVT_SAMPLE", ""), "", None, None),
    ("large backup (120k files)", "large-hit", "", None, "found"),
    ("full-size encrypted (170 MB list)", "huge-encrypted-hit", PASSWORD, None, "found"),
    ("Android collection, clean", "android-clean", "", None, None),
    ("Android, planted package", "android-hit", "", None, "found"),
    ("Android, Cellebrite traces", "android-cellebrite", "", None, "found"),
]


def wait_until(test, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        if test():
            return
        time.sleep(0.2)
    raise TimeoutError("condition not met")


def desktop(folder, password):
    env = dict(os.environ, ZBT_TEST_PASSWORD=password)
    out = subprocess.run([sys.executable, os.path.join(HERE, "desktop_check.py"), folder],
                         capture_output=True, text=True, env=env, check=True).stdout
    return json.loads(out)


def normalise(p):
    p = json.loads(json.dumps(p, default=str))
    p["hits"] = sorted(tuple(h) for h in p["hits"])
    p["leads"] = sorted(tuple(l) for l in p.get("leads", []))
    # Paths differ (the page mounts at /evidence); compare what the person sees.
    p["gaps"] = sorted(g for g in p["gaps"])
    return p


def run(fixtures, browsers, csp):
    log = os.path.join(fixtures, "server-requests.log")
    if os.path.exists(log):
        os.remove(log)
    handler = functools.partial(serve.Handler, directory=DIST, log=log, csp=csp)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:{}/index.html".format(server.server_address[1])
    from playwright.sync_api import sync_playwright
    failures = 0
    with sync_playwright() as pw:
        for name in browsers:
            browser = getattr(pw, name).launch()
            page = browser.new_page(accept_downloads=True)
            problems = []
            page.on("pageerror", lambda e: problems.append("pageerror: " + str(e)))
            page.on("console", lambda m: problems.append("console." + m.type + ": " + m.text)
                    if m.type in ("error",) else None)
            t0 = time.time()
            page.goto(base)
            page.wait_for_selector('#seal:not([data-state="pending"]), #error:not([hidden])', timeout=300000)
            if not page.locator("#error").is_hidden():
                print("[{}] FAILED TO START: {}".format(name, page.locator("#error-text").inner_text()))
                for p in problems:
                    print("   ", p[:400])
                failures += 1
                browser.close()
                continue
            seal = page.get_attribute("#seal", "data-state")
            print("[{}] ready in {:.1f}s, seal={}".format(name, time.time() - t0, seal))
            if csp and seal != "sealed":
                print("   FAIL: worker not sealed")
                failures += 1
            for label, folder, password, choose, expected in CASES:
                path = os.path.join(fixtures, folder) if folder else ""
                if not path or not os.path.isdir(path):
                    print("   skip {} (not present)".format(label))
                    continue
                page.set_input_files("#folder-input", path)
                wait_until(lambda: page.locator("#start-note").inner_text() != "Opening the folder…"
                           and (page.locator("#start").is_enabled() or page.locator("#start-note").inner_text()))
                if choose:
                    options = page.locator("#which-select option").all_inner_texts()
                    index = next((i for i, t in enumerate(options) if choose in t), None)
                    if index is None:
                        print("   FAIL {}: no option {!r} in {}".format(label, choose, options))
                        failures += 1
                        continue
                    page.select_option("#which-select", str(index))
                if password:
                    page.fill("#password", password)
                with open(log, "a", encoding="utf-8") as fh:
                    fh.write("--- start {} {}\n".format(name, label))
                t1 = time.time()
                page.click("#start")
                page.wait_for_selector("#result:not([hidden]), #error:not([hidden])", timeout=600000)
                with open(log, "a", encoding="utf-8") as fh:
                    fh.write("--- end {} {}\n".format(name, label))
                if not page.locator("#error").is_hidden():
                    print("   FAIL {}: {}".format(label, page.locator("#error-text").inner_text()))
                    failures += 1
                    continue
                with page.expect_download() as dl:
                    page.click("#save-json")
                document = json.loads(open(dl.value.path(), encoding="utf-8").read())
                got = normalise(parity(document))
                sub = os.path.join(path, document.get("scope", {}).get("phone", "") and "" or "")
                ref_folder = path
                if choose:
                    ref_folder = os.path.join(path, sorted(os.listdir(path))[index])
                want = normalise(desktop(ref_folder, password))
                ok = (expected is None or got["kind"] == expected) and got == want
                kind = page.get_attribute("#verdict", "data-kind")
                title = page.locator("#verdict-title").inner_text()
                print("   {} {:<30} {:>5.1f}s  page={} ({}) desktop={}  \"{}\"".format(
                    "ok  " if ok else "FAIL", label, time.time() - t1, got["kind"], kind, want["kind"], title))
                if not ok:
                    failures += 1
                    for key in ("status", "gaps", "hits", "leads"):
                        if got[key] != want[key]:
                            print("      {}: page={} desktop={}".format(key, got[key], want[key]))
                page.click("#again")
            real = [p for p in problems if "seal-probe" not in p and "Content Security Policy" not in p
                    and "Content-Security-Policy" not in p]
            for p in real:
                print("   note:", p[:300])
            browser.close()
    server.shutdown()
    lines = open(log, encoding="utf-8").read().splitlines()
    inside, during = False, []
    for line in lines:
        if line.startswith("--- start"):
            inside = True
        elif line.startswith("--- end"):
            inside = False
        elif inside:
            during.append(line)
    probe = [l for l in lines if l.startswith("SEAL-PROBE")]
    print("requests to the server while checks ran:", len(during), during[:5])
    print("seal probes that reached the server:", len(probe))
    if csp and (during or probe):
        failures += 1
    print("RESULT:", "PASS" if not failures else "{} FAILURE(S)".format(failures))
    return 1 if failures else 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("fixtures")
    p.add_argument("--browsers", default="chromium,firefox,webkit")
    p.add_argument("--no-csp", action="store_true")
    a = p.parse_args()
    sys.exit(run(os.path.abspath(a.fixtures), a.browsers.split(","), not a.no_csp))
