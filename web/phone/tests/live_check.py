"""Check a deployed copy of the phone check page in Chromium, Firefox and WebKit.

    python web/phone/tests/live_check.py https://HOST/scan/phone/ FIXTURES_DIR

For each browser: the page loads, every file matches files.json (the page
refuses otherwise), the worker reports itself SEALED (the server sent the
worker's own policy), and a planted backup gives the red result. Read-only:
it only loads the page and reads local fixture folders.
"""
import os
import sys
import time


def main(url, fixtures):
    from playwright.sync_api import sync_playwright
    failures = []
    with sync_playwright() as pw:
        for name in ("chromium", "firefox", "webkit"):
            browser = getattr(pw, name).launch()
            page = browser.new_page()
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            t0 = time.time()
            page.goto(url)
            page.wait_for_selector('#seal:not([data-state="pending"]), #error:not([hidden])', timeout=300000)
            if not page.locator("#error").is_hidden():
                failures.append("{}: {}".format(name, page.locator("#error-text").inner_text()))
                browser.close()
                continue
            seal = page.get_attribute("#seal", "data-state")
            page.set_input_files("#folder-input", os.path.join(fixtures, "plain-hit"))
            end = time.time() + 60
            while not page.locator("#start").is_enabled() and time.time() < end:
                time.sleep(0.2)
            page.click("#start")
            page.wait_for_selector("#result:not([hidden]), #error:not([hidden])", timeout=300000)
            kind = page.get_attribute("#verdict", "data-kind")
            print("{:<9} ready {:>5.1f}s  seal={}  planted backup -> {}".format(name, time.time() - t0, seal, kind))
            if seal != "sealed":
                failures.append(name + ": worker not sealed (check the worker.js policy header)")
            if kind != "found":
                failures.append(name + ": planted backup gave " + str(kind))
            for e in errors:
                print("   pageerror:", e[:300])
            browser.close()
    print("RESULT:", "PASS" if not failures else failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], os.path.abspath(sys.argv[2])))
