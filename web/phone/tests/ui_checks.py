"""Behaviour checks for the phone check page, with screenshots for review.

    python web/phone/tests/ui_checks.py FIXTURES_DIR SHOTS_DIR

1. Stop during an encrypted unlock ends the worker, restarts the checker, and
   a following check still works.
2. A result in Arabic is translated and laid out right to left.
3. Served WITHOUT the security headers, the page says the extra lock is
   missing (it must never claim "sealed" when it is not).
4. Screenshots of the main states at desktop and phone widths.
"""
import functools
import http.server
import os
import sys
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import serve  # noqa: E402

DIST = os.path.join(os.path.dirname(HERE), "dist")


def server(csp):
    handler = functools.partial(serve.Handler, directory=DIST, log=None, csp=csp)
    s = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s, "http://127.0.0.1:{}/index.html".format(s.server_address[1])


def wait_until(test, timeout=120):
    end = time.time() + timeout
    while time.time() < end:
        if test():
            return True
        time.sleep(0.2)
    raise TimeoutError("condition not met")


def ready(page):
    page.wait_for_selector('#seal:not([data-state="pending"])', timeout=300000)


def pick(page, folder):
    page.set_input_files("#folder-input", folder)
    wait_until(lambda: page.locator("#start").is_enabled())


def main(fixtures, shots):
    os.makedirs(shots, exist_ok=True)
    from playwright.sync_api import sync_playwright
    failures = []
    s, url = server(True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 900}, accept_downloads=True)
        page.goto(url)
        ready(page)
        page.screenshot(path=os.path.join(shots, "01-start-desktop.png"), full_page=True)

        # 1. Stop during the encrypted unlock, then check again.
        pick(page, os.path.join(fixtures, "large-hit"))
        page.click("#start")
        page.wait_for_selector("#stop", state="visible", timeout=10000)
        page.screenshot(path=os.path.join(shots, "02-progress.png"), full_page=False)
        page.click("#stop", timeout=5000)
        if not page.locator("#result").is_hidden():
            failures.append("a result appeared after Stop")
        ready(page)
        wait_until(lambda: page.locator("#loader").is_hidden())
        pick(page, os.path.join(fixtures, "plain-hit"))
        page.click("#start")
        page.wait_for_selector("#result:not([hidden])", timeout=120000)
        kind = page.get_attribute("#verdict", "data-kind")
        print("stop then check again:", kind)
        if kind != "found":
            failures.append("check after Stop gave " + str(kind))
        page.screenshot(path=os.path.join(shots, "03-result-found.png"), full_page=True)

        # Green result.
        page.click("#again")
        pick(page, os.path.join(fixtures, "plain-clean"))
        page.click("#start")
        page.wait_for_selector("#result:not([hidden])", timeout=120000)
        page.screenshot(path=os.path.join(shots, "04-result-clean.png"), full_page=True)

        # Wrong password: never green.
        page.click("#again")
        pick(page, os.path.join(fixtures, "encrypted-hit"))
        page.fill("#password", "wrong")
        page.click("#start")
        page.wait_for_selector("#result:not([hidden])", timeout=120000)
        page.screenshot(path=os.path.join(shots, "05-result-wrong-password.png"), full_page=True)

        # 2. Arabic.
        page.click("#again")
        pick(page, os.path.join(fixtures, "plain-hit"))
        page.select_option("#lang", "ar")
        page.click("#start")
        page.wait_for_selector("#result:not([hidden])", timeout=120000)
        direction = page.get_attribute("#result", "dir")
        title = page.locator("#verdict-title").inner_text()
        print("arabic:", direction, title)
        if direction != "rtl" or not any("؀" <= c <= "ۿ" for c in title):
            failures.append("Arabic result not translated/right-to-left: {} {!r}".format(direction, title))
        page.screenshot(path=os.path.join(shots, "06-result-arabic.png"), full_page=True)

        # Cellebrite headline.
        page.click("#again")
        pick(page, os.path.join(fixtures, "android-cellebrite"))
        page.select_option("#lang", "en")
        page.click("#start")
        page.wait_for_selector("#result:not([hidden])", timeout=120000)
        page.screenshot(path=os.path.join(shots, "07-result-cellebrite.png"), full_page=True)

        # Phone width (the page tells people to use a computer).
        mobile = browser.new_page(viewport={"width": 390, "height": 844}, is_mobile=True, has_touch=True,
                                  user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 18_6 like Mac OS X) "
                                             "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Mobile/15E148 Safari/604.1")
        mobile.goto(url)
        ready(mobile)
        if mobile.locator("#mobile-note").is_hidden():
            failures.append("phone visitor not told to use a computer")
        mobile.screenshot(path=os.path.join(shots, "08-phone-width.png"), full_page=True)
        browser.close()
    s.shutdown()

    # 3. Without the headers the page must not claim to be sealed.
    s, url = server(False)
    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        page = browser.new_page(viewport={"width": 1280, "height": 900})
        page.goto(url)
        ready(page)
        state = page.get_attribute("#seal", "data-state")
        print("served without headers, seal state:", state)
        if state != "open":
            failures.append("page claimed '{}' without the security headers".format(state))
        page.locator("#seal").screenshot(path=os.path.join(shots, "09-unsealed-warning.png"))
        browser.close()
    s.shutdown()
    print("RESULT:", "PASS" if not failures else failures)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])))
