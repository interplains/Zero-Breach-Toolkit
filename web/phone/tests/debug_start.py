"""Load the page in one browser and print what happens during start-up (debug aid).

    python web/phone/tests/debug_start.py [chromium|firefox|webkit] [seconds] [--no-csp]
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

name = sys.argv[1] if len(sys.argv) > 1 else "chromium"
seconds = int(sys.argv[2]) if len(sys.argv) > 2 else 60
csp = "--no-csp" not in sys.argv
handler = functools.partial(serve.Handler, directory=os.path.join(os.path.dirname(HERE), "dist"),
                            log=None, csp=csp)
server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
threading.Thread(target=server.serve_forever, daemon=True).start()
from playwright.sync_api import sync_playwright  # noqa: E402
with sync_playwright() as pw:
    browser = getattr(pw, name).launch()
    page = browser.new_page()
    page.on("console", lambda m: print("console.{}: {}".format(m.type, m.text[:500])))
    page.on("pageerror", lambda e: print("pageerror:", str(e)[:500]))
    page.on("worker", lambda w: print("worker started:", w.url))
    page.goto("http://127.0.0.1:{}/index.html".format(server.server_address[1]))
    end = time.time() + seconds
    last = None
    while time.time() < end:
        now = (page.locator("#loader-text").inner_text(), page.get_attribute("#seal", "data-state"),
               page.locator("#error-text").inner_text())
        if now != last:
            print(round(time.time() - end + seconds, 1), now)
            last = now
        if now[1] != "pending" or now[2]:
            break
        time.sleep(0.5)
    browser.close()
server.shutdown()
