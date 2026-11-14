"""Serve web/phone/dist locally with the security headers production must send.

    python web/phone/tests/serve.py [--port 8771] [--dir web/phone/dist] [--log FILE] [--no-csp]

Every request is appended to --log as "METHOD PATH", so a test can show that no
request reached the server while a check ran. A request for seal-probe.txt is
logged as SEAL-PROBE-REACHED-SERVER: with the headers on, it must never appear.

The two policies (the deployment must send the same):
  page and its scripts: PAGE_CSP
  worker.js:            WORKER_CSP  (no connect-src, so every connection is refused)
"""
import argparse
import functools
import http.server
import os
import threading

PAGE_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
            "connect-src 'self'; worker-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
WORKER_CSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'"
LOCK = threading.Lock()


class Handler(http.server.SimpleHTTPRequestHandler):
    extensions_map = dict(http.server.SimpleHTTPRequestHandler.extensions_map, **{
        ".mjs": "text/javascript", ".js": "text/javascript", ".wasm": "application/wasm",
        ".json": "application/json", ".whl": "application/zip", ".zip": "application/zip"})

    def __init__(self, *a, log=None, csp=True, **k):
        self._log, self._csp = log, csp
        super().__init__(*a, **k)

    def log_message(self, *_a):
        pass

    def _record(self):
        path = self.path.split("?")[0]
        line = "{} {}".format(self.command, path)
        if path.endswith("seal-probe.txt"):
            line = "SEAL-PROBE-REACHED-SERVER " + line
        if self._log:
            with LOCK, open(self._log, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def do_GET(self):
        self._record()
        super().do_GET()

    def end_headers(self):
        if self._csp:
            path = self.path.split("?")[0]
            self.send_header("Content-Security-Policy", WORKER_CSP if path.endswith("/worker.js") else PAGE_CSP)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        super().end_headers()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--port", type=int, default=8771)
    p.add_argument("--dir", default=os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "dist"))
    p.add_argument("--log")
    p.add_argument("--no-csp", action="store_true")
    a = p.parse_args()
    handler = functools.partial(Handler, directory=a.dir, log=a.log, csp=not a.no_csp)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", a.port), handler)
    print("serving", a.dir, "on http://127.0.0.1:{}/".format(a.port), flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
