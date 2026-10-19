"""Deliberately vulnerable local lab app - the ONLY sanctioned scan target.

Run it, point glassbox at it, watch findings appear:

    python lab/mock_app.py            # serves on http://127.0.0.1:8888

Why this exists: a recon tool needs a reproducible target to demonstrate
against, and scanning random internet hosts is both impolite and out of scope.
Everything this app "leaks" is fake by construction - the credentials below
are strings shaped like real ones so the scanner proves it can find them, but
they were never valid anywhere.

Bound to 127.0.0.1 only: this server refuses to be reached from another machine.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = 8888

# Fake credentials planted for the scanner demo. Not real, never were.
FAKE_AWS_KEY = "AKIA" + "DEMOFAKEKEY12345"  # matches secret.aws.access_key_id shape
FAKE_GH_PAT = "ghp_" + "DemoOnly1234567890123456789012345678"
FAKE_PASSWORD_LINE = 'password = "lab-demo-not-a-real-secret"'

PAGE = """<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>Glassbox Lab</title>
<!-- no CSP header on purpose: the audit should flag this page -->
</head>
<body>
  <h1>Glassbox Lab - intentionally vulnerable</h1>
  <p>Authorized local testing only. Every secret below is fake.</p>
  <ul>
    <li><a href="/search?q=glassbox&page=1">search (reflected param)</a></li>
    <li><a href="/login">login (no HttpOnly cookie)</a></li>
    <li><a href="/debug">debug (leaks fake secrets)</a></li>
    <li><a href="/admin">admin (403 but exists)</a></li>
    <li><a href="/backup.zip">backup.zip (200 - juicy hit)</a></li>
  </ul>
</body>
</html>
"""


class LabHandler(BaseHTTPRequestHandler):
    """Four routes, each demonstrating one class of finding."""

    server_version = "GlassboxLab/0.1"  # version disclosure on purpose

    def _send(
        self,
        status: int,
        body: str,
        content_type: str = "text/html; charset=utf-8",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        # Missing: HSTS, CSP, X-Content-Type-Options, X-Frame-Options (on purpose).
        self.send_header("Set-Cookie", "sessionid=labsession123; Path=/")  # no Secure, no HttpOnly
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802 - http.server API
        parsed = urlparse(self.path)
        route = parsed.path.rstrip("/") or "/"

        if route == "/":
            self._send(200, PAGE)
        elif route == "/search":
            query = parse_qs(parsed.query)
            term = (query.get("q") or [""])[0]
            page = (query.get("page") or ["1"])[0]
            # Reflected without encoding: XSS demo (safe, it's your own browser).
            self._send(200, f"<p>Results for {term} (page {page})</p>")
        elif route == "/login":
            self._send(200, "<form method='post'><input name='user'></form>")
        elif route == "/debug":
            self._send(
                200,
                f"<pre>aws_key={FAKE_AWS_KEY}\ngithub_token={FAKE_GH_PAT}\n{FAKE_PASSWORD_LINE}</pre>",
            )
        elif route == "/admin":
            self._send(403, "<p>forbidden</p>")
        elif route == "/backup.zip":
            self._send(200, "PK\x03\x04 fake zip bytes", content_type="application/zip")
        else:
            self._send(404, "<p>not found</p>")

    def log_message(self, fmt: str, *args: object) -> None:
        """Print one concise line per request - visible, but not a log file."""
        print(f"[lab] {self.address_string()} {fmt % args}")


def main() -> None:
    server = ThreadingHTTPServer((HOST, PORT), LabHandler)
    print(f"Glassbox lab listening on http://{HOST}:{PORT} (Ctrl+C to stop)")
    print("Authorized local testing target only - do not expose this port.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping lab")
        server.server_close()


if __name__ == "__main__":
    main()
