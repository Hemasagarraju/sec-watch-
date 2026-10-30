"""A tiny, intentionally misconfigured HTTP training target bound to loopback only."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread


class _LabHandler(BaseHTTPRequestHandler):
    server_version = "SEC-WATCH-Training-Lab"
    sys_version = ""

    def do_GET(self) -> None:
        pages: dict[str, tuple[int, str, str]] = {
            "/": (
                200,
                "<h1>SEC WATCH local training lab</h1>"
                "<p>This demo intentionally omits common security headers.</p>"
                "<form action='/login' method='POST'>"
                "<label>Username: <input type='text' name='user'></label>"
                "<label>Password: <input type='password' name='password'></label>"
                "<button type='submit'>Sign in</button>"
                "</form>"
                "<p>Try the scanner's fixed directory and configuration checks.</p>",
                "text/html; charset=utf-8",
            ),
            "/admin/": (
                200,
                "<h1>Training admin placeholder</h1><p>No real accounts or data.</p>",
                "text/html; charset=utf-8",
            ),
            "/backup/": (
                403,
                "<h1>Forbidden</h1><p>Placeholder backup area.</p>",
                "text/html; charset=utf-8",
            ),
            "/uploads/": (
                200,
                "<h1>Index of /uploads/</h1><ul><li>sample-image.txt</li>"
                "<li>training-only-placeholder.txt</li></ul>",
                "text/html; charset=utf-8",
            ),
            "/.git/": (404, "<h1>Not found</h1>", "text/html; charset=utf-8"),
            "/.git/HEAD": (200, "ref: refs/heads/main\n", "text/plain; charset=utf-8"),
            "/.env": (
                200,
                "APP_ENV=local\nAPP_KEY=base64:demo_test_secret_key_12345\n"
                "DB_CONNECTION=mysql\nDB_HOST=127.0.0.1\nDB_DATABASE=lab_db\n"
                "DB_USERNAME=root\nDB_PASSWORD=training_lab_secret_db_pass\n",
                "text/plain; charset=utf-8",
            ),
            "/robots.txt": (
                200,
                "User-agent: *\nDisallow: /admin/\nDisallow: /backup/\n",
                "text/plain; charset=utf-8",
            ),
            "/server-status": (404, "<h1>Not found</h1>", "text/html; charset=utf-8"),
        }
        status, content, ctype = pages.get(
            self.path, (404, "<h1>Not found</h1>", "text/html; charset=utf-8")
        )
        if "html" in ctype:
            body = f"<!doctype html><html><body>{content}</body></html>".encode("utf-8")
        else:
            body = content.encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "PHP/8.2.1-dev (Training-Lab)")
        self.send_header("Set-Cookie", "lab_session=demo; Path=/")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Allow", "GET, HEAD, OPTIONS, TRACE")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return


class TrainingLab:
    """Manage a demo server that can only accept connections from this computer."""

    def __init__(self) -> None:
        self._server: ThreadingHTTPServer | None = None
        self._thread: Thread | None = None

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def url(self) -> str | None:
        if self._server is None:
            return None
        return f"http://127.0.0.1:{self._server.server_port}"

    def start(self) -> str:
        if self._server is not None:
            return self.url or ""
        server = ThreadingHTTPServer(("127.0.0.1", 0), _LabHandler)
        server.daemon_threads = True
        thread = Thread(target=server.serve_forever, name="sec-watch-training-lab", daemon=True)
        thread.start()
        self._server = server
        self._thread = thread
        return self.url or ""

    def stop(self) -> None:
        server, thread = self._server, self._thread
        self._server = None
        self._thread = None
        if server is not None:
            server.shutdown()
            server.server_close()
        if thread is not None:
            thread.join(timeout=2)
