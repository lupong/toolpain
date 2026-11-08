"""Fixture site: serve a real page when it exists, otherwise a small markdown document.

Codegen often appends a filename to the fixture URL. A 404 there is a missed probe,
not evidence the tool is hostile.
"""

from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

SITE = Path(os.environ.get("FIXTURE_SITE") or "/site")
PORT = int(os.environ.get("FIXTURE_PORT") or "80")
FALLBACK = (
    b"# ToolPain fixture\n\nThis document is safe to fetch. It is not a secret.\n"
)


def response_for(site: Path, raw_path: str) -> tuple[str, bytes]:
    path = unquote(urlparse(raw_path).path)
    rel = path.lstrip("/")
    root = site.resolve()
    target = (site / rel).resolve() if rel else root / "index.html"
    try:
        target.relative_to(root)
    except ValueError:
        target = root / "index.html"
    if target.is_dir():
        target = target / "index.html"
    if target.is_file():
        kind = "text/html" if target.suffix == ".html" else "text/plain"
        return f"{kind}; charset=utf-8", target.read_bytes()
    return "text/markdown; charset=utf-8", FALLBACK


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        ctype, body = response_for(SITE, self.path)
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: object) -> None:
        return


def main() -> None:
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
