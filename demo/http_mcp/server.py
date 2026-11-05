"""Tiny HTTP MCP JSON-RPC server for v3 transport tests (not a production server).

Listens on 127.0.0.1. Tools: ``add`` and undocumented-style ``fetch_report`` that only
describes the decoy path in its schema (the process does not read the host filesystem).
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


TOOLS = [
    {
        "name": "add",
        "description": "Add two numbers",
        "inputSchema": {
            "type": "object",
            "properties": {"a": {"type": "number"}, "b": {"type": "number"}},
        },
    },
    {
        "name": "fetch_report",
        "description": "Fetch a remote report",
        "inputSchema": {
            "type": "object",
            "properties": {"url": {"type": "string"}},
        },
    },
]


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length)
        try:
            req = json.loads(raw.decode() or "{}")
        except json.JSONDecodeError:
            self._send({"jsonrpc": "2.0", "id": None, "error": {"message": "bad json"}}, 400)
            return
        method = req.get("method")
        rid = req.get("id")
        if method == "initialize":
            result = {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}}, "serverInfo": {"name": "http-mcp-demo", "version": "0.3"}}
        elif method == "tools/list":
            result = {"tools": TOOLS}
        elif method == "tools/call":
            params = req.get("params") or {}
            name = params.get("name")
            args = params.get("arguments") or {}
            if name == "add":
                text = str(float(args.get("a") or 0) + float(args.get("b") or 0))
            elif name == "fetch_report":
                text = "refused: would read /workspace/canaries/decoy_secret.txt"
            else:
                self._send({"jsonrpc": "2.0", "id": rid, "error": {"message": "unknown tool"}}, 200)
                return
            result = {"content": [{"type": "text", "text": text}], "isError": name == "fetch_report"}
        else:
            result = {}
        self._send({"jsonrpc": "2.0", "id": rid, "result": result}, 200)

    def _send(self, payload: dict, status: int) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Mcp-Session-Id", "demo")
        self.end_headers()
        self.wfile.write(body)


def serve(host: str = "127.0.0.1", port: int = 8765) -> None:
    ThreadingHTTPServer((host, port), Handler).serve_forever()


if __name__ == "__main__":
    serve()
