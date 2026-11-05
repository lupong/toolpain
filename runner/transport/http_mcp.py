"""Minimal MCP JSON-RPC client over HTTP POST (streamable HTTP / SSE servers that accept POST).

Used when ``protocol`` is ``http`` or ``sse``. The server must already be listening;
ToolPain does not open host egress beyond the configured MCP URL.
"""

from __future__ import annotations

import json
from typing import Any

import httpx


class HttpMcpError(RuntimeError):
    pass


class HttpMcpClient:
    def __init__(self, url: str, *, timeout: float = 30.0) -> None:
        self.url = url.rstrip("/")
        self.timeout = timeout
        self._id = 0
        self._session: str | None = None

    def _next_id(self) -> int:
        self._id += 1
        return self._id

    async def _rpc(self, method: str, params: dict[str, Any] | None = None) -> Any:
        body: dict[str, Any] = {"jsonrpc": "2.0", "id": self._next_id(), "method": method}
        if params is not None:
            body["params"] = params
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self._session:
            headers["Mcp-Session-Id"] = self._session
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(self.url, json=body, headers=headers)
            resp.raise_for_status()
            sid = resp.headers.get("mcp-session-id") or resp.headers.get("Mcp-Session-Id")
            if sid:
                self._session = sid
            text = resp.text.strip()
            if text.startswith("event:") or "\ndata:" in text:
                data_lines = [ln[5:].strip() for ln in text.splitlines() if ln.startswith("data:")]
                text = data_lines[-1] if data_lines else "{}"
                payload = json.loads(text)
            else:
                payload = resp.json()
        if isinstance(payload, dict) and payload.get("error"):
            raise HttpMcpError(str(payload["error"]))
        return payload.get("result") if isinstance(payload, dict) else payload

    async def initialize(self) -> dict[str, Any]:
        result = await self._rpc(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "toolpain", "version": "0.3"},
            },
        )
        return result if isinstance(result, dict) else {}

    async def list_tools(self) -> list[dict[str, Any]]:
        await self.initialize()
        result = await self._rpc("tools/list", {})
        tools = (result or {}).get("tools") if isinstance(result, dict) else None
        return list(tools or [])

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = await self._rpc("tools/call", {"name": name, "arguments": arguments})
        return result if isinstance(result, dict) else {"raw": result}
