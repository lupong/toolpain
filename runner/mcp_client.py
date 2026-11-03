"""Thin async wrapper over the official ``mcp`` SDK (v2) for stdio servers.

Targets are always launched via a stdio command supplied by the caller (a ``docker run -i``
command from the sandbox in production). This module never decides *what* to execute.
"""

from __future__ import annotations

import tempfile
import time
from contextlib import AsyncExitStack
from types import TracebackType
from typing import Any, TextIO

import anyio
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client

from runner.models import (
    CallOutcome,
    PromptInfo,
    ResourceInfo,
    ServerSnapshot,
    ToolInfo,
)

DEFAULT_INIT_TIMEOUT = 60.0
DEFAULT_CALL_TIMEOUT = 30.0
MAX_PAGES = 20
MAX_TEXT = 4000


class McpClientError(RuntimeError):
    """Raised when the server cannot be started or initialised."""


def _field(obj: Any, snake: str, camel: str, default: Any = None) -> Any:
    """Read an attribute that is snake_case in mcp 2.x and camelCase in 1.x."""
    if hasattr(obj, snake):
        return getattr(obj, snake)
    return getattr(obj, camel, default)


def _tool_info(tool: types.Tool) -> ToolInfo:
    annotations = getattr(tool, "annotations", None)
    return ToolInfo(
        name=tool.name,
        description=tool.description or "",
        input_schema=dict(_field(tool, "input_schema", "inputSchema", {}) or {}),
        annotations=annotations.model_dump(exclude_none=True) if annotations else None,
    )


def _result_text(result: types.CallToolResult) -> str:
    parts = [c.text for c in result.content if isinstance(c, types.TextContent)]
    return "\n".join(parts)[:MAX_TEXT]


class McpClient:
    """Async context manager: spawn a stdio MCP server, initialise, expose helpers."""

    def __init__(
        self,
        params: StdioServerParameters,
        *,
        init_timeout: float = DEFAULT_INIT_TIMEOUT,
        call_timeout: float = DEFAULT_CALL_TIMEOUT,
    ) -> None:
        self.params = params
        self.init_timeout = init_timeout
        self.call_timeout = call_timeout
        self.server_name = ""
        self.server_version = ""
        self.instructions: str | None = None
        self._stack = AsyncExitStack()
        self._session: ClientSession | None = None
        self._errlog: TextIO | None = None

    async def __aenter__(self) -> McpClient:
        self._errlog = tempfile.TemporaryFile("w+", encoding="utf-8")  # noqa: SIM115
        try:
            read, write = await self._stack.enter_async_context(
                stdio_client(self.params, errlog=self._errlog)
            )
            session = await self._stack.enter_async_context(ClientSession(read, write))
            with anyio.fail_after(self.init_timeout):
                init = await session.initialize()
        except BaseException as exc:
            await self._stack.aclose()
            raise McpClientError(
                f"failed to start MCP server: {exc!r}; {self.stderr_tail()}"
            ) from exc
        self._session = session
        info = init.server_info
        self.server_name = info.name
        self.server_version = info.version or ""
        self.instructions = init.instructions
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        try:
            await self._stack.aclose()
        finally:
            if self._errlog is not None:
                self._errlog.close()

    @property
    def session(self) -> ClientSession:
        if self._session is None:
            raise McpClientError("client not started")
        return self._session

    def stderr_tail(self, limit: int = 800) -> str:
        if self._errlog is None or self._errlog.closed:
            return ""
        try:
            self._errlog.flush()
            self._errlog.seek(0)
            return self._errlog.read()[-limit:]
        except (OSError, ValueError):
            return ""

    async def list_tools(self) -> list[ToolInfo]:
        tools: list[ToolInfo] = []
        cursor: str | None = None
        for _ in range(MAX_PAGES):
            params = types.PaginatedRequestParams(cursor=cursor) if cursor else None
            with anyio.fail_after(self.call_timeout):
                result = await self.session.list_tools(params=params)
            tools.extend(_tool_info(t) for t in result.tools)
            cursor = _field(result, "next_cursor", "nextCursor")
            if not cursor:
                break
        return tools

    async def list_resources(self) -> list[ResourceInfo]:
        try:
            with anyio.fail_after(self.call_timeout):
                result = await self.session.list_resources()
        except Exception:  # capability may be absent
            return []
        return [
            ResourceInfo(uri=str(r.uri), name=r.name or "", description=r.description or "")
            for r in result.resources
        ]

    async def list_prompts(self) -> list[PromptInfo]:
        try:
            with anyio.fail_after(self.call_timeout):
                result = await self.session.list_prompts()
        except Exception:
            return []
        return [PromptInfo(name=p.name, description=p.description or "") for p in result.prompts]

    async def snapshot(self) -> ServerSnapshot:
        return ServerSnapshot(
            server_name=self.server_name,
            server_version=self.server_version,
            instructions=self.instructions,
            tools=await self.list_tools(),
            resources=await self.list_resources(),
            prompts=await self.list_prompts(),
        )

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any] | None = None,
        *,
        timeout: float | None = None,
    ) -> CallOutcome:
        args = dict(arguments or {})
        limit = timeout or self.call_timeout
        start = time.time()
        try:
            with anyio.fail_after(limit):
                result = await self.session.call_tool(name, args, read_timeout_seconds=limit)
        except TimeoutError:
            return CallOutcome(
                tool=name,
                arguments=args,
                ok=False,
                timed_out=True,
                error=f"timeout after {limit}s",
                start=start,
                end=time.time(),
            )
        except Exception as exc:  # protocol-level error (e.g. invalid params)
            return CallOutcome(
                tool=name,
                arguments=args,
                ok=False,
                is_error=True,
                error=str(exc),
                start=start,
                end=time.time(),
            )
        assert isinstance(result, types.CallToolResult)
        text = _result_text(result)
        return CallOutcome(
            tool=name,
            arguments=args,
            ok=not result.is_error,
            is_error=bool(result.is_error),
            text=text,
            error=text if result.is_error else None,
            start=start,
            end=time.time(),
        )


async def snapshot_server(
    params: StdioServerParameters, *, init_timeout: float = DEFAULT_INIT_TIMEOUT
) -> ServerSnapshot:
    """Start a server, list everything it advertises, shut it down."""
    async with McpClient(params, init_timeout=init_timeout) as client:
        return await client.snapshot()
