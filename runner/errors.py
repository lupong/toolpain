"""Typed scan failures. The code is the control plane's error panel key."""

from __future__ import annotations

from runner.fetch import FetchError


class ScanFailure(Exception):
    def __init__(self, code: str, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(detail)


def classify_fetch(exc: FetchError) -> ScanFailure:
    text = str(exc).lower()
    if "invalid git ref" in text or "couldn't find remote ref" in text or "remote branch" in text:
        return ScanFailure("ref_missing", str(exc))
    if "unsupported repo" in text:
        return ScanFailure("invalid_repo", str(exc))
    return ScanFailure("repo_unavailable", str(exc))


def ensure_launchable(language: str, server_cmd: list[str] | None) -> None:
    """A tree with no detected language and no override cannot be probed."""
    if server_cmd:
        return
    if language != "unknown":
        return
    raise ScanFailure(
        "no_mcp_server",
        "No MCP server detected and no server_cmd was provided. Tried: (none)",
    )
