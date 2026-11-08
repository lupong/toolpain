"""Typed scan failures. The code is the control plane's error panel key."""

from __future__ import annotations

from runner.build import BuildError
from runner.fetch import FetchError
from runner.launch_plan import LaunchError


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


def classify_build_or_launch(exc: BaseException) -> ScanFailure:
    """Map sandbox build/launch failures onto control-plane error panels."""
    if isinstance(exc, ScanFailure):
        return exc
    if isinstance(exc, LaunchError):
        return ScanFailure("launch_failed", str(exc))
    text = str(exc).lower()
    if isinstance(exc, BuildError) and (
        "spoke mcp" in text or "mcp initialize" in text or "launch candidate" in text
    ):
        return ScanFailure("launch_failed", str(exc))
    if isinstance(exc, BuildError):
        return ScanFailure("build_failed", str(exc))
    return ScanFailure("internal", str(exc))


def ensure_launchable(
    language: str,
    server_cmd: list[str] | None,
    *,
    manifests: list[str] | None = None,
) -> None:
    """Refuse an empty tree. Manifests like go.mod are enough; codegen builds them."""
    if server_cmd:
        return
    if language != "unknown":
        return
    if manifests:
        return
    raise ScanFailure(
        "no_mcp_server",
        "No MCP server detected and no server_cmd was provided. Tried: (none)",
    )
