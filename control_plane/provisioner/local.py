"""LocalProvisioner: runs the runner against the sandbox on this machine."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any

from control_plane.provisioner.base import Provisioner

log = logging.getLogger("toolpain.local")


def _failure_kind(exc: BaseException) -> tuple[str, str]:
    """Map a runner exception to an error-card id and the stage that failed."""
    msg = str(exc).lower()
    name = type(exc).__name__
    if "401" in msg or "api key" in msg or "unauthorized" in msg:
        return "key", "provision"
    if name == "BuildError" or "docker build" in msg or "npm" in msg:
        return "build", "build"
    if name == "FetchError":
        if "unsupported repo url" in msg or "invalid git ref" in msg:
            return "invalid", "fetch"
        return "private", "fetch"
    if "vultr" in msg or "instance" in msg or name == "TimeoutError":
        return "vm", "provision"
    return "failed", "analyze"


REPO_ROOT = Path(__file__).resolve().parents[2]
DEMO_PATHS = {
    "decoy-trap-server": REPO_ROOT / "demo" / "decoy-trap-server",
}


class LocalProvisioner(Provisioner):
    def __init__(
        self,
        emit_event: Callable[..., Any] | None = None,
        save_report: Callable[..., Any] | None = None,
        update_scan: Callable[..., Any] | None = None,
        control_plane_url: str = "http://127.0.0.1:8000",
        **_kwargs: Any,
    ) -> None:
        self._emit = emit_event
        self._save_report = save_report
        self._update_scan = update_scan
        self._control_plane_url = control_plane_url
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._byo_keys: dict[str, str] = {}

    def store_byo_key(self, scan_id: str, key: str) -> None:
        self._byo_keys[scan_id] = key

    def pop_byo_key(self, scan_id: str) -> str | None:
        return self._byo_keys.pop(scan_id, None)

    async def start_scan(
        self,
        scan_id: str,
        repo_url: str,
        ref: str,
        token: str,
        **kwargs: Any,
    ) -> None:
        byo = kwargs.get("byo_vultr_key")
        if byo:
            self.store_byo_key(scan_id, byo)
        task = asyncio.create_task(
            self._run(
                scan_id,
                repo_url,
                ref,
                token,
                demo=kwargs.get("demo"),
                prefer_subdir=kwargs.get("prefer_subdir"),
                scan_brief=kwargs.get("scan_brief"),
                protocol=kwargs.get("protocol") or "auto",
                upstream_url=kwargs.get("upstream_url"),
                mcp_url=kwargs.get("mcp_url"),
            )
        )
        self._tasks[scan_id] = task

    async def cancel_scan(self, scan_id: str) -> None:
        task = self._tasks.pop(scan_id, None)
        if task and not task.done():
            task.cancel()
        self.pop_byo_key(scan_id)

    async def _run(
        self,
        scan_id: str,
        repo_url: str,
        ref: str,
        token: str,
        *,
        demo: str | None = None,
        prefer_subdir: str | None = None,
        scan_brief: str | None = None,
        protocol: str = "auto",
        upstream_url: str | None = None,
        mcp_url: str | None = None,
    ) -> None:
        try:
            if self._update_scan:
                result = self._update_scan(scan_id, status="running")
                if asyncio.iscoroutine(result):
                    await result
            from runner.main import run_scan

            local_path = DEMO_PATHS.get(demo) if demo else None
            if prefer_subdir is None and demo == "server-filesystem":
                prefer_subdir = "src/filesystem"
            # local_path=None → packaged fetch/build/launch against repo_url
            report = await asyncio.to_thread(
                run_scan,
                scan_id=scan_id,
                repo_url=repo_url,
                ref=ref,
                token=token,
                control_plane_url=self._control_plane_url,
                local_path=local_path,
                sandbox="auto",
                prefer_subdir=prefer_subdir,
                scan_brief=scan_brief,
                protocol=protocol,
                upstream_url=upstream_url,
                mcp_url=mcp_url,
            )
            if self._save_report and report:
                result = self._save_report(scan_id, report)
                if asyncio.iscoroutine(result):
                    await result
            if self._update_scan and report:
                result = self._update_scan(
                    scan_id,
                    status="done",
                    verdict=report.get("verdict"),
                    findings_count=len(report.get("findings", [])),
                )
                if asyncio.iscoroutine(result):
                    await result
        except Exception as exc:
            log.exception("local scan failed: %s", exc)
            kind, stage = _failure_kind(exc)
            if self._emit:
                result = self._emit(
                    scan_id,
                    stage,
                    "alert",
                    f"Scan failed: {exc}",
                    {"error": kind, "detail": str(exc)[:800]},
                )
                if asyncio.iscoroutine(result):
                    await result
            if self._update_scan:
                result = self._update_scan(scan_id, status="failed")
                if asyncio.iscoroutine(result):
                    await result
        finally:
            self.pop_byo_key(scan_id)
            self._tasks.pop(scan_id, None)
