"""LocalProvisioner: runs the runner against the sandbox on this machine."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

from control_plane.provisioner.base import Provisioner

log = logging.getLogger("toolpain.local")


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
        task = asyncio.create_task(self._run(scan_id, repo_url, ref, token))
        self._tasks[scan_id] = task

    async def cancel_scan(self, scan_id: str) -> None:
        task = self._tasks.pop(scan_id, None)
        if task and not task.done():
            task.cancel()
        self.pop_byo_key(scan_id)

    async def _run(self, scan_id: str, repo_url: str, ref: str, token: str) -> None:
        try:
            if self._update_scan:
                result = self._update_scan(scan_id, status="running")
                if asyncio.iscoroutine(result):
                    await result
            from runner.main import run_scan

            report = await asyncio.to_thread(
                run_scan,
                scan_id=scan_id,
                repo_url=repo_url,
                ref=ref,
                token=token,
                control_plane_url=self._control_plane_url,
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
            if self._emit:
                result = self._emit(scan_id, "analyze", "alert", f"Scan failed: {exc}")
                if asyncio.iscoroutine(result):
                    await result
            if self._update_scan:
                result = self._update_scan(scan_id, status="failed")
                if asyncio.iscoroutine(result):
                    await result
        finally:
            self.pop_byo_key(scan_id)
            self._tasks.pop(scan_id, None)
