"""FakeProvisioner: replays scripted stage events and the sample report."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from control_plane.provisioner.base import Provisioner
from control_plane.sample_report import sample_report

STAGES = [
    ("intake", "Scan accepted"),
    ("provision", "Fake VM ready (no cloud call)"),
    ("fetch", "Cloned repository"),
    ("build", "Built run image"),
    ("isolate", "Internal network + sinkhole + decoys planted"),
    ("discover", "Discovered tools from D/S/R/F sources"),
    ("research", "LLM profiles complete (fake mode)"),
    ("probe", "Probed tools; contained undeclared egress"),
    ("analyze", "Analysis complete"),
    ("report", "Report assembled"),
    ("destroy", "Environment destroyed"),
]


class FakeProvisioner(Provisioner):
    def __init__(
        self,
        emit_event: Callable[..., Any] | None = None,
        save_report: Callable[..., Any] | None = None,
        update_scan: Callable[..., Any] | None = None,
        delay_sec: float = 0.15,
        **_kwargs: Any,
    ) -> None:
        self._emit = emit_event
        self._save_report = save_report
        self._update_scan = update_scan
        self._delay = delay_sec
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
        task = asyncio.create_task(self._run(scan_id, repo_url, ref))
        self._tasks[scan_id] = task

    async def cancel_scan(self, scan_id: str) -> None:
        task = self._tasks.pop(scan_id, None)
        if task and not task.done():
            task.cancel()
        self.pop_byo_key(scan_id)
        if self._emit:
            await _maybe_await(
                self._emit(scan_id, "destroy", "warn", "Scan cancelled; environment destroyed")
            )
        if self._update_scan:
            await _maybe_await(self._update_scan(scan_id, status="cancelled"))

    async def _run(self, scan_id: str, repo_url: str, ref: str) -> None:
        try:
            if self._update_scan:
                await _maybe_await(self._update_scan(scan_id, status="running"))
            for stage, msg in STAGES:
                if self._emit:
                    level = "info"
                    if stage == "probe":
                        level = "alert"
                        msg = (
                            "Flagged: fetch_report read the planted decoy and tried "
                            "an undeclared host collector.sinkhole.local. Contained."
                        )
                    await _maybe_await(self._emit(scan_id, stage, level, msg, {"ref": ref}))
                await asyncio.sleep(self._delay)

            report = sample_report(scan_id, repo_url)
            if self._save_report:
                await _maybe_await(self._save_report(scan_id, report))
            if self._update_scan:
                await _maybe_await(
                    self._update_scan(
                        scan_id,
                        status="done",
                        verdict=report["verdict"],
                        findings_count=len(report.get("findings", [])),
                    )
                )
        except asyncio.CancelledError:
            raise
        finally:
            self.pop_byo_key(scan_id)
            self._tasks.pop(scan_id, None)


async def _maybe_await(result: Any) -> Any:
    if asyncio.iscoroutine(result):
        return await result
    return result
