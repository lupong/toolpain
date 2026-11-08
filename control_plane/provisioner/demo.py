"""DemoProvisioner: replays a paced demo and the report for that demo.

Default pacing is about 35–40 seconds so the containment story can be read.
Tests pass ``delay_sec`` to sleep a fixed short interval per beat instead.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import Any

from control_plane.provisioner.base import Provisioner
from control_plane.sample_report import report_for_demo

# (stage, level, msg, data, seconds) — seconds used only when delay_sec is None.
Beat = tuple[str, str, str, dict[str, Any], float]


class DemoProvisioner(Provisioner):
    def __init__(
        self,
        emit_event: Callable[..., Any] | None = None,
        save_report: Callable[..., Any] | None = None,
        update_scan: Callable[..., Any] | None = None,
        delay_sec: float | None = None,
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
        task = asyncio.create_task(self._run(scan_id, repo_url, ref, demo=kwargs.get("demo")))
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

    async def _run(
        self,
        scan_id: str,
        repo_url: str,
        ref: str,
        demo: str | None = None,
    ) -> None:
        try:
            if self._update_scan:
                await _maybe_await(self._update_scan(scan_id, status="running"))
            report = report_for_demo(demo, scan_id, repo_url)
            for stage, level, msg, data, seconds in _beats(report, repo_url, ref):
                if self._emit:
                    await _maybe_await(self._emit(scan_id, stage, level, msg, data))
                await asyncio.sleep(self._delay if self._delay is not None else seconds)

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


def _beats(report: dict[str, Any], repo_url: str, ref: str) -> list[Beat]:
    repo = repo_url.removeprefix("https://github.com/")
    tools = list(report.get("tools") or [])
    names = [t["name"] for t in tools]
    decoys = 4
    stage = 2.5
    beats: list[Beat] = [
        ("intake", "info", f"Accepted {repo} @ {ref}", {"ref": ref}, stage),
        (
            "provision",
            "info",
            f"Instance toolpain-scan requested for {repo}",
            {},
            stage,
        ),
        (
            "provision",
            "info",
            "Instance ready · firewall group: no inbound",
            {},
            stage,
        ),
        ("fetch", "info", f"Cloned {repo}", {"ref": ref}, stage),
        ("build", "info", "Run image committed", {}, stage),
        (
            "isolate",
            "info",
            "Network blocked · internal only · DNS sinkholed",
            {"network": "blocked", "decoys": decoys},
            stage,
        ),
        (
            "isolate",
            "info",
            f"{decoys} decoys planted (file, .env, cookie, localStorage)",
            {"decoys": decoys, "network": "blocked"},
            stage,
        ),
        (
            "discover",
            "info",
            f"{len(names)} tools discovered",
            {
                "tools": [
                    {
                        "name": t["name"],
                        "sources": t.get("sources") or [],
                        "status": "queued",
                    }
                    for t in tools
                ]
            },
            stage,
        ),
        ("research", "info", f"Profiles ready for {len(names)} tools", {}, stage),
    ]
    decoy_reads = int((report.get("stats") or {}).get("decoy_reads") or 0)
    for tool in tools:
        verdict = str(tool.get("verdict") or "confirmed")
        tool_decoys = int(tool.get("decoy_reads") or 0)
        level = "alert" if decoy_reads > 0 and tool_decoys > 0 else "info"
        data: dict[str, Any] = {
            "tool": tool["name"],
            "verdict": verdict,
            "sources": list(tool.get("sources") or []),
            "status": verdict,
        }
        if level == "alert":
            hosts = tool.get("egress") or []
            if hosts:
                data["host"] = hosts[0]
        beats.append(("probe", level, f"{tool['name']} → {verdict}", data, 0.8))
    if report.get("verdict") == "clean":
        beats.append(("analyze", "info", "No decoy reads and no undeclared hosts", {}, stage))
    else:
        beats.append(("analyze", "info", "Analysis complete", {}, stage))
    beats.append(("report", "info", "Report assembled", {}, stage))
    beats.append(("destroy", "info", "Environment destroyed", {}, stage))
    return beats


async def _maybe_await(result: Any) -> Any:
    if asyncio.iscoroutine(result):
        return await result
    return result
