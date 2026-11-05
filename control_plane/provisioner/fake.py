"""FakeProvisioner: replays a paced demo and the report for that demo.

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


class FakeProvisioner(Provisioner):
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
    shown = tools[:6]
    decoys = 4
    beats: list[Beat] = [
        ("intake", "info", f"Accepted {repo} @ {ref}", {"ref": ref}, 1.5),
        (
            "provision",
            "info",
            f"Instance toolpain-scan requested for {repo}",
            {},
            3.5,
        ),
        (
            "provision",
            "info",
            "Instance ready · firewall group: no inbound",
            {},
            3.0,
        ),
        ("fetch", "info", f"Cloned {repo}", {"ref": ref}, 2.0),
        ("build", "info", "Run image committed", {}, 2.5),
        (
            "isolate",
            "info",
            "Network blocked · internal only · DNS sinkholed",
            {"network": "blocked", "decoys": decoys},
            3.5,
        ),
        (
            "isolate",
            "info",
            f"{decoys} decoys planted (file, .env, cookie, localStorage)",
            {"decoys": decoys, "network": "blocked"},
            2.5,
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
            2.0,
        ),
        ("research", "info", f"Profiles ready for {len(names)} tools", {}, 2.0),
    ]
    for tool in shown:
        verdict = tool.get("verdict") or "confirmed"
        level = "info"
        msg = f"{tool['name']} matched its claim"
        data: dict[str, Any] = {"tool": tool["name"], "status": verdict}
        seconds = 1.6
        if verdict == "flagged":
            level = "alert"
            host = (tool.get("egress") or ["an undeclared host"])[0]
            msg = f"{tool['name']} read the planted decoy and tried {host}. Contained."
            data["host"] = host
            seconds = 5.5
        elif verdict == "exceeds_claim":
            level = "warn"
            msg = f"{tool['name']} did more than its description allows"
            seconds = 2.2
        beats.append(("probe", level, msg, data, seconds))
    rest = len(names) - len(shown)
    if rest > 0:
        beats.append(("probe", "info", f"{rest} more tools probed · claims held", {}, 1.6))
    if report.get("verdict") == "clean":
        beats.append(
            (
                "analyze",
                "info",
                "No decoy reads and no undeclared hosts",
                {},
                2.0,
            )
        )
    else:
        beats.append(("analyze", "info", "Analysis complete", {}, 2.0))
    beats.append(("report", "info", "Report assembled", {}, 1.5))
    beats.append(("destroy", "info", "Environment destroyed", {}, 2.0))
    return beats


async def _maybe_await(result: Any) -> Any:
    if asyncio.iscoroutine(result):
        return await result
    return result
