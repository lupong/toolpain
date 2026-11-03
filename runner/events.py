"""Event sinks: how the runner reports progress (control plane over HTTP, or nowhere)."""

from __future__ import annotations

import logging
from typing import Any, Protocol

import httpx

log = logging.getLogger("toolpain.runner")


class EventSink(Protocol):
    async def emit(
        self,
        stage: str,
        msg: str,
        level: str = "info",
        data: dict[str, Any] | None = None,
    ) -> None: ...

    async def report(self, report: dict[str, Any]) -> None: ...


class NullSink:
    """Collects events in memory; used when no control plane is configured."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []
        self.reports: list[dict[str, Any]] = []

    async def emit(
        self,
        stage: str,
        msg: str,
        level: str = "info",
        data: dict[str, Any] | None = None,
    ) -> None:
        self.events.append({"stage": stage, "level": level, "msg": msg, "data": data or {}})
        log.info("[%s] %s", stage, msg)

    async def report(self, report: dict[str, Any]) -> None:
        self.reports.append(report)


class HttpSink(NullSink):
    """Posts events and the final report to the control plane (``X-Scan-Token`` auth)."""

    def __init__(
        self,
        base_url: str,
        scan_id: str,
        token: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        super().__init__()
        self.base_url = base_url.rstrip("/")
        self.scan_id = scan_id
        self._headers = {"X-Scan-Token": token}
        self._client = client or httpx.AsyncClient(timeout=10)
        self._owns_client = client is None

    async def _post(self, path: str, body: dict[str, Any]) -> None:
        url = f"{self.base_url}/internal/scans/{self.scan_id}/{path}"
        try:
            resp = await self._client.post(url, json=body, headers=self._headers)
            resp.raise_for_status()
        except httpx.HTTPError as exc:  # never let reporting failures kill a scan
            log.warning("control plane post to %s failed: %s", path, exc)

    async def emit(
        self,
        stage: str,
        msg: str,
        level: str = "info",
        data: dict[str, Any] | None = None,
    ) -> None:
        await super().emit(stage, msg, level, data)
        await self._post("events", {"stage": stage, "level": level, "msg": msg, "data": data or {}})

    async def report(self, report: dict[str, Any]) -> None:
        await super().report(report)
        await self._post("report", report)

    async def aclose(self) -> None:
        if self._owns_client:
            await self._client.aclose()
