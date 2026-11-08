"""DemoSandbox: replays a recorded trace fixture so the pipeline runs without Docker.

It satisfies the same ``Sandbox`` protocol as :class:`sandbox.sandbox.DockerSandbox`. The
target server is run as a *local process* via ``runner.launch.local_launcher``, which only
accepts scripts under ``demo/`` (ToolPain's own demo server). When the runner reports a tool
call window through ``on_call_complete``, the fixture's strace lines and sinkhole records for
that tool are rendered inside the window and parsed with the real parser.
"""

from __future__ import annotations

import json
import re
import shutil
import tempfile
from collections.abc import Sequence
from pathlib import Path
from types import TracebackType
from typing import Any

from mcp import StdioServerParameters

from runner.launch import DECOY_SERVER, local_launcher
from sandbox.decoys import DecoySet, plant_decoys
from sandbox.models import SinkholeRecord, TraceEvent
from sandbox.trace import parse_strace_text

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
DECOY_TRAP_FIXTURE = FIXTURE_DIR / "decoy_trap.json"
_FRAC_RE = re.compile(r"^(\d+)\s+@(\d*\.?\d+)\s+(.*)$")


def load_fixture(path: Path = DECOY_TRAP_FIXTURE) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


class DemoSandbox:
    def __init__(
        self,
        scan_id: str = "demo",
        *,
        fixture: dict[str, Any] | None = None,
        script: Path = DECOY_SERVER,
        sinkhole_ip: str = "10.66.0.53",
    ) -> None:
        self.scan_id = scan_id
        self.fixture = fixture if fixture is not None else load_fixture()
        self.sinkhole_ip = sinkhole_ip
        self.fixture_url = "http://fixture.local/"
        self.settle_sec = 0.0
        self.network = f"tp_internal_{scan_id}"
        self._launch = local_launcher(script)
        self._events: list[TraceEvent] = []
        self._records: list[SinkholeRecord] = []
        self._root: Path | None = None
        self._started_at = 0.0
        self.decoys: DecoySet

    async def __aenter__(self) -> DemoSandbox:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.stop()

    async def start(self) -> None:
        self._root = Path(tempfile.mkdtemp(prefix=f"tp_demo_{self.scan_id}_"))
        self.decoys = plant_decoys(self._root / "workspace", self.scan_id)
        self._events, self._records = [], []

    async def stop(self) -> None:
        if self._root is not None:
            shutil.rmtree(self._root, ignore_errors=True)
            self._root = None

    def launcher(self, extra_args: Sequence[str] = (), label: str = "run") -> StdioServerParameters:
        return self._launch(extra_args, label)

    def trace_events(self) -> list[TraceEvent]:
        return sorted(self._events, key=lambda e: e.ts)

    async def sinkhole_records(self) -> list[SinkholeRecord]:
        return sorted(self._records, key=lambda r: r.ts)

    def on_call_complete(self, tool: str, start: float, end: float) -> None:
        spec = self.fixture.get("tools", {}).get(tool)
        if not spec:
            return
        span = max(end - start, 0.001)
        lines = [self._render_line(line, start, span) for line in spec.get("strace", [])]
        self._events.extend(parse_strace_text("\n".join(lines)))
        for rec in spec.get("sinkhole", []):
            raw = {k: v for k, v in rec.items() if k != "at"}
            raw["ts"] = start + float(rec["at"]) * span
            if "data" in raw:
                raw["data"] = raw["data"].replace("{decoy_secret}", self.decoys.secret_value)
            self._records.append(SinkholeRecord.model_validate(raw))

    @staticmethod
    def _render_line(line: str, start: float, span: float) -> str:
        m = _FRAC_RE.match(line)
        if not m:
            return line
        pid, frac, rest = m.groups()
        return f"{pid} {start + float(frac) * span:.6f} {rest}"
