"""Probe stage: call every tool with safe arguments and correlate trace events to each call.

Arguments are derived from each tool's ``inputSchema`` (minimal values; fixture-site URLs for
URL-ish fields). The target only ever runs through the sandbox launcher, so file and network
effects are contained; syscall trace events and sinkhole records are attributed to calls by time
window ``[call_start, call_end + 500ms]``.
"""

from __future__ import annotations

import asyncio
import re
from collections import defaultdict
from collections.abc import Sequence
from typing import Any

from pydantic import BaseModel, Field

from runner.discover import Launcher
from runner.events import EventSink, NullSink
from runner.mcp_client import McpClient
from runner.models import CallOutcome, DiscoveredTool
from sandbox.models import SinkholeRecord, TraceEvent
from sandbox.sandbox import Sandbox
from sandbox.trace import is_noise_path

TAIL_SEC = 0.5
FIXTURE_HOSTS = {"fixture.local"}
SCHEMA_ERROR_RE = re.compile(
    r"validation|invalid|required|missing|argument|schema|should be|expected", re.IGNORECASE
)
OPEN_SYSCALLS = {"open", "openat", "openat2", "creat"}
WRITE_SYSCALLS = {"unlink", "unlinkat", "rename", "renameat", "renameat2", "mkdir", "mkdirat"}


class ProbeResult(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    ok: bool = False
    is_error: bool = False
    timed_out: bool = False
    retried: bool = False
    error: str | None = None
    output: str = ""
    start: float = 0.0
    end: float = 0.0
    events: list[TraceEvent] = Field(default_factory=list)
    sinkhole: list[SinkholeRecord] = Field(default_factory=list)
    files_read: list[str] = Field(default_factory=list)
    files_written: list[str] = Field(default_factory=list)
    processes: list[str] = Field(default_factory=list)
    network: list[str] = Field(default_factory=list)
    egress_hosts: list[str] = Field(default_factory=list)
    listening_ports: list[int] = Field(default_factory=list)
    decoy_reads: list[str] = Field(default_factory=list)
    decoy_in_sinkhole: bool = False
    exercised: bool = False

    @property
    def tripped_decoy(self) -> bool:
        return bool(self.decoy_reads) or self.decoy_in_sinkhole


# ---------------------------------------------------------------------------
# Safe argument generation
# ---------------------------------------------------------------------------

_URL_KEYS = re.compile(r"(^|_)(url|uri|href|link|endpoint)$", re.IGNORECASE)
_PATH_KEYS = re.compile(r"(path|file|filename|dir|directory|folder)$", re.IGNORECASE)
_CODE_KEYS = re.compile(r"(code|script|expression|function|command|cmd|query)$", re.IGNORECASE)


def _string_value(key: str, spec: dict[str, Any], fixture_url: str) -> str:
    fmt = spec.get("format", "")
    if fmt in {"uri", "url"} or _URL_KEYS.search(key):
        return fixture_url
    if _PATH_KEYS.search(key):
        return "/tmp/toolpain-probe.txt"
    if re.search(r"(command|cmd)$", key, re.IGNORECASE):
        return "true"
    if _CODE_KEYS.search(key):
        return "1+1"
    if "email" in key.lower():
        return "probe@example.invalid"
    return "toolpain-probe"


def _value_for(key: str, spec: dict[str, Any], fixture_url: str, depth: int = 0) -> Any:
    if "default" in spec:
        return spec["default"]
    if "const" in spec:
        return spec["const"]
    if spec.get("enum"):
        return spec["enum"][0]
    for combo in ("anyOf", "oneOf"):
        options = [o for o in spec.get(combo, []) if o.get("type") != "null"]
        if options:
            return _value_for(key, options[0], fixture_url, depth)
    kind = spec.get("type", "string")
    if isinstance(kind, list):
        kind = next((k for k in kind if k != "null"), "string")
    if kind == "integer":
        return int(spec.get("minimum", 1))
    if kind == "number":
        return float(spec.get("minimum", 1))
    if kind == "boolean":
        return False
    if kind == "array":
        if spec.get("minItems", 0) > 0 and depth < 3:
            return [_value_for(key, spec.get("items", {}), fixture_url, depth + 1)]
        return []
    if kind == "object":
        return generate_args(spec, fixture_url=fixture_url, depth=depth + 1)
    if kind == "null":
        return None
    return _string_value(key, spec, fixture_url)


def generate_args(
    schema: dict[str, Any],
    *,
    fixture_url: str = "http://fixture.local/",
    full: bool = False,
    depth: int = 0,
) -> dict[str, Any]:
    """Minimal valid arguments for ``schema``; ``full=True`` also fills optional properties."""
    props: dict[str, Any] = (schema or {}).get("properties") or {}
    required = set((schema or {}).get("required") or [])
    args: dict[str, Any] = {}
    for key, spec in props.items():
        if key in required or full:
            args[key] = _value_for(key, spec if isinstance(spec, dict) else {}, fixture_url, depth)
    return args


# ---------------------------------------------------------------------------
# Correlation
# ---------------------------------------------------------------------------


def assign_to_windows(
    items: Sequence[Any], windows: dict[str, tuple[float, float]], tail: float = TAIL_SEC
) -> dict[str, list[Any]]:
    """Attribute timestamped items to call windows ``[start, end + tail]``.

    An item strictly inside a call's ``[start, end]`` wins; otherwise it goes to the most
    recently started call whose tail covers it, so back-to-back calls do not steal events.
    """
    out: dict[str, list[Any]] = defaultdict(list)
    ordered = sorted(windows.items(), key=lambda kv: kv[1][0])
    for item in items:
        ts = item.ts
        inside = [n for n, (s, e) in ordered if s <= ts <= e]
        if inside:
            out[inside[-1]].append(item)
            continue
        tails = [n for n, (s, e) in ordered if e < ts <= e + tail]
        if tails:
            out[tails[-1]].append(item)
    return out


def _is_loopback(addr: str | None) -> bool:
    return bool(addr) and (addr.startswith("127.") or addr in {"::1", "0.0.0.0", "::"})


def summarize(
    result: ProbeResult,
    events: list[TraceEvent],
    records: list[SinkholeRecord],
    sandbox: Sandbox,
) -> ProbeResult:
    """Fill the observed-behaviour fields of ``result`` from correlated events."""
    result.events, result.sinkhole = events, records
    reads: list[str] = []
    writes: list[str] = []
    decoys: list[str] = []
    for e in events:
        if e.kind == "file" and e.path:
            if e.syscall in OPEN_SYSCALLS and sandbox.decoys.is_decoy_path(e.path):
                decoys.append(e.path)
            if is_noise_path(e.path) or not e.ok:
                continue
            if e.syscall in OPEN_SYSCALLS:
                (writes if e.is_write else reads).append(e.path)
            elif e.syscall in WRITE_SYSCALLS:
                writes.append(e.path)
        elif e.kind == "proc" and e.syscall.startswith("execve") and e.ok:
            result.processes.append(e.detail.removeprefix(e.syscall).strip() or (e.path or ""))
    result.files_read = list(dict.fromkeys(reads))
    result.files_written = list(dict.fromkeys(writes))
    result.decoy_reads = list(dict.fromkeys(decoys))

    hosts: list[str] = [r.host for r in records if r.proto in {"http", "tls", "dns"} and r.host]
    network: list[str] = []
    for e in events:
        if e.kind != "net" or not e.addr:
            continue
        if e.syscall in {"bind", "listen"}:
            if e.port:
                result.listening_ports.append(e.port)
            continue
        if e.syscall != "connect" or _is_loopback(e.addr) or e.family == "AF_UNIX":
            continue
        if e.addr == sandbox.sinkhole_ip and e.port == 53:
            continue  # DNS lookups are captured via sinkhole dns records
        if e.addr == sandbox.sinkhole_ip:
            continue  # host resolved through sinkhole records above
        hosts.append(e.addr)  # IP-literal egress: no route, but the attempt is visible
        network.append(f"{e.addr}:{e.port}" if e.port else e.addr)
    all_hosts = list(dict.fromkeys(hosts))
    result.egress_hosts = [h for h in all_hosts if h not in FIXTURE_HOSTS]
    for rec in records:
        if rec.proto in {"http", "tls"} and rec.host and rec.host not in FIXTURE_HOSTS:
            entry = f"{rec.host}:{rec.port}" if rec.port else rec.host
            network.append(entry)
    result.network = list(dict.fromkeys(network))
    result.listening_ports = sorted(set(result.listening_ports))
    result.decoy_in_sinkhole = any(
        v in (r.data + r.request_line + " ".join(r.headers.values()))
        for r in records
        for v in sandbox.decoys.values
    )
    return result


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _flag_args(flags: list[str]) -> tuple[str, ...]:
    return tuple(flags[0].split(" ")) if flags else ()


async def _call_with_retry(
    client: McpClient,
    tool: DiscoveredTool,
    fixture_url: str,
    timeout: float,
    *,
    preferred_args: dict[str, Any] | None = None,
) -> tuple[CallOutcome, bool]:
    args = (
        dict(preferred_args)
        if preferred_args is not None
        else generate_args(tool.input_schema, fixture_url=fixture_url)
    )
    outcome = await client.call_tool(tool.name, args, timeout=timeout)
    if outcome.is_error and not outcome.timed_out and SCHEMA_ERROR_RE.search(outcome.error or ""):
        fuller = generate_args(tool.input_schema, fixture_url=fixture_url, full=True)
        if fuller != args:
            return await client.call_tool(tool.name, fuller, timeout=timeout), True
    return outcome, False


async def probe_tools(
    launch: Launcher,
    sandbox: Sandbox,
    tools: Sequence[DiscoveredTool],
    *,
    call_timeout: float = 30.0,
    sink: EventSink | None = None,
    harness: Any | None = None,
) -> dict[str, ProbeResult]:
    """Call each tool once (twice on a schema error) and return correlated observations.

    When ``harness`` (a :class:`runner.harness.ProbeHarness`) is provided, preferred
    arguments come from the LLM/fixture call plan instead of blank schema defaults.
    """
    sink = sink or NullSink()
    groups: dict[tuple[str, ...], list[DiscoveredTool]] = defaultdict(list)
    for tool in tools:
        use_flags = tool.hidden_behind_flag and tool.flags
        groups[_flag_args(tool.flags if use_flags else [])].append(tool)

    outcomes: dict[str, CallOutcome] = {}
    retried: dict[str, bool] = {}
    for flags, group in groups.items():
        async with McpClient(launch(flags, "probe"), call_timeout=call_timeout) as client:
            for tool in group:
                plan = harness.plan_for(tool.name) if harness is not None else None
                if plan is not None and plan.skip:
                    await sink.emit(
                        "probe",
                        f"Skipping {tool.name}: {plan.skip_reason or 'harness skip'}",
                        data={"tool": tool.name, "skipped": True},
                    )
                    continue
                preferred = None
                if harness is not None:
                    preferred = harness.arguments_for(
                        tool.name, tool.input_schema, sandbox.fixture_url
                    )
                await sink.emit(
                    "probe",
                    f"Probing {tool.name}" + (" (harness args)" if preferred is not None else ""),
                    data={"tool": tool.name, "harness": preferred is not None},
                )
                outcome, did_retry = await _call_with_retry(
                    client,
                    tool,
                    sandbox.fixture_url,
                    call_timeout,
                    preferred_args=preferred,
                )
                outcomes[tool.name], retried[tool.name] = outcome, did_retry
                sandbox.on_call_complete(tool.name, outcome.start, outcome.end)
                if sandbox.settle_sec:
                    await asyncio.sleep(sandbox.settle_sec)

    windows = {n: (o.start, o.end) for n, o in outcomes.items()}
    events = assign_to_windows(sandbox.trace_events(), windows)
    records = assign_to_windows(await sandbox.sinkhole_records(), windows)
    results: dict[str, ProbeResult] = {}
    for name, o in outcomes.items():
        res = ProbeResult(
            tool=name,
            arguments=o.arguments,
            ok=o.ok,
            is_error=o.is_error,
            timed_out=o.timed_out,
            retried=retried[name],
            error=o.error,
            output=o.text[:500],
            start=o.start,
            end=o.end,
            exercised=not o.timed_out,
        )
        results[name] = summarize(res, events.get(name, []), records.get(name, []), sandbox)
        if results[name].tripped_decoy:
            hosts = ", ".join(results[name].egress_hosts) or "no host"
            await sink.emit(
                "probe",
                f"Flagged: {name} read the planted decoy and tried {hosts}. Contained.",
                level="alert",
                data={"tool": name, "hosts": results[name].egress_hosts},
            )
    return results
