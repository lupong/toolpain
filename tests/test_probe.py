"""M5: safe-argument generation, trace correlation, and probing decoy-trap-server."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from runner.models import CallOutcome, DiscoveredTool
from runner.probe import ProbeResult, _call_with_retry, assign_to_windows, generate_args, summarize
from sandbox.models import TraceEvent

COLLECTOR = "collector.sinkhole.local"


def test_generate_args_required_only_and_types() -> None:
    schema = {
        "type": "object",
        "required": ["url", "count", "flag", "mode", "items", "nested", "text"],
        "properties": {
            "url": {"type": "string"},
            "count": {"type": "integer", "minimum": 3},
            "flag": {"type": "boolean"},
            "mode": {"enum": ["fast", "slow"]},
            "items": {"type": "array", "minItems": 1, "items": {"type": "string"}},
            "nested": {
                "type": "object",
                "required": ["path"],
                "properties": {"path": {"type": "string"}},
            },
            "text": {"type": "string", "default": "hello"},
            "optional": {"type": "string"},
        },
    }
    args = generate_args(schema, fixture_url="http://fixture.local/")
    assert args == {
        "url": "http://fixture.local/",
        "count": 3,
        "flag": False,
        "mode": "fast",
        "items": ["toolpain-probe"],
        "nested": {"path": "/tmp/toolpain-probe.txt"},
        "text": "hello",
    }
    assert "optional" in generate_args(schema, full=True)
    assert generate_args({}) == {}


def test_generate_args_code_and_nullable() -> None:
    schema = {
        "required": ["expression", "maybe"],
        "properties": {
            "expression": {"type": "string"},
            "maybe": {"anyOf": [{"type": "null"}, {"type": "integer"}]},
        },
    }
    assert generate_args(schema) == {"expression": "1+1", "maybe": 1}


def test_assign_to_windows_strict_beats_tail() -> None:
    windows = {"a": (10.0, 11.0), "b": (11.2, 12.0)}
    items = [
        SimpleNamespace(ts=10.5, id="in-a"),
        SimpleNamespace(ts=11.1, id="tail-a"),
        SimpleNamespace(ts=11.3, id="in-b"),  # inside b, also within a's 500ms tail
        SimpleNamespace(ts=12.4, id="tail-b"),
        SimpleNamespace(ts=13.0, id="outside"),
        SimpleNamespace(ts=9.0, id="before"),
    ]
    got = assign_to_windows(items, windows)
    assert [i.id for i in got["a"]] == ["in-a", "tail-a"]
    assert [i.id for i in got["b"]] == ["in-b", "tail-b"]


class _StubClient:
    def __init__(self, first_error: str | None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.first_error = first_error

    async def call_tool(self, name: str, args: dict[str, Any], timeout: float) -> CallOutcome:
        self.calls.append(args)
        failing = self.first_error is not None and len(self.calls) == 1
        return CallOutcome(
            tool=name,
            arguments=args,
            ok=not failing,
            is_error=failing,
            error=self.first_error if failing else None,
            start=1.0,
            end=2.0,
        )


async def test_retry_once_on_schema_error_with_fuller_args() -> None:
    tool = DiscoveredTool(
        name="t",
        input_schema={
            "properties": {"a": {"type": "string"}, "b": {"type": "integer"}},
            "required": ["a"],
        },
    )
    client = _StubClient("Input should be a valid integer: validation error")
    outcome, retried = await _call_with_retry(client, tool, "http://fixture.local/", 5)  # type: ignore[arg-type]
    assert retried and outcome.ok
    assert client.calls == [{"a": "toolpain-probe"}, {"a": "toolpain-probe", "b": 1}]


async def test_no_retry_for_non_schema_error() -> None:
    tool = DiscoveredTool(name="t", input_schema={"properties": {"a": {"type": "string"}}})
    client = _StubClient("kaboom")
    _, retried = await _call_with_retry(client, tool, "http://fixture.local/", 5)  # type: ignore[arg-type]
    assert not retried and len(client.calls) == 1


def test_fixture_container_ip_is_not_undeclared_egress() -> None:
    box = SimpleNamespace(
        sinkhole_ip="10.66.207.53",
        fixture_ip="10.66.207.80",
        decoys=SimpleNamespace(values=[], is_decoy_path=lambda path: False),
    )
    result = summarize(
        ProbeResult(tool="convert_to_markdown", exercised=True),
        [
            TraceEvent(
                ts=1.0,
                pid=1,
                kind="net",
                detail="connect",
                syscall="connect",
                addr="10.66.207.80",
                port=80,
            )
        ],
        [],
        box,  # type: ignore[arg-type]
    )
    assert result.egress_hosts == []
    assert result.network == ["fixture.local:80"]


def test_decoy_trap_fetch_report_trips_decoy_and_sinkhole(decoy_scan: dict[str, Any]) -> None:
    probe = decoy_scan["probes"]["fetch_report"]
    decoys = decoy_scan["decoys"]
    assert probe.ok and probe.exercised
    assert probe.decoy_reads == ["/workspace/canaries/decoy_secret.txt"]
    assert probe.egress_hosts == [COLLECTOR]
    assert f"{COLLECTOR}:443" in probe.network
    assert probe.decoy_in_sinkhole and probe.tripped_decoy
    assert any(r.proto == "http" and decoys.secret_value in r.data for r in probe.sinkhole)
    assert probe.files_read == ["/workspace/canaries/decoy_secret.txt"]


def test_decoy_trap_honest_tools_show_nothing(decoy_scan: dict[str, Any]) -> None:
    probes = decoy_scan["probes"]
    assert set(probes) == {
        "add",
        "echo",
        "reverse_text",
        "word_count",
        "current_time",
        "fetch_report",
    }
    for name, probe in probes.items():
        if name == "fetch_report":
            continue
        assert probe.ok, name
        assert not probe.decoy_reads and not probe.decoy_in_sinkhole, name
        assert probe.egress_hosts == [] and probe.network == [] and probe.processes == [], name
        assert probe.files_read == [] and probe.files_written == [], name


def test_probe_events_are_emitted(decoy_scan: dict[str, Any]) -> None:
    events = decoy_scan["sink"].events
    alerts = [e for e in events if e["level"] == "alert"]
    assert len(alerts) == 1 and "fetch_report" in alerts[0]["msg"] and COLLECTOR in alerts[0]["msg"]
    assert sum(1 for e in events if e["msg"].startswith("Probing ")) == 6
