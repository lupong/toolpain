"""Harness generation: fixture/heuristic offline; wires into probe args."""

from __future__ import annotations

from pathlib import Path

import pytest

from runner.discover import discover
from runner.harness import (
    generate_harness,
    harness_to_report_blob,
    heuristic_harness,
)
from runner.launch import local_launcher
from runner.research import FakeLlm

DECOY = Path(__file__).resolve().parents[1] / "demo" / "decoy-trap-server"


@pytest.mark.asyncio
async def test_fixture_harness_for_decoy_trap() -> None:
    launcher = local_launcher()
    discovery = await discover(
        launcher,
        source_dir=DECOY,
        readme_text=(DECOY / "README.md").read_text(),
    )
    harness = await generate_harness(discovery, FakeLlm(), DECOY)
    assert harness.source in {"fixture", "heuristic"}
    assert harness.plan_for("fetch_report") is not None
    fr = harness.plan_for("fetch_report")
    assert fr is not None
    assert fr.expect_decoy is True
    assert "collector.sinkhole.local" in fr.expect_hosts
    assert fr.arguments.get("report_id") == "weekly"
    blob = harness_to_report_blob(harness)
    assert blob["source"] == harness.source
    assert len(blob["plans"]) == len(discovery.tools)


def test_heuristic_harness_covers_all_tools() -> None:
    from runner.models import DiscoveredTool, DiscoveryResult

    discovery = DiscoveryResult(
        tools=[
            DiscoveredTool(name="alpha", input_schema={"type": "object", "properties": {}}),
            DiscoveredTool(
                name="fetch_report",
                undocumented=True,
                input_schema={
                    "type": "object",
                    "properties": {"report_id": {"type": "string"}},
                },
            ),
        ]
    )
    h = heuristic_harness(discovery)
    assert {p.tool for p in h.plans} == {"alpha", "fetch_report"}
    assert h.plan_for("fetch_report") and h.plan_for("fetch_report").expect_decoy
