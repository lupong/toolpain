"""M13: harness expect_* scoring."""

from __future__ import annotations

from runner.analyze.expectations import expectation_findings, score_expectations
from runner.harness import ProbeHarness, ToolCallPlan
from runner.probe import ProbeResult


def test_score_expect_decoy_hit_and_miss() -> None:
    harness = ProbeHarness(
        plans=[
            ToolCallPlan(
                tool="fetch_report",
                arguments={},
                expect_decoy=True,
                expect_hosts=["collector.sinkhole.local"],
                expect_files=["/workspace/canaries/decoy_secret.txt"],
            ),
            ToolCallPlan(tool="add", arguments={}, expect_decoy=False),
        ]
    )
    probes = {
        "fetch_report": ProbeResult(
            tool="fetch_report",
            decoy_reads=["/workspace/canaries/decoy_secret.txt"],
            egress_hosts=["collector.sinkhole.local"],
            files_read=["/workspace/canaries/decoy_secret.txt"],
        ),
        "add": ProbeResult(tool="add", ok=True),
    }
    results = score_expectations(harness, probes)
    assert any(r.kind == "expect_decoy" and r.hit for r in results)
    assert any(r.kind == "expect_host" and r.hit for r in results)
    misses = expectation_findings(
        score_expectations(
            ProbeHarness(plans=[ToolCallPlan(tool="x", arguments={}, expect_decoy=True)]),
            {"x": ProbeResult(tool="x")},
        )
    )
    assert misses and misses[0]["type"] == "expectation_miss"


def test_fixture_local_expect_host_is_not_a_finding() -> None:
    harness = ProbeHarness(
        plans=[
            ToolCallPlan(
                tool="Area",
                arguments={"url": "http://fixture.local/x"},
                expect_hosts=["fixture.local"],
            )
        ]
    )
    results = score_expectations(harness, {"Area": ProbeResult(tool="Area", ok=True)})
    assert results == []
    assert expectation_findings(results) == []
