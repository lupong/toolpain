"""Score harness expect_* hints against observed probe results."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from runner.harness import ProbeHarness
from runner.probe import ProbeResult


class ExpectationResult(BaseModel):
    tool: str
    kind: str  # expect_decoy | expect_host | expect_file
    expected: str
    hit: bool
    evidence: str = ""


def score_expectations(
    harness: ProbeHarness | None,
    probes: dict[str, ProbeResult],
) -> list[ExpectationResult]:
    if harness is None:
        return []
    out: list[ExpectationResult] = []
    for plan in harness.plans:
        if plan.skip:
            continue
        probe = probes.get(plan.tool)
        if plan.expect_decoy:
            hit = bool(probe and (probe.decoy_reads or probe.decoy_in_sinkhole))
            out.append(
                ExpectationResult(
                    tool=plan.tool,
                    kind="expect_decoy",
                    expected="decoy read",
                    hit=hit,
                    evidence=(
                        ",".join(probe.decoy_reads[:3])
                        if probe and probe.decoy_reads
                        else ("sinkhole" if probe and probe.decoy_in_sinkhole else "none")
                    ),
                )
            )
        for host in plan.expect_hosts:
            observed = set(probe.egress_hosts + probe.network) if probe else set()
            hit = any(host in o or o in host for o in observed)
            out.append(
                ExpectationResult(
                    tool=plan.tool,
                    kind="expect_host",
                    expected=host,
                    hit=hit,
                    evidence=",".join(sorted(observed)[:6]) if observed else "none",
                )
            )
        for path in plan.expect_files:
            files = set(
                (probe.files_read if probe else []) + (probe.files_written if probe else [])
            )
            hit = path in files or any(path in f or f.endswith(path.split("/")[-1]) for f in files)
            out.append(
                ExpectationResult(
                    tool=plan.tool,
                    kind="expect_file",
                    expected=path,
                    hit=hit,
                    evidence=",".join(sorted(files)[:6]) if files else "none",
                )
            )
    return out


def expectation_findings(results: list[ExpectationResult]) -> list[dict[str, Any]]:
    """Missed hostile expectations are medium; unexpected silence on decoy is informative."""
    findings: list[dict[str, Any]] = []
    for r in results:
        if r.hit:
            continue
        if r.kind == "expect_decoy":
            sev, title = "medium", f"Expected decoy activity from `{r.tool}` not observed"
        elif r.kind == "expect_host":
            sev, title = "low", f"Expected host `{r.expected}` not seen for `{r.tool}`"
        else:
            sev, title = "low", f"Expected file `{r.expected}` not seen for `{r.tool}`"
        findings.append(
            {
                "severity": sev,
                "type": "expectation_miss",
                "tool": r.tool,
                "title": title,
                "evidence": r.evidence,
                "explanation": (
                    f"Harness planned {r.kind}={r.expected!r} but the probe window did not match."
                ),
                "recommendation": "Re-check tool args or treat the expectation as stale.",
            }
        )
    return findings
