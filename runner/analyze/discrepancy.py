"""Four-source discrepancies: undocumented, hidden behind flag, documented but missing,
description mismatch, and fork drift against an upstream tool list."""

from __future__ import annotations

from pydantic import BaseModel

from runner.analyze.privilege import PrivilegeAssessment
from runner.models import DiscoveryResult


class Discrepancy(BaseModel):
    kind: str
    tool: str
    severity: str
    title: str
    detail: str = ""
    file: str | None = None


def fork_drift(
    discovery: DiscoveryResult, upstream_tools: list[str] | None
) -> list[dict[str, str | None]]:
    """Tools added to / removed from the fork relative to upstream."""
    if upstream_tools is None:
        return []
    upstream = set(upstream_tools)
    drift: list[dict[str, str | None]] = []
    for tool in discovery.tools:
        if tool.name not in upstream and (set(tool.sources) & {"S", "R", "F"}):
            drift.append({"change": "added_tool", "tool": tool.name, "file": tool.file})
    current = set(discovery.names)
    drift += [
        {"change": "removed_tool", "tool": name, "file": None}
        for name in sorted(upstream - current)
    ]
    return drift


def find_discrepancies(
    discovery: DiscoveryResult,
    assessments: dict[str, PrivilegeAssessment],
    upstream_tools: list[str] | None = None,
) -> list[Discrepancy]:
    out: list[Discrepancy] = []
    runtimeish = sum(1 for t in discovery.tools if set(t.sources) & {"S", "R", "F"})
    ghosts = sum(
        1 for t in discovery.tools if t.documented and not (set(t.sources) & {"S", "R", "F"})
    )
    # A long README catalog of names the runtime never exposes is noise.
    report_documented_missing = ghosts <= max(3, runtimeish // 4)
    for tool in discovery.tools:
        tier = assessments[tool.name].tier if tool.name in assessments else "low"
        if tool.undocumented:
            out.append(
                Discrepancy(
                    kind="undocumented",
                    tool=tool.name,
                    severity="high" if tier in {"critical", "high"} else "medium",
                    title=f"`{tool.name}` is not documented",
                    detail=f"Seen via {'/'.join(tool.sources)} but absent from the docs.",
                    file=tool.file,
                )
            )
        if tool.hidden_behind_flag:
            out.append(
                Discrepancy(
                    kind="hidden_behind_flag",
                    tool=tool.name,
                    severity="medium",
                    title="Tool only appears with a capability flag",
                    detail=f"Only listed when started with {', '.join(tool.flags)}.",
                    file=tool.file,
                )
            )
        if (
            report_documented_missing
            and tool.documented
            and not (set(tool.sources) & {"S", "R", "F"})
        ):
            out.append(
                Discrepancy(
                    kind="documented_missing",
                    tool=tool.name,
                    severity="low",
                    title=f"Documented tool `{tool.name}` not found in code or at runtime",
                )
            )
        assessment = assessments.get(tool.name)
        if assessment and assessment.exceeds and tool.sources:
            severe = {"credential_read", "file_read", "file_write", "shell", "subprocess"}
            exceeds = list(assessment.exceeds)
            detail = (
                f"Claimed: {', '.join(assessment.claimed) or 'nothing notable'}. "
                f"Observed beyond that: {', '.join(exceeds)}."
            )
            out.append(
                Discrepancy(
                    kind="description_mismatch",
                    tool=tool.name,
                    severity="high" if severe & set(assessment.exceeds) else "medium",
                    title=f"`{tool.name}` does more than it claims",
                    detail=detail,
                    file=tool.file,
                )
            )
    for drift in fork_drift(discovery, upstream_tools):
        out.append(
            Discrepancy(
                kind="fork_drift",
                tool=str(drift["tool"]),
                severity="high" if drift["change"] == "added_tool" else "low",
                title=(
                    "Tool not present upstream"
                    if drift["change"] == "added_tool"
                    else "Upstream tool missing from fork"
                ),
                detail=f"Fork drift: {drift['change']}",
                file=drift["file"],
            )
        )
    return out
