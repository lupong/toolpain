"""Assemble the final report (Part 1.7 shape) from discovery, probes, and analysis."""

from __future__ import annotations

from typing import Any

from control_plane.models import Report
from runner.analyze import AnalysisInput, AnalysisResult
from runner.analyze.privilege import tier_rank
from runner.models import DiscoveredTool
from runner.probe import ProbeResult

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]
FINDING_FOR_DISCREPANCY = {
    "undocumented": "undocumented_tool",
    "hidden_behind_flag": "hidden_behind_flag",
    "documented_missing": "documented_missing",
    "description_mismatch": "description_mismatch",
    "fork_drift": "fork_added_tool",
}
ANOMALY_VERDICT_KINDS = {"decoy_read", "decoy_read_and_egress", "undeclared_egress"}


def _tool_verdict(tool: DiscoveredTool, probe: ProbeResult | None, analysis: AnalysisResult) -> str:
    flagged = {a.tool for a in analysis.anomalies if a.kind in ANOMALY_VERDICT_KINDS}
    if tool.name in flagged:
        return "flagged"
    if probe is None or not probe.exercised:
        return "not_observed"
    exceeds = any(
        d.kind == "description_mismatch" and d.tool == tool.name for d in analysis.discrepancies
    )
    return "exceeds_claim" if exceeds else "confirmed"


def _tool_entry(
    tool: DiscoveredTool, data: AnalysisInput, analysis: AnalysisResult
) -> dict[str, Any]:
    probe = data.probes.get(tool.name)
    assessment = analysis.assessments[tool.name]
    profile = data.profiles.get(tool.name)
    evidence = [
        (a.evidence[:2000] + "\n…[truncated]") if len(a.evidence) > 2000 else a.evidence
        for a in analysis.anomalies
        if a.tool == tool.name and a.evidence
    ]
    downstream = analysis.downstream[tool.name]
    return {
        "name": tool.name,
        "privilege": assessment.tier,
        "verdict": _tool_verdict(tool, probe, analysis),
        "sources": list(tool.sources),
        "egress": list(probe.egress_hosts) if probe else [],
        "decoy_reads": len(probe.decoy_reads) if probe else 0,
        "claimed": (profile.claimed_behavior if profile else None) or tool.description or None,
        "observed": {
            "files": (probe.files_read + probe.files_written) if probe else [],
            "processes": list(probe.processes) if probe else [],
            "network": list(probe.network) if probe else [],
        },
        "evidence": evidence,
        "downstream": downstream.hosts + downstream.services,
        "capabilities": assessment.capabilities,
        "privilege_reasons": assessment.reasons,
    }


def _findings(analysis: AnalysisResult, data: AnalysisInput) -> list[dict[str, Any]]:
    raw: list[dict[str, Any]] = []
    for a in analysis.anomalies:
        raw.append(
            {
                "severity": a.severity,
                "type": a.kind,
                "tool": a.tool,
                "title": a.title,
                "evidence": a.evidence,
                "explanation": a.explanation,
                "recommendation": a.recommendation,
            }
        )
    for name, probe in data.probes.items():
        if not probe.timed_out:
            continue
        raw.append(
            {
                "severity": "medium",
                "type": "probe_timeout",
                "tool": name,
                "title": f"{name} timed out",
                "evidence": (probe.error or probe.output or "")[:500],
                "explanation": f"{name} did not finish within the per-tool limit.",
                "recommendation": "Treat this tool as not observed and re-scan if it should have run.",
            }
        )
    for d in analysis.discrepancies:
        raw.append(
            {
                "severity": d.severity,
                "type": FINDING_FOR_DISCREPANCY.get(d.kind, d.kind),
                "tool": d.tool,
                "title": d.title,
                "evidence": d.file or d.detail,
                "explanation": d.detail,
                "recommendation": "Verify the tool is intended; document it or remove it.",
            }
        )
    raw.sort(key=lambda f: (SEVERITY_ORDER.index(f["severity"]), f["type"], f["tool"] or ""))
    return [{"id": f"F{i}", **f} for i, f in enumerate(raw, start=1)]


def overall_verdict(
    findings: list[dict[str, Any]], tools: list[dict[str, Any]], analysis: AnalysisResult
) -> str:
    types = {f["type"] for f in findings}
    if types & ANOMALY_VERDICT_KINDS:
        return "flagged"
    if not tools:
        return "suspicious"
    if tools and all(t.get("verdict") == "not_observed" for t in tools):
        return "suspicious"
    suspicious = {"undocumented_tool", "fork_added_tool", "hidden_behind_flag", "prompt_injection"}
    medium_anomaly = any(a.severity in {"medium", "high", "critical"} for a in analysis.anomalies)
    if types & suspicious or medium_anomaly:
        return "suspicious"
    if any(t["verdict"] == "exceeds_claim" for t in tools) or "description_mismatch" in types:
        return "over_privileged"
    return "clean"


def _least_privilege(
    tools: list[dict[str, Any]], analysis: AnalysisResult, undocumented: set[str]
) -> dict[str, Any]:
    """Allow only documented, confirmed tools at medium tier or below."""
    allow = [
        t["name"]
        for t in tools
        if tier_rank(t["privilege"]) >= tier_rank("medium")
        and t["verdict"] not in {"flagged", "exceeds_claim"}
        and t["name"] not in undocumented
    ]
    return {"allow_tools": allow, "allow_hosts": list(analysis.egress.declared)}


def _graph(tools: list[dict[str, Any]], analysis: AnalysisResult) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = [
        {"data": {"id": "server", "label": "MCP server", "kind": "server"}}
    ]
    edges: list[dict[str, Any]] = []
    seen: set[str] = {"server"}

    def node(node_id: str, label: str, kind: str, **extra: Any) -> None:
        if node_id not in seen:
            seen.add(node_id)
            nodes.append({"data": {"id": node_id, "label": label, "kind": kind, **extra}})

    def edge(source: str, target: str, kind: str) -> None:
        edges.append(
            {"data": {"id": f"e{len(edges) + 1}", "source": source, "target": target, "kind": kind}}
        )

    cap_label = {"file_read": "local files", "file_write": "local files", "network": "network"}
    cap_label |= {"code_exec": "code exec", "shell": "subprocess", "subprocess": "subprocess"}
    cap_label |= {"credential_read": "credentials", "browser": "browser data"}
    for t in tools:
        flagged = t["verdict"] == "flagged"
        node(t["name"], t["name"], "tool", flagged=flagged, privilege=t["privilege"])
        edge("server", t["name"], "member")
        for cap in t["capabilities"]:
            if cap in cap_label:
                cap_id = "cap_" + cap_label[cap].replace(" ", "_")
                node(cap_id, cap_label[cap], "cap")
                observed = cap in {
                    c for a in analysis.assessments.values() for c in a.observed
                } and (cap in analysis.assessments[t["name"]].observed)
                edge(t["name"], cap_id, "observed" if observed else "claimed")
    for attempt in analysis.egress.attempted:
        host_id = "host_" + attempt.host.replace(".", "_")
        node(host_id, attempt.host, "host", blocked=attempt.blocked)
        edge(attempt.tool, host_id, "blocked")
    for t in tools:
        if t["decoy_reads"]:
            node("decoy", "decoy_secret.txt", "decoy")
            edge(t["name"], "decoy", "observed")
    for combo in analysis.combos:
        if len(combo.tools) == 2:
            edge(combo.tools[0], combo.tools[1], "toxic")
    return {"nodes": nodes, "edges": edges}


def build_report(
    scan_id: str,
    repo: dict[str, Any],
    data: AnalysisInput,
    analysis: AnalysisResult,
) -> dict[str, Any]:
    """Return the report dict (validated against the control-plane ``Report`` model)."""
    tool_entries = [_tool_entry(t, data, analysis) for t in data.discovery.tools]
    tool_entries.sort(key=lambda t: (tier_rank(t["privilege"]), t["name"]))
    findings = _findings(analysis, data)
    verdict = overall_verdict(findings, tool_entries, analysis)
    attempted = [
        {"host": a.host, "tool": a.tool, "blocked": a.blocked} for a in analysis.egress.attempted
    ]
    report: dict[str, Any] = {
        "scan_id": scan_id,
        "repo": {**repo, "fork_drift": analysis.drift},
        "verdict": verdict,
        "stats": {
            "tools": len(tool_entries),
            "undocumented": sum(1 for t in data.discovery.tools if t.undocumented),
            "critical_tier": sum(1 for t in tool_entries if t["privilege"] == "critical"),
            "toxic_combos": len(analysis.combos),
            "egress_attempted": len(attempted),
            "decoy_reads": sum(t["decoy_reads"] for t in tool_entries),
        },
        "tools": tool_entries,
        "toxic_combos": [c.model_dump() for c in analysis.combos],
        "findings": findings,
        "egress": {"declared": analysis.egress.declared, "attempted": attempted},
        "ingress": analysis.egress.ingress,
        "least_privilege_config": _least_privilege(
            tool_entries, analysis, {t.name for t in data.discovery.tools if t.undocumented}
        ),
        "graph": _graph(tool_entries, analysis),
    }
    Report.model_validate(report)
    return report
