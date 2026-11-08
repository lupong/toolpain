"""Deflate oracle/docs noise on reports (runner now filters this at source).

Applied to API/certificate views without rewriting the sealed on-disk report.
"""

from __future__ import annotations

import copy
from typing import Any

from runner.discover import is_plausible_tool_name

_ANOMALY_FLAG = {"decoy_read", "decoy_read_and_egress", "undeclared_egress"}
_SUSPICIOUS = {"undocumented_tool", "fork_added_tool", "hidden_behind_flag", "prompt_injection"}
_PLACEHOLDER = {"", "0", "[0]", "[]", "none", "null"}


def _oracle_noise(finding: dict[str, Any], *, decoy_reads: int, egress_attempted: int) -> bool:
    ftype = str(finding.get("type") or "")
    if not ftype.startswith("llm_oracle"):
        return False
    blob = " ".join(
        str(finding.get(k) or "") for k in ("type", "title", "evidence", "explanation")
    ).lower()
    evidence = str(finding.get("evidence") or "").strip()
    if "decoy" in blob:
        return decoy_reads <= 0 or evidence.lower() in _PLACEHOLDER
    if "egress" in blob or "undeclared" in blob:
        return egress_attempted <= 0
    return evidence.lower() in {"0", "[0]", "[]"}


def _docs_catalog_is_noise(tools: list[dict[str, Any]]) -> bool:
    """True when the only D-source names look like README headings, not tools."""
    d_names = [
        str(t.get("name") or "")
        for t in tools
        if "D" in (t.get("sources") or [])
    ]
    if not d_names:
        return False
    plausible = [n for n in d_names if is_plausible_tool_name(n)]
    return not plausible


def sanitize_report(report: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow-copied report with inflated oracle/docs findings removed."""
    out = copy.deepcopy(report)
    stats = dict(out.get("stats") or {})
    decoy_reads = int(stats.get("decoy_reads") or 0)
    egress_attempted = int(stats.get("egress_attempted") or 0)
    tools = list(out.get("tools") or [])
    catalog_noise = _docs_catalog_is_noise(tools)

    cleaned_tools = [t for t in tools if is_plausible_tool_name(str(t.get("name") or ""))]
    out["tools"] = cleaned_tools

    findings_in = list(out.get("findings") or [])
    findings: list[dict[str, Any]] = []
    for finding in findings_in:
        ftype = str(finding.get("type") or "")
        tool = str(finding.get("tool") or "")
        if tool and not is_plausible_tool_name(tool):
            continue
        if _oracle_noise(finding, decoy_reads=decoy_reads, egress_attempted=egress_attempted):
            continue
        if catalog_noise and ftype in {"undocumented_tool", "documented_missing"}:
            continue
        findings.append(finding)

    # Re-id for a stable ticket table.
    for i, finding in enumerate(findings, start=1):
        finding["id"] = f"F{i}"
    out["findings"] = findings

    if catalog_noise:
        stats["undocumented"] = 0
    else:
        stats["undocumented"] = sum(
            1 for t in cleaned_tools if t.get("sources") and "D" not in t["sources"]
        )
    stats["tools"] = len(cleaned_tools)
    stats["oracle_findings"] = sum(
        1 for f in findings if str(f.get("type") or "").startswith("llm_oracle")
    )
    out["stats"] = stats

    types = {str(f.get("type") or "") for f in findings}
    if types & _ANOMALY_FLAG or decoy_reads > 0:
        out["verdict"] = "flagged"
    else:
        out["verdict"] = _verdict_from_types(types, cleaned_tools)

    if out.get("llm_oracle"):
        out["llm_oracle"] = [
            f
            for f in out["llm_oracle"]
            if not _oracle_noise(f, decoy_reads=decoy_reads, egress_attempted=egress_attempted)
        ]

    config = out.get("least_privilege_config")
    if isinstance(config, dict):
        allow = config.get("allow_tools")
        if isinstance(allow, list):
            config = {
                **config,
                "allow_tools": [n for n in allow if is_plausible_tool_name(str(n))],
            }
            out["least_privilege_config"] = config
    return out


def _verdict_from_types(types: set[str], tools: list[dict[str, Any]]) -> str:
    material = {t for t in types if not t.startswith("llm_oracle")}
    if not tools:
        return "suspicious"
    if tools and all(t.get("verdict") == "not_observed" for t in tools):
        return "suspicious"
    if material & _SUSPICIOUS:
        return "suspicious"
    if any(t.get("verdict") == "exceeds_claim" for t in tools) or "description_mismatch" in material:
        return "over_privileged"
    return "clean"
