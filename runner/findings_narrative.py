"""LLM rewrite of finding explanation + recommendation for IT operators.

Runs after findings are assembled. Soft-fails to the original heuristic text.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Protocol

from runner.certificate_narrative import _clip

log = logging.getLogger("toolpain.findings_narrative")

TASK_MARKER = "TASK: FINDINGS_NARRATIVE"

SCAN_CONTEXT = {
    "where_observed": (
        "ToolPain ran the MCP server inside an isolated scanner sandbox. "
        "Filesystem, process, and network observations are of that server process "
        "on the scanner — not of the MCP client laptop, IDE, or end-user machine."
    ),
    "audience": (
        "IT / security reviewer who must decide whether to approve this MCP server "
        "for agents, what to allow-list, and what to ask the owner to change."
    ),
    "voice": (
        "Plain language. Say what happened, why it matters for production use, "
        "and the concrete next action. Do not invent vendors, customers, or paths "
        "that are not in the evidence. Prefer 'MCP server sandbox' over jargon "
        "like 'strace' unless quoting evidence."
    ),
}


class LlmClient(Protocol):
    async def chat_json(self, messages: list[dict[str, str]]) -> dict[str, Any]: ...


def evidence_pack(report: dict[str, Any]) -> dict[str, Any]:
    findings = report.get("findings") or []
    tools = {str(t.get("name") or ""): t for t in (report.get("tools") or []) if t.get("name")}
    packed: list[dict[str, Any]] = []
    for finding in findings[:60]:
        tool_name = str(finding.get("tool") or "")
        tool = tools.get(tool_name) or {}
        observed = tool.get("observed") or {}
        packed.append(
            {
                "id": finding.get("id"),
                "severity": finding.get("severity"),
                "type": finding.get("type"),
                "tool": tool_name or None,
                "title": _clip(finding.get("title"), 160),
                "explanation": _clip(finding.get("explanation"), 400),
                "recommendation": _clip(finding.get("recommendation"), 240),
                "evidence": _clip(finding.get("evidence"), 320),
                "tool_claimed": _clip(tool.get("claimed"), 160),
                "tool_observed": {
                    "files": [_clip(p, 120) for p in list(observed.get("files") or [])[:8]],
                    "network": [_clip(p, 80) for p in list(observed.get("network") or [])[:8]],
                    "processes": [_clip(p, 80) for p in list(observed.get("processes") or [])[:6]],
                },
                "tool_capabilities": list(tool.get("capabilities") or [])[:12],
                "tool_verdict": tool.get("verdict"),
            }
        )
    return {
        "verdict": report.get("verdict"),
        "scan_context": SCAN_CONTEXT,
        "repo": {
            "url": (report.get("repo") or {}).get("url"),
            "package": (report.get("repo") or {}).get("package"),
        },
        "least_privilege_config": report.get("least_privilege_config") or {},
        "findings": packed,
    }


def build_findings_prompt(report: dict[str, Any]) -> list[dict[str, str]]:
    pack = evidence_pack(report)
    return [
        {
            "role": "user",
            "content": (
                f"{TASK_MARKER}\n"
                "Rewrite each finding's explanation and recommendation for an IT / "
                "security reviewer who must act on this scan.\n"
                "Return one JSON object: {\"findings\": [{\"id\", \"explanation\", "
                "\"recommendation\"}, ...]} — one entry per input finding id.\n"
                "Rules:\n"
                "- Keep severity/type/title unchanged (do not return them).\n"
                "- explanation: 1-3 sentences. What was observed, where it happened "
                "(use scan_context.where_observed), and why an IT reviewer should care.\n"
                "- recommendation: 1-2 sentences. Concrete next step (allow-list, "
                "remove tool, document claim, block host, re-scan, ask owner, etc.).\n"
                "- Ground every claim in the evidence pack. Do not invent hosts, paths, "
                "or capabilities that are not listed.\n"
                "- No markdown. No pricing.\n"
                f"EVIDENCE:\n{json.dumps(pack, default=str)}"
            ),
        }
    ]


def apply_finding_narratives(
    report: dict[str, Any], raw: dict[str, Any] | None
) -> dict[str, Any]:
    """Merge LLM explanation/recommendation onto findings; leave others untouched."""
    findings = list(report.get("findings") or [])
    if not findings or not isinstance(raw, dict):
        return report
    items = raw.get("findings")
    if not isinstance(items, list):
        return report
    by_id: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            continue
        fid = str(item.get("id") or "").strip()
        if not fid:
            continue
        by_id[fid] = item
    if not by_id:
        return report
    updated: list[dict[str, Any]] = []
    for finding in findings:
        fid = str(finding.get("id") or "")
        patch = by_id.get(fid)
        if not patch:
            updated.append(finding)
            continue
        row = dict(finding)
        explanation = _clip(patch.get("explanation"), 800)
        recommendation = _clip(patch.get("recommendation"), 400)
        if explanation:
            row["explanation"] = explanation
        if recommendation:
            row["recommendation"] = recommendation
        updated.append(row)
    out = dict(report)
    out["findings"] = updated
    return out


async def enrich_findings_narrative(llm: LlmClient, report: dict[str, Any]) -> dict[str, Any]:
    """Ask the LLM to rewrite finding copy. FixtureLlm / failures keep originals."""
    from runner.research import FixtureLlm

    findings = report.get("findings") or []
    if not findings:
        return report
    if isinstance(llm, FixtureLlm):
        return report
    messages = build_findings_prompt(report)
    try:
        raw = await llm.chat_json(messages)
        enriched = apply_finding_narratives(report, raw)
        if enriched is not report:
            log.info("findings narrative applied to %s finding(s)", len(findings))
        return enriched
    except Exception as exc:  # noqa: BLE001 — findings copy must not fail the scan
        log.warning("findings narrative LLM failed: %s", exc)
        return report
