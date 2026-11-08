"""LLM-written certificate narrative: business use case + next-step recommendations.

Runs once per scan after findings are final. Output is stored on the report and
rendered into the HTML/PDF certificate. Heuristic repo-specific copy is not used
for live scans.
"""

from __future__ import annotations

import logging
import re
from typing import Any, Protocol

log = logging.getLogger("toolpain.certificate_narrative")


class LlmClient(Protocol):
    async def chat_json(self, messages: list[dict[str, str]]) -> dict[str, Any]: ...

TASK_MARKER = "TASK: CERTIFICATE_NARRATIVE"

# Kept in runner/ so scanner hot-sync does not depend on a rebaked control_plane.llm.
FIXTURE_CERTIFICATE_NARRATIVE = {
    "business_summary": (
        "This MCP server exposes tools for an AI agent or client application. "
        "Fixture-mode narrative — live scans use the LLM for certificate copy."
    ),
    "recommendations": [
        "Review findings and apply the least-privilege allowlist before production use.",
        "Re-scan after any tool, dependency, or docs change.",
    ],
}


def _clip(text: object, limit: int) -> str:
    value = re.sub(r"\s+", " ", str(text or "")).strip()
    if len(value) <= limit:
        return value
    return value[: limit - 1].rstrip() + "…"


def evidence_pack(report: dict[str, Any]) -> dict[str, Any]:
    """Compact, non-secret evidence the model may use for the certificate."""
    from runner.findings_narrative import SCAN_CONTEXT

    repo = report.get("repo") or {}
    stats = report.get("stats") or {}
    tools = report.get("tools") or []
    findings = report.get("findings") or []
    harness = report.get("harness") or {}
    launch = report.get("launch") or {}
    recipe = ((report.get("recipe") or {}).get("codegen") or {})
    return {
        "verdict": report.get("verdict"),
        "scan_context": SCAN_CONTEXT,
        "repo": {
            "url": repo.get("url"),
            "package": repo.get("package"),
            "language": repo.get("language"),
            "workdir": repo.get("workdir"),
        },
        "stats": {
            "tools": stats.get("tools"),
            "undocumented": stats.get("undocumented"),
            "critical_tier": stats.get("critical_tier"),
            "toxic_combos": stats.get("toxic_combos"),
            "egress_attempted": stats.get("egress_attempted"),
            "decoy_reads": stats.get("decoy_reads"),
            "oracle_findings": stats.get("oracle_findings"),
            "expectation_misses": stats.get("expectation_misses"),
            "research_profiled": stats.get("research_profiled"),
            "research_total": stats.get("research_total"),
        },
        "tools": [
            {
                "name": t.get("name"),
                "privilege": t.get("privilege"),
                "verdict": t.get("verdict"),
                "sources": t.get("sources"),
                "claimed": _clip(t.get("claimed"), 160),
                "capabilities": list(t.get("capabilities") or [])[:10],
            }
            for t in tools[:40]
        ],
        "findings": [
            {
                "severity": f.get("severity"),
                "type": f.get("type"),
                "tool": f.get("tool"),
                "title": _clip(f.get("title"), 160),
                "explanation": _clip(f.get("explanation"), 280),
                "recommendation": _clip(f.get("recommendation"), 200),
            }
            for f in findings[:30]
        ],
        "harness_summary": _clip(harness.get("server_summary"), 300),
        "launch": {
            "source": launch.get("source"),
            "rationale": _clip(launch.get("rationale"), 240),
        },
        "codegen_rationale": _clip(recipe.get("rationale"), 240),
        "least_privilege_config": report.get("least_privilege_config") or {},
        "egress_declared": (report.get("egress") or {}).get("declared") or [],
    }


def build_narrative_prompt(report: dict[str, Any]) -> list[dict[str, str]]:
    import json

    pack = evidence_pack(report)
    return [
        {
            "role": "user",
            "content": (
                f"{TASK_MARKER}\n"
                "Write the ToolPain scan certificate narrative for an IT / security reviewer.\n"
                "Return one JSON object with keys:\n"
                "  business_summary: 2-4 sentences. What this MCP server is for from a "
                "business / product use-case perspective (who benefits, what job it does). "
                "Do not invent vendors or customers. Ground claims in the evidence pack. "
                "Do not paste raw package paths as the whole answer.\n"
                "  recommendations: array of 3-8 short, ranked next actions the operator "
                "should take given the verdict and findings. Be concrete and actionable "
                "(approve, allow-list tools/hosts, ask owner to document, block, re-scan). "
                "Use scan_context so recommendations reflect where behavior was observed "
                "(MCP server sandbox, not the end-user laptop). If the scan is clean, "
                "say what to keep / when to re-scan.\n"
                "No markdown. No rate-card or pricing talk.\n"
                f"EVIDENCE:\n{json.dumps(pack, default=str)}"
            ),
        }
    ]


def normalize_narrative(raw: dict[str, Any] | None, *, source: str) -> dict[str, Any]:
    data = raw if isinstance(raw, dict) else {}
    summary = _clip(data.get("business_summary"), 1200)
    recs_raw = data.get("recommendations")
    recommendations: list[str] = []
    if isinstance(recs_raw, list):
        for item in recs_raw:
            text = _clip(item, 400)
            if text and text not in recommendations:
                recommendations.append(text)
            if len(recommendations) >= 10:
                break
    elif isinstance(recs_raw, str) and recs_raw.strip():
        recommendations.append(_clip(recs_raw, 400))
    return {
        "business_summary": summary,
        "recommendations": recommendations,
        "source": source,
    }


def fixture_narrative(report: dict[str, Any]) -> dict[str, Any]:
    """Deterministic offline narrative for FixtureLlm / tests — not live scans."""
    verdict = report.get("verdict") or "unknown"
    tools = report.get("tools") or []
    names = [str(t.get("name") or "") for t in tools if t.get("name")][:8]
    package = ((report.get("repo") or {}).get("package")) or "this MCP server"
    summary = (
        f"{package} exposes MCP tools for an AI agent or client application"
        + (f" (including {', '.join(names)})." if names else ".")
        + f" This fixture-mode scan finished with verdict `{verdict}`."
    )
    recommendations = [
        "Review the findings table and apply the least-privilege allowlist before production use.",
        "Re-scan after any tool, dependency, or docs change.",
    ]
    if verdict == "flagged":
        recommendations.insert(
            0,
            "Do not expose this server to untrusted agents until decoy/egress findings are remediated.",
        )
    elif verdict == "suspicious":
        recommendations.insert(
            0,
            "Investigate undocumented or unexpected tools before approving this server.",
        )
    return normalize_narrative(
        {"business_summary": summary, "recommendations": recommendations},
        source="fixture",
    )


async def generate_certificate_narrative(
    llm: LlmClient,
    report: dict[str, Any],
) -> dict[str, Any]:
    """Ask the LLM for certificate copy. FixtureLlm stays offline; live fails soft."""
    # Late import avoids research ↔ certificate_narrative cycles on scanners.
    from runner.research import FixtureLlm

    if isinstance(llm, FixtureLlm):
        return fixture_narrative(report)
    messages = build_narrative_prompt(report)
    try:
        raw = await llm.chat_json(messages)
        narrative = normalize_narrative(raw, source="llm")
        if narrative["business_summary"] and narrative["recommendations"]:
            return narrative
        log.warning("certificate narrative incomplete; using fixture-shaped fallback")
    except Exception as exc:  # noqa: BLE001 — narrative must not fail the scan
        log.warning("certificate narrative LLM failed: %s", exc)
    fallback = fixture_narrative(report)
    fallback["source"] = "fallback"
    return fallback
