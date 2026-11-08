"""Fill missing certificate narrative via the control-plane LLM (legacy scans)."""

from __future__ import annotations

import logging
from typing import Any

from control_plane.config import Settings
from control_plane.llm import chat_json
from runner.certificate_narrative import (
    build_narrative_prompt,
    fixture_narrative,
    normalize_narrative,
)

log = logging.getLogger("toolpain.certificate_narrative")


def _has_narrative(report: dict[str, Any]) -> bool:
    block = report.get("certificate")
    if not isinstance(block, dict):
        return False
    summary = str(block.get("business_summary") or "").strip()
    recs = block.get("recommendations")
    return bool(summary) and isinstance(recs, list) and bool(recs)


async def ensure_report_narrative(settings: Settings, report: dict[str, Any]) -> dict[str, Any]:
    """Return a report copy that includes LLM certificate narrative when missing."""
    if _has_narrative(report):
        return report
    try:
        raw = await chat_json(settings, build_narrative_prompt(report))
        narrative = normalize_narrative(raw, source="llm")
        if not narrative["business_summary"] or not narrative["recommendations"]:
            raise ValueError("incomplete narrative")
    except Exception as exc:  # noqa: BLE001 — certificate must still render
        log.warning("on-demand certificate narrative failed: %s", exc)
        narrative = fixture_narrative(report)
        narrative["source"] = "fallback"
    out = dict(report)
    out["certificate"] = narrative
    return out
