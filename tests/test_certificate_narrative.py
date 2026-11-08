"""LLM certificate narrative (business use case + recommendations)."""

from __future__ import annotations

import pytest

from runner.certificate_narrative import (
    fixture_narrative,
    generate_certificate_narrative,
    normalize_narrative,
)
from runner.research import FixtureLlm


def test_normalize_narrative_clips_and_dedupes() -> None:
    out = normalize_narrative(
        {
            "business_summary": "  Serves agents.  ",
            "recommendations": ["A", "A", "B", ""],
        },
        source="llm",
    )
    assert out["business_summary"] == "Serves agents."
    assert out["recommendations"] == ["A", "B"]
    assert out["source"] == "llm"


@pytest.mark.asyncio
async def test_fixture_llm_generates_narrative() -> None:
    report = {
        "verdict": "clean",
        "repo": {"package": "demo-mcp"},
        "tools": [{"name": "echo", "privilege": "low", "verdict": "confirmed"}],
        "findings": [],
        "stats": {"tools": 1, "undocumented": 0, "decoy_reads": 0},
    }
    narrative = await generate_certificate_narrative(FixtureLlm(), report)
    assert narrative["business_summary"]
    assert narrative["recommendations"]
    assert narrative["source"] == "fixture"


def test_fixture_narrative_mentions_verdict() -> None:
    narrative = fixture_narrative({"verdict": "flagged", "repo": {}, "tools": []})
    assert "flagged" in narrative["business_summary"]
    assert any("untrusted" in r.lower() or "decoy" in r.lower() for r in narrative["recommendations"])
