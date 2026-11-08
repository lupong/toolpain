"""IT-facing LLM finding explanation / recommendation rewrite."""

from __future__ import annotations

import pytest

from runner.findings_narrative import (
    SCAN_CONTEXT,
    apply_finding_narratives,
    build_findings_prompt,
    enrich_findings_narrative,
    evidence_pack,
)
from runner.research import FixtureLlm


def test_evidence_pack_includes_scan_context_and_observed() -> None:
    report = {
        "verdict": "over_privileged",
        "repo": {"package": "demo-mcp", "url": "https://github.com/ex/demo"},
        "tools": [
            {
                "name": "comment_create",
                "claimed": "Create a Confluence comment",
                "verdict": "exceeds_claim",
                "capabilities": ["file_write", "network"],
                "observed": {
                    "files": ["/tmp/temp.md"],
                    "network": ["api.atlassian.com"],
                    "processes": [],
                },
            }
        ],
        "findings": [
            {
                "id": "F1",
                "severity": "high",
                "type": "description_mismatch",
                "tool": "comment_create",
                "title": "`comment_create` does more than it claims",
                "explanation": "Claimed: network. Observed: file_write.",
                "recommendation": "Verify the tool is intended.",
                "evidence": "tools.py",
            }
        ],
        "least_privilege_config": {"allow_tools": []},
    }
    pack = evidence_pack(report)
    assert pack["scan_context"] == SCAN_CONTEXT
    assert "MCP server" in pack["scan_context"]["where_observed"]
    assert pack["findings"][0]["tool_observed"]["files"] == ["/tmp/temp.md"]
    prompt = build_findings_prompt(report)
    assert "FINDINGS_NARRATIVE" in prompt[0]["content"]
    assert "IT" in prompt[0]["content"]


def test_apply_finding_narratives_merges_by_id() -> None:
    report = {
        "findings": [
            {
                "id": "F1",
                "title": "t",
                "explanation": "old",
                "recommendation": "old-rec",
            }
        ]
    }
    out = apply_finding_narratives(
        report,
        {
            "findings": [
                {
                    "id": "F1",
                    "explanation": "Server wrote a temp file in the sandbox while calling the API.",
                    "recommendation": "Ask the owner to document temp-file use; keep allow-list tight.",
                }
            ]
        },
    )
    assert "sandbox" in out["findings"][0]["explanation"]
    assert "allow-list" in out["findings"][0]["recommendation"]
    assert out["findings"][0]["title"] == "t"


@pytest.mark.asyncio
async def test_fixture_llm_leaves_findings_unchanged() -> None:
    report = {
        "findings": [
            {
                "id": "F1",
                "explanation": "heuristic",
                "recommendation": "check it",
            }
        ],
        "tools": [],
    }
    out = await enrich_findings_narrative(FixtureLlm(), report)
    assert out["findings"][0]["explanation"] == "heuristic"
