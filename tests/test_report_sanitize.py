"""Legacy report deflation for oracle/docs noise."""

from __future__ import annotations

from control_plane.certificate import build_certificate, report_hash
from control_plane.report_sanitize import sanitize_report
from datetime import UTC, datetime


def _noisy_report() -> dict:
    tools = [
        {
            "name": "execute_sql",
            "privilege": "critical",
            "verdict": "confirmed",
            "sources": ["R"],
            "decoy_reads": 0,
        },
        {
            "name": "list_tables",
            "privilege": "medium",
            "verdict": "confirmed",
            "sources": ["R"],
            "decoy_reads": 0,
        },
        {
            "name": "Function",
            "privilege": "low",
            "verdict": "not_observed",
            "sources": ["D"],
            "decoy_reads": 0,
        },
        {
            "name": "Setup",
            "privilege": "low",
            "verdict": "not_observed",
            "sources": ["D"],
            "decoy_reads": 0,
        },
    ]
    findings = [
        {
            "id": "F1",
            "severity": "high",
            "type": "undocumented_tool",
            "tool": "execute_sql",
            "title": "undocumented",
        },
        {
            "id": "F2",
            "severity": "high",
            "type": "llm_oracle_decoy_read",
            "tool": "list_tables",
            "title": "Decoy file read",
            "evidence": "[0]",
        },
        {
            "id": "F3",
            "severity": "low",
            "type": "documented_missing",
            "tool": "Function",
            "title": "missing",
        },
    ]
    return {
        "verdict": "suspicious",
        "coverage": "full",
        "repo": {"url": "https://github.com/example/db", "package": "db"},
        "stats": {
            "tools": 4,
            "undocumented": 2,
            "decoy_reads": 0,
            "egress_attempted": 0,
            "oracle_findings": 1,
        },
        "tools": tools,
        "findings": findings,
        "llm_oracle": [findings[1]],
        "least_privilege_config": {"allow_tools": ["Function"], "allow_hosts": []},
    }


def test_sanitize_drops_oracle_and_docs_noise_and_clears_verdict() -> None:
    cleaned = sanitize_report(_noisy_report())
    assert cleaned["verdict"] == "clean"
    assert cleaned["stats"]["undocumented"] == 0
    assert cleaned["stats"]["oracle_findings"] == 0
    assert {t["name"] for t in cleaned["tools"]} == {"execute_sql", "list_tables"}
    assert cleaned["findings"] == []


def test_certificate_uses_deflated_view_but_seals_original_hash() -> None:
    raw = _noisy_report()
    raw["certificate"] = {
        "business_summary": "Agents use this server for database tasks.",
        "recommendations": ["Apply the allowlist.", "Re-scan after changes."],
        "source": "llm",
    }
    now = datetime(2026, 11, 8, tzinfo=UTC)
    cert = build_certificate(
        "s_noise",
        repo_url="https://github.com/example/db",
        ref="main",
        created_at=now,
        updated_at=now,
        account_mode="toolpain",
        report=raw,
    )
    assert cert["verdict"] == "clean"
    assert cert["report_sha256"] == report_hash(raw)
    assert "database tasks" in cert["business_summary"]
    assert cert["severity"]["high"] == 0
    assert not any(f["type"] == "llm_oracle_decoy_read" for f in cert["findings"])
