"""Certificate content: business summary, recommendations, and tables."""

from __future__ import annotations

from datetime import UTC, datetime

from control_plane.certificate import build_certificate, render_html, render_pdf


def _report() -> dict:
    return {
        "verdict": "suspicious",
        "coverage": "full",
        "repo": {
            "url": "https://github.com/googleapis/genai-toolbox",
            "commit": "8d54da0",
            "package": "@toolbox-sdk/server",
            "language": "node",
            "workdir": "npm/server",
        },
        "stats": {
            "tools": 6,
            "undocumented": 4,
            "critical_tier": 1,
            "toxic_combos": 0,
            "egress_attempted": 0,
            "decoy_reads": 0,
            "oracle_findings": 2,
            "expectation_misses": 1,
            "research_profiled": 2,
            "research_total": 6,
        },
        "tools": [
            {"name": "execute_sql", "privilege": "critical", "verdict": "confirmed"},
            {"name": "list_tables", "privilege": "medium", "verdict": "confirmed"},
            {"name": "database_overview", "privilege": "low", "verdict": "confirmed"},
            {"name": "Function", "privilege": "low", "verdict": "not_observed"},
            {"name": "Setup", "privilege": "low", "verdict": "not_observed"},
        ],
        "findings": [
            {
                "id": "F1",
                "severity": "high",
                "type": "undocumented_tool",
                "tool": "execute_sql",
                "title": "`execute_sql` is not documented",
                "recommendation": "Document or remove execute_sql.",
            },
            {
                "id": "F2",
                "severity": "high",
                "type": "llm_oracle_decoy_read",
                "tool": "list_tables",
                "title": "Decoy file read",
                "recommendation": "Remove file access.",
            },
            {
                "id": "F3",
                "severity": "low",
                "type": "expectation_miss",
                "tool": "database_overview",
                "title": "Expected host miss",
            },
        ],
        "recipe": {
            "codegen": {
                "rationale": "Declare the postgres sidecar and probe with SELECT 1.",
            }
        },
        "least_privilege_config": {"allow_tools": ["list_tables"], "allow_hosts": []},
        "costs": {"actual": {"meters": {"provisioner": "vultr", "runtime": "runc"}}},
        "certificate": {
            "business_summary": (
                "This MCP server lets agents query and inspect a SQL database for "
                "operations and analytics workflows without a raw DB client."
            ),
            "recommendations": [
                "Gate execute_sql behind a read-only allowlist before production.",
                "Publish a real tool catalog in docs, then re-scan.",
            ],
            "source": "llm",
        },
    }


def test_certificate_adds_summary_recommendations_and_tables() -> None:
    now = datetime(2026, 11, 8, 15, 30, tzinfo=UTC)
    cert = build_certificate(
        "s_testcert",
        repo_url="https://github.com/googleapis/genai-toolbox",
        ref="main",
        created_at=now,
        updated_at=now,
        account_mode="toolpain",
        report=_report(),
        ticket="RITM9",
        verify_url="https://toolpain.com/verify/x",
    )
    assert "SQL database" in cert["business_summary"]
    assert cert["narrative_source"] == "llm"
    assert any("execute_sql" in r for r in cert["recommendations"])
    # Docs heading noise + uncorroborated oracle claims are deflated before the certificate.
    assert cert["verdict"] in {"clean", "suspicious", "over_privileged", "flagged"}
    assert not any(f.get("type", "").startswith("llm_oracle") for f in cert["findings"])
    assert "Function" not in {t["name"] for t in cert["tools"]}

    html = render_html(cert)
    assert "Business use case" in html
    assert "Recommended next steps" in html
    assert "Findings by type" in html
    assert "<table" in html
    assert "execute_sql" in html

    pdf = render_pdf(cert)
    assert pdf.startswith(b"%PDF")
    assert b"Business use case" in pdf
    assert b"Recommended next steps" in pdf
    assert b"Findings by type" in pdf
    assert b"RITM9" in pdf
