"""Part 1.7 sample report used by FakeProvisioner and seeded demos."""

from __future__ import annotations

from typing import Any


def sample_report(scan_id: str, repo_url: str | None = None) -> dict[str, Any]:
    repo = repo_url or "https://github.com/andrew/playwright-mcp"
    return {
        "scan_id": scan_id,
        "repo": {
            "url": repo,
            "commit": "a1b2c3d",
            "upstream": "microsoft/playwright-mcp",
            "fork_drift": [
                {
                    "change": "added_tool",
                    "tool": "fetch_report",
                    "file": "src/tools/report.ts",
                }
            ],
        },
        "verdict": "flagged",
        "stats": {
            "tools": 27,
            "undocumented": 1,
            "critical_tier": 3,
            "toxic_combos": 4,
            "egress_attempted": 2,
            "decoy_reads": 1,
        },
        "tools": [
            {
                "name": "browser_navigate",
                "privilege": "high",
                "verdict": "confirmed",
                "sources": ["D", "S", "R"],
                "egress": ["fixture.local"],
                "decoy_reads": 0,
                "claimed": "Navigate the browser to a URL",
                "observed": {
                    "files": [],
                    "processes": [],
                    "network": ["fixture.local"],
                },
                "evidence": [],
                "downstream": [],
            },
            {
                "name": "browser_evaluate",
                "privilege": "critical",
                "verdict": "confirmed",
                "sources": ["D", "S", "R"],
                "egress": [],
                "decoy_reads": 0,
                "claimed": "Evaluate JavaScript in the page",
                "observed": {"files": [], "processes": [], "network": []},
                "evidence": [],
                "downstream": [],
            },
            {
                "name": "browser_file_upload",
                "privilege": "high",
                "verdict": "exceeds_claim",
                "sources": ["D", "S", "R"],
                "egress": [],
                "decoy_reads": 0,
                "claimed": "Upload a file via a file chooser",
                "observed": {
                    "files": ["/tmp/upload.bin"],
                    "processes": [],
                    "network": [],
                },
                "evidence": ['openat("/tmp/upload.bin")'],
                "downstream": [],
            },
            {
                "name": "fetch_report",
                "privilege": "critical",
                "verdict": "flagged",
                "sources": ["S", "R"],
                "egress": ["collector.sinkhole.local"],
                "decoy_reads": 1,
                "claimed": None,
                "observed": {
                    "files": ["/workspace/canaries/decoy_secret.txt"],
                    "processes": [],
                    "network": ["collector.sinkhole.local:443"],
                },
                "evidence": [
                    'openat("/workspace/canaries/decoy_secret.txt") -> '
                    "connect collector.sinkhole.local:443 (contained by sinkhole)"
                ],
                "downstream": ["collector.sinkhole.local"],
            },
            {
                "name": "browser_click",
                "privilege": "low",
                "verdict": "confirmed",
                "sources": ["D", "S", "R"],
                "egress": [],
                "decoy_reads": 0,
                "claimed": "Click an element",
                "observed": {"files": [], "processes": [], "network": []},
                "evidence": [],
                "downstream": [],
            },
            {
                "name": "browser_pdf_save",
                "privilege": "medium",
                "verdict": "confirmed",
                "sources": ["D", "S", "F"],
                "egress": [],
                "decoy_reads": 0,
                "claimed": "Save page as PDF (capability flag)",
                "observed": {
                    "files": ["/tmp/page.pdf"],
                    "processes": [],
                    "network": [],
                },
                "evidence": [],
                "downstream": [],
            },
        ],
        "toxic_combos": [
            {
                "tools": ["browser_file_upload", "browser_navigate"],
                "risk": "exfiltration",
                "severity": "high",
                "why": "Upload plus navigate can move local data to a remote origin.",
            },
            {
                "tools": ["browser_evaluate", "browser_navigate"],
                "risk": "token_theft",
                "severity": "high",
                "why": "Evaluate can read tokens; navigate can exfiltrate them.",
            },
            {
                "tools": ["fetch_report", "browser_evaluate"],
                "risk": "credential_harvesting",
                "severity": "critical",
                "why": "Undocumented fetch plus eval can harvest planted secrets.",
            },
            {
                "tools": ["browser_pdf_save", "browser_file_upload"],
                "risk": "covert_channel",
                "severity": "medium",
                "why": "Shared filesystem artifacts can bridge tool boundaries.",
            },
        ],
        "findings": [
            {
                "id": "F1",
                "severity": "critical",
                "type": "decoy_read_and_egress",
                "tool": "fetch_report",
                "title": (
                    "Undocumented tool read a planted decoy and attempted an undeclared connection"
                ),
                "evidence": (
                    'openat("/workspace/canaries/decoy_secret.txt") -> '
                    "connect collector.sinkhole.local:443 (contained by sinkhole)"
                ),
                "explanation": (
                    "fetch_report opened the planted decoy and tried to reach "
                    "collector.sinkhole.local. Contained by the sinkhole."
                ),
                "recommendation": "Remove fetch_report; block undeclared hosts.",
            },
            {
                "id": "F2",
                "severity": "high",
                "type": "fork_added_tool",
                "tool": "fetch_report",
                "title": "Tool not present upstream",
                "evidence": "src/tools/report.ts added vs microsoft/playwright-mcp",
                "explanation": "Fork introduced fetch_report; upstream has no such tool.",
                "recommendation": "Diff the fork; drop undocumented tools before use.",
            },
            {
                "id": "F3",
                "severity": "medium",
                "type": "hidden_behind_flag",
                "tool": "browser_pdf_save",
                "title": "Tool only appears with a capability flag",
                "evidence": "Present in runtime+flags (F), absent in default runtime (R)",
                "explanation": "browser_pdf_save is gated; default discovery misses it.",
                "recommendation": "Document capability flags; include them in allowlists.",
            },
        ],
        "egress": {
            "declared": [],
            "attempted": [
                {
                    "host": "collector.sinkhole.local",
                    "tool": "fetch_report",
                    "blocked": True,
                },
                {
                    "host": "cdn.thirdparty.local",
                    "tool": "browser_navigate",
                    "blocked": True,
                },
            ],
        },
        "ingress": [],
        "least_privilege_config": {
            "allow_tools": [
                "browser_navigate",
                "browser_snapshot",
                "browser_click",
                "browser_type",
            ],
            "allow_hosts": ["your-app.example"],
        },
        "graph": {
            "nodes": [
                {"data": {"id": "server", "label": "MCP server", "kind": "server"}},
                {
                    "data": {
                        "id": "fetch_report",
                        "label": "fetch_report",
                        "kind": "tool",
                        "flagged": True,
                    }
                },
                {
                    "data": {
                        "id": "browser_navigate",
                        "label": "browser_navigate",
                        "kind": "tool",
                    }
                },
                {"data": {"id": "cap_files", "label": "local files", "kind": "cap"}},
                {
                    "data": {
                        "id": "host_sink",
                        "label": "collector.sinkhole.local",
                        "kind": "host",
                        "blocked": True,
                    }
                },
                {"data": {"id": "decoy", "label": "decoy_secret.txt", "kind": "decoy"}},
            ],
            "edges": [
                {
                    "data": {
                        "id": "e1",
                        "source": "server",
                        "target": "fetch_report",
                        "kind": "member",
                    }
                },
                {
                    "data": {
                        "id": "e2",
                        "source": "server",
                        "target": "browser_navigate",
                        "kind": "member",
                    }
                },
                {
                    "data": {
                        "id": "e3",
                        "source": "fetch_report",
                        "target": "decoy",
                        "kind": "observed",
                    }
                },
                {
                    "data": {
                        "id": "e4",
                        "source": "fetch_report",
                        "target": "host_sink",
                        "kind": "blocked",
                    }
                },
                {
                    "data": {
                        "id": "e5",
                        "source": "fetch_report",
                        "target": "cap_files",
                        "kind": "observed",
                    }
                },
            ],
        },
    }


DEMO_REPOS = {
    "server-filesystem": {
        "repo_url": "https://github.com/modelcontextprotocol/servers",
        "ref": "main",
        "verdict": "clean",
    },
    "playwright-mcp": {
        "repo_url": "https://github.com/microsoft/playwright-mcp",
        "ref": "main",
        "verdict": "over_privileged",
    },
    "decoy-trap-server": {
        "repo_url": "https://github.com/lupong/toolpain",
        "ref": "main",
        "verdict": "flagged",
    },
}
