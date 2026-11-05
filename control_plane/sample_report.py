"""Part 1.7 sample report used by FakeProvisioner and seeded demos."""

from __future__ import annotations

from typing import Any


def sample_report(
    scan_id: str, repo_url: str | None = None, demo: str | None = None
) -> dict[str, Any]:
    """Return the demo report that matches ``demo``, or the flagged decoy report."""
    if demo == "server-filesystem":
        return filesystem_report(scan_id, repo_url)
    if demo == "playwright-mcp":
        return over_privileged_report(scan_id, repo_url)
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


def _tool(
    name: str,
    privilege: str,
    verdict: str,
    claimed: str,
    sources: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "name": name,
        "privilege": privilege,
        "verdict": verdict,
        "sources": sources or ["D", "S", "R"],
        "egress": [],
        "decoy_reads": 0,
        "claimed": claimed,
        "observed": {"files": [], "processes": [], "network": []},
        "evidence": [],
        "downstream": [],
    }


def _member_graph(label: str, tool_names: list[str]) -> dict[str, Any]:
    nodes: list[dict[str, Any]] = [{"data": {"id": "server", "label": label, "kind": "server"}}]
    edges: list[dict[str, Any]] = []
    for i, name in enumerate(tool_names, start=1):
        nodes.append({"data": {"id": name, "label": name, "kind": "tool", "privilege": "low"}})
        edges.append(
            {"data": {"id": f"e{i}", "source": "server", "target": name, "kind": "member"}}
        )
    return {"nodes": nodes, "edges": edges}


_FS_TOOLS = [
    ("read_file", "low", "Read a file inside the allowed directories"),
    ("read_multiple_files", "low", "Read several files inside the allowed directories"),
    ("write_file", "medium", "Write a file inside the allowed directories"),
    ("edit_file", "medium", "Apply a patch inside the allowed directories"),
    ("create_directory", "low", "Create a directory inside the allowed directories"),
    ("list_directory", "low", "List a directory inside the allowed directories"),
    ("directory_tree", "low", "Show a directory tree inside the allowed directories"),
    ("move_file", "medium", "Move or rename a file inside the allowed directories"),
    ("search_files", "low", "Search for files inside the allowed directories"),
    ("get_file_info", "low", "Read metadata for a file inside the allowed directories"),
    ("list_allowed_directories", "low", "List the directories this server is allowed to touch"),
]


def filesystem_report(scan_id: str, repo_url: str | None = None) -> dict[str, Any]:
    """Clean official filesystem server. No Playwright tools, no undocumented tools."""
    repo = repo_url or DEMO_REPOS["server-filesystem"]["repo_url"]
    tools = [_tool(name, priv, "confirmed", claimed) for name, priv, claimed in _FS_TOOLS]
    allow = [name for name, priv, _claimed in _FS_TOOLS if priv == "low"]
    return {
        "scan_id": scan_id,
        "repo": {
            "url": repo,
            "commit": "c4e1a90",
            "upstream": "modelcontextprotocol/servers",
            "fork_drift": [],
        },
        "verdict": "clean",
        "stats": {
            "tools": len(tools),
            "undocumented": 0,
            "critical_tier": 0,
            "toxic_combos": 0,
            "egress_attempted": 0,
            "decoy_reads": 0,
        },
        "tools": tools,
        "toxic_combos": [],
        "findings": [],
        "egress": {"declared": [], "attempted": []},
        "ingress": [],
        "least_privilege_config": {"allow_tools": allow, "allow_hosts": []},
        "graph": _member_graph("server-filesystem", [t["name"] for t in tools]),
    }


def over_privileged_report(scan_id: str, repo_url: str | None = None) -> dict[str, Any]:
    """Upstream Playwright: powerful tools, no decoy and no undocumented fetch_report."""
    repo = repo_url or DEMO_REPOS["playwright-mcp"]["repo_url"]
    report = sample_report(scan_id, repo)
    report["verdict"] = "over_privileged"
    report["repo"]["upstream"] = "microsoft/playwright-mcp"
    report["repo"]["fork_drift"] = []
    report["tools"] = [t for t in report["tools"] if t["name"] != "fetch_report"]
    for tool in report["tools"]:
        tool["decoy_reads"] = 0
        if tool["name"] == "browser_navigate":
            tool["egress"] = ["fixture.local"]
            tool["verdict"] = "confirmed"
        if tool["name"] == "browser_file_upload":
            tool["verdict"] = "exceeds_claim"
    report["findings"] = [
        {
            "id": "F1",
            "severity": "high",
            "type": "description_mismatch",
            "tool": "browser_file_upload",
            "title": "Upload reads outside the directory it claims",
            "evidence": 'openat("/tmp/upload.bin")',
            "explanation": (
                "browser_file_upload opened a path outside the upload directory "
                "its description allows."
            ),
            "recommendation": "Scope uploads to one directory, or drop browser_file_upload.",
        },
        {
            "id": "F2",
            "severity": "medium",
            "type": "hidden_behind_flag",
            "tool": "browser_pdf_save",
            "title": "Tool only appears with a capability flag",
            "evidence": "Present with --caps=pdf, absent from the default tool list",
            "explanation": (
                "browser_pdf_save stays hidden until the server starts with --caps=pdf."
            ),
            "recommendation": "Start the server with only the flags you intend to expose.",
        },
    ]
    report["toxic_combos"] = [c for c in report["toxic_combos"] if "fetch_report" not in c["tools"]]
    report["egress"] = {"declared": ["your-app.example"], "attempted": []}
    names = [t["name"] for t in report["tools"]]
    report["stats"] = {
        "tools": len(names),
        "undocumented": 0,
        "critical_tier": sum(1 for t in report["tools"] if t["privilege"] == "critical"),
        "toxic_combos": len(report["toxic_combos"]),
        "egress_attempted": 0,
        "decoy_reads": 0,
    }
    report["least_privilege_config"] = {
        "allow_tools": ["browser_navigate", "browser_snapshot", "browser_click", "browser_type"],
        "allow_hosts": ["your-app.example"],
    }
    report["graph"] = _member_graph("playwright-mcp", names)
    return report


def report_for_demo(demo: str | None, scan_id: str, repo_url: str | None = None) -> dict[str, Any]:
    """Pick the seeded/fake report that matches the demo's verdict."""
    return sample_report(scan_id, repo_url, demo=demo)


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
