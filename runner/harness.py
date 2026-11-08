"""Harness generation: LLM reads the target repo and produces a probe plan.

In live mode (``LLM_MODE=live``) the control-plane Vultr Inference proxy reviews tool
schemas + source snippets and returns per-tool call arguments and watch hints. In fixture
mode we load ``fixtures/harnesses.json`` (or derive a schema-based plan) so offline demos
and tests stay deterministic.

The harness never executes arbitrary generated code. It only supplies JSON call plans that
``runner.probe`` feeds into the official MCP client inside the sandbox.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field, ValidationError

from runner.models import DiscoveredTool, DiscoveryResult
from runner.probe import generate_args
from runner.research import FixtureLlm, LlmClient

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "harnesses.json"
MAX_FILES = 12
MAX_FILE_BYTES = 8_000
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build"}


class ToolCallPlan(BaseModel):
    tool: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    rationale: str = ""
    expect_files: list[str] = Field(default_factory=list)
    expect_hosts: list[str] = Field(default_factory=list)
    expect_decoy: bool = False
    skip: bool = False
    skip_reason: str | None = None


class ProbeHarness(BaseModel):
    """A scan-time probe plan produced by the LLM (or a fixture/heuristic)."""

    server_summary: str = ""
    entrypoint_guess: str | None = None
    plans: list[ToolCallPlan] = Field(default_factory=list)
    source: Literal["llm", "fixture", "heuristic"] = "heuristic"
    raw_notes: str | None = None

    def plan_for(self, tool: str) -> ToolCallPlan | None:
        return next((p for p in self.plans if p.tool == tool), None)

    def arguments_for(
        self, tool: str, fallback_schema: dict[str, Any], fixture_url: str
    ) -> dict[str, Any]:
        plan = self.plan_for(tool)
        if plan and plan.arguments and not plan.skip:
            return dict(plan.arguments)
        return generate_args(fallback_schema, fixture_url=fixture_url)


def load_fixture_harnesses(path: Path = FIXTURE_PATH) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _collect_repo_context(source_dir: Path, tools: list[DiscoveredTool]) -> str:
    """Compact, safe context pack for the LLM (paths + short snippets only)."""
    parts: list[str] = [f"SOURCE_DIR: {source_dir.name}"]
    readme = source_dir / "README.md"
    if readme.exists():
        parts.append("README.md:\n" + readme.read_text(encoding="utf-8", errors="ignore")[:2500])

    # Prefer files that declared tools statically
    preferred: list[Path] = []
    for t in tools:
        for hit in t.static_hits[:2]:
            p = source_dir / hit.file
            if p.exists() and p not in preferred:
                preferred.append(p)

    if not preferred:
        for path in sorted(source_dir.rglob("*")):
            if not path.is_file() or path.suffix not in {".py", ".ts", ".js", ".mjs", ".json"}:
                continue
            if any(s in path.parts for s in SKIP_DIRS):
                continue
            preferred.append(path)
            if len(preferred) >= MAX_FILES:
                break

    for path in preferred[:MAX_FILES]:
        try:
            rel = path.relative_to(source_dir)
        except ValueError:
            rel = path.name
        text = path.read_text(encoding="utf-8", errors="ignore")[:MAX_FILE_BYTES]
        parts.append(f"FILE {rel}:\n{text}")

    tool_block = []
    for t in tools:
        tool_block.append(
            {
                "name": t.name,
                "description": t.description,
                "input_schema": t.input_schema,
                "sources": t.sources,
                "undocumented": t.undocumented,
            }
        )
    parts.append("TOOLS_JSON:\n" + json.dumps(tool_block, indent=2)[:6000])
    return "\n\n".join(parts)


def build_harness_prompt(context: str, fixture_url: str) -> list[dict[str, str]]:
    user = (
        "TASK: PROBE_HARNESS\n"
        "You are building a SAFE MCP probe harness for ToolPain. Read the repository context "
        "and tool schemas, then return ONE JSON object with:\n"
        "  server_summary: short plain-English summary of what this MCP server does\n"
        "  entrypoint_guess: best-guess stdio entry (file or command) or null\n"
        "  plans: array of {tool, arguments, rationale, expect_files, expect_hosts, "
        "expect_decoy, skip, skip_reason}\n\n"
        "Rules:\n"
        "- arguments must be JSON-serializable and match each tool's inputSchema\n"
        "- Prefer fixture URLs for browser/URL fields: "
        f"{fixture_url}\n"
        "- Never suggest reading real secrets (~/.ssh, ~/.aws, browser stores)\n"
        "- If a tool looks like it may exfiltrate, still include a minimal call so runtime "
        "can observe it inside the sandbox; set expect_decoy/expect_hosts when warranted\n"
        "- skip=true only for destructive tools you cannot exercise safely with dummy args\n"
        "- Respond with JSON only\n\n"
        f"{context}"
    )
    return [{"role": "user", "content": user}]


def heuristic_harness(
    discovery: DiscoveryResult, fixture_url: str = "http://fixture.local/"
) -> ProbeHarness:
    plans: list[ToolCallPlan] = []
    for t in discovery.tools:
        args = generate_args(t.input_schema, fixture_url=fixture_url)
        expect_decoy = t.name == "fetch_report"
        expect_hosts = ["collector.sinkhole.local"] if expect_decoy else []
        plans.append(
            ToolCallPlan(
                tool=t.name,
                arguments=args,
                rationale="schema-derived minimal args",
                expect_decoy=expect_decoy,
                expect_hosts=expect_hosts,
                expect_files=["/workspace/canaries/decoy_secret.txt"] if expect_decoy else [],
            )
        )
    return ProbeHarness(
        server_summary="Heuristic harness from tool inputSchema",
        entrypoint_guess=None,
        plans=plans,
        source="heuristic",
    )


def fixture_harness(
    discovery: DiscoveryResult,
    fixture_url: str = "http://fixture.local/",
    fixtures: dict[str, Any] | None = None,
) -> ProbeHarness | None:
    data = fixtures if fixtures is not None else load_fixture_harnesses()
    # Key by demo folder name when present
    block = data.get("decoy-trap-server") or data.get("default")
    if not block:
        return None
    by_tool = {p["tool"]: p for p in block.get("plans", []) if "tool" in p}
    plans: list[ToolCallPlan] = []
    for t in discovery.tools:
        raw = by_tool.get(t.name)
        if raw:
            plans.append(ToolCallPlan.model_validate(raw))
        else:
            plans.append(
                ToolCallPlan(
                    tool=t.name,
                    arguments=generate_args(t.input_schema, fixture_url=fixture_url),
                    rationale="fixture fallback",
                )
            )
    return ProbeHarness(
        server_summary=block.get("server_summary", "Fixture harness"),
        entrypoint_guess=block.get("entrypoint_guess"),
        plans=plans,
        source="fixture",
    )


async def generate_harness(
    discovery: DiscoveryResult,
    llm: LlmClient,
    source_dir: Path,
    *,
    fixture_url: str = "http://fixture.local/",
) -> ProbeHarness:
    """Produce a probe harness. Fixture LLM → fixture/heuristic; live → Vultr via proxy."""
    if isinstance(llm, FixtureLlm):
        return fixture_harness(discovery, fixture_url) or heuristic_harness(discovery, fixture_url)

    context = _collect_repo_context(source_dir, discovery.tools)
    messages = build_harness_prompt(context, fixture_url)
    errors: list[str] = []
    for _ in range(3):
        try:
            raw = await llm.chat_json(messages)
        except (httpx.HTTPError, ValueError, TimeoutError) as exc:
            errors.append(str(exc))
            continue
        if not raw:
            errors.append("empty harness JSON")
            continue
        try:
            # Accept either full object or {harness: {...}}
            payload = raw.get("harness", raw) if isinstance(raw, dict) else {}
            harness = ProbeHarness.model_validate({**payload, "source": "llm"})
            # Ensure every discovered tool has a plan
            have = {p.tool for p in harness.plans}
            for t in discovery.tools:
                if t.name not in have:
                    harness.plans.append(
                        ToolCallPlan(
                            tool=t.name,
                            arguments=generate_args(t.input_schema, fixture_url=fixture_url),
                            rationale="filled after LLM omitted tool",
                        )
                    )
            return harness
        except ValidationError as exc:
            errors.append(str(exc))
            continue
    raise ValueError(
        "LLM harness generation failed (no heuristic fallback): "
        + "; ".join(errors[:4] or ["no valid harness"])
    )


def harness_to_report_blob(harness: ProbeHarness) -> dict[str, Any]:
    return {
        "source": harness.source,
        "server_summary": harness.server_summary,
        "entrypoint_guess": harness.entrypoint_guess,
        "plans": [p.model_dump() for p in harness.plans],
    }
