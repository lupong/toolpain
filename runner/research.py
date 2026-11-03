"""Research stage: one LLM-built profile per tool (claimed behavior, resources, risk).

* ``LLM_MODE=fake`` -> :class:`FakeLlm` / fixtures, fully deterministic and offline.
* ``LLM_MODE=live`` -> :class:`ControlPlaneLlm`, which posts to the control-plane proxy
  (``/internal/llm/chat``). The runner never holds the inference key.

Every LLM answer must be JSON that validates as :class:`ToolProfile`; one retry on failure,
then a heuristic fallback so the pipeline never stalls.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Literal, Protocol

import httpx
from pydantic import BaseModel, Field, ValidationError

from runner.models import DiscoveredTool, DiscoveryResult

FIXTURE_PATH = Path(__file__).resolve().parent / "fixtures" / "tool_profiles.json"
Risk = Literal["info", "low", "medium", "high", "critical"]


class ToolProfile(BaseModel):
    tool: str
    claimed_behavior: str | None = None
    resources: list[str] = Field(default_factory=list)
    downstream: list[str] = Field(default_factory=list)
    risk: Risk = "low"
    privilege_hint: Risk = "low"
    source: Literal["llm", "fixture", "heuristic"] = "heuristic"


class LlmClient(Protocol):
    async def chat_json(self, messages: list[dict[str, str]]) -> dict[str, Any]: ...


class FakeLlm:
    """Deterministic stand-in: serves fixtures by tool name, otherwise a heuristic profile."""

    def __init__(self, fixtures: dict[str, dict[str, Any]] | None = None) -> None:
        self.fixtures = fixtures if fixtures is not None else load_fixtures()

    async def chat_json(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        text = messages[-1]["content"]
        match = re.search(r"TOOL_NAME: (\S+)", text)
        name = match.group(1) if match else ""
        return dict(self.fixtures.get(name, {}))


class ControlPlaneLlm:
    """Calls the control-plane LLM proxy with the per-scan token."""

    def __init__(self, base_url: str, token: str, client: httpx.AsyncClient | None = None) -> None:
        self.base_url = base_url.rstrip("/")
        self._headers = {"X-Scan-Token": token}
        self._client = client or httpx.AsyncClient(timeout=60)

    async def chat_json(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        resp = await self._client.post(
            f"{self.base_url}/internal/llm/chat", json={"messages": messages}, headers=self._headers
        )
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, dict) else {}


def load_fixtures(path: Path = FIXTURE_PATH) -> dict[str, dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


def build_llm(mode: str, control_plane_url: str | None, token: str | None) -> LlmClient:
    if mode == "live" and control_plane_url and token:
        return ControlPlaneLlm(control_plane_url, token)
    return FakeLlm()


def heuristic_profile(tool: DiscoveredTool) -> ToolProfile:
    text = f"{tool.name} {tool.description}".lower()
    risk: Risk = "low"
    if re.search(r"\b(exec|eval|shell|command|script)", text):
        risk = "critical"
    elif re.search(r"\b(write|delete|upload|download|fetch|http|url|navigat|file)", text):
        risk = "high"
    return ToolProfile(
        tool=tool.name,
        claimed_behavior=tool.description or None,
        risk=risk,
        privilege_hint=risk,
        source="heuristic",
    )


def build_prompt(tool: DiscoveredTool, readme_text: str | None) -> list[dict[str, str]]:
    snippet = tool.static_hits[0].snippet[:3000] if tool.static_hits else ""
    user = (
        f"TOOL_NAME: {tool.name}\n"
        f"DESCRIPTION: {tool.description}\n"
        f"INPUT_SCHEMA: {json.dumps(tool.input_schema)[:1500]}\n"
        f"SOURCE:\n{snippet}\n"
        f"README (excerpt):\n{(readme_text or '')[:1500]}\n\n"
        "Return one JSON object with keys: claimed_behavior (string or null), resources "
        "(files/paths the code touches), downstream (hosts/services it talks to), "
        "risk and privilege_hint (each one of info|low|medium|high|critical)."
    )
    return [{"role": "user", "content": user}]


async def profile_tool(
    tool: DiscoveredTool, llm: LlmClient, readme_text: str | None = None
) -> ToolProfile:
    messages = build_prompt(tool, readme_text)
    for _ in range(2):  # one retry on parse/validation failure
        try:
            raw = await llm.chat_json(messages)
        except (httpx.HTTPError, ValueError):
            continue
        if not raw:
            break
        try:
            fixture = isinstance(llm, FakeLlm)
            return ToolProfile.model_validate(
                {**raw, "tool": tool.name, "source": "fixture" if fixture else "llm"}
            )
        except ValidationError:
            continue
    return heuristic_profile(tool)


async def research_tools(
    discovery: DiscoveryResult, llm: LlmClient, readme_text: str | None = None
) -> dict[str, ToolProfile]:
    return {t.name: await profile_tool(t, llm, readme_text) for t in discovery.tools}
