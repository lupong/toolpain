"""Research stage: one LLM-built profile per tool (claimed behavior, resources, risk).

* ``LLM_MODE=fake`` -> :class:`FakeLlm` / fixtures, fully deterministic and offline.
* ``LLM_MODE=ollama`` / ``local`` -> Ollama OpenAI-compatible API (direct or via control plane).
* ``LLM_MODE=live`` -> :class:`ControlPlaneLlm`, which posts to the control-plane proxy
  (``/internal/llm/chat``). Vultr key stays on the control plane.

Every LLM answer must be JSON that validates as :class:`ToolProfile`; one retry on failure,
then a heuristic fallback so the pipeline never stalls.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Literal, Protocol

import httpx
from pydantic import BaseModel, Field, ValidationError

from control_plane.llm import (
    _extract_json,
    _is_executable_codegen_request,
    _is_harness_request,
    _is_recipe_request,
    _is_workdir_pick_request,
)
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
        if "PROBE_HARNESS" in text:
            # Harness generation short-circuits in runner.harness for FakeLlm;
            # this branch keeps the proxy-shaped contract for direct callers.
            from runner.harness import load_fixture_harnesses

            block = load_fixture_harnesses().get("decoy-trap-server") or {}
            return {
                "server_summary": block.get("server_summary", "fake harness"),
                "entrypoint_guess": block.get("entrypoint_guess"),
                "plans": block.get("plans", []),
            }
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


class DirectOpenAILlm:
    """CLI fallback: talk to an OpenAI-compatible endpoint without the control plane.

    Used for ``LLM_MODE=ollama`` when scanning without a scan token (local one-shots).
    """

    def __init__(
        self,
        base_url: str,
        api_key: str,
        model: str,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self._client = client or httpx.AsyncClient(timeout=120)

    async def chat_json(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        want_harness = _is_harness_request(messages)
        want_recipe = _is_recipe_request(messages)
        want_exec = _is_executable_codegen_request(messages)
        want_workdir = _is_workdir_pick_request(messages)
        if want_harness:
            system = (
                "You generate SAFE MCP probe harnesses as a single JSON object. "
                "No markdown fences. Keys: server_summary, entrypoint_guess, plans "
                "(array of {tool, arguments, rationale, expect_files, expect_hosts, "
                "expect_decoy, skip, skip_reason}). Never suggest reading real secret paths."
            )
        elif want_exec:
            system = (
                "You generate ToolPain executable scan artifacts as one JSON object. "
                "Keys: launch_sh, probe_py (build_plans + optional next_plans), "
                "oracle_py (review_observations), rationale. No markdown. "
                "Python: no os/sys/subprocess/socket/open/eval. Honor USER_SCAN_BRIEF."
            )
        elif want_workdir:
            system = (
                "You generate a ToolPain workdir picker as one JSON object. "
                "Keys: workdir_pick_py (def pick_workdir(candidates, tree_summary)), "
                "rationale. No markdown. Honor USER_SCAN_BRIEF."
            )
        elif want_recipe:
            system = (
                "You choose SAFE ToolPain scan build/launch settings as one JSON object. "
                "No markdown. Keys: language, install_argv, apt_packages, launch_candidates, "
                "rationale. Never emit Dockerfile bodies."
            )
        else:
            system = "Respond with a single JSON object only. No markdown."
        payload = {
            "model": self.model,
            "temperature": 0,
            "messages": [{"role": "system", "content": system}, *messages],
        }
        resp = await self._client.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json=payload,
        )
        resp.raise_for_status()
        content = resp.json()["choices"][0]["message"]["content"] or "{}"
        parsed = _extract_json(content)
        if parsed is None:
            raise ValueError("model did not return JSON object")
        return parsed


def build_llm(mode: str, control_plane_url: str | None, token: str | None) -> LlmClient:
    mode = (mode or "fake").lower()
    if mode in {"live", "ollama", "local", "openai"} and control_plane_url and token:
        return ControlPlaneLlm(control_plane_url, token)
    if mode == "openai":
        key = os.environ.get("OPENAI_API_KEY")
        if not key:
            return FakeLlm()
        return DirectOpenAILlm(
            base_url=os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1"),
            api_key=key,
            model=os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
        )
    if mode in {"ollama", "local"}:
        return DirectOpenAILlm(
            base_url=os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434/v1"),
            api_key=os.environ.get("OLLAMA_API_KEY", "ollama"),
            model=os.environ.get("OLLAMA_MODEL", "llama3.2:latest"),
        )
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
    cap = int(os.environ.get("TOOLPAIN_MAX_PROFILES") or "40")
    tools = list(discovery.tools)[: max(1, cap)]
    return {t.name: await profile_tool(t, llm, readme_text) for t in tools}
