"""Research stage: one LLM-built profile per tool (claimed behavior, resources, risk).

* ``LLM_MODE=fixture`` -> :class:`FixtureLlm` / fixtures, fully deterministic and offline.
* ``LLM_MODE=ollama`` / ``local`` -> local Ollama (direct or via control plane).
* ``LLM_MODE=live`` -> :class:`ControlPlaneLlm`, which posts to the control-plane proxy
  (``/internal/llm/chat``). Vultr Inference key stays on the control plane.

Every LLM answer must be JSON that validates as :class:`ToolProfile`; one retry on failure,
then fail closed on live LLMs (FixtureLlm may use a local heuristic for tests).
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


class FixtureLlm:
    """Deterministic stand-in: serves fixtures by tool name, otherwise a heuristic profile."""

    def __init__(self, fixtures: dict[str, dict[str, Any]] | None = None) -> None:
        self.fixtures = fixtures if fixtures is not None else load_fixtures()

    async def chat_json(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        text = messages[-1]["content"]
        if "CERTIFICATE_NARRATIVE" in text:
            # Lazy import: avoids circular import with certificate_narrative.
            from runner.certificate_narrative import FIXTURE_CERTIFICATE_NARRATIVE

            return dict(FIXTURE_CERTIFICATE_NARRATIVE)
        if "FINDINGS_NARRATIVE" in text:
            # Live mode rewrites findings; fixture keeps heuristic copy (empty patch).
            return {"findings": []}
        if "PROBE_HARNESS" in text:
            # Harness generation short-circuits in runner.harness for FixtureLlm;
            # this branch keeps the proxy-shaped contract for direct callers.
            from runner.harness import load_fixture_harnesses

            block = load_fixture_harnesses().get("decoy-trap-server") or {}
            return {
                "server_summary": block.get("server_summary", "fixture harness"),
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
        blob = " ".join(m.get("content", "") for m in messages)
        if "TOOL_NAME:" in blob or "claimed_behavior" in blob:
            kind = "research"
        elif "CERTIFICATE_NARRATIVE" in blob or "FINDINGS_NARRATIVE" in blob:
            kind = "research"
        elif any(
            marker in blob
            for marker in (
                "EXECUTABLE_SCAN_CODE",
                "WORKDIR_PICK_CODE",
                "PROBE_HARNESS",
                "SCAN_RECIPE",
            )
        ):
            kind = "codegen"
        else:
            kind = "research"
        resp = await self._client.post(
            f"{self.base_url}/internal/llm/chat",
            json={"messages": messages, "kind": kind, "schema_hint": kind},
            headers=self._headers,
        )
        resp.raise_for_status()
        data = resp.json()
        return data if isinstance(data, dict) else {}


def load_fixtures(path: Path = FIXTURE_PATH) -> dict[str, dict[str, Any]]:
    return json.loads(path.read_text(encoding="utf-8"))


class DirectChatLlm:
    """CLI fallback: talk to a local chat-completions endpoint without the control plane.

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
        blob = " ".join(m.get("content", "") for m in messages)
        want_cert = "CERTIFICATE_NARRATIVE" in blob
        want_findings = "FINDINGS_NARRATIVE" in blob
        if want_findings:
            system = (
                "You rewrite ToolPain findings for IT reviewers as one JSON object. "
                "Keys: findings (array of {id, explanation, recommendation}). "
                "Use scan_context: observations are of the MCP server sandbox, not the "
                "client laptop. No markdown. No pricing."
            )
        elif want_cert:
            system = (
                "You write ToolPain scan certificate narratives as one JSON object. "
                "Keys: business_summary, recommendations. No markdown. No pricing. "
                "Use scan_context so locality of observations is clear to IT reviewers."
            )
        elif want_harness:
            system = (
                "You generate SAFE MCP probe harnesses as a single JSON object. "
                "No markdown fences. Keys: server_summary, entrypoint_guess, plans "
                "(array of {tool, arguments, rationale, expect_files, expect_hosts, "
                "expect_decoy, skip, skip_reason}). Never suggest reading real secret paths."
            )
        elif want_exec:
            system = (
                "You generate ToolPain executable scan artifacts as one JSON object. "
                "Keys: setup_sh (one command per line, builds the repo), "
                "launch_sh, probe_py (build_plans + optional next_plans), "
                "oracle_py (review_observations), rationale. No markdown. "
                "Python: no os/sys/subprocess/socket/open/eval. The fixture answers every path. "
                "Do not emit a finding only because a tool returned an error or an HTTP status. "
                "Honor USER_SCAN_BRIEF."
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
    """Pick an LLM client.

    Authenticated scanner runs (control-plane URL + scan token) always use the
    CP proxy unless ``mode`` is explicitly ``fixture`` / ``off`` (local demos/tests).

    Configured modes never silently degrade to :class:`FixtureLlm` — that would look
    like a live scan while serving templates.
    """
    mode = (mode or "fixture").lower()
    if control_plane_url and token and mode not in {"fixture", "off"}:
        return ControlPlaneLlm(control_plane_url, token)
    if mode in {"ollama", "local"}:
        return DirectChatLlm(
            base_url=os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434/v1"),
            api_key=os.environ.get("OLLAMA_API_KEY", "ollama"),
            model=os.environ.get("OLLAMA_MODEL", "llama3.2:latest"),
        )
    if mode in {"live"}:
        raise RuntimeError(
            "LLM_MODE=live requires CONTROL_PLANE_URL + scan token "
            "(refusing FixtureLlm fallback)"
        )
    if mode not in {"fixture", "off", ""}:
        raise RuntimeError(f"Unknown LLM_MODE={mode!r} (refusing FixtureLlm fallback)")
    return FixtureLlm()


def default_llm_mode(*, control_plane_url: str | None, token: str | None) -> str:
    """Env ``LLM_MODE``, else ``live`` when talking to a CP.

    Without a CP, operators must set ``LLM_MODE`` explicitly — we no longer
    default to fixture (that hid missing config).
    """
    env = (os.environ.get("LLM_MODE") or "").strip().lower()
    if env:
        return env
    if control_plane_url and token:
        return "live"
    raise RuntimeError(
        "LLM_MODE is unset and no control-plane URL+token were provided. "
        "Set LLM_MODE=live|ollama (or fixture only for offline tests)."
    )


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
    errors: list[str] = []
    for _ in range(3):  # retries on parse/validation failure
        try:
            raw = await llm.chat_json(messages)
        except (httpx.HTTPError, ValueError) as exc:
            errors.append(str(exc))
            continue
        if not raw:
            errors.append("empty profile JSON")
            continue
        try:
            fixture = isinstance(llm, FixtureLlm)
            return ToolProfile.model_validate(
                {**raw, "tool": tool.name, "source": "fixture" if fixture else "llm"}
            )
        except ValidationError as exc:
            errors.append(str(exc))
            continue
    # Fixture/offline only — live scans must not invent risk scores without the model.
    if isinstance(llm, FixtureLlm):
        return heuristic_profile(tool)
    raise ValueError(
        f"LLM tool profile failed for {tool.name} (no heuristic fallback): "
        + "; ".join(errors[:3] or ["no valid profile"])
    )


def _profile_priority(tool: DiscoveredTool) -> tuple[int, str]:
    """Undocumented and higher-risk-looking tools first when an optional cap is set."""
    text = f"{tool.name} {tool.description}".lower()
    risk = 0
    if tool.undocumented:
        risk += 40
    if re.search(r"\b(exec|eval|shell|command|script|write|delete|upload|token|secret)\b", text):
        risk += 30
    elif re.search(r"\b(fetch|http|url|file|read|navigat)\b", text):
        risk += 15
    if "R" in tool.sources:
        risk += 5
    return (-risk, tool.name)


def _optional_profile_cap() -> int | None:
    """Return an explicit TOOLPAIN_MAX_PROFILES cap, or None to profile every tool."""
    raw = (os.environ.get("TOOLPAIN_MAX_PROFILES") or "").strip()
    if not raw or raw in {"0", "none", "all", "unlimited"}:
        return None
    if not raw.isdigit():
        return None
    return max(1, int(raw))


async def research_tools(
    discovery: DiscoveryResult, llm: LlmClient, readme_text: str | None = None
) -> dict[str, ToolProfile]:
    # Default: one LLM research profile per discovered tool (repo/runtime set size).
    # Optional emergency cost brake: set TOOLPAIN_MAX_PROFILES to a positive integer.
    tools = sorted(discovery.tools, key=_profile_priority)
    cap = _optional_profile_cap()
    if cap is not None:
        tools = tools[:cap]
    return {t.name: await profile_tool(t, llm, readme_text) for t in tools}
