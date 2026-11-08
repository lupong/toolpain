"""M5: research profiles (fixture profiles, retry, heuristic fallback, control-plane proxy)."""

from __future__ import annotations

from typing import Any

import httpx
import pytest
import respx

from control_plane.config import get_settings
from control_plane.llm import model_for_messages
from runner.models import DiscoveredTool, DiscoveryResult
from runner.research import (
    ControlPlaneLlm,
    FixtureLlm,
    build_llm,
    heuristic_profile,
    profile_tool,
    research_tools,
)


class _BadThenGood:
    def __init__(self) -> None:
        self.calls = 0

    async def chat_json(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        self.calls += 1
        if self.calls == 1:
            return {"risk": "not-a-risk-level"}  # fails validation
        return {"claimed_behavior": "does x", "risk": "medium", "privilege_hint": "medium"}


class _AlwaysBad:
    async def chat_json(self, messages: list[dict[str, str]]) -> dict[str, Any]:
        return {"risk": 12345}


async def test_fixture_mode_serves_fixtures() -> None:
    discovery = DiscoveryResult(
        tools=[
            DiscoveredTool(name="fetch_report", description="Fetch a summary of the report."),
            DiscoveredTool(name="mystery_tool", description="Writes files to disk."),
        ]
    )
    profiles = await research_tools(discovery, FixtureLlm())
    fr = profiles["fetch_report"]
    assert fr.source == "fixture" and fr.risk == "critical"
    assert fr.resources == ["/workspace/canaries/decoy_secret.txt"]
    assert fr.downstream == ["collector.sinkhole.local"]
    assert profiles["mystery_tool"].source == "heuristic"
    assert profiles["mystery_tool"].risk == "high"


async def test_retry_once_on_validation_failure() -> None:
    llm = _BadThenGood()
    profile = await profile_tool(DiscoveredTool(name="x", description="d"), llm)
    assert llm.calls == 2 and profile.source == "llm" and profile.risk == "medium"


async def test_live_llm_does_not_fall_back_to_heuristic() -> None:
    with pytest.raises(ValueError, match="no heuristic fallback"):
        await profile_tool(
            DiscoveredTool(name="run_script", description="Run a script"), _AlwaysBad()
        )
    assert heuristic_profile(DiscoveredTool(name="add", description="Add numbers")).risk == "low"
    # Fixture LLM still uses heuristic after fixture miss.
    profile = await profile_tool(
        DiscoveredTool(name="run_script", description="Run a script"), FixtureLlm()
    )
    assert profile.source == "heuristic" and profile.risk == "critical"


@respx.mock
async def test_control_plane_llm_posts_token() -> None:
    route = respx.post("http://cp.test/internal/llm/chat").mock(
        return_value=httpx.Response(
            200, json={"claimed_behavior": "c", "risk": "low", "privilege_hint": "low"}
        )
    )
    llm = ControlPlaneLlm("http://cp.test", "tok-123")
    profile = await profile_tool(DiscoveredTool(name="x"), llm)
    assert profile.source == "llm" and profile.claimed_behavior == "c"
    assert route.calls.last.request.headers["X-Scan-Token"] == "tok-123"
    body = route.calls.last.request.read()
    assert b'"kind":"research"' in body or b'"kind": "research"' in body


@pytest.mark.asyncio
async def test_research_tools_profiles_all_by_default(monkeypatch) -> None:
    monkeypatch.delenv("TOOLPAIN_MAX_PROFILES", raising=False)
    tools = [
        DiscoveredTool(name="safe_add", description="Add numbers", sources=["R"]),
        DiscoveredTool(name="shell_exec", description="Run a shell command", sources=["R"]),
        DiscoveredTool(name="ping", description="Ping", sources=["R"]),
    ]
    profiles = await research_tools(DiscoveryResult(tools=tools), FixtureLlm())
    assert set(profiles) == {"safe_add", "shell_exec", "ping"}


@pytest.mark.asyncio
async def test_research_tools_optional_cap_prefers_undocumented(monkeypatch) -> None:
    monkeypatch.setenv("TOOLPAIN_MAX_PROFILES", "3")
    tools = [
        DiscoveredTool(name="safe_add", description="Add numbers", sources=["R"]),
        DiscoveredTool(name="shell_exec", description="Run a shell command", sources=["R"]),
        DiscoveredTool(
            name="hidden_write",
            description="Write a file",
            sources=["R"],
            undocumented=True,
        ),
        DiscoveredTool(name="ping", description="Ping", sources=["R"]),
        DiscoveredTool(name="list_x", description="List", sources=["R"]),
    ]
    profiles = await research_tools(DiscoveryResult(tools=tools), FixtureLlm())
    assert len(profiles) == 3
    assert "hidden_write" in profiles
    assert "shell_exec" in profiles


def test_codegen_model_is_separate_from_research(monkeypatch) -> None:
    monkeypatch.setenv("LLM_MODE", "live")
    monkeypatch.setenv("VULTR_INFERENCE_API_KEY", "test-key")
    monkeypatch.setenv("VULTR_INFERENCE_MODEL", "deepseek-v4.1-flash-1017")
    monkeypatch.setenv("CODEGEN_MODEL", "qwen3.8-27b")
    settings = get_settings()
    codegen = model_for_messages(
        settings, [{"role": "user", "content": "TASK: EXECUTABLE_SCAN_CODE"}]
    )
    research = model_for_messages(settings, [{"role": "user", "content": "profile the tool"}])
    assert codegen == "qwen3.8-27b"
    assert research == "deepseek-v4.1-flash-1017"


def test_build_llm_modes(monkeypatch) -> None:
    from runner.research import DirectChatLlm, default_llm_mode

    monkeypatch.delenv("LLM_MODE", raising=False)
    assert isinstance(build_llm("fixture", "http://cp", "t"), FixtureLlm)
    assert isinstance(build_llm("live", "http://cp", "t"), ControlPlaneLlm)
    with pytest.raises(RuntimeError, match="refusing FixtureLlm"):
        build_llm("live", None, None)
    assert isinstance(build_llm("ollama", "http://cp", "t"), ControlPlaneLlm)
    assert isinstance(build_llm("ollama", None, None), DirectChatLlm)
    with pytest.raises(RuntimeError, match="Unknown LLM_MODE"):
        build_llm("not-a-mode", None, None)
    # Any configured mode with CP+token uses the proxy (scanners must not fall to FixtureLlm).
    assert isinstance(build_llm("auto", "http://cp", "t"), ControlPlaneLlm)
    assert default_llm_mode(control_plane_url="http://cp", token="t") == "live"
    with pytest.raises(RuntimeError, match="LLM_MODE is unset"):
        default_llm_mode(control_plane_url=None, token=None)
