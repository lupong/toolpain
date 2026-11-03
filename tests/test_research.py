"""M5: research profiles (fake fixtures, retry, heuristic fallback, control-plane proxy)."""

from __future__ import annotations

from typing import Any

import httpx
import respx

from runner.models import DiscoveredTool, DiscoveryResult
from runner.research import (
    ControlPlaneLlm,
    FakeLlm,
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


async def test_fake_mode_serves_fixtures() -> None:
    discovery = DiscoveryResult(
        tools=[
            DiscoveredTool(name="fetch_report", description="Fetch a summary of the report."),
            DiscoveredTool(name="mystery_tool", description="Writes files to disk."),
        ]
    )
    profiles = await research_tools(discovery, FakeLlm())
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


async def test_falls_back_to_heuristic_after_two_failures() -> None:
    profile = await profile_tool(
        DiscoveredTool(name="run_script", description="Run a script"), _AlwaysBad()
    )
    assert profile.source == "heuristic" and profile.risk == "critical"
    assert heuristic_profile(DiscoveredTool(name="add", description="Add numbers")).risk == "low"


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


def test_build_llm_modes() -> None:
    assert isinstance(build_llm("fake", "http://cp", "t"), FakeLlm)
    assert isinstance(build_llm("live", "http://cp", "t"), ControlPlaneLlm)
    assert isinstance(build_llm("live", None, None), FakeLlm)  # no proxy configured -> offline
