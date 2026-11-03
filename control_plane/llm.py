"""LLM proxy: sole holder of the Vultr inference key.

Fake mode returns deterministic JSON shaped for the requested task (tool profile vs probe
harness). Live mode calls Vultr Serverless Inference (OpenAI-compatible).
"""

from __future__ import annotations

import json
import re
from typing import Any

from control_plane.config import Settings

FAKE_TOOL_PROFILE = {
    "claimed_behavior": "Performs the documented tool action",
    "resources": [],
    "downstream": [],
    "risk": "low",
    "privilege_hint": "low",
}

FAKE_HARNESS = {
    "server_summary": "Fake-mode harness (set LLM_MODE=live + VULTR_INFERENCE_API_KEY for real generation)",
    "entrypoint_guess": None,
    "plans": [],
    "source": "fixture",
}


def _is_harness_request(messages: list[dict[str, str]]) -> bool:
    blob = " ".join(m.get("content", "") for m in messages)
    return "PROBE_HARNESS" in blob or "TASK: PROBE_HARNESS" in blob


def _extract_json(content: str) -> dict[str, Any] | None:
    content = content.strip()
    if content.startswith("```"):
        content = re.sub(r"^```(?:json)?\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
    try:
        data = json.loads(content)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        # Best-effort: first {...} block
        start, end = content.find("{"), content.rfind("}")
        if start >= 0 and end > start:
            try:
                data = json.loads(content[start : end + 1])
                return data if isinstance(data, dict) else None
            except json.JSONDecodeError:
                return None
    return None


async def chat_json(
    settings: Settings,
    messages: list[dict[str, str]],
    *,
    schema_hint: str | None = None,
) -> dict[str, Any]:
    want_harness = _is_harness_request(messages)
    if settings.llm_mode != "live" or not settings.vultr_inference_api_key:
        return dict(FAKE_HARNESS) if want_harness else dict(FAKE_TOOL_PROFILE)

    from openai import AsyncOpenAI

    client = AsyncOpenAI(
        api_key=settings.vultr_inference_api_key,
        base_url=settings.vultr_inference_base_url,
    )
    model = settings.vultr_inference_model
    if not model:
        models = await client.models.list()
        model = models.data[0].id if models.data else "gpt-4o-mini"

    if want_harness:
        system = (
            "You generate SAFE MCP probe harnesses as a single JSON object. "
            "No markdown fences. Keys: server_summary, entrypoint_guess, plans "
            "(array of {tool, arguments, rationale, expect_files, expect_hosts, "
            "expect_decoy, skip, skip_reason}). Never suggest reading real secret paths."
        )
    else:
        system = "Respond with a single JSON object only. No markdown." + (
            f" Schema hint: {schema_hint}" if schema_hint else ""
        )

    for attempt in range(2):
        resp = await client.chat.completions.create(
            model=model,
            messages=[{"role": "system", "content": system}, *messages],
            temperature=0,
        )
        content = resp.choices[0].message.content or "{}"
        parsed = _extract_json(content)
        if parsed is not None:
            return parsed
        if attempt == 0:
            continue
    return dict(FAKE_HARNESS) if want_harness else dict(FAKE_TOOL_PROFILE)
