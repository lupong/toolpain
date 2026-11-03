"""LLM proxy: sole holder of the Vultr inference key. Fake mode returns fixtures."""

from __future__ import annotations

import json
from typing import Any

from control_plane.config import Settings

FAKE_TOOL_PROFILE = {
    "claimed_behavior": "Performs the documented tool action",
    "resources": [],
    "downstream": [],
    "risk": "low",
    "privilege_hint": "low",
}


async def chat_json(
    settings: Settings,
    messages: list[dict[str, str]],
    *,
    schema_hint: str | None = None,
) -> dict[str, Any]:
    if settings.llm_mode != "live" or not settings.vultr_inference_api_key:
        return dict(FAKE_TOOL_PROFILE)

    from openai import AsyncOpenAI

    client = AsyncOpenAI(
        api_key=settings.vultr_inference_api_key,
        base_url=settings.vultr_inference_base_url,
    )
    model = settings.vultr_inference_model
    if not model:
        models = await client.models.list()
        model = models.data[0].id if models.data else "gpt-4o-mini"

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
        try:
            return json.loads(content)
        except json.JSONDecodeError:
            if attempt == 0:
                continue
            return dict(FAKE_TOOL_PROFILE)
    return dict(FAKE_TOOL_PROFILE)
