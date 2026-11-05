"""LLM proxy: routes harness/profile JSON generation.

Modes:
* ``fake`` — deterministic fixtures (offline tests)
* ``ollama`` / ``local`` — OpenAI-compatible Ollama on this machine
* ``openai`` — OpenAI API (or compatible gateway via ``OPENAI_BASE_URL``)
* ``live`` — Vultr Serverless Inference (requires ``VULTR_INFERENCE_API_KEY``)

The runner prefers the control-plane proxy (``/internal/llm/chat``) so keys stay server-side.
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
    "server_summary": "Fake-mode harness (set LLM_MODE=openai|ollama|live for real generation)",
    "entrypoint_guess": None,
    "plans": [],
    "source": "fixture",
}


def _is_harness_request(messages: list[dict[str, str]]) -> bool:
    blob = " ".join(m.get("content", "") for m in messages)
    return "PROBE_HARNESS" in blob or "TASK: PROBE_HARNESS" in blob


def _is_recipe_request(messages: list[dict[str, str]]) -> bool:
    blob = " ".join(m.get("content", "") for m in messages)
    return "SCAN_RECIPE" in blob or "TASK: SCAN_RECIPE" in blob


def _is_executable_codegen_request(messages: list[dict[str, str]]) -> bool:
    blob = " ".join(m.get("content", "") for m in messages)
    return "EXECUTABLE_SCAN_CODE" in blob or "TASK: EXECUTABLE_SCAN_CODE" in blob


def _is_workdir_pick_request(messages: list[dict[str, str]]) -> bool:
    blob = " ".join(m.get("content", "") for m in messages)
    return "WORKDIR_PICK_CODE" in blob or "TASK: WORKDIR_PICK_CODE" in blob


FAKE_RECIPE = {
    "language": "python",
    "install_argv": ["pip", "install", "--no-cache-dir", "."],
    "apt_packages": ["strace"],
    "launch_candidates": [["python", "/app/server.py"], ["python", "server.py"]],
    "rationale": "fake-mode recipe",
}

FAKE_EXECUTABLE_CODE = {
    "launch_sh": "#!/bin/sh\nexec python /app/server.py\n",
    "probe_py": (
        "def build_plans(tools, fixture_url):\n"
        "    plans = []\n"
        "    for t in tools:\n"
        "        name = t['name'] if isinstance(t, dict) else str(t)\n"
        "        plans.append({\n"
        "            'tool': name,\n"
        "            'arguments': {},\n"
        "            'rationale': 'fake',\n"
        "            'expect_decoy': False,\n"
        "            'expect_hosts': [],\n"
        "            'expect_files': [],\n"
        "            'skip': False,\n"
        "        })\n"
        "    return plans\n"
        "\n"
        "def next_plans(tools, fixture_url, prior_results):\n"
        "    return []\n"
    ),
    "oracle_py": (
        "def review_observations(observations):\n"
        "    return []\n"
    ),
    "rationale": "fake-mode executable artifacts",
}

FAKE_WORKDIR_PICK = {
    "workdir_pick_py": (
        "def pick_workdir(candidates, tree_summary):\n"
        "    return candidates[0] if candidates else '.'\n"
    ),
    "rationale": "fake-mode workdir pick",
}


def _extract_json(content: str) -> dict[str, Any] | None:
    content = content.strip()
    if content.startswith("```"):
        content = re.sub(r"^```(?:json)?\s*", "", content)
        content = re.sub(r"\s*```$", "", content)
    try:
        data = json.loads(content)
        return data if isinstance(data, dict) else None
    except json.JSONDecodeError:
        start, end = content.find("{"), content.rfind("}")
        if start >= 0 and end > start:
            try:
                data = json.loads(content[start : end + 1])
                return data if isinstance(data, dict) else None
            except json.JSONDecodeError:
                return None
    return None


def resolve_openai_backend(settings: Settings) -> tuple[str, str, str] | None:
    """Return ``(base_url, api_key, model)`` or ``None`` for fake/offline."""
    mode = settings.llm_mode
    if mode == "openai" and settings.openai_api_key:
        return (
            settings.openai_base_url,
            settings.openai_api_key,
            settings.openai_model,
        )
    if mode in {"ollama", "local"}:
        return (
            settings.ollama_base_url,
            settings.ollama_api_key,
            settings.ollama_model,
        )
    if mode == "live" and settings.vultr_inference_api_key:
        return (
            settings.vultr_inference_base_url,
            settings.vultr_inference_api_key,
            settings.vultr_inference_model or "",
        )
    return None


async def chat_json(
    settings: Settings,
    messages: list[dict[str, str]],
    *,
    schema_hint: str | None = None,
) -> dict[str, Any]:
    want_harness = _is_harness_request(messages)
    want_recipe = _is_recipe_request(messages)
    want_exec = _is_executable_codegen_request(messages)
    want_workdir = _is_workdir_pick_request(messages)
    backend = resolve_openai_backend(settings)
    if backend is None:
        if want_exec:
            return dict(FAKE_EXECUTABLE_CODE)
        if want_workdir:
            return dict(FAKE_WORKDIR_PICK)
        if want_harness:
            return dict(FAKE_HARNESS)
        if want_recipe:
            return dict(FAKE_RECIPE)
        return dict(FAKE_TOOL_PROFILE)

    base_url, api_key, model = backend

    from openai import AsyncOpenAI

    client = AsyncOpenAI(api_key=api_key, base_url=base_url)
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
    elif want_exec:
        system = (
            "You generate ToolPain executable scan artifacts as one JSON object. "
            "Keys: launch_sh (tiny sh with only exec lines), probe_py "
            "(build_plans + optional next_plans), oracle_py (review_observations), "
            "rationale. No markdown. Python: no os/sys/subprocess/socket/open/eval. "
            "Honor USER_SCAN_BRIEF when present."
        )
    elif want_workdir:
        system = (
            "You generate a ToolPain workdir picker as one JSON object. "
            "Keys: workdir_pick_py (def pick_workdir(candidates, tree_summary) -> str), "
            "rationale. No markdown. Python: no os/sys/subprocess/socket/open/eval. "
            "Return a candidate path only. Honor USER_SCAN_BRIEF when present."
        )
    elif want_recipe:
        system = (
            "You choose SAFE ToolPain scan build/launch settings as one JSON object. "
            "No markdown. Keys: language (python|node), install_argv (string array), "
            "apt_packages (string array including strace), launch_candidates "
            "(array of argv arrays), rationale. Never emit shell, Dockerfiles, or Python."
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
    if want_exec:
        return dict(FAKE_EXECUTABLE_CODE)
    if want_workdir:
        return dict(FAKE_WORKDIR_PICK)
    if want_harness:
        return dict(FAKE_HARNESS)
    if want_recipe:
        return dict(FAKE_RECIPE)
    return dict(FAKE_TOOL_PROFILE)
