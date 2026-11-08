"""LLM proxy: routes harness/profile JSON generation.

Modes:
* ``fixture`` — deterministic fixtures (offline tests)
* ``ollama`` / ``local`` — local Ollama on this machine (laptop only)
* ``live`` — Vultr Serverless Inference (requires ``VULTR_INFERENCE_API_KEY``)

Production uses Vultr Inference only. The runner prefers the control-plane proxy
(``/internal/llm/chat``) so keys stay server-side.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from openai import AsyncOpenAI  # chat-completions HTTP client (Vultr Inference / Ollama)

from control_plane.config import Settings

log = logging.getLogger("toolpain.llm")

# Duplicated in runner.certificate_narrative for scanner hot-sync independence.
FIXTURE_CERTIFICATE_NARRATIVE = {
    "business_summary": (
        "This MCP server exposes tools for an AI agent or client application. "
        "Fixture-mode narrative — live scans use the LLM for certificate copy."
    ),
    "recommendations": [
        "Review findings and apply the least-privilege allowlist before production use.",
        "Re-scan after any tool, dependency, or docs change.",
    ],
}

FIXTURE_TOOL_PROFILE = {
    "claimed_behavior": "Performs the documented tool action",
    "resources": [],
    "downstream": [],
    "risk": "low",
    "privilege_hint": "low",
}

FIXTURE_HARNESS = {
    "server_summary": "Fixture-mode harness (set LLM_MODE=live|ollama for real generation)",
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


def _is_certificate_narrative_request(messages: list[dict[str, str]]) -> bool:
    blob = " ".join(m.get("content", "") for m in messages)
    return "CERTIFICATE_NARRATIVE" in blob or "TASK: CERTIFICATE_NARRATIVE" in blob


def _is_findings_narrative_request(messages: list[dict[str, str]]) -> bool:
    blob = " ".join(m.get("content", "") for m in messages)
    return "FINDINGS_NARRATIVE" in blob or "TASK: FINDINGS_NARRATIVE" in blob


FIXTURE_RECIPE = {
    "language": "python",
    "install_argv": ["pip", "install", "--no-cache-dir", "."],
    "apt_packages": ["strace"],
    "launch_candidates": [["python", "/app/server.py"], ["python", "server.py"]],
    "rationale": "fixture-mode recipe",
}

FIXTURE_EXECUTABLE_CODE = {
    "setup_sh": "#!/bin/sh\npip install --no-cache-dir .\n",
    "launch_sh": "#!/bin/sh\nexec python /app/server.py\n",
    "probe_py": (
        "def build_plans(tools, fixture_url):\n"
        "    plans = []\n"
        "    for t in tools:\n"
        "        name = t['name'] if isinstance(t, dict) else str(t)\n"
        "        plans.append({\n"
        "            'tool': name,\n"
        "            'arguments': {},\n"
        "            'rationale': 'fixture',\n"
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
    "oracle_py": ("def review_observations(observations):\n    return []\n"),
    "rationale": "fixture-mode executable artifacts",
}

FIXTURE_WORKDIR_PICK = {
    "workdir_pick_py": (
        "def pick_workdir(candidates, tree_summary):\n"
        "    return candidates[0] if candidates else '.'\n"
    ),
    "rationale": "fixture-mode workdir pick",
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


def resolve_llm_backend(settings: Settings) -> tuple[str, str, str] | None:
    """Return ``(base_url, api_key, model)`` or ``None`` for fixture/offline.

    Backends: Vultr Inference (``live``) and local Ollama (``ollama`` / ``local``).
    """
    mode = settings.llm_mode
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


def model_for_messages(settings: Settings, messages: list[dict[str, str]]) -> str:
    """Executable codegen uses CODEGEN_MODEL. Research stays on the general model."""
    backend = resolve_llm_backend(settings)
    general = backend[2] if backend else (settings.vultr_inference_model or settings.codegen_model)
    if _is_executable_codegen_request(messages) or _is_workdir_pick_request(messages):
        return settings.codegen_model or general
    return general


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
    want_cert = _is_certificate_narrative_request(messages)
    want_findings = _is_findings_narrative_request(messages)
    backend = resolve_llm_backend(settings)
    if backend is None:
        # Fixtures only in explicit fixture mode — never silently substitute for live.
        if settings.llm_mode != "fixture":
            raise RuntimeError(
                f"LLM backend unavailable for llm_mode={settings.llm_mode!r}; "
                "refusing heuristic/fixture substitute"
            )
        if want_exec:
            return dict(FIXTURE_EXECUTABLE_CODE)
        if want_workdir:
            return dict(FIXTURE_WORKDIR_PICK)
        if want_harness:
            return dict(FIXTURE_HARNESS)
        if want_recipe:
            return dict(FIXTURE_RECIPE)
        if want_findings:
            return {"findings": []}
        if want_cert:
            return dict(FIXTURE_CERTIFICATE_NARRATIVE)
        return dict(FIXTURE_TOOL_PROFILE)

    base_url, api_key, _general = backend
    model = model_for_messages(settings, messages)
    if _is_executable_codegen_request(messages) or _is_workdir_pick_request(messages):
        log.info("codegen model %s", model)

    client = AsyncOpenAI(api_key=api_key, base_url=base_url)
    if not model:
        models = await client.models.list()
        model = models.data[0].id if models.data else (settings.vultr_inference_model or "deepseek-v4.1-flash-1017")

    if want_findings:
        system = (
            "You rewrite ToolPain findings for IT / security reviewers as one JSON object. "
            "Keys: findings (array of {id, explanation, recommendation}). "
            "Observations are of the MCP server process in the scan sandbox, not the "
            "MCP client laptop. Be concrete about next actions. Ground claims in the "
            "evidence pack. No markdown. No pricing."
        )
    elif want_cert:
        system = (
            "You write ToolPain scan certificate narratives as one JSON object. "
            "Keys: business_summary (2-4 sentences on the business/product use case "
            "of this MCP server), recommendations (array of 3-8 concrete next actions). "
            "Use scan_context so locality is clear to IT reviewers. "
            "Ground claims in the evidence pack. No markdown. No pricing."
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
            "launch_sh (tiny sh with only exec lines), probe_py "
            "(build_plans + optional next_plans), oracle_py (review_observations), "
            "rationale. No markdown. Python: no os/sys/subprocess/socket/open/eval. "
            "The fixture answers every path. Do not emit a finding only because a tool "
            "returned an error or an HTTP status. "
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
    if settings.llm_mode == "fixture":
        if want_exec:
            return dict(FIXTURE_EXECUTABLE_CODE)
        if want_workdir:
            return dict(FIXTURE_WORKDIR_PICK)
        if want_harness:
            return dict(FIXTURE_HARNESS)
        if want_recipe:
            return dict(FIXTURE_RECIPE)
        if want_findings:
            return {"findings": []}
        if want_cert:
            return dict(FIXTURE_CERTIFICATE_NARRATIVE)
        return dict(FIXTURE_TOOL_PROFILE)
    raise ValueError("model did not return a JSON object after retries")
