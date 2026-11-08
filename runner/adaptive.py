"""LLM-authored *recipes* (data) for install/language + candidate argv order.

Executable launch/probe artifacts live in ``runner.codegen`` (AST/shell-guarded).
This module still only accepts JSON recipe fields:
* language / install_argv / apt_packages / launch_candidates
Packaged code renders Dockerfiles from ``runner/templates/`` and validates argv.
"""

from __future__ import annotations

import logging
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field, ValidationError

from runner.build import ALLOWED_BASES, make_build_plan
from runner.detect import python_console_scripts
from runner.launch_plan import candidate_argvs
from runner.plans import BuildPlan, LaunchCandidate, RepoManifest
from runner.research import FixtureLlm, LlmClient
from runner.safe_argv import (
    ArgvError,
    validate_apt_packages,
    validate_install_argv,
    validate_launch_argv,
)

log = logging.getLogger("toolpain.adaptive")


class AdaptiveRecipe(BaseModel):
    """Validated LLM (or heuristic) recipe for a scan target."""

    language: Literal["python", "node"]
    install_argv: list[str] = Field(default_factory=list)
    apt_packages: list[str] = Field(default_factory=lambda: ["strace"])
    launch_candidates: list[list[str]] = Field(default_factory=list)
    rationale: str = ""
    source: Literal["llm", "heuristic"] = "heuristic"


def _repo_snippet(manifest: RepoManifest) -> str:
    parts: list[str] = [
        f"package_name: {manifest.package_name}",
        f"language_guess: {manifest.language}",
        f"workdir: {manifest.workdir.name}",
        f"manifests: {manifest.manifests}",
    ]
    for name in ("README.md", "pyproject.toml", "package.json"):
        path = manifest.workdir / name
        if path.is_file():
            parts.append(f"{name}:\n{path.read_text(encoding='utf-8', errors='ignore')[:3500]}")
    scripts = python_console_scripts(manifest.workdir)
    if scripts:
        parts.append(f"console_scripts: {scripts}")
    return "\n\n".join(parts)


def build_recipe_prompt(manifest: RepoManifest) -> list[dict[str, str]]:
    user = (
        "TASK: SCAN_RECIPE\n"
        "You are choosing SAFE build/launch settings for ToolPain to scan an MCP server.\n"
        "Return ONE JSON object with keys:\n"
        '  language: "python" or "node"\n'
        "  install_argv: argv array for dependency install inside the image "
        '(e.g. ["pip","install","--no-cache-dir","."] or ["npm","ci","--omit=dev"])\n'
        '  apt_packages: subset of ["strace","curl","ca-certificates"] (always include strace)\n'
        "  launch_candidates: ordered list of argv arrays to try for stdio MCP "
        '(e.g. [["mcp-server-time"],["python","-m","mcp_server_time"]])\n'
        "  rationale: short string\n\n"
        "Rules:\n"
        "- JSON only, no markdown\n"
        "- Never include shell operators, curl|sh, or Dockerfile text\n"
        "- Prefer console_scripts / package.bin when present\n"
        "- First launch candidate should be the most likely working entrypoint\n\n"
        f"{_repo_snippet(manifest)}"
    )
    return [{"role": "user", "content": user}]


def heuristic_recipe(manifest: RepoManifest, scan_id: str) -> AdaptiveRecipe:
    plan = make_build_plan(manifest, scan_id)
    cands = [c.argv for c in candidate_argvs(manifest)]
    return AdaptiveRecipe(
        language=plan.language,
        install_argv=list(plan.install_argv),
        apt_packages=list(plan.apt_packages),
        launch_candidates=cands,
        rationale="packaged heuristic BuildPlan + LaunchPlan candidates",
        source="heuristic",
    )


def _coerce_recipe(raw: dict[str, Any], manifest: RepoManifest, scan_id: str) -> AdaptiveRecipe:
    fallback = heuristic_recipe(manifest, scan_id)
    lang = raw.get("language") or fallback.language
    if lang not in {"python", "node"}:
        lang = fallback.language
    try:
        install = validate_install_argv(
            [str(x) for x in (raw.get("install_argv") or fallback.install_argv)]
        )
    except ArgvError:
        install = list(fallback.install_argv)
    try:
        apt = validate_apt_packages(
            [str(x) for x in (raw.get("apt_packages") or fallback.apt_packages)]
        )
    except ArgvError:
        apt = list(fallback.apt_packages)
    if "strace" not in apt:
        apt = ["strace", *apt]

    launch: list[list[str]] = []
    for item in raw.get("launch_candidates") or []:
        if not isinstance(item, list) or not item:
            continue
        try:
            launch.append(validate_launch_argv([str(x) for x in item]))
        except ArgvError:
            continue
    if not launch:
        launch = list(fallback.launch_candidates)

    return AdaptiveRecipe(
        language=lang,  # type: ignore[arg-type]
        install_argv=install,
        apt_packages=apt,
        launch_candidates=launch,
        rationale=str(raw.get("rationale") or "llm recipe")[:400],
        source="llm",
    )


async def generate_recipe(
    manifest: RepoManifest,
    llm: LlmClient,
    scan_id: str,
) -> AdaptiveRecipe:
    """Ask the LLM for a scan recipe. Heuristics only when using FixtureLlm."""
    if isinstance(llm, FixtureLlm):
        return heuristic_recipe(manifest, scan_id)

    messages = build_recipe_prompt(manifest)
    errors: list[str] = []
    for _ in range(3):
        try:
            raw = await llm.chat_json(messages)
        except (httpx.HTTPError, ValueError, TimeoutError, OSError) as exc:
            log.warning("recipe llm call failed: %s", exc)
            errors.append(str(exc))
            continue
        if not isinstance(raw, dict) or not raw:
            errors.append("empty recipe JSON")
            continue
        try:
            return _coerce_recipe(raw, manifest, scan_id)
        except (ValidationError, ArgvError, TypeError, ValueError) as exc:
            log.warning("recipe coerce failed: %s", exc)
            errors.append(str(exc))
            continue
    raise ValueError(
        "LLM recipe generation failed (no heuristic fallback): "
        + "; ".join(errors[:4] or ["no valid recipe"])
    )


def recipe_to_build_plan(recipe: AdaptiveRecipe, manifest: RepoManifest, scan_id: str) -> BuildPlan:
    """Legacy language Dockerfile path. The live scan uses generated setup.sh instead."""
    log.warning(
        "recipe_to_build_plan is off the scan path; prefer generated setup.sh (scan_id=%s)",
        scan_id,
    )
    base = make_build_plan(manifest, scan_id)
    # Keep packaged template/base; overlay LLM install/apt when language matches.
    language = recipe.language if recipe.language in {"python", "node"} else base.language
    template = language
    base_image = "python:3.12-slim-bookworm" if language == "python" else "node:22-bookworm-slim"
    if base_image not in ALLOWED_BASES:
        base_image = base.base_image
    return BuildPlan(
        language=language,  # type: ignore[arg-type]
        template=template,  # type: ignore[arg-type]
        base_image=base_image,  # type: ignore[arg-type]
        workdir=manifest.workdir,
        apt_packages=recipe.apt_packages or ["strace"],
        install_argv=recipe.install_argv or list(base.install_argv),
        image_tag=base.image_tag,
    )


def recipe_launch_candidates(recipe: AdaptiveRecipe) -> list[LaunchCandidate]:
    out: list[LaunchCandidate] = []
    for argv in recipe.launch_candidates:
        out.append(
            LaunchCandidate(
                argv=argv,
                rationale=f"{recipe.source}: {recipe.rationale}"[:200],
            )
        )
    return out
