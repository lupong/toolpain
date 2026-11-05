"""Data-only plans for fetch / build / launch.

These models are the trust boundary for adaptive scan stages: they may be filled by
heuristics (or later by Inference), but only packaged code interprets them. Never put
shell strings, Dockerfile bodies, or Python source in these plans.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

Language = Literal["python", "node", "unknown"]
BaseImage = Literal["python:3.12-slim-bookworm", "node:22-bookworm-slim"]


class RepoManifest(BaseModel):
    """What fetch produced: a concrete tree + detected package root."""

    repo_url: str
    ref: str
    commit: str
    root: Path
    workdir: Path
    language: Language = "unknown"
    manifests: list[str] = Field(default_factory=list)
    package_name: str | None = None
    candidates: list[str] = Field(default_factory=list)
    readme_path: str | None = None


class BuildPlan(BaseModel):
    """Inputs for rendering a packaged Dockerfile template (never LLM-authored Docker)."""

    language: Literal["python", "node"]
    template: Literal["python", "node"]
    base_image: BaseImage
    workdir: Path
    apt_packages: list[str] = Field(default_factory=lambda: ["strace"])
    install_argv: list[str] = Field(default_factory=list)
    image_tag: str


class LaunchCandidate(BaseModel):
    argv: list[str]
    env: dict[str, str] = Field(default_factory=dict)
    rationale: str = ""


class LaunchPlan(BaseModel):
    """Winning argv used as DockerSandbox.server_cmd (strace wraps this)."""

    argv: list[str]
    env: dict[str, str] = Field(default_factory=dict)
    rationale: str = ""
    tried: list[LaunchCandidate] = Field(default_factory=list)
    source: Literal["trial", "override", "demo", "llm"] = "trial"
