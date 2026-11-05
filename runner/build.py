"""Build stage: BuildPlan → packaged Dockerfile template → ``docker build``.

The Dockerfile body always comes from ``runner/templates/``. BuildPlan only supplies
allowlisted fields (base image, apt packages, install argv).
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path

from runner.plans import BaseImage, BuildPlan, RepoManifest
from runner.safe_argv import join_shell_argv, validate_apt_packages, validate_install_argv

log = logging.getLogger("toolpain.build")

TEMPLATES = Path(__file__).resolve().parent / "templates"
ALLOWED_BASES: set[str] = {"python:3.12-slim-bookworm", "node:22-bookworm-slim"}
IMAGE_TAG_RE = re.compile(r"^toolpain-scan-[a-z0-9_]+:[a-z0-9._-]+$")


class BuildError(RuntimeError):
    pass


def make_build_plan(manifest: RepoManifest, scan_id: str) -> BuildPlan:
    lang = manifest.language
    if lang not in {"python", "node"}:
        raise BuildError(
            f"unsupported_language: {lang!r} (ToolPain v2 builds python|node stdio MCP only). "
            f"Set prefer_subdir to a python/node package, or wait for HTTP/SSE support. "
            f"workdir={manifest.workdir}"
        )
    safe = re.sub(r"[^a-z0-9_]", "", scan_id.lower())[:24] or "scan"
    tag = f"toolpain-scan-{safe}:run"
    if lang == "python":
        base: BaseImage = "python:3.12-slim-bookworm"
        if (manifest.workdir / "pyproject.toml").exists() or (
            manifest.workdir / "setup.py"
        ).exists():
            install = ["pip", "install", "--no-cache-dir", "."]
        else:
            # Bare server.py demo-style tree: install mcp only (no version pin — argv allowlist).
            install = ["pip", "install", "--no-cache-dir", "mcp"]
        return BuildPlan(
            language="python",
            template="python",
            base_image=base,
            workdir=manifest.workdir,
            apt_packages=["strace"],
            install_argv=install,
            image_tag=tag,
        )
    install_node = (
        ["npm", "ci", "--omit=dev"]
        if (manifest.workdir / "package-lock.json").exists()
        else ["npm", "install", "--omit=dev"]
    )
    return BuildPlan(
        language="node",
        template="node",
        base_image="node:22-bookworm-slim",
        workdir=manifest.workdir,
        apt_packages=["strace"],
        install_argv=install_node,
        image_tag=tag,
    )


def render_dockerfile(plan: BuildPlan) -> str:
    if plan.base_image not in ALLOWED_BASES:
        raise BuildError(f"base image not allowlisted: {plan.base_image}")
    apt = validate_apt_packages(plan.apt_packages)
    install_argv = validate_install_argv(plan.install_argv)
    template_name = f"Dockerfile.{plan.template}"
    path = TEMPLATES / template_name
    if not path.is_file():
        raise BuildError(f"missing packaged template {template_name}")
    text = path.read_text(encoding="utf-8")
    rendered = (
        text.replace("{{BASE_IMAGE}}", plan.base_image)
        .replace("{{APT_PACKAGES}}", " ".join(apt))
        .replace("{{INSTALL_CMD}}", join_shell_argv(install_argv))
    )
    if "{{" in rendered:
        raise BuildError("unresolved template placeholders")
    return rendered


def build_image(plan: BuildPlan, *, timeout: float = 600.0) -> str:
    """Write Dockerfile into the workdir, ``docker build``, return image tag."""
    if not IMAGE_TAG_RE.match(plan.image_tag):
        raise BuildError(f"refusing image tag {plan.image_tag!r}")
    if shutil.which("docker") is None:
        raise BuildError("docker not found on PATH")
    workdir = plan.workdir.resolve()
    if not workdir.is_dir():
        raise BuildError(f"build workdir missing: {workdir}")

    dockerfile = render_dockerfile(plan)
    df_path = workdir / "Dockerfile.toolpain"
    df_path.write_text(dockerfile, encoding="utf-8")
    log.info("building %s from %s", plan.image_tag, workdir)
    try:
        proc = subprocess.run(
            [
                "docker",
                "build",
                "-f",
                str(df_path),
                "-t",
                plan.image_tag,
                str(workdir),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise BuildError(f"docker build failed to start: {exc}") from exc
    finally:
        df_path.unlink(missing_ok=True)

    if proc.returncode != 0:
        tail = (proc.stderr or proc.stdout or "")[-800:]
        raise BuildError(f"docker build failed: {tail}")
    return plan.image_tag
