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
_ANSI = re.compile(r"\x1b\[[0-9;]*m")
_DOCKER_NOISE = (
    "Sending build context",
    "Step ",
    "--->",
    "Removing intermediate",
    "Removed intermediate",
    "Running in ",
    "Using cache",
)
_APT_NOISE = (
    "Setting up ",
    "Unpacking ",
    "Selecting previously",
    "Preparing to unpack",
    "Get:",
    "Hit:",
    "Reading package",
    "Building dependency",
    "The following ",
    "(Reading database",
)
_ERROR_LINE = re.compile(
    r"error:|ERROR:|Error:|not found|externally-managed|No such file|"
    r"returned a non-zero|fatal:",
    re.IGNORECASE,
)
_LEGACY_BUILDER_BANNER = re.compile(
    r"DEPRECATED: The legacy builder is deprecated and will be removed in a future release\.\s*"
    r"Install the buildx component to build images with BuildKit:\s*"
    r"https://docs\.docker\.com/go/buildx/\s*",
    re.IGNORECASE,
)


def _build_log_tail(stdout: str, stderr: str, *, limit: int = 2000) -> str:
    """Keep the script's own error. Drop builder banners and pip progress bars."""
    text = "\n".join(part.strip() for part in (stdout, stderr) if part and part.strip())
    text = _ANSI.sub("", _LEGACY_BUILDER_BANNER.sub("", text)).replace("\r", "\n")
    kept: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or "━━" in stripped or "eta 0:" in stripped:
            continue
        if stripped.startswith(_DOCKER_NOISE):
            continue
        if stripped.startswith(("Collecting ", "Downloading ", "Using cached ")):
            continue
        if stripped.startswith(_APT_NOISE):
            continue
        kept.append(stripped)
    body = "\n".join(kept).strip()
    if not body:
        return "docker build exited without a log"
    errors = [line for line in kept if _ERROR_LINE.search(line)]
    if not errors:
        return body[-limit:]
    head = "\n".join(errors[-6:])
    room = max(limit - len(head) - 1, 0)
    return f"{head}\n{body[-room:]}".strip() if room else head[-limit:]


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


SANDBOX_BASE_TAG = "toolpain-sandbox:trixie"


def sandbox_image_tag(scan_id: str) -> str:
    safe = re.sub(r"[^a-z0-9_]", "", scan_id.lower())[:24] or "scan"
    tag = f"toolpain-scan-{safe}:run"
    if not IMAGE_TAG_RE.match(tag):
        raise BuildError(f"refusing image tag {tag!r}")
    return tag


def ensure_sandbox_base(*, timeout: float = 900.0) -> None:
    """Build the one sandbox image if it is not already present.

    Toolchains live here. Which ones a repo uses is decided by the generated setup script.
    """
    if shutil.which("docker") is None:
        raise BuildError("docker not found on PATH")
    inspect = subprocess.run(
        ["docker", "image", "inspect", SANDBOX_BASE_TAG],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    if inspect.returncode == 0:
        helper = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                SANDBOX_BASE_TAG,
                "test",
                "-x",
                "/usr/local/bin/toolpain-install-go",
            ],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        if helper.returncode == 0:
            return
        log.info("sandbox base %s missing toolpain-install-go; rebuilding", SANDBOX_BASE_TAG)
    dockerfile = TEMPLATES / "Dockerfile.sandbox-base"
    log.info("building sandbox base %s", SANDBOX_BASE_TAG)
    proc = subprocess.run(
        ["docker", "build", "-f", str(dockerfile), "-t", SANDBOX_BASE_TAG, str(TEMPLATES)],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )
    if proc.returncode != 0:
        raise BuildError(f"sandbox base build failed: {_build_log_tail(proc.stdout, proc.stderr)}")


def build_generated_image(workdir: Path, image_tag: str, *, timeout: float = 600.0) -> str:
    """Build a scan image that runs the generated setup script. No language branch."""
    if not IMAGE_TAG_RE.match(image_tag):
        raise BuildError(f"refusing image tag {image_tag!r}")
    if shutil.which("docker") is None:
        raise BuildError("docker not found on PATH")
    root = workdir.resolve()
    if not root.is_dir():
        raise BuildError(f"build workdir missing: {root}")
    if not (root / "toolpain_setup.sh").is_file():
        raise BuildError("generated setup script is missing")
    ensure_sandbox_base()
    dockerfile = (TEMPLATES / "Dockerfile.sandbox").read_text(encoding="utf-8")
    df_path = root / "Dockerfile.toolpain"
    df_path.write_text(dockerfile, encoding="utf-8")
    log.info("building %s from generated setup in %s", image_tag, root)
    try:
        proc = subprocess.run(
            ["docker", "build", "-f", str(df_path), "-t", image_tag, str(root)],
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
        raise BuildError(f"docker build failed: {_build_log_tail(proc.stdout, proc.stderr)}")
    return image_tag


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
        raise BuildError(f"docker build failed: {_build_log_tail(proc.stdout, proc.stderr)}")
    return plan.image_tag
