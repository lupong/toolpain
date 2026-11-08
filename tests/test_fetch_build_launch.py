"""Fetch / BuildPlan / LaunchPlan units (no network clone required for most)."""

from __future__ import annotations

from pathlib import Path

import pytest

from runner.build import _build_log_tail, make_build_plan, render_dockerfile
from runner.detect import detect_language_at, detect_package
from runner.fetch import FetchError, manifest_from_local, validate_ref, validate_repo_url
from runner.launch_plan import candidate_argvs
from runner.safe_argv import ArgvError, validate_install_argv

ROOT = Path(__file__).resolve().parents[1]
DECOY = ROOT / "demo" / "decoy-trap-server"
TIME_SAMPLE = Path("/tmp/toolpain-samples/servers/src/time")


def test_validate_repo_url_and_ref() -> None:
    assert validate_repo_url("https://github.com/modelcontextprotocol/servers/") == (
        "https://github.com/modelcontextprotocol/servers"
    )
    with pytest.raises(FetchError):
        validate_repo_url("https://gitlab.com/x/y")
    assert validate_ref("main") == "main"
    with pytest.raises(FetchError):
        validate_ref("evil;rm")
    with pytest.raises(FetchError):
        validate_ref("../main")


def test_manifest_from_decoy() -> None:
    m = manifest_from_local(DECOY, repo_url="https://github.com/lupong/toolpain")
    assert m.language == "python"
    assert m.workdir == DECOY.resolve()
    assert "server.py" in m.manifests


def test_build_plan_and_dockerfile_for_decoy() -> None:
    m = manifest_from_local(DECOY)
    plan = make_build_plan(m, "s_test1")
    assert plan.template == "python"
    assert plan.base_image == "python:3.12-slim-bookworm"
    df = render_dockerfile(plan)
    assert "FROM python:3.12-slim-bookworm" in df
    assert "strace" in df
    assert "pip install" in df
    assert "{{" not in df


def test_install_argv_allowlist() -> None:
    validate_install_argv(["pip", "install", "--no-cache-dir", "."])
    with pytest.raises(ArgvError):
        validate_install_argv(["curl", "http://evil"])


@pytest.mark.skipif(not TIME_SAMPLE.is_dir(), reason="mcp-server-time sample not cloned")
def test_detect_and_candidates_for_time_sample() -> None:
    m = manifest_from_local(TIME_SAMPLE)
    assert m.language == "python"
    assert m.package_name == "mcp-server-time"
    cands = candidate_argvs(m)
    assert any(c.argv[0] == "mcp-server-time" for c in cands)
    assert any(c.argv[:3] == ["python", "-m", "mcp_server_time"] for c in cands)


def test_monorepo_prefers_mcp_server_package(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# mono")
    pkg = tmp_path / "src" / "time"
    pkg.mkdir(parents=True)
    (pkg / "pyproject.toml").write_text(
        """
[project]
name = "mcp-server-time"
dependencies = ["mcp>=1.0"]
[project.scripts]
mcp-server-time = "mcp_server_time:main"
"""
    )
    (pkg / "src" / "mcp_server_time").mkdir(parents=True)
    (pkg / "src" / "mcp_server_time" / "__init__.py").write_text("def main():\n    pass\n")
    other = tmp_path / "src" / "other"
    other.mkdir(parents=True)
    (other / "pyproject.toml").write_text(
        """
[project]
name = "unrelated"
dependencies = ["requests"]
"""
    )
    m = detect_package(tmp_path)
    assert m.workdir == pkg.resolve()
    assert m.language == "python"
    lang, name, _ = detect_language_at(pkg)
    assert lang == "python" and name == "mcp-server-time"


def test_monorepo_scores_a_go_mcp_package(tmp_path: Path) -> None:
    helper = tmp_path / "scripts"
    helper.mkdir()
    (helper / "pyproject.toml").write_text(
        """
[project]
name = "helpers"
dependencies = ["requests"]
"""
    )
    go = tmp_path / "servers" / "github-mcp"
    go.mkdir(parents=True)
    (go / "go.mod").write_text(
        "module github.com/example/github-mcp-server\n\nrequire github.com/modelcontextprotocol/go-sdk v1.0.0\n"
    )
    (go / "README.md").write_text("# github-mcp-server\n")
    m = detect_package(tmp_path)
    assert m.workdir == go.resolve()
    assert m.language == "unknown"


def test_build_log_keeps_the_script_error_not_the_builder_banner() -> None:
    banner = (
        "DEPRECATED: The legacy builder is deprecated and will be removed in a future release.\n"
        "            Install the buildx component to build images with BuildKit:\n"
        "            https://docs.docker.com/go/buildx/\n"
    )
    stdout = "Step 5/6 : RUN /bin/sh /app/toolpain_setup.sh\n/bin/sh: 1: uv: not found\n"
    tail = _build_log_tail(stdout, banner + "The command returned a non-zero code: 1\n")
    assert "uv: not found" in tail
    assert "DEPRECATED" not in tail
    progress = (
        "Collecting cffi>=2.0.0\n"
        "  Downloading cffi-2.1.1.whl (218 kB)\n"
        "     ━━━━━━━━━━━━━ 218.7/218.7 kB 18.1 MB/s eta 0:00:00\n"
    )
    failed = _build_log_tail(
        progress * 40 + "ERROR: Could not open requirements file: requirements.txt\n",
        "The command returned a non-zero code: 1\n",
    )
    assert "requirements.txt" in failed
    assert "━━" not in failed
    assert "Collecting" not in failed
    noisy = _build_log_tail(
        "Sending build context to Docker daemon  1.942MB\n"
        "Step 5/7 : RUN /bin/sh /app/toolpain_setup.sh\n"
        " ---> Running in a554291300ad\n"
        "\x1b[91m/app/toolpain_setup.sh: 2: pip: not found\n"
        "\x1b[0mThe command '/bin/sh -c /bin/sh /app/toolpain_setup.sh' returned a non-zero code: 127\n",
        "",
    )
    assert noisy.startswith("pip: not found") or "pip: not found" in noisy.splitlines()[0]
    assert "Sending build context" not in noisy
    assert "\x1b" not in noisy
    buried = _build_log_tail(
        "Setting up python3-pip (23.0.1) ...\n" * 80
        + "error: externally-managed-environment\n"
        + "hint: See PEP 668 for the detailed specification.\n",
        "",
    )
    assert buried.startswith("error: externally-managed-environment")
    assert "Setting up" not in buried
