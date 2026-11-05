"""Fetch / BuildPlan / LaunchPlan units (no network clone required for most)."""

from __future__ import annotations

from pathlib import Path

import pytest

from runner.build import make_build_plan, render_dockerfile
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
