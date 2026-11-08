"""Monorepo intake inspect + create_scan gate."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from control_plane.intake_inspect import (
    IntakeInspection,
    candidates_from_tree_paths,
    fixture_monorepo_message,
    inspect_repo,
)
from control_plane.main import AppState, app
from control_plane.provisioner.demo import DemoProvisioner


def test_candidates_from_awslabs_style_tree() -> None:
    paths = [
        "README.md",
        "src/openapi-mcp-server/pyproject.toml",
        "src/openapi-mcp-server/server.py",
        "src/eks-mcp-server/pyproject.toml",
        "src/aws-api-mcp-server/pyproject.toml",
        "src/time-mcp-server/package.json",
        "samples/mcp-integration-with-kb/package.json",
        "docs/guide.md",
    ]
    cands = candidates_from_tree_paths(paths)
    assert len(cands) >= 4
    assert "src/openapi-mcp-server" in cands
    assert "src/eks-mcp-server" in cands
    assert all(not c.startswith("samples/") for c in cands)


def test_candidates_microsoft_style_collapses_nested() -> None:
    paths = [
        "servers/Azure.Mcp.Server/src/Azure.Mcp.Server.csproj",
        "servers/Azure.Mcp.Server/vscode/package.json",
        "servers/Azure.Mcp.Server/vscode/src/test/outerloop/fixtures/startup-trigger/package.json",
        "servers/Fabric.Mcp.Server/src/Fabric.Mcp.Server.csproj",
        "servers/Fabric.Mcp.Server/vscode/package.json",
        "servers/Template.Mcp.Server/src/Template.Mcp.Server.csproj",
        "eng/tools/foo/package.json",
    ]
    cands = candidates_from_tree_paths(paths)
    assert cands == [
        "servers/Azure.Mcp.Server",
        "servers/Fabric.Mcp.Server",
        "servers/Template.Mcp.Server",
    ]


def test_candidates_single_package_not_multi() -> None:
    paths = ["package.json", "src/index.ts", "README.md"]
    # Root-only manifest → single candidate; create_scan gate stays open.
    assert candidates_from_tree_paths(paths) == ["."]


def test_candidates_genai_toolbox_style_packaging_roots() -> None:
    """googleapis/genai-toolbox: root go.mod + npm/* + pypi — must be multi before provision."""
    paths = [
        "go.mod",
        "README.md",
        "npm/server/package.json",
        "npm/server-linux-x64/package.json",
        "npm/server-win32-x64/package.json",
        "npm/server-darwin-x64/package.json",
        "npm/server-win32-arm64/package.json",
        "npm/server-darwin-arm64/package.json",
        "pypi/pyproject.toml",
        "docs/en/documentation/getting-started/quickstart/js/adk/package.json",
        ".hugo/package.json",
        "internal/foo/go.mod",
    ]
    cands = candidates_from_tree_paths(paths)
    assert "." in cands
    assert "npm/server" in cands
    assert "pypi" in cands
    assert "npm/server-linux-x64" in cands
    assert len(cands) >= 8
    assert all(not c.startswith("docs/") for c in cands)
    assert all(not c.startswith("internal/") for c in cands)
    assert "hugo" not in cands
    assert all(not c.startswith(".hugo") for c in cands)


def test_dot_prefixed_dirs_not_stripped_to_bare_name() -> None:
    # lstrip("./") would wrongly turn .hugo → hugo; must keep skip behavior.
    assert candidates_from_tree_paths([".hugo/go.mod", ".hugo/package.json"]) == []


def test_fixture_message_includes_count() -> None:
    msg = fixture_monorepo_message(63)
    assert "63" in msg
    assert "server" in msg.lower()
    assert "aws" not in msg.lower()


@pytest.mark.asyncio
async def test_inspect_repo_uses_injected_tree(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_MODE", "fixture")
    from control_plane.config import get_settings

    settings = get_settings()
    paths = [f"src/pkg-{i}-mcp-server/pyproject.toml" for i in range(5)]
    result = await inspect_repo(
        settings,
        "https://github.com/awslabs/mcp",
        "main",
        tree_paths=paths,
        with_message=True,
    )
    assert result.multi
    assert result.count == 5
    assert result.message
    assert "5" in result.message


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("PROVISIONER", "demo")
    monkeypatch.setenv("LLM_MODE", "fixture")
    monkeypatch.setenv("TOOLPAIN_DATA_DIR", str(tmp_path))
    import control_plane.main as main_mod

    state = AppState()
    state.provisioner = DemoProvisioner(
        emit_event=state.emit_event,
        save_report=state.save_report,
        update_scan=state.update_scan,
        delay_sec=0.02,
    )
    main_mod.STATE = state

    async def _single(
        settings,
        repo_url: str,
        ref: str = "main",
        **kwargs,
    ) -> IntakeInspection:
        return IntakeInspection(repo_url=repo_url, ref=ref, candidates=["."], message=None)

    monkeypatch.setattr(main_mod, "inspect_repo", _single)
    with TestClient(app) as c:
        yield c


def test_intake_inspect_endpoint_multi(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROVISIONER", "demo")
    monkeypatch.setenv("LLM_MODE", "fixture")
    monkeypatch.setenv("TOOLPAIN_DATA_DIR", str(tmp_path))
    import control_plane.main as main_mod

    state = AppState()
    state.provisioner = DemoProvisioner(
        emit_event=state.emit_event,
        save_report=state.save_report,
        update_scan=state.update_scan,
        delay_sec=0.02,
    )
    main_mod.STATE = state

    async def _multi(settings, repo_url: str, ref: str = "main", **kwargs) -> IntakeInspection:
        cands = ["src/a-mcp-server", "src/b-mcp-server", "src/c-mcp-server"]
        return IntakeInspection(
            repo_url=repo_url,
            ref=ref,
            candidates=cands,
            message=fixture_monorepo_message(len(cands)),
        )

    monkeypatch.setattr(main_mod, "inspect_repo", _multi)
    with TestClient(app) as c:
        r = c.post(
            "/api/intake/inspect",
            json={"repo_url": "https://github.com/awslabs/mcp", "ref": "main"},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["multi"] is True
        assert body["count"] == 3
        assert body["message"]
        assert "src/a-mcp-server" in body["candidates"]


def test_create_scan_rejects_monorepo_without_prefer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PROVISIONER", "demo")
    monkeypatch.setenv("LLM_MODE", "fixture")
    monkeypatch.setenv("TOOLPAIN_DATA_DIR", str(tmp_path))
    import control_plane.main as main_mod

    state = AppState()
    state.provisioner = DemoProvisioner(
        emit_event=state.emit_event,
        save_report=state.save_report,
        update_scan=state.update_scan,
        delay_sec=0.02,
    )
    main_mod.STATE = state

    async def _multi(settings, repo_url: str, ref: str = "main", **kwargs) -> IntakeInspection:
        cands = ["src/openapi-mcp-server", "src/eks-mcp-server"]
        return IntakeInspection(
            repo_url=repo_url,
            ref=ref,
            candidates=cands,
            message=fixture_monorepo_message(2),
        )

    monkeypatch.setattr(main_mod, "inspect_repo", _multi)
    with TestClient(app) as c:
        r = c.post(
            "/api/scans",
            json={"repo_url": "https://github.com/awslabs/mcp", "ref": "main"},
        )
        assert r.status_code == 422
        detail = r.json()["detail"]
        assert detail["code"] == "monorepo_choice_required"
        assert detail["count"] == 2
        assert "openapi" in detail["message"].lower() or "2" in detail["message"]


def test_create_scan_allows_monorepo_with_prefer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PROVISIONER", "demo")
    monkeypatch.setenv("LLM_MODE", "fixture")
    monkeypatch.setenv("TOOLPAIN_DATA_DIR", str(tmp_path))
    import control_plane.main as main_mod

    state = AppState()
    started = AsyncMock()
    state.provisioner = DemoProvisioner(
        emit_event=state.emit_event,
        save_report=state.save_report,
        update_scan=state.update_scan,
        delay_sec=0.02,
    )
    state.provisioner.start_scan = started  # type: ignore[method-assign]
    main_mod.STATE = state

    async def _multi(settings, repo_url: str, ref: str = "main", **kwargs) -> IntakeInspection:
        return IntakeInspection(
            repo_url=repo_url,
            ref=ref,
            candidates=["src/openapi-mcp-server", "src/eks-mcp-server"],
            message=fixture_monorepo_message(2),
        )

    monkeypatch.setattr(main_mod, "inspect_repo", _multi)
    with TestClient(app) as c:
        r = c.post(
            "/api/scans",
            json={
                "repo_url": "https://github.com/awslabs/mcp",
                "ref": "main",
                "prefer_subdir": "src/openapi-mcp-server",
            },
        )
        assert r.status_code == 201
        assert started.await_count == 1
        kwargs = started.await_args.kwargs
        assert kwargs.get("prefer_subdir") == "src/openapi-mcp-server"


def test_create_scan_demo_skips_gate(client: TestClient) -> None:
    r = client.post(
        "/api/scans",
        json={
            "repo_url": "https://github.com/modelcontextprotocol/servers",
            "demo": "server-filesystem",
        },
    )
    assert r.status_code == 201
