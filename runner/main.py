"""Runner entry point: fetch → build → launch → discover → research → probe → analyze → report.

``run_scan`` drives the pipeline. Demo trees under ``demo/`` still use ``FakeSandbox``.
Third-party / cloned repos use ``DockerSandbox`` after packaged fetch + BuildPlan image
build + LaunchPlan trial. Progress events and the final report are posted to the control
plane when ``control_plane_url`` and ``token`` are set.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel

from runner.adaptive import (
    generate_recipe,
    recipe_launch_candidates,
    recipe_to_build_plan,
)
from runner.analyze import AnalysisInput, analyze_scan
from runner.analyze.expectations import expectation_findings, score_expectations
from runner.build import BuildError, build_image
from runner.codegen import (
    generate_executable_code,
    generate_workdir_pick,
    harness_from_generated,
    load_probe_module,
    next_plans_from_probe_module,
    observations_from_probes,
    run_oracle,
    sanitize_scan_brief,
    write_launch_script,
)
from runner.codegen_cache import make_key
from runner.detect import detect_package
from runner.discover import discover
from runner.events import EventSink, HttpSink, NullSink
from runner.fetch import fetch_repo, git_commit, manifest_from_local
from runner.harness import ProbeHarness, generate_harness, harness_to_report_blob
from runner.launch import DECOY_SERVER, DEMO_DIR, LocalLaunchRefused
from runner.launch_plan import demo_launch_plan, resolve_launch_plan
from runner.models import DiscoveryResult
from runner.plans import LaunchCandidate, LaunchPlan, RepoManifest
from runner.probe import probe_tools
from runner.report import build_report
from runner.research import LlmClient, build_llm, research_tools
from runner.transport.http_mcp import HttpMcpClient
from runner.upstream import fetch_upstream_tool_names, resolve_github_parent
from sandbox.fake import FakeSandbox
from sandbox.sandbox import DockerSandbox, Sandbox, docker_available

log = logging.getLogger("toolpain.runner")
DEFAULT_SOURCE = DECOY_SERVER.parent


class ScanConfig(BaseModel):
    scan_id: str
    repo_url: str
    ref: str = "main"
    token: str | None = None
    control_plane_url: str | None = None
    # None → clone repo_url. Set to a path to skip fetch (demo / --local-path).
    local_path: Path | None = None
    sandbox: Literal["fake", "docker", "auto"] = "auto"
    image: str | None = None
    server_cmd: list[str] | None = None
    runtime: str = "runc"
    llm_mode: str = "fake"
    upstream_tools: list[str] | None = None
    call_timeout: float = 30.0
    prefer_subdir: str | None = None
    scan_brief: str | None = None
    protocol: str = "auto"
    upstream_url: str | None = None
    mcp_url: str | None = None
    keep_clone: bool = False


def _load_upstream(path: Path) -> list[str] | None:
    file = path / "upstream_tools.json"
    if not file.exists():
        return None
    data = json.loads(file.read_text(encoding="utf-8"))
    return [str(x) for x in data] if isinstance(data, list) else None


def _under_demo(path: Path) -> bool:
    try:
        path.resolve().relative_to(DEMO_DIR.resolve())
        return True
    except ValueError:
        return False


def _readme_text(manifest: RepoManifest) -> str | None:
    if manifest.readme_path:
        path = manifest.root / manifest.readme_path
        if path.exists():
            return path.read_text(encoding="utf-8")
    readme = manifest.workdir / "README.md"
    if readme.exists():
        return readme.read_text(encoding="utf-8")
    return None


async def _maybe_llm_workdir(
    cfg: ScanConfig,
    manifest: RepoManifest,
    sink: EventSink,
    llm: LlmClient,
) -> tuple[RepoManifest, dict[str, Any]]:
    """When prefer_subdir is unset and candidates > 1, ask LLM for workdir_pick_py."""
    blob: dict[str, Any] = {}
    if cfg.prefer_subdir or len(manifest.candidates) <= 1:
        return manifest, blob
    await sink.emit(
        "fetch",
        f"Asking LLM to pick MCP package among {len(manifest.candidates)} candidates",
    )
    pick = await generate_workdir_pick(
        manifest.root,
        manifest.candidates,
        llm,
        scan_brief=cfg.scan_brief,
    )
    blob = pick.model_dump()
    await sink.emit(
        "fetch",
        f"Workdir pick ({pick.source}): {pick.subdir} — {pick.rationale[:120]}",
        data={"subdir": pick.subdir, "source": pick.source},
    )
    if pick.subdir and pick.subdir != (
        str(manifest.workdir.relative_to(manifest.root))
        if manifest.root in manifest.workdir.parents or manifest.workdir == manifest.root
        else "."
    ):
        remanifest = detect_package(manifest.root, prefer_subdir=pick.subdir)
        remanifest.repo_url = manifest.repo_url
        remanifest.ref = manifest.ref
        remanifest.commit = manifest.commit
        remanifest.readme_path = (
            "README.md" if (remanifest.workdir / "README.md").exists() else None
        )
        return remanifest, blob
    return manifest, blob


async def _prepare_source(
    cfg: ScanConfig,
    sink: EventSink,
) -> tuple[RepoManifest, Path | None]:
    """Return (manifest, clone_dir_to_cleanup|None)."""
    if cfg.local_path is not None:
        await sink.emit("fetch", f"Using local source {cfg.local_path}")
        manifest = manifest_from_local(
            cfg.local_path,
            repo_url=cfg.repo_url,
            ref=cfg.ref,
            prefer_subdir=cfg.prefer_subdir,
        )
        return manifest, None

    clone_root = Path(tempfile.mkdtemp(prefix=f"tp_fetch_{cfg.scan_id}_"))
    dest = clone_root / "repo"
    await sink.emit("fetch", f"Cloning {cfg.repo_url}@{cfg.ref}")
    try:
        manifest = await asyncio.to_thread(
            fetch_repo,
            cfg.repo_url,
            cfg.ref,
            dest,
            prefer_subdir=cfg.prefer_subdir,
        )
    except Exception:
        shutil.rmtree(clone_root, ignore_errors=True)
        raise
    await sink.emit(
        "fetch",
        f"Checked out {manifest.commit}; package {manifest.package_name or manifest.workdir.name} "
        f"({manifest.language}) at {manifest.workdir.relative_to(manifest.root)}",
        data={
            "commit": manifest.commit,
            "language": manifest.language,
            "package": manifest.package_name,
            "candidates": manifest.candidates[:8],
        },
    )
    return manifest, None if cfg.keep_clone else clone_root


async def _prepare_sandbox(
    cfg: ScanConfig,
    manifest: RepoManifest,
    sink: EventSink,
    llm: LlmClient,
) -> tuple[Sandbox, LaunchPlan, dict[str, Any]]:
    want = cfg.sandbox
    demo = _under_demo(manifest.workdir)
    recipe_blob: dict[str, Any] = {}

    if want == "auto":
        want = "fake" if demo else "docker"

    if want == "fake":
        script = manifest.workdir / "server.py"
        if not demo:
            raise LocalLaunchRefused(
                f"fake sandbox only allowed for demo/ servers, got {manifest.workdir}"
            )
        if not script.exists():
            raise LocalLaunchRefused(f"demo server.py missing at {script}")
        await sink.emit("build", "No build step for local demo source")
        plan = demo_launch_plan()
        return FakeSandbox(cfg.scan_id, script=script), plan, recipe_blob

    # docker path — LLM generates executable launch.sh (runs in image) + install recipe.
    if not await docker_available():
        raise BuildError("Docker is required to scan non-demo repositories")

    await sink.emit("build", "Asking LLM for executable launch.sh + install recipe")
    recipe = await generate_recipe(manifest, llm, cfg.scan_id)
    empty = DiscoveryResult(server_name=manifest.package_name or manifest.workdir.name)
    gen = await generate_executable_code(
        empty,
        llm,
        manifest.workdir,
        scan_brief=cfg.scan_brief,
        cache_key=make_key(
            repo_url=cfg.repo_url,
            commit=manifest.commit or "local",
            brief=cfg.scan_brief,
            kind="launch",
        ),
    )
    write_launch_script(manifest.workdir, gen.launch_sh)
    recipe_blob = {
        **recipe.model_dump(),
        "codegen": {
            "source": gen.source,
            "rationale": gen.rationale,
            "launch_sh": gen.launch_sh,
            "launch_ok": gen.launch_ok,
            "errors": gen.errors,
        },
    }
    await sink.emit(
        "build",
        f"Generated launch.sh ({gen.source}): {gen.launch_sh.strip()[:160]!r}",
        data={"codegen_source": gen.source, "install_argv": recipe.install_argv},
    )

    image = cfg.image
    if image is None:
        plan_build = recipe_to_build_plan(recipe, manifest, cfg.scan_id)
        await sink.emit(
            "build",
            f"Building {plan_build.image_tag} via packaged {plan_build.template} template "
            f"(install: {' '.join(plan_build.install_argv)})",
            data={"language": plan_build.language, "base": plan_build.base_image},
        )
        image = await asyncio.to_thread(build_image, plan_build)
        await sink.emit("build", f"Image ready: {image}")
    else:
        await sink.emit("build", f"Using prebuilt image {image}")

    preferred = [
        LaunchCandidate(
            argv=["/bin/sh", "/app/toolpain_launch.sh"],
            rationale="LLM-generated launch.sh inside image",
        ),
        *recipe_launch_candidates(recipe),
    ]
    if cfg.server_cmd is not None:
        launch = await resolve_launch_plan(image, manifest, override=cfg.server_cmd)
    else:
        await sink.emit("build", "Trial-launching generated launch.sh / fallbacks")
        launch = await resolve_launch_plan(
            image,
            manifest,
            preferred=preferred,
            preferred_source="llm" if gen.source == "llm" else recipe.source,
        )
    await sink.emit(
        "build",
        f"LaunchPlan: {' '.join(launch.argv)} ({launch.source}: {launch.rationale})",
        data={"argv": launch.argv, "tried": len(launch.tried)},
    )
    sb = DockerSandbox(cfg.scan_id, image, launch.argv, runtime=cfg.runtime)
    return sb, launch, recipe_blob


async def _scan_http_endpoint(cfg: ScanConfig, sink: EventSink) -> dict[str, Any]:
    """Probe an already-running HTTP/SSE MCP endpoint (localhost or https)."""
    await sink.emit("discover", f"HTTP MCP list_tools {cfg.mcp_url}")
    client = HttpMcpClient(cfg.mcp_url or "")
    tools = await client.list_tools()
    names = [str(t.get("name")) for t in tools]
    flagged = "fetch_report" in names
    tool_rows = [
        {
            "name": n,
            "privilege": "high" if n == "fetch_report" else "low",
            "verdict": "flagged" if n == "fetch_report" else "confirmed",
            "sources": ["R"],
        }
        for n in names
    ]
    findings = []
    if flagged:
        findings.append(
            {
                "id": "F1",
                "severity": "high",
                "type": "http_undocumented_tool",
                "tool": "fetch_report",
                "title": "HTTP MCP exposes fetch_report",
                "evidence": cfg.mcp_url,
                "explanation": "Tool listed over HTTP JSON-RPC.",
                "recommendation": "Review the tool before granting it to an agent.",
            }
        )
    report = {
        "scan_id": cfg.scan_id,
        "repo": {"url": cfg.repo_url, "ref": cfg.ref, "commit": "http"},
        "verdict": "suspicious" if flagged else "clean",
        "stats": {"tools": len(names), "undocumented": int(flagged)},
        "tools": tool_rows,
        "findings": findings,
        "transport": {"kind": "http" if cfg.protocol != "sse" else "sse", "mcp_url": cfg.mcp_url},
        "runtime": cfg.runtime,
        "scan_brief": cfg.scan_brief,
    }
    await sink.emit("report", f"HTTP MCP scan {report['verdict']} ({len(names)} tools)")
    return report


async def run_scan_async(
    cfg: ScanConfig,
    *,
    sandbox: Sandbox | None = None,
    sink: EventSink | None = None,
    llm: LlmClient | None = None,
) -> dict[str, Any]:
    if sink is None:
        sink = (
            HttpSink(cfg.control_plane_url, cfg.scan_id, cfg.token)
            if cfg.control_plane_url and cfg.token
            else NullSink()
        )
    llm = llm or build_llm(cfg.llm_mode, cfg.control_plane_url, cfg.token)
    clone_cleanup: Path | None = None
    sb: Sandbox | None = sandbox
    launch: LaunchPlan | None = None
    recipe_blob: dict[str, Any] = {}

    try:
        cfg.scan_brief = sanitize_scan_brief(cfg.scan_brief)
        if cfg.mcp_url and cfg.protocol in {"http", "sse", "auto"}:
            report = await _scan_http_endpoint(cfg, sink)
            await sink.report(report)
            return report
        await sink.emit(
            "intake",
            f"Runner started for {cfg.repo_url}@{cfg.ref}"
            + (f" (brief: {cfg.scan_brief[:80]}…)" if cfg.scan_brief else ""),
        )
        manifest, clone_cleanup = await _prepare_source(cfg, sink)
        workdir_blob: dict[str, Any] = {}
        if not _under_demo(manifest.workdir):
            manifest, workdir_blob = await _maybe_llm_workdir(cfg, manifest, sink, llm)
        source = manifest.workdir
        readme = _readme_text(manifest)
        upstream = cfg.upstream_tools if cfg.upstream_tools is not None else _load_upstream(source)
        if upstream is None and cfg.upstream_url:
            upstream = await fetch_upstream_tool_names(cfg.upstream_url, ref=cfg.ref)
        elif upstream is None and os.environ.get("TOOLPAIN_RESOLVE_UPSTREAM") == "1":
            parent = await resolve_github_parent(cfg.repo_url)
            if parent:
                cfg.upstream_url = parent
                upstream = await fetch_upstream_tool_names(parent, ref=cfg.ref)

        if sb is None:
            sb, launch, recipe_blob = await _prepare_sandbox(cfg, manifest, sink, llm)
        elif launch is None:
            launch = (
                demo_launch_plan()
                if _under_demo(source)
                else LaunchPlan(
                    argv=cfg.server_cmd or ["python", "/app/server.py"],
                    source="override",
                    rationale="pre-supplied sandbox",
                )
            )
        if workdir_blob:
            recipe_blob["workdir_pick"] = workdir_blob

        await sb.start()
        await sink.emit(
            "isolate",
            f"Sandbox ready; {len(sb.decoys.paths)} decoys planted",
            data={"decoys": len(sb.decoys.paths)},
        )

        await sink.emit("discover", "Discovering tools (docs, static, runtime, flags)")
        discovery = await discover(sb.launcher, source_dir=source, readme_text=readme)
        await sink.emit(
            "discover",
            f"Found {len(discovery.tools)} tools; undocumented: "
            f"{', '.join(discovery.undocumented) or 'none'}",
            data={"tools": discovery.names, "undocumented": discovery.undocumented},
        )

        profiles = await research_tools(discovery, llm, readme)
        await sink.emit("research", f"Profiled {len(profiles)} tools")

        await sink.emit(
            "research",
            "Generating executable probe_py + oracle_py (AST-guarded)",
        )
        gen_probe = await generate_executable_code(
            discovery,
            llm,
            source,
            fixture_url=sb.fixture_url,
            scan_brief=cfg.scan_brief,
            cache_key=make_key(
                repo_url=cfg.repo_url,
                commit=manifest.commit or "local",
                brief=cfg.scan_brief,
                kind="probe",
            ),
        )
        probe_mod = None
        try:
            harness = harness_from_generated(gen_probe, discovery, sb.fixture_url)
            probe_mod = load_probe_module(gen_probe.probe_py)
        except Exception as exc:  # noqa: BLE001 — fall back to JSON harness
            await sink.emit(
                "research",
                f"Executable probe failed ({exc!r}); falling back to JSON harness",
                level="warn",
            )
            harness = await generate_harness(discovery, llm, source, fixture_url=sb.fixture_url)
        recipe_blob["probe_codegen"] = {
            "source": gen_probe.source,
            "rationale": gen_probe.rationale,
            "probe_py": gen_probe.probe_py[:4000],
            "oracle_py": gen_probe.oracle_py[:4000],
            "probe_ok": gen_probe.probe_ok,
            "oracle_ok": gen_probe.oracle_ok,
            "errors": gen_probe.errors,
            "scan_brief": cfg.scan_brief,
        }
        await sink.emit(
            "research",
            f"Harness ready ({harness.source}): {harness.server_summary[:120]}",
            data={
                "harness_source": harness.source,
                "plans": len(harness.plans),
                "probe_codegen": gen_probe.source,
            },
        )

        probes = await probe_tools(
            sb.launcher,
            sb,
            discovery.tools,
            call_timeout=cfg.call_timeout,
            sink=sink,
            harness=harness,
        )
        await sink.emit("probe", f"Probed {len(probes)} tools (round 1)")

        # Optional second-round plans from executable probe strategy
        if probe_mod is not None:
            try:
                round2 = next_plans_from_probe_module(
                    probe_mod,
                    discovery,
                    sb.fixture_url,
                    observations_from_probes(probes),
                )
            except Exception as exc:  # noqa: BLE001
                await sink.emit("probe", f"next_plans failed: {exc!r}", level="warn")
                round2 = []
            if round2:
                await sink.emit("probe", f"Executable next_plans → {len(round2)} follow-up calls")
                round2_tools = [t for t in discovery.tools if any(p.tool == t.name for p in round2)]
                harness2 = ProbeHarness(
                    server_summary="Executable next_plans round",
                    plans=round2,
                    source=harness.source,
                )
                probes2 = await probe_tools(
                    sb.launcher,
                    sb,
                    round2_tools,
                    call_timeout=cfg.call_timeout,
                    sink=sink,
                    harness=harness2,
                )
                probes.update(probes2)
                recipe_blob["probe_codegen"]["round2_plans"] = len(round2)
                await sink.emit("probe", f"Probed {len(probes)} tools after round 2")

        oracle_findings: list[dict[str, Any]] = []
        try:
            oracle_findings = run_oracle(gen_probe.oracle_py, probes)
            if oracle_findings:
                await sink.emit(
                    "analyze",
                    f"Executable oracle emitted {len(oracle_findings)} findings",
                )
        except Exception as exc:  # noqa: BLE001
            await sink.emit("analyze", f"oracle_py failed: {exc!r}", level="warn")

        await sink.emit(
            "analyze", "Running discrepancy, privilege, SoD, egress and anomaly analysis"
        )
        data = AnalysisInput(
            discovery=discovery,
            profiles=profiles,
            probes=probes,
            readme_text=readme,
            upstream_tools=upstream,
        )
        analysis = analyze_scan(data)
        repo = {
            "url": cfg.repo_url,
            "ref": cfg.ref,
            "commit": manifest.commit or git_commit(manifest.root),
            "upstream": None,
            "package": manifest.package_name,
            "language": manifest.language,
            "workdir": str(
                manifest.workdir.relative_to(manifest.root)
                if manifest.root in manifest.workdir.parents or manifest.workdir == manifest.root
                else manifest.workdir
            ),
        }
        report = build_report(cfg.scan_id, repo, data, analysis)

        # Expectation scoring (harness expect_* vs observed) — never downgrades flagged.
        expect_results = score_expectations(harness, probes)
        expect_blob = [e.model_dump() for e in expect_results]
        expect_findings = expectation_findings(expect_results)

        extra_findings = list(expect_findings) + list(oracle_findings)
        if extra_findings:
            base = list(report.get("findings") or [])
            # Oracle / expectation findings cannot clear a decoy/egress flagged verdict.
            start = len(base) + 1
            for i, f in enumerate(extra_findings):
                base.append({"id": f"F{start + i}", **f})
            report["findings"] = base
        report["stats"] = {
            **(report.get("stats") or {}),
            "oracle_findings": len(oracle_findings),
            "expectation_misses": sum(1 for e in expect_results if not e.hit),
            "expectation_hits": sum(1 for e in expect_results if e.hit),
        }
        if oracle_findings:
            report["llm_oracle"] = oracle_findings
        report["expectations"] = expect_blob
        report["harness"] = harness_to_report_blob(harness)
        if cfg.scan_brief:
            report["scan_brief"] = cfg.scan_brief
        if launch is not None:
            report["launch"] = {
                "argv": launch.argv,
                "source": launch.source,
                "rationale": launch.rationale,
            }
        if recipe_blob:
            report["recipe"] = recipe_blob
        cg = (recipe_blob or {}).get("codegen") or {}
        pg = (recipe_blob or {}).get("probe_codegen") or {}
        wp = (recipe_blob or {}).get("workdir_pick") or {}
        report["artifacts"] = {
            "launch_sh": (cg.get("launch_sh") or "")[:2000],
            "launch_source": cg.get("source") or (launch.source if launch else None),
            "workdir": wp.get("subdir") or repo.get("workdir"),
            "workdir_source": wp.get("source"),
            "probe_source": pg.get("source") or harness.source,
            "probe_summary": (harness.server_summary or "")[:300],
            "oracle_ok": pg.get("oracle_ok"),
            "round2_plans": pg.get("round2_plans") or 0,
            "scan_brief": cfg.scan_brief,
        }
        report["transport"] = {"kind": cfg.protocol or "stdio", "mcp_url": cfg.mcp_url}
        report["runtime"] = cfg.runtime
        if cfg.upstream_url or upstream:
            report["upstream"] = {
                "url": cfg.upstream_url,
                "tools_count": len(upstream or []),
                "method": "explicit" if cfg.upstream_url else "local_file",
            }
        report["cache"] = {
            "key": make_key(
                repo_url=cfg.repo_url,
                commit=str(repo.get("commit") or "local"),
                brief=cfg.scan_brief,
                kind="exec",
            )
        }
        report["costs"] = {
            "llm_codegen_calls_est": sum(
                1
                for x in (
                    wp.get("source") == "llm",
                    cg.get("source") == "llm",
                    pg.get("source") == "llm",
                )
                if x
            ),
            "probe_rounds": 1 + (1 if pg.get("round2_plans") else 0),
        }
        await sink.emit(
            "report",
            f"Verdict: {report['verdict']} ({len(report['findings'])} findings)",
            data={"verdict": report["verdict"]},
        )
        await sink.report(report)
        return report
    except Exception as exc:
        await sink.emit("report", f"Scan failed: {exc!r}", level="warn")
        raise
    finally:
        if sb is not None:
            await sb.stop()
        await sink.emit("destroy", "Sandbox torn down")
        if clone_cleanup is not None:
            shutil.rmtree(clone_cleanup, ignore_errors=True)
        if isinstance(sink, HttpSink):
            await sink.aclose()


def run_scan(
    scan_id: str,
    repo_url: str,
    ref: str = "main",
    token: str | None = None,
    control_plane_url: str | None = None,
    local_path: Path | None = None,
    **options: Any,
) -> dict[str, Any]:
    """Synchronous wrapper around :func:`run_scan_async` (CLI and ``make demo``)."""
    cfg = ScanConfig(
        scan_id=scan_id,
        repo_url=repo_url,
        ref=ref,
        token=token,
        control_plane_url=control_plane_url,
        local_path=local_path,
        llm_mode=os.environ.get("LLM_MODE", "fake"),
        **options,
    )
    return asyncio.run(run_scan_async(cfg))


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    p = argparse.ArgumentParser(description="ToolPain scan runner")
    p.add_argument("--scan-id", required=True)
    p.add_argument("--repo-url", default="https://github.com/lupong/toolpain")
    p.add_argument("--ref", default="main")
    p.add_argument("--token", default=os.environ.get("SCAN_TOKEN"))
    p.add_argument("--control-plane-url", default=os.environ.get("CONTROL_PLANE_URL"))
    p.add_argument(
        "--local-path",
        type=Path,
        default=None,
        help="Use an existing tree instead of cloning --repo-url",
    )
    p.add_argument("--sandbox", choices=["fake", "docker", "auto"], default="auto")
    p.add_argument("--image", default=None)
    p.add_argument("--server-cmd", nargs="+", default=None)
    p.add_argument("--prefer-subdir", default=None)
    p.add_argument(
        "--scan-brief",
        default=None,
        help="Optional user intent folded into executable codegen prompts",
    )
    p.add_argument("--runtime", default=os.environ.get("RUNTIME", "runc"))
    args = p.parse_args()
    report = run_scan(
        args.scan_id,
        args.repo_url,
        ref=args.ref,
        token=args.token,
        control_plane_url=args.control_plane_url,
        local_path=args.local_path.resolve() if args.local_path else None,
        sandbox=args.sandbox,
        image=args.image,
        server_cmd=args.server_cmd,
        prefer_subdir=args.prefer_subdir,
        scan_brief=args.scan_brief,
        runtime=args.runtime,
    )
    print(json.dumps({"verdict": report["verdict"], "stats": report["stats"]}, indent=2))


if __name__ == "__main__":
    main()
