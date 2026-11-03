"""Runner entry point: discover -> research -> probe -> analyze -> report.

``run_scan`` drives the pipeline for a local/demo source tree. Without Docker it uses
``FakeSandbox`` (the demo server runs as a local process, trace replayed from a fixture);
with ``sandbox="docker"`` the target runs inside ``DockerSandbox``. Progress events and the
final report are posted to the control plane when ``control_plane_url`` and ``token`` are set.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from runner.analyze import AnalysisInput, analyze_scan
from runner.discover import discover
from runner.events import EventSink, HttpSink, NullSink
from runner.harness import generate_harness, harness_to_report_blob
from runner.launch import DECOY_SERVER
from runner.probe import probe_tools
from runner.report import build_report
from runner.research import LlmClient, build_llm, research_tools
from sandbox.fake import FakeSandbox
from sandbox.sandbox import DockerSandbox, Sandbox

log = logging.getLogger("toolpain.runner")
DEFAULT_SOURCE = DECOY_SERVER.parent


class ScanConfig(BaseModel):
    scan_id: str
    repo_url: str
    ref: str = "main"
    token: str | None = None
    control_plane_url: str | None = None
    local_path: Path = DEFAULT_SOURCE
    sandbox: Literal["fake", "docker"] = "fake"
    image: str | None = None
    server_cmd: list[str] = Field(default_factory=lambda: ["python", "/app/server.py"])
    runtime: str = "runc"
    llm_mode: str = "fake"
    upstream_tools: list[str] | None = None
    call_timeout: float = 30.0


def _git_commit(path: Path) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        return out.stdout.strip() or "local"
    except (OSError, subprocess.SubprocessError):
        return "local"


def _load_upstream(path: Path) -> list[str] | None:
    file = path / "upstream_tools.json"
    if not file.exists():
        return None
    data = json.loads(file.read_text(encoding="utf-8"))
    return [str(x) for x in data] if isinstance(data, list) else None


def _make_sandbox(cfg: ScanConfig) -> Sandbox:
    if cfg.sandbox == "docker":
        if not cfg.image:
            raise ValueError("sandbox='docker' requires an image")
        return DockerSandbox(cfg.scan_id, cfg.image, cfg.server_cmd, runtime=cfg.runtime)
    return FakeSandbox(cfg.scan_id, script=cfg.local_path / "server.py")


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
    sb = sandbox or _make_sandbox(cfg)
    source = cfg.local_path
    readme_file = source / "README.md"
    readme = readme_file.read_text(encoding="utf-8") if readme_file.exists() else None
    upstream = cfg.upstream_tools if cfg.upstream_tools is not None else _load_upstream(source)

    try:
        await sink.emit("intake", f"Runner started for {cfg.repo_url}@{cfg.ref}")
        await sink.emit("fetch", f"Using local source {source}")
        await sink.emit("build", "No build step for local/demo source")
        await sb.start()
        await sink.emit(
            "isolate",
            f"Sandbox ready ({cfg.sandbox}); {len(sb.decoys.paths)} decoys planted",
            data={"decoys": len(sb.decoys.paths)},
        )

        await sink.emit("discover", "Discovering tools (docs, static, runtime, flags)")
        discovery = await discover(sb.launcher, source_dir=source, readme_text=readme)
        await sink.emit(
            "discover",
            f"Found {len(discovery.tools)} tools; undocumented: {', '.join(discovery.undocumented) or 'none'}",
            data={"tools": discovery.names, "undocumented": discovery.undocumented},
        )

        profiles = await research_tools(discovery, llm, readme)
        await sink.emit("research", f"Profiled {len(profiles)} tools")

        await sink.emit(
            "research",
            "Generating probe harness from repo context (Vultr Inference when live)",
        )
        harness = await generate_harness(discovery, llm, source, fixture_url=sb.fixture_url)
        await sink.emit(
            "research",
            f"Harness ready ({harness.source}): {harness.server_summary[:120]}",
            data={"harness_source": harness.source, "plans": len(harness.plans)},
        )

        probes = await probe_tools(
            sb.launcher,
            sb,
            discovery.tools,
            call_timeout=cfg.call_timeout,
            sink=sink,
            harness=harness,
        )
        await sink.emit("probe", f"Probed {len(probes)} tools")

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
            "commit": _git_commit(source),
            "upstream": None,
        }
        report = build_report(cfg.scan_id, repo, data, analysis)
        report["harness"] = harness_to_report_blob(harness)
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
        await sb.stop()
        await sink.emit("destroy", "Sandbox torn down")
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
        local_path=local_path or DEFAULT_SOURCE,
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
    p.add_argument("--local-path", type=Path, default=DEFAULT_SOURCE)
    p.add_argument("--sandbox", choices=["fake", "docker"], default="fake")
    p.add_argument("--image", default=None)
    p.add_argument("--runtime", default=os.environ.get("RUNTIME", "runc"))
    args = p.parse_args()
    report = run_scan(
        args.scan_id,
        args.repo_url,
        ref=args.ref,
        token=args.token,
        control_plane_url=args.control_plane_url,
        local_path=args.local_path.resolve(),
        sandbox=args.sandbox,
        image=args.image,
        runtime=args.runtime,
    )
    print(json.dumps({"verdict": report["verdict"], "stats": report["stats"]}, indent=2))


if __name__ == "__main__":
    main()
