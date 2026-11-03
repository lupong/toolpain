"""Shared fixtures: docker availability and the decoy-trap sandbox image."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from pathlib import Path

import pytest

from sandbox.sandbox import docker_available

REPO = Path(__file__).resolve().parents[1]
DECOY_IMAGE = "toolpain-decoy-trap:test"
BASE_IMAGE = "python:3.12-slim"
PULL_TIMEOUT = 120
BUILD_TIMEOUT = 600


def _docker(*args: str, timeout: int) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


@pytest.fixture(scope="session")
def docker_ok() -> bool:
    return asyncio.run(docker_available())


@pytest.fixture(scope="session")
def decoy_image(docker_ok: bool) -> str:
    """Build the decoy-trap run image once per session.

    Skips (never hangs) when Docker is unavailable, the base image cannot be pulled, or the
    build fails/times out (e.g. a stuck credential helper or no network).
    """
    if not docker_ok or shutil.which("docker") is None:
        pytest.skip("docker daemon not available")
    try:
        if _docker("image", "inspect", BASE_IMAGE, timeout=15).returncode != 0:
            pull = _docker("pull", "-q", BASE_IMAGE, timeout=PULL_TIMEOUT)
            if pull.returncode != 0:
                pytest.skip(f"cannot pull {BASE_IMAGE}: {pull.stderr[-200:]}")
        build = _docker(
            "build", "-q", "-t", DECOY_IMAGE, str(REPO / "demo" / "decoy-trap-server"),
            timeout=BUILD_TIMEOUT,
        )  # fmt: skip
    except subprocess.TimeoutExpired:
        pytest.skip("docker pull/build timed out (registry or credential helper unreachable)")
    if build.returncode != 0:
        pytest.skip(f"cannot build decoy image: {build.stderr[-200:]}")
    return DECOY_IMAGE


@pytest.fixture(scope="session")
def decoy_scan() -> dict[str, object]:
    """One full local scan of demo/decoy-trap-server (FakeSandbox), shared across test modules."""
    from runner.analyze import AnalysisInput, analyze_scan
    from runner.discover import discover
    from runner.events import NullSink
    from runner.launch import DECOY_SERVER
    from runner.probe import probe_tools
    from runner.report import build_report
    from runner.research import FakeLlm, research_tools
    from sandbox.fake import FakeSandbox

    source = DECOY_SERVER.parent
    readme = (source / "README.md").read_text()
    upstream = ["add", "echo", "reverse_text", "word_count", "current_time"]

    async def go() -> dict[str, object]:
        sink = NullSink()
        async with FakeSandbox("s_fix") as sb:
            discovery = await discover(sb.launcher, source_dir=source, readme_text=readme)
            profiles = await research_tools(discovery, FakeLlm(), readme)
            probes = await probe_tools(sb.launcher, sb, discovery.tools, sink=sink)
            data = AnalysisInput(
                discovery=discovery,
                profiles=profiles,
                probes=probes,
                readme_text=readme,
                upstream_tools=upstream,
            )
            analysis = analyze_scan(data)
            report = build_report("s_fix", {"url": "https://github.com/x/y"}, data, analysis)
            return {
                "discovery": discovery,
                "profiles": profiles,
                "probes": probes,
                "data": data,
                "analysis": analysis,
                "report": report,
                "sink": sink,
                "decoys": sb.decoys,
            }

    return asyncio.run(go())
