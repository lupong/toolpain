"""M5/M6: probe decoy-trap + analysis yields flagged / critical finding."""

from __future__ import annotations

from pathlib import Path

import pytest

from runner.analyze import AnalysisInput, analyze_scan
from runner.discover import discover
from runner.launch import local_launcher
from runner.main import run_scan
from runner.probe import probe_tools
from runner.report import build_report
from runner.research import FixtureLlm, research_tools
from sandbox.demo import DemoSandbox
from sandbox.trace import parse_strace_text

DECOY = Path(__file__).resolve().parents[1] / "demo" / "decoy-trap-server"


def test_parser_fixture_epoch_format() -> None:
    text = (
        '1 1710000000.100000 openat(AT_FDCWD, "/workspace/canaries/decoy_secret.txt", O_RDONLY) = 5\n'
        "1 1710000000.300000 connect(7, {sa_family=AF_INET, sin_port=htons(443), "
        'sin_addr=inet_addr("10.66.0.53")}, 16) = 0\n'
    )
    events = parse_strace_text(text)
    assert any(e.kind == "file" and e.path and "decoy_secret" in e.path for e in events)
    assert any(e.kind == "net" for e in events)


@pytest.mark.asyncio
async def test_decoy_trap_analysis_flagged() -> None:
    launcher = local_launcher()
    readme = (DECOY / "README.md").read_text()
    result = await discover(launcher, source_dir=DECOY, readme_text=readme)
    profiles = await research_tools(result, FixtureLlm(), readme)
    async with DemoSandbox("s_test") as sb:
        probes = await probe_tools(launcher, sb, result.tools)

    fr = probes["fetch_report"]
    assert fr.tripped_decoy

    data = AnalysisInput(
        discovery=result,
        profiles=profiles,
        probes=probes,
        readme_text=readme,
        upstream_tools=["add", "echo", "reverse_text", "word_count", "current_time"],
    )
    analysis = analyze_scan(data)
    report = build_report(
        "s_test",
        {"url": "https://github.com/lupong/toolpain", "commit": "local"},
        data,
        analysis,
    )
    assert report["verdict"] == "flagged"
    assert report["stats"]["decoy_reads"] >= 1
    assert any(f["type"] == "decoy_read_and_egress" for f in report["findings"])
    assert any(f.get("severity") == "critical" for f in report["findings"])


def test_make_demo_path() -> None:
    report = run_scan(
        "s_demo",
        "https://github.com/lupong/toolpain",
        local_path=DECOY,
        sandbox="demo",
    )
    assert report["verdict"] == "flagged"
    assert any(f["type"] == "decoy_read_and_egress" for f in report["findings"])
