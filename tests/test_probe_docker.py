"""M5/M6 acceptance in a real Docker sandbox (``-m docker``): contained decoy trip."""

from __future__ import annotations

import uuid

import pytest

from runner.analyze import AnalysisInput, analyze_scan
from runner.discover import discover
from runner.launch import DECOY_SERVER
from runner.probe import probe_tools
from runner.report import build_report
from runner.research import FakeLlm, research_tools
from sandbox.sandbox import DockerSandbox

SOURCE = DECOY_SERVER.parent


@pytest.mark.docker
async def test_docker_probe_records_decoy_trip_for_fetch_report(decoy_image: str) -> None:
    sb = DockerSandbox(f"s_pd{uuid.uuid4().hex[:6]}", decoy_image, ["python", "/app/server.py"])
    readme = (SOURCE / "README.md").read_text()
    async with sb:
        discovery = await discover(sb.launcher, source_dir=SOURCE, readme_text=readme)
        assert discovery.undocumented == ["fetch_report"]
        probes = await probe_tools(sb.launcher, sb, discovery.tools, call_timeout=60)
        fetch = probes["fetch_report"]
        assert fetch.decoy_reads == ["/workspace/canaries/decoy_secret.txt"]
        assert "collector.sinkhole.local" in fetch.egress_hosts
        assert fetch.decoy_in_sinkhole  # the planted value reached the sinkhole, contained
        for name, probe in probes.items():
            if name != "fetch_report":
                assert not probe.decoy_reads and not probe.egress_hosts, name
        profiles = await research_tools(discovery, FakeLlm(), readme)
        data = AnalysisInput(
            discovery=discovery,
            profiles=profiles,
            probes=probes,
            readme_text=readme,
            upstream_tools=["add", "echo", "reverse_text", "word_count", "current_time"],
        )
        report = build_report(
            "s_pdock", {"url": "https://github.com/x/y"}, data, analyze_scan(data)
        )
    assert report["verdict"] == "flagged"
    assert any(f["type"] == "decoy_read_and_egress" for f in report["findings"])
    assert await sb.leftovers() == []
