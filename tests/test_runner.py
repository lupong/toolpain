"""run_scan: end-to-end local/demo pipeline and control-plane event posting."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import respx

from runner.events import HttpSink, NullSink
from runner.launch import LocalLaunchRefused
from runner.main import ScanConfig, run_scan_async

EVENTS_URL = "http://cp.test/internal/scans/s_http/events"
REPORT_URL = "http://cp.test/internal/scans/s_http/report"


@respx.mock
async def test_run_scan_posts_events_and_report_with_token() -> None:
    events = respx.post(EVENTS_URL).mock(return_value=httpx.Response(201, json={}))
    report_route = respx.post(REPORT_URL).mock(return_value=httpx.Response(201, json={}))
    cfg = ScanConfig(
        scan_id="s_http",
        repo_url="https://github.com/lupong/toolpain",
        token="scan-token-1",
        control_plane_url="http://cp.test",
    )
    report = await run_scan_async(cfg)

    assert report["verdict"] == "flagged"
    bodies = [json.loads(c.request.content) for c in events.calls]
    stages = [b["stage"] for b in bodies]
    for stage in (
        "intake",
        "isolate",
        "discover",
        "research",
        "probe",
        "analyze",
        "report",
        "destroy",
    ):
        assert stage in stages, stage
    assert stages.index("discover") < stages.index("probe") < stages.index("analyze")
    alerts = [b for b in bodies if b["level"] == "alert"]
    assert len(alerts) == 1 and "fetch_report" in alerts[0]["msg"]
    assert all(c.request.headers["X-Scan-Token"] == "scan-token-1" for c in events.calls)
    assert report_route.call_count == 1
    posted = json.loads(report_route.calls.last.request.content)
    assert posted["verdict"] == "flagged" and posted["scan_id"] == "s_http"
    assert report_route.calls.last.request.headers["X-Scan-Token"] == "scan-token-1"


@respx.mock
async def test_run_scan_without_token_makes_no_http_calls() -> None:
    sink = NullSink()
    cfg = ScanConfig(scan_id="s_local", repo_url="https://github.com/lupong/toolpain")
    report = await run_scan_async(cfg, sink=sink)  # respx with no routes: any HTTP call would fail
    assert report["verdict"] == "flagged"
    assert sink.reports == [report] and sink.events


@respx.mock
async def test_control_plane_errors_do_not_kill_the_scan() -> None:
    respx.post(EVENTS_URL).mock(return_value=httpx.Response(500))
    respx.post(REPORT_URL).mock(side_effect=httpx.ConnectError("down"))
    cfg = ScanConfig(
        scan_id="s_http",
        repo_url="https://github.com/lupong/toolpain",
        token="t",
        control_plane_url="http://cp.test",
    )
    assert (await run_scan_async(cfg))["verdict"] == "flagged"


async def test_http_sink_posts_to_internal_endpoints() -> None:
    with respx.mock:
        ev = respx.post("http://cp.test/internal/scans/abc/events").mock(
            return_value=httpx.Response(201)
        )
        sink = HttpSink("http://cp.test/", "abc", "tok")
        await sink.emit("probe", "hello", level="warn", data={"k": 1})
        await sink.aclose()
    assert json.loads(ev.calls.last.request.content) == {
        "stage": "probe",
        "level": "warn",
        "msg": "hello",
        "data": {"k": 1},
    }


async def test_local_run_refused_outside_demo(tmp_path: Path) -> None:
    (tmp_path / "server.py").write_text("print('hi')")
    cfg = ScanConfig(scan_id="s_bad", repo_url="https://github.com/a/b", local_path=tmp_path)
    with pytest.raises(LocalLaunchRefused):
        await run_scan_async(cfg)


async def test_docker_sandbox_requires_image() -> None:
    cfg = ScanConfig(scan_id="s_x", repo_url="https://github.com/a/b", sandbox="docker")
    with pytest.raises(ValueError, match="image"):
        await run_scan_async(cfg)
