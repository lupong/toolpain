"""M1: control plane create → SSE → report; validation + token auth."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from control_plane.main import AppState, app
from control_plane.provisioner.fake import FakeProvisioner


@pytest.fixture()
def client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("PROVISIONER", "fake")
    monkeypatch.setenv("LLM_MODE", "fake")
    monkeypatch.setenv("TOOLPAIN_DATA_DIR", str(tmp_path))
    # Rebuild app state against temp DB
    import control_plane.main as main_mod

    state = AppState()
    state.provisioner = FakeProvisioner(
        emit_event=state.emit_event,
        save_report=state.save_report,
        update_scan=state.update_scan,
        delay_sec=0.05,
    )
    main_mod.STATE = state
    with TestClient(app) as c:
        yield c


def test_invalid_repo_url_422(client: TestClient) -> None:
    r = client.post("/api/scans", json={"repo_url": "not-a-github-url"})
    assert r.status_code == 422


def test_wrong_token_401(client: TestClient) -> None:
    r = client.post(
        "/api/scans",
        json={"repo_url": "https://github.com/microsoft/playwright-mcp"},
    )
    assert r.status_code == 201
    scan_id = r.json()["id"]
    bad = client.post(
        f"/internal/scans/{scan_id}/events",
        headers={"X-Scan-Token": "wrong"},
        json={"stage": "probe", "msg": "nope"},
    )
    assert bad.status_code == 401


def test_create_scan_sse_report(client: TestClient) -> None:
    r = client.post(
        "/api/scans",
        json={"repo_url": "https://github.com/andrew/playwright-mcp", "ref": "main"},
    )
    assert r.status_code == 201
    body = r.json()
    scan_id = body["id"]
    assert body["status"] == "queued"
    assert body["account_mode"] == "toolpain"

    # Poll until report ready (fake provisioner is fast)
    report = None
    for _ in range(80):
        rr = client.get(f"/api/scans/{scan_id}/report")
        if rr.status_code == 200:
            report = rr.json()
            break
        time.sleep(0.05)
    assert report is not None
    assert report["verdict"] == "flagged"
    assert report["scan_id"] == scan_id
    assert any(f["type"] == "decoy_read_and_egress" for f in report["findings"])

    # Events were recorded
    scan = client.get(f"/api/scans/{scan_id}").json()
    assert scan["status"] == "done"
    assert scan["verdict"] == "flagged"


def test_demo_reports_match_their_story() -> None:
    from control_plane.models import Report
    from control_plane.sample_report import report_for_demo

    clean = report_for_demo("server-filesystem", "s_clean")
    Report.model_validate(clean)
    assert clean["verdict"] == "clean"
    assert clean["stats"]["undocumented"] == 0
    assert clean["stats"]["decoy_reads"] == 0
    assert clean["findings"] == []
    names = [t["name"] for t in clean["tools"]]
    assert "read_file" in names
    assert "fetch_report" not in names
    assert "browser_navigate" not in names

    over = report_for_demo("playwright-mcp", "s_over")
    Report.model_validate(over)
    assert over["verdict"] == "over_privileged"
    assert over["stats"]["decoy_reads"] == 0
    assert over["stats"]["undocumented"] == 0
    assert all(f["type"] != "decoy_read_and_egress" for f in over["findings"])
    assert all(t["name"] != "fetch_report" for t in over["tools"])

    flagged = report_for_demo("decoy-trap-server", "s_flag")
    Report.model_validate(flagged)
    assert flagged["verdict"] == "flagged"
    assert any(t["name"] == "fetch_report" for t in flagged["tools"])


def test_filesystem_demo_scan_is_clean(client: TestClient) -> None:
    r = client.post(
        "/api/scans",
        json={
            "repo_url": "https://github.com/modelcontextprotocol/servers",
            "demo": "server-filesystem",
        },
    )
    assert r.status_code == 201
    scan_id = r.json()["id"]
    report = None
    for _ in range(80):
        rr = client.get(f"/api/scans/{scan_id}/report")
        if rr.status_code == 200:
            report = rr.json()
            break
        time.sleep(0.05)
    assert report is not None
    assert report["verdict"] == "clean"
    assert "fetch_report" not in {t["name"] for t in report["tools"]}
    log = client.get(f"/api/scans/{scan_id}/log")
    assert log.status_code == 200
    assert log.json()
    assert all("fetch_report" not in ev["msg"] for ev in log.json())


def test_internal_event_with_token(client: TestClient) -> None:
    import control_plane.main as main_mod

    r = client.post(
        "/api/scans",
        json={"repo_url": "https://github.com/modelcontextprotocol/servers"},
    )
    scan_id = r.json()["id"]
    token = main_mod.STATE.db.get_token(scan_id)
    assert token
    ev = client.post(
        f"/internal/scans/{scan_id}/events",
        headers={"X-Scan-Token": token},
        json={"stage": "discover", "level": "info", "msg": "found 3 tools"},
    )
    assert ev.status_code == 201
