"""Failure/destroy events must leave status=running so the UI SSE can finish."""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from control_plane.failures import terminal_update_from_event
from control_plane.main import AppState, app
from control_plane.provisioner.demo import DemoProvisioner


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
        delay_sec=0.05,
    )
    main_mod.STATE = state
    with TestClient(app) as c:
        yield c


def test_coded_failure_terminalizes() -> None:
    out = terminal_update_from_event(
        stage="report",
        msg="Scan failed: McpClientError: connection closed",
        data={"code": "internal", "error": "internal"},
    )
    assert out == {
        "status": "failed",
        "error_code": "internal",
        "error_detail": "Scan failed: McpClientError: connection closed",
    }


def test_codegen_retry_free_text_error_does_not_terminalize() -> None:
    out = terminal_update_from_event(
        stage="build",
        msg="Codegen setup attempt 1 did not run; sending the failure back",
        data={"error": "pip failed: No module named foo"},
    )
    assert out is None


def test_sandbox_destroy_without_report_terminalizes() -> None:
    out = terminal_update_from_event(
        stage="destroy",
        msg="Sandbox torn down",
        data={},
    )
    assert out is not None
    assert out["status"] == "failed"
    assert out["error_code"] == "internal"


def test_instance_destroy_without_report_is_timeout() -> None:
    out = terminal_update_from_event(
        stage="destroy",
        msg="Instance destroyed",
        data={},
    )
    assert out is not None
    assert out["status"] == "timeout"
    assert out["error_code"] == "probe_timeout"


def test_internal_event_marks_scan_failed(client) -> None:  # type: ignore[no-untyped-def]
    import control_plane.main as main_mod

    r = client.post(
        "/api/scans",
        json={
            "repo_url": "https://github.com/modelcontextprotocol/servers",
            "prefer_subdir": "src/filesystem",
        },
    )
    assert r.status_code == 201, r.text
    scan_id = r.json()["id"]
    token = main_mod.STATE.db.get_token(scan_id)
    assert token

    ev = client.post(
        f"/internal/scans/{scan_id}/events",
        headers={"X-Scan-Token": token},
        json={
            "stage": "report",
            "level": "warn",
            "msg": "Scan failed",
            "data": {"code": "internal", "error": "internal"},
        },
    )
    assert ev.status_code == 201
    scan = client.get(f"/api/scans/{scan_id}").json()
    assert scan["status"] == "failed"
    assert scan["error_code"] == "internal"

    # Later destroy must not bounce a terminal scan.
    client.post(
        f"/internal/scans/{scan_id}/events",
        headers={"X-Scan-Token": token},
        json={"stage": "destroy", "level": "info", "msg": "Sandbox torn down"},
    )
    assert client.get(f"/api/scans/{scan_id}").json()["status"] == "failed"


def test_destroy_alone_marks_failed(client) -> None:  # type: ignore[no-untyped-def]
    import control_plane.main as main_mod

    r = client.post(
        "/api/scans",
        json={
            "repo_url": "https://github.com/modelcontextprotocol/servers",
            "prefer_subdir": "src/filesystem",
        },
    )
    assert r.status_code == 201, r.text
    scan_id = r.json()["id"]
    token = main_mod.STATE.db.get_token(scan_id)
    assert token
    main_mod.STATE.db.update_scan(scan_id, status="running")

    client.post(
        f"/internal/scans/{scan_id}/events",
        headers={"X-Scan-Token": token},
        json={"stage": "destroy", "level": "info", "msg": "Sandbox torn down"},
    )
    scan = client.get(f"/api/scans/{scan_id}").json()
    assert scan["status"] == "failed"
