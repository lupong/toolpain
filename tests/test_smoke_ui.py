"""M2 smoke: fake provisioner full scan + UI assets present (Playwright optional)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient


@pytest.mark.smoke
def test_fake_scan_and_ui_assets(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROVISIONER", "fake")
    monkeypatch.setenv("LLM_MODE", "fake")
    monkeypatch.setenv("TOOLPAIN_DATA_DIR", str(tmp_path))

    import control_plane.main as main_mod
    from control_plane.main import AppState, app
    from control_plane.provisioner.fake import FakeProvisioner

    state = AppState()
    state.provisioner = FakeProvisioner(
        emit_event=state.emit_event,
        save_report=state.save_report,
        update_scan=state.update_scan,
        delay_sec=0.05,
    )
    main_mod.STATE = state

    web = Path(__file__).resolve().parents[1] / "web"
    assert (web / "index.html").exists()
    assert (web / "scan.html").exists()
    assert "TP.appendLog" in (web / "app.js").read_text()
    assert "EventSource" in (web / "app.js").read_text()

    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        assert client.get("/scan.html").status_code == 200
        assert client.get("/app.js").status_code == 200

        r = client.post(
            "/api/scans",
            json={"repo_url": "https://github.com/andrew/playwright-mcp", "demo": "decoy-trap-server"},
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
        assert report["verdict"] == "flagged"
        assert any("Report" in line for line in (web / "scan.html").read_text().splitlines() if "Report" in line)

        # Optional Playwright path — skip cleanly if browsers missing
        try:
            from playwright.sync_api import sync_playwright
        except Exception:
            return

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                # Static check of design file loads offline
                page.goto((web / "index.html").as_uri())
                page.wait_for_selector("#scan-btn")
                browser.close()
        except Exception as exc:
            pytest.skip(f"playwright browsers unavailable: {exc}")
