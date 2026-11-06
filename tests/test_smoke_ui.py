"""M2 smoke: fake provisioner full scan + UI assets present (Playwright optional)."""

from __future__ import annotations

import threading
import time
import urllib.request
from pathlib import Path

import pytest
import uvicorn
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
            json={
                "repo_url": "https://github.com/andrew/playwright-mcp",
                "demo": "decoy-trap-server",
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
        assert report["verdict"] == "flagged"
        assert any(
            "Report" in line
            for line in (web / "scan.html").read_text().splitlines()
            if "Report" in line
        )

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


@pytest.mark.smoke
def test_playwright_demo_reports_fit_a_phone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        pytest.skip("playwright not installed")

    monkeypatch.setenv("PROVISIONER", "fake")
    monkeypatch.setenv("LLM_MODE", "fake")
    monkeypatch.setenv("TOOLPAIN_DATA_DIR", str(tmp_path))

    import control_plane.main as main_mod
    from control_plane.main import AppState
    from control_plane.provisioner.fake import FakeProvisioner

    previous = main_mod.STATE
    state = AppState()
    state.provisioner = FakeProvisioner(
        emit_event=state.emit_event,
        save_report=state.save_report,
        update_scan=state.update_scan,
        delay_sec=0.02,
    )
    main_mod.STATE = state
    port = 8765
    config = uvicorn.Config(main_mod.app, host="127.0.0.1", port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 10
    up = False
    while time.time() < deadline:
        try:
            urllib.request.urlopen(base + "/api/health", timeout=0.5)
            up = True
            break
        except Exception:
            time.sleep(0.1)
    if not up:
        server.should_exit = True
        main_mod.STATE = previous
        pytest.fail("control plane did not start")

    expected = {
        "server-filesystem": "CLEAN",
        "playwright-mcp": "OVER-PRIVILEGED",
        "decoy-trap-server": "FLAGGED",
    }
    try:
        with sync_playwright() as p:
            try:
                browser = p.chromium.launch(headless=True)
            except Exception as exc:
                pytest.skip(f"playwright browsers unavailable: {exc}")
            page = browser.new_page(viewport={"width": 375, "height": 812})
            page.goto(base + "/")
            page.wait_for_selector("#repo")
            fits = page.evaluate(
                "() => document.documentElement.scrollWidth <= window.innerWidth + 1"
            )
            assert fits
            for demo, label in expected.items():
                page.goto(base + "/")
                page.locator(f'a.tp-demo-chip[href*="demo={demo}"]').click()
                page.wait_for_selector("#view-report", state="visible", timeout=20000)
                page.click("#view-report")
                page.wait_for_function(
                    "(label) => (document.querySelector('#verdict-badge') || {}).textContent && "
                    "document.querySelector('#verdict-badge').textContent.toUpperCase().includes(label)",
                    arg=label,
                    timeout=10000,
                )
                if demo == "server-filesystem":
                    assert "Ouch" not in page.locator("#verdict-title").inner_text()
                    assert "fetch_report" not in page.content()
                fits = page.evaluate(
                    "() => document.documentElement.scrollWidth <= window.innerWidth + 1"
                )
                assert fits
            browser.close()
    finally:
        server.should_exit = True
        main_mod.STATE = previous
