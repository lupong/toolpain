"""v5: report numbers match the data, the certificate is the ticket record, and failures have a bundle."""

from __future__ import annotations

import io
import json
import logging
import time
import zipfile
from pathlib import Path
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

from control_plane.failures import FAILURE_CODES
from control_plane.jsonlog import JsonFormatter
from control_plane.sample_report import report_for_demo


def _derived(report: dict) -> dict[str, int]:
    tools = report["tools"]
    return {
        "tools": len(tools),
        "undocumented": sum(1 for t in tools if t.get("sources") and "D" not in t["sources"]),
        "critical_tier": sum(1 for t in tools if t.get("privilege") == "critical"),
        "toxic_combos": len(report["toxic_combos"]),
        "egress_attempted": len((report.get("egress") or {}).get("attempted") or []),
        "decoy_reads": sum(int(t.get("decoy_reads") or 0) for t in tools),
    }


@pytest.mark.parametrize("demo", ["server-filesystem", "playwright-mcp", "decoy-trap-server"])
def test_demo_counts_match_the_report(demo: str) -> None:
    report = report_for_demo(demo, "s_demo")
    assert report["stats"] == _derived(report)


def test_landing_has_no_debug_chip_and_derives_counts() -> None:
    html = Path("web/index.html").read_text(encoding="utf-8")
    nav = html.split("</nav>", 1)[0]
    assert "ops-status" not in nav
    assert 'id="ops-status" hidden' in html
    advanced = html.split("<details", 1)[1]
    assert 'id="protocol"' in advanced
    assert 'id="scan-brief"' in advanced
    assert 'id="ticket"' in html.split("<details", 1)[0]
    script = Path("web/app.js").read_text(encoding="utf-8")
    assert "function derived(" in script
    assert "var stats = derived(report)" in script
    assert "stats.tools !=" not in script
    scan = Path("web/scan.html").read_text(encoding="utf-8")
    assert 'id="runtime-value"' not in scan
    assert 'id="meter-cpu"' not in scan
    assert 'id="meter-mem"' not in scan
    assert "gVisor (runsc)" not in scan
    assert 'id="tab-drift"' in scan and "hidden" in scan.split('id="tab-drift"', 1)[1].split(">", 1)[0]
    assert "Add to ticket" in scan


def _client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, object]:
    monkeypatch.setenv("PROVISIONER", "demo")
    monkeypatch.setenv("LLM_MODE", "fixture")
    monkeypatch.setenv("TOOLPAIN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("TOOLPAIN_ADMIN_TOKEN", "admin-test")
    import control_plane.main as main_mod
    from control_plane.main import AppState, app
    from control_plane.provisioner.demo import DemoProvisioner

    state = AppState()
    state.provisioner = DemoProvisioner(
        emit_event=state.emit_event,
        save_report=state.save_report,
        update_scan=state.update_scan,
        delay_sec=0.01,
    )
    main_mod.STATE = state
    return TestClient(app), state


def test_ticket_lands_on_the_note_and_the_pdf(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _state = _client(tmp_path, monkeypatch)
    with client:
        created = client.post(
            "/api/scans",
            json={
                "repo_url": "https://github.com/lupong/toolpain",
                "demo": "decoy-trap-server",
                "ticket": "RITM0012345",
            },
        )
        assert created.status_code == 201
        body = created.json()
        assert body["ticket"] == "RITM0012345"
        scan_id = body["id"]
        report = None
        for _ in range(80):
            got = client.get(f"/api/scans/{scan_id}/report")
            if got.status_code == 200:
                report = got.json()
                break
            time.sleep(0.05)
        assert report is not None
        note = client.post(f"/api/scans/{scan_id}/verify-link")
        assert note.status_code == 200
        assert "RITM0012345" in note.json()["note"]
        assert scan_id in note.json()["note"]
        pdf = client.get(f"/api/scans/{scan_id}/certificate.pdf")
        assert pdf.status_code == 200
        assert b"RITM0012345" in pdf.content
        assert b"Rate card" not in pdf.content


def test_verify_page_checks_report_and_pdf(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, state = _client(tmp_path, monkeypatch)
    with client:
        created = client.post(
            "/api/scans",
            json={"repo_url": "https://github.com/lupong/toolpain", "demo": "server-filesystem"},
        )
        scan_id = created.json()["id"]
        for _ in range(80):
            if client.get(f"/api/scans/{scan_id}/report").status_code == 200:
                break
            time.sleep(0.05)
        pdf = client.get(f"/api/scans/{scan_id}/certificate.pdf")
        link = client.post(f"/api/scans/{scan_id}/verify-link").json()
        path = urlparse(link["url"]).path
        ok = client.get(path)
        assert ok.status_code == 200
        assert "Matches the stored report" in ok.text
        uploaded = client.post(path, files={"pdf": ("cert.pdf", pdf.content, "application/pdf")})
        assert "Uploaded PDF matches the certificate" in uploaded.text
        edited = client.post(
            path,
            files={"pdf": ("cert.pdf", pdf.content + b" ", "application/pdf")},
        )
        assert "Uploaded PDF does not match the certificate" in edited.text
        report = state.db.get_report(scan_id)
        assert report is not None
        report["verdict"] = "flagged"
        state.db.save_report(scan_id, report, state.settings.reports_dir)
        changed = client.get(path)
        assert "Does not match the stored report" in changed.text
        assert 'class="banner bad"' in changed.text


def test_debug_bundle_redacts_and_names_the_stage(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, state = _client(tmp_path, monkeypatch)
    with client:
        scan = state.db.create_scan(
            "s_fail",
            "https://github.com/lupong/toolpain",
            "main",
            "tok-fail",
            account_mode="toolpain",
        )
        state.update_scan(
            scan.id,
            status="failed",
            error_code="build_failed",
            error_detail="image build failed",
        )
        state.emit_event(
            scan.id,
            "build",
            "alert",
            "runner stderr: pip failed vultr_api_key=ABCDEFGHIJKLMNOPQRSTUV",
            {"code": "build_failed", "error": "build_failed"},
        )
        diag = client.get(f"/api/scans/{scan.id}/diagnostics")
        assert diag.status_code == 200
        body = diag.json()
        assert body["failing_stage"] == "build"
        assert body["error_code"] == "build_failed"
        assert "pip failed" in (body["log_excerpt"] or "")
        denied = client.get(f"/api/scans/{scan.id}/debug.zip", headers={"X-Admin-Token": "nope"})
        assert denied.status_code == 403
        bundle = client.get(
            f"/api/scans/{scan.id}/debug.zip", headers={"X-Admin-Token": "admin-test"}
        )
        assert bundle.status_code == 200
        with zipfile.ZipFile(io.BytesIO(bundle.content)) as archive:
            names = set(archive.namelist())
            assert "events.json" in names
            assert "runner.stderr" in names
            raw = archive.read("runner.stderr").decode()
            events = archive.read("events.json").decode()
        assert "ABCDEFGHIJKLMNOPQRSTUV" not in raw
        assert "ABCDEFGHIJKLMNOPQRSTUV" not in events
        assert "REDACTED" in raw or "REDACTED" in events


def test_system_is_admin_only_and_logs_are_json(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _state = _client(tmp_path, monkeypatch)
    captured: list[str] = []

    class Grab(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            captured.append(JsonFormatter().format(record))

    handler = Grab()
    logging.getLogger("toolpain").addHandler(handler)
    try:
        with client:
            assert client.get("/api/system").status_code == 403
            assert client.get("/api/system", headers={"X-Api-Token": "scan-token"}).status_code == 403
            opened = client.get("/api/system", headers={"X-Admin-Token": "admin-test"})
            assert opened.status_code == 200
            assert opened.json()["version"] == "0.5.0"
            created = client.post(
                "/api/scans",
                json={"repo_url": "https://github.com/lupong/toolpain", "demo": "server-filesystem"},
            )
            scan_id = created.json()["id"]
            for _ in range(80):
                if client.get(f"/api/scans/{scan_id}").json()["status"] == "done":
                    break
                time.sleep(0.05)
    finally:
        logging.getLogger("toolpain").removeHandler(handler)
    assert captured
    for line in captured:
        body = json.loads(line)
        assert "scan_id" in body
    assert any(json.loads(line)["scan_id"] == scan_id for line in captured)


def test_runbook_covers_every_error_code() -> None:
    text = Path("docs/RUNBOOK.md").read_text(encoding="utf-8")
    for code in FAILURE_CODES:
        assert f"## {code}" in text
