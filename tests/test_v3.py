"""v3: share links, compare, HTTP MCP, codegen cache, API token isolation."""

from __future__ import annotations

import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from control_plane.cli import scan_payload
from control_plane.share import compare_reports, sign_share, verify_share
from demo.http_mcp.server import Handler
from runner.codegen_cache import load_cached, make_key, store_cached
from runner.transport.http_mcp import HttpMcpClient


def test_scan_payload_includes_protocol_and_mcp_url() -> None:
    body = scan_payload(
        "https://github.com/a/b",
        "main",
        "http",
        None,
        None,
        "http://127.0.0.1:9/mcp",
        None,
    )
    assert body["protocol"] == "http"
    assert body["mcp_url"] == "http://127.0.0.1:9/mcp"
    assert "scan_brief" not in body


def test_share_roundtrip() -> None:
    token, _exp = sign_share("s_demo", ttl_sec=120)
    assert verify_share(token) == "s_demo"
    assert verify_share("not-a-token") is None


def test_compare_reports() -> None:
    delta = compare_reports(
        {"scan_id": "a", "verdict": "clean", "tools": [{"name": "add"}], "findings": []},
        {
            "scan_id": "b",
            "verdict": "suspicious",
            "tools": [{"name": "add"}, {"name": "fetch_report"}],
            "findings": [{"type": "http_undocumented_tool"}],
        },
    )
    assert delta["tools_added"] == ["fetch_report"]
    assert delta["verdict_changed"] is True


def test_codegen_cache_roundtrip(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TOOLPAIN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CODEGEN_CACHE", "1")
    key = make_key(repo_url="https://github.com/a/b", commit="abc", brief="x", kind="probe")
    store_cached(key, {"launch_sh": "#!/bin/sh\n", "probe_py": "def build_plans():\n pass\n"})
    hit = load_cached(key)
    assert hit and hit["launch_sh"].startswith("#!")


@pytest.mark.asyncio
async def test_http_mcp_lists_tools() -> None:
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = HttpMcpClient(f"http://127.0.0.1:{port}/mcp")
        tools = await client.list_tools()
        names = {t["name"] for t in tools}
        assert "add" in names and "fetch_report" in names
        out = await client.call_tool("add", {"a": 2, "b": 3})
        assert "5" in str(out)
    finally:
        server.shutdown()


def test_api_token_isolates_scans(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROVISIONER", "fake")
    monkeypatch.setenv("LLM_MODE", "fake")
    monkeypatch.setenv("TOOLPAIN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("TOOLPAIN_ADMIN_TOKEN", "admin-test")

    from control_plane.main import app

    with TestClient(app) as client:
        a = client.post(
            "/api/tokens",
            json={"label": "a", "quota": 5},
            headers={"X-Admin-Token": "admin-test"},
        )
        b = client.post(
            "/api/tokens",
            json={"label": "b", "quota": 5},
            headers={"X-Admin-Token": "admin-test"},
        )
        assert a.status_code == 200 and b.status_code == 200
        tok_a, tok_b = a.json()["token"], b.json()["token"]
        created = client.post(
            "/api/scans",
            json={"repo_url": "https://github.com/lupong/toolpain", "demo": "decoy-trap-server"},
            headers={"X-Api-Token": tok_a},
        )
        assert created.status_code == 201
        scan_id = created.json()["id"]
        visible_b = client.get("/api/scans", headers={"X-Api-Token": tok_b})
        assert all(row["id"] != scan_id for row in visible_b.json())
        denied = client.get(f"/api/scans/{scan_id}/report", headers={"X-Api-Token": tok_b})
        assert denied.status_code in {403, 404}
