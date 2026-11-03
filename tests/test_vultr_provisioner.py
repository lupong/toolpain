"""M8: Vultr create → poll → destroy via respx; BYO key never in DB/logs/SSE."""

from __future__ import annotations

import base64
import logging
from pathlib import Path

import httpx
import pytest
import respx
from fastapi.testclient import TestClient

from control_plane.redaction import RedactingFilter, redact_text


@respx.mock
@pytest.mark.asyncio
async def test_vultr_create_poll_destroy() -> None:
    from control_plane.provisioner import vultr_ops

    create_route = respx.post("https://api.vultr.com/v2/instances").mock(
        return_value=httpx.Response(
            202,
            json={
                "instance": {
                    "id": "vm-1",
                    "status": "pending",
                    "power_status": "stopped",
                    "label": "toolpain-scan-s_test",
                }
            },
        )
    )
    get_route = respx.get("https://api.vultr.com/v2/instances/vm-1").mock(
        return_value=httpx.Response(
            200,
            json={
                "instance": {
                    "id": "vm-1",
                    "status": "active",
                    "power_status": "running",
                }
            },
        )
    )
    del_route = respx.delete("https://api.vultr.com/v2/instances/vm-1").mock(
        return_value=httpx.Response(204)
    )

    inst = await vultr_ops.create_instance(
        "test-key-aaaaaaaaaaaaaaaaaaaaaaaa",
        region="ewr",
        plan="vc2-2c-4gb",
        snapshot_id=None,
        label="toolpain-scan-s_test",
        user_data=base64.b64encode(b"#cloud-config\n").decode(),
    )
    assert inst["id"] == "vm-1"
    got = await vultr_ops.get_instance("test-key-aaaaaaaaaaaaaaaaaaaaaaaa", "vm-1")
    assert got["status"] == "active"
    await vultr_ops.destroy_instance("test-key-aaaaaaaaaaaaaaaaaaaaaaaa", "vm-1")
    assert create_route.called
    assert get_route.called
    assert del_route.called


def test_byo_key_not_in_db_logs_or_sse(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROVISIONER", "fake")
    monkeypatch.setenv("LLM_MODE", "fake")
    monkeypatch.setenv("TOOLPAIN_DATA_DIR", str(tmp_path))

    import control_plane.main as main_mod
    from control_plane.main import AppState, app
    from control_plane.provisioner.fake import FakeProvisioner

    secret = "vultr-byo-key-SHOULD-NOT-LEAK-0123456789abcdef"

    state = AppState()
    state.provisioner = FakeProvisioner(
        emit_event=state.emit_event,
        save_report=state.save_report,
        update_scan=state.update_scan,
        delay_sec=0.02,
    )
    main_mod.STATE = state

    # Capture logs
    records: list[str] = []

    class Cap(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(self.format(record))

    handler = Cap()
    handler.addFilter(RedactingFilter())
    logging.getLogger().addHandler(handler)

    with TestClient(app) as client:
        r = client.post(
            "/api/scans",
            json={
                "repo_url": "https://github.com/andrew/playwright-mcp",
                "byo_vultr_key": secret,
            },
        )
        assert r.status_code == 201
        scan_id = r.json()["id"]
        assert r.json()["account_mode"] == "byo"

        # Key must not be in scan row / events / report files
        db_text = Path(state.settings.db_path).read_bytes()
        assert secret.encode() not in db_text

        for ev in state.db.list_events(scan_id):
            assert secret not in ev.msg
            assert secret not in str(ev.data)

        # Memory-only store then cleared after fake run
        import time

        for _ in range(40):
            if state.db.get_scan(scan_id) and state.db.get_scan(scan_id).status == "done":
                break
            time.sleep(0.05)
        assert state.provisioner.pop_byo_key(scan_id) is None

    logging.getLogger().removeHandler(handler)
    blob = "\n".join(records)
    assert secret not in blob
    assert redact_text(f"Authorization: Bearer {secret}").endswith("***REDACTED***")


@respx.mock
@pytest.mark.asyncio
async def test_reaper_deletes_old_instances() -> None:
    from control_plane import reaper

    respx.get("https://api.vultr.com/v2/instances").mock(
        return_value=httpx.Response(
            200,
            json={
                "instances": [
                    {
                        "id": "old-1",
                        "label": "toolpain-scan-s_old",
                        "date_created": "2020-01-01T00:00:00+00:00",
                        "tags": ["toolpain"],
                    },
                    {
                        "id": "new-1",
                        "label": "toolpain-scan-s_new",
                        "date_created": "2099-01-01T00:00:00+00:00",
                        "tags": ["toolpain"],
                    },
                ]
            },
        )
    )
    del_route = respx.delete("https://api.vultr.com/v2/instances/old-1").mock(
        return_value=httpx.Response(204)
    )
    deleted = await reaper.reap(api_key="k" * 40, max_age_min=30)
    assert deleted == ["old-1"]
    assert del_route.called
