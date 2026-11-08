"""Warm scanner pool claim / heartbeat (opt-in)."""

from __future__ import annotations

import pytest

from control_plane.scanner_pool import PoolAssignment, pool_from_settings


@pytest.mark.asyncio
async def test_pool_claim_and_heartbeat_assignment() -> None:
    pool = pool_from_settings(enabled=True, size=2, token="pool-secret")
    await pool.register_or_heartbeat("i-1", status="idle")
    await pool.register_or_heartbeat("i-2", status="idle")
    snap = pool.snapshot()
    assert snap["enabled"] is True
    assert snap["ready"] == 2

    claimed = await pool.claim(
        PoolAssignment(
            scan_id="s_abc",
            repo_url="https://github.com/example/repo",
            ref="main",
            token="scan-tok",
            control_plane_url="https://toolpain.example",
            prefer_subdir="npm/server",
        )
    )
    assert claimed == "i-1"
    assert pool.snapshot()["ready"] == 1
    assert pool.snapshot()["busy"] == 1

    hb = await pool.register_or_heartbeat("i-1", status="busy")
    assert hb["assignment"]["scan_id"] == "s_abc"
    assert hb["assignment"]["prefer_subdir"] == "npm/server"

    await pool.release("i-1", keep=True)
    assert pool.snapshot()["ready"] == 2
    hb2 = await pool.register_or_heartbeat("i-1", status="idle")
    assert hb2["assignment"] is None


def test_pool_disabled_by_default_snapshot() -> None:
    pool = pool_from_settings(enabled=False, size=2, token=None)
    assert pool.snapshot() == {
        "enabled": False,
        "size": 2,
        "ready": 0,
        "busy": 0,
        "pending": 0,
        "members": 0,
    }


def test_pool_token_check() -> None:
    pool = pool_from_settings(enabled=True, size=1, token="abc")
    assert pool.check_token("abc")
    assert not pool.check_token("nope")
    assert not pool.check_token(None)