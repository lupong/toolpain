"""Unit tests for Vultr CP API-key bootstrap."""

from __future__ import annotations

import pytest
import respx

from control_plane.provisioner.vultr_bootstrap import (
    VultrBootstrapError,
    bootstrap_control_plane_api_key,
)

API = "https://api.vultr.com/v2"


@pytest.mark.asyncio
@respx.mock
async def test_bootstrap_creates_service_user_whitelists_and_mints_key() -> None:
    respx.get(f"{API}/users").respond(200, json={"users": []})
    respx.post(f"{API}/users").respond(
        201,
        json={
            "user": {
                "id": "u-1",
                "email": "toolpain-cp-abcd1234@users.toolpain.internal",
                "service_user": True,
            }
        },
    )
    respx.get(f"{API}/users/u-1/ip-whitelist").respond(200, json={"ip_whitelist": []})
    respx.post(f"{API}/users/u-1/ip-whitelist").respond(204)
    respx.post(f"{API}/users/u-1/apikeys").respond(
        201,
        json={"api_key": {"id": "k-1", "api_key": "A" * 40, "name": "toolpain-control-plane"}},
    )

    result = await bootstrap_control_plane_api_key(
        bootstrap_api_key="bootstrap",
        control_plane_ip="140.82.61.136",
    )
    assert result.user_id == "u-1"
    assert result.api_key == "A" * 40
    assert result.allowed_ip == "140.82.61.136"
    assert result.created_user is True
    assert respx.calls.call_count == 5


@pytest.mark.asyncio
@respx.mock
async def test_bootstrap_reuses_existing_service_user() -> None:
    respx.get(f"{API}/users").respond(
        200,
        json={
            "users": [
                {
                    "id": "u-existing",
                    "email": "toolpain-cp-old@users.toolpain.internal",
                    "service_user": True,
                }
            ]
        },
    )
    respx.get(f"{API}/users/u-existing/ip-whitelist").respond(
        200,
        json={"ip_whitelist": [{"subnet": "140.82.61.136", "subnet_size": 32}]},
    )
    respx.post(f"{API}/users/u-existing/apikeys").respond(
        201,
        json={"api_key": "B" * 36},
    )

    result = await bootstrap_control_plane_api_key(
        bootstrap_api_key="bootstrap",
        control_plane_ip="140.82.61.136",
    )
    assert result.user_id == "u-existing"
    assert result.created_user is False
    assert result.api_key == "B" * 36
    # No create-user, no whitelist POST
    assert not any(c.request.method == "POST" and c.request.url.path == "/v2/users" for c in respx.calls)


@pytest.mark.asyncio
@respx.mock
async def test_bootstrap_explains_unauthorized_ip() -> None:
    respx.get(f"{API}/users").respond(
        401,
        json={"error": "Unauthorized IP address: 1.2.3.4", "status": 401},
    )
    with pytest.raises(VultrBootstrapError, match="bootstrap key rejected"):
        await bootstrap_control_plane_api_key(
            bootstrap_api_key="bootstrap",
            control_plane_ip="140.82.61.136",
        )
