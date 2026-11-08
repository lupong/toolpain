"""Bootstrap a VM-scoped Vultr API key for the control plane.

Uses a short-lived bootstrap key (your account token, typically laptop-allowlisted)
to create a Vultr *service user* whose API key is IP-locked to the control-plane
VM. The CP then uses only that key for create/destroy of scanner VMs.
"""

from __future__ import annotations

import logging
import secrets
import uuid
from dataclasses import dataclass
from typing import Any

import httpx

log = logging.getLogger("toolpain.vultr.bootstrap")

API = "https://api.vultr.com/v2"

# Minimum ACLs for ephemeral scanner lifecycle (create/list/destroy instances).
_CP_ACLS = (
    "provisioning",
    "subscriptions",
    "subscriptions_view",
)


@dataclass(frozen=True)
class BootstrapResult:
    user_id: str
    email: str
    api_key: str
    api_key_id: str | None
    allowed_ip: str
    created_user: bool


class VultrBootstrapError(RuntimeError):
    """Bootstrap failed (auth, permissions, or API shape)."""


def _raise_for_status(resp: httpx.Response, *, what: str) -> None:
    if resp.is_success:
        return
    detail = resp.text[:400]
    if resp.status_code == 401 and "Unauthorized IP" in detail:
        raise VultrBootstrapError(
            f"{what}: bootstrap key rejected from this IP. "
            "Temporarily allow this client IP (or all IPv4) on the bootstrap "
            f"key, then retry. Vultr said: {detail}"
        )
    raise VultrBootstrapError(f"{what}: HTTP {resp.status_code}: {detail}")


async def _list_users(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    resp = await client.get("/users")
    _raise_for_status(resp, what="list users")
    return list((resp.json() or {}).get("users") or [])


async def _find_existing_service_user(
    client: httpx.AsyncClient, *, email_local: str
) -> dict[str, Any] | None:
    """Match service users whose local-part is ``email_local`` or ``email_local-*``."""
    for user in await _list_users(client):
        email = str(user.get("email") or "")
        local = email.split("@", 1)[0]
        if not user.get("service_user"):
            continue
        if local == email_local or local.startswith(f"{email_local}-"):
            return user
    return None


async def _ensure_ip_whitelist(
    client: httpx.AsyncClient, *, user_id: str, ip: str
) -> None:
    resp = await client.get(f"/users/{user_id}/ip-whitelist")
    _raise_for_status(resp, what="list IP whitelist")
    entries = list((resp.json() or {}).get("ip_whitelist") or [])
    for entry in entries:
        if entry.get("subnet") == ip and int(entry.get("subnet_size") or -1) == 32:
            return
    resp = await client.post(
        f"/users/{user_id}/ip-whitelist",
        json={"subnet": ip, "subnet_size": 32},
    )
    # 204 No Content on success
    if resp.status_code not in (200, 201, 204):
        _raise_for_status(resp, what="add IP whitelist")


async def _create_user_api_key(
    client: httpx.AsyncClient, *, user_id: str, name: str
) -> tuple[str, str | None]:
    resp = await client.post(
        f"/users/{user_id}/apikeys",
        json={"name": name, "expire": False},
    )
    _raise_for_status(resp, what="create user API key")
    body = resp.json() or {}
    # Response shapes vary: {api_key: "..."} or {api_key: {id, api_key, ...}}
    raw = body.get("api_key")
    if isinstance(raw, dict):
        key = raw.get("api_key") or raw.get("key")
        key_id = raw.get("id")
        if not key:
            raise VultrBootstrapError(f"create user API key: missing secret in {body!r}")
        return str(key), str(key_id) if key_id else None
    if isinstance(raw, str) and raw and "*" not in raw:
        key_id = (body.get("id") if isinstance(body.get("id"), str) else None) or (
            (body.get("api_key_id") if isinstance(body.get("api_key_id"), str) else None)
        )
        return raw, key_id
    # Some accounts return {api_keys: [{api_key: "..."}]}
    keys = body.get("api_keys")
    if isinstance(keys, list) and keys:
        first = keys[0]
        if isinstance(first, dict) and first.get("api_key") and "*" not in str(first["api_key"]):
            return str(first["api_key"]), (
                str(first["id"]) if first.get("id") else None
            )
    raise VultrBootstrapError(f"create user API key: unexpected response {body!r}")


async def bootstrap_control_plane_api_key(
    *,
    bootstrap_api_key: str,
    control_plane_ip: str,
    email_local: str = "toolpain-cp",
    email_domain: str = "users.toolpain.internal",
    key_name: str = "toolpain-control-plane",
    timeout_sec: float = 60.0,
) -> BootstrapResult:
    """Create (or reuse) a service user + API key allowlisted to ``control_plane_ip``.

    ``bootstrap_api_key`` must be able to manage users (root / manage_users).
    Returns a plaintext API key intended only for the control-plane VM.
    """
    ip = control_plane_ip.strip()
    if not ip or "/" in ip:
        raise VultrBootstrapError(f"control_plane_ip must be a bare IPv4 address, got {ip!r}")

    headers = {
        "Authorization": f"Bearer {bootstrap_api_key}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(
        base_url=API, headers=headers, timeout=timeout_sec
    ) as client:
        existing = await _find_existing_service_user(client, email_local=email_local)
        created_user = False
        if existing is None:
            email = f"{email_local}-{uuid.uuid4().hex[:8]}@{email_domain}"
            password = secrets.token_urlsafe(24)
            resp = await client.post(
                "/users",
                json={
                    "email": email,
                    "first_name": "ToolPain",
                    "last_name": "ControlPlane",
                    "password": password,
                    "api_enabled": True,
                    "service_user": True,
                    "acls": list(_CP_ACLS),
                },
            )
            _raise_for_status(resp, what="create service user")
            body = resp.json() or {}
            user = body.get("user") or body
            user_id = str(user.get("id") or "")
            if not user_id:
                raise VultrBootstrapError(f"create service user: no id in {body!r}")
            # Prefer key returned at create-time for service users.
            minted = (
                body.get("api_key")
                or user.get("api_key")
                or body.get("key")
            )
            api_key: str | None = minted if isinstance(minted, str) and minted else None
            api_key_id: str | None = None
            created_user = True
            log.info("created Vultr service user id=%s email=%s", user_id, email)
        else:
            user_id = str(existing["id"])
            email = str(existing.get("email") or "")
            api_key = None
            api_key_id = None
            log.info("reusing Vultr service user id=%s email=%s", user_id, email)

        await _ensure_ip_whitelist(client, user_id=user_id, ip=ip)
        log.info("allowlisted %s/32 on user %s", ip, user_id)

        if not api_key:
            api_key, api_key_id = await _create_user_api_key(
                client, user_id=user_id, name=key_name
            )
            log.info("minted API key for user %s (id=%s)", user_id, api_key_id)

        # Prove the new key works from... we can't prove from CP here; just shape-check.
        if len(api_key) < 20 or "*" in api_key:
            raise VultrBootstrapError("bootstrap produced a masked/invalid API key")

        return BootstrapResult(
            user_id=user_id,
            email=email,
            api_key=api_key,
            api_key_id=api_key_id,
            allowed_ip=ip,
            created_user=created_user,
        )
