"""Vultr API v2 helpers (create / poll / destroy). Expanded in M8."""

from __future__ import annotations

import asyncio
import base64
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from control_plane.provisioner.vultr import VultrProvisioner

log = logging.getLogger("toolpain.vultr")
API = "https://api.vultr.com/v2"


async def destroy_instance(api_key: str, instance_id: str) -> None:
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.delete(
            f"{API}/instances/{instance_id}",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        r.raise_for_status()


async def create_instance(
    api_key: str,
    *,
    region: str,
    plan: str,
    snapshot_id: str | None,
    label: str,
    user_data: str,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "region": region,
        "plan": plan,
        "label": label,
        "tags": ["toolpain"],
        "user_data": user_data,
        "enable_ipv6": False,
    }
    if snapshot_id:
        payload["snapshot_id"] = snapshot_id
    else:
        payload["os_id"] = 2284  # Ubuntu fallback
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.post(
            f"{API}/instances",
            headers={"Authorization": f"Bearer {api_key}"},
            json=payload,
        )
        r.raise_for_status()
        return r.json()["instance"]


async def get_instance(api_key: str, instance_id: str) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.get(
            f"{API}/instances/{instance_id}",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        r.raise_for_status()
        return r.json()["instance"]


async def provision_and_run(
    provisioner: VultrProvisioner,
    *,
    scan_id: str,
    repo_url: str,
    ref: str,
    token: str,
) -> None:
    """Create VM, wait for active, rely on cloud-init to run the runner, then destroy."""
    key = provisioner.key_for(scan_id)
    if not key:
        raise RuntimeError("no Vultr API key")
    cloud_init = Path(__file__).resolve().parents[2] / "infra" / "cloud-init.yaml"
    raw = cloud_init.read_text() if cloud_init.exists() else "#cloud-config\nruncmd: []\n"
    # Inject scan params
    raw = (
        raw.replace("{{SCAN_ID}}", scan_id)
        .replace("{{REPO_URL}}", repo_url)
        .replace("{{REF}}", ref)
        .replace("{{TOKEN}}", token)
    )
    user_data = base64.b64encode(raw.encode()).decode()
    import os

    instance = await create_instance(
        key,
        region=os.environ.get("VULTR_REGION", "ewr"),
        plan=os.environ.get("VULTR_PLAN", "vc2-2c-4gb"),
        snapshot_id=os.environ.get("VULTR_SNAPSHOT_ID") or None,
        label=f"toolpain-scan-{scan_id}",
        user_data=user_data,
    )
    instance_id = instance["id"]
    provisioner._instances[scan_id] = instance_id
    if provisioner._emit:
        provisioner._emit(scan_id, "provision", "info", f"Created instance {instance_id}")
    # Poll ready
    for _ in range(60):
        inst = await get_instance(key, instance_id)
        if inst.get("status") == "active" and inst.get("power_status") == "running":
            break
        await asyncio.sleep(5)
    else:
        if provisioner._update_scan:
            provisioner._update_scan(scan_id, status="failed")
        await destroy_instance(key, instance_id)
        return
    if provisioner._emit:
        provisioner._emit(scan_id, "provision", "info", "Instance active; runner via cloud-init")
    # Wait for runner callback (report) with timeout; reaper handles orphans
    for _ in range(360):
        await asyncio.sleep(5)
        # Destroy is caller's / reaper responsibility after report; soft wait
        if scan_id not in provisioner._instances:
            break
    # Always destroy
    try:
        await destroy_instance(key, instance_id)
    finally:
        provisioner._instances.pop(scan_id, None)
        provisioner.pop_byo_key(scan_id)
        if provisioner._emit:
            provisioner._emit(scan_id, "destroy", "info", "Instance destroyed")
