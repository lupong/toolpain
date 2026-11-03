"""Delete orphaned toolpain-scan-* Vultr instances older than REAPER_MAX_AGE_MIN."""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

log = logging.getLogger("toolpain.reaper")
API = "https://api.vultr.com/v2"


async def list_toolpain_instances(api_key: str) -> list[dict[str, Any]]:
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.get(
            f"{API}/instances",
            headers={"Authorization": f"Bearer {api_key}"},
            params={"tag": "toolpain"},
        )
        r.raise_for_status()
        return list(r.json().get("instances") or [])


async def delete_instance(api_key: str, instance_id: str) -> None:
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.delete(
            f"{API}/instances/{instance_id}",
            headers={"Authorization": f"Bearer {api_key}"},
        )
        r.raise_for_status()


def _parse_created(inst: dict[str, Any]) -> datetime | None:
    raw = inst.get("date_created") or inst.get("created_at")
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
    except ValueError:
        return None


async def reap(
    api_key: str | None = None,
    max_age_min: int | None = None,
) -> list[str]:
    """Destroy toolpain-scan-* instances older than max_age_min. Returns deleted ids."""
    key = api_key or os.environ.get("VULTR_API_KEY")
    if not key:
        log.info("reaper: no VULTR_API_KEY; skip")
        return []
    age = max_age_min if max_age_min is not None else int(os.environ.get("REAPER_MAX_AGE_MIN", "30"))
    cutoff = datetime.now(UTC) - timedelta(minutes=age)
    deleted: list[str] = []
    for inst in await list_toolpain_instances(key):
        label = inst.get("label") or ""
        if not label.startswith("toolpain-scan-"):
            continue
        created = _parse_created(inst)
        if created and created > cutoff:
            continue
        iid = inst["id"]
        log.warning("reaper: deleting orphan %s label=%s", iid, label)
        await delete_instance(key, iid)
        deleted.append(iid)
    return deleted
