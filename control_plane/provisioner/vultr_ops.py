"""Vultr API v2 helpers (create / poll / destroy)."""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import secrets
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from control_plane.provisioner.vultr import VultrProvisioner

log = logging.getLogger("toolpain.vultr")
API = "https://api.vultr.com/v2"

_SAFE_ENV_RE = re.compile(r"^[A-Za-z0-9_./:@+=%-]+$")


_LLM_MODE_OK = frozenset({"live", "ollama", "local"})


def scanner_llm_mode(raw: str | None = None) -> str:
    """LLM mode injected into scanner VMs — live (Vultr) or ollama only (CP proxy)."""
    mode = (raw if raw is not None else os.environ.get("LLM_MODE") or "live").strip().lower()
    if mode in _LLM_MODE_OK:
        return mode
    return "live"


def render_cloud_init(
    template: str,
    *,
    scan_id: str,
    repo_url: str,
    ref: str,
    token: str,
    control_plane_url: str,
    prefer_subdir: str | None = None,
    scan_brief: str | None = None,
    llm_mode: str | None = None,
) -> str:
    """Substitute cloud-init placeholders. Brief is base64 to avoid YAML breakage."""
    brief_b64 = base64.b64encode((scan_brief or "").encode()).decode() if scan_brief else ""
    subdir = (prefer_subdir or "").strip().strip("/")
    if subdir and (".." in subdir or not _SAFE_ENV_RE.match(subdir)):
        subdir = ""
    mode = scanner_llm_mode(llm_mode)
    # Empty = profile every tool. Only pass through an explicit positive integer.
    max_profiles = (os.environ.get("TOOLPAIN_MAX_PROFILES") or "").strip()
    if max_profiles and not max_profiles.isdigit():
        max_profiles = ""
    raw = (
        template.replace("{{SCAN_ID}}", scan_id)
        .replace("{{REPO_URL}}", repo_url)
        .replace("{{REF}}", ref)
        .replace("{{TOKEN}}", token)
        .replace("{{CONTROL_PLANE_URL}}", control_plane_url)
        .replace("{{LLM_MODE}}", mode)
        .replace("{{PREFER_SUBDIR}}", subdir)
        .replace("{{SCAN_BRIEF_B64}}", brief_b64)
        .replace("{{TOOLPAIN_MAX_PROFILES}}", max_profiles)
    )
    return raw


async def destroy_instance(api_key: str, instance_id: str) -> None:
    last_exc: Exception | None = None
    for attempt in range(8):
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                r = await client.delete(
                    f"{API}/instances/{instance_id}",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                if r.status_code == 404:
                    return
                if r.status_code in {401, 409, 429, 500, 502, 503} and attempt < 7:
                    await asyncio.sleep(5 * (attempt + 1))
                    continue
                r.raise_for_status()
                return
        except Exception as exc:  # noqa: BLE001 — destroy must outwait Vultr locks
            last_exc = exc
            await asyncio.sleep(5 * (attempt + 1))
    if last_exc is not None:
        raise last_exc


async def create_instance(
    api_key: str,
    *,
    region: str,
    plan: str,
    snapshot_id: str | None,
    label: str,
    user_data: str,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "region": region,
        "plan": plan,
        "label": label,
        "tags": tags or ["toolpain"],
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
    last_exc: Exception | None = None
    for attempt in range(6):
        try:
            async with httpx.AsyncClient(timeout=60) as client:
                r = await client.get(
                    f"{API}/instances/{instance_id}",
                    headers={"Authorization": f"Bearer {api_key}"},
                )
                # Fresh instances are often "locked" (409) while Vultr finishes setup.
                if r.status_code in {401, 409, 429, 500, 502, 503} and attempt < 5:
                    await asyncio.sleep(3 * (attempt + 1))
                    continue
                r.raise_for_status()
                return r.json()["instance"]
        except Exception as exc:  # noqa: BLE001 — retry transient Vultr blips
            last_exc = exc
            await asyncio.sleep(3 * (attempt + 1))
    assert last_exc is not None
    raise last_exc


async def list_instances(api_key: str, *, tag: str | None = None) -> list[dict[str, Any]]:
    params: dict[str, Any] = {"per_page": 100}
    if tag:
        params["tag"] = tag
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.get(
            f"{API}/instances",
            headers={"Authorization": f"Bearer {api_key}"},
            params=params,
        )
        r.raise_for_status()
        return list(r.json().get("instances") or [])


def render_pool_cloud_init(
    template: str,
    *,
    control_plane_url: str,
    pool_token: str,
    llm_mode: str | None = None,
) -> str:
    mode = scanner_llm_mode(llm_mode)
    max_profiles = (os.environ.get("TOOLPAIN_MAX_PROFILES") or "").strip()
    if max_profiles and not max_profiles.isdigit():
        max_profiles = ""
    return (
        template.replace("{{CONTROL_PLANE_URL}}", control_plane_url.rstrip("/"))
        .replace("{{POOL_TOKEN}}", pool_token)
        .replace("{{LLM_MODE}}", mode)
        .replace("{{TOOLPAIN_MAX_PROFILES}}", max_profiles)
    )


async def ensure_scanner_pool(provisioner: VultrProvisioner) -> None:
    """Create warm-pool VMs up to configured size (no-op when pool disabled)."""
    pool = getattr(provisioner, "pool", None)
    if pool is None or not pool.enabled or pool.size <= 0:
        return
    key = provisioner.api_key
    if not key:
        log.warning("scanner pool enabled but no VULTR_API_KEY")
        return
    from control_plane.scanner_pool import POOL_LABEL_PREFIX, POOL_TAG

    control_plane_url = (
        os.environ.get("CONTROL_PLANE_URL")
        or getattr(provisioner, "control_plane_url", None)
        or "http://127.0.0.1:8000"
    )
    try:
        existing = await list_instances(key, tag=POOL_TAG)
    except Exception as exc:  # noqa: BLE001
        log.warning("list pool instances failed: %s", exc)
        existing = []
    live = [
        inst
        for inst in existing
        if str(inst.get("label") or "").startswith(POOL_LABEL_PREFIX)
        and inst.get("status") != "pending_destroy"
    ]
    for inst in live:
        await pool.note_member(str(inst["id"]), status="pending")
    need = max(0, pool.size - len(live))
    if need <= 0:
        log.info("scanner pool already at size %s", len(live))
        return
    template_path = Path(__file__).resolve().parents[2] / "infra" / "cloud-init-pool.yaml"
    if not template_path.exists():
        log.error("missing %s", template_path)
        return
    template = template_path.read_text(encoding="utf-8")
    raw = render_pool_cloud_init(
        template,
        control_plane_url=control_plane_url.rstrip("/"),
        pool_token=pool.token,
        llm_mode=scanner_llm_mode(),
    )
    user_data = base64.b64encode(raw.encode()).decode()
    for i in range(need):
        label = f"{POOL_LABEL_PREFIX}{i}-{secrets.token_hex(3)}"
        try:
            inst = await create_instance(
                key,
                region=os.environ.get("VULTR_REGION", "ewr"),
                plan=os.environ.get("VULTR_PLAN", "vc2-2c-4gb"),
                snapshot_id=os.environ.get("VULTR_SNAPSHOT_ID") or None,
                label=label,
                user_data=user_data,
                tags=["toolpain", POOL_TAG],
            )
            await pool.note_member(str(inst["id"]), status="pending")
            log.info("created pool instance %s (%s)", inst.get("id"), label)
        except Exception as exc:  # noqa: BLE001
            log.exception("failed to create pool instance: %s", exc)


async def _wait_scan_terminal(provisioner: VultrProvisioner, scan_id: str) -> None:
    for _ in range(360):
        await asyncio.sleep(5)
        if provisioner.scan_finished(scan_id):
            break
        if scan_id not in provisioner._instances:
            break
    if not provisioner.scan_finished(scan_id):
        if provisioner._emit:
            provisioner._emit(
                scan_id,
                "report",
                "warn",
                "Scan timed out waiting for report",
                {"code": "probe_timeout", "error": "probe_timeout"},
            )
        if provisioner._update_scan:
            provisioner._update_scan(
                scan_id,
                status="timeout",
                error_code="probe_timeout",
                error_detail="Scan timed out waiting for report",
            )


async def provision_and_run(
    provisioner: VultrProvisioner,
    *,
    scan_id: str,
    repo_url: str,
    ref: str,
    token: str,
    prefer_subdir: str | None = None,
    scan_brief: str | None = None,
    use_pool: bool = False,
) -> None:
    """Create → wait → destroy, or claim a warm-pool VM when this scan opts in."""
    key = provisioner.key_for(scan_id)
    if not key:
        raise RuntimeError("no Vultr API key")
    control_plane_url = (
        os.environ.get("CONTROL_PLANE_URL")
        or getattr(provisioner, "control_plane_url", None)
        or "http://127.0.0.1:8000"
    ).rstrip("/")

    pool = getattr(provisioner, "pool", None)
    # Per-scan opt-in only. SCANNER_POOL_ENABLED keeps VMs warm; use_pool claims one.
    if use_pool and pool is not None and pool.enabled:
        from control_plane.scanner_pool import PoolAssignment

        brief_b64 = (
            base64.b64encode((scan_brief or "").encode()).decode() if scan_brief else ""
        )
        subdir = (prefer_subdir or "").strip().strip("/")
        if subdir and (".." in subdir or not _SAFE_ENV_RE.match(subdir)):
            subdir = ""
        claimed = await pool.claim(
            PoolAssignment(
                scan_id=scan_id,
                repo_url=repo_url,
                ref=ref,
                token=token,
                control_plane_url=control_plane_url,
                prefer_subdir=subdir,
                scan_brief_b64=brief_b64,
                llm_mode=scanner_llm_mode(),
            )
        )
        if claimed:
            provisioner._instances[scan_id] = claimed
            if provisioner._emit:
                provisioner._emit(
                    scan_id,
                    "provision",
                    "info",
                    f"Claimed warm-pool instance {claimed}",
                    {"pool": True, "instance_id": claimed},
                )
            try:
                await _wait_scan_terminal(provisioner, scan_id)
            finally:
                await pool.release(claimed, keep=True)
                provisioner._instances.pop(scan_id, None)
                provisioner.pop_byo_key(scan_id)
                if provisioner._emit:
                    provisioner._emit(
                        scan_id,
                        "destroy",
                        "info",
                        "Released warm-pool instance (host kept)",
                        {"pool": True},
                    )
            return
        if provisioner._emit:
            provisioner._emit(
                scan_id,
                "provision",
                "warn",
                "Warm pool opted in, but no idle scanner was ready yet — creating on-demand "
                "(pool VMs take a few minutes to become ready after enable/refill)",
                {"pool": True, "fallback": "create"},
            )
    elif use_pool and provisioner._emit:
        provisioner._emit(
            scan_id,
            "provision",
            "info",
            "Warm pool opted in, but pool capacity is off on the control plane — creating a new scanner VM",
            {"pool": False, "fallback": "create"},
        )

    cloud_init = Path(__file__).resolve().parents[2] / "infra" / "cloud-init.yaml"
    template = cloud_init.read_text() if cloud_init.exists() else "#cloud-config\nruncmd: []\n"
    raw = render_cloud_init(
        template,
        scan_id=scan_id,
        repo_url=repo_url,
        ref=ref,
        token=token,
        control_plane_url=control_plane_url,
        prefer_subdir=prefer_subdir,
        scan_brief=scan_brief,
        llm_mode=scanner_llm_mode(),
    )
    user_data = base64.b64encode(raw.encode()).decode()

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

    ready = False
    for _ in range(120):  # up to ~10 minutes for snapshot unlock + boot
        try:
            inst = await get_instance(key, instance_id)
        except Exception as exc:  # noqa: BLE001 — keep waiting through temporary lock errors
            log.warning("get_instance %s: %s", instance_id, exc)
            await asyncio.sleep(5)
            continue
        status = inst.get("status")
        power = inst.get("power_status")
        server = inst.get("server_status")
        if status == "active" and power == "running" and server in {None, "ok", "none"}:
            ready = True
            break
        await asyncio.sleep(5)
    if not ready:
        if provisioner._emit:
            provisioner._emit(
                scan_id,
                "provision",
                "warn",
                "Instance did not become ready in time",
                {"code": "vm", "error": "vm"},
            )
        if provisioner._update_scan:
            provisioner._update_scan(
                scan_id, status="failed", error_code="vm", error_detail="instance not ready"
            )
        await destroy_instance(key, instance_id)
        provisioner._instances.pop(scan_id, None)
        provisioner.pop_byo_key(scan_id)
        return

    if provisioner._emit:
        provisioner._emit(
            scan_id,
            "provision",
            "info",
            "Instance active; runner via cloud-init",
        )

    await _wait_scan_terminal(provisioner, scan_id)

    try:
        await destroy_instance(key, instance_id)
    finally:
        provisioner._instances.pop(scan_id, None)
        provisioner.pop_byo_key(scan_id)
        if provisioner._emit:
            provisioner._emit(scan_id, "destroy", "info", "Instance destroyed")
