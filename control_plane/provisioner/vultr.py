"""VultrProvisioner: create/poll/delete ephemeral scanner VMs."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from typing import Any

from control_plane.provisioner.base import Provisioner

log = logging.getLogger("toolpain.vultr")

_TERMINAL = frozenset({"done", "failed", "cancelled", "timeout"})


class VultrProvisioner(Provisioner):
    def __init__(
        self,
        api_key: str | None = None,
        emit_event: Callable[..., Any] | None = None,
        save_report: Callable[..., Any] | None = None,
        update_scan: Callable[..., Any] | None = None,
        get_scan: Callable[..., Any] | None = None,
        control_plane_url: str = "http://127.0.0.1:8000",
        pool: Any | None = None,
        **kwargs: Any,
    ) -> None:
        self.api_key = api_key
        self._emit = emit_event
        self._save_report = save_report
        self._update_scan = update_scan
        self._get_scan = get_scan
        self.control_plane_url = control_plane_url
        self.pool = pool
        self._byo_keys: dict[str, str] = {}
        self._instances: dict[str, str] = {}
        self._tasks: dict[str, asyncio.Task[None]] = {}

    def store_byo_key(self, scan_id: str, key: str) -> None:
        self._byo_keys[scan_id] = key

    def pop_byo_key(self, scan_id: str) -> str | None:
        return self._byo_keys.pop(scan_id, None)

    def key_for(self, scan_id: str) -> str | None:
        return self._byo_keys.get(scan_id) or self.api_key

    def scan_finished(self, scan_id: str) -> bool:
        if self._get_scan is None:
            return False
        scan = self._get_scan(scan_id)
        if scan is None:
            return False
        status = getattr(scan, "status", None) or (
            scan.get("status") if isinstance(scan, dict) else None
        )
        return status in _TERMINAL

    async def start_scan(
        self,
        scan_id: str,
        repo_url: str,
        ref: str,
        token: str,
        **kwargs: Any,
    ) -> None:
        byo = kwargs.get("byo_vultr_key")
        if byo:
            self.store_byo_key(scan_id, byo)
        if not self.key_for(scan_id):
            # Never silently replay DemoProvisioner — that looks like a real Vultr scan.
            msg = "PROVISIONER=vultr requires VULTR_API_KEY (or BYO key); refusing demo fallback"
            log.error("vultr scan %s: %s", scan_id, msg)
            if self._emit:
                self._emit(
                    scan_id,
                    "provision",
                    "warn",
                    msg,
                    {"code": "vm", "error": "vm"},
                )
            if self._update_scan:
                self._update_scan(
                    scan_id,
                    status="failed",
                    error_code="vm",
                    error_detail=msg,
                )
            raise RuntimeError(msg)
        task = asyncio.create_task(
            self._run(
                scan_id,
                repo_url,
                ref,
                token,
                prefer_subdir=kwargs.get("prefer_subdir"),
                scan_brief=kwargs.get("scan_brief"),
                use_pool=bool(kwargs.get("use_pool")),
            )
        )
        self._tasks[scan_id] = task

    async def _run(
        self,
        scan_id: str,
        repo_url: str,
        ref: str,
        token: str,
        *,
        prefer_subdir: str | None = None,
        scan_brief: str | None = None,
        use_pool: bool = False,
    ) -> None:
        from control_plane.provisioner import vultr_ops

        try:
            if self._update_scan:
                self._update_scan(scan_id, status="running")
            await vultr_ops.provision_and_run(
                self,
                scan_id=scan_id,
                repo_url=repo_url,
                ref=ref,
                token=token,
                prefer_subdir=prefer_subdir,
                scan_brief=scan_brief,
                use_pool=use_pool,
            )
        except Exception as exc:
            log.exception("vultr scan %s failed", scan_id)
            if self._emit:
                self._emit(
                    scan_id,
                    "provision",
                    "warn",
                    f"Vultr provision failed: {exc}",
                    {"code": "vm", "error": "vm"},
                )
            if self._update_scan:
                self._update_scan(
                    scan_id,
                    status="failed",
                    error_code="vm",
                    error_detail=str(exc)[:500],
                )
            instance_id = self._instances.pop(scan_id, None)
            key = self.key_for(scan_id)
            if instance_id and key:
                try:
                    await vultr_ops.destroy_instance(key, instance_id)
                except Exception:
                    log.exception("failed to destroy instance %s after error", instance_id)
            self.pop_byo_key(scan_id)
        finally:
            self._tasks.pop(scan_id, None)

    async def cancel_scan(self, scan_id: str) -> None:
        task = self._tasks.pop(scan_id, None)
        if task and not task.done():
            task.cancel()
        instance_id = self._instances.pop(scan_id, None)
        key = self.key_for(scan_id)
        self.pop_byo_key(scan_id)
        if instance_id and key:
            try:
                from control_plane.provisioner import vultr_ops

                await vultr_ops.destroy_instance(key, instance_id)
            except Exception:
                log.exception("failed to destroy instance %s", instance_id)
