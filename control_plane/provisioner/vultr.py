"""VultrProvisioner: create/poll/delete ephemeral scanner VMs."""

from __future__ import annotations

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
        **kwargs: Any,
    ) -> None:
        self.api_key = api_key
        self._emit = emit_event
        self._save_report = save_report
        self._update_scan = update_scan
        self._get_scan = get_scan
        self.control_plane_url = control_plane_url
        self._byo_keys: dict[str, str] = {}
        self._instances: dict[str, str] = {}

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
            from control_plane.provisioner.fake import FakeProvisioner

            fake = FakeProvisioner(
                emit_event=self._emit,
                save_report=self._save_report,
                update_scan=self._update_scan,
            )
            await fake.start_scan(scan_id, repo_url, ref, token, **kwargs)
            return
        from control_plane.provisioner import vultr_ops

        await vultr_ops.provision_and_run(
            self,
            scan_id=scan_id,
            repo_url=repo_url,
            ref=ref,
            token=token,
            prefer_subdir=kwargs.get("prefer_subdir"),
            scan_brief=kwargs.get("scan_brief"),
        )

    async def cancel_scan(self, scan_id: str) -> None:
        instance_id = self._instances.pop(scan_id, None)
        key = self.pop_byo_key(scan_id)
        if instance_id and key:
            try:
                from control_plane.provisioner import vultr_ops

                await vultr_ops.destroy_instance(key, instance_id)
            except Exception:
                log.exception("failed to destroy instance %s", instance_id)
