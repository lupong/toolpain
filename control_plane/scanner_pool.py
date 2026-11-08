"""Optional warm scanner pool (opt-in).

When ``SCANNER_POOL_ENABLED=1``, the control plane keeps N snapshot VMs warm.
Pool agents heartbeat here; scans claim an idle member instead of create+boot.
Default is off — create-per-scan remains the production path.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any

log = logging.getLogger("toolpain.scanner_pool")

POOL_TAG = "toolpain-pool"
POOL_LABEL_PREFIX = "toolpain-pool-"


@dataclass
class PoolAssignment:
    scan_id: str
    repo_url: str
    ref: str
    token: str
    control_plane_url: str
    prefer_subdir: str = ""
    scan_brief_b64: str = ""
    llm_mode: str = "live"


@dataclass
class PoolMember:
    instance_id: str
    status: str = "pending"  # pending | idle | busy | offline
    last_seen: float = 0.0
    assignment: PoolAssignment | None = None
    scan_id: str | None = None


@dataclass
class ScannerPool:
    enabled: bool
    size: int
    token: str
    members: dict[str, PoolMember] = field(default_factory=dict)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def snapshot(self) -> dict[str, Any]:
        idle = sum(1 for m in self.members.values() if m.status == "idle")
        busy = sum(1 for m in self.members.values() if m.status == "busy")
        pending = sum(1 for m in self.members.values() if m.status == "pending")
        return {
            "enabled": self.enabled,
            "size": self.size,
            "ready": idle,
            "busy": busy,
            "pending": pending,
            "members": len(self.members),
        }

    def check_token(self, presented: str | None) -> bool:
        if not self.enabled or not self.token or not presented:
            return False
        return secrets.compare_digest(self.token, presented)

    async def register_or_heartbeat(
        self,
        instance_id: str,
        *,
        status: str = "idle",
    ) -> dict[str, Any]:
        async with self._lock:
            member = self.members.get(instance_id)
            if member is None:
                member = PoolMember(instance_id=instance_id)
                self.members[instance_id] = member
            member.last_seen = time.time()
            if status == "idle" and member.assignment is None:
                member.status = "idle"
                member.scan_id = None
            elif status == "busy":
                member.status = "busy"
            elif status == "offline":
                member.status = "offline"
            assignment = None
            if member.assignment is not None:
                a = member.assignment
                assignment = {
                    "scan_id": a.scan_id,
                    "repo_url": a.repo_url,
                    "ref": a.ref,
                    "token": a.token,
                    "control_plane_url": a.control_plane_url,
                    "prefer_subdir": a.prefer_subdir,
                    "scan_brief_b64": a.scan_brief_b64,
                    "llm_mode": a.llm_mode,
                }
                member.status = "busy"
                member.scan_id = a.scan_id
            return {"ok": True, "assignment": assignment}

    async def claim(
        self,
        assignment: PoolAssignment,
    ) -> str | None:
        """Bind ``assignment`` to an idle member. Returns instance_id or None."""
        async with self._lock:
            now = time.time()
            for member in self.members.values():
                if member.status != "idle":
                    continue
                if now - member.last_seen > 90:
                    member.status = "offline"
                    continue
                member.assignment = assignment
                member.status = "busy"
                member.scan_id = assignment.scan_id
                member.last_seen = now
                log.info(
                    "pool claimed %s for %s",
                    member.instance_id,
                    assignment.scan_id,
                )
                return member.instance_id
            return None

    async def release(self, instance_id: str, *, keep: bool = True) -> None:
        async with self._lock:
            member = self.members.get(instance_id)
            if not member:
                return
            member.assignment = None
            member.scan_id = None
            if keep:
                member.status = "idle"
            else:
                member.status = "offline"
                self.members.pop(instance_id, None)

    async def note_member(self, instance_id: str, *, status: str = "pending") -> None:
        async with self._lock:
            if instance_id not in self.members:
                self.members[instance_id] = PoolMember(
                    instance_id=instance_id,
                    status=status,
                    last_seen=time.time(),
                )


def pool_from_settings(
    *,
    enabled: bool,
    size: int,
    token: str | None,
) -> ScannerPool:
    tok = (token or "").strip()
    if enabled and not tok:
        # Deterministic enough for a single CP process; operators should set env.
        tok = secrets.token_urlsafe(24)
        log.warning("SCANNER_POOL_ENABLED without SCANNER_POOL_TOKEN; generated ephemeral token")
    return ScannerPool(enabled=enabled, size=max(0, size), token=tok)
