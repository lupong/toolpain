"""Provisioner interface."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class Provisioner(ABC):
    """Start and tear down a scan environment."""

    @abstractmethod
    async def start_scan(
        self, scan_id: str, repo_url: str, ref: str, token: str, **kwargs: Any
    ) -> None:
        """Kick off the scan asynchronously (may schedule background work)."""

    @abstractmethod
    async def cancel_scan(self, scan_id: str) -> None:
        """Best-effort cancel / destroy."""
