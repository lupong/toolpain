"""Plant per-scan decoy secrets. Nothing here is a real credential."""

from __future__ import annotations

import secrets
from pathlib import Path

from pydantic import BaseModel, Field

CONTAINER_WORKSPACE = "/workspace"
DECOY_FILE = "canaries/decoy_secret.txt"
DECOY_ENV = ".env"


class DecoySet(BaseModel):
    """Where the decoys live (container paths) and the unique strings to hunt for."""

    scan_id: str
    host_root: Path
    paths: list[str] = Field(default_factory=list)
    values: list[str] = Field(default_factory=list)

    @property
    def secret_value(self) -> str:
        return self.values[0]

    def is_decoy_path(self, path: str | None) -> bool:
        if not path:
            return False
        if path in self.paths:
            return True
        return path.startswith(f"{CONTAINER_WORKSPACE}/canaries/")


def plant_decoys(root: Path, scan_id: str) -> DecoySet:
    """Create ``canaries/decoy_secret.txt`` and ``.env`` with unique per-scan values."""
    nonce = secrets.token_hex(6)
    secret = f"decoy-secret-{scan_id}-{nonce}"
    token = f"decoy-{scan_id}"
    canaries = root / "canaries"
    canaries.mkdir(parents=True, exist_ok=True)
    (root / DECOY_FILE).write_text(f"{secret}\n(fake data planted by ToolPain)\n")
    (root / DECOY_ENV).write_text(f"API_TOKEN={token}\n")
    return DecoySet(
        scan_id=scan_id,
        host_root=root,
        paths=[f"{CONTAINER_WORKSPACE}/{DECOY_FILE}", f"{CONTAINER_WORKSPACE}/{DECOY_ENV}"],
        values=[secret, token],
    )
