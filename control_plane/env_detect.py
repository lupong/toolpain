"""Detect Docker and gVisor (runsc) availability for sandbox mode selection."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class EnvInfo:
    docker: bool
    runsc: bool
    runtime: str  # runsc | runc | none
    mode: str  # full | runc | demo_sandbox

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def _has_docker() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        r = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
            check=False,
        )
        return r.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _has_runsc() -> bool:
    if shutil.which("runsc"):
        return True
    try:
        r = subprocess.run(
            ["docker", "info", "--format", "{{.Runtimes}}"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        return r.returncode == 0 and "runsc" in (r.stdout or "")
    except (OSError, subprocess.TimeoutExpired):
        return False


def detect() -> EnvInfo:
    """Return sandbox capability for this host."""
    docker = _has_docker()
    runsc = _has_runsc() if docker else False
    if docker and runsc:
        return EnvInfo(docker=True, runsc=True, runtime="runsc", mode="full")
    if docker:
        return EnvInfo(docker=True, runsc=False, runtime="runc", mode="runc")
    return EnvInfo(docker=False, runsc=False, runtime="none", mode="demo_sandbox")


if __name__ == "__main__":
    print(detect())
