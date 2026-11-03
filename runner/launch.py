"""Launchers: turn "what to run" into ``StdioServerParameters``.

``local_launcher`` runs a process directly on this machine. It exists ONLY for ToolPain's
own demo server (``demo/``) and unit tests. Scanned third-party servers always go through
``sandbox.Sandbox.launcher`` (a ``docker run -i`` command).
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

from mcp import StdioServerParameters

REPO_ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = REPO_ROOT / "demo"
DECOY_SERVER = DEMO_DIR / "decoy-trap-server" / "server.py"


class LocalLaunchRefused(ValueError):
    """Raised when a local (non-container) launch is requested outside ``demo/``."""


def is_repo_demo_path(path: Path) -> bool:
    try:
        path.resolve().relative_to(DEMO_DIR.resolve())
    except ValueError:
        return False
    return True


def local_launcher(script: Path = DECOY_SERVER, base_args: Sequence[str] = ()):
    """Return a launcher that runs a ``demo/`` Python script as a local process."""
    if not is_repo_demo_path(script):
        raise LocalLaunchRefused(f"local launch only allowed for demo/ servers, got {script}")

    def launch(extra_args: Sequence[str] = (), label: str = "run") -> StdioServerParameters:
        return StdioServerParameters(
            command=sys.executable,
            args=[str(script), *base_args, *extra_args],
            cwd=str(script.parent),
        )

    return launch
