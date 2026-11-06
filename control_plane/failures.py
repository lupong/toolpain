"""Closed set of scan failure codes and the error-panel each one opens."""

from __future__ import annotations

PANEL_FOR_CODE: dict[str, str] = {
    "invalid_repo": "invalid",
    "repo_unavailable": "private",
    "ref_missing": "failed",
    "build_failed": "build",
    "launch_failed": "build",
    "no_mcp_server": "failed",
    "probe_timeout": "timeout",
    "report_invalid": "failed",
    "provision_failed": "vm",
    "byo_rejected": "key",
    "cancelled": "cancelled",
    "internal": "failed",
}

FAILURE_CODES = frozenset(PANEL_FOR_CODE)
TERMINAL_STATUSES = frozenset({"cancelled", "failed", "timeout", "done"})
