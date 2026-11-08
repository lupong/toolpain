"""Closed set of scan failure codes and the error-panel each one opens."""

from __future__ import annotations

from typing import Any

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
    "vm": "vm",
}

FAILURE_CODES = frozenset(PANEL_FOR_CODE)
TERMINAL_STATUSES = frozenset({"cancelled", "failed", "timeout", "done"})


def terminal_update_from_event(
    *,
    stage: str,
    msg: str,
    data: dict[str, Any] | None,
) -> dict[str, str] | None:
    """If this runner/provisioner event should end the scan, return ``update_scan`` kwargs.

    Success posts ``/internal/.../report`` (status=done) *before* sandbox destroy.
    Failure emits a coded error (or ``Scan failed``) then destroy without a report —
    those must flip the scan off ``running`` so SSE ``done`` fires and the UI unsticks.
    Free-text ``data.error`` from codegen retries is ignored (not a FAILURE_CODES value).
    """
    payload = data or {}
    raw = payload.get("error") if payload.get("error") is not None else payload.get("code")
    code = str(raw).strip() if raw is not None else ""
    text = (msg or "").strip()
    lower = text.lower()

    if code in FAILURE_CODES:
        status = "timeout" if code == "probe_timeout" else "failed"
        if code == "cancelled":
            status = "cancelled"
        return {
            "status": status,
            "error_code": code,
            "error_detail": (text or code)[:500],
        }
    if lower.startswith("scan failed"):
        return {
            "status": "failed",
            "error_code": "internal",
            "error_detail": text[:500] or "Scan failed",
        }
    if stage == "destroy":
        # Runner/provisioner tore down while still non-terminal → no success report.
        if "instance destroyed" in lower:
            return {
                "status": "timeout",
                "error_code": "probe_timeout",
                "error_detail": text[:500] or "Instance destroyed before scan finished",
            }
        return {
            "status": "failed",
            "error_code": "internal",
            "error_detail": text[:500] or "Sandbox torn down without a report",
        }
    return None
