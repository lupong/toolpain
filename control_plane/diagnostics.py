"""Stage timings and a redacted debug bundle for a scan that needs a human."""

from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime
from typing import Any

from control_plane.models import EventOut, ScanSummary
from control_plane.redaction import redact_text


def _parse_ts(value: datetime | str | None) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def stage_timings(events: list[EventOut]) -> list[dict[str, Any]]:
    grouped: dict[str, list[EventOut]] = {}
    order: list[str] = []
    for event in events:
        stage = str(event.stage or "")
        if not stage:
            continue
        if stage not in grouped:
            order.append(stage)
            grouped[stage] = []
        grouped[stage].append(event)
    rows: list[dict[str, Any]] = []
    for stage in order:
        items = grouped[stage]
        start = _parse_ts(items[0].ts)
        end = _parse_ts(items[-1].ts)
        duration = None
        if start and end:
            duration = round(max(0.0, (end - start).total_seconds()), 3)
        failed = any((ev.data or {}).get("error") or (ev.data or {}).get("code") for ev in items)
        status = "failed" if failed else "done"
        excerpt = redact_text(items[-1].msg or "")
        rows.append(
            {
                "stage": stage,
                "start": start.isoformat() if start else None,
                "end": end.isoformat() if end else None,
                "duration_sec": duration,
                "status": status,
                "log_excerpt": excerpt,
            }
        )
    return rows


def build_diagnostics(
    scan: ScanSummary,
    events: list[EventOut],
    report: dict[str, Any] | None,
    llm_counts: dict[str, int],
) -> dict[str, Any]:
    timings = stage_timings(events)
    failing = next((row for row in timings if row["status"] == "failed"), None)
    art = (report or {}).get("artifacts") or {}
    launch = (report or {}).get("launch") or {}
    meters = (((report or {}).get("costs") or {}).get("actual") or {}).get("meters") or {}
    return {
        "scan_id": scan.id,
        "status": scan.status,
        "error_code": scan.error_code,
        "error_detail": scan.error_detail,
        "failing_stage": failing["stage"] if failing else None,
        "log_excerpt": failing["log_excerpt"] if failing else None,
        "stages": timings,
        "launch_argv": launch.get("argv") or [],
        "launch_sh": art.get("launch_sh"),
        "probe_source": art.get("probe_source"),
        "probe_summary": art.get("probe_summary"),
        "codegen_fallback": art.get("probe_source") == "heuristic" or art.get("launch_source") == "heuristic",
        "llm_calls": llm_counts,
        "sandbox": {
            "provisioner": meters.get("provisioner"),
            "runtime": (report or {}).get("runtime") or meters.get("runtime"),
            "network": "blocked",
        },
    }


def debug_bundle(
    scan: ScanSummary,
    events: list[EventOut],
    report: dict[str, Any] | None,
    diagnostics: dict[str, Any],
) -> bytes:
    """ZIP of the scan record. Every text file is passed through redaction."""
    event_rows = [
        {
            "id": ev.id,
            "stage": ev.stage,
            "level": ev.level,
            "msg": redact_text(ev.msg),
            "ts": ev.ts.isoformat() if isinstance(ev.ts, datetime) else ev.ts,
            "data": ev.data,
        }
        for ev in events
    ]
    stderr_lines = [
        redact_text(ev.msg)
        for ev in events
        if ev.stage in {diagnostics.get("failing_stage"), "build", "launch"} and ev.level in {"alert", "warn"}
    ]
    env = {
        "scan_id": scan.id,
        "status": scan.status,
        "error_code": scan.error_code,
        "runtime": (diagnostics.get("sandbox") or {}).get("runtime"),
        "provisioner": (diagnostics.get("sandbox") or {}).get("provisioner"),
    }
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("events.json", redact_text(json.dumps(event_rows, indent=2, default=str)))
        if report is not None:
            archive.writestr("report.json", redact_text(json.dumps(report, indent=2, default=str)))
        else:
            archive.writestr(
                "report.json",
                redact_text(json.dumps({"error": scan.error_code, "detail": scan.error_detail})),
            )
        archive.writestr("runner.stderr", "\n".join(stderr_lines) or "No runner stderr was recorded.")
        archive.writestr("environment.json", json.dumps(env, indent=2))
        archive.writestr("diagnostics.json", redact_text(json.dumps(diagnostics, indent=2, default=str)))
    return buffer.getvalue()
