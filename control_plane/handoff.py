"""Plain text an IT admin pastes into a ServiceNow or Jira ticket."""

from __future__ import annotations

from typing import Any

from control_plane.models import ScanSummary


def _repo_short(url: str) -> str:
    text = url.removeprefix("https://github.com/").strip("/")
    return text or url


def _counts(report: dict[str, Any]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in report.get("findings") or []:
        sev = str(finding.get("severity") or "")
        if sev in counts:
            counts[sev] += 1
    return counts


def ticket_note(
    scan: ScanSummary,
    report: dict[str, Any],
    *,
    verify_url: str,
    report_sha256: str,
) -> str:
    verdict = str(report.get("verdict") or scan.verdict or "done").upper()
    counts = _counts(report)
    notable = [
        f"{counts[name]} {name}"
        for name in ("critical", "high", "medium")
        if counts[name]
    ]
    tally = f" ({', '.join(notable)})" if notable else ""
    repo = report.get("repo") or {}
    commit = str(repo.get("commit") or "")
    ref = scan.ref or "main"
    lines = [
        f"ToolPain scan {scan.id} · {verdict}{tally}",
        f"Repo: {_repo_short(str(repo.get('url') or scan.repo_url))} @ {ref}"
        + (f" · {commit}" if commit else ""),
    ]
    if scan.ticket:
        lines.append(f"Ticket: {scan.ticket}")
    findings = list(report.get("findings") or [])
    if findings:
        top = findings[0]
        lines.append(f"Top finding: {top.get('title') or top.get('type') or 'See the certificate.'}")
    rec = ""
    if report.get("verdict") == "flagged" and findings and findings[0].get("tool"):
        rec = f"Block {findings[0]['tool']}, then use the least-privilege config."
    elif report.get("verdict") == "clean":
        rec = "Safe to add. The least-privilege config is still the tightest setup."
    elif report.get("verdict") == "over_privileged":
        rec = "Use the least-privilege config to turn off tools you don't need."
    if rec:
        lines.append(f"Next step: {rec}")
    lines.append(f"Certificate: {verify_url} · SHA-256 {report_sha256[:12]}…")
    return "\n".join(lines)


def failure_note(scan: ScanSummary, *, stage: str | None, detail: str | None) -> str:
    code = scan.error_code or "failed"
    where = stage or "scan"
    reason = detail or scan.error_detail or "The scan stopped before a report."
    lines = [
        f"ToolPain scan {scan.id} failed",
        f"Error: {code} at {where}",
        f"Reason: {reason}",
    ]
    if scan.ticket:
        lines.append(f"Ticket: {scan.ticket}")
    return "\n".join(lines)
