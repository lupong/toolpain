"""Scan record for an IT file: one model, an HTML preview, and a PDF download.

The record certifies that ToolPain ran the scan. It is not a warranty, and it
carries no seal.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

from fpdf import FPDF

STATEMENT = (
    "This record certifies that the scan above was performed. "
    "It is not a warranty that the server is safe to run."
)


def report_hash(report: dict[str, Any]) -> str:
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def _esc(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_certificate(
    scan_id: str,
    *,
    repo_url: str,
    ref: str,
    created_at: datetime,
    updated_at: datetime,
    account_mode: str,
    report: dict[str, Any],
) -> dict[str, Any]:
    findings = list(report.get("findings") or [])
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        sev = str(finding.get("severity") or "")
        if sev in counts:
            counts[sev] += 1
    tools = [
        {
            "name": t.get("name"),
            "privilege": t.get("privilege"),
            "verdict": t.get("verdict"),
        }
        for t in (report.get("tools") or [])
    ]
    repo = report.get("repo") or {}
    costs = report.get("costs") or {}
    partial = bool(report.get("partial"))
    return {
        "title": "Partial scan record" if partial else "ToolPain Scan Record",
        "scan_id": scan_id,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "repo_url": repo.get("url") or repo_url,
        "ref": ref,
        "commit": repo.get("commit") or "",
        "started": created_at.isoformat(),
        "finished": updated_at.isoformat(),
        "account_mode": account_mode,
        "provisioner": ((costs.get("actual") or {}).get("meters") or {}).get("provisioner"),
        "runtime": report.get("runtime"),
        "coverage": report.get("coverage") or "full",
        "verdict": report.get("verdict"),
        "severity": counts,
        "tools": tools,
        "findings": [
            {
                "id": f.get("id"),
                "severity": f.get("severity"),
                "title": f.get("title"),
                "tool": f.get("tool"),
            }
            for f in findings
        ],
        "costs": {
            "rate_card": costs.get("rate_card"),
            "estimate_usd": (costs.get("estimate") or {}).get("total_usd")
            if isinstance(costs.get("estimate"), dict)
            else None,
            "actual_usd": (costs.get("actual") or {}).get("total_usd"),
            "delta_usd": costs.get("delta_usd"),
        },
        "report_sha256": report_hash(report),
        "statement": STATEMENT,
    }


def render_html(cert: dict[str, Any]) -> str:
    tool_rows = (
        "".join(
            "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                _esc(t["name"]), _esc(t["privilege"]), _esc(t["verdict"])
            )
            for t in cert["tools"]
        )
        or "<tr><td colspan='3'>No tools were discovered.</td></tr>"
    )
    finding_rows = (
        "".join(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                _esc(f["id"]), _esc(f["severity"]), _esc(f["title"]), _esc(f["tool"])
            )
            for f in cert["findings"]
        )
        or "<tr><td colspan='4'>No findings.</td></tr>"
    )
    costs = cert["costs"]
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{_esc(cert["title"])}</title>
<style>
  body {{ font: 14px/1.45 Georgia, serif; color: #1a1a1a; margin: 32px; }}
  h1 {{ font-size: 22px; margin: 0 0 4px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 8px 0 16px; }}
  th, td {{ border: 1px solid #bbb; padding: 4px 6px; text-align: left; vertical-align: top; }}
  th {{ background: #f3f3f3; }}
  .muted {{ color: #444; }}
  @media (max-width: 560px) {{ body {{ margin: 12px; }} table {{ display: block; overflow-x: auto; }} }}
</style></head><body>
<h1>{_esc(cert["title"])}</h1>
<p class="muted">Record {_esc(cert["scan_id"])} · generated {_esc(cert["generated_at"])}</p>
<h2>Scan</h2>
<table>
<tr><th>Repository</th><td>{_esc(cert["repo_url"])}</td></tr>
<tr><th>Ref</th><td>{_esc(cert["ref"])}</td></tr>
<tr><th>Commit</th><td>{_esc(cert["commit"])}</td></tr>
<tr><th>Started</th><td>{_esc(cert["started"])}</td></tr>
<tr><th>Finished</th><td>{_esc(cert["finished"])}</td></tr>
<tr><th>Account</th><td>{_esc(cert["account_mode"])}</td></tr>
<tr><th>Provisioner</th><td>{_esc(cert["provisioner"])}</td></tr>
<tr><th>Runtime</th><td>{_esc(cert["runtime"])}</td></tr>
<tr><th>Coverage</th><td>{_esc(cert["coverage"])}</td></tr>
<tr><th>Verdict</th><td>{_esc(cert["verdict"])}</td></tr>
</table>
<h2>Findings by severity</h2>
<p>critical {cert["severity"]["critical"]} · high {cert["severity"]["high"]} · medium {cert["severity"]["medium"]} · low {cert["severity"]["low"]} · info {cert["severity"]["info"]}</p>
<h2>Tools</h2>
<table><tr><th>Name</th><th>Privilege</th><th>Verdict</th></tr>{tool_rows}</table>
<h2>Findings</h2>
<table><tr><th>Id</th><th>Severity</th><th>Title</th><th>Tool</th></tr>{finding_rows}</table>
<h2>Cost</h2>
<p>Rate card {_esc(costs["rate_card"])}. Estimate {_esc(costs["estimate_usd"])}. Actual {_esc(costs["actual_usd"])}. Delta {_esc(costs["delta_usd"])}.</p>
<h2>Integrity</h2>
<p>SHA-256 of the canonical report JSON: {_esc(cert["report_sha256"])}</p>
<p>{_esc(cert["statement"])}</p>
</body></html>"""


def render_pdf(cert: dict[str, Any]) -> bytes:
    pdf = FPDF()
    pdf.compress = False
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Helvetica", size=16)
    pdf.multi_cell(0, 8, cert["title"])
    pdf.set_font("Helvetica", size=10)

    def line(text: str) -> None:
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, text)

    line(f"Record {cert['scan_id']}")
    line(f"Generated {cert['generated_at']}")
    lines = [
        f"Repository {cert['repo_url']}",
        f"Ref {cert['ref']}",
        f"Commit {cert['commit']}",
        f"Started {cert['started']}",
        f"Finished {cert['finished']}",
        f"Account {cert['account_mode']}",
        f"Provisioner {cert['provisioner']}",
        f"Runtime {cert['runtime']}",
        f"Coverage {cert['coverage']}",
        f"Verdict {cert['verdict']}",
        "Severity " + ", ".join(f"{k} {v}" for k, v in cert["severity"].items()),
    ]
    for item in lines:
        line(item)
    pdf.ln(2)
    pdf.set_font("Helvetica", size=12)
    pdf.cell(0, 7, "Tools", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=10)
    if cert["tools"]:
        for tool in cert["tools"]:
            line(f"{tool['name']}  {tool['privilege']}  {tool['verdict']}")
    else:
        line("No tools were discovered.")
    pdf.ln(1)
    pdf.set_font("Helvetica", size=12)
    pdf.cell(0, 7, "Findings", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=10)
    if cert["findings"]:
        for finding in cert["findings"]:
            line(f"{finding['id']} {finding['severity']} {finding['title']} ({finding['tool']})")
    else:
        line("No findings.")
    costs = cert["costs"]
    pdf.ln(1)
    line(
        "Cost rate card {rate}. Estimate {est}. Actual {act}. Delta {delta}.".format(
            rate=costs["rate_card"],
            est=costs["estimate_usd"],
            act=costs["actual_usd"],
            delta=costs["delta_usd"],
        )
    )
    digest = str(cert["report_sha256"])
    line("Report SHA-256 " + " ".join(digest[i : i + 32] for i in range(0, len(digest), 32)))
    line(cert["statement"])
    out = pdf.output()
    return bytes(out)
