"""MCP server scan certificate: one model, an HTML page, and a PDF.

The certificate says the scan ran and what it found. It is not a warranty,
and it does not include the rate-card cost.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import UTC, datetime
from typing import Any

import segno
from fpdf import FPDF
from fpdf.fonts import FontFace

from control_plane.report_sanitize import sanitize_report

STATEMENT = (
    "This record certifies that the scan above was performed. "
    "It is not a warranty that the server is safe to run."
)

_LOGO = (
    '<svg width="28" height="28" viewBox="0 0 24 24" aria-hidden="true">'
    '<path d="M2 14h4l3-8 4 13 3-9 2 4h4" fill="none" stroke="#FF5A36" stroke-width="2"/>'
    "</svg>"
)

_MISSING_NARRATIVE = (
    "Certificate narrative was not generated for this scan. "
    "Re-run the scan so the LLM can write the business use case and next steps."
)


def report_hash(report: dict[str, Any]) -> str:
    # Certificate narrative is presentation copy; sealing ignores it so on-demand
    # LLM fill for legacy scans does not break verify.
    payload = {k: v for k, v in report.items() if k != "certificate"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode()).hexdigest()


def pdf_hash(pdf: bytes) -> str:
    return hashlib.sha256(pdf).hexdigest()


def _esc(value: object) -> str:
    text = "" if value is None else str(value)
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _present(value: object) -> bool:
    if value is None:
        return False
    text = str(value).strip()
    return text not in {"", "None", "null"}


def _when(value: datetime | str) -> str:
    if isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return value
    else:
        parsed = value
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    utc = parsed.astimezone(UTC)
    local = parsed.astimezone()
    return (
        f"{local.strftime('%Y-%m-%d %H:%M:%S %Z')} "
        f"({utc.strftime('%Y-%m-%d %H:%M:%S UTC')})"
    )


def _duration(start: datetime, end: datetime) -> str | None:
    if start.tzinfo is None:
        start = start.replace(tzinfo=UTC)
    if end.tzinfo is None:
        end = end.replace(tzinfo=UTC)
    seconds = int((end - start).total_seconds())
    if seconds < 0:
        return None
    if seconds < 1:
        return "under 1 second"
    minutes, sec = divmod(seconds, 60)
    if minutes:
        return f"{minutes}m {sec:02d}s"
    return f"{sec}s"


def _qr_svg(url: str) -> str:
    qr = segno.make(url, error="m")
    size = 4
    dim = len(qr.matrix) * size
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{dim}" height="{dim}" viewBox="0 0 {dim} {dim}">'
    ]
    for y, row in enumerate(qr.matrix):
        for x, cell in enumerate(row):
            if cell:
                parts.append(
                    f'<rect x="{x * size}" y="{y * size}" width="{size}" height="{size}" fill="#1a1a1a"/>'
                )
    parts.append("</svg>")
    return "".join(parts)


def _pdf_text(value: object) -> str:
    """Helvetica can't render full Unicode; keep certificate PDF ASCII-safe."""
    text = "" if value is None else str(value)
    text = text.replace("\u2014", "-").replace("\u2013", "-").replace("\u2022", "-")
    text = text.replace("\u00b7", "|").replace("\u2019", "'").replace("\u2018", "'")
    text = text.replace("\u201c", '"').replace("\u201d", '"')
    return text.encode("latin-1", "replace").decode("latin-1")


def _finding_type_rows(findings: list[dict[str, Any]]) -> list[tuple[str, int]]:
    counts = Counter(str(f.get("type") or "unknown") for f in findings)
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def narrative_from_report(report: dict[str, Any]) -> tuple[str, list[str], str]:
    """LLM narrative stored on the report. No repo-specific heuristics."""
    block = report.get("certificate") if isinstance(report.get("certificate"), dict) else {}
    summary = str(block.get("business_summary") or "").strip()
    recs_raw = block.get("recommendations") if isinstance(block, dict) else None
    recommendations: list[str] = []
    if isinstance(recs_raw, list):
        for item in recs_raw:
            text = str(item or "").strip()
            if text and text not in recommendations:
                recommendations.append(text)
    source = str(block.get("source") or "") if isinstance(block, dict) else ""
    if summary and recommendations:
        return summary, recommendations[:10], source or "llm"
    return (
        _MISSING_NARRATIVE,
        ["Re-scan to generate LLM business-use summary and ranked recommendations."],
        "missing",
    )


def build_certificate(
    scan_id: str,
    *,
    repo_url: str,
    ref: str,
    created_at: datetime,
    updated_at: datetime,
    account_mode: str,
    report: dict[str, Any],
    ticket: str | None = None,
    scanned_by: str | None = None,
    verify_url: str | None = None,
    seal_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    # Integrity hash is over the sealed on-disk report; the certificate body uses a
    # noise-deflated view so oracle/docs inflation does not dominate the record.
    digest = report_hash(seal_report if seal_report is not None else report)
    view = sanitize_report(report)
    if isinstance(report.get("certificate"), dict):
        view["certificate"] = report["certificate"]
    findings = list(view.get("findings") or [])
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
        for t in (view.get("tools") or [])
    ]
    repo = view.get("repo") or {}
    costs = view.get("costs") or {}
    meters = ((costs.get("actual") or {}).get("meters") or {}) if isinstance(costs, dict) else {}
    runtime = view.get("runtime") or meters.get("runtime")
    provisioner = meters.get("provisioner")
    coverage = view.get("coverage") or "full"
    network = "not isolated" if coverage == "list_only" else "blocked"
    config = view.get("least_privilege_config") or {}
    type_rows = _finding_type_rows(findings)
    business_summary, recommendations, narrative_source = narrative_from_report(view)
    return {
        "title": "MCP Server Scan Certificate",
        "certificate_id": f"C-{scan_id}",
        "scan_id": scan_id,
        "ticket": ticket or None,
        "verdict": view.get("verdict"),
        "headline": _headline(view),
        "business_summary": business_summary,
        "recommendations": recommendations,
        "narrative_source": narrative_source,
        "finding_types": [{"type": name, "count": count} for name, count in type_rows],
        "repo_url": repo.get("url") or repo_url,
        "ref": ref,
        "commit": repo.get("commit") or "",
        "scanned_by": scanned_by or account_mode,
        "started": _when(created_at),
        "finished": _when(updated_at),
        "duration": _duration(created_at, updated_at),
        "provisioner": provisioner,
        "runtime": runtime,
        "network": network,
        "destroyed_at": _when(updated_at),
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
        "least_privilege_config": config,
        "verify_url": verify_url or "",
        "report_sha256": digest,
        "statement": STATEMENT,
    }


def _headline(report: dict[str, Any]) -> str:
    verdict = report.get("verdict")
    tools = report.get("tools") or []
    findings = report.get("findings") or []
    if verdict == "clean":
        if len(tools) == 1:
            return "No pain found. The tool did what it claimed."
        return f"No pain found. All {len(tools)} tools did what they claimed."
    if verdict == "over_privileged":
        extra = sum(1 for t in tools if t.get("verdict") == "exceeds_claim")
        if extra == 1:
            return "Over-privileged: 1 tool can do more than it claims."
        return f"Over-privileged: {extra} tools can do more than they claim."
    if verdict == "suspicious":
        return "Suspicious: worth a closer look."
    crit = sum(1 for f in findings if f.get("severity") == "critical")
    if crit:
        noun = "finding" if crit == 1 else "findings"
        return f"{crit} critical {noun}."
    return "See the findings before adding this server."


def _rows(cert: dict[str, Any]) -> list[tuple[str, str]]:
    fields = [
        ("Repository", cert.get("repo_url")),
        ("Ref", cert.get("ref")),
        ("Commit", cert.get("commit")),
        ("Ticket", cert.get("ticket")),
        ("Scanned by", cert.get("scanned_by")),
        ("Started", cert.get("started")),
        ("Finished", cert.get("finished")),
        ("Duration", cert.get("duration")),
        ("Provisioner", cert.get("provisioner")),
        ("Runtime", cert.get("runtime")),
        ("Network", cert.get("network")),
        ("VM destroyed at", cert.get("destroyed_at")),
        ("Verdict", cert.get("verdict")),
    ]
    return [(label, str(value)) for label, value in fields if _present(value)]


def render_html(cert: dict[str, Any], *, banner: str | None = None, banner_ok: bool | None = None) -> str:
    rows = "".join(
        f"<tr><th>{_esc(label)}</th><td>{_esc(value)}</td></tr>" for label, value in _rows(cert)
    )
    sev = cert["severity"]
    severity_rows = "".join(
        f"<tr><td>{_esc(name)}</td><td>{sev[name]}</td></tr>"
        for name in ("critical", "high", "medium", "low", "info")
    )
    type_rows = "".join(
        f"<tr><td>{_esc(row['type'])}</td><td>{row['count']}</td></tr>"
        for row in cert.get("finding_types") or []
    ) or "<tr><td colspan='2'>No finding types.</td></tr>"
    tool_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            _esc(t["name"]), _esc(t["privilege"]), _esc(t["verdict"])
        )
        for t in cert["tools"]
    ) or "<tr><td colspan='3'>No tools were discovered.</td></tr>"
    finding_rows = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
            _esc(f["id"]), _esc(f["severity"]), _esc(f["title"]), _esc(f["tool"])
        )
        for f in cert["findings"]
    ) or "<tr><td colspan='4'>No findings.</td></tr>"
    rec_rows = "".join(
        f"<tr><td>{i}</td><td>{_esc(item)}</td></tr>"
        for i, item in enumerate(cert.get("recommendations") or [], start=1)
    ) or "<tr><td colspan='2'>No recommendations.</td></tr>"
    config = json.dumps(cert.get("least_privilege_config") or {}, indent=2)
    qr = _qr_svg(cert["verify_url"]) if cert.get("verify_url") else ""
    banner_html = ""
    if banner:
        kind = "ok" if banner_ok else "bad"
        banner_html = f'<p class="banner {kind}">{_esc(banner)}</p>'
    verify_block = ""
    if cert.get("verify_url"):
        verify_block = (
            f"<h2>Integrity</h2><div class='qr'>{qr}</div>"
            f"<p><a href=\"{_esc(cert['verify_url'])}\">{_esc(cert['verify_url'])}</a></p>"
            f"<p>SHA-256 {_esc(cert['report_sha256'])}</p>"
        )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>{_esc(cert["title"])}</title>
<style>
  body {{ margin: 0; background: #eef1f4; color: #1a1a1a; font: 14px/1.45 system-ui, sans-serif; }}
  .sheet {{ max-width: 800px; margin: 24px auto; background: #fff; padding: 32px; border-top: 6px solid #FF5A36; }}
  h1 {{ font-size: 22px; margin: 8px 0 4px; }}
  h2 {{ font-size: 16px; margin: 20px 0 8px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 8px 0 16px; }}
  th, td {{ border: 1px solid #d5dbe3; padding: 6px 8px; text-align: left; vertical-align: top; }}
  th {{ background: #f6f8fa; width: 28%; }}
  table.grid th {{ width: auto; }}
  .brand {{ display: flex; align-items: center; gap: 8px; font-weight: 700; color: #FF5A36; }}
  .verdict {{ display: inline-block; padding: 2px 8px; border-radius: 999px; background: #111; color: #fff; font-size: 12px; letter-spacing: .04em; }}
  .summary {{ margin: 12px 0 16px; padding: 12px 14px; background: #f6f8fa; border-left: 4px solid #FF5A36; }}
  pre {{ background: #f6f8fa; padding: 12px; overflow-x: auto; font-size: 12px; }}
  .banner {{ margin: 0 auto; max-width: 800px; padding: 12px 16px; font-weight: 650; }}
  .banner.ok {{ background: #e5f6ee; color: #0d6b3d; }}
  .banner.bad {{ background: #fde8ec; color: #9b1c32; }}
  .qr {{ margin: 8px 0 12px; max-width: 100%; }}
  .qr svg {{ display: block; max-width: 168px; height: auto; }}
  footer {{ margin-top: 16px; color: #5c6b7a; font-size: 12px; }}
  @media (max-width: 560px) {{ .sheet {{ margin: 0; padding: 16px; }} table {{ display: block; overflow-x: auto; }} }}
</style></head><body>
{banner_html}
<article class="sheet">
  <div class="brand">{_LOGO} ToolPain</div>
  <h1>{_esc(cert["title"])}</h1>
  <p><span class="verdict">{_esc(str(cert.get("verdict") or "").upper())}</span>
     {_esc(cert["certificate_id"])}</p>
  <p>{_esc(cert.get("headline") or "")}</p>
  <h2>Business use case</h2>
  <p class="summary">{_esc(cert.get("business_summary") or "")}</p>
  <h2>Scan</h2>
  <table>{rows}</table>
  <h2>Findings by severity</h2>
  <table class="grid"><tr><th>Severity</th><th>Count</th></tr>{severity_rows}</table>
  <h2>Findings by type</h2>
  <table class="grid"><tr><th>Type</th><th>Count</th></tr>{type_rows}</table>
  <h2>Recommended next steps</h2>
  <table class="grid"><tr><th>#</th><th>Recommendation</th></tr>{rec_rows}</table>
  <h2>Findings</h2>
  <table class="grid"><tr><th>Id</th><th>Severity</th><th>Title</th><th>Tool</th></tr>{finding_rows}</table>
  <h2>Tools</h2>
  <table class="grid"><tr><th>Name</th><th>Privilege</th><th>Verdict</th></tr>{tool_rows}</table>
  <h2>Recommended config</h2>
  <pre>{_esc(config)}</pre>
  {verify_block}
  <p>{_esc(cert["statement"])}</p>
  <footer>Certificate {_esc(cert["certificate_id"])} · page 1 of 1</footer>
</article>
</body></html>"""


class _CertPDF(FPDF):
    cert_id: str = ""

    def footer(self) -> None:
        self.set_y(-12)
        self.set_font("Helvetica", size=8)
        self.set_text_color(80, 80, 80)
        label = f"Certificate {self.cert_id}  ·  page {self.page_no()} of {{nb}}"
        self.cell(0, 8, _pdf_text(label), align="C")


def _draw_qr(pdf: FPDF, url: str) -> None:
    qr = segno.make(url, error="m")
    # Keep the code fully on the current page (Integrity is forced onto a fresh page).
    size = min(1.4, 70.0 / max(len(qr.matrix), 1))
    origin_x = pdf.l_margin
    origin_y = pdf.get_y()
    needed = len(qr.matrix) * size + 28
    if origin_y + needed > pdf.h - pdf.b_margin:
        pdf.add_page()
        origin_y = pdf.get_y()
    pdf.set_fill_color(26, 26, 26)
    for y, row in enumerate(qr.matrix):
        for x, cell in enumerate(row):
            if cell:
                pdf.rect(origin_x + x * size, origin_y + y * size, size, size, style="F")
    pdf.set_y(origin_y + len(qr.matrix) * size + 2)


def _section(pdf: FPDF, title: str, *, new_page: bool = False) -> None:
    if new_page:
        pdf.add_page()
    else:
        pdf.ln(2)
    pdf.set_font("Helvetica", style="B", size=12)
    pdf.set_text_color(20, 20, 20)
    pdf.set_x(pdf.l_margin)
    pdf.cell(0, 7, _pdf_text(title), new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", size=9)


def _write_table(pdf: FPDF, rows: list[list[str]], *, col_widths: tuple[float, ...] | None = None) -> None:
    if not rows:
        return
    heading = FontFace(emphasis="BOLD", size_pt=9, color=(20, 20, 20))
    with pdf.table(
        col_widths=col_widths,
        line_height=5,
        text_align="LEFT",
        headings_style=heading,
        first_row_as_headings=True,
        padding=1.5,
    ) as table:
        for row in rows:
            cells = table.row()
            for cell in row:
                cells.cell(_pdf_text(cell))


def render_pdf(cert: dict[str, Any]) -> bytes:
    pdf = _CertPDF()
    pdf.cert_id = str(cert["certificate_id"])
    pdf.alias_nb_pages()
    pdf.compress = False
    pdf.set_auto_page_break(auto=True, margin=16)
    pdf.add_page()
    pdf.set_text_color(255, 90, 54)
    pdf.set_font("Helvetica", style="B", size=14)
    pdf.cell(0, 8, "ToolPain", new_x="LMARGIN", new_y="NEXT")
    pdf.set_text_color(20, 20, 20)
    pdf.set_font("Helvetica", size=16)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 8, _pdf_text(cert["title"]))
    pdf.set_font("Helvetica", size=11)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 6, _pdf_text(f"{str(cert.get('verdict') or '').upper()}   {cert['certificate_id']}"))
    if cert.get("headline"):
        pdf.set_font("Helvetica", size=10)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, _pdf_text(cert["headline"]))

    _section(pdf, "Business use case")
    pdf.set_font("Helvetica", size=10)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 5, _pdf_text(cert.get("business_summary") or ""))

    _section(pdf, "Scan")
    _write_table(
        pdf,
        [["Field", "Value"], *[[label, value] for label, value in _rows(cert)]],
        col_widths=(45, 145),
    )

    sev = cert["severity"]
    _section(pdf, "Findings by severity")
    _write_table(
        pdf,
        [
            ["Severity", "Count"],
            *[[name, str(sev[name])] for name in ("critical", "high", "medium", "low", "info")],
        ],
        col_widths=(60, 40),
    )

    _section(pdf, "Findings by type")
    type_rows = cert.get("finding_types") or []
    if type_rows:
        _write_table(
            pdf,
            [["Type", "Count"], *[[row["type"], str(row["count"])] for row in type_rows]],
            col_widths=(120, 40),
        )
    else:
        pdf.set_font("Helvetica", size=10)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, "No finding types.")

    _section(pdf, "Recommended next steps")
    recs = cert.get("recommendations") or []
    if recs:
        _write_table(
            pdf,
            [["#", "Recommendation"], *[[str(i), item] for i, item in enumerate(recs, start=1)]],
            col_widths=(12, 178),
        )
    else:
        pdf.set_font("Helvetica", size=10)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, "No recommendations.")

    _section(pdf, "Findings")
    if cert["findings"]:
        _write_table(
            pdf,
            [
                ["Id", "Severity", "Title", "Tool"],
                *[
                    [
                        str(f.get("id") or ""),
                        str(f.get("severity") or ""),
                        str(f.get("title") or ""),
                        str(f.get("tool") or ""),
                    ]
                    for f in cert["findings"]
                ],
            ],
            col_widths=(18, 24, 108, 40),
        )
    else:
        pdf.set_font("Helvetica", size=10)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, "No findings.")

    _section(pdf, "Tools")
    tools = list(cert["tools"] or [])
    if tools:
        # Large servers (100+ tools) blow the PDF; keep a sample so Integrity fits.
        shown = tools[:40]
        _write_table(
            pdf,
            [
                ["Name", "Privilege", "Verdict"],
                *[
                    [
                        str(t.get("name") or ""),
                        str(t.get("privilege") or ""),
                        str(t.get("verdict") or ""),
                    ]
                    for t in shown
                ],
            ],
            col_widths=(80, 40, 70),
        )
        if len(tools) > len(shown):
            pdf.set_font("Helvetica", size=9)
            pdf.set_x(pdf.l_margin)
            pdf.multi_cell(
                0,
                4,
                _pdf_text(f"... and {len(tools) - len(shown)} more tools (full list in the JSON report)."),
            )
    else:
        pdf.set_font("Helvetica", size=10)
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, "No tools were discovered.")

    _section(pdf, "Recommended config")
    pdf.set_font("Helvetica", size=9)
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 4, _pdf_text(json.dumps(cert.get("least_privilege_config") or {}, indent=2)))

    _section(pdf, "Integrity", new_page=True)
    pdf.set_font("Helvetica", size=10)
    if cert.get("verify_url"):
        _draw_qr(pdf, str(cert["verify_url"]))
        pdf.set_x(pdf.l_margin)
        pdf.multi_cell(0, 5, _pdf_text(cert["verify_url"]))
    digest = str(cert["report_sha256"])
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 5, _pdf_text("SHA-256 " + " ".join(digest[i : i + 32] for i in range(0, len(digest), 32))))
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 5, _pdf_text(cert["statement"]))
    out = pdf.output()
    return bytes(out)
