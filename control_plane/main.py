"""FastAPI control plane: public API, SSE, static web/, internal runner callbacks."""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import secrets
import sys
import tarfile
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from sse_starlette.sse import EventSourceResponse
from starlette.middleware.base import BaseHTTPMiddleware

from control_plane.certificate import (
    build_certificate,
    pdf_hash,
    render_html,
    render_pdf,
    report_hash,
)
from control_plane.certificate_narrative import ensure_report_narrative
from control_plane.cli import scan_main
from control_plane.config import get_settings
from control_plane.costs import FIXTURES, build_estimate, load_rate_card, price_actual
from control_plane.db import Database
from control_plane.diagnostics import build_diagnostics, debug_bundle
from control_plane.env_detect import detect
from control_plane.failures import FAILURE_CODES, TERMINAL_STATUSES, terminal_update_from_event
from control_plane.handoff import failure_note, ticket_note
from control_plane.jsonlog import install_json_logs
from control_plane.intake_inspect import inspect_repo
from control_plane.llm import chat_json
from control_plane.report_sanitize import sanitize_report
from control_plane.models import (
    EventIn,
    EventOut,
    IntakeInspectRequest,
    IntakeInspectResponse,
    Report,
    ScanCreate,
    ScanSummary,
)
from control_plane.provisioner import get_provisioner
from control_plane.redaction import install_redaction, redact_text
from control_plane.sample_report import DEMO_REPOS, report_for_demo
from control_plane.scanner_pool import pool_from_settings
from control_plane.share import compare_reports, share_expiry, sign_share, verify_share

VERIFY_TTL_SEC = 365 * 24 * 60 * 60
PRODUCT_VERSION = "0.5.0"

log = logging.getLogger("toolpain")
ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Simple per-IP rate limit for scan creation."""

    def __init__(self, app: FastAPI, limit: int = 10, window_sec: int = 60) -> None:
        super().__init__(app)
        self.limit = limit
        self.window = window_sec
        self._hits: dict[str, list[float]] = {}

    async def dispatch(self, request: Request, call_next):  # type: ignore[no-untyped-def]
        if request.method == "POST" and request.url.path == "/api/scans":
            ip = request.client.host if request.client else "unknown"
            now = time.time()
            bucket = [t for t in self._hits.get(ip, []) if now - t < self.window]
            if len(bucket) >= self.limit:
                return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
            bucket.append(now)
            self._hits[ip] = bucket
        return await call_next(request)


class AppState:
    def __init__(self) -> None:
        self.settings = get_settings()
        self.settings.data_dir.mkdir(parents=True, exist_ok=True)
        self.settings.reports_dir.mkdir(parents=True, exist_ok=True)
        self.db = Database(self.settings.db_path)
        self.subscribers: dict[str, list[asyncio.Queue[dict[str, Any]]]] = {}
        self.pool = pool_from_settings(
            enabled=self.settings.scanner_pool_enabled,
            size=self.settings.scanner_pool_size,
            token=self.settings.scanner_pool_token,
        )
        self.provisioner = get_provisioner(
            self.settings.provisioner,
            emit_event=self.emit_event,
            save_report=self.save_report,
            update_scan=self.update_scan,
            get_scan=self.db.get_scan,
            api_key=self.settings.vultr_api_key,
            control_plane_url=self.settings.control_plane_url,
            pool=self.pool if self.settings.provisioner == "vultr" else None,
        )

    def emit_event(
        self,
        scan_id: str,
        stage: str,
        level: str,
        msg: str,
        data: dict[str, Any] | None = None,
    ) -> Any:
        safe_msg = redact_text(msg)
        safe_data = data or {}
        log.info(
            safe_msg,
            extra={
                "scan_id": scan_id,
                "stage": stage,
                "error_code": str(safe_data.get("code") or safe_data.get("error") or ""),
            },
        )
        event = self.db.add_event(scan_id, stage, level, safe_msg, safe_data)
        payload = event.model_dump(mode="json")
        for q in list(self.subscribers.get(scan_id, [])):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass
        return event

    def save_report(self, scan_id: str, report: Report | dict[str, Any]) -> None:
        payload = report.model_dump() if isinstance(report, Report) else dict(report)
        costs = payload.get("costs") or {}
        if "actual" not in costs:
            payload["costs"] = self._price(scan_id, payload)
        self.db.save_report(scan_id, payload, self.settings.reports_dir)

    def _price(self, scan_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        scan = self.db.get_scan(scan_id)
        meters = payload.get("meters") or {}
        counts = self.db.llm_call_counts(scan_id)
        now = datetime.now(UTC)
        started = scan.created_at if scan else now
        if started.tzinfo is None:
            started = started.replace(tzinfo=UTC)
        duration = meters.get("duration_sec")
        if duration is None:
            duration = max(0.0, (now - started).total_seconds())
        repo_bytes = int(meters.get("repo_bytes") or 0)
        if not repo_bytes and scan:
            pinned = FIXTURES.get(scan.repo_url.rstrip("/"))
            if pinned:
                repo_bytes = int(pinned["size_kb"]) * 1024
        provisioner = str(meters.get("provisioner") or "")
        if not provisioner:
            provisioner = "vultr" if scan and scan.account_mode == "byo" else "local"
            if self.settings.provisioner == "vultr" and provisioner == "local":
                provisioner = "vultr"
        rounds = int(
            meters.get("probe_rounds") or payload.get("stats", {}).get("probe_rounds") or 1
        )
        return price_actual(
            card=load_rate_card(),
            provisioner=provisioner,
            duration_sec=float(duration),
            repo_bytes=repo_bytes,
            codegen_calls=int(meters.get("codegen_calls") or counts.get("codegen") or 0),
            research_calls=int(meters.get("research_calls") or counts.get("research") or 0),
            probe_rounds=rounds,
            runtime=meters.get("runtime") or payload.get("runtime"),
            estimate=self.db.get_estimate(scan_id),
        )

    def update_scan(self, scan_id: str, **kwargs: Any) -> None:
        self.db.update_scan(scan_id, **kwargs)
        # Notify SSE listeners of status changes
        status = kwargs.get("status")
        if status:
            self.emit_event(
                scan_id,
                "report" if status == "done" else "intake",
                "info",
                f"status={status}",
                {"status": status, "verdict": kwargs.get("verdict")},
            )


STATE = AppState()


def get_state() -> AppState:
    return STATE


def require_scan_token(
    scan_id: str,
    x_scan_token: str | None = Header(default=None, alias="X-Scan-Token"),
    state: AppState = Depends(get_state),
) -> str:
    expected = state.db.get_token(scan_id)
    if not expected or not x_scan_token or not secrets.compare_digest(x_scan_token, expected):
        raise HTTPException(status_code=401, detail="invalid scan token")
    return x_scan_token


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    install_redaction(log)
    logging.basicConfig(level=logging.INFO)
    install_json_logs()
    log.info(
        "ToolPain control plane starting provisioner=%s llm=%s pool=%s",
        STATE.settings.provisioner,
        STATE.settings.llm_mode,
        STATE.pool.snapshot(),
    )
    _seed_demos(STATE)
    pool_task: asyncio.Task[None] | None = None
    if (
        STATE.settings.provisioner == "vultr"
        and STATE.pool.enabled
        and STATE.settings.vultr_api_key
    ):
        from control_plane.provisioner import vultr_ops

        async def _ensure_pool() -> None:
            try:
                await vultr_ops.ensure_scanner_pool(STATE.provisioner)  # type: ignore[arg-type]
            except Exception:  # noqa: BLE001
                log.exception("scanner pool ensure failed")

        pool_task = asyncio.create_task(_ensure_pool())
    yield
    if pool_task is not None:
        pool_task.cancel()
        try:
            await pool_task
        except asyncio.CancelledError:
            pass


app = FastAPI(title="ToolPain", version=PRODUCT_VERSION, lifespan=lifespan)
app.add_middleware(RateLimitMiddleware, limit=20, window_sec=60)


@app.get("/api/health")
def health(state: AppState = Depends(get_state)) -> dict[str, Any]:
    return {
        "ok": True,
        "env": detect().as_dict(),
        "provisioner": state.settings.provisioner,
        "llm_mode": state.settings.llm_mode,
        "codegen_mode": (os.environ.get("CODEGEN_MODE") or "llm").lower(),
        "codegen_model": state.settings.codegen_model,
        "version": PRODUCT_VERSION,
        "supports": ["stdio", "http", "sse"],
        "scanner_pool": state.pool.snapshot(),
    }


@app.post("/internal/pool/heartbeat")
async def pool_heartbeat(
    body: dict[str, Any],
    request: Request,
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Warm-pool agents report idle/busy and receive scan assignments."""
    presented = request.headers.get("X-Pool-Token")
    if not state.pool.check_token(presented):
        raise HTTPException(status_code=401, detail="invalid pool token")
    instance_id = str(body.get("instance_id") or "").strip()
    if not instance_id:
        raise HTTPException(status_code=422, detail="instance_id required")
    status = str(body.get("status") or "idle").strip().lower()
    if status not in {"idle", "busy", "offline", "pending"}:
        status = "idle"
    return await state.pool.register_or_heartbeat(instance_id, status=status)


@app.post("/api/intake/inspect", response_model=IntakeInspectResponse)
async def intake_inspect(
    body: IntakeInspectRequest,
    state: AppState = Depends(get_state),
) -> IntakeInspectResponse:
    try:
        inspection = await inspect_repo(
            state.settings,
            body.repo_url,
            body.ref or "main",
            with_message=True,
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return IntakeInspectResponse(**inspection.as_dict())


@app.post("/api/scans", response_model=ScanSummary, status_code=201)
async def create_scan(
    body: ScanCreate,
    state: AppState = Depends(get_state),
    x_api_token: str | None = Header(default=None, alias="X-Api-Token"),
) -> ScanSummary:
    if x_api_token and not state.db.consume_quota(x_api_token):
        raise HTTPException(status_code=429, detail="quota")
    demo = body.demo
    repo_url = body.repo_url
    ref = body.ref or "main"
    if demo and demo in DEMO_REPOS:
        repo_url = DEMO_REPOS[demo]["repo_url"]
        ref = DEMO_REPOS[demo].get("ref", ref)

    # Monorepo gate: require an explicit package path when multiple MCP servers exist.
    # Demos and existing mcp_url targets skip this (no clone / package pick).
    # GitHub inspect failures fail open so a flaky API does not block every scan.
    if not demo and not body.mcp_url:
        try:
            inspection = await inspect_repo(
                state.settings,
                repo_url,
                ref,
                with_message=True,
            )
        except RuntimeError:
            inspection = None
        if inspection and inspection.multi and not body.prefer_subdir:
            raise HTTPException(
                status_code=422,
                detail={
                    "code": "monorepo_choice_required",
                    "message": inspection.message
                    or (
                        f"This repository contains {inspection.count} MCP servers. "
                        "Pick one server path to scan."
                    ),
                    "candidates": inspection.candidates,
                    "count": inspection.count,
                },
            )

    scan_id = f"s_{uuid.uuid4().hex[:8]}"
    token = secrets.token_urlsafe(24)
    account_mode = "byo" if body.byo_vultr_key else "toolpain"
    label = None
    if x_api_token:
        label = state.db.token_label(x_api_token)
    summary = state.db.create_scan(
        scan_id,
        repo_url,
        ref,
        token,
        account_mode=account_mode,
        demo=demo,
        ticket=body.ticket,
        token_label=label or ("demo" if demo else None),
    )
    provisioner = (
        "vultr" if body.byo_vultr_key or state.settings.provisioner == "vultr" else "local"
    )
    state.db.set_estimate(scan_id, build_estimate(repo_url, provisioner))
    if x_api_token:
        state.db.set_owner(scan_id, state.db.hash_token(x_api_token))
    state.emit_event(scan_id, "intake", "info", f"Accepted scan for {repo_url}@{ref}")
    await state.provisioner.start_scan(
        scan_id,
        repo_url,
        ref,
        token,
        byo_vultr_key=body.byo_vultr_key,
        demo=demo,
        prefer_subdir=body.prefer_subdir,
        scan_brief=body.scan_brief,
        protocol=body.protocol,
        upstream_url=body.upstream_url,
        mcp_url=body.mcp_url,
        use_pool=bool(body.use_pool),
    )
    return summary


def _view_summary(state: AppState, scan: ScanSummary) -> ScanSummary:
    """Overlay deflated verdict/findings for done scans (oracle/docs noise)."""
    if scan.status != "done":
        return scan
    report = state.db.get_report(scan.id)
    if not report:
        return scan
    view = sanitize_report(report)
    return scan.model_copy(
        update={
            "verdict": view.get("verdict"),
            "findings_count": len(view.get("findings") or []),
        }
    )


@app.get("/api/scans", response_model=list[ScanSummary])
def list_scans(
    state: AppState = Depends(get_state),
    x_api_token: str | None = Header(default=None, alias="X-Api-Token"),
) -> list[ScanSummary]:
    owner = state.db.hash_token(x_api_token) if x_api_token else None
    return [_view_summary(state, s) for s in state.db.list_scans(owner_hash=owner)]


@app.get("/api/scans/{scan_id}", response_model=ScanSummary)
def get_scan(scan_id: str, state: AppState = Depends(get_state)) -> ScanSummary:
    scan = state.db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    return _view_summary(state, scan)


@app.get("/api/scans/{scan_id}/events")
async def scan_events(
    scan_id: str,
    request: Request,
    state: AppState = Depends(get_state),
) -> EventSourceResponse:
    if not state.db.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="scan not found")

    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=256)
    state.subscribers.setdefault(scan_id, []).append(queue)

    async def gen() -> AsyncIterator[dict[str, Any]]:
        last_id = 0
        try:
            for ev in state.db.list_events(scan_id, after_id=0):
                last_id = ev.id
                yield {"event": "stage", "data": ev.model_dump_json()}
            while True:
                if await request.is_disconnected():
                    break
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=1.0)
                    yield {
                        "event": "stage",
                        "data": __import__("json").dumps(payload),
                    }
                    last_id = max(last_id, int(payload.get("id", 0)))
                except TimeoutError:
                    # Catch up any missed DB events
                    for ev in state.db.list_events(scan_id, after_id=last_id):
                        last_id = ev.id
                        yield {"event": "stage", "data": ev.model_dump_json()}
                    scan = state.db.get_scan(scan_id)
                    if scan and scan.status in {"done", "failed", "cancelled", "timeout"}:
                        # drain remaining then end
                        for ev in state.db.list_events(scan_id, after_id=last_id):
                            last_id = ev.id
                            yield {"event": "stage", "data": ev.model_dump_json()}
                        error, detail = _failure_from_events(state, scan_id)
                        yield {
                            "event": "done",
                            "data": json.dumps(
                                {
                                    "status": scan.status,
                                    "verdict": scan.verdict,
                                    "error": error,
                                    "detail": detail,
                                }
                            ),
                        }
                        break
                    yield {"event": "ping", "data": "{}"}
        finally:
            subs = state.subscribers.get(scan_id, [])
            if queue in subs:
                subs.remove(queue)

    return EventSourceResponse(gen())


@app.get("/api/scans/{scan_id}/log", response_model=list[EventOut])
def scan_log(scan_id: str, state: AppState = Depends(get_state)) -> list[EventOut]:
    if not state.db.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="scan not found")
    return state.db.list_events(scan_id)


@app.get("/api/scans/{scan_id}/report")
def get_report(
    scan_id: str,
    state: AppState = Depends(get_state),
    x_api_token: str | None = Header(default=None, alias="X-Api-Token"),
) -> dict[str, Any]:
    if not state.db.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="scan not found")
    owner = state.db.owner_of(scan_id)
    if owner and state.db.hash_token(x_api_token or "") != owner:
        raise HTTPException(status_code=403, detail="private report")
    report = state.db.get_report(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="report not ready")
    return sanitize_report(report)


@app.post("/api/scans/{scan_id}/share")
def share_scan(
    scan_id: str,
    state: AppState = Depends(get_state),
    x_api_token: str | None = Header(default=None, alias="X-Api-Token"),
) -> dict[str, Any]:
    if not state.db.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="scan not found")
    owner = state.db.owner_of(scan_id)
    if owner and state.db.hash_token(x_api_token or "") != owner:
        raise HTTPException(status_code=403, detail="private report")
    token, exp = sign_share(scan_id)
    return {"token": token, "expires_at": exp, "url": f"/share/{token}"}


def _wants_html(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "text/html" in accept and "application/json" not in accept.split(",")[0]


@app.get("/share/{token}")
def shared_report(token: str, request: Request, state: AppState = Depends(get_state)) -> Any:
    scan_id = verify_share(token)
    if not scan_id:
        if _wants_html(request):
            return RedirectResponse("/scan.html?state=error&reason=share", status_code=302)
        raise HTTPException(status_code=404, detail="share link invalid or expired")
    if _wants_html(request):
        return RedirectResponse(f"/scan.html?share={token}", status_code=302)
    report = state.db.get_report(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="report not ready")
    report = sanitize_report(report)
    exp = share_expiry(token)
    return JSONResponse(
        report,
        headers={"X-Share-Expires": datetime.fromtimestamp(exp, UTC).isoformat() if exp else ""},
    )


@app.get("/share/{token}/certificate")
async def shared_certificate_html(
    token: str, request: Request, state: AppState = Depends(get_state)
) -> HTMLResponse:
    return HTMLResponse(await _certificate_html_for_share(token, state, _base_url(request)))


@app.get("/share/{token}/certificate.pdf")
async def shared_certificate_pdf(
    token: str, request: Request, state: AppState = Depends(get_state)
) -> Response:
    scan_id = verify_share(token)
    if not scan_id:
        raise HTTPException(status_code=404, detail="share link invalid or expired")
    cert = await _certificate_model(
        state, scan_id, token=None, via_share=True, base_url=_base_url(request)
    )
    pdf = render_pdf(cert)
    state.db.seal_certificate(scan_id, cert["report_sha256"], pdf_hash(pdf))
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="toolpain-{scan_id}.pdf"'},
    )


@app.get("/api/compare")
def compare_scans(
    a: str,
    b: str,
    state: AppState = Depends(get_state),
    x_api_token: str | None = Header(default=None, alias="X-Api-Token"),
) -> dict[str, Any]:
    left = state.db.get_report(a)
    right = state.db.get_report(b)
    if not left or not right:
        raise HTTPException(status_code=404, detail="both reports must exist")
    if not _compare_allowed(state, a, b, x_api_token):
        raise HTTPException(status_code=403, detail="report is private")
    return compare_reports(left, right)


@app.post("/api/tokens")
def issue_token(
    body: dict[str, Any],
    state: AppState = Depends(get_state),
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
) -> dict[str, Any]:
    expected = os.environ.get("TOOLPAIN_ADMIN_TOKEN") or "toolpain-dev-admin"
    if x_admin_token != expected:
        raise HTTPException(status_code=401, detail="admin token required")
    token = secrets.token_urlsafe(24)
    label = str(body.get("label") or "token")[:80]
    if "quota" in body and body.get("quota") is not None:
        try:
            quota = int(body.get("quota"))
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="quota") from exc
        if quota < 0:
            raise HTTPException(status_code=422, detail="quota")
    else:
        quota = 20
    state.db.issue_api_token(token, label, quota)
    return {"token": token, "label": label, "quota": quota}


@app.post("/api/scans/{scan_id}/cancel", status_code=202)
async def cancel_scan(scan_id: str, state: AppState = Depends(get_state)) -> dict[str, str]:
    scan = state.db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    if scan.status in TERMINAL_STATUSES:
        return {"status": scan.status}
    await state.provisioner.cancel_scan(scan_id)
    state.db.update_scan(
        scan_id, status="cancelled", error_code="cancelled", error_detail="cancelled"
    )
    return {"status": "cancelled"}


@app.get("/internal/scans/{scan_id}/runner-sync.tgz")
def runner_sync_tarball(
    scan_id: str,
    _: str = Depends(require_scan_token),
    state: AppState = Depends(get_state),
) -> Response:
    """Ship CP ``runner/`` + ``sandbox/`` Python to scanners (avoids rebake for hotfixes)."""
    if not state.db.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="scan not found")

    root = Path(__file__).resolve().parents[1]
    packages = [root / "runner", root / "sandbox"]
    if not (root / "runner").is_dir():
        raise HTTPException(status_code=404, detail="runner package missing")
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for pkg in packages:
            if not pkg.is_dir():
                continue
            for path in sorted(pkg.rglob("*.py")):
                if "__pycache__" in path.parts:
                    continue
                tar.add(path, arcname=str(path.relative_to(root)))
    return Response(
        content=buf.getvalue(),
        media_type="application/gzip",
        headers={"Content-Disposition": "attachment; filename=runner-sync.tgz"},
    )


@app.post("/internal/scans/{scan_id}/events", status_code=201)
def internal_event(
    scan_id: str,
    body: EventIn,
    _: str = Depends(require_scan_token),
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    scan = state.db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    ev = state.emit_event(scan_id, body.stage, body.level, body.msg, body.data)
    # Failure/destroy without a success report must leave ``running`` so SSE ``done`` fires.
    if scan.status not in TERMINAL_STATUSES:
        finish = terminal_update_from_event(stage=body.stage, msg=body.msg, data=body.data)
        if finish:
            state.update_scan(scan_id, **finish)
    return {"id": ev.id}


@app.post("/internal/scans/{scan_id}/report", status_code=201)
def internal_report(
    scan_id: str,
    body: dict[str, Any],
    _: str = Depends(require_scan_token),
    state: AppState = Depends(get_state),
) -> dict[str, str]:
    scan = state.db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    if scan.status in TERMINAL_STATUSES:
        raise HTTPException(status_code=409, detail="scan is already finished")
    try:
        report = Report.model_validate(body)
    except ValidationError as exc:
        state.emit_event(
            scan_id,
            "report",
            "warn",
            "Report failed validation",
            {"code": "report_invalid", "error": "report_invalid"},
        )
        state.update_scan(
            scan_id,
            status="failed",
            error_code="report_invalid",
            error_detail="report_invalid",
        )
        raise HTTPException(status_code=422, detail=exc.errors()) from exc
    payload = report.model_dump()
    state.save_report(scan_id, payload)
    state.update_scan(
        scan_id,
        status="done",
        verdict=payload.get("verdict"),
        findings_count=len(payload.get("findings") or []),
    )
    return {"status": "ok"}


@app.post("/internal/llm/chat")
async def internal_llm(
    body: dict[str, Any],
    x_scan_token: str | None = Header(default=None, alias="X-Scan-Token"),
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    # Token must match some active scan
    if not x_scan_token:
        raise HTTPException(status_code=401, detail="invalid scan token")
    scan_id = state.db.scan_id_for_token(x_scan_token)
    if not scan_id:
        raise HTTPException(status_code=401, detail="invalid scan token")
    if state.settings.llm_mode in {"fixture", "off"}:
        raise HTTPException(
            status_code=503,
            detail="control plane LLM_MODE is fixture; scanners require live (or ollama locally)",
        )
    kind_hint = str(body.get("kind") or body.get("schema_hint") or "")
    state.db.record_llm_call(scan_id, "research" if "research" in kind_hint else "codegen")
    try:
        return await chat_json(
            state.settings,
            body.get("messages") or [],
            schema_hint=body.get("schema_hint"),
        )
    except RuntimeError as exc:
        # Missing inference key / unresolved backend — surface as 503, not an uncaught 500.
        raise HTTPException(status_code=503, detail=str(exc)) from exc


def _failure_from_events(state: AppState, scan_id: str) -> tuple[str | None, str | None]:
    """Last classified failure on a scan, if the runner recorded one."""
    error = None
    detail = None
    for ev in reversed(state.db.list_events(scan_id)):
        data = ev.data or {}
        if data.get("error"):
            return str(data["error"]), ev.msg
        if ev.level == "alert" and ev.msg.lower().startswith("scan failed"):
            detail = ev.msg
    return error, detail


def _seed_demos(state: AppState) -> None:
    """Seed three demo scans with reports if DB is empty."""
    if state.db.list_scans(limit=1):
        return
    for demo_key, meta in DEMO_REPOS.items():
        scan_id = f"demo_{demo_key.replace('-', '_')[:12]}"
        token = secrets.token_urlsafe(16)
        state.db.create_scan(
            scan_id,
            meta["repo_url"],
            meta.get("ref", "main"),
            token,
            account_mode="toolpain",
            demo=demo_key,
        )
        report = report_for_demo(demo_key, scan_id, meta["repo_url"])
        state.db.set_estimate(scan_id, build_estimate(meta["repo_url"], "local"))
        state.save_report(scan_id, report)
        state.update_scan(
            scan_id,
            status="done",
            verdict=report["verdict"],
            findings_count=len(report.get("findings", [])),
        )


def _compare_allowed(state: AppState, a: str, b: str, token: str | None) -> bool:
    owner_a = state.db.owner_of(a)
    owner_b = state.db.owner_of(b)
    if not owner_a and not owner_b:
        return True
    if owner_a and owner_b and owner_a == owner_b:
        return state.db.hash_token(token or "") == owner_a
    return False


def _can_read(state: AppState, scan_id: str, token: str | None) -> bool:
    owner = state.db.owner_of(scan_id)
    if not owner:
        return True
    return state.db.hash_token(token or "") == owner


def _base_url(request: Request) -> str:
    return str(request.base_url).rstrip("/")


def _require_admin(token: str | None) -> None:
    expected = os.environ.get("TOOLPAIN_ADMIN_TOKEN") or "toolpain-dev-admin"
    if not token or token != expected:
        raise HTTPException(status_code=403, detail="admin token required")


async def _certificate_model(
    state: AppState,
    scan_id: str,
    token: str | None,
    *,
    via_share: bool,
    base_url: str,
) -> dict[str, Any]:
    scan = state.db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    if not via_share and not _can_read(state, scan_id, token):
        raise HTTPException(status_code=403, detail="private report")
    if scan.status != "done":
        raise HTTPException(
            status_code=409, detail="certificate is available when the scan is done"
        )
    sealed = state.db.get_report(scan_id)
    if not sealed:
        raise HTTPException(status_code=404, detail="report not ready")
    # LLM narrative is generated from the deflated view; seal hash stays on disk bytes.
    view = sanitize_report(sealed)
    view = await ensure_report_narrative(state.settings, view)
    share, _exp = sign_share(scan_id, ttl_sec=VERIFY_TTL_SEC)
    cert = build_certificate(
        scan.id,
        repo_url=scan.repo_url,
        ref=scan.ref,
        created_at=scan.created_at,
        updated_at=scan.updated_at,
        account_mode=scan.account_mode,
        report=view,
        seal_report=sealed,
        ticket=scan.ticket,
        scanned_by=scan.token_label or scan.account_mode,
        verify_url=f"{base_url}/verify/{share}",
    )
    state.db.seal_certificate(scan_id, cert["report_sha256"])
    return cert


async def _certificate_html_for_share(token: str, state: AppState, base_url: str) -> str:
    scan_id = verify_share(token)
    if not scan_id:
        raise HTTPException(status_code=404, detail="share link invalid or expired")
    return render_html(
        await _certificate_model(state, scan_id, None, via_share=True, base_url=base_url)
    )


@app.post("/api/estimate")
def estimate(body: dict[str, Any]) -> dict[str, Any]:
    raw = str(body.get("repo_url") or "")
    try:
        created = ScanCreate(repo_url=raw, ref=str(body.get("ref") or "main"))
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc
    provisioner = "vultr" if str(body.get("provisioner") or "") == "vultr" else "local"
    return build_estimate(created.repo_url, provisioner)


@app.get("/api/scans/{scan_id}/certificate")
async def certificate_html(
    scan_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    x_api_token: str | None = Header(default=None, alias="X-Api-Token"),
) -> HTMLResponse:
    cert = await _certificate_model(
        state, scan_id, x_api_token, via_share=False, base_url=_base_url(request)
    )
    return HTMLResponse(render_html(cert))


@app.get("/api/scans/{scan_id}/certificate.pdf")
async def certificate_pdf(
    scan_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    x_api_token: str | None = Header(default=None, alias="X-Api-Token"),
) -> Response:
    cert = await _certificate_model(
        state, scan_id, x_api_token, via_share=False, base_url=_base_url(request)
    )
    pdf = render_pdf(cert)
    state.db.seal_certificate(scan_id, cert["report_sha256"], pdf_hash(pdf))
    return Response(
        content=pdf,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="toolpain-{scan_id}.pdf"'},
    )


@app.post("/api/scans/{scan_id}/verify-link")
def verify_link(
    scan_id: str,
    request: Request,
    state: AppState = Depends(get_state),
    x_api_token: str | None = Header(default=None, alias="X-Api-Token"),
) -> dict[str, Any]:
    scan = state.db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    if not _can_read(state, scan_id, x_api_token):
        raise HTTPException(status_code=403, detail="private report")
    token, exp = sign_share(scan_id, ttl_sec=VERIFY_TTL_SEC)
    url = f"{_base_url(request)}/verify/{token}"
    report = state.db.get_report(scan_id)
    if scan.status == "done" and report:
        digest = report_hash(report)
        note = ticket_note(scan, report, verify_url=url, report_sha256=digest)
    else:
        events = state.db.list_events(scan_id)
        stage = next(
            (
                ev.stage
                for ev in reversed(events)
                if (ev.data or {}).get("code") or (ev.data or {}).get("error")
            ),
            None,
        )
        digest = ""
        note = failure_note(scan, stage=str(stage) if stage else None, detail=scan.error_detail)
    return {"token": token, "expires_at": exp, "url": url, "note": note, "report_sha256": digest}


@app.get("/api/scans/{scan_id}/diagnostics")
def scan_diagnostics(
    scan_id: str,
    state: AppState = Depends(get_state),
    x_api_token: str | None = Header(default=None, alias="X-Api-Token"),
) -> dict[str, Any]:
    scan = state.db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    if not _can_read(state, scan_id, x_api_token):
        raise HTTPException(status_code=403, detail="private report")
    return build_diagnostics(
        scan,
        state.db.list_events(scan_id),
        state.db.get_report(scan_id),
        state.db.llm_call_counts(scan_id),
    )


@app.get("/api/scans/{scan_id}/debug.zip")
def scan_debug_bundle(
    scan_id: str,
    state: AppState = Depends(get_state),
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
) -> Response:
    _require_admin(x_admin_token)
    scan = state.db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    events = state.db.list_events(scan_id)
    report = state.db.get_report(scan_id)
    diagnostics = build_diagnostics(scan, events, report, state.db.llm_call_counts(scan_id))
    body = debug_bundle(scan, events, report, diagnostics)
    return Response(
        content=body,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="toolpain-{scan_id}-debug.zip"'},
    )


def _system_payload(state: AppState) -> dict[str, Any]:
    counts = state.db.status_counts()
    since = (datetime.now(UTC) - timedelta(hours=24)).isoformat()
    return {
        "version": PRODUCT_VERSION,
        "commit": os.environ.get("TOOLPAIN_COMMIT") or "unknown",
        "provisioner": state.settings.provisioner,
        "runtime": detect().as_dict(),
        "llm_mode": state.settings.llm_mode,
        "codegen_mode": (os.environ.get("CODEGEN_MODE") or "llm").lower(),
        "codegen_model": state.settings.codegen_model,
        "queue_depth": counts.get("queued", 0),
        "running": counts.get("running", 0),
        "reaper_last_run": None,
        "failed_24h": state.db.failed_since(since),
        "scans_by_status": counts,
        "error_codes": sorted(FAILURE_CODES),
    }


@app.get("/api/system")
def system_status(
    state: AppState = Depends(get_state),
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
) -> dict[str, Any]:
    _require_admin(x_admin_token)
    return _system_payload(state)


@app.get("/metrics")
def metrics(
    state: AppState = Depends(get_state),
    x_admin_token: str | None = Header(default=None, alias="X-Admin-Token"),
) -> Response:
    _require_admin(x_admin_token)
    lines = [
        f'toolpain_scans{{status="{status}"}} {count}'
        for status, count in sorted(state.db.status_counts().items())
    ]
    return Response("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


@app.api_route("/verify/{token}", methods=["GET", "POST"])
async def verify_page(
    token: str, request: Request, state: AppState = Depends(get_state)
) -> HTMLResponse:
    scan_id = verify_share(token)
    if not scan_id:
        raise HTTPException(status_code=404, detail="share link invalid or expired")
    scan = state.db.get_scan(scan_id)
    report = state.db.get_report(scan_id) if scan else None
    if not scan or scan.status != "done" or not report:
        raise HTTPException(status_code=404, detail="report not ready")
    current = report_hash(report)
    sealed, pdf_sealed = state.db.certificate_seal(scan_id)
    if not sealed:
        state.db.seal_certificate(scan_id, current)
        sealed = current
    report_ok = sealed == current
    pdf_message = ""
    pdf_ok = True
    pdf_checked = False
    if request.method == "POST":
        form = await request.form()
        upload = form.get("pdf")
        pdf_checked = True
        if upload is None or not hasattr(upload, "read"):
            pdf_message = "No PDF was uploaded"
            pdf_ok = False
        else:
            data = await upload.read()
            digest = pdf_hash(data)
            if not pdf_sealed:
                pdf_message = "No certificate file is on record yet"
                pdf_ok = False
            elif digest == pdf_sealed:
                pdf_message = "Uploaded PDF matches the certificate"
                pdf_ok = True
            else:
                pdf_message = "Uploaded PDF does not match the certificate"
                pdf_ok = False
    parts = ["Matches the stored report" if report_ok else "Does not match the stored report"]
    if pdf_message:
        parts.append(pdf_message)
    exp = share_expiry(token)
    if exp:
        parts.append(f"Link expires {datetime.fromtimestamp(exp, UTC).date().isoformat()}")
    cert = await _certificate_model(
        state, scan_id, None, via_share=True, base_url=_base_url(request)
    )
    html = render_html(
        cert,
        banner=". ".join(parts),
        banner_ok=report_ok and (pdf_ok if pdf_checked else True),
    )
    form_html = (
        '<form class="sheet" method="post" enctype="multipart/form-data">'
        "<h2>Check a PDF from the ticket</h2>"
        '<input type="file" name="pdf" accept="application/pdf" required>'
        '<button type="submit">Check PDF</button></form>'
    )
    return HTMLResponse(html.replace("</article>", "</article>" + form_html))


# Static web UI
if WEB.exists():
    app.mount("/assets", StaticFiles(directory=WEB), name="assets")


def _web_or_design(name: str) -> FileResponse:
    path = WEB / name
    if not path.exists():
        return FileResponse(ROOT / "design" / name)
    return FileResponse(path)


@app.get("/")
@app.get("/index.html")
def index() -> FileResponse:
    return _web_or_design("index.html")


@app.get("/scan.html")
def scan_page() -> FileResponse:
    return _web_or_design("scan.html")


@app.get("/style.css")
def style() -> FileResponse:
    return _web_or_design("style.css")


@app.get("/system.html")
def system_page() -> FileResponse:
    return _web_or_design("system.html")


@app.get("/app.js")
def app_js() -> FileResponse:
    return _web_or_design("app.js")


@app.get("/favicon.svg")
def favicon() -> FileResponse:
    return _web_or_design("favicon.svg")


@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": exc.errors()})


def main() -> None:
    if len(sys.argv) > 1 and sys.argv[1] == "scan":
        scan_main(sys.argv[2:])
        return
    import uvicorn

    uvicorn.run(
        "control_plane.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
    )


if __name__ == "__main__":
    main()
