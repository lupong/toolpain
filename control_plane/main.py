"""FastAPI control plane: public API, SSE, static web/, internal runner callbacks."""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ValidationError
from sse_starlette.sse import EventSourceResponse
from starlette.middleware.base import BaseHTTPMiddleware

from control_plane.config import get_settings
from control_plane.db import Database
from control_plane.models import EventIn, Report, ScanCreate, ScanSummary
from control_plane.provisioner import get_provisioner
from control_plane.redaction import install_redaction, redact_text
from control_plane.sample_report import DEMO_REPOS, sample_report

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
        self.provisioner = get_provisioner(
            self.settings.provisioner,
            emit_event=self.emit_event,
            save_report=self.save_report,
            update_scan=self.update_scan,
            api_key=self.settings.vultr_api_key,
            control_plane_url=self.settings.control_plane_url,
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
        event = self.db.add_event(scan_id, stage, level, safe_msg, safe_data)
        payload = event.model_dump(mode="json")
        for q in list(self.subscribers.get(scan_id, [])):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass
        return event

    def save_report(self, scan_id: str, report: Report | dict[str, Any]) -> None:
        self.db.save_report(scan_id, report, self.settings.reports_dir)

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
    log.info(
        "ToolPain control plane starting provisioner=%s llm=%s",
        STATE.settings.provisioner,
        STATE.settings.llm_mode,
    )
    _seed_demos(STATE)
    yield


app = FastAPI(title="ToolPain", version="0.1.0", lifespan=lifespan)
app.add_middleware(RateLimitMiddleware, limit=20, window_sec=60)


@app.get("/api/health")
def health(state: AppState = Depends(get_state)) -> dict[str, Any]:
    from control_plane.env_detect import detect

    return {"ok": True, "env": detect().as_dict(), "provisioner": state.settings.provisioner}


@app.post("/api/scans", response_model=ScanSummary, status_code=201)
async def create_scan(
    body: ScanCreate,
    state: AppState = Depends(get_state),
) -> ScanSummary:
    demo = body.demo
    repo_url = body.repo_url
    ref = body.ref or "main"
    if demo and demo in DEMO_REPOS:
        repo_url = DEMO_REPOS[demo]["repo_url"]
        ref = DEMO_REPOS[demo].get("ref", ref)

    scan_id = f"s_{uuid.uuid4().hex[:8]}"
    token = secrets.token_urlsafe(24)
    account_mode = "byo" if body.byo_vultr_key else "toolpain"
    summary = state.db.create_scan(
        scan_id, repo_url, ref, token, account_mode=account_mode, demo=demo
    )
    state.emit_event(scan_id, "intake", "info", f"Accepted scan for {repo_url}@{ref}")
    await state.provisioner.start_scan(
        scan_id,
        repo_url,
        ref,
        token,
        byo_vultr_key=body.byo_vultr_key,
        demo=demo,
    )
    return summary


@app.get("/api/scans", response_model=list[ScanSummary])
def list_scans(state: AppState = Depends(get_state)) -> list[ScanSummary]:
    return state.db.list_scans()


@app.get("/api/scans/{scan_id}", response_model=ScanSummary)
def get_scan(scan_id: str, state: AppState = Depends(get_state)) -> ScanSummary:
    scan = state.db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan


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
                        yield {
                            "event": "done",
                            "data": __import__("json").dumps(
                                {"status": scan.status, "verdict": scan.verdict}
                            ),
                        }
                        break
                    yield {"event": "ping", "data": "{}"}
        finally:
            subs = state.subscribers.get(scan_id, [])
            if queue in subs:
                subs.remove(queue)

    return EventSourceResponse(gen())


@app.get("/api/scans/{scan_id}/report")
def get_report(scan_id: str, state: AppState = Depends(get_state)) -> dict[str, Any]:
    if not state.db.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="scan not found")
    report = state.db.get_report(scan_id)
    if not report:
        raise HTTPException(status_code=404, detail="report not ready")
    return report


@app.post("/api/scans/{scan_id}/cancel", status_code=202)
async def cancel_scan(scan_id: str, state: AppState = Depends(get_state)) -> dict[str, str]:
    if not state.db.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="scan not found")
    await state.provisioner.cancel_scan(scan_id)
    state.db.update_scan(scan_id, status="cancelled")
    return {"status": "cancelled"}


@app.post("/internal/scans/{scan_id}/events", status_code=201)
def internal_event(
    scan_id: str,
    body: EventIn,
    _: str = Depends(require_scan_token),
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    if not state.db.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="scan not found")
    ev = state.emit_event(scan_id, body.stage, body.level, body.msg, body.data)
    return {"id": ev.id}


@app.post("/internal/scans/{scan_id}/report", status_code=201)
def internal_report(
    scan_id: str,
    body: dict[str, Any],
    _: str = Depends(require_scan_token),
    state: AppState = Depends(get_state),
) -> dict[str, str]:
    if not state.db.get_scan(scan_id):
        raise HTTPException(status_code=404, detail="scan not found")
    try:
        report = Report.model_validate(body)
        payload = report.model_dump()
    except ValidationError:
        payload = body
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
    # Accept any known token
    known = False
    for s in state.db.list_scans(limit=200):
        if state.db.get_token(s.id) == x_scan_token:
            known = True
            break
    if not known:
        raise HTTPException(status_code=401, detail="invalid scan token")
    from control_plane.llm import chat_json

    return await chat_json(
        state.settings,
        body.get("messages") or [],
        schema_hint=body.get("schema_hint"),
    )


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
        report = sample_report(scan_id, meta["repo_url"])
        if demo_key == "server-filesystem":
            report["verdict"] = "clean"
            report["findings"] = []
            report["stats"]["decoy_reads"] = 0
            report["stats"]["egress_attempted"] = 0
            report["tools"] = [t for t in report["tools"] if t["name"] != "fetch_report"]
            report["toxic_combos"] = []
        elif demo_key == "playwright-mcp":
            report["verdict"] = "over_privileged"
            report["findings"] = [f for f in report["findings"] if f["id"] != "F1"]
            report["stats"]["decoy_reads"] = 0
            for t in report["tools"]:
                if t["name"] == "fetch_report":
                    t["verdict"] = "exceeds_claim"
                    t["decoy_reads"] = 0
        state.save_report(scan_id, report)
        state.update_scan(
            scan_id,
            status="done",
            verdict=report["verdict"],
            findings_count=len(report.get("findings", [])),
        )


# Static web UI
if WEB.exists():
    app.mount("/assets", StaticFiles(directory=WEB), name="assets")


@app.get("/")
def index() -> FileResponse:
    path = WEB / "index.html"
    if not path.exists():
        return FileResponse(ROOT / "design" / "index.html")
    return FileResponse(path)


@app.get("/scan.html")
def scan_page() -> FileResponse:
    path = WEB / "scan.html"
    if not path.exists():
        return FileResponse(ROOT / "design" / "scan.html")
    return FileResponse(path)


@app.get("/style.css")
def style() -> FileResponse:
    path = WEB / "style.css"
    if not path.exists():
        return FileResponse(ROOT / "design" / "style.css")
    return FileResponse(path)


@app.get("/app.js")
def app_js() -> FileResponse:
    path = WEB / "app.js"
    if not path.exists():
        return FileResponse(ROOT / "design" / "app.js")
    return FileResponse(path)


@app.exception_handler(ValidationError)
async def validation_exception_handler(request: Request, exc: ValidationError) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": exc.errors()})


def main() -> None:
    import uvicorn

    uvicorn.run(
        "control_plane.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
    )


if __name__ == "__main__":
    main()
