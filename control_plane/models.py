"""Pydantic models for scans, events, and reports."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

GITHUB_URL_RE = re.compile(
    r"^https://github\.com/(?P<owner>[A-Za-z0-9_.-]+)/(?P<repo>[A-Za-z0-9_.-]+)/?$"
)

StageName = Literal[
    "intake",
    "provision",
    "fetch",
    "build",
    "isolate",
    "discover",
    "research",
    "probe",
    "analyze",
    "report",
    "destroy",
]

ScanStatus = Literal["queued", "running", "done", "failed", "cancelled", "timeout"]
AccountMode = Literal["toolpain", "byo"]
OverallVerdict = Literal["clean", "over_privileged", "suspicious", "flagged"]
ToolVerdict = Literal["confirmed", "exceeds_claim", "not_observed", "flagged"]
Severity = Literal["critical", "high", "medium", "low", "info"]


class ScanCreate(BaseModel):
    repo_url: str
    ref: str = "main"
    byo_vultr_key: str | None = None
    demo: str | None = None  # server-filesystem | playwright-mcp | decoy-trap-server
    prefer_subdir: str | None = None  # monorepo package path, e.g. src/time
    scan_brief: str | None = None  # optional user intent for executable codegen
    protocol: Literal["auto", "stdio", "http", "sse"] = "auto"
    upstream_url: str | None = None
    mcp_url: str | None = None  # existing HTTP/SSE MCP endpoint (no host egress beyond this URL)

    @field_validator("repo_url")
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not GITHUB_URL_RE.match(v):
            raise ValueError("repo_url must be https://github.com/<owner>/<repo>")
        return v

    @field_validator("prefer_subdir")
    @classmethod
    def validate_prefer_subdir(cls, v: str | None) -> str | None:
        if v is None:
            return None
        v = v.strip().strip("/")
        if not v or ".." in v or v.startswith("/") or "\\" in v:
            raise ValueError("prefer_subdir must be a relative path without ..")
        return v

    @field_validator("scan_brief")
    @classmethod
    def validate_scan_brief(cls, v: str | None) -> str | None:
        if v is None:
            return None
        text = "".join(ch for ch in v if ord(ch) >= 32 or ch in "\n\t").strip()
        if not text:
            return None
        return text[:2000]

    @field_validator("upstream_url")
    @classmethod
    def validate_upstream(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        v = str(v).strip().rstrip("/")
        if not GITHUB_URL_RE.match(v):
            raise ValueError("upstream_url must be https://github.com/<owner>/<repo>")
        return v

    @field_validator("mcp_url")
    @classmethod
    def validate_mcp_url(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        v = str(v).strip()
        if not v.startswith(("http://127.0.0.1", "http://localhost", "https://")):
            raise ValueError("mcp_url must be localhost or https")
        return v


class ScanSummary(BaseModel):
    id: str
    repo_url: str
    ref: str
    status: ScanStatus
    account_mode: AccountMode
    created_at: datetime
    updated_at: datetime
    verdict: OverallVerdict | None = None
    findings_count: int = 0
    demo: str | None = None


class EventIn(BaseModel):
    stage: StageName | str
    level: Literal["info", "warn", "alert"] = "info"
    msg: str
    ts: datetime | None = None
    data: dict[str, Any] = Field(default_factory=dict)


class EventOut(EventIn):
    id: int
    scan_id: str


class ToolReport(BaseModel):
    name: str
    privilege: str
    verdict: ToolVerdict
    sources: list[str] = Field(default_factory=list)
    egress: list[str] = Field(default_factory=list)
    decoy_reads: int = 0
    claimed: str | None = None
    observed: dict[str, Any] = Field(default_factory=dict)
    evidence: list[str] = Field(default_factory=list)
    downstream: list[str] = Field(default_factory=list)


class ToxicCombo(BaseModel):
    tools: list[str]
    risk: str
    severity: Severity
    why: str | None = None


class Finding(BaseModel):
    id: str
    severity: Severity
    type: str
    tool: str | None = None
    title: str
    evidence: str | None = None
    recommendation: str | None = None
    explanation: str | None = None


class ForkDrift(BaseModel):
    change: str
    tool: str
    file: str | None = None


class EgressAttempt(BaseModel):
    host: str
    tool: str
    blocked: bool = True


class Report(BaseModel):
    scan_id: str
    repo: dict[str, Any]
    verdict: OverallVerdict
    stats: dict[str, Any]
    tools: list[ToolReport]
    toxic_combos: list[ToxicCombo] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    egress: dict[str, Any] = Field(default_factory=dict)
    least_privilege_config: dict[str, Any] = Field(default_factory=dict)
    ingress: list[dict[str, Any]] = Field(default_factory=list)
    graph: dict[str, Any] | None = None
    harness: dict[str, Any] | None = None
    # v2 executable-codegen / operator fields (optional)
    scan_brief: str | None = None
    launch: dict[str, Any] | None = None
    recipe: dict[str, Any] | None = None
    llm_oracle: list[dict[str, Any]] | None = None
    expectations: list[dict[str, Any]] | None = None
    artifacts: dict[str, Any] | None = None
    costs: dict[str, Any] | None = None
    transport: dict[str, Any] | None = None
    upstream: dict[str, Any] | None = None
    cache: dict[str, Any] | None = None
    runtime: str | None = None
