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

    @field_validator("repo_url")
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not GITHUB_URL_RE.match(v):
            raise ValueError("repo_url must be https://github.com/<owner>/<repo>")
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
