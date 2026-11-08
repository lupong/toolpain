"""Pydantic models for scans, events, and reports."""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime
from typing import Any, Literal
from urllib.parse import urlparse

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


class IntakeInspectRequest(BaseModel):
    repo_url: str
    ref: str = "main"

    @field_validator("repo_url")
    @classmethod
    def validate_github_url(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not GITHUB_URL_RE.match(v):
            raise ValueError("repo_url must be https://github.com/<owner>/<repo>")
        return v


class IntakeInspectResponse(BaseModel):
    repo_url: str
    ref: str
    multi: bool
    count: int
    candidates: list[str]
    message: str | None = None


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
    ticket: str | None = None  # ITSM ticket id, printed on the certificate
    # Opt-in per scan. Off by default — create a fresh VM unless the user asks for pool.
    use_pool: bool = False

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
        """Allow localhost HTTP, or HTTPS that is not a private, link-local, or metadata host.

        Userinfo is rejected. Raw IPs in private, loopback, link-local, reserved, or
        multicast ranges are rejected. Hostnames that are cloud metadata names are
        rejected. Other HTTPS hostnames are accepted without a DNS lookup so intake
        does not depend on the network.
        """
        if v is None or not str(v).strip():
            return None
        v = str(v).strip()
        parsed = urlparse(v)
        if parsed.username or parsed.password:
            raise ValueError("mcp_url must not include userinfo")
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme == "http" and host in {"127.0.0.1", "localhost"}:
            return v
        if parsed.scheme != "https" or not host:
            raise ValueError("mcp_url must be http://127.0.0.1, http://localhost, or https")
        if host in {"169.254.169.254", "metadata.google.internal"} or host.endswith(
            ".metadata.internal"
        ):
            raise ValueError("mcp_url host is not allowed")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return v
        if (
            ip.is_private
            or ip.is_link_local
            or ip.is_loopback
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            raise ValueError("mcp_url must not be a private or link-local address")
        return v

    @field_validator("ticket")
    @classmethod
    def validate_ticket(cls, v: str | None) -> str | None:
        if v is None or not str(v).strip():
            return None
        text = "".join(ch for ch in str(v) if ch.isalnum() or ch in "-_").strip()
        if not text:
            return None
        return text[:64]


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
    error_code: str | None = None
    error_detail: str | None = None
    ticket: str | None = None
    token_label: str | None = None


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


class ReportError(BaseModel):
    code: str
    detail: str | None = None


class Report(BaseModel):
    scan_id: str
    repo: dict[str, Any]
    verdict: OverallVerdict
    stats: dict[str, Any]
    tools: list[ToolReport]
    coverage: Literal["full", "list_only"] | None = None
    partial: bool = False
    error: ReportError | None = None
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
    # LLM-written certificate copy (business use case + ranked next steps)
    certificate: dict[str, Any] | None = None
