"""Privilege tiering (docs/ARCHITECTURE.md section 4.3).

Capabilities come from two places:

* **claimed**  - what the tool's name / description / schema say it does;
* **observed** - what the probe trace and sinkhole actually saw.

The tier is computed from the union, so a tool that quietly does more than it claims is tiered
by what it really does.
"""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, Field

from runner.analyze.egress import host_is_declared
from runner.models import DiscoveredTool
from runner.probe import ProbeResult
from runner.research import ToolProfile

Tier = Literal["critical", "high", "medium", "low", "info"]
TIER_ORDER: list[Tier] = ["critical", "high", "medium", "low", "info"]

CODE_EXEC_RE = re.compile(
    r"\b(eval|evaluate|exec|execute|run_?code|run_?script|javascript)\b", re.I
)
SHELL_RE = re.compile(
    r"\b(shell|bash|subprocess|spawn|terminal|run_?command|shell_?command)\b",
    re.I,
)
WRITE_RE = re.compile(
    r"\b(write|save|create_?file|edit_?file|append|delete|remove|move|rename|mkdir)\b", re.I
)
READ_RE = re.compile(r"\b(read|cat|open_?file|get_?file|load|list_?dir\w*|search_?files)\b", re.I)
NETWORK_RE = re.compile(
    r"\b(fetch|http|https|download|navigate|request|browse|web|curl|post|webhook|"
    r"send|upload|github|gitlab|bitbucket|remote)\b",
    re.I,
)
BROWSER_RE = re.compile(
    r"\b(browser|playwright|puppeteer|click|page|snapshot|screenshot)\b|^browser_", re.I
)
UPLOAD_RE = re.compile(r"upload", re.I)
MEDIA_RE = re.compile(r"(pdf|screenshot|snapshot)", re.I)
SCOPED_RE = re.compile(
    r"(within|allowed director|workspace|sandbox|restricted|only (in|under))", re.I
)
PATH_PROP_RE = re.compile(r"(path|file|filename|directory|dir|destination)$", re.I)
INFO_RE = re.compile(
    r"^(get_?)?(version|status|time|current_time|ping|echo|help|info|list_\w+|add|sum|"
    r"reverse\w*|word_?count|count\w*|health)$",
    re.I,
)


class PrivilegeAssessment(BaseModel):
    tool: str
    tier: Tier
    claimed: list[str] = Field(default_factory=list)
    observed: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    exceeds: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)


def claimed_capabilities(tool: DiscoveredTool) -> set[str]:
    """Capabilities implied by the tool's own name, description, and input schema."""
    text = f"{tool.name.replace('_', ' ')} {tool.name} {tool.description}"
    props = (tool.input_schema or {}).get("properties", {}) or {}
    has_path = any(PATH_PROP_RE.search(k) for k in props)
    has_url = any(re.search(r"(url|uri|href)$", k, re.I) for k in props)
    scoped = bool(SCOPED_RE.search(tool.description))
    # GitHub/GitLab-style API tools mutate remote repos, not the local disk.
    remote_api = bool(NETWORK_RE.search(text))
    caps: set[str] = set()
    if CODE_EXEC_RE.search(text):
        caps.add("code_exec")
    if SHELL_RE.search(text):
        caps.add("shell")
    if UPLOAD_RE.search(tool.name):
        caps.update({"upload", "network"})
    if MEDIA_RE.search(tool.name) and WRITE_RE.search(text):
        caps.add("media_save")
    elif WRITE_RE.search(text) and has_path and not remote_api:
        caps.add("file_write_scoped" if scoped else "file_write")
    if READ_RE.search(text) and has_path and not remote_api:
        caps.add("file_read_scoped" if scoped else "file_read")
    if remote_api or has_url:
        caps.add("network")
    if BROWSER_RE.search(text):
        caps.add("browser")
    return caps


def observed_capabilities(probe: ProbeResult | None) -> set[str]:
    caps: set[str] = set()
    if probe is None:
        return caps
    if probe.decoy_reads or probe.decoy_in_sinkhole:
        caps.add("credential_read")
    if any(not p.startswith("/workspace/canaries") for p in probe.files_read):
        caps.add("file_read")
    if probe.files_written:
        caps.add("file_write")
    if probe.processes:
        caps.add("subprocess")
        if any(re.search(r"(^|/)(ba|da|z)?sh\b", p) for p in probe.processes):
            caps.add("shell")
    if probe.egress_hosts:
        caps.add("network")
    return caps


def _tier(caps: set[str], tool: DiscoveredTool, reasons: list[str]) -> Tier:
    def hit(reason: str) -> bool:
        reasons.append(reason)
        return True

    if "code_exec" in caps and hit("code execution / eval"):
        return "critical"
    if "file_write" in caps and hit("arbitrary file write"):
        return "critical"
    if "credential_read" in caps and hit("read a planted decoy credential"):
        return "critical"
    if {"network", "file_read"} <= caps and hit("unrestricted network plus file read"):
        return "critical"
    if "shell" in caps and hit("subprocess spawn with shell"):
        return "critical"
    if "subprocess" in caps and hit("spawns subprocesses"):
        return "high"
    if "file_read" in caps and hit("arbitrary file read"):
        return "high"
    if {"browser", "network"} <= caps and "upload" in caps and hit("browser navigate plus upload"):
        return "high"
    if "upload" in caps and hit("file upload"):
        return "high"
    if "network" in caps and hit("network egress"):
        return "high"
    if "file_read_scoped" in caps and hit("scoped file read"):
        return "medium"
    if "file_write_scoped" in caps and hit("scoped file write"):
        return "medium"
    if "media_save" in caps and hit("saves PDF/screenshot artifacts"):
        return "medium"
    if INFO_RE.match(tool.name) and hit("pure metadata / compute, no side effects"):
        return "info"
    reasons.append("no file, network, or exec capability")
    return "low"


def assess_privilege(
    tool: DiscoveredTool,
    profile: ToolProfile | None = None,
    probe: ProbeResult | None = None,
    declared_hosts: list[str] | None = None,
) -> PrivilegeAssessment:
    claimed = claimed_capabilities(tool)
    observed = observed_capabilities(probe)
    # Network only to hosts the docs already allow is within the product claim.
    if (
        probe
        and probe.egress_hosts
        and declared_hosts
        and all(host_is_declared(h, declared_hosts) for h in probe.egress_hosts)
    ):
        claimed = set(claimed) | {"network"}
    caps = claimed | observed
    reasons: list[str] = []
    tier = _tier(caps, tool, reasons)
    exceeds = sorted(observed - claimed - {"file_read_scoped", "file_write_scoped"})
    if "file_read" in claimed:
        exceeds = [c for c in exceeds if c != "file_read"]
    if "network" in claimed:
        exceeds = [c for c in exceeds if c != "network"]
    return PrivilegeAssessment(
        tool=tool.name,
        tier=tier,
        claimed=sorted(claimed),
        observed=sorted(observed),
        capabilities=sorted(caps),
        exceeds=exceeds,
        reasons=reasons,
    )


def tier_rank(tier: str) -> int:
    return TIER_ORDER.index(tier) if tier in TIER_ORDER else len(TIER_ORDER)
