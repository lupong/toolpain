"""Egress and ingress: declared vs attempted hosts, listening ports."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from runner.probe import FIXTURE_HOSTS, ProbeResult

_URL_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)")
_MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\([^)]+\)")
_HTML_IMG_RE = re.compile(r"<img\b[^>]*>", re.IGNORECASE)
DOC_HOST_IGNORE = {
    "localhost",
    "127.0.0.1",
    "github.com",
    "docs.github.com",
    "npmjs.com",
    "pypi.org",
    "example.com",
    "img.shields.io",
    "shields.io",
    "badge.fury.io",
    "goreportcard.com",
    "camo.githubusercontent.com",
    "raw.githubusercontent.com",
    "user-images.githubusercontent.com",
    "avatars.githubusercontent.com",
    "modelcontextprotocol.io",
    # Install / editor / marketplace links, not runtime egress the server claims.
    "code.visualstudio.com",
    "insiders.vscode.dev",
    "vscode.dev",
    "marketplace.visualstudio.com",
    "www.docker.com",
    "docker.com",
    "hub.docker.com",
    # README placeholders for GitHub Enterprise examples.
    "octocorp.ghe.com",
    "copilot-api.octocorp.ghe.com",
    "yoursubdomain.ghe.com",
}
_PLACEHOLDER_HOST = re.compile(
    r"(^|\.)example\.com$|^your[a-z]*\.|^example\.|^placeholder\.|^\*",
    re.I,
)


class EgressAttempt(BaseModel):
    host: str
    tool: str
    blocked: bool = True
    port: int | None = None
    declared: bool = False


class EgressAnalysis(BaseModel):
    declared: list[str] = Field(default_factory=list)
    attempted: list[EgressAttempt] = Field(default_factory=list)
    ingress: list[dict[str, object]] = Field(default_factory=list)

    @property
    def undeclared(self) -> list[EgressAttempt]:
        return [a for a in self.attempted if not a.declared]


# Product words in docs imply their public API host even when only github.com links appear.
_IMPLIED_API_HOSTS: tuple[tuple[re.Pattern[str], tuple[str, ...]], ...] = (
    (re.compile(r"\bGitHub\b"), ("api.github.com",)),
    (re.compile(r"\bGitLab\b"), ("gitlab.com", "api.gitlab.com")),
)


def declared_hosts(readme_text: str | None) -> list[str]:
    """Hosts the docs openly say the server talks to (excluding badges and package hosts)."""
    text = _MD_IMAGE_RE.sub("", readme_text or "")
    text = _HTML_IMG_RE.sub("", text)
    hosts = {
        h.lower()
        for h in _URL_RE.findall(text)
        if h.lower() not in DOC_HOST_IGNORE and not _PLACEHOLDER_HOST.search(h)
    }
    for pattern, implied in _IMPLIED_API_HOSTS:
        if pattern.search(text):
            hosts.update(implied)
    return sorted(hosts)


def host_is_declared(host: str, declared: list[str]) -> bool:
    """Exact match, or observed host is a subdomain of a declared parent."""
    h = host.lower().rstrip(".")
    declared_l = [d.lower().rstrip(".") for d in declared]
    if h in declared_l:
        return True
    return any(h.endswith("." + d) for d in declared_l)


def _port_for(probe: ProbeResult, host: str) -> int | None:
    for rec in probe.sinkhole:
        if rec.host == host and rec.port:
            return rec.port
    return None


def analyze_egress(
    probes: dict[str, ProbeResult], readme_text: str | None = None
) -> EgressAnalysis:
    declared = declared_hosts(readme_text)
    attempted: list[EgressAttempt] = []
    ingress: list[dict[str, object]] = []
    for name, probe in probes.items():
        for host in probe.egress_hosts:
            if host in FIXTURE_HOSTS:
                continue
            attempted.append(
                EgressAttempt(
                    host=host,
                    tool=name,
                    blocked=True,  # the sandbox has no route out: every attempt is contained
                    port=_port_for(probe, host),
                    declared=host_is_declared(host, declared),
                )
            )
        ingress += [{"port": p, "proto": "tcp", "tool": name} for p in probe.listening_ports]
    return EgressAnalysis(declared=declared, attempted=attempted, ingress=ingress)
