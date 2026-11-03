"""Egress and ingress: declared vs attempted hosts, listening ports."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from runner.probe import FIXTURE_HOSTS, ProbeResult

_URL_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)")
DOC_HOST_IGNORE = {"localhost", "127.0.0.1", "github.com", "npmjs.com", "pypi.org", "example.com"}


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


def declared_hosts(readme_text: str | None) -> list[str]:
    """Hosts the docs openly say the server talks to (excluding repo/package hosts)."""
    hosts = [h.lower() for h in _URL_RE.findall(readme_text or "")]
    return sorted({h for h in hosts if h not in DOC_HOST_IGNORE})


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
                    declared=host in declared,
                )
            )
        ingress += [{"port": p, "proto": "tcp", "tool": name} for p in probe.listening_ports]
    return EgressAnalysis(declared=declared, attempted=attempted, ingress=ingress)
