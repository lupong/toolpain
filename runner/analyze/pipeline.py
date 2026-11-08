"""Run every analyzer over a scan's discovery, research, and probe output."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from runner.analyze.anomalies import Anomaly, find_anomalies
from runner.analyze.discrepancy import Discrepancy, find_discrepancies, fork_drift
from runner.analyze.downstream import Downstream, analyze_downstream
from runner.analyze.egress import EgressAnalysis, analyze_egress
from runner.analyze.privilege import PrivilegeAssessment, assess_privilege
from runner.analyze.sod import Combo, find_toxic_combos
from runner.models import DiscoveryResult
from runner.probe import ProbeResult
from runner.research import ToolProfile


class AnalysisInput(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    discovery: DiscoveryResult
    profiles: dict[str, ToolProfile] = Field(default_factory=dict)
    probes: dict[str, ProbeResult] = Field(default_factory=dict)
    readme_text: str | None = None
    upstream_tools: list[str] | None = None


class AnalysisResult(BaseModel):
    assessments: dict[str, PrivilegeAssessment]
    discrepancies: list[Discrepancy]
    drift: list[dict[str, str | None]]
    combos: list[Combo]
    anomalies: list[Anomaly]
    egress: EgressAnalysis
    downstream: dict[str, Downstream]


def analyze_scan(data: AnalysisInput) -> AnalysisResult:
    tools = data.discovery.tools
    egress = analyze_egress(data.probes, data.readme_text)
    assessments = {
        t.name: assess_privilege(
            t,
            data.profiles.get(t.name),
            data.probes.get(t.name),
            declared_hosts=egress.declared,
        )
        for t in tools
    }
    return AnalysisResult(
        assessments=assessments,
        discrepancies=find_discrepancies(data.discovery, assessments, data.upstream_tools),
        drift=fork_drift(data.discovery, data.upstream_tools),
        combos=find_toxic_combos(list(assessments.values())),
        anomalies=find_anomalies(tools, data.probes, egress),
        egress=egress,
        downstream={
            t.name: analyze_downstream(t, data.profiles.get(t.name), data.probes.get(t.name))
            for t in tools
        },
    )
