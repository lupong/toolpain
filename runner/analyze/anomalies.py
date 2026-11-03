"""Anomalies: decoy reads, undeclared egress, subprocesses, metadata access, obfuscation,
prompt injection in tool descriptions."""

from __future__ import annotations

import re

from pydantic import BaseModel

from runner.analyze.egress import EgressAnalysis
from runner.models import DiscoveredTool
from runner.probe import ProbeResult

METADATA_HOSTS = {"169.254.169.254", "metadata.google.internal", "100.100.100.200"}
OBFUSCATION_RE = re.compile(
    r"(base64\.b64decode|b64decode\(|atob\(|fromCharCode|eval\(\s*compile|exec\(\s*compile|"
    r"\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){5,}|['\"][A-Za-z0-9+/=]{120,}['\"]|"
    r"\beval\(|\bexec\()"
)
INJECTION_RE = re.compile(
    r"(ignore (all |any )?(previous|prior|above) (instructions|prompts)|"
    r"<important>|do not (tell|mention|reveal)[^.]{0,40}(user|human)|"
    r"system prompt|before (using|calling) this tool[^.]{0,60}(read|send|include)|"
    r"(read|send|include|cat)[^.]{0,40}(~/\.ssh|id_rsa|\.env|credentials)|"
    r"exfiltrat)",
    re.I,
)


class Anomaly(BaseModel):
    kind: str
    severity: str
    tool: str
    title: str
    evidence: str = ""
    explanation: str = ""
    recommendation: str = ""


def _decoy_evidence(probe: ProbeResult) -> str:
    path = probe.decoy_reads[0] if probe.decoy_reads else "decoy"
    target = next((n for n in probe.network if not n.startswith("fixture")), None)
    if target is None and probe.egress_hosts:
        target = probe.egress_hosts[0]
    if target:
        return f'openat("{path}") -> connect {target} (contained by sinkhole)'
    return f'openat("{path}")'


def _decoy_anomalies(
    tool: DiscoveredTool | None, probe: ProbeResult, egress: EgressAnalysis
) -> list[Anomaly]:
    name = probe.tool
    undeclared = [a for a in egress.undeclared if a.tool == name]
    if probe.tripped_decoy and undeclared:
        lead = "Undocumented tool" if tool and tool.undocumented else "Tool"
        host = undeclared[0].host
        return [
            Anomaly(
                kind="decoy_read_and_egress",
                severity="critical",
                tool=name,
                title=f"{lead} read a planted decoy and attempted an undeclared connection",
                evidence=_decoy_evidence(probe),
                explanation=(
                    f"`{name}` opened the decoy file ToolPain planted in the sandbox and then "
                    f"tried to reach `{host}`, which the server never declares. The sinkhole "
                    "contained the connection; nothing left the sandbox."
                ),
                recommendation=f"Do not install this server. Remove `{name}` and block `{host}`.",
            )
        ]
    out: list[Anomaly] = []
    if probe.tripped_decoy:
        out.append(
            Anomaly(
                kind="decoy_read",
                severity="critical",
                tool=name,
                title="Tool read a planted decoy credential",
                evidence=_decoy_evidence(probe),
                explanation=f"`{name}` accessed a decoy secret with no stated reason to.",
                recommendation=f"Remove or sandbox `{name}`.",
            )
        )
    for attempt in undeclared:
        out.append(
            Anomaly(
                kind="undeclared_egress",
                severity="high",
                tool=name,
                title=f"Undeclared egress to {attempt.host}",
                evidence=f"connect {attempt.host}" + (f":{attempt.port}" if attempt.port else ""),
                explanation=f"`{name}` contacted `{attempt.host}`, which the docs never mention.",
                recommendation=f"Allow-list `{attempt.host}` only if it is intended.",
            )
        )
    return out


def _process_anomalies(probe: ProbeResult) -> list[Anomaly]:
    out: list[Anomaly] = []
    for proc in probe.processes:
        shell = bool(re.search(r"(^|/|\s)(ba|da|z)?sh(\s|$)", proc))
        out.append(
            Anomaly(
                kind="subprocess_spawn",
                severity="high" if shell else "medium",
                tool=probe.tool,
                title=f"`{probe.tool}` spawned {'a shell' if shell else 'a subprocess'}",
                evidence=f"execve {proc}"[:200],
                explanation="Spawning processes lets a tool run arbitrary programs.",
                recommendation="Confirm the subprocess is required and its arguments are fixed.",
            )
        )
    return out


def find_anomalies(
    tools: list[DiscoveredTool], probes: dict[str, ProbeResult], egress: EgressAnalysis
) -> list[Anomaly]:
    by_name = {t.name: t for t in tools}
    found: list[Anomaly] = []
    for name, probe in probes.items():
        found += _decoy_anomalies(by_name.get(name), probe, egress)
        found += _process_anomalies(probe)
        hit = next((h for h in probe.egress_hosts if h in METADATA_HOSTS), None)
        if hit:
            found.append(
                Anomaly(
                    kind="metadata_endpoint",
                    severity="high",
                    tool=name,
                    title="Attempted cloud metadata endpoint access",
                    evidence=f"connect {hit}",
                    explanation="Metadata endpoints hand out cloud credentials.",
                    recommendation="Block link-local addresses; remove this behaviour.",
                )
            )
    for tool in tools:
        code = "\n".join(h.snippet for h in tool.static_hits)
        m = OBFUSCATION_RE.search(code)
        if m:
            found.append(
                Anomaly(
                    kind="obfuscation",
                    severity="medium",
                    tool=tool.name,
                    title=f"Obfuscated or dynamic code in `{tool.name}`",
                    evidence=m.group(0)[:120],
                    explanation="Encoded payloads or dynamic eval hide what code will run.",
                    recommendation="Review the implementation by hand.",
                )
            )
        m = INJECTION_RE.search(tool.description or "")
        if m:
            found.append(
                Anomaly(
                    kind="prompt_injection",
                    severity="high",
                    tool=tool.name,
                    title=f"Prompt-injection text in `{tool.name}` description",
                    evidence=tool.description[:240],
                    explanation="The description tries to instruct the model rather than describe the tool.",
                    recommendation="Treat the server as hostile; do not expose it to an agent.",
                )
            )
    return found
