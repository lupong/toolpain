"""Separation-of-duties: toxic tool combinations.

A combo is a tool pair (or a single tool that holds both halves) whose capabilities together
enable exfiltration, token theft, credential harvesting, or a covert channel through shared
storage.
"""

from __future__ import annotations

from pydantic import BaseModel

from runner.analyze.privilege import PrivilegeAssessment

MAX_COMBOS = 12
SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

READS_LOCAL = {"file_read", "file_read_scoped", "credential_read"}
EGRESS = {"network", "upload"}
EXEC = {"code_exec", "shell", "subprocess"}
WRITES = {"file_write", "file_write_scoped", "media_save"}

WHY = {
    "exfiltration": "{a} can read local data and {b} can send it to a remote host.",
    "token_theft": "{a} can evaluate code in a context holding tokens; {b} can send them out.",
    "credential_harvesting": "{a} touches credentials; {b} can execute or transmit them.",
    "covert_channel": "{a} writes files that {b} can read or upload (shared storage bridge).",
}


class Combo(BaseModel):
    tools: list[str]
    risk: str
    severity: str
    why: str


def _pair_risks(a: PrivilegeAssessment, b: PrivilegeAssessment) -> list[tuple[str, str]]:
    """Risks where ``a`` supplies the first half and ``b`` the second."""
    ca, cb = set(a.capabilities), set(b.capabilities)
    risks: list[tuple[str, str]] = []
    if "credential_read" in ca and (cb & (EXEC | EGRESS)):
        risks.append(("credential_harvesting", "critical"))
    if ca & READS_LOCAL and cb & EGRESS:
        severity = "critical" if "credential_read" in ca else "high"
        risks.append(("exfiltration", severity))
    if "code_exec" in ca and (cb & EGRESS or "browser" in cb):
        risks.append(("token_theft", "high"))
    if a.tool != b.tool and ca & WRITES and (cb & (READS_LOCAL | {"upload"})):
        risks.append(("covert_channel", "medium"))
    return risks


def find_toxic_combos(assessments: list[PrivilegeAssessment]) -> list[Combo]:
    seen: dict[tuple[frozenset[str], str], Combo] = {}
    for a in assessments:
        for b in assessments:
            for risk, severity in _pair_risks(a, b):
                key = (frozenset({a.tool, b.tool}), risk)
                if key in seen and SEVERITY_RANK[seen[key].severity] <= SEVERITY_RANK[severity]:
                    continue
                tools = [a.tool] if a.tool == b.tool else [a.tool, b.tool]
                seen[key] = Combo(
                    tools=tools,
                    risk=risk,
                    severity=severity,
                    why=WHY[risk].format(
                        a=a.tool, b=b.tool if a.tool != b.tool else "the same tool"
                    ),
                )
    combos = sorted(seen.values(), key=lambda c: (SEVERITY_RANK[c.severity], c.risk, c.tools))
    return combos[:MAX_COMBOS]
