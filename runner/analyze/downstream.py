"""Downstream services: SDK imports, env vars, and hosts - static plus observed."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field

from runner.models import DiscoveredTool
from runner.probe import FIXTURE_HOSTS, ProbeResult
from runner.research import ToolProfile

KNOWN_SDKS = {
    "openai": "OpenAI",
    "anthropic": "Anthropic",
    "boto3": "AWS",
    "botocore": "AWS",
    "stripe": "Stripe",
    "slack_sdk": "Slack",
    "github": "GitHub",
    "octokit": "GitHub",
    "requests": "HTTP (requests)",
    "httpx": "HTTP (httpx)",
    "aiohttp": "HTTP (aiohttp)",
    "urllib": "HTTP (urllib)",
    "socket": "raw sockets",
    "axios": "HTTP (axios)",
    "node-fetch": "HTTP (fetch)",
    "psycopg2": "PostgreSQL",
    "pymongo": "MongoDB",
    "redis": "Redis",
    "smtplib": "SMTP",
    "sqlalchemy": "SQL database",
}
_PY_IMPORT_RE = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))", re.M)
_JS_IMPORT_RE = re.compile(r"""(?:from\s+|require\(\s*)['"]([@\w./\-]+)['"]""")
_ENV_RES = [
    re.compile(r"""os\.environ\[\s*['"](\w+)['"]"""),
    re.compile(r"""os\.environ\.get\(\s*['"](\w+)['"]"""),
    re.compile(r"""os\.getenv\(\s*['"](\w+)['"]"""),
    re.compile(r"process\.env\.(\w+)"),
    re.compile(r"""process\.env\[\s*['"](\w+)['"]"""),
]
_URL_RE = re.compile(r"https?://([A-Za-z0-9.\-]+)")
_HOST_RE = re.compile(r"^[a-z0-9\-]+(\.[a-z0-9\-]+)+$", re.I)
_FILE_EXTS = {"py", "txt", "json", "md", "js", "ts", "yaml", "yml", "env", "log", "cfg", "toml"}


class Downstream(BaseModel):
    services: list[str] = Field(default_factory=list)
    env_vars: list[str] = Field(default_factory=list)
    hosts: list[str] = Field(default_factory=list)


def _looks_like_host(value: str) -> bool:
    return bool(_HOST_RE.match(value)) and value.rsplit(".", 1)[-1].lower() not in _FILE_EXTS


def _modules(text: str) -> set[str]:
    found = {a or b for a, b in _PY_IMPORT_RE.findall(text)}
    found |= set(_JS_IMPORT_RE.findall(text))
    roots = {m.split(".")[0].split("/")[0] for m in found if m}
    roots |= {m for m in found if m in KNOWN_SDKS}
    return roots


def analyze_downstream(
    tool: DiscoveredTool, profile: ToolProfile | None, probe: ProbeResult | None
) -> Downstream:
    text = "\n".join(h.snippet for h in tool.static_hits)
    context = {k: v for h in tool.static_hits for k, v in h.context.items()}
    services = sorted({KNOWN_SDKS[m] for m in _modules(text) if m in KNOWN_SDKS})
    env_vars = sorted({m for rx in _ENV_RES for m in rx.findall(text)})
    hosts = list(_URL_RE.findall(text))
    hosts += [v for v in context.values() if _looks_like_host(v)]
    if profile:
        hosts += [h for h in profile.downstream if _looks_like_host(h)]
    if probe:
        hosts += probe.egress_hosts
    hosts = [h for h in dict.fromkeys(hosts) if h not in FIXTURE_HOSTS]
    return Downstream(services=services, env_vars=env_vars, hosts=hosts)
