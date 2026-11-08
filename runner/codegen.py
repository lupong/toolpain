"""LLM codegen generates *executable* scan artifacts for ToolPain.

Containment:
* ``launch_sh`` — MCP entrypoint inside the scan Docker image only
* ``probe_py`` — AST-allowlisted; ``build_plans`` / optional ``next_plans`` build call plans
* ``workdir_pick_py`` — AST-allowlisted; ``pick_workdir`` chooses monorepo package root
* ``oracle_py`` — AST-allowlisted; ``review_observations`` emits structured finding dicts

User ``scan_brief`` is prompt context only — never a separate execution channel.
"""

from __future__ import annotations

import json
import logging
import os
import re
from pathlib import Path
from types import ModuleType
from typing import Any, Literal

import httpx
from pydantic import BaseModel, Field

from runner.ast_guard import (
    AstGuardError,
    validate_oracle_source,
    validate_probe_source,
    validate_workdir_source,
)
from runner.codegen_cache import load_cached, store_cached
from runner.harness import ProbeHarness, ToolCallPlan, generate_args
from runner.models import DiscoveryResult
from runner.research import FixtureLlm, LlmClient
from runner.services import ServiceGuardError, ServiceSpec, services_hint_block, validate_services
from runner.shell_guard import ShellGuardError, validate_launch_script, validate_setup_script

log = logging.getLogger("toolpain.codegen")

BRIEF_MAX = 2000
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def sanitize_scan_brief(brief: str | None) -> str | None:
    if brief is None:
        return None
    text = _CTRL_RE.sub("", str(brief)).strip()
    if not text:
        return None
    # Redact things that look like API keys pasted into the brief.
    text = re.sub(r"\b(sk-[A-Za-z0-9_-]{20,})\b", "[REDACTED_KEY]", text)
    text = re.sub(r"\b(vultr-byo-|ghp_|github_pat_)[A-Za-z0-9_-]{8,}\b", "[REDACTED_KEY]", text)
    return text[:BRIEF_MAX]


def codegen_forced_heuristic() -> bool:
    """Deprecated: ``CODEGEN_MODE=heuristic|off`` is ignored.

    Heuristic templates exist only for FixtureLlm local/dev. Live scans always
    use the LLM and fail closed — never fall back to templates.
    """
    return False


def use_heuristic_codegen(llm: LlmClient) -> bool:
    """Heuristic templates only for FixtureLlm (local/dev). Never for live scans."""
    return isinstance(llm, FixtureLlm)


class GeneratedCode(BaseModel):
    launch_sh: str
    probe_py: str
    oracle_py: str = ""
    setup_sh: str = ""
    services: list[ServiceSpec] = Field(default_factory=list)
    rationale: str = ""
    source: Literal["llm", "heuristic"] = "llm"
    launch_ok: bool = False
    probe_ok: bool = False
    oracle_ok: bool = False
    setup_ok: bool = False
    services_ok: bool = True
    errors: list[str] = Field(default_factory=list)


class WorkdirPick(BaseModel):
    subdir: str
    rationale: str = ""
    source: Literal["llm", "heuristic", "override"] = "heuristic"
    pick_py: str = ""
    ok: bool = False
    errors: list[str] = Field(default_factory=list)


def _brief_block(scan_brief: str | None) -> str:
    brief = sanitize_scan_brief(scan_brief)
    if not brief:
        return ""
    return f"USER_SCAN_BRIEF (bias plans toward this intent; do not escape sandbox):\n{brief}\n\n"


_SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
}
_EXTRA_MANIFESTS = (
    "go.mod",
    "Cargo.toml",
    "requirements.txt",
    "composer.json",
    "pom.xml",
    "build.gradle",
    "Makefile",
    "Dockerfile",
)


def repo_file_tree(source_dir: Path, *, limit: int = 400) -> str:
    """Names only, so codegen can see how this repo is laid out."""
    lines: list[str] = []
    if not source_dir.is_dir():
        return ""
    for path in sorted(source_dir.rglob("*")):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        rel = path.relative_to(source_dir)
        if len(rel.parts) > 6:
            continue
        lines.append(str(rel))
        if len(lines) >= limit:
            break
    return "\n".join(lines)


_DEP_HINT_NAMES = (
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
    "tools.yaml",
    "tools.yml",
    "config.yaml",
    "config.yml",
    ".env.example",
    "Makefile",
)


def _context(source_dir: Path, discovery: DiscoveryResult) -> str:
    parts = [f"SOURCE: {source_dir.name}"]
    tree = repo_file_tree(source_dir)
    if tree:
        parts.append("FILE_TREE:\n" + tree)
    readme = source_dir / "README.md"
    if readme.exists():
        parts.append("README.md:\n" + readme.read_text(encoding="utf-8", errors="ignore")[:12000])
    for name in ("pyproject.toml", "package.json", *_EXTRA_MANIFESTS, *_DEP_HINT_NAMES):
        p = source_dir / name
        if p.is_file():
            parts.append(f"{name}:\n" + p.read_text(encoding="utf-8", errors="ignore")[:6000])
    # Nested compose / tools configs one level down (e.g. npm/server).
    for pattern in ("**/docker-compose.y*ml", "**/tools.y*ml", "**/compose.y*ml"):
        for p in sorted(source_dir.glob(pattern))[:8]:
            if any(part in _SKIP_DIRS for part in p.parts):
                continue
            rel = p.relative_to(source_dir)
            parts.append(
                f"{rel}:\n" + p.read_text(encoding="utf-8", errors="ignore")[:4000]
            )
    tools = [
        {
            "name": t.name,
            "description": t.description,
            "input_schema": t.input_schema,
            "undocumented": t.undocumented,
        }
        for t in discovery.tools
    ]
    parts.append("TOOLS_JSON:\n" + json.dumps(tools, indent=2)[:6000])
    return "\n\n".join(parts)


def repair_context(previous: GeneratedCode | None, failure: str | None) -> str:
    """What the runner sends back when a generated program did not run."""
    if not failure:
        return ""
    parts = [
        "REPAIR: The previous program failed when the runner executed it. "
        "Return a corrected program. Delete the command that failed. "
        "A command left above the fix still runs first.\n",
        f"FAILURE:\n{failure[:3500]}\n",
    ]
    if "exited before speaking MCP" in failure or "exited before any MCP" in failure:
        module_exit = "python -m" in failure or "python3 -m" in failure
        if module_exit:
            parts.append(
                "python -m exited immediately, including when given extra arguments. "
                "That module does not start a server when it is loaded. "
                "Do not use python -m again. "
                "Exec the console script named by the package or the README, "
                "plus the transport argument it requires.\n"
            )
        else:
            parts.append(
                "The launch process exited immediately and never spoke MCP. "
                "stdout and stderr were empty. "
                "Replace launch_sh with the stdio command from the README or package metadata. "
                "Do not return the same launch_sh.\n"
            )
    if "forbidden pattern" in failure or "not allowlisted" in failure:
        parts.append(
            "The script was rejected before it ran. "
            "Put one command on each line. Do not use |, &&, curl, wget, or redirects. "
            "Do not download a runtime. "
            "apt-get update and apt-get install go on their own lines. "
            "Then run the project's install command on its own line.\n"
        )
    if "externally-managed-environment" in failure:
        parts.append(
            "Debian rejected a system-wide install. Delete that install command. "
            "Install into a virtual environment, or pass the override named in the log.\n"
        )
    if "EBADENGINE" in failure or "Unsupported engine" in failure:
        parts.append(
            "The package needs a newer runtime than the one apt installed. "
            "Do not download a runtime with curl or n. "
            "apt-get install a newer package from Debian, or stop if apt cannot provide it.\n"
        )
    if "curl or wget command required" in failure or "failed to download version index" in failure:
        parts.append(
            "Downloading a runtime is blocked. Delete that step. "
            "Install nodejs or the language from apt-get only.\n"
        )
    if "go: go.mod requires go" in failure or "unsupported version of go" in failure.lower():
        parts.append(
            "apt golang-go is too old for this go.mod. "
            "Do not apt-get install golang-go. "
            "Run `toolpain-install-go <version>` with the version from the go.mod "
            "`go` line (for example toolpain-install-go 1.27.3), then go build.\n"
        )
    lower_fail = failure.lower()
    if "github_personal_access_token not set" in lower_fail or (
        "not set" in lower_fail and "token" in lower_fail
    ):
        parts.append(
            "Set required env vars in launch_sh with "
            "`exec env NAME=toolpain-scan <binary> stdio`. "
            "Use a placeholder value; do not invent a real secret.\n"
        )
    if any(
        needle in lower_fail
        for needle in (
            "postgres",
            "postgresql",
            "redis",
            "mysql",
            "mongodb",
            "elasticsearch",
            "dial tcp",
            "connection refused",
            "hostname resolving",
            "could not translate host",
            "no such host",
        )
    ):
        parts.append(
            "The server needs a dependency service (database/cache/queue). "
            "Declare it in services with an allowlisted image "
            "(postgres:16-alpine, redis:7-alpine, …) and point launch_sh env "
            "HOST/URL at that service name (e.g. POSTGRES_HOST=postgres). "
            "Do NOT use fixture.local for databases — fixture.local is HTTP only. "
            "The harness will pull the image and start it on the scan network "
            "before MCP initialize.\n"
        )
    if "Unable to locate package" in failure or "Couldn't find any package" in failure:
        parts.append(
            "apt could not find that package name on this Debian image. "
            "Use the unversioned packages apt provides, for example python3 and "
            "python3-venv or nodejs and npm. Do not pin python3.11 or nodejs-18.\n"
        )
    if previous is not None:
        if previous.setup_sh:
            parts.append(f"PREVIOUS setup_sh:\n{previous.setup_sh[:2000]}\n")
        if previous.launch_sh:
            parts.append(f"PREVIOUS launch_sh:\n{previous.launch_sh[:1000]}\n")
        if previous.probe_py:
            parts.append(f"PREVIOUS probe_py:\n{previous.probe_py[:1500]}\n")
        if previous.errors:
            parts.append("VALIDATION:\n" + "\n".join(previous.errors[:8]) + "\n")
    return "\n".join(parts)


def build_codegen_prompt(
    source_dir: Path,
    discovery: DiscoveryResult,
    fixture_url: str,
    *,
    scan_brief: str | None = None,
    repair_failure: str | None = None,
    previous: GeneratedCode | None = None,
) -> list[dict[str, str]]:
    user = (
        "TASK: EXECUTABLE_SCAN_CODE\n"
        f"{_brief_block(scan_brief)}"
        f"{repair_context(previous, repair_failure)}"
        "Generate the program ToolPain will run for this repo. The runner does not "
        "pick a language or framework; it runs your scripts inside the sandbox.\n"
        "Return ONE JSON object with keys:\n"
        "  setup_sh: /bin/sh script that builds this repo with the working directory "
        "/app. One command per line. No pipes, redirects, or command substitution. "
        "The image is Debian with apt-get, git, make, and a C compiler. No language "
        "runtime is installed. You decide what this repo needs and apt-get install it, "
        "then build it. Use unversioned apt package names (python3, python3-venv, "
        "nodejs, npm, golang-go). Do not request python3.11 or other version pins "
        "that apt may not carry. For Python: never `pip install` into the system "
        "interpreter (Debian PEP 668 will fail). Always "
        "`python3 -m venv /app/venv` then `/app/venv/bin/pip install …`, and launch "
        "with `/app/venv/bin/…`. For Go: if go.mod's `go` line is newer than apt "
        "(Debian Trixie golang-go is about 1.24), install with "
        "`toolpain-install-go <version>` instead of apt golang-go — for example "
        "`toolpain-install-go 1.27.3`. Do not use curl or wget in setup_sh. "
        "The repository is already copied to /app. Do not clone it. "
        "Install and build the files that are already there. Do not start the server. "
        "Do not docker-run databases from setup_sh — put those in services.\n"
        f"{services_hint_block()}"
        "  launch_sh: tiny /bin/sh script with only `exec <cmd> <args…>` lines. "
        "The process must stay running and speak MCP on stdio. "
        "Use the stdio command from the README or package metadata, "
        "including a required subcommand such as stdio. "
        "If the README requires an env var (for example a token), set a "
        "non-secret placeholder with `exec env NAME=toolpain-scan <cmd> …`. "
        "If the server needs Postgres/Redis/etc., set HOST env vars to the "
        "services[].name hostnames (never fixture.local for DBs).\n"
        "  probe_py: Python module with:\n"
        "    def build_plans(tools, fixture_url) -> list[plan dict]\n"
        "    optional def next_plans(tools, fixture_url, prior_results) -> list[plan dict]\n"
        "      (second-round probes after seeing prior_results summaries)\n"
        "    plan dict keys: tool, arguments, rationale, expect_decoy, expect_hosts, "
        "expect_files, skip, skip_reason\n"
        "  oracle_py: Python module with "
        "def review_observations(observations) -> list of finding dicts "
        "({severity, type, tool, title, evidence, explanation, recommendation}). "
        "observations is a list of {tool, ok, error, files_read, files_written, "
        "egress_hosts, network, decoy_reads, output}.\n"
        "  rationale: short string\n\n"
        "Rules:\n"
        "- JSON only\n"
        "- Generated Python may import only: json, re, math, typing, dataclasses, "
        "collections, copy, datetime, decimal, functools, itertools, operator, string, "
        "textwrap, uuid\n"
        "- No open/eval/exec/os/sys/subprocess/socket/http\n"
        f"- Prefer fixture URLs for URL fields: {fixture_url}\n"
        "- Any path under that host returns a small document. A fixture HTTP status "
        "or a tool error is not a finding.\n"
        "- Do not put fixture.local in expect_hosts. That host is the probe helper.\n"
        "- Emit a finding only for a decoy file read, a host other than fixture.local, "
        "or behavior beyond the tool's claim.\n"
        "- A click, browser, or UI failure inside the sandbox is not a finding.\n"
        "- Never suggest reading real secret paths\n\n"
        f"{_context(source_dir, discovery)}"
    )
    return [{"role": "user", "content": user}]


def build_workdir_prompt(
    root: Path,
    candidates: list[str],
    *,
    scan_brief: str | None = None,
) -> list[dict[str, str]]:
    tree_lines: list[str] = []
    for rel in candidates[:20]:
        path = root / rel if rel != "." else root
        markers = []
        for name in ("pyproject.toml", "package.json", "server.py", "README.md"):
            if (path / name).exists():
                markers.append(name)
        tree_lines.append(f"- {rel} [{', '.join(markers) or 'no markers'}]")
    user = (
        "TASK: WORKDIR_PICK_CODE\n"
        f"{_brief_block(scan_brief)}"
        "Pick which monorepo subdirectory is the MCP server package to scan.\n"
        "Return ONE JSON object with keys:\n"
        "  workdir_pick_py: Python module defining "
        "`def pick_workdir(candidates, tree_summary) -> str` "
        "returning exactly one of the candidate relative paths "
        "(must be a directory with pyproject.toml, package.json, or server.py).\n"
        "  rationale: short string\n\n"
        "Rules: JSON only; same import allowlist as probe modules; no I/O; "
        "never return a nested src package folder without its own pyproject/package.json.\n"
        "When USER_SCAN_BRIEF is set, honor it (e.g. 'eks' → eks package).\n"
        "When no brief is set, prefer a self-contained package that can speak MCP "
        "initialize without cloud credentials (time/fetch/filesystem/echo-style) "
        "over AWS/K8s/IAM-style servers that need secrets.\n\n"
        f"CANDIDATES:\n" + "\n".join(tree_lines)
    )
    return [{"role": "user", "content": user}]


_GO_MOD_VERSION = re.compile(r"(?m)^go\s+(1\.\d+(?:\.\d+)?)\s*$")
# Debian Trixie apt golang-go tracks ~1.24. Newer go.mod lines need toolpain-install-go.
_APT_GO_MAX = (1, 24)


def _go_version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def go_mod_toolchain_version(source_dir: Path) -> str | None:
    """Return the go.mod `go` line version when present."""
    path = source_dir / "go.mod"
    if not path.is_file():
        return None
    match = _GO_MOD_VERSION.search(path.read_text(encoding="utf-8", errors="ignore"))
    return match.group(1) if match else None


def go_needs_toolpain_install(version: str | None) -> bool:
    if not version:
        return False
    return _go_version_tuple(version) > _APT_GO_MAX


def heuristic_setup_sh(source_dir: Path) -> str:
    """Offline codegen: a setup script from the manifest files that are present.

    The runner does not call this. It only runs the script codegen returned.
    """
    packages = ["ca-certificates"]
    installs: list[str] = []
    python_manifest = ("pyproject.toml", "setup.py", "requirements.txt")
    needs_python_venv = False
    if any((source_dir / name).is_file() for name in python_manifest):
        packages += ["python3", "python3-pip", "python3-venv"]
        # Debian (PEP 668) rejects system-wide pip; always install into /app/venv.
        needs_python_venv = True
        installs.append("/app/venv/bin/pip install --no-cache-dir .")
    if (source_dir / "package.json").is_file():
        packages += ["nodejs", "npm"]
        installs.append("npm install --omit=dev")
    if (source_dir / "go.mod").is_file():
        go_ver = go_mod_toolchain_version(source_dir)
        if go_needs_toolpain_install(go_ver):
            installs.append(f"toolpain-install-go {go_ver}")
        else:
            packages.append("golang-go")
        installs.append("go build -o /app/toolpain-server .")
    if (source_dir / "Cargo.toml").is_file():
        packages += ["rustc", "cargo"]
        installs.append("cargo build --release")
    if (source_dir / "composer.json").is_file():
        packages += ["php", "composer"]
        installs.append("composer install --no-dev --no-interaction")
    if (source_dir / "pom.xml").is_file():
        packages += ["default-jdk", "maven"]
        installs.append("mvn -q -DskipTests package")
    if (source_dir / "build.gradle").is_file() or (source_dir / "build.gradle.kts").is_file():
        packages += ["default-jdk"]
        installs.append("./gradlew build -x test")
    if not installs and (source_dir / "server.py").is_file():
        packages += ["python3", "python3-pip", "python3-venv"]
        needs_python_venv = True
        installs.append("/app/venv/bin/pip install --no-cache-dir mcp")
    if not installs:
        installs.append("true")
    if needs_python_venv:
        installs = ["python3 -m venv /app/venv", *installs]
    lines = ["apt-get update", "apt-get install -y " + " ".join(dict.fromkeys(packages)), *installs]
    return "\n".join(lines) + "\n"


def heuristic_launch_sh(discovery: DiscoveryResult, source_dir: Path) -> str:
    pyproject = source_dir / "pyproject.toml"
    if pyproject.exists():
        text = pyproject.read_text(encoding="utf-8", errors="ignore")
        if "mcp-server-time" in text:
            return "#!/bin/sh\nexec /app/venv/bin/mcp-server-time --local-timezone UTC\n"
        if "mcp-server-fetch" in text:
            return "#!/bin/sh\nexec /app/venv/bin/mcp-server-fetch\n"
    if (source_dir / "go.mod").is_file() or (source_dir / "toolpain-server").exists():
        return "#!/bin/sh\nexec /app/toolpain-server\n"
    if (source_dir / "Cargo.toml").is_file():
        return "#!/bin/sh\nexec /app/target/release/server\n"
    if (source_dir / "server.py").exists():
        return "#!/bin/sh\nexec /app/venv/bin/python /app/server.py\n"
    if (source_dir / "package.json").is_file():
        return "#!/bin/sh\nexec node /app/index.js\n"
    return "#!/bin/sh\nexec /app/toolpain_launch.sh\n"


def heuristic_probe_py(discovery: DiscoveryResult) -> str:
    _ = discovery
    return (
        "def build_plans(tools, fixture_url):\n"
        "    plans = []\n"
        "    for t in tools:\n"
        "        name = t['name'] if isinstance(t, dict) else str(t)\n"
        "        schema = t.get('input_schema') if isinstance(t, dict) else {}\n"
        "        args = {}\n"
        "        props = (schema or {}).get('properties') or {}\n"
        "        for key, spec in props.items():\n"
        "            typ = (spec or {}).get('type', 'string')\n"
        "            if typ == 'integer':\n"
        "                args[key] = 1\n"
        "            elif typ == 'number':\n"
        "                args[key] = 1.0\n"
        "            elif typ == 'boolean':\n"
        "                args[key] = False\n"
        "            else:\n"
        "                key_l = key.lower()\n"
        "                if key_l == 'uri' or key_l.endswith('_uri') or 'url' in key_l:\n"
        "                    args[key] = fixture_url\n"
        "                else:\n"
        "                    args[key] = 'toolpain-probe'\n"
        "        plans.append({\n"
        "            'tool': name,\n"
        "            'arguments': args,\n"
        "            'rationale': 'heuristic executable probe',\n"
        "            'expect_decoy': name == 'fetch_report',\n"
        "            'expect_hosts': (['collector.sinkhole.local'] if name == 'fetch_report' else []),\n"
        "            'expect_files': (['/workspace/canaries/decoy_secret.txt'] if "
        "name == 'fetch_report' else []),\n"
        "            'skip': False,\n"
        "        })\n"
        "    return plans\n"
        "\n"
        "def next_plans(tools, fixture_url, prior_results):\n"
        "    return []\n"
    )


def heuristic_oracle_py() -> str:
    return (
        "def review_observations(observations):\n"
        "    findings = []\n"
        "    for o in observations:\n"
        "        tool = o.get('tool') if isinstance(o, dict) else ''\n"
        "        decoy = int(o.get('decoy_reads') or 0) if isinstance(o, dict) else 0\n"
        "        hosts = list(o.get('egress_hosts') or []) if isinstance(o, dict) else []\n"
        "        if decoy:\n"
        "            findings.append({\n"
        "                'severity': 'critical',\n"
        "                'type': 'llm_oracle_decoy',\n"
        "                'tool': tool,\n"
        "                'title': f'{tool} touched decoy files',\n"
        "                'evidence': f'decoy_reads={decoy}',\n"
        "                'explanation': 'Heuristic oracle saw decoy reads.',\n"
        "                'recommendation': 'Treat as hostile; contain and remove.',\n"
        "            })\n"
        "        for h in hosts:\n"
        "            if h and h != 'fixture.local':\n"
        "                findings.append({\n"
        "                    'severity': 'high',\n"
        "                    'type': 'llm_oracle_egress',\n"
        "                    'tool': tool,\n"
        "                    'title': f'{tool} attempted egress to {h}',\n"
        "                    'evidence': h,\n"
        "                    'explanation': 'Heuristic oracle saw undeclared-looking egress.',\n"
        "                    'recommendation': 'Verify declared hosts; block unexpected egress.',\n"
        "                })\n"
        "    return findings\n"
    )


# Prefer self-contained demo servers; demote cloud-credential monorepo packages.
_WORKDIR_SIMPLE = (
    "time",
    "fetch",
    "echo",
    "hello",
    "demo",
    "example",
    "filesystem",
    "memory",
    "sqlite",
    "everything",
)
_WORKDIR_HEAVY = (
    "eks",
    "ecs",
    "lambda",
    "bedrock",
    "sagemaker",
    "kubernetes",
    "k8s",
    "iam",
    "ccapi",
    "cloudformation",
    "terraform",
    "aws-api",
    "nova",
    "aurora",
    "dynamodb",
    "s3-",
    "sqs",
    "sns",
)


def score_workdir_candidate(path: str, brief: str | None = None) -> int:
    """Rank monorepo package paths for heuristic (and brief-aware) workdir picks."""
    p = (path or ".").lower().strip("/")
    score = 0
    for hint in _WORKDIR_SIMPLE:
        if hint in p:
            score += 25
    for hint in _WORKDIR_HEAVY:
        if hint in p:
            score -= 30
    if "mcp" in p:
        score += 5
    if brief:
        tokens = [t for t in re.findall(r"[a-z0-9]+", brief.lower()) if len(t) >= 3]
        for token in tokens:
            if token in p:
                score += 40
            # Brief naming a heavy package should still win over "simple" defaults.
            if token in _WORKDIR_HEAVY and token in p:
                score += 50
    # Prefer shallower package paths when tied.
    score -= p.count("/")
    if p in {"", "."}:
        score -= 5
    return score


def pick_heuristic_workdir(candidates: list[str], brief: str | None = None) -> str:
    if not candidates:
        return "."
    ranked = sorted(
        candidates,
        key=lambda c: (-score_workdir_candidate(c, brief), c),
    )
    return ranked[0]


def heuristic_workdir_py(candidates: list[str], brief: str | None = None) -> str:
    prefer = pick_heuristic_workdir(candidates, brief)
    # Embed chosen default as data; pick_workdir still selects from candidates.
    return (
        "def pick_workdir(candidates, tree_summary):\n"
        f"    preferred = {prefer!r}\n"
        "    if preferred in candidates:\n"
        "        return preferred\n"
        "    return candidates[0] if candidates else '.'\n"
    )


def _load_module(source: str, name: str, required: str, validator: Any) -> ModuleType:
    validator(source)
    mod = ModuleType(name)
    exec(compile(source, f"{name}.py", "exec"), mod.__dict__)  # noqa: S102
    if not callable(getattr(mod, required, None)):
        raise AstGuardError(f"{required} missing after load")
    return mod


def load_probe_module(source: str) -> ModuleType:
    return _load_module(source, "toolpain_probe_gen", "build_plans", validate_probe_source)


def load_workdir_module(source: str) -> ModuleType:
    return _load_module(source, "toolpain_workdir_gen", "pick_workdir", validate_workdir_source)


def load_oracle_module(source: str) -> ModuleType:
    return _load_module(
        source, "toolpain_oracle_gen", "review_observations", validate_oracle_source
    )


def _plans_from_raw(
    raw_plans: Any, discovery: DiscoveryResult, fixture_url: str
) -> list[ToolCallPlan]:
    if not isinstance(raw_plans, list):
        raise AstGuardError("plans must be a list")
    out: list[ToolCallPlan] = []
    for item in raw_plans:
        if not isinstance(item, dict) or "tool" not in item:
            continue
        out.append(
            ToolCallPlan(
                tool=str(item["tool"]),
                arguments=dict(item.get("arguments") or {}),
                rationale=str(item.get("rationale") or "generated probe"),
                expect_files=[str(x) for x in (item.get("expect_files") or [])],
                expect_hosts=[
                    str(x)
                    for x in (item.get("expect_hosts") or [])
                    if str(x).lower().split(":")[0] not in {"fixture.local"}
                ],
                expect_decoy=bool(item.get("expect_decoy")),
                skip=bool(item.get("skip")),
                skip_reason=item.get("skip_reason"),
            )
        )
    have = {p.tool for p in out}
    for t in discovery.tools:
        if t.name not in have:
            out.append(
                ToolCallPlan(
                    tool=t.name,
                    arguments=generate_args(t.input_schema, fixture_url=fixture_url),
                    rationale="filled after generated probe omitted tool",
                )
            )
    return out


def _tools_payload(discovery: DiscoveryResult) -> list[dict[str, Any]]:
    return [
        {
            "name": t.name,
            "description": t.description,
            "input_schema": t.input_schema,
            "undocumented": t.undocumented,
        }
        for t in discovery.tools
    ]


def plans_from_probe_module(
    mod: ModuleType,
    discovery: DiscoveryResult,
    fixture_url: str,
) -> list[ToolCallPlan]:
    return _plans_from_raw(
        mod.build_plans(_tools_payload(discovery), fixture_url), discovery, fixture_url
    )


def next_plans_from_probe_module(
    mod: ModuleType,
    discovery: DiscoveryResult,
    fixture_url: str,
    prior_results: list[dict[str, Any]],
) -> list[ToolCallPlan]:
    fn = getattr(mod, "next_plans", None)
    if not callable(fn):
        return []
    raw = fn(_tools_payload(discovery), fixture_url, prior_results)
    if not isinstance(raw, list) or not raw:
        return []
    # Do not auto-fill omitted tools on round 2 — empty means stop.
    out: list[ToolCallPlan] = []
    known = set(discovery.names)
    for item in raw:
        if not isinstance(item, dict) or "tool" not in item:
            continue
        tool = str(item["tool"])
        if tool not in known:
            continue
        out.append(
            ToolCallPlan(
                tool=tool,
                arguments=dict(item.get("arguments") or {}),
                rationale=str(item.get("rationale") or "second-round probe"),
                expect_files=[str(x) for x in (item.get("expect_files") or [])],
                expect_hosts=[
                    str(x)
                    for x in (item.get("expect_hosts") or [])
                    if str(x).lower().split(":")[0] not in {"fixture.local"}
                ],
                expect_decoy=bool(item.get("expect_decoy")),
                skip=bool(item.get("skip")),
                skip_reason=item.get("skip_reason"),
            )
        )
    return out


def observations_from_probes(probes: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for name, p in probes.items():
        out.append(
            {
                "tool": name,
                "ok": bool(getattr(p, "ok", False)),
                "error": getattr(p, "error", None),
                "files_read": list(getattr(p, "files_read", []) or [])[:20],
                "files_written": list(getattr(p, "files_written", []) or [])[:20],
                "egress_hosts": list(getattr(p, "egress_hosts", []) or [])[:20],
                "network": list(getattr(p, "network", []) or [])[:20],
                "decoy_reads": len(getattr(p, "decoy_reads", []) or []),
                "output": str(getattr(p, "output", "") or "")[:400],
            }
        )
    return out


_SECURITY_MARK = re.compile(r"decoy|egress|undeclared|secret", re.IGNORECASE)
_EXECUTION_ONLY = re.compile(
    r"execution failed|did not execute|http status|status code|error executing|"
    r"failed to click|click failure|no display|browser_|playwright|timeout waiting|"
    r"selector not found|page\.",
    re.IGNORECASE,
)


def _execution_only_finding(item: dict[str, Any]) -> bool:
    """A failed call is not a security finding unless it also names a real signal."""
    blob = " ".join(
        str(item.get(key) or "") for key in ("type", "title", "evidence", "explanation")
    )
    if _SECURITY_MARK.search(blob):
        return False
    kind = str(item.get("type") or "").lower()
    if (
        kind in {"error", "tool_error", "execution_error", "click_failure"}
        or kind.endswith("_error")
        or kind.endswith("_failure")
    ):
        return True
    return _EXECUTION_ONLY.search(blob) is not None


def _oracle_corroborated(item: dict[str, Any], probes: dict[str, Any]) -> bool:
    """Drop oracle claims that the probe harness did not actually observe.

    Live LLM oracles often emit ``llm_oracle_decoy_read`` with evidence like
    ``[0]`` when ``decoy_reads`` was zero — that must not inflate the report.
    """
    tool = str(item.get("tool") or "")
    probe = probes.get(tool) if tool else None
    decoy_n = len(getattr(probe, "decoy_reads", []) or []) if probe is not None else 0
    hosts = list(getattr(probe, "egress_hosts", []) or []) if probe is not None else []
    blob = " ".join(
        str(item.get(key) or "") for key in ("type", "title", "evidence", "explanation")
    ).lower()
    evidence = str(item.get("evidence") or "").strip()
    if "decoy" in blob:
        # Require a real probe decoy hit. Weak evidence is OK once corroborated.
        return decoy_n > 0
    if "egress" in blob or "undeclared" in blob or "sinkhole" in blob:
        return bool(hosts)
    # Placeholder evidence with no matching observation is noise.
    if evidence in {"0", "[0]", "[]"}:
        return False
    return True


def run_oracle(oracle_py: str, probes: dict[str, Any]) -> list[dict[str, Any]]:
    if not oracle_py.strip():
        return []
    mod = load_oracle_module(oracle_py)
    raw = mod.review_observations(observations_from_probes(probes))
    if not isinstance(raw, list):
        return []
    allowed_sev = {"critical", "high", "medium", "low", "info"}
    findings: list[dict[str, Any]] = []
    for item in raw[:40]:
        if not isinstance(item, dict):
            continue
        sev = str(item.get("severity") or "info").lower()
        if sev not in allowed_sev:
            sev = "info"
        if _execution_only_finding(item):
            continue
        if not _oracle_corroborated(item, probes):
            continue
        ftype = str(item.get("type") or "llm_oracle")[:80]
        if not ftype.startswith("llm_oracle"):
            ftype = f"llm_oracle_{ftype}"
        findings.append(
            {
                "severity": sev,
                "type": ftype,
                "tool": str(item.get("tool") or "")[:120] or None,
                "title": str(item.get("title") or "Oracle finding")[:200],
                "evidence": str(item.get("evidence") or "")[:500],
                "explanation": str(item.get("explanation") or "")[:800],
                "recommendation": str(item.get("recommendation") or "")[:400],
            }
        )
    return findings


def _has_project_manifest(root: Path, rel: str) -> bool:
    """True when the path can be ``pip install .`` / ``npm ci``'d (not a bare nested package)."""
    path = root if rel in {".", ""} else root / rel
    return (
        (path / "pyproject.toml").exists()
        or (path / "package.json").exists()
        or (path / "setup.py").exists()
    )


def _workdir_candidate_pool(root: Path, candidates: list[str]) -> list[str]:
    """Prefer dirs with pyproject/package.json; avoid nested ``server.py`` package folders."""
    strong = [c for c in candidates if _has_project_manifest(root, c)]
    if strong:
        return strong
    # Demo-style trees: only server.py at the package root.
    weak = [c for c in candidates if c in {".", ""} or (root / c / "server.py").exists()]
    return weak or list(candidates)


def resolve_workdir_choice(root: Path, chosen: str, candidates: list[str]) -> str:
    """Map an LLM/heuristic choice onto an installable candidate path."""
    chosen_s = str(chosen or "").strip().strip("/") or "."
    pool = _workdir_candidate_pool(root, candidates)

    if chosen_s in pool:
        return chosen_s

    # Nested path → longest matching pool prefix (e.g. src/time/src/pkg → src/time).
    best = ""
    for c in pool:
        if chosen_s == c or chosen_s.startswith(c.rstrip("/") + "/"):
            if len(c) >= len(best):
                best = c
    if best:
        return best

    if "." in pool:
        return "."
    if pool:
        return pool[0]
    raise AstGuardError(f"pick_workdir returned non-candidate: {chosen_s!r}")


def pick_workdir_from_module(
    pick_py: str,
    candidates: list[str],
    tree_summary: str,
    *,
    root: Path | None = None,
) -> str:
    mod = load_workdir_module(pick_py)
    chosen = mod.pick_workdir(list(candidates), tree_summary)
    if root is None:
        chosen_s = str(chosen or "").strip().strip("/") or "."
        if chosen_s in candidates:
            return chosen_s
        if chosen_s == "." and "." in candidates:
            return "."
        raise AstGuardError(f"pick_workdir returned non-candidate: {chosen_s!r}")
    return resolve_workdir_choice(root, str(chosen or ""), candidates)


async def generate_workdir_pick(
    root: Path,
    candidates: list[str],
    llm: LlmClient,
    *,
    scan_brief: str | None = None,
) -> WorkdirPick:
    if not candidates:
        return WorkdirPick(subdir=".", rationale="no candidates", source="heuristic", ok=True)
    if len(candidates) == 1:
        return WorkdirPick(
            subdir=candidates[0],
            rationale="single candidate",
            source="heuristic",
            ok=True,
        )

    # Prefer pyproject/package.json roots — nested server.py packages are not pip-installable alone.
    prompt_cands = _workdir_candidate_pool(root, candidates)
    tree = "\n".join(f"- {c}" for c in prompt_cands[:20])
    if use_heuristic_codegen(llm):
        pick_py = heuristic_workdir_py(prompt_cands, scan_brief)
        sub = pick_workdir_from_module(pick_py, prompt_cands, tree, root=root)
        why = (
            "heuristic workdir pick (brief-aware)"
            if scan_brief
            else "heuristic workdir pick"
        )
        return WorkdirPick(
            subdir=sub,
            rationale=why,
            source="heuristic",
            pick_py=pick_py,
            ok=True,
        )

    messages = build_workdir_prompt(root, prompt_cands, scan_brief=scan_brief)
    errors: list[str] = []
    raw: dict[str, Any] = {}
    for _ in range(3):
        try:
            raw = await llm.chat_json(messages)
        except (httpx.HTTPError, ValueError, TimeoutError, OSError) as exc:
            errors.append(str(exc))
            continue
        if isinstance(raw, dict) and raw:
            break
    pick_py = str(raw.get("workdir_pick_py") or "")
    rationale = str(raw.get("rationale") or "llm workdir pick")
    try:
        if not pick_py.strip():
            raise AstGuardError("LLM returned empty workdir_pick_py")
        sub = pick_workdir_from_module(pick_py, prompt_cands, tree, root=root)
        return WorkdirPick(
            subdir=sub,
            rationale=rationale[:400],
            source="llm",
            pick_py=pick_py,
            ok=True,
            errors=errors[:4],
        )
    except (AstGuardError, Exception) as exc:  # noqa: BLE001
        errors.append(str(exc))
        raise AstGuardError(
            "LLM workdir pick failed (no heuristic fallback): " + "; ".join(errors[:4])
        ) from exc


async def generate_executable_code(
    discovery: DiscoveryResult,
    llm: LlmClient,
    source_dir: Path,
    *,
    fixture_url: str = "http://fixture.local/",
    scan_brief: str | None = None,
    cache_key: str | None = None,
    repair_failure: str | None = None,
    previous: GeneratedCode | None = None,
    allow_fallback: bool = True,
    remember: bool = True,
) -> GeneratedCode:
    """Ask the LLM for the scan program. A repair note means the last program did not run."""
    if cache_key and not repair_failure:
        hit = load_cached(cache_key)
        if hit and hit.get("launch_sh") and hit.get("probe_py"):
            cached_source = hit.get("source") or "llm"
            # Live scans must not reuse heuristic/fixture cache entries.
            if use_heuristic_codegen(llm) or cached_source == "llm":
                return GeneratedCode.model_validate({**hit, "source": cached_source})
    if use_heuristic_codegen(llm):
        launch = validate_launch_script(heuristic_launch_sh(discovery, source_dir))
        probe = heuristic_probe_py(discovery)
        oracle = heuristic_oracle_py()
        setup = validate_setup_script(heuristic_setup_sh(source_dir))
        validate_probe_source(probe)
        validate_oracle_source(oracle)
        return GeneratedCode(
            launch_sh=launch,
            probe_py=probe,
            oracle_py=oracle,
            setup_sh=setup,
            services=[],
            rationale="heuristic executable artifacts (fixture LLM)",
            source="heuristic",
            launch_ok=True,
            probe_ok=True,
            oracle_ok=True,
            setup_ok=True,
            services_ok=True,
        )

    # Live path: LLM only — never substitute heuristic templates.
    _ = allow_fallback  # ignored; kept for call-site compatibility


    messages = build_codegen_prompt(
        source_dir,
        discovery,
        fixture_url,
        scan_brief=scan_brief,
        repair_failure=repair_failure,
        previous=previous,
    )
    errors: list[str] = []
    raw: dict[str, Any] = {}
    for _ in range(3):
        try:
            raw = await llm.chat_json(messages)
        except (httpx.HTTPError, ValueError, TimeoutError, OSError) as exc:
            errors.append(str(exc))
            continue
        if isinstance(raw, dict) and raw:
            break
    else:
        raw = {}

    if not raw:
        return GeneratedCode(
            launch_sh="",
            probe_py="",
            oracle_py="",
            setup_sh="",
            services=[],
            rationale="LLM returned no executable JSON",
            source="llm",
            launch_ok=False,
            probe_ok=False,
            oracle_ok=False,
            setup_ok=False,
            services_ok=False,
            errors=(errors or ["LLM returned no executable JSON"])[:8],
        )

    launch_sh = str(raw.get("launch_sh") or "")
    probe_py = str(raw.get("probe_py") or "")
    oracle_py = str(raw.get("oracle_py") or "")
    setup_sh = str(raw.get("setup_sh") or "")
    rationale = str(raw.get("rationale") or "llm executable codegen")
    launch_ok = probe_ok = oracle_ok = setup_ok = False
    services_ok = False
    services: list[ServiceSpec] = []

    try:
        setup_sh = validate_setup_script(setup_sh)
        setup_ok = True
    except ShellGuardError as exc:
        errors.append(f"setup_sh: {exc}")
        rationale += " [setup rejected]"

    try:
        launch_sh = validate_launch_script(launch_sh)
        launch_ok = True
    except ShellGuardError as exc:
        errors.append(f"launch_sh: {exc}")
        rationale += " [launch rejected]"

    try:
        services = validate_services(raw.get("services"))
        services_ok = True
    except ServiceGuardError as exc:
        errors.append(f"services: {exc}")
        rationale += " [services rejected]"

    try:
        validate_probe_source(probe_py)
        load_probe_module(probe_py)
        probe_ok = True
    except (AstGuardError, Exception) as exc:  # noqa: BLE001
        errors.append(f"probe_py: {exc}")
        rationale += " [probe rejected]"

    try:
        validate_oracle_source(oracle_py)
        load_oracle_module(oracle_py)
        oracle_ok = True
    except (AstGuardError, Exception) as exc:  # noqa: BLE001
        errors.append(f"oracle_py: {exc}")
        rationale += " [oracle rejected]"

    generated = GeneratedCode(
        launch_sh=launch_sh,
        probe_py=probe_py,
        oracle_py=oracle_py,
        setup_sh=setup_sh,
        services=services,
        rationale=rationale[:500],
        source="llm",
        launch_ok=launch_ok,
        probe_ok=probe_ok,
        oracle_ok=oracle_ok,
        setup_ok=setup_ok,
        services_ok=services_ok,
        errors=errors[:8],
    )
    runnable = (
        generated.setup_ok
        and generated.launch_ok
        and generated.probe_ok
        and generated.services_ok
    )
    if remember and cache_key and runnable and not generated.errors:
        store_cached(cache_key, generated.model_dump())
    return generated


def harness_from_generated(
    code: GeneratedCode,
    discovery: DiscoveryResult,
    fixture_url: str,
) -> ProbeHarness:
    mod = load_probe_module(code.probe_py)
    plans = plans_from_probe_module(mod, discovery, fixture_url)
    return ProbeHarness(
        server_summary=f"Executable probe module ({code.source}): {code.rationale}"[:300],
        entrypoint_guess="toolpain_launch.sh",
        plans=plans,
        source="llm" if code.source == "llm" else "heuristic",
        raw_notes="; ".join(code.errors) if code.errors else None,
    )


def write_setup_script(workdir: Path, setup_sh: str) -> Path:
    """Write the script and stop at the first failing command so a broken install fails the build."""
    lines = [
        line
        for line in setup_sh.splitlines()
        if line.strip() not in {"set -e", "set -eu", "set -euo pipefail"}
    ]
    if lines and lines[0].startswith("#!"):
        lines.insert(1, "set -e")
    else:
        lines.insert(0, "set -e")
    path = workdir / "toolpain_setup.sh"
    path.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
    path.chmod(0o755)
    return path


def write_launch_script(workdir: Path, launch_sh: str) -> Path:
    path = workdir / "toolpain_launch.sh"
    path.write_text(launch_sh, encoding="utf-8")
    path.chmod(0o755)
    return path
