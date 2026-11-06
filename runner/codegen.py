"""OpenAI (etc.) generates *executable* scan artifacts for ToolPain.

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
from runner.research import FakeLlm, LlmClient
from runner.shell_guard import ShellGuardError, validate_launch_script

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
    """``CODEGEN_MODE=heuristic|off`` disables LLM executable generation (incident switch)."""
    mode = (os.environ.get("CODEGEN_MODE") or "llm").strip().lower()
    return mode in {"heuristic", "off", "false", "0"}


class GeneratedCode(BaseModel):
    launch_sh: str
    probe_py: str
    oracle_py: str = ""
    rationale: str = ""
    source: Literal["llm", "heuristic"] = "llm"
    launch_ok: bool = False
    probe_ok: bool = False
    oracle_ok: bool = False
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


def _context(source_dir: Path, discovery: DiscoveryResult) -> str:
    parts = [f"SOURCE: {source_dir.name}"]
    readme = source_dir / "README.md"
    if readme.exists():
        parts.append("README.md:\n" + readme.read_text(encoding="utf-8", errors="ignore")[:2500])
    for name in ("pyproject.toml", "package.json"):
        p = source_dir / name
        if p.exists():
            parts.append(f"{name}:\n" + p.read_text(encoding="utf-8", errors="ignore")[:2500])
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


def build_codegen_prompt(
    source_dir: Path,
    discovery: DiscoveryResult,
    fixture_url: str,
    *,
    scan_brief: str | None = None,
) -> list[dict[str, str]]:
    user = (
        "TASK: EXECUTABLE_SCAN_CODE\n"
        f"{_brief_block(scan_brief)}"
        "Generate executable artifacts ToolPain will run when scanning this MCP server.\n"
        "Return ONE JSON object with keys:\n"
        "  launch_sh: tiny /bin/sh script with only `exec <cmd> <args…>` lines "
        '(example: "#!/bin/sh\\nexec mcp-server-time --local-timezone UTC\\n").\n'
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
        "never return a nested src package folder without its own pyproject/package.json.\n\n"
        f"CANDIDATES:\n" + "\n".join(tree_lines)
    )
    return [{"role": "user", "content": user}]


def heuristic_launch_sh(discovery: DiscoveryResult, source_dir: Path) -> str:
    pyproject = source_dir / "pyproject.toml"
    if pyproject.exists():
        text = pyproject.read_text(encoding="utf-8", errors="ignore")
        if "mcp-server-time" in text:
            return "#!/bin/sh\nexec mcp-server-time --local-timezone UTC\n"
        if "mcp-server-fetch" in text:
            return "#!/bin/sh\nexec mcp-server-fetch\n"
    if (source_dir / "server.py").exists():
        return "#!/bin/sh\nexec python /app/server.py\n"
    return "#!/bin/sh\nexec python -m mcp\n"


def heuristic_probe_py(discovery: DiscoveryResult) -> str:
    _ = discovery
    return (
        "def build_plans(tools, fixture_url):\n"
        "    plans = []\n"
        "    for t in tools:\n"
        "        name = t['name'] if isinstance(t, dict) else str(t)\n"
        "        schema = t.get('input_schema') if isinstance(t, dict) else {}\n"
        "        undocumented = bool(t.get('undocumented')) if isinstance(t, dict) else False\n"
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
        "                args[key] = fixture_url if 'url' in key.lower() else 'toolpain-probe'\n"
        "        plans.append({\n"
        "            'tool': name,\n"
        "            'arguments': args,\n"
        "            'rationale': 'heuristic executable probe',\n"
        "            'expect_decoy': undocumented or name == 'fetch_report',\n"
        "            'expect_hosts': (['collector.sinkhole.local'] if "
        "(undocumented or name == 'fetch_report') else []),\n"
        "            'expect_files': (['/workspace/canaries/decoy_secret.txt'] if "
        "(undocumented or name == 'fetch_report') else []),\n"
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


def heuristic_workdir_py(candidates: list[str]) -> str:
    prefer = next(
        (c for c in candidates if "time" in c.lower() or "mcp" in c.lower() or c not in {".", ""}),
        candidates[0] if candidates else ".",
    )
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
                expect_hosts=[str(x) for x in (item.get("expect_hosts") or [])],
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
                expect_hosts=[str(x) for x in (item.get("expect_hosts") or [])],
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
    if isinstance(llm, FakeLlm) or codegen_forced_heuristic():
        pick_py = heuristic_workdir_py(prompt_cands)
        sub = pick_workdir_from_module(pick_py, prompt_cands, tree, root=root)
        return WorkdirPick(
            subdir=sub,
            rationale="heuristic workdir pick",
            source="heuristic",
            pick_py=pick_py,
            ok=True,
        )

    messages = build_workdir_prompt(root, prompt_cands, scan_brief=scan_brief)
    errors: list[str] = []
    raw: dict[str, Any] = {}
    for _ in range(2):
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
        sub = pick_workdir_from_module(pick_py, prompt_cands, tree, root=root)
        return WorkdirPick(
            subdir=sub,
            rationale=rationale[:400],
            source="llm" if raw else "heuristic",
            pick_py=pick_py,
            ok=True,
            errors=errors[:4],
        )
    except (AstGuardError, Exception) as exc:  # noqa: BLE001
        errors.append(str(exc))
        pick_py = heuristic_workdir_py(prompt_cands)
        sub = pick_workdir_from_module(pick_py, prompt_cands, tree, root=root)
        return WorkdirPick(
            subdir=sub,
            rationale=rationale[:400] + " [workdir fallback]",
            source="heuristic",
            pick_py=pick_py,
            ok=True,
            errors=errors[:4],
        )


async def generate_executable_code(
    discovery: DiscoveryResult,
    llm: LlmClient,
    source_dir: Path,
    *,
    fixture_url: str = "http://fixture.local/",
    scan_brief: str | None = None,
    cache_key: str | None = None,
) -> GeneratedCode:
    """Ask the LLM for launch.sh + probe.py + oracle; validate; fall back to heuristics."""
    if cache_key:
        hit = load_cached(cache_key)
        if hit and hit.get("launch_sh") and hit.get("probe_py"):
            return GeneratedCode.model_validate({**hit, "source": hit.get("source") or "llm"})
    if isinstance(llm, FakeLlm) or codegen_forced_heuristic():
        launch = validate_launch_script(heuristic_launch_sh(discovery, source_dir))
        probe = heuristic_probe_py(discovery)
        oracle = heuristic_oracle_py()
        validate_probe_source(probe)
        validate_oracle_source(oracle)
        why = (
            "CODEGEN_MODE"
            if codegen_forced_heuristic() and not isinstance(llm, FakeLlm)
            else "fake LLM"
        )
        return GeneratedCode(
            launch_sh=launch,
            probe_py=probe,
            oracle_py=oracle,
            rationale=f"heuristic executable artifacts ({why})",
            source="heuristic",
            launch_ok=True,
            probe_ok=True,
            oracle_ok=True,
        )

    messages = build_codegen_prompt(source_dir, discovery, fixture_url, scan_brief=scan_brief)
    errors: list[str] = []
    raw: dict[str, Any] = {}
    for _ in range(2):
        try:
            raw = await llm.chat_json(messages)
        except (httpx.HTTPError, ValueError, TimeoutError, OSError) as exc:
            errors.append(str(exc))
            continue
        if isinstance(raw, dict) and raw:
            break
    else:
        raw = {}

    launch_sh = str(raw.get("launch_sh") or "")
    probe_py = str(raw.get("probe_py") or "")
    oracle_py = str(raw.get("oracle_py") or "")
    rationale = str(raw.get("rationale") or "llm executable codegen")
    launch_ok = probe_ok = oracle_ok = False

    try:
        launch_sh = validate_launch_script(launch_sh)
        launch_ok = True
    except ShellGuardError as exc:
        errors.append(f"launch_sh: {exc}")
        launch_sh = validate_launch_script(heuristic_launch_sh(discovery, source_dir))
        launch_ok = True
        rationale += " [launch fallback]"

    try:
        validate_probe_source(probe_py)
        load_probe_module(probe_py)
        probe_ok = True
    except (AstGuardError, Exception) as exc:  # noqa: BLE001
        errors.append(f"probe_py: {exc}")
        probe_py = heuristic_probe_py(discovery)
        validate_probe_source(probe_py)
        probe_ok = True
        rationale += " [probe fallback]"

    try:
        validate_oracle_source(oracle_py)
        load_oracle_module(oracle_py)
        oracle_ok = True
    except (AstGuardError, Exception) as exc:  # noqa: BLE001
        errors.append(f"oracle_py: {exc}")
        oracle_py = heuristic_oracle_py()
        validate_oracle_source(oracle_py)
        oracle_ok = True
        rationale += " [oracle fallback]"

    generated = GeneratedCode(
        launch_sh=launch_sh,
        probe_py=probe_py,
        oracle_py=oracle_py,
        rationale=rationale[:500],
        source="heuristic" if errors or not raw else "llm",
        launch_ok=launch_ok,
        probe_ok=probe_ok,
        oracle_ok=oracle_ok,
        errors=errors[:8],
    )
    if cache_key and generated.launch_ok and generated.probe_ok:
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


def write_launch_script(workdir: Path, launch_sh: str) -> Path:
    path = workdir / "toolpain_launch.sh"
    path.write_text(launch_sh, encoding="utf-8")
    path.chmod(0o755)
    return path
