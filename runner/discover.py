"""Four-source tool discovery.

* **R** runtime default  - start the server as-is and ``tools/list``.
* **F** runtime + flags  - parse ``--help`` / README for capability flags, retry with each.
* **S** static source    - regex/AST scan of the repo for tool registrations.
* **D** docs             - tools named in the README (LLM extraction, or regex in fake mode).

A tool seen in S/R/F but absent from D is *undocumented*; a tool seen only via F is
*hidden behind a flag*.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Awaitable, Callable, Iterable, Sequence
from pathlib import Path
from typing import Protocol

from mcp import StdioServerParameters

from runner.mcp_client import McpClientError, snapshot_server
from runner.models import (
    SOURCE_ORDER,
    DiscoveredTool,
    DiscoveryResult,
    ServerSnapshot,
    SourceCode,
    StaticHit,
    ToolInfo,
)

MAX_FLAG_ATTEMPTS = 5
MAX_STATIC_FILE_BYTES = 1_000_000
SNIPPET_LINES = 60
SKIP_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    ".venv",
    "venv",
    "__pycache__",
    "test",
    "tests",
    "__tests__",
    "site-packages",
}
STATIC_SUFFIXES = {".py", ".ts", ".tsx", ".js", ".mjs", ".cjs"}
FLAG_KEYWORDS = (
    "cap",
    "enable",
    "allow",
    "unsafe",
    "experimental",
    "all",
    "vision",
    "pdf",
    "tools",
    "dangerous",
    "full",
    "advanced",
    "admin",
    "write",
    "extra",
    "include",
)
FLAG_BLOCKLIST = {"help", "version", "port", "host", "config", "headless", "debug", "verbose"}


class Launcher(Protocol):
    """Builds the stdio launch parameters for the target (docker run in production)."""

    def __call__(
        self, extra_args: Sequence[str] = (), label: str = "run"
    ) -> StdioServerParameters: ...


DocsExtractor = Callable[[str], Awaitable[list[str]]]
HelpProvider = Callable[[], Awaitable[str]]

# ---------------------------------------------------------------------------
# D: docs
# ---------------------------------------------------------------------------

_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")
_IDENT = r"[A-Za-z_][A-Za-z0-9_.\-]*"
_BULLET_RE = re.compile(rf"^\s*(?:[-*+]|\d+\.)\s+\**`?({_IDENT})`?\**\s*(?::|-|–|—|\(|$)")
_TABLE_RE = re.compile(rf"^\|\s*\**`?({_IDENT})`?\**\s*\|")
_TOOLISH_BULLET_RE = re.compile(r"^\s*(?:[-*+])\s+\**`([a-z][a-z0-9]*_[a-z0-9_]+)`\**")
_HEADING_NAME_RE = re.compile(rf"^`?({_IDENT})`?$")
_TABLE_HEADER_WORDS = {"name", "tool", "tools", "description", "parameter", "parameters"}


def parse_docs_tools(readme: str) -> list[str]:
    """Regex extraction of tool names from README markdown (used in fake mode).

    Nested bullets under a tool, and bullets under a tool subheading, are
    arguments. They are not extra tools.
    """
    found: list[str] = []
    tools_level: int | None = None
    inside_tool_heading = False
    tool_bullet_indent: int | None = None
    in_fence = False
    for line in readme.splitlines():
        if line.strip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        heading = _HEADING_RE.match(line)
        if heading:
            level, text = len(heading.group(1)), heading.group(2)
            if tools_level is not None and level <= tools_level:
                tools_level = None
                inside_tool_heading = False
                tool_bullet_indent = None
            if tools_level is not None and level > tools_level:
                inside_tool_heading = True
                m = _HEADING_NAME_RE.match(text)
                if m:
                    found.append(m.group(1))
            elif re.search(r"\btools?\b", text, re.IGNORECASE):
                tools_level = level
                inside_tool_heading = False
                tool_bullet_indent = None
            continue
        if tools_level is not None:
            if inside_tool_heading:
                continue
            table = _TABLE_RE.match(line)
            bullet = _BULLET_RE.match(line)
            m = bullet or table
            if not m or m.group(1).lower() in _TABLE_HEADER_WORDS:
                continue
            if table:
                found.append(m.group(1))
                continue
            indent = len(line) - len(line.lstrip(" "))
            if tool_bullet_indent is None or indent < tool_bullet_indent:
                tool_bullet_indent = indent
            if indent <= tool_bullet_indent:
                found.append(m.group(1))
        else:
            m = _TOOLISH_BULLET_RE.match(line)
            if m:
                found.append(m.group(1))
    return list(dict.fromkeys(found))


async def extract_docs_tools(readme: str, extractor: DocsExtractor | None = None) -> list[str]:
    """LLM extraction when an extractor is supplied (live mode); regex otherwise."""
    if extractor is not None:
        try:
            names = await extractor(readme)
        except Exception:
            names = []
        if names:
            return list(dict.fromkeys(names))
    return parse_docs_tools(readme)


# ---------------------------------------------------------------------------
# S: static source scan
# ---------------------------------------------------------------------------

_TS_REGISTER_RES = [
    re.compile(r"""\.(?:tool|registerTool|addTool)\(\s*['"`]([A-Za-z][\w.\-]*)['"`]"""),
]
_TS_NAME_RE = re.compile(r"""\bname\s*:\s*['"`]([A-Za-z][\w.\-]*)['"`]""")
_TS_CONTEXT_RE = re.compile(r"description|inputSchema")
_PY_TOOL_CALL_RE = re.compile(r"""\bTool\(\s*name\s*=\s*['"]([A-Za-z][\w.\-]*)['"]""")
_PY_DECORATOR_RE = re.compile(r"^\s*@\w+(?:\.\w+)*\.tool\b")
_PY_DEF_RE = re.compile(r"^\s*(?:async\s+)?def\s+(\w+)")


def _iter_source_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if path.suffix not in STATIC_SUFFIXES or not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts[:-1]
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if re.search(r"\.(test|spec)\.", path.name):
            continue
        try:
            if path.stat().st_size > MAX_STATIC_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def _module_constants(tree: ast.Module) -> dict[str, str]:
    """Module-level ``NAME = "string"`` assignments (hosts, paths the code refers to)."""
    consts: dict[str, str] = {}
    for node in tree.body:
        if (
            isinstance(node, ast.Assign)
            and isinstance(node.value, ast.Constant)
            and isinstance(node.value.value, str)
        ):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    consts[target.id] = node.value.value
    return consts


def _python_hits(rel: str, text: str) -> list[StaticHit]:
    hits: list[StaticHit] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return _python_regex_hits(rel, text)
    consts = _module_constants(tree)
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for dec in node.decorator_list:
            target = dec.func if isinstance(dec, ast.Call) else dec
            if not (isinstance(target, ast.Attribute) and target.attr == "tool"):
                continue
            name = node.name
            if isinstance(dec, ast.Call):
                for kw in dec.keywords:
                    if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                        name = str(kw.value.value)
                if dec.args and isinstance(dec.args[0], ast.Constant):
                    name = str(dec.args[0].value)
            snippet = ast.get_source_segment(text, node) or ""
            refs = {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
            hits.append(
                StaticHit(
                    name=name,
                    file=rel,
                    line=node.lineno,
                    snippet=snippet[:4000],
                    pattern="@tool",
                    context={k: v for k, v in consts.items() if k in refs},
                )
            )
    lines = text.splitlines()
    for m in _PY_TOOL_CALL_RE.finditer(text):
        line_no = text.count("\n", 0, m.start()) + 1
        hits.append(
            StaticHit(
                name=m.group(1),
                file=rel,
                line=line_no,
                snippet="\n".join(lines[line_no - 1 : line_no - 1 + SNIPPET_LINES])[:4000],
                pattern="Tool(name=)",
            )
        )
    return hits


def _python_regex_hits(rel: str, text: str) -> list[StaticHit]:
    hits: list[StaticHit] = []
    lines = text.splitlines()
    for i, line in enumerate(lines):
        if not _PY_DECORATOR_RE.match(line):
            continue
        for j in range(i + 1, min(i + 6, len(lines))):
            m = _PY_DEF_RE.match(lines[j])
            if m:
                snippet = "\n".join(lines[j : j + SNIPPET_LINES])
                hits.append(
                    StaticHit(
                        name=m.group(1),
                        file=rel,
                        line=j + 1,
                        snippet=snippet[:4000],
                        pattern="@tool",
                    )
                )
                break
    return hits


def _script_hits(rel: str, text: str) -> list[StaticHit]:
    hits: list[StaticHit] = []
    lines = text.splitlines()
    seen: set[tuple[str, int]] = set()

    def add(name: str, line_no: int, pattern: str) -> None:
        if (name, line_no) in seen:
            return
        seen.add((name, line_no))
        snippet = "\n".join(lines[line_no - 1 : line_no - 1 + SNIPPET_LINES])
        hits.append(
            StaticHit(name=name, file=rel, line=line_no, snippet=snippet[:4000], pattern=pattern)
        )

    for pat in _TS_REGISTER_RES:
        for m in pat.finditer(text):
            add(m.group(1), text.count("\n", 0, m.start()) + 1, "server.tool(")
    for m in _TS_NAME_RE.finditer(text):
        line_no = text.count("\n", 0, m.start()) + 1
        window = "\n".join(lines[line_no - 1 : line_no + 6])
        if _TS_CONTEXT_RE.search(window):
            add(m.group(1), line_no, "name:")
    return hits


def scan_static(source_dir: Path) -> list[StaticHit]:
    """Find tool registrations in Python and TypeScript/JavaScript sources."""
    hits: list[StaticHit] = []
    for path in _iter_source_files(source_dir):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(source_dir))
        if path.suffix == ".py":
            hits.extend(_python_hits(rel, text))
        else:
            hits.extend(_script_hits(rel, text))
    return hits


# ---------------------------------------------------------------------------
# F: flag extraction
# ---------------------------------------------------------------------------

_FLAG_RE = re.compile(r"(--[a-z][a-z0-9\-]+)(?:[= ]<?([A-Za-z0-9_,|\-]+)>?)?")


def extract_flag_candidates(*texts: str, limit: int = MAX_FLAG_ATTEMPTS) -> list[list[str]]:
    """Return argument lists worth retrying (one list per attempt)."""
    attempts: list[list[str]] = []
    seen: set[str] = set()
    for text in texts:
        for m in _FLAG_RE.finditer(text or ""):
            flag, value = m.group(1), m.group(2)
            bare = flag[2:]
            if bare in FLAG_BLOCKLIST or not any(k in bare for k in FLAG_KEYWORDS):
                continue
            if value and re.search(r"[,|]", value):
                args = [f"{flag}={value.replace('|', ',')}"]
            else:
                args = [flag]
            key = " ".join(args)
            if key in seen:
                continue
            seen.add(key)
            attempts.append(args)
            if len(attempts) >= limit:
                return attempts
    return attempts


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def _ordered(sources: set[SourceCode]) -> list[SourceCode]:
    return sorted(sources, key=SOURCE_ORDER.index)


async def discover(
    launch: Launcher,
    *,
    source_dir: Path | None = None,
    readme_text: str | None = None,
    help_provider: HelpProvider | None = None,
    docs_extractor: DocsExtractor | None = None,
    init_timeout: float = 60.0,
) -> DiscoveryResult:
    """Run all four discovery sources and merge them into one result."""
    notes: list[str] = []

    # R: runtime default
    base = await snapshot_server(launch((), "discover"), init_timeout=init_timeout)
    runtime_names = {t.name for t in base.tools}

    # D: docs
    docs_tools = await extract_docs_tools(readme_text, docs_extractor) if readme_text else []

    # S: static
    hits = scan_static(source_dir) if source_dir and source_dir.is_dir() else []

    # F: runtime with flags
    help_text = ""
    if help_provider is not None:
        try:
            help_text = await help_provider()
        except Exception as exc:
            notes.append(f"help provider failed: {exc!r}")
    attempts = extract_flag_candidates(help_text, readme_text or "")
    flag_names: dict[str, list[str]] = {}
    flagged_tools: dict[str, ToolInfo] = {}
    for args in attempts:
        label = " ".join(args)
        try:
            snap = await snapshot_server(launch(args, "flags"), init_timeout=init_timeout)
        except (McpClientError, OSError) as exc:
            notes.append(f"flag attempt {label!r} failed: {str(exc)[:120]}")
            continue
        for tool in snap.tools:
            flag_names.setdefault(tool.name, []).append(label)
            flagged_tools.setdefault(tool.name, tool)

    return _merge(
        base=base,
        flag_tools=flagged_tools,
        flag_names=flag_names,
        hits=hits,
        docs_tools=docs_tools,
        runtime_names=runtime_names,
        attempts=[" ".join(a) for a in attempts],
        notes=notes,
        have_docs=readme_text is not None,
    )


def _schema_properties(tools: list[ToolInfo]) -> set[str]:
    """Argument names advertised by a runtime tool schema."""
    names: set[str] = set()
    for tool in tools:
        props = tool.input_schema.get("properties") if isinstance(tool.input_schema, dict) else None
        if isinstance(props, dict):
            names.update(str(key) for key in props)
    return names


def _merge(
    *,
    base: ServerSnapshot,
    flag_tools: dict[str, ToolInfo],
    flag_names: dict[str, list[str]],
    hits: list[StaticHit],
    docs_tools: list[str],
    runtime_names: set[str],
    attempts: list[str],
    notes: list[str],
    have_docs: bool,
) -> DiscoveryResult:
    by_name: dict[str, DiscoveredTool] = {}
    sources: dict[str, set[SourceCode]] = {}

    def entry(name: str) -> DiscoveredTool:
        if name not in by_name:
            by_name[name] = DiscoveredTool(name=name)
            sources[name] = set()
        return by_name[name]

    for tool in base.tools:
        e = entry(tool.name)
        e.description, e.input_schema = tool.description, tool.input_schema
        sources[tool.name].add("R")
    for name, tool in flag_tools.items():
        e = entry(name)
        if not e.description:
            e.description, e.input_schema = tool.description, tool.input_schema
        sources[name].add("F")
        e.flags = sorted(set(e.flags) | set(flag_names.get(name, [])))
    for hit in hits:
        e = entry(hit.name)
        e.static_hits.append(hit)
        sources[hit.name].add("S")
    argument_names = _schema_properties([*base.tools, *flag_tools.values()])
    known = set(runtime_names) | set(flag_tools) | {hit.name for hit in hits}
    kept_docs = [name for name in docs_tools if name in known or name not in argument_names]
    for name in kept_docs:
        entry(name)
        sources[name].add("D")

    doc_set = set(kept_docs)
    for name, e in by_name.items():
        src = sources[name]
        e.sources = _ordered(src)
        e.documented = "D" in src
        e.undocumented = have_docs and "D" not in src and bool(src & {"S", "R", "F"})
        e.hidden_behind_flag = "F" in src and "R" not in src
        if name in doc_set and not (src & {"S", "R", "F"}):
            e.documented = True

    return DiscoveryResult(
        server_name=base.server_name,
        tools=sorted(by_name.values(), key=lambda t: t.name),
        resources=base.resources,
        prompts=base.prompts,
        docs_tools=kept_docs,
        flag_candidates=attempts,
        notes=notes,
    )
