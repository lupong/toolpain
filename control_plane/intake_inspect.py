"""Pre-scan monorepo inspection via GitHub's public API.

Lists likely MCP package paths so the UI can require a single-server choice
before spinning a scanner VM. Candidate discovery mirrors ``runner.detect``
markers (manifests anywhere in the tree), not only ``src|packages|servers``.
"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

import httpx
from openai import AsyncOpenAI

from control_plane.config import Settings
from control_plane.llm import resolve_llm_backend
from control_plane.models import GITHUB_URL_RE

log = logging.getLogger("toolpain.intake_inspect")

_MAX_CANDIDATES = 80
_PACKAGE_ROOTS = frozenset({"src", "packages", "servers", "mcp-servers"})
_MCP_NAME_RE = re.compile(r"(^|[-_.])mcp([-_.]|server)|mcp\.server|mcp-server", re.I)
_MARKER_NAMES = frozenset(
    {
        "pyproject.toml",
        "package.json",
        "server.py",
        "go.mod",
        "Cargo.toml",
        "composer.json",
        "pom.xml",
        "build.gradle",
    }
)
# Align with runner.detect.SKIP_DIR_NAMES (+ intake-only noise).
_SKIP_SEGMENTS = frozenset(
    {
        "test",
        "tests",
        "fixtures",
        "vscode",
        "perf",
        "node_modules",
        "__pycache__",
        "docs",
        "examples",
        "example",
        "eng",
        "tools",
        "internal",
        "vendor",
        "third_party",
        "third-party",
        "samples",
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "dist",
        "build",
        ".hugo",
        ".ci",
        ".github",
        ".gemini",
    }
)

FIXTURE_MONOREPO_MESSAGE = (
    "This repository contains {count} MCP servers. "
    "ToolPain scans one server per run — choose which one to scan before starting."
)


@dataclass(frozen=True)
class IntakeInspection:
    repo_url: str
    ref: str
    candidates: list[str]
    message: str | None = None

    @property
    def count(self) -> int:
        return len(self.candidates)

    @property
    def multi(self) -> bool:
        return self.count > 1

    def as_dict(self) -> dict[str, Any]:
        return {
            "repo_url": self.repo_url,
            "ref": self.ref,
            "multi": self.multi,
            "count": self.count,
            "candidates": list(self.candidates),
            "message": self.message,
        }


def parse_github_repo(repo_url: str) -> tuple[str, str]:
    m = GITHUB_URL_RE.match(repo_url.strip().rstrip("/"))
    if not m:
        raise ValueError("repo_url must be https://github.com/<owner>/<repo>")
    return m.group("owner"), m.group("repo")


def _is_manifest_name(name: str) -> bool:
    return name in _MARKER_NAMES or name.endswith(".csproj")


def _normalize_repo_path(raw: str) -> str:
    """Normalize a git tree path without ``lstrip('./')`` (that eats ``.hugo`` → ``hugo``)."""
    p = raw.strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p


def _canonical_package_root(path: str) -> str | None:
    """Map nested paths to ``src|packages|servers/<package>`` when possible."""
    parts = PurePosixPath(_normalize_repo_path(path)).parts
    if len(parts) < 2 or parts[0] not in _PACKAGE_ROOTS:
        return None
    package = parts[1]
    if package.lower() in _SKIP_SEGMENTS or package.startswith("."):
        return None
    return f"{parts[0]}/{package}"


def candidates_from_tree_paths(paths: list[str]) -> list[str]:
    """Derive MCP package dirs from a flat list of git tree paths.

    Matches runner package-root markers (pyproject/package.json/go.mod/…) so
    repos like googleapis/genai-toolbox (``npm/*``, ``pypi``, root ``go.mod``)
    are flagged before provision — not only awslabs-style ``src/<pkg>`` layouts.
    """
    found: set[str] = set()
    for raw in paths:
        p = _normalize_repo_path(raw)
        if not p or p.endswith("/"):
            continue
        parts = PurePosixPath(p).parts
        if not parts:
            continue
        name = parts[-1]
        if not _is_manifest_name(name):
            continue
        parent_segs = [seg.lower() for seg in parts[:-1]]
        if any(seg in _SKIP_SEGMENTS or seg.startswith(".") for seg in parent_segs):
            continue

        collapsed = _canonical_package_root(p)
        if collapsed is not None:
            package_leaf = collapsed.split("/", 1)[1]
            deeper = parent_segs[1:]  # under src/<pkg>/…
            if any(seg in _SKIP_SEGMENTS for seg in deeper) and not _MCP_NAME_RE.search(
                package_leaf
            ):
                continue
            found.add(collapsed)
            continue

        # Non-standard layout (npm/server, pypi, root go.mod, …).
        parent = "." if len(parts) == 1 else str(PurePosixPath(*parts[:-1]))
        if parent != "." and len(PurePosixPath(parent).parts) > 3:
            continue
        found.add(parent)

    ordered = sorted(found, key=lambda c: (c == ".", c))
    return ordered[:_MAX_CANDIDATES]


async def _fetch_tree_paths(owner: str, repo: str, ref: str) -> list[str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "toolpain-intake",
    }
    url = f"https://api.github.com/repos/{owner}/{repo}/git/trees/{ref}"
    async with httpx.AsyncClient(
        timeout=30.0, headers=headers, follow_redirects=True
    ) as client:
        r = await client.get(url, params={"recursive": "1"})
        if r.status_code == 404:
            # Branch tip may need commit SHA from the branch API.
            br = await client.get(f"https://api.github.com/repos/{owner}/{repo}/branches/{ref}")
            if br.status_code == 200:
                sha = (br.json().get("commit") or {}).get("sha")
                if sha:
                    r = await client.get(
                        f"https://api.github.com/repos/{owner}/{repo}/git/trees/{sha}",
                        params={"recursive": "1"},
                    )
        if r.status_code == 200:
            data = r.json()
            tree = data.get("tree") or []
            paths = [str(item.get("path") or "") for item in tree if item.get("path")]
            if paths:
                return paths
        # Fallback: list common monorepo roots + packaging dirs.
        paths: list[str] = []
        for pref in ("src", "packages", "servers", "mcp-servers", "npm", "pypi"):
            cr = await client.get(
                f"https://api.github.com/repos/{owner}/{repo}/contents/{pref}",
                params={"ref": ref},
            )
            if cr.status_code != 200:
                continue
            items = cr.json()
            if not isinstance(items, list):
                continue
            for item in items:
                if item.get("type") == "dir" and item.get("name"):
                    paths.append(f"{pref}/{item['name']}/package.json")
                    paths.append(f"{pref}/{item['name']}/pyproject.toml")
        # Root manifests
        for marker in ("go.mod", "pyproject.toml", "package.json"):
            paths.append(marker)
        if paths:
            return paths
        if r.status_code >= 400:
            log.warning("github tree fetch failed %s %s", r.status_code, r.text[:200])
            raise RuntimeError(f"could not inspect github.com/{owner}/{repo}@{ref}")
        return []


def fixture_monorepo_message(count: int) -> str:
    return FIXTURE_MONOREPO_MESSAGE.format(count=count)


async def draft_monorepo_message(
    settings: Settings,
    *,
    repo_url: str,
    count: int,
    samples: list[str],
) -> str:
    """LLM-written intake copy; fixture/canned when offline."""
    fallback = fixture_monorepo_message(count)
    if count <= 1:
        return fallback
    backend = resolve_llm_backend(settings)
    if backend is None or settings.llm_mode == "fixture":
        return fallback

    base_url, api_key, model = backend
    sample_blob = ", ".join(samples[:12])
    user = (
        "TASK: MULTI_SERVER_INTAKE_COPY\n"
        f"repo: {repo_url}\n"
        f"server_count: {count}\n"
        f"sample_paths: {sample_blob}\n"
        "Write a short JSON object with key message (string, 2-4 sentences). "
        "Explain generically that this GitHub repo contains multiple MCP servers "
        "or packaging roots, ToolPain detects that and scans exactly one per run, "
        "and the user must pick which path to scan. Plain language, no markdown, no hype. "
        "Do not frame this as an AWS-only or vendor-specific feature. "
        "Only mention a vendor if it appears in the sample_paths the user must choose."
    )
    client = AsyncOpenAI(api_key=api_key, base_url=base_url)
    if not model:
        models = await client.models.list()
        model = models.data[0].id if models.data else (
            settings.vultr_inference_model or "deepseek-v4.1-flash-1017"
        )
    try:
        resp = await client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": "Respond with a single JSON object only. No markdown.",
                },
                {"role": "user", "content": user},
            ],
            temperature=0.2,
        )
        content = resp.choices[0].message.content or "{}"
        content = content.strip()
        if content.startswith("```"):
            content = re.sub(r"^```(?:json)?\s*", "", content)
            content = re.sub(r"\s*```$", "", content)
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            start, end = content.find("{"), content.rfind("}")
            data = json.loads(content[start : end + 1]) if start >= 0 and end > start else {}
        msg = data.get("message") if isinstance(data, dict) else None
        if isinstance(msg, str) and msg.strip():
            return msg.strip()[:800]
    except Exception as exc:  # noqa: BLE001 — intake must not fail the form on LLM blips
        log.warning("monorepo intake LLM failed: %s", exc)
    return fallback


async def inspect_repo(
    settings: Settings,
    repo_url: str,
    ref: str = "main",
    *,
    tree_paths: list[str] | None = None,
    with_message: bool = True,
) -> IntakeInspection:
    """Inspect a public GitHub repo for multiple MCP package candidates."""
    repo_url = repo_url.strip().rstrip("/")
    ref = (ref or "main").strip() or "main"
    owner, repo = parse_github_repo(repo_url)
    paths = tree_paths if tree_paths is not None else await _fetch_tree_paths(owner, repo, ref)
    candidates = candidates_from_tree_paths(paths)
    message = None
    if with_message and len(candidates) > 1:
        message = await draft_monorepo_message(
            settings,
            repo_url=repo_url,
            count=len(candidates),
            samples=candidates,
        )
    return IntakeInspection(
        repo_url=repo_url,
        ref=ref,
        candidates=candidates,
        message=message,
    )
