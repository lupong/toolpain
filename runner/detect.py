"""Package / language detection → inputs for BuildPlan and LaunchPlan.

Heuristics only — no code execution. Prefer leaf packages that look like MCP servers.
"""

from __future__ import annotations

import json
import logging
import os
import re
import tomllib
from pathlib import Path

from runner.plans import Language, RepoManifest

log = logging.getLogger("toolpain.detect")

SKIP_DIR_NAMES = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".tox",
    "dist",
    "build",
    ".mypy_cache",
    ".ruff_cache",
    "tests",
    "test",
    "docs",
    "examples",
    "example",
    # ToolPain's own non-target trees (never scan these as the MCP server).
    "sandbox",
    "control_plane",
    "runner",
    "web",
    "design",
    "infra",
    "data",
}

MCP_IMPORT_RE = re.compile(
    r"^\s*(from\s+mcp(\.|\s)|import\s+mcp(\.|\s)|from\s+mcp\.server|FastMCP|MCPServer)",
    re.M,
)

MCP_NAME_HINT = re.compile(r"mcp|model.?context", re.I)


def _read_toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return {}


def _read_json(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _deps_blob(data: dict) -> str:
    parts: list[str] = []
    project = data.get("project") or {}
    for key in ("dependencies", "optional-dependencies"):
        val = project.get(key)
        if isinstance(val, list):
            parts.extend(str(x) for x in val)
        elif isinstance(val, dict):
            for items in val.values():
                if isinstance(items, list):
                    parts.extend(str(x) for x in items)
    return " ".join(parts).lower()


def _looks_like_mcp_server_py(path: Path) -> bool:
    server = path / "server.py"
    if not server.is_file():
        return False
    try:
        text = server.read_text(encoding="utf-8", errors="ignore")[:8000]
    except OSError:
        return False
    return bool(MCP_IMPORT_RE.search(text))


def _python_score(path: Path, data: dict) -> int:
    score = 0
    name = str((data.get("project") or {}).get("name") or path.name)
    deps = _deps_blob(data)
    scripts = (data.get("project") or {}).get("scripts") or {}
    script_names = " ".join(str(k) for k in scripts)
    has_server_py = (path / "server.py").exists()
    mcp_server_py = _looks_like_mcp_server_py(path)
    # Strong MCP-server signals (not merely "depends on mcp", which ToolPain itself does).
    if mcp_server_py:
        score += 55
    elif has_server_py:
        score += 15
    if any(str(k).startswith("mcp-server") or "mcp" in str(k) for k in scripts):
        score += 45
    elif scripts:
        score += 10
    if name.startswith("mcp-server-"):
        score += 30
    elif MCP_NAME_HINT.search(name):
        score += 15
    if "mcp" in deps and (mcp_server_py or scripts):
        score += 25
    elif "mcp" in deps:
        score += 5
    if name in {"mcp-server-time", "mcp-server-fetch", "mcp-server-git"}:
        score += 10
    # Soft-demote cloud-credential packages so monorepo defaults aren't EKS/IAM-first.
    heavy = (
        "eks",
        "ecs",
        "lambda",
        "bedrock",
        "sagemaker",
        "iam",
        "kubernetes",
        "k8s",
        "ccapi",
    )
    label = f"{name} {path.name}".lower()
    if any(h in label for h in heavy):
        score -= 20
    if any(h in label for h in ("time", "fetch", "filesystem", "echo", "memory")):
        score += 12
    if (path / "Dockerfile").exists():
        score += 5
    if path.name in {"src", "packages", "servers"}:
        score -= 5
    # Never treat the ToolPain scanner tree as the scan target.
    if name == "toolpain" or (path / "control_plane").is_dir() or (path / "runner").is_dir():
        score -= 100
    if "toolpain" in script_names:
        score -= 50
    return score


def _node_score(path: Path, data: dict) -> int:
    score = 10
    name = str(data.get("name") or path.name)
    deps = {
        **(data.get("dependencies") or {}),
        **(data.get("devDependencies") or {}),
        **(data.get("peerDependencies") or {}),
    }
    dep_names = " ".join(deps).lower()
    if "@modelcontextprotocol/sdk" in dep_names or "mcp" in dep_names:
        score += 50
    if MCP_NAME_HINT.search(name):
        score += 20
    if data.get("bin"):
        score += 15
    if data.get("main") or data.get("exports"):
        score += 5
    if (path / "Dockerfile").exists():
        score += 5
    return score


def _unknown_score(path: Path, name: str | None) -> int:
    """Score Go / Rust / PHP / Java roots the same way python|node get a baseline."""
    score = 10
    label = name or path.name
    if MCP_NAME_HINT.search(label):
        score += 40
    if (path / "README.md").exists():
        score += 10
    blob = ""
    for filename in ("go.mod", "Cargo.toml", "composer.json", "pom.xml", "build.gradle"):
        file = path / filename
        if file.is_file():
            try:
                blob += file.read_text(encoding="utf-8", errors="replace")[:4000].lower()
            except OSError:
                continue
    if "mcp" in blob or "modelcontextprotocol" in blob:
        score += 50
    if (path / "Dockerfile").exists():
        score += 5
    return score


def detect_language_at(path: Path) -> tuple[Language, str | None, list[str]]:
    """Return (language, package_name, relative manifest file names) for a directory."""
    manifests: list[str] = []
    py = path / "pyproject.toml"
    pkg = path / "package.json"
    name: str | None = None
    if py.exists():
        manifests.append("pyproject.toml")
        data = _read_toml(py)
        name = (data.get("project") or {}).get("name")
        if isinstance(name, str):
            return "python", name, manifests
        return "python", path.name, manifests
    if pkg.exists():
        manifests.append("package.json")
        data = _read_json(pkg)
        name = data.get("name") if isinstance(data.get("name"), str) else path.name
        return "node", name, manifests
    if (path / "server.py").exists():
        manifests.append("server.py")
        return "python", path.name, manifests
    for name in ("go.mod", "Cargo.toml", "composer.json", "pom.xml", "build.gradle"):
        if (path / name).exists():
            manifests.append(name)
            return "unknown", path.name, manifests
    return "unknown", None, manifests


def _iter_package_roots(root: Path) -> list[Path]:
    found: list[Path] = []
    for dirpath_str, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES and not d.startswith(".")]
        dirpath = Path(dirpath_str)
        rel_parts = dirpath.relative_to(root).parts
        if len(rel_parts) > 6:
            dirnames.clear()
            continue
        markers = (
            "pyproject.toml",
            "package.json",
            "server.py",
            "go.mod",
            "Cargo.toml",
            "composer.json",
            "pom.xml",
            "build.gradle",
        )
        if any(name in filenames for name in markers):
            found.append(dirpath)
    if not found:
        found.append(root)
    return found


def detect_package(root: Path, *, prefer_subdir: str | None = None) -> RepoManifest:
    """Pick the best MCP package workdir under ``root``."""
    root = root.resolve()
    if prefer_subdir:
        preferred = (root / prefer_subdir).resolve()
        if preferred.is_dir() and (preferred == root or root in preferred.parents):
            lang, name, manifests = detect_language_at(preferred)
            readme = "README.md" if (preferred / "README.md").exists() else None
            return RepoManifest(
                repo_url="",
                ref="",
                commit="local",
                root=root,
                workdir=preferred,
                language=lang,
                manifests=manifests,
                package_name=name,
                candidates=[str(preferred.relative_to(root))],
                readme_path=readme,
            )

    scored: list[tuple[int, Path, Language, str | None, list[str]]] = []
    for path in _iter_package_roots(root):
        lang, name, manifests = detect_language_at(path)
        if lang == "python":
            data = _read_toml(path / "pyproject.toml") if (path / "pyproject.toml").exists() else {}
            score = _python_score(path, data)
        elif lang == "node":
            data = _read_json(path / "package.json") if (path / "package.json").exists() else {}
            score = _node_score(path, data)
        else:
            score = _unknown_score(path, name)
        # Prefer deeper leaves when scores tie (monorepo package vs root).
        score += min(len(path.relative_to(root).parts), 4)
        scored.append((score, path, lang, name, manifests))

    scored.sort(key=lambda t: (-t[0], len(str(t[1]))))
    best = scored[0]
    candidates = []
    for _, path, _, _, _ in scored[:12]:
        try:
            candidates.append(str(path.relative_to(root)))
        except ValueError:
            candidates.append(str(path))

    workdir = best[1]
    readme = None
    if (workdir / "README.md").exists():
        try:
            readme = str((workdir / "README.md").relative_to(root))
        except ValueError:
            readme = "README.md"

    return RepoManifest(
        repo_url="",
        ref="",
        commit="local",
        root=root,
        workdir=workdir,
        language=best[2],
        manifests=best[4],
        package_name=best[3],
        candidates=candidates,
        readme_path=readme,
    )


def python_console_scripts(workdir: Path) -> list[str]:
    data = _read_toml(workdir / "pyproject.toml")
    scripts = (data.get("project") or {}).get("scripts") or {}
    return [str(k) for k in scripts]


def python_module_candidates(workdir: Path) -> list[str]:
    """Importable module names under src/ or package dir."""
    mods: list[str] = []
    src = workdir / "src"
    search = src if src.is_dir() else workdir
    for child in search.iterdir() if search.is_dir() else []:
        if child.name.startswith("_") or child.name.endswith(".egg-info"):
            continue
        if child.is_dir() and (child / "__init__.py").exists():
            mods.append(child.name)
        elif child.suffix == ".py" and child.stem not in {"setup", "conftest"}:
            mods.append(child.stem)
    return mods


def node_bin_commands(workdir: Path) -> list[list[str]]:
    data = _read_json(workdir / "package.json")
    out: list[list[str]] = []
    bin_field = data.get("bin")
    if isinstance(bin_field, str):
        out.append(["node", bin_field])
    elif isinstance(bin_field, dict):
        for rel in bin_field.values():
            out.append(["node", str(rel)])
    main = data.get("main")
    if isinstance(main, str):
        out.append(["node", main])
    return out
