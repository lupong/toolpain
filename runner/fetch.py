"""Fetch stage: packaged git clone → RepoManifest.

Refs and URLs are passed as argv to ``git`` (never through a shell). Only
``https://github.com/<owner>/<repo>`` is accepted.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
from pathlib import Path

from control_plane.models import GITHUB_URL_RE
from runner.detect import detect_language_at, detect_package
from runner.plans import RepoManifest

log = logging.getLogger("toolpain.fetch")

REF_RE = re.compile(r"^[A-Za-z0-9._/-]+$")
SHA_RE = re.compile(r"^[0-9a-f]{7,40}$", re.IGNORECASE)


class FetchError(RuntimeError):
    pass


def validate_repo_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if not GITHUB_URL_RE.match(url):
        raise FetchError(f"unsupported repo URL (need https://github.com/owner/repo): {url}")
    return url


def validate_ref(ref: str) -> str:
    ref = ref.strip()
    if not ref or not REF_RE.match(ref) or ".." in ref:
        raise FetchError(f"invalid git ref: {ref!r}")
    return ref


def _run_git(argv: list[str], *, timeout: float = 180.0) -> str:
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise FetchError(f"git failed to start: {exc}") from exc
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()[:400]
        raise FetchError(f"{' '.join(argv[:3])} failed: {err}")
    return proc.stdout.strip()


def git_commit(path: Path) -> str:
    try:
        return (
            _run_git(["git", "-C", str(path), "rev-parse", "--short", "HEAD"], timeout=10)
            or "local"
        )
    except FetchError:
        return "local"


def _readme_rel(root: Path, workdir: Path) -> str | None:
    readme = workdir / "README.md"
    if not readme.exists():
        return None
    try:
        return str(readme.relative_to(root))
    except ValueError:
        return "README.md"


def fetch_repo(
    repo_url: str,
    ref: str,
    dest: Path,
    *,
    prefer_subdir: str | None = None,
) -> RepoManifest:
    """Shallow-clone ``repo_url`` at ``ref`` into ``dest`` and detect the MCP package root."""
    url = validate_repo_url(repo_url)
    ref = validate_ref(ref)
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)

    if SHA_RE.match(ref):
        _run_git(["git", "clone", "--depth", "1", url, str(dest)], timeout=300)
        _run_git(["git", "-C", str(dest), "fetch", "--depth", "1", "origin", ref], timeout=180)
        _run_git(["git", "-C", str(dest), "checkout", ref], timeout=60)
    else:
        _run_git(
            ["git", "clone", "--depth", "1", "--branch", ref, url, str(dest)],
            timeout=300,
        )

    commit = git_commit(dest)
    manifest = detect_package(dest, prefer_subdir=prefer_subdir)
    manifest.repo_url = url
    manifest.ref = ref
    manifest.commit = commit
    manifest.readme_path = _readme_rel(manifest.root, manifest.workdir)
    log.info(
        "fetched %s@%s (%s) workdir=%s language=%s",
        url,
        ref,
        commit,
        manifest.workdir,
        manifest.language,
    )
    return manifest


def manifest_from_local(
    path: Path,
    *,
    repo_url: str = "local",
    ref: str = "local",
    prefer_subdir: str | None = None,
) -> RepoManifest:
    """Build a RepoManifest for an already-present tree (demo or --local-path)."""
    root = path.resolve()
    if not root.is_dir():
        raise FetchError(f"local path is not a directory: {root}")

    # Direct package root (pyproject / package.json / server.py) wins over parent walk.
    if (
        (root / "pyproject.toml").exists()
        or (root / "package.json").exists()
        or (root / "server.py").exists()
    ):
        lang, name, manifests = detect_language_at(root)
        git_root = root
        for parent in [root, *root.parents]:
            if (parent / ".git").exists():
                git_root = parent
                break
        return RepoManifest(
            repo_url=repo_url,
            ref=ref,
            commit=git_commit(git_root),
            root=git_root,
            workdir=root,
            language=lang,
            manifests=manifests,
            package_name=name,
            candidates=["."],
            readme_path=_readme_rel(git_root, root),
        )

    manifest = detect_package(root, prefer_subdir=prefer_subdir)
    manifest.repo_url = repo_url
    manifest.ref = ref
    manifest.commit = git_commit(manifest.root)
    manifest.readme_path = _readme_rel(manifest.root, manifest.workdir)
    return manifest
