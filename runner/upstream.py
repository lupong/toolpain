"""Best-effort upstream tool-name baseline for fork drift (GitHub raw README / tools list)."""

from __future__ import annotations

import logging
import re

import httpx

log = logging.getLogger("toolpain.upstream")

_TOOL_BULLET = re.compile(
    r"^\s*[-*]\s+`?([a-z][a-z0-9_]{1,64})`?(?:\s|—|-|:|$)",
    re.I | re.M,
)


def guess_upstream_repo(repo_url: str) -> str | None:
    """Heuristic: if URL looks like a fork path we still need explicit upstream later.

    For now return None unless TOOLPAIN_UPSTREAM_URL is set for the scan — callers
    pass an optional override. Kept as a hook for v2 fork compare.
    """
    _ = repo_url
    return None


async def resolve_github_parent(repo_url: str, *, token: str | None = None) -> str | None:
    """Return ``https://github.com/owner/repo`` of the fork parent when GitHub says so."""
    m = re.match(r"https://github\.com/([^/]+)/([^/]+)/?$", repo_url.strip())
    if not m:
        return None
    headers = {"Accept": "application/vnd.github+json", "User-Agent": "toolpain"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    url = f"https://api.github.com/repos/{m.group(1)}/{m.group(2)}"
    try:
        async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code != 200:
                return None
            parent = (resp.json() or {}).get("parent") or {}
            full = parent.get("full_name")
    except (httpx.HTTPError, OSError, ValueError) as exc:
        log.info("upstream parent lookup failed: %s", exc)
        return None
    if not full or "/" not in str(full):
        return None
    return f"https://github.com/{full}"


async def fetch_upstream_tool_names(
    upstream_repo_url: str,
    *,
    ref: str = "main",
    timeout: float = 20.0,
) -> list[str] | None:
    """Pull README from GitHub and regex-extract tool-ish names (shallow)."""
    m = re.match(r"https://github\.com/([^/]+)/([^/]+)/?$", upstream_repo_url.strip())
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    raw_url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/README.md"
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(raw_url)
            if resp.status_code != 200:
                return None
            text = resp.text
    except (httpx.HTTPError, OSError) as exc:
        log.info("upstream fetch failed: %s", exc)
        return None
    names = list(dict.fromkeys(_TOOL_BULLET.findall(text)))
    return names[:80] or None


def upstream_from_env_or_file(local_list: list[str] | None) -> list[str] | None:
    return local_list
