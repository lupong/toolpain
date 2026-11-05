"""LaunchPlan: candidate argv lists + trial MCP initialize until one speaks.

Candidates are derived from packaged heuristics (pyproject scripts, package.json bin,
common server.py layouts). Trial runs use short-lived ``docker run -i`` with network
none — not the full sandbox — solely to find a working stdio entrypoint.
"""

from __future__ import annotations

import asyncio
import logging

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from runner.detect import node_bin_commands, python_console_scripts, python_module_candidates
from runner.plans import LaunchCandidate, LaunchPlan, RepoManifest
from runner.safe_argv import ArgvError, validate_launch_argv

log = logging.getLogger("toolpain.launch")


class LaunchError(RuntimeError):
    pass


def candidate_argvs(manifest: RepoManifest) -> list[LaunchCandidate]:
    workdir = manifest.workdir
    out: list[LaunchCandidate] = []

    if manifest.language == "python":
        for script in python_console_scripts(workdir):
            out.append(LaunchCandidate(argv=[script], rationale=f"pyproject script {script}"))
            if script.startswith("mcp-server-") and "time" in script:
                out.append(
                    LaunchCandidate(
                        argv=[script, "--local-timezone", "UTC"],
                        rationale=f"pyproject script {script} + UTC tz",
                    )
                )
        for mod in python_module_candidates(workdir):
            out.append(LaunchCandidate(argv=["python", "-m", mod], rationale=f"python -m {mod}"))
        if (workdir / "server.py").exists():
            out.append(
                LaunchCandidate(
                    argv=["python", "/app/server.py"],
                    rationale="server.py at package root",
                )
            )
        # Common FastMCP layout copied to /app
        out.append(
            LaunchCandidate(argv=["python", "server.py"], rationale="cwd-relative server.py")
        )

    elif manifest.language == "node":
        for argv in node_bin_commands(workdir):
            # bin paths are relative; in image they live under /app
            fixed = [argv[0], *(p if p.startswith("/") else f"/app/{p}" for p in argv[1:])]
            out.append(LaunchCandidate(argv=fixed, rationale="package.json bin/main"))
        for rel in ("dist/index.js", "build/index.js", "index.js", "src/index.js"):
            if (workdir / rel).exists():
                out.append(LaunchCandidate(argv=["node", f"/app/{rel}"], rationale=f"found {rel}"))

    # Deduplicate while preserving order
    seen: set[tuple[str, ...]] = set()
    unique: list[LaunchCandidate] = []
    for c in out:
        key = tuple(c.argv)
        if key in seen:
            continue
        seen.add(key)
        try:
            validate_launch_argv(c.argv)
        except ArgvError:
            continue
        unique.append(c)
    return unique


async def _trial_initialize(image: str, argv: list[str], *, timeout: float = 25.0) -> bool:
    params = StdioServerParameters(
        command="docker",
        args=["run", "-i", "--rm", "--network", "none", image, *argv],
    )
    try:
        async with asyncio.timeout(timeout):
            async with stdio_client(params) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    return bool(tools.tools is not None)
    except Exception as exc:  # noqa: BLE001 — trial: any failure means try next
        log.debug("launch trial failed for %s: %s", argv, exc)
        return False


async def resolve_launch_plan(
    image: str,
    manifest: RepoManifest,
    *,
    override: list[str] | None = None,
    preferred: list[LaunchCandidate] | None = None,
    preferred_source: str = "llm",
    timeout: float = 25.0,
) -> LaunchPlan:
    if override:
        argv = validate_launch_argv(override)
        return LaunchPlan(argv=argv, rationale="caller override", source="override", tried=[])

    heuristic = candidate_argvs(manifest)
    # Prefer LLM-ordered candidates first, then packaged heuristics (deduped).
    candidates: list[LaunchCandidate] = []
    seen: set[tuple[str, ...]] = set()
    for cand in [*(preferred or []), *heuristic]:
        key = tuple(cand.argv)
        if key in seen:
            continue
        seen.add(key)
        candidates.append(cand)
    if not candidates:
        raise LaunchError(f"no launch candidates for {manifest.workdir} ({manifest.language})")

    tried: list[LaunchCandidate] = []
    for cand in candidates:
        tried.append(cand)
        log.info("trying launch %s", cand.argv)
        ok = await _trial_initialize(image, cand.argv, timeout=timeout)
        if ok:
            from_llm = preferred is not None and any(
                tuple(c.argv) == tuple(cand.argv) for c in preferred
            )
            return LaunchPlan(
                argv=cand.argv,
                env=cand.env,
                rationale=cand.rationale,
                tried=tried,
                source="llm" if from_llm and preferred_source == "llm" else "trial",
            )

    raise LaunchError(
        "no launch candidate spoke MCP initialize; tried: "
        + ", ".join(" ".join(c.argv) for c in tried[:8])
    )


def demo_launch_plan() -> LaunchPlan:
    return LaunchPlan(
        argv=["python", "/app/server.py"],
        rationale="demo/decoy-trap-server",
        source="demo",
    )
