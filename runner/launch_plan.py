"""LaunchPlan: candidate argv lists + trial MCP initialize until one speaks.

Candidates are derived from packaged heuristics (pyproject scripts, package.json bin,
common server.py layouts). Trial runs use short-lived ``docker run -i`` with network
none — not the full sandbox — solely to find a working stdio entrypoint.
"""

from __future__ import annotations

import asyncio
import logging
import tempfile

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from runner.detect import node_bin_commands, python_console_scripts, python_module_candidates
from runner.plans import LaunchCandidate, LaunchPlan, RepoManifest
from runner.safe_argv import ArgvError, validate_launch_argv

log = logging.getLogger("toolpain.launch")


def _failure_text(exc: BaseException) -> str:
    if isinstance(exc, BaseExceptionGroup):
        return "; ".join(_failure_text(sub) for sub in exc.exceptions)
    return str(exc).strip() or exc.__class__.__name__


async def _classify_silent_exit(image: str, argv: list[str], *, timeout: float = 4.0) -> str:
    """When MCP never starts, say whether the process exited or stayed up without speaking."""
    proc = await asyncio.create_subprocess_exec(
        "docker",
        "run",
        "--rm",
        "-i",
        "--network",
        "none",
        image,
        *argv,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(b""), timeout=timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        return "process stayed up but did not speak MCP initialize"
    code = proc.returncode if proc.returncode is not None else -1
    out = (stdout or b"").decode("utf-8", errors="replace").strip()[:200]
    err = (stderr or b"").decode("utf-8", errors="replace").strip()[-400:]
    bits = [f"process exited {code}"]
    if out:
        bits.append(f"stdout: {out}")
    else:
        bits.append("stdout empty")
    if err:
        bits.append(f"stderr: {err}")
    else:
        bits.append("stderr empty")
    if code == 0 and not out and not err:
        bits.append("command returned without starting a server")
    return "; ".join(bits)


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


async def _trial_initialize(
    image: str,
    argv: list[str],
    *,
    timeout: float = 25.0,
    network: str | None = None,
    extra_hosts: dict[str, str] | None = None,
) -> str | None:
    """Return None when the process speaks MCP. Otherwise return the error and stderr."""
    docker_args = ["run", "-i", "--rm"]
    if network:
        docker_args += ["--network", network]
        for host, ip in (extra_hosts or {}).items():
            docker_args += ["--add-host", f"{host}:{ip}"]
    else:
        docker_args += ["--network", "none"]
    docker_args += [image, *argv]
    params = StdioServerParameters(
        command="docker",
        args=docker_args,
    )
    errlog = tempfile.TemporaryFile("w+", encoding="utf-8")  # noqa: SIM115 — closed in finally
    try:
        async with asyncio.timeout(timeout):
            async with stdio_client(params, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    tools = await session.list_tools()
                    if tools.tools is None:
                        return "initialize returned no tool list"
                    return None
    except Exception as exc:  # noqa: BLE001 — trial: any failure means try next
        errlog.seek(0)
        tail = errlog.read()[-800:].strip()
        detail = _failure_text(exc)
        log.debug("MCP initialize check failed for %s: %s", argv, detail)
        if tail:
            return f"{detail}; stderr: {tail}"
        if "closed" in detail.lower() or "timeout" in detail.lower():
            try:
                classified = await _classify_silent_exit(image, argv)
            except Exception as classify_exc:  # noqa: BLE001 — still return the MCP error
                classified = str(classify_exc)
            return f"{detail}; the process exited before speaking MCP; {classified}"
        return detail
    finally:
        errlog.close()


async def resolve_launch_plan(
    image: str,
    manifest: RepoManifest,
    *,
    override: list[str] | None = None,
    preferred: list[LaunchCandidate] | None = None,
    preferred_source: str = "llm",
    timeout: float = 25.0,
    packaged_fallbacks: bool = True,
    network: str | None = None,
    extra_hosts: dict[str, str] | None = None,
) -> LaunchPlan:
    if override:
        argv = validate_launch_argv(override)
        return LaunchPlan(argv=argv, rationale="caller override", source="override", tried=[])

    heuristic = candidate_argvs(manifest) if packaged_fallbacks else []
    # Codegen's command is the launch. Packaged language guesses are opt-in.
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
    last_failure = ""
    for cand in candidates:
        tried.append(cand)
        log.info("trying launch %s", cand.argv)
        failure = await _trial_initialize(
            image,
            cand.argv,
            timeout=timeout,
            network=network,
            extra_hosts=extra_hosts,
        )
        if failure is None:
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
        last_failure = failure

    detail = "; ".join(" ".join(c.argv) for c in tried[:8])
    if last_failure:
        detail = f"{detail}; last error: {last_failure[:1500]}"
    raise LaunchError(f"no launch candidate spoke MCP initialize; tried: {detail}")


def demo_launch_plan() -> LaunchPlan:
    return LaunchPlan(
        argv=["python", "/app/server.py"],
        rationale="demo/decoy-trap-server",
        source="demo",
    )
