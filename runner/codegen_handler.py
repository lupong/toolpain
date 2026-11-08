"""The scan's goal stays here. Codegen is the agent that makes the program runnable.

Each piece is generated, run, and on failure sent back with the error. The handler
does not invent a language or a replacement script.
"""

from __future__ import annotations

import asyncio
import re
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from runner.build import BuildError, build_generated_image, sandbox_image_tag
from runner.codegen import (
    GeneratedCode,
    generate_executable_code,
    harness_from_generated,
    load_probe_module,
    use_heuristic_codegen,
    write_launch_script,
    write_setup_script,
)
from runner.codegen_cache import make_key, store_cached
from runner.events import EventSink
from runner.harness import generate_harness
from runner.launch_plan import LaunchError, resolve_launch_plan
from runner.models import DiscoveryResult
from runner.plans import LaunchCandidate, LaunchPlan, RepoManifest
from runner.research import LlmClient
from sandbox.sandbox import DockerSandbox, safe_id as safe_scan_id

MAX_ATTEMPTS = 5

_PYTHON_M_RE = re.compile(r"(?:python3?|/app/venv/bin/python3?)\s+-m\s+([A-Za-z0-9_.]+)")


def _launch_key(launch_sh: str) -> str:
    """Normalize the launch so python -m package and tiny edits count as the same attempt."""
    lines = [
        line.strip()
        for line in launch_sh.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    body = " ".join(lines)
    match = _PYTHON_M_RE.search(body)
    if match:
        return f"python-m:{match.group(1)}"
    return " ".join(lines)


def _same_program(
    code: GeneratedCode,
    previous: GeneratedCode,
    *,
    failure: str | None = None,
) -> bool:
    if failure and (
        "spoke MCP" in failure
        or "exited before speaking MCP" in failure
        or "did not speak MCP" in failure
    ):
        return _launch_key(code.launch_sh) == _launch_key(previous.launch_sh)
    return (
        code.setup_sh.strip() == previous.setup_sh.strip()
        and code.launch_sh.strip() == previous.launch_sh.strip()
    )


class CodegenRunError(RuntimeError):
    """Codegen used every attempt and the program still did not run."""

    def __init__(self, message: str, previous: GeneratedCode | None) -> None:
        super().__init__(message)
        self.previous = previous


def attempt_budget(llm: LlmClient) -> int:
    """A fixture model cannot repair itself, so it gets one try."""
    if use_heuristic_codegen(llm):
        return 1
    return MAX_ATTEMPTS


async def until_runnable[T](
    produce: Callable[[str | None, GeneratedCode | None], Awaitable[GeneratedCode]],
    run: Callable[[GeneratedCode], Awaitable[T]],
    *,
    attempts: int,
    sink: EventSink,
    stage: str,
    piece: str,
) -> tuple[T, int]:
    """Generate, run, and hand the failure back until the piece runs or attempts end."""
    failure: str | None = None
    previous: GeneratedCode | None = None
    last: BaseException | None = None
    for number in range(1, attempts + 1):
        code = await produce(failure, previous)
        await sink.emit(
            stage,
            f"Codegen {piece} attempt {number} of {attempts} ({code.source})",
            data={"attempt": number, "source": code.source},
        )
        same = previous is not None and _same_program(code, previous, failure=failure)
        if same:
            failure = (
                f"{failure or 'the previous program failed'}\n"
                "You returned the same scripts. Change the command that failed."
            )
            last = CodegenRunError("same program", previous)
            retrying = number < attempts
            await sink.emit(
                stage,
                f"Codegen {piece} attempt {number} repeated the same program"
                + (f"; retrying ({number + 1}/{attempts})" if retrying else ""),
                level="warn",
                data={
                    "error": failure[-1500:],
                    "attempt": number,
                    "attempts": attempts,
                    "retrying": retrying,
                },
            )
            continue
        try:
            return await run(code), number
        except Exception as exc:  # noqa: BLE001 — the failure is the repair prompt
            last = exc
            failure = str(exc)[:4000]
            previous = code
            retrying = number < attempts
            await sink.emit(
                stage,
                f"Codegen {piece} attempt {number} did not run"
                + (
                    f"; retrying ({number + 1}/{attempts})"
                    if retrying
                    else "; sending the failure back"
                ),
                level="warn",
                data={
                    "error": failure[-1500:],
                    "attempt": number,
                    "attempts": attempts,
                    "retrying": retrying,
                },
            )
    detail = str(last) if last else "no program"
    raise CodegenRunError(
        f"codegen could not make {piece} runnable: {detail}",
        previous,
    ) from last


async def runnable_build(
    *,
    llm: LlmClient,
    manifest: RepoManifest,
    scan_id: str,
    repo_url: str,
    scan_brief: str | None,
    image: str | None,
    server_cmd: list[str] | None,
    runtime: str,
    sink: EventSink,
) -> tuple[DockerSandbox, LaunchPlan, dict[str, Any]]:
    """Build and start whatever codegen writes. Retry with the build or launch error."""
    cache_key = make_key(
        repo_url=repo_url,
        commit=manifest.commit or "local",
        brief=scan_brief,
        kind="launch",
    )
    discovery = DiscoveryResult(server_name=manifest.package_name or manifest.workdir.name)
    tag = sandbox_image_tag(scan_id)

    async def produce(failure: str | None, previous: GeneratedCode | None) -> GeneratedCode:
        return await generate_executable_code(
            discovery,
            llm,
            manifest.workdir,
            scan_brief=scan_brief,
            cache_key=None if failure else cache_key,
            repair_failure=failure,
            previous=previous,
            allow_fallback=False,
            remember=False,
        )

    async def run(code: GeneratedCode) -> tuple[DockerSandbox, LaunchPlan, GeneratedCode]:
        if not code.setup_ok or not code.launch_ok or not code.services_ok:
            raise BuildError("; ".join(code.errors) or "setup or launch script was rejected")
        write_setup_script(manifest.workdir, code.setup_sh)
        write_launch_script(manifest.workdir, code.launch_sh)
        built = image
        if built is None:
            await sink.emit("build", f"Running generated setup.sh for {tag}")
            built = await asyncio.to_thread(build_generated_image, manifest.workdir, tag)
        else:
            await sink.emit("build", f"Using prebuilt image {built}")
        trial_stack = None
        try:
            if code.services:
                from sandbox.sidecars import start_sidecars

                await sink.emit(
                    "build",
                    "Starting dependency sidecars before MCP initialize: "
                    + ", ".join(f"{s.name}={s.image}" for s in code.services),
                )
                trial_net = f"tp_trial_{safe_scan_id(scan_id)}"
                trial_stack = await start_sidecars(
                    scan_id=safe_scan_id(scan_id),
                    network=trial_net,
                    services=list(code.services),
                    create_network=True,
                )
            if server_cmd is not None:
                launch = await resolve_launch_plan(built, manifest, override=server_cmd)
            else:
                launch = await resolve_launch_plan(
                    built,
                    manifest,
                    preferred=[
                        LaunchCandidate(
                            argv=["/bin/sh", "/app/toolpain_launch.sh"],
                            rationale="codegen launch.sh inside image",
                        )
                    ],
                    preferred_source="llm" if code.source == "llm" else "trial",
                    packaged_fallbacks=False,
                    network=trial_stack.network if trial_stack else None,
                    extra_hosts=trial_stack.hosts if trial_stack else None,
                )
        except LaunchError as exc:
            raise LaunchError(f"{exc}\nlaunch_sh:\n{code.launch_sh.strip()}") from exc
        finally:
            if trial_stack is not None:
                await trial_stack.cleanup()
        store_cached(cache_key, code.model_dump())
        sandbox = DockerSandbox(
            scan_id,
            built,
            launch.argv,
            runtime=runtime,
            services=list(code.services),
        )
        return sandbox, launch, code

    try:
        (sandbox, launch, code), used = await until_runnable(
            produce,
            run,
            attempts=attempt_budget(llm),
            sink=sink,
            stage="build",
            piece="setup",
        )
    except CodegenRunError as exc:
        cause = exc.__cause__
        if isinstance(cause, LaunchError):
            raise cause from exc
        raise BuildError(str(exc)) from exc
    return (
        sandbox,
        launch,
        {
            "codegen": {
                "source": code.source,
                "rationale": code.rationale,
                "launch_sh": code.launch_sh,
                "launch_ok": code.launch_ok,
                "setup_sh": code.setup_sh,
                "setup_ok": code.setup_ok,
                "services": [s.model_dump() for s in code.services],
                "services_ok": code.services_ok,
                "errors": code.errors,
                "attempts": used,
            }
        },
    )


async def runnable_probe(
    *,
    llm: LlmClient,
    discovery: DiscoveryResult,
    source_dir: Path,
    fixture_url: str,
    scan_brief: str | None,
    repo_url: str,
    commit: str,
    sink: EventSink,
) -> tuple[GeneratedCode, Any, Any]:
    """Load the probe and oracle codegen wrote. Send a load failure back, then retry."""
    cache_key = make_key(
        repo_url=repo_url,
        commit=commit or "local",
        brief=scan_brief,
        kind="probe",
    )

    async def produce(failure: str | None, previous: GeneratedCode | None) -> GeneratedCode:
        return await generate_executable_code(
            discovery,
            llm,
            source_dir,
            fixture_url=fixture_url,
            scan_brief=scan_brief,
            cache_key=None if failure else cache_key,
            repair_failure=failure,
            previous=previous,
            allow_fallback=False,
            remember=False,
        )

    async def run(code: GeneratedCode) -> tuple[GeneratedCode, Any, Any]:
        if not code.probe_ok or not code.oracle_ok:
            raise BuildError("; ".join(code.errors) or "probe or oracle was rejected")
        harness = harness_from_generated(code, discovery, fixture_url)
        module = load_probe_module(code.probe_py)
        store_cached(cache_key, code.model_dump())
        return code, harness, module

    try:
        (code, harness, module), _used = await until_runnable(
            produce,
            run,
            attempts=attempt_budget(llm),
            sink=sink,
            stage="research",
            piece="probe",
        )
    except CodegenRunError as exc:
        if use_heuristic_codegen(llm):
            await sink.emit(
                "research",
                f"Codegen probe did not run ({exc}); using the schema harness",
                level="warn",
            )
            harness = await generate_harness(
                discovery, llm, source_dir, fixture_url=fixture_url
            )
            previous = exc.previous or GeneratedCode(
                launch_sh="",
                probe_py="",
                source="heuristic",
                rationale="probe repair exhausted",
            )
            return previous, harness, None
        # Live path: executable probe/oracle is required — no schema-harness downgrade.
        raise BuildError(
            f"LLM probe codegen exhausted (no heuristic fallback): {exc}"
        ) from exc
    return code, harness, module
