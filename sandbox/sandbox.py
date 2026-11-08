"""Docker sandbox: per-scan internal network, sinkhole, fixture site, decoys, teardown.

The scanned server runs through ``Sandbox.launcher`` which yields a ``docker run -i`` stdio
command with: internal-only network, sinkhole DNS, read-only root, tmpfs /tmp, cap-drop ALL,
no-new-privileges, pid/memory/cpu limits, the decoy workspace mounted read-only and, in runc
mode, in-container ``strace`` writing to a host-visible trace directory.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import shutil
import tempfile
import time
from collections.abc import Sequence
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol

from mcp import StdioServerParameters

from runner.services import ServiceSpec
from sandbox.decoys import DecoySet, plant_decoys
from sandbox.models import SinkholeRecord, TraceEvent
from sandbox.trace import parse_strace_file

if False:  # TYPE_CHECKING-friendly without circular import at runtime
    from sandbox.sidecars import SidecarStack

SANDBOX_DIR = Path(__file__).resolve().parent
SINKHOLE_IMAGE = "toolpain-sinkhole:latest"
FIXTURE_IMAGE = "toolpain-fixture:latest"
SUBNET_PREFIX = "10.66"
SINKHOLE_HOST_OCTET = 53
FIXTURE_HOST_OCTET = 80
FIXTURE_HOSTNAME = "fixture.local"
STRACE_FILTER = "trace=file,network,process"


class SandboxError(RuntimeError):
    pass


class Sandbox(Protocol):
    """What the runner needs from any sandbox (real Docker or the demo replayer)."""

    scan_id: str
    decoys: DecoySet
    sinkhole_ip: str
    fixture_url: str
    settle_sec: float

    async def start(self) -> None: ...
    async def stop(self) -> None: ...
    def launcher(
        self, extra_args: Sequence[str] = (), label: str = "run"
    ) -> StdioServerParameters: ...
    def trace_events(self) -> list[TraceEvent]: ...
    async def sinkhole_records(self) -> list[SinkholeRecord]: ...
    def on_call_complete(self, tool: str, start: float, end: float) -> None: ...


def safe_id(scan_id: str) -> str:
    return re.sub(r"[^a-z0-9_]", "", scan_id.lower())[:24] or "scan"


def subnet_octet(scan_id: str, attempt: int = 0) -> int:
    digest = int(hashlib.sha1(scan_id.encode()).hexdigest(), 16)
    return 16 + (digest + attempt) % 200


async def run_docker(*args: str, check: bool = True, timeout: float = 120.0) -> tuple[int, str]:
    """Run ``docker <args>``; return (returncode, combined output)."""
    proc = await asyncio.create_subprocess_exec(
        "docker",
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        proc.kill()
        raise SandboxError(f"docker {' '.join(args[:2])} timed out") from None
    text = out.decode(errors="replace")
    if check and proc.returncode != 0:
        raise SandboxError(f"docker {' '.join(args[:3])} failed: {text.strip()[:400]}")
    return proc.returncode or 0, text


async def docker_available() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        code, _ = await run_docker("info", check=False, timeout=15)
    except (SandboxError, OSError):
        return False
    return code == 0


class DockerSandbox:
    def __init__(
        self,
        scan_id: str,
        image: str,
        server_cmd: Sequence[str],
        *,
        runtime: str = "runc",
        base_dir: Path | None = None,
        memory: str = "2g",
        cpus: str = "2",
        pids_limit: int = 256,
        sinkhole_image: str = SINKHOLE_IMAGE,
        fixture_image: str = FIXTURE_IMAGE,
        services: Sequence[ServiceSpec] | None = None,
    ) -> None:
        self.scan_id = safe_id(scan_id)
        self.image = image
        self.server_cmd = list(server_cmd)
        self.runtime = runtime
        self.memory, self.cpus, self.pids_limit = memory, cpus, pids_limit
        self.sinkhole_image, self.fixture_image = sinkhole_image, fixture_image
        self.services = list(services or [])
        self.settle_sec = 0.6
        self.network = f"tp_internal_{self.scan_id}"
        self.octet = subnet_octet(self.scan_id)
        self.subnet = f"{SUBNET_PREFIX}.{self.octet}.0/24"
        self.sinkhole_ip = f"{SUBNET_PREFIX}.{self.octet}.{SINKHOLE_HOST_OCTET}"
        self.fixture_ip = f"{SUBNET_PREFIX}.{self.octet}.{FIXTURE_HOST_OCTET}"
        self.fixture_url = f"http://{FIXTURE_HOSTNAME}/"
        self._base = base_dir
        self._root: Path | None = None
        self._launches = 0
        self._started = False
        self._sidecar_stack: Any | None = None
        self.decoys: DecoySet

    # -- paths -------------------------------------------------------------
    @property
    def root(self) -> Path:
        if self._root is None:
            raise SandboxError("sandbox not started")
        return self._root

    @property
    def trace_dir(self) -> Path:
        return self.root / "trace"

    @property
    def sinkhole_name(self) -> str:
        return f"tp_sinkhole_{self.scan_id}"

    @property
    def fixture_name(self) -> str:
        return f"tp_fixture_{self.scan_id}"

    @property
    def label_filter(self) -> str:
        return f"label=toolpain.scan={self.scan_id}"

    # -- lifecycle ---------------------------------------------------------
    async def __aenter__(self) -> DockerSandbox:
        await self.start()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        await self.stop()

    async def start(self) -> None:
        self._root = Path(tempfile.mkdtemp(prefix=f"tp_{self.scan_id}_"))
        self.trace_dir.mkdir()
        self.trace_dir.chmod(0o777)
        try:
            await self._ensure_images()
            await self._create_network()
            self._started = True
            self.decoys = plant_decoys(self.root / "workspace", self.scan_id)
            site = self._prepare_fixture_site()
            if self.services:
                from sandbox.sidecars import start_sidecars

                self._sidecar_stack = await start_sidecars(
                    scan_id=self.scan_id,
                    network=self.network,
                    services=self.services,
                    subnet_prefix_ip=f"{SUBNET_PREFIX}.{self.octet}.",
                    start_octet=90,
                )
            await self._start_sinkhole()
            await self._start_fixture(site)
        except BaseException:
            await self.stop()
            raise

    async def stop(self) -> None:
        """Remove every container and the network for this scan, then the temp dir."""
        try:
            _, ids = await run_docker("ps", "-aq", "--filter", self.label_filter, check=False)
            if ids.split():
                await run_docker("rm", "-f", *ids.split(), check=False)
            await run_docker("network", "rm", self.network, check=False)
        finally:
            if self._root is not None:
                shutil.rmtree(self._root, ignore_errors=True)
                self._root = None
            self._started = False

    async def leftovers(self) -> list[str]:
        """Names of containers/networks still around for this scan (should be empty)."""
        _, names = await run_docker(
            "ps", "-a", "--filter", self.label_filter, "--format", "{{.Names}}", check=False
        )
        _, nets = await run_docker(
            "network",
            "ls",
            "--filter",
            f"name={self.network}",
            "--format",
            "{{.Name}}",
            check=False,
        )
        return [n for n in [*names.split(), *nets.split()] if n]

    # -- setup helpers -------------------------------------------------------
    async def _ensure_images(self) -> None:
        for image, context in (
            (self.sinkhole_image, SANDBOX_DIR / "sinkhole"),
            (self.fixture_image, SANDBOX_DIR / "fixture_site"),
        ):
            code, _ = await run_docker("image", "inspect", image, check=False)
            if code != 0:
                await run_docker("build", "-q", "-t", image, str(context), timeout=600)

    async def _create_network(self) -> None:
        for attempt in range(10):
            octet = subnet_octet(self.scan_id, attempt)
            subnet = f"{SUBNET_PREFIX}.{octet}.0/24"
            code, out = await run_docker(
                "network",
                "create",
                "--internal",
                "--subnet",
                subnet,
                "--label",
                f"toolpain.scan={self.scan_id}",
                self.network,
                check=False,
            )
            if code == 0:
                self.octet, self.subnet = octet, subnet
                self.sinkhole_ip = f"{SUBNET_PREFIX}.{octet}.{SINKHOLE_HOST_OCTET}"
                self.fixture_ip = f"{SUBNET_PREFIX}.{octet}.{FIXTURE_HOST_OCTET}"
                return
            if "overlap" not in out.lower() and "pool" not in out.lower():
                raise SandboxError(f"network create failed: {out.strip()[:300]}")
        raise SandboxError("no free 10.66.x.0/24 subnet")

    def _prepare_fixture_site(self) -> Path:
        site = self.root / "site"
        shutil.copytree(
            SANDBOX_DIR / "fixture_site", site, ignore=shutil.ignore_patterns("*.py", "Dockerfile")
        )
        token = self.decoys.values[1]
        for page in site.glob("*.html"):
            page.write_text(page.read_text().replace("__DECOY_TOKEN__", token))
        return site

    def _hardening(self) -> list[str]:
        return [
            "--read-only",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--pids-limit",
            str(self.pids_limit),
            "--memory",
            self.memory,
        ]

    async def _start_sinkhole(self) -> None:
        pairs = [f"{FIXTURE_HOSTNAME}={self.fixture_ip}"]
        if self._sidecar_stack:
            for host, ip in self._sidecar_stack.hosts.items():
                pairs.append(f"{host}={ip}")
        overrides = ",".join(pairs)
        await run_docker(
            "run", "-d", "--name", self.sinkhole_name,
            "--label", f"toolpain.scan={self.scan_id}",
            "--network", self.network, "--ip", self.sinkhole_ip,
            *self._hardening(), "--cap-add", "NET_BIND_SERVICE",
            "-e", f"SINKHOLE_IP={self.sinkhole_ip}",
            "-e", f"SINKHOLE_OVERRIDES={overrides}",
            self.sinkhole_image,
        )  # fmt: skip
        deadline = time.time() + 20
        while time.time() < deadline:
            _, logs = await run_docker("logs", self.sinkhole_name, check=False)
            if '"ready"' in logs:
                return
            await asyncio.sleep(0.3)
        raise SandboxError("sinkhole did not become ready")

    async def _start_fixture(self, site: Path) -> None:
        await run_docker(
            "run", "-d", "--name", self.fixture_name,
            "--label", f"toolpain.scan={self.scan_id}",
            "--network", self.network, "--ip", self.fixture_ip,
            *self._hardening(), "--cap-add", "NET_BIND_SERVICE",
            "-v", f"{site}:/site:ro",
            self.fixture_image,
        )  # fmt: skip

    # -- target launch -------------------------------------------------------
    def docker_run_args(self, extra_args: Sequence[str] = (), label: str = "run") -> list[str]:
        """Argument list (after ``docker``) that runs the target with stdio attached."""
        self._launches += 1
        k = self._launches
        tag = re.sub(r"[^a-z0-9]", "", label.lower()) or "run"
        name = f"tp_target_{self.scan_id}_{k}_{tag}"
        args = [
            "run", "-i", "--rm", "--name", name,
            "--label", f"toolpain.scan={self.scan_id}",
            "--network", self.network, "--dns", self.sinkhole_ip,
            *self._hardening(), "--tmpfs", "/tmp", "--cpus", self.cpus,
            "-v", f"{self.decoys.host_root}:/workspace:ro",
            "-v", f"{self.trace_dir}:/trace",
        ]  # fmt: skip
        if self.runtime and self.runtime != "default":
            args.append(f"--runtime={self.runtime}")
        cmd = [*self.server_cmd, *extra_args]
        if self.runtime == "runsc":
            args += [self.image, *cmd]
        else:
            args += ["--cap-add", "SYS_PTRACE", self.image]
            args += [
                "strace", "-f", "-ttt", "-s", "256", "-e", STRACE_FILTER,
                "-o", f"/trace/trace-{k:03d}-{tag}.log", *cmd,
            ]  # fmt: skip
        return args

    def launcher(self, extra_args: Sequence[str] = (), label: str = "run") -> StdioServerParameters:
        if not self._started:
            raise SandboxError("sandbox not started")
        return StdioServerParameters(command="docker", args=self.docker_run_args(extra_args, label))

    # -- observations ----------------------------------------------------------
    def trace_events(self) -> list[TraceEvent]:
        events: list[TraceEvent] = []
        for path in sorted(self.trace_dir.glob("trace-*.log")):
            events.extend(parse_strace_file(path))
        return sorted(events, key=lambda e: e.ts)

    async def sinkhole_records(self) -> list[SinkholeRecord]:
        _, logs = await run_docker("logs", self.sinkhole_name, check=False)
        return parse_sinkhole_logs(logs)

    def on_call_complete(self, tool: str, start: float, end: float) -> None:
        """Real sandboxes observe syscalls directly; nothing to do."""

    async def run_in_network(
        self, image: str, cmd: Sequence[str], timeout: float = 60.0
    ) -> tuple[int, str]:
        """Run a throwaway container on the internal network (used by containment tests)."""
        args = [
            "run",
            "--rm",
            "--label",
            f"toolpain.scan={self.scan_id}",
            "--network",
            self.network,
        ]
        args += ["--dns", self.sinkhole_ip, "--cap-drop", "ALL", "--memory", "256m", image, *cmd]
        return await run_docker(*args, check=False, timeout=timeout)


def parse_sinkhole_logs(text: str) -> list[SinkholeRecord]:
    records: list[SinkholeRecord] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            continue
        if raw.get("proto") not in {"dns", "http", "tls", "tcp"}:
            continue
        records.append(SinkholeRecord.model_validate(raw))
    return records
