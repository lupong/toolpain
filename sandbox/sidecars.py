"""Start allowlisted dependency containers on a Docker network for a scan."""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field

from runner.services import ServiceSpec
from sandbox.sandbox import SandboxError, run_docker

log = logging.getLogger("toolpain.sidecars")


@dataclass
class SidecarStack:
    network: str
    hosts: dict[str, str] = field(default_factory=dict)
    container_names: list[str] = field(default_factory=list)
    owned_network: bool = False

    async def cleanup(self) -> None:
        for name in self.container_names:
            await run_docker("rm", "-f", name, check=False)
        if self.owned_network and self.network:
            await run_docker("network", "rm", self.network, check=False)


async def ensure_image(image: str, *, timeout: float = 300.0) -> None:
    code, _ = await run_docker("image", "inspect", image, check=False)
    if code == 0:
        return
    log.info("pulling sidecar image %s", image)
    await run_docker("pull", image, check=True, timeout=timeout)


async def _ready_check(container: str, spec: ServiceSpec) -> None:
    deadline = asyncio.get_event_loop().time() + max(15, spec.ready_timeout_sec)
    last = ""
    while asyncio.get_event_loop().time() < deadline:
        image = spec.image.lower()
        if image.startswith("postgres:") or image.startswith("pgvector/"):
            user = spec.env.get("POSTGRES_USER") or "postgres"
            code, out = await run_docker(
                "exec",
                container,
                "pg_isready",
                "-U",
                user,
                check=False,
                timeout=15,
            )
            last = out.strip()[:200]
            if code == 0:
                return
        elif image.startswith("redis:"):
            code, out = await run_docker(
                "exec", container, "redis-cli", "ping", check=False, timeout=15
            )
            last = out.strip()[:200]
            if code == 0 and "PONG" in out.upper():
                return
        elif image.startswith("mysql:") or image.startswith("mariadb:"):
            code, out = await run_docker(
                "exec",
                container,
                "mysqladmin",
                "ping",
                "-h",
                "127.0.0.1",
                "--silent",
                check=False,
                timeout=15,
            )
            last = out.strip()[:200]
            if code == 0:
                return
        else:
            # Generic: container still running counts as ready after a short settle.
            code, out = await run_docker(
                "inspect",
                "-f",
                "{{.State.Running}}",
                container,
                check=False,
                timeout=15,
            )
            last = out.strip()
            if code == 0 and out.strip().lower() == "true":
                await asyncio.sleep(2.0)
                return
        await asyncio.sleep(1.5)
    raise SandboxError(
        f"sidecar {spec.name} ({spec.image}) not ready in {spec.ready_timeout_sec}s: {last}"
    )


async def start_sidecars(
    *,
    scan_id: str,
    network: str,
    services: list[ServiceSpec],
    subnet_prefix_ip: str | None = None,
    start_octet: int = 90,
    create_network: bool = False,
) -> SidecarStack:
    """Pull and start sidecars on ``network``. Caller owns teardown via ``cleanup``."""
    if not services:
        return SidecarStack(network=network, owned_network=False)

    stack = SidecarStack(network=network, owned_network=create_network)
    if create_network:
        code, out = await run_docker(
            "network",
            "create",
            "--label",
            f"toolpain.scan={scan_id}",
            network,
            check=False,
        )
        if code != 0 and "already exists" not in out.lower():
            raise SandboxError(f"sidecar network create failed: {out.strip()[:300]}")

    try:
        for index, spec in enumerate(services):
            await ensure_image(spec.image)
            cname = f"tp_svc_{scan_id}_{spec.name}"[:60]
            await run_docker("rm", "-f", cname, check=False)
            args = [
                "run",
                "-d",
                "--name",
                cname,
                "--label",
                f"toolpain.scan={scan_id}",
                "--label",
                "toolpain.role=sidecar",
                "--network",
                network,
                "--memory",
                "1g",
                "--pids-limit",
                "256",
            ]
            if subnet_prefix_ip:
                # e.g. 10.66.42. — host octet start_octet+index
                ip = f"{subnet_prefix_ip}{start_octet + index}"
                args += ["--ip", ip]
                stack.hosts[spec.name] = ip
            for key, value in spec.env.items():
                args += ["-e", f"{key}={value}"]
            # Common postgres trust for scan-local use.
            if spec.image.lower().startswith(("postgres:", "pgvector/")):
                args += ["-e", "POSTGRES_HOST_AUTH_METHOD=trust"]
            args.append(spec.image)
            await run_docker(*args, timeout=120)
            stack.container_names.append(cname)
            if spec.name not in stack.hosts:
                # Discover assigned IP.
                code, out = await run_docker(
                    "inspect",
                    "-f",
                    "{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}",
                    cname,
                    check=False,
                )
                ip = out.strip().splitlines()[-1].strip() if out.strip() else ""
                if code != 0 or not ip:
                    raise SandboxError(f"could not resolve IP for sidecar {spec.name}")
                stack.hosts[spec.name] = ip
            await _ready_check(cname, spec)
            log.info("sidecar ready %s → %s (%s)", spec.name, stack.hosts[spec.name], spec.image)
    except Exception:
        await stack.cleanup()
        raise
    return stack
