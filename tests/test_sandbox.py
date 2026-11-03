"""M4: FakeSandbox replay (always runs) and Docker containment (``-m docker``)."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from sandbox.decoys import DecoySet
from sandbox.fake import FakeSandbox
from sandbox.sandbox import DockerSandbox, safe_id, subnet_octet

# ---------------------------------------------------------------------------
# FakeSandbox: no Docker needed
# ---------------------------------------------------------------------------


async def test_fake_sandbox_replays_fixture_inside_call_window() -> None:
    async with FakeSandbox("s_fake") as sb:
        assert sb.decoys.paths[0] == "/workspace/canaries/decoy_secret.txt"
        start = time.time()
        sb.on_call_complete("fetch_report", start, start + 1.0)
        sb.on_call_complete("add", start + 2.0, start + 2.1)
        events = sb.trace_events()
        decoy = next(e for e in events if e.path == "/workspace/canaries/decoy_secret.txt")
        assert start <= decoy.ts <= start + 1.0
        assert any(e.syscall == "connect" and e.port == 443 for e in events)
        records = await sb.sinkhole_records()
        http = next(r for r in records if r.proto == "http")
        assert http.host == "collector.sinkhole.local"
        assert sb.decoys.secret_value in http.data  # exfil payload carries the decoy
        assert any(r.proto == "dns" for r in records)
        sb.on_call_complete("unknown_tool", start, start + 1)  # silently ignored


async def test_fake_sandbox_stop_removes_workspace() -> None:
    sb = FakeSandbox("s_fake2")
    await sb.start()
    root = sb.decoys.host_root
    assert (root / "canaries" / "decoy_secret.txt").exists()
    await sb.stop()
    assert not root.exists()


def test_subnet_and_ids() -> None:
    assert safe_id("S_8F2C-xx!") == "s_8f2cxx"
    assert 16 <= subnet_octet("abc") < 216
    assert subnet_octet("abc") != subnet_octet("abc", 1)


def test_docker_command_shape() -> None:
    sb = DockerSandbox("s_cmd", "img:1", ["python", "/app/server.py"], runtime="runc")
    sb.network = "tp_internal_s_cmd"
    sb._started = True  # noqa: SLF001 - build the command without starting containers
    sb._root = Path("/tmp/tp_cmd_test")  # noqa: SLF001
    sb.decoys = DecoySet(scan_id="s_cmd", host_root=sb._root / "workspace")  # noqa: SLF001
    args = sb.docker_run_args(["--flag"], "probe")
    joined = " ".join(args)
    for needle in (
        "run -i --rm",
        "--network tp_internal_s_cmd",
        f"--dns {sb.sinkhole_ip}",
        "--read-only",
        "--tmpfs /tmp",
        "--cap-drop ALL",
        "--security-opt no-new-privileges",
        "--pids-limit 256",
        "--memory 2g",
        "--cpus 2",
        ":/workspace:ro",
        "--runtime=runc",
        "--cap-add SYS_PTRACE",
        "strace -f -ttt",
        "python /app/server.py --flag",
    ):
        assert needle in joined, needle
    assert "--cap-add" not in " ".join(args).replace("--cap-add SYS_PTRACE", "")
    assert sb.sinkhole_ip.endswith(".53") and sb.sinkhole_ip.startswith("10.66.")


# ---------------------------------------------------------------------------
# Docker: containment + teardown
# ---------------------------------------------------------------------------


@pytest.mark.docker
async def test_docker_containment_and_teardown(decoy_image: str) -> None:
    sb = DockerSandbox("s_contain", decoy_image, ["python", "/app/server.py"])
    async with sb:
        # curl example.com: DNS -> sinkhole, HTTP request logged, no real internet.
        code, out = await sb.run_in_network(
            decoy_image, ["curl", "-s", "-i", "-m", "8", "http://example.com/probe"]
        )
        assert code == 0 and "HTTP/1.1 200" in out  # answered by the sinkhole, not example.com
        # socket connect to the collector host on 443 lands on the sinkhole.
        code, out = await sb.run_in_network(
            decoy_image,
            [
                "python",
                "-c",
                "import socket;s=socket.create_connection(('collector.sinkhole.local',443),5);"
                "s.sendall(b'hi');print('connected')",
            ],
        )
        assert "connected" in out
        # IP-literal egress has no route.
        code, _ = await sb.run_in_network(
            decoy_image, ["curl", "-s", "-m", "4", "http://93.184.216.34/"]
        )
        assert code != 0
        # fixture site reachable by name inside the sandbox.
        code, out = await sb.run_in_network(
            decoy_image, ["curl", "-s", "-m", "5", "http://fixture.local/"]
        )
        assert "ToolPain fixture site" in out
        records = await sb.sinkhole_records()
        assert any(r.proto == "dns" and r.host == "example.com" for r in records)
        assert any(r.proto == "http" and r.host == "example.com" for r in records)
        assert any(r.host == "collector.sinkhole.local" for r in records if r.proto == "dns")
        assert any(r.proto == "tcp" and r.port == 443 for r in records)
    assert await sb.leftovers() == []
