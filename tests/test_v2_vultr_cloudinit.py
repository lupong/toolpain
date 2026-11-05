"""M11: cloud-init placeholder injection for Vultr scanner VMs."""

from __future__ import annotations

from pathlib import Path

from control_plane.provisioner.vultr_ops import render_cloud_init


def test_render_cloud_init_injects_control_plane_and_brief() -> None:
    template = (Path(__file__).resolve().parents[1] / "infra" / "cloud-init.yaml").read_text()
    out = render_cloud_init(
        template,
        scan_id="s_abc",
        repo_url="https://github.com/modelcontextprotocol/servers",
        ref="main",
        token="tok_secret",
        control_plane_url="https://toolpain.example",
        prefer_subdir="src/time",
        scan_brief="prefer time package",
    )
    assert "{{CONTROL_PLANE_URL}}" not in out
    assert "CONTROL_PLANE_URL=https://toolpain.example" in out
    assert "PREFER_SUBDIR=src/time" in out
    assert "SCAN_BRIEF_B64=" in out
    assert "prefer time package" not in out  # brief is base64, not plaintext in env value path
    assert "--prefer-subdir" in out
    assert "--scan-brief" in out
    assert "Scanner VM runner starting" in out


def test_render_cloud_init_rejects_path_traversal_subdir() -> None:
    out = render_cloud_init(
        "PREFER_SUBDIR={{PREFER_SUBDIR}}\n",
        scan_id="s1",
        repo_url="https://github.com/a/b",
        ref="main",
        token="t",
        control_plane_url="http://127.0.0.1:8000",
        prefer_subdir="../etc",
    )
    assert "PREFER_SUBDIR=\n" in out or out.strip().endswith("PREFER_SUBDIR=")
