"""Warm-pool cloud-init must be valid YAML (no column-0 heredoc breakage)."""

from __future__ import annotations

from pathlib import Path

import yaml

from control_plane.provisioner.vultr_ops import render_pool_cloud_init


def test_pool_cloud_init_is_valid_yaml() -> None:
    template = (Path(__file__).resolve().parents[1] / "infra" / "cloud-init-pool.yaml").read_text()
    assert "python3 - <<" not in template
    rendered = render_pool_cloud_init(
        template,
        control_plane_url="https://toolpain.example",
        pool_token="tok",
        llm_mode="live",
    )
    data = yaml.safe_load(rendered)
    assert isinstance(data, dict)
    paths = {item.get("path") for item in (data.get("write_files") or [])}
    assert "/usr/local/bin/toolpain-pool-agent.py" in paths
    assert "/usr/local/bin/toolpain-run.sh" in paths
    assert "/etc/toolpain/pool.env" in paths
    assert "CONTROL_PLANE_URL=https://toolpain.example" in rendered
    assert "POOL_TOKEN=tok" in rendered