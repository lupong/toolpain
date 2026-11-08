"""M11: cloud-init placeholder injection for Vultr scanner VMs."""

from __future__ import annotations

from pathlib import Path

import yaml

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
    assert "LLM_MODE=live" in out or "LLM_MODE=ollama" in out
    assert "LLM_MODE=fixture" not in out
    assert "PREFER_SUBDIR=src/time" in out
    assert "SCAN_BRIEF_B64=" in out
    assert "prefer time package" not in out  # brief is base64, not plaintext in env value path
    assert "--prefer-subdir" in out
    assert "--scan-brief" in out
    assert "Scanner VM runner starting" in out
    assert "Repairing toolpain install" in out
    assert "import runner.main" in out
    assert "export LLM_MODE" in out
    assert "runner-sync.tgz" in out
    assert "Synced runner+sandbox packages from control plane" in out
    assert "CODEGEN_MODE=llm" in out
    assert "provision_failed" in out
    assert "REPAIR_TIMEOUT_SEC" in out
    assert "toolpain-ping.py" in out
    # Nested Python heredocs break YAML; ping helper must stay a separate file.
    assert "python3 - <<" not in out


def test_cloud_init_template_is_valid_yaml() -> None:
    template = (Path(__file__).resolve().parents[1] / "infra" / "cloud-init.yaml").read_text()
    rendered = render_cloud_init(
        template,
        scan_id="s_abc",
        repo_url="https://github.com/example/repo",
        ref="main",
        token="tok",
        control_plane_url="https://toolpain.example",
        prefer_subdir="src/time",
        scan_brief="prefer time",
    )
    data = yaml.safe_load(rendered)
    assert isinstance(data, dict)
    paths = {item.get("path") for item in (data.get("write_files") or [])}
    assert "/usr/local/bin/toolpain-run.sh" in paths
    assert "/usr/local/bin/toolpain-ping.py" in paths
    assert "/etc/toolpain/scan.env" in paths



def test_render_cloud_init_never_injects_fixture_llm(monkeypatch) -> None:
    monkeypatch.setenv("LLM_MODE", "fixture")
    out = render_cloud_init(
        "LLM_MODE={{LLM_MODE}}\n",
        scan_id="s1",
        repo_url="https://github.com/a/b",
        ref="main",
        token="t",
        control_plane_url="https://toolpain.example",
        llm_mode="fixture",
    )
    assert "LLM_MODE=live" in out
    assert "LLM_MODE=fixture" not in out


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
