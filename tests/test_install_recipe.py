"""Shared install recipe stays wired for local + Vultr parity."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_install_script_exists_and_gates_runner_import() -> None:
    script = (ROOT / "infra" / "install_toolpain.sh").read_text()
    assert "import runner.main" in script
    assert "zero-byte" in script or "st_size == 0" in script
    assert "Never copy" in script or "rm -rf" in script


def test_bake_script_uses_shared_install() -> None:
    bake = (ROOT / "infra" / "snapshot" / "bake.sh").read_text()
    assert "install_toolpain.sh" in bake
    assert "bake_verify_ok" in bake
    assert "nftables" in bake
    assert "enable nftables" not in bake.lower() or "disable nftables" in bake


def test_cloud_init_repairs_with_shared_install() -> None:
    cloud = (ROOT / "infra" / "cloud-init.yaml").read_text()
    assert "install_toolpain.sh" in cloud
    assert "import runner.main" in cloud
    assert "provision_failed" in cloud
    assert "REPAIR_TIMEOUT_SEC" in cloud
    assert "toolpain-ping.py" in cloud
