"""Provisioners: demo, local, vultr."""

from __future__ import annotations

from control_plane.provisioner.base import Provisioner
from control_plane.provisioner.demo import DemoProvisioner


def get_provisioner(name: str, **kwargs) -> Provisioner:
    name = (name or "demo").lower()
    if name == "demo":
        return DemoProvisioner(**kwargs)
    if name == "local":
        from control_plane.provisioner.local import LocalProvisioner

        return LocalProvisioner(**kwargs)
    if name == "vultr":
        from control_plane.provisioner.vultr import VultrProvisioner

        return VultrProvisioner(**kwargs)
    raise ValueError(f"unknown provisioner: {name}")


__all__ = ["Provisioner", "DemoProvisioner", "get_provisioner"]
