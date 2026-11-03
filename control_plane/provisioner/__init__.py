"""Provisioners: fake, local, vultr."""

from __future__ import annotations

from control_plane.provisioner.base import Provisioner
from control_plane.provisioner.fake import FakeProvisioner


def get_provisioner(name: str, **kwargs) -> Provisioner:
    name = (name or "fake").lower()
    if name == "fake":
        return FakeProvisioner(**kwargs)
    if name == "local":
        from control_plane.provisioner.local import LocalProvisioner

        return LocalProvisioner(**kwargs)
    if name == "vultr":
        from control_plane.provisioner.vultr import VultrProvisioner

        return VultrProvisioner(**kwargs)
    raise ValueError(f"unknown provisioner: {name}")


__all__ = ["Provisioner", "FakeProvisioner", "get_provisioner"]
