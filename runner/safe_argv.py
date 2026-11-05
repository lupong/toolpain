"""Allowlists for argv that end up in Dockerfiles or process launches."""

from __future__ import annotations

import re
import shlex

TOKEN_RE = re.compile(r"^[A-Za-z0-9_@.+/=:-]+$")

ALLOWED_APT = frozenset(
    {
        "strace",
        "curl",
        "ca-certificates",
        "git",
        "build-essential",
        "python3-dev",
    }
)

ALLOWED_INSTALL_HEADS = frozenset(
    {
        "pip",
        "python",
        "python3",
        "npm",
        "pnpm",
        "yarn",
        "uv",
    }
)


class ArgvError(ValueError):
    pass


def validate_token(token: str) -> str:
    if not token or not TOKEN_RE.match(token):
        raise ArgvError(f"disallowed argv token: {token!r}")
    if ".." in token:
        raise ArgvError(f"disallowed argv token: {token!r}")
    return token


def validate_apt_packages(packages: list[str]) -> list[str]:
    out: list[str] = []
    for pkg in packages:
        if pkg not in ALLOWED_APT:
            raise ArgvError(f"apt package not allowlisted: {pkg}")
        out.append(pkg)
    return out or ["strace"]


def validate_install_argv(argv: list[str]) -> list[str]:
    if not argv:
        raise ArgvError("empty install argv")
    if argv[0] not in ALLOWED_INSTALL_HEADS:
        raise ArgvError(f"install program not allowlisted: {argv[0]}")
    return [validate_token(a) for a in argv]


ALLOWED_LAUNCH_PATHS = frozenset(
    {
        "/bin/sh",
        "/usr/bin/sh",
        "/usr/local/bin/node",
        "/usr/bin/node",
        "/usr/bin/python",
        "/usr/bin/python3",
    }
)


def validate_launch_argv(argv: list[str]) -> list[str]:
    if not argv:
        raise ArgvError("empty launch argv")
    # First token: bare command, /app/…, or a short allowlisted absolute path
    # (e.g. /bin/sh wrapping the LLM-generated toolpain_launch.sh).
    head = argv[0]
    if head.startswith("/"):
        if (
            not head.startswith("/app/")
            and head not in ALLOWED_LAUNCH_PATHS
            and not head.startswith("/usr/")
        ):
            raise ArgvError(f"launch path not allowlisted: {head}")
    return [validate_token(a) for a in argv]


def join_shell_argv(argv: list[str]) -> str:
    """Shell-join for Dockerfile RUN — tokens already allowlisted."""
    return shlex.join(argv)
