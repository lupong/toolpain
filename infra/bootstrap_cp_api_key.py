#!/usr/bin/env python3
"""Mint a CP-scoped Vultr API key and install it on the control-plane VM.

Usage (from a host whose IP is allowlisted on your bootstrap key)::

    python infra/bootstrap_cp_api_key.py \\
        --bootstrap-key "$VULTR_API_KEY" \\
        --cp-ip 140.82.61.136 \\
        --ssh-host 140.82.61.136

Does not print the minted key. Writes it to the remote ``/opt/toolpain/.env``
as ``VULTR_API_KEY`` and restarts ``toolpain.service``.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# Allow running as ``python infra/bootstrap_cp_api_key.py`` without install.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from control_plane.provisioner.vultr_bootstrap import (  # noqa: E402
    VultrBootstrapError,
    bootstrap_control_plane_api_key,
)


def _ssh_base(host: str) -> list[str]:
    return [
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "BatchMode=yes",
        f"root@{host}",
    ]


def _install_key_on_cp(*, host: str, api_key: str) -> None:
    """Replace VULTR_API_KEY in remote .env and restart the service."""
    with tempfile.NamedTemporaryFile("w", delete=False) as fh:
        fh.write(api_key)
        key_path = fh.name
    try:
        subprocess.run(
            [
                "scp",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                key_path,
                f"root@{host}:/tmp/toolpain-vultr-key",
            ],
            check=True,
            capture_output=True,
        )
        remote = r"""
set -euo pipefail
KEY=$(cat /tmp/toolpain-vultr-key)
rm -f /tmp/toolpain-vultr-key
ENV=/opt/toolpain/.env
test -f "$ENV"
tmp=$(mktemp)
awk -v k="$KEY" '
  BEGIN { done=0 }
  /^VULTR_API_KEY=/ { print "VULTR_API_KEY=" k; done=1; next }
  { print }
  END { if (!done) print "VULTR_API_KEY=" k }
' "$ENV" > "$tmp"
mv "$tmp" "$ENV"
chmod 600 "$ENV"
systemctl restart toolpain
sleep 2
curl -fsS http://127.0.0.1:8000/api/health >/dev/null
echo installed_ok
"""
        out = subprocess.run(
            _ssh_base(host) + ["bash", "-s"],
            input=remote,
            text=True,
            check=True,
            capture_output=True,
        )
        if "installed_ok" not in out.stdout:
            raise RuntimeError(f"remote install failed: {out.stdout!r} {out.stderr!r}")
    finally:
        Path(key_path).unlink(missing_ok=True)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--bootstrap-key",
        default=os.environ.get("VULTR_BOOTSTRAP_API_KEY")
        or os.environ.get("VULTR_API_KEY")
        or "",
        help="Account key used once to create the service user (env VULTR_BOOTSTRAP_API_KEY)",
    )
    p.add_argument("--cp-ip", required=True, help="Control-plane public IPv4")
    p.add_argument(
        "--ssh-host",
        default="",
        help="SSH host to install the key on (default: same as --cp-ip)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Create/reuse credentials but do not SSH-install",
    )
    args = p.parse_args()
    if not args.bootstrap_key:
        print("missing --bootstrap-key / VULTR_BOOTSTRAP_API_KEY", file=sys.stderr)
        return 2
    ssh_host = args.ssh_host or args.cp_ip

    try:
        result = asyncio.run(
            bootstrap_control_plane_api_key(
                bootstrap_api_key=args.bootstrap_key,
                control_plane_ip=args.cp_ip,
            )
        )
    except VultrBootstrapError as exc:
        print(f"bootstrap failed: {exc}", file=sys.stderr)
        return 1

    print(
        f"ok user_id={result.user_id} email={result.email} "
        f"allowed_ip={result.allowed_ip}/32 created_user={result.created_user}"
    )
    if args.dry_run:
        print("dry-run: skipping remote install")
        return 0

    _install_key_on_cp(host=ssh_host, api_key=result.api_key)
    print(f"installed on {ssh_host} and restarted toolpain.service")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
