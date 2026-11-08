#!/usr/bin/env bash
# Bake a scanner VM image using the *same* install recipe as local (`infra/install_toolpain.sh`).
#
# Run ON the Ubuntu bake VM (22.04+ / 24.04), not on your laptop:
#
#   sudo bash infra/snapshot/bake.sh
#   # or from a fresh VM with the repo already at /opt/toolpain:
#   sudo TOOLPAIN_ROOT=/opt/toolpain bash /opt/toolpain/infra/snapshot/bake.sh
#
# Then snapshot the instance in Vultr and set VULTR_SNAPSHOT_ID on the control plane.
#
# This script intentionally:
# - installs OS deps (docker, python3.12, git)
# - installs ToolPain into /opt/toolpain/.venv via infra/install_toolpain.sh (verified)
# - stages nftables.conf but does NOT enable nftables (that would lock you out of SSH)
# - never copies a laptop .venv
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: run as root on the bake VM (sudo bash infra/snapshot/bake.sh)" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
ROOT="${TOOLPAIN_ROOT:-}"
if [[ -z "$ROOT" ]]; then
  ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
fi
if [[ ! -f "$ROOT/pyproject.toml" ]]; then
  echo "error: TOOLPAIN_ROOT=$ROOT has no pyproject.toml" >&2
  exit 1
fi

echo "==> OS packages"
apt-get update -y
apt-get install -y --no-install-recommends \
  ca-certificates curl git python3 python3-venv python3-pip \
  docker.io docker-buildx nftables

# Prefer 3.12 when the distro provides it (Ubuntu 24.04).
if ! python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 12) else 1)'; then
  apt-get install -y --no-install-recommends python3.12 python3.12-venv || true
fi

echo "==> Docker"
systemctl enable --now docker
docker info >/dev/null

echo "==> Install ToolPain at /opt/toolpain (fresh venv, verified imports)"
mkdir -p /opt/toolpain
if [[ "$ROOT" != "/opt/toolpain" ]]; then
  # Copy tree without any host .venv / data / caches.
  rsync -a --delete \
    --exclude '.venv/' \
    --exclude 'data/' \
    --exclude '.git/' \
    --exclude '__pycache__/' \
    --exclude '.pytest_cache/' \
    --exclude '.ruff_cache/' \
    --exclude 'node_modules/' \
    --exclude '.env' \
    "$ROOT"/ /opt/toolpain/
fi

TOOLPAIN_INSTALL_DEV=0 TOOLPAIN_PYTHON="$(command -v python3.12 || command -v python3)" \
  bash /opt/toolpain/infra/install_toolpain.sh /opt/toolpain

echo "==> Stage nftables (disabled until after a scan in cloud-init)"
# cloud-init copies infra/nftables.conf into place after the runner finishes.
# Leave system nftables disabled so SSH stays up for snapshot + debug.
systemctl disable nftables 2>/dev/null || true
test -f /opt/toolpain/infra/nftables.conf

echo "==> Pre-pull / warm nothing required; first scan builds toolpain-sandbox:trixie"

# Final gate (same as install script; redundant but explicit for operators).
/opt/toolpain/.venv/bin/python -c 'import runner.main; print("bake_verify_ok")'

cat <<EOF

========================================================================
BAKE READY — snapshot this VM in the Vultr console (or API), then:
  1. Set VULTR_SNAPSHOT_ID=<new-id> on the control plane .env
  2. Destroy this bake VM
  3. Do NOT enable nftables before snapshotting

Install recipe used: infra/install_toolpain.sh (same as local make install)
========================================================================
EOF
