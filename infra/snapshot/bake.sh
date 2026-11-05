#!/usr/bin/env bash
# Bake a Vultr scanner snapshot checklist (M18). Requires a temporary Ubuntu VM.
set -euo pipefail
SHA="${1:-main}"
echo "ToolPain v3 snapshot bake"
echo "1. Launch Ubuntu 22.04 in Vultr"
echo "2. Install docker.io python3.12 git"
echo "3. git clone --depth 1 --branch ${SHA} https://github.com/lupong/toolpain.git /opt/toolpain"
echo "4. python3.12 -m pip install -e /opt/toolpain"
echo "5. Install infra/nftables.conf"
echo "6. Snapshot the VM and set VULTR_SNAPSHOT_ID"
echo "Live sign-off still needs VULTR_API_KEY + CONTROL_PLANE_URL. See infra/README-deploy.md"
