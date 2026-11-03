#!/usr/bin/env bash
# Build a Vultr snapshot with Docker, ToolPain runner deps, and nftables preinstalled.
# Requires: VULTR_API_KEY, and a temporary build instance (manual or API).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
echo "ToolPain snapshot build helper"
echo "1. Launch an Ubuntu 22.04+ VM in your Vultr account"
echo "2. Install docker + python3.12 + clone lupong/toolpain"
echo "3. pip install -e '.[dev]' (or production deps)"
echo "4. Copy infra/nftables.conf into /etc/nftables.conf and enable"
echo "5. Snapshot the instance; set VULTR_SNAPSHOT_ID in control-plane .env"
echo
echo "Repo root: $ROOT"
echo "See infra/README-deploy.md for the full control-plane deploy."
