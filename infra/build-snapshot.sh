#!/usr/bin/env bash
# Deprecated pointer — use infra/snapshot/bake.sh on the bake VM.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cat <<EOF
ToolPain scanner snapshot bake

Run on a fresh Ubuntu 22.04+ Vultr VM (as root):

  # Option A: clone then bake
  git clone --depth 1 https://github.com/lupong/toolpain.git /opt/toolpain
  sudo bash /opt/toolpain/infra/snapshot/bake.sh

  # Option B: from a laptop checkout already synced to the VM
  sudo TOOLPAIN_ROOT=/path/to/checkout bash infra/snapshot/bake.sh

That script uses infra/install_toolpain.sh — the same install local \`make install\` uses.
After it prints bake_verify_ok, snapshot the VM and set VULTR_SNAPSHOT_ID.

Full deploy: docs/VULTR_DEPLOY.md
Repo root: $ROOT
EOF
