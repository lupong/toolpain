# Deploy ToolPain on Vultr

## 1. Snapshot (scanner VMs)

1. Create an Ubuntu 22.04+ VM.
2. Install Docker, Python 3.12, git.
3. Clone this repo to `/opt/toolpain` and `pip install -e .`.
4. Install `infra/nftables.conf`.
5. Snapshot the VM → set `VULTR_SNAPSHOT_ID` on the control plane.

Optional: install gVisor (`runsc`) and configure `infra/docker-daemon.json` for full mode.

## 2. Control plane VM

1. Fresh Ubuntu VM with a public IP.
2. Point `toolpain.com` A record at the IP.
3. Install Python 3.12, Caddy, clone repo.
4. Copy `.env.example` → `.env` and set:
   - `PROVISIONER=vultr`
   - `VULTR_API_KEY`
   - `VULTR_INFERENCE_API_KEY`
   - `LLM_MODE=live`
   - `VULTR_SNAPSHOT_ID`
   - `CONTROL_PLANE_URL=https://toolpain.com`
5. `pip install -e .`
6. Run under systemd: `uvicorn control_plane.main:app --host 127.0.0.1 --port 8000`
7. Use the root `Caddyfile` for HTTPS reverse proxy to `:8000`.

## 3. DNS

- `toolpain.com` → control plane IP
- Optional `www` CNAME → `toolpain.com`

## 4. Verify a real Vultr scan

```bash
export PROVISIONER=vultr
export VULTR_API_KEY=...
export VULTR_SNAPSHOT_ID=...          # required for reliable boots
export CONTROL_PLANE_URL=https://toolpain.com
export LLM_MODE=openai                # or live + VULTR_INFERENCE_API_KEY
export OPENAI_API_KEY=...             # if openai
make dev
# POST /api/scans with a public MCP repo (optional scan_brief / prefer_subdir)
# Confirm instance labeled toolpain-scan-<id> appears
# Confirm early "Scanner VM runner starting" event, then report + destroy
```

Cloud-init injects `CONTROL_PLANE_URL`, `PREFER_SUBDIR`, and base64 `SCAN_BRIEF_B64`.
Destroy runs when the scan hits a terminal status (report posted) or after timeout; reaper cleans orphans.

## 5. Reaper

Cron every 10 minutes:

```bash
python -c "import asyncio; from control_plane.reaper import reap; print(asyncio.run(reap()))"
```
