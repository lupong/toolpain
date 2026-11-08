# Deploy ToolPain on Vultr

Production ToolPain is a **control plane VM** plus **ephemeral scanner VMs**, with **Vultr Serverless Inference** (Qwen for codegen) behind the control-plane LLM proxy.

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for how the agentic harness works.

---

## Layout

```
┌─────────────────────────┐         ┌──────────────────────────────┐
│ Control plane VM        │  API    │ Scanner VM (per scan)          │
│ toolpain-control-plane  │ ──────► │ boots from VULTR_SNAPSHOT_ID   │
│ public HTTPS            │ create/ │ cloud-init → runner            │
│ VULTR_API_KEY (service) │ destroy │ callbacks → CONTROL_PLANE_URL  │
│ VULTR_INFERENCE_API_KEY │         │ destroyed when scan ends       │
└─────────────────────────┘         └──────────────────────────────┘
```

- `CONTROL_PLANE_URL` must be reachable from the public internet (scanners call it).
- Do not put a personal Vultr root key on the CP for day-to-day provision. Mint a **service-user** key locked to the CP IP.

---

## One-time admin setup

1. Vultr account with billing; SSH key uploaded; region/plan chosen (defaults in `.env.example`: `ewr`, `vc2-2c-4gb`).
2. **Inference:** create a Vultr Serverless Inference subscription; set `VULTR_INFERENCE_API_KEY`, `VULTR_INFERENCE_MODEL`, and `CODEGEN_MODEL=qwen3.8-27b` (repo review + bootstrap/probe generation).
3. **Bootstrap API key** (laptop only): personal key with manage-users, IP-ACL’d to the deploy host. Used once to mint the CP service key — not left as `VULTR_API_KEY` on the CP.
4. **DNS:** A record for your hostname → CP public IP. Then on the CP:

```bash
sudo TOOLPAIN_HOSTNAME=toolpain.com bash /opt/toolpain/infra/wire_cp_hostname.sh
```

---

## 1. Bake the scanner snapshot

Use the same install recipe as production — never copy a laptop `.venv`.

```bash
git clone --depth 1 https://github.com/lupong/toolpain.git /opt/toolpain
sudo bash /opt/toolpain/infra/snapshot/bake.sh
# must print bake_verify_ok
```

Snapshot the VM → set `VULTR_SNAPSHOT_ID`. Destroy the bake VM.

Scripts: `infra/install_toolpain.sh`, `infra/snapshot/bake.sh`.

---

## 2. Control plane VM

1. Create Ubuntu VM; open SSH + 80/443/8000 as needed.
2. Install ToolPain:

```bash
sudo TOOLPAIN_INSTALL_DEV=0 bash infra/install_toolpain.sh /opt/toolpain
```

3. `/opt/toolpain/.env` (from `.env.example`):

```bash
PROVISIONER=vultr
LLM_MODE=live
CONTROL_PLANE_URL=https://<hostname>
VULTR_SNAPSHOT_ID=<uuid>
VULTR_REGION=ewr
VULTR_PLAN=vc2-2c-4gb
VULTR_INFERENCE_API_KEY=…
VULTR_INFERENCE_MODEL=deepseek-v4.1-flash-1017
CODEGEN_MODEL=qwen3.8-27b
TOOLPAIN_DATA_DIR=/var/lib/toolpain
HOST=0.0.0.0
PORT=8000
# VULTR_API_KEY filled in step 3
```

4. systemd → `uvicorn control_plane.main:app --host 0.0.0.0 --port 8000` with `EnvironmentFile=/opt/toolpain/.env`.
5. `curl -fsS https://<hostname>/api/health` → `"provisioner":"vultr"`, `"llm_mode":"live"`.

Optional warm pool: `SCANNER_POOL_ENABLED=1`, `SCANNER_POOL_SIZE`, `SCANNER_POOL_TOKEN`.

---

## 3. CP-scoped Vultr API key

From a host allowed on the bootstrap key ACL (often the CP itself):

```bash
export VULTR_BOOTSTRAP_API_KEY=…   # temporary
python infra/bootstrap_cp_api_key.py --cp-ip <CP_PUBLIC_IP>
```

Writes `VULTR_API_KEY` on the CP (service user, IP-locked). Remove bootstrap key material afterward.

---

## 4. Smoke scan

```bash
curl -fsS -X POST "$CONTROL_PLANE_URL/api/scans" \
  -H 'Content-Type: application/json' \
  -d '{"repo_url":"https://github.com/modelcontextprotocol/servers","ref":"main","prefer_subdir":"src/time"}'
```

Expect a `toolpain-scan-*` instance, runner events, terminal status, then destroy (or reaper within `REAPER_MAX_AGE_MIN`).

---

## Secrets

| Secret | Where | Use |
|--------|-------|-----|
| `VULTR_BOOTSTRAP_API_KEY` | Laptop / one-shot | Bake, mint service user |
| `VULTR_API_KEY` | CP `.env` only | Create/destroy scanners |
| `VULTR_INFERENCE_API_KEY` | CP `.env` only | LLM proxy (Qwen + research) |
| Per-scan token | Memory + cloud-init | Scanner → CP callbacks |

---

## Common failures

| Symptom | Fix |
|---------|-----|
| `401` IP unauthorized | Add client IP `/32` on the bootstrap/service ACL |
| No scanner callbacks | `CONTROL_PLANE_URL` must be public (not `127.0.0.1`) |
| Runner exits after start | Rebake snapshot (`bake_verify_ok`); do not rsync host venvs |
| Orphan `toolpain-scan-*` | Run reaper on CP; destroy via service key |

Scan `error_code` values: [`RUNBOOK.md`](RUNBOOK.md).

---

## Related paths

| Path | Role |
|------|------|
| `infra/install_toolpain.sh` | Fresh venv + install |
| `infra/snapshot/bake.sh` | Scanner snapshot bake |
| `infra/bootstrap_cp_api_key.py` | Mint CP service key |
| `infra/cloud-init.yaml` | Scanner boot |
| `infra/cloud-init-pool.yaml` | Warm-pool agent boot |
| `infra/nftables.conf` | Scanner lockdown |
| `infra/wire_cp_hostname.sh` | Caddy + HTTPS |
| `Caddyfile` | TLS reverse proxy |
