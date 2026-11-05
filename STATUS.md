# ToolPain Status (2026-11-04)

## v1 shipped

- Control plane, web UI, runner pipeline, Docker sandbox, decoy demo
- Local OpenAI executable codegen: `launch_sh`, `probe_py`/`next_plans`, `workdir_pick`, `oracle_py`, `scan_brief`

## v2 in progress / implemented locally

Plan: [`docs/V2_PLAN.md`](docs/V2_PLAN.md)

| Milestone | Status |
|---|---|
| M11 Vultr cloud-init URL/brief/subdir + destroy-on-terminal | Code complete (needs live `VULTR_API_KEY` + snapshot to prove) |
| M12 Codegen eval + `CODEGEN_MODE` kill-switch | Tests + env shipped |
| M13 expect_* scoring + oracle merge (append-only) | Shipped |
| M14 Artifacts panel + prefer_subdir + re-scan with brief | Shipped |
| M15 unsupported_language clarity | Shipped (HTTP/SSE still deferred) |
| M16 Ops: health fields, ARCHITECTURE, deploy docs | Shipped |
| M17 Ops status chip + re-scan | Shipped |

## Still needs real keys / environment

- Live Vultr VM e2e (`VULTR_API_KEY` + `VULTR_SNAPSHOT_ID`) → **v3 M18 gate**
- Optional `LLM_MODE=live` with `VULTR_INFERENCE_API_KEY`
- gVisor snapshot bake → **v3 M24**

## v3 (planned)

Plan: [`docs/V3_PLAN.md`](docs/V3_PLAN.md) — multi-transport MCP, share/CI, upstream intelligence, codegen cache, multi-tenant lite.

## Verify

```bash
python3.12 -m venv .venv && source .venv/bin/activate
make install && make lint test
# local openai:
# PROVISIONER=local LLM_MODE=openai make dev
```
