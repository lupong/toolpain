# ToolPain Status (2026-11-05)

## Design pass (UI1–UI7)

- Each demo tells its own story: filesystem is clean, playwright-mcp is over-privileged, decoy-trap-server is flagged. Only the decoy scan emits an alert.
- Live scans start empty and fill from per-tool probe events. Cancel stops the run and shows “Scan cancelled. VM destroyed.”
- Reports, recent scans, and the landing page are built from scan data and stay on one screen at 375px in both themes.

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

## v3 implemented locally

Plan: [`docs/V3_PLAN.md`](docs/V3_PLAN.md) — multi-transport MCP, share/CI, upstream intelligence, codegen cache, multi-tenant lite. Live VM sign-off was not part of that local close.

## v4 implemented locally

Plan: [`docs/V4_PLAN.md`](docs/V4_PLAN.md). Reports must validate. Cancelled, failed, and timed-out scans stay that way. The intake form shows a rate-card estimate; the report shows the actual and the delta. A done scan has an HTML record and a PDF download. Live Vultr is v6. v5 is the rehearsal in between.

## Verify

```bash
python3.12 -m venv .venv && source .venv/bin/activate
make install && make lint test
# local openai:
# PROVISIONER=local LLM_MODE=openai make dev
```
