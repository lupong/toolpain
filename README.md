# ToolPain

**Find the tools that hurt before they hurt you.**

ToolPain is a **security harness for MCP servers**. Paste a GitHub link; ToolPain runs an **agentic scan on Vultr**: ephemeral compute, Vultr Inference (Qwen) reviews the repo and generates bootstrap/probe programs, the harness executes them in isolation, and you get a runtime proof of what each tool really does versus what it claims.

Nothing in production depends on scanning on your laptop. **Vultr is the substrate** — VMs, snapshots, and Serverless Inference.

```
Browser → Control plane (Vultr VM)
                │
                ├─ Vultr API → ephemeral scanner VM
                │                  └─ Docker sandbox · sinkhole · strace
                │
                └─ Vultr Inference (Qwen + research models)
                       └─ setup / launch / probe / report narrative
```

## What you get

- Runtime evidence for every MCP tool (files, network, processes)
- Undocumented tools, over-privilege, toxic combos, decoy traps, undeclared egress
- IT-facing findings + downloadable **scan certificate**
- Least-privilege allowlist to paste into your agent config

## Docs

| Doc | Purpose |
|-----|---------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Product architecture — harness, agentic flow, Vultr, Qwen |
| [`docs/VULTR_DEPLOY.md`](docs/VULTR_DEPLOY.md) | Deploy control plane + scanners on Vultr |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | Scan error codes for operators |

## Quick start (offline demo)

```bash
git clone https://github.com/lupong/toolpain.git
cd toolpain
cp .env.example .env          # PROVISIONER=demo, LLM_MODE=fixture
make install
make dev                      # http://127.0.0.1:8000
```

Open the UI → **decoy-trap-server (flagged)** → watch findings and the access graph.

For a real Docker sandbox on your machine: `PROVISIONER=local` and `make demo`.

## Production (Vultr)

```bash
PROVISIONER=vultr
LLM_MODE=live
VULTR_INFERENCE_API_KEY=…    # Serverless Inference
CODEGEN_MODEL=qwen3.8-27b    # repo review + bootstrap/probe codegen
VULTR_API_KEY=…              # CP-scoped service user (see deploy doc)
VULTR_SNAPSHOT_ID=…          # baked scanner image
CONTROL_PLANE_URL=https://…  # reachable from scanner VMs
```

Full bake / CP / smoke-scan checklist: **[`docs/VULTR_DEPLOY.md`](docs/VULTR_DEPLOY.md)**.

## Safety

Scanned servers run only inside containers on ephemeral Vultr scanners (or local Docker in `local` mode). Egress is sinkholed. Decys are planted by ToolPain. Model-written scripts must pass AST/shell guards before execution.

The only deliberately-bad test server is `demo/decoy-trap-server` — it reads a planted decoy and talks only to the in-sandbox sinkhole.

## License

MIT (hackathon prototype).
