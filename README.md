# ToolPain

**Find the tools that hurt before they hurt you.**

ToolPain is a **security harness for MCP servers**. Paste a GitHub link; ToolPain runs an **agentic scan on Vultr**: ephemeral compute, Vultr Inference (Qwen) reviews the repo and generates bootstrap/probe programs, the harness executes them in isolation, and you get a runtime proof of what each tool really does versus what it claims.

Live: [toolpain.com](https://toolpain.com) · Source: [github.com/lupong/toolpain](https://github.com/lupong/toolpain)

---

## Vultr services and infrastructure

| Vultr service | Role in ToolPain |
|---------------|------------------|
| **Cloud Compute (VMs)** | Long-lived **control plane** VM (`toolpain-control-plane`) plus **ephemeral scanner** VMs per scan (`vc2-2c-4gb`, region `ewr`) |
| **Snapshots** | Baked scanner image (`VULTR_SNAPSHOT_ID`) with Docker, ToolPain runner, and cloud-init entrypoint — scanners boot ready instead of installing from scratch |
| **Vultr API** | Control plane creates, polls, and destroys scanner instances; optional **warm scanner pool** keeps idle VMs tagged `toolpain-pool` for faster intake |
| **Serverless Inference** | Sole production LLM backend (`VULTR_INFERENCE_API_KEY`). **Qwen** (`CODEGEN_MODEL=qwen3.8-27b`) reviews repos and writes setup/launch/probe code; other Inference models handle research profiles and IT-facing report narrative |
| **Object / account networking** | Public HTTPS to the control plane; scanners callback to `CONTROL_PLANE_URL`; scan networks sinkhole egress |

Nothing in production depends on the operator’s laptop for compute or models. **Vultr is the substrate.**

---

## Backend, deployment architecture, and how Vultr powers it

```
Browser ──HTTPS──► Control plane VM (Vultr)
                      FastAPI · SQLite · web UI
                      VULTR_API_KEY → create / destroy scanners
                      VULTR_INFERENCE_API_KEY → LLM proxy only
                           │
                           ├─ Vultr API → scanner VM (from snapshot)
                           │                 Docker sandbox · sinkhole · strace
                           │                 runner agent loop
                           │                 callbacks → CONTROL_PLANE_URL
                           │                 destroyed (or pool-released) when done
                           │
                           └─ Vultr Serverless Inference
                                  Qwen codegen · research · certificate copy
```

**Control plane** (`control_plane/`) — long-lived Vultr VM behind [toolpain.com](https://toolpain.com). Serves the UI and scan API, holds Vultr + Inference credentials, proxies every model call so keys never land on scanners, and provisions compute.

**Scanner** (`runner/` + `sandbox/`) — ephemeral Vultr VM (or warm-pool member). Cloud-init starts the agent worker: clone → codegen/build → launch MCP → discover tools → research → probe under isolation → analyze → report → tear down.

**How Vultr powers it:** the API turns each scan into real disposable infrastructure; Inference turns each repo into executable scan artifacts; snapshots make that loop fast and repeatable. Offline `PROVISIONER=demo|local` exists for development only — **hackathon / production is `PROVISIONER=vultr` + `LLM_MODE=live`.**

Deploy detail: [`docs/VULTR_DEPLOY.md`](docs/VULTR_DEPLOY.md) · Architecture: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

---

## Agent use case — real tasks, not a chatbot demo

**Use case:** Before an organization wires an MCP server into an agent, ToolPain **proves at runtime** what each tool actually does (files, network, processes) versus docs and manifests — inside throwaway Vultr infrastructure.

The agent is not a conversational assistant. It is a **bounded agent loop on Vultr** that performs concrete engineering and security work per repository:

1. **Read the repo** — Vultr Inference (Qwen) inspects tree, manifests, and an optional scan brief.
2. **Write the bootstrap** — emits guarded `setup_sh` / `launch_sh` so diverse MCP servers (Node, Python, Go, …) come up without a hand-written adapter per language.
3. **Repair on failure** — harness feeds build/launch errors back to the model and retries within bounds until MCP speaks (or fails closed).
4. **Inventory tools** — combines docs, static analysis, and live runtime discovery.
5. **Research each tool** — Inference profiles claimed behavior and risk.
6. **Probe for real** — calls tools inside Docker on the scanner VM; sinkhole + strace capture undeclared egress, decoy reads, over-privilege, and toxic combos.
7. **Report for IT** — findings narrative, access graph, downloadable **scan certificate**, and a least-privilege allowlist to paste into agent config.

**Safety of the agent:** model outputs are data/programs under AST and shell guards — not unconstrained host RCE. Execution happens only in containers on ephemeral Vultr scanners. Inference and account keys stay on the control plane.

Try the three demos on the live site (clean / powerful / flagged) — each starts a real Vultr scan of that server.

---

## What you get

- Runtime evidence for every MCP tool (files, network, processes)
- Undocumented tools, over-privilege, toxic combos, decoy traps, undeclared egress
- IT-facing findings + downloadable **scan certificate**
- Least-privilege allowlist to paste into your agent config

## Docs

| Doc | Purpose |
|-----|---------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Harness, agentic flow, Vultr, Qwen |
| [`docs/VULTR_DEPLOY.md`](docs/VULTR_DEPLOY.md) | Bake snapshot, CP, smoke scan |
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

Full checklist: [`docs/VULTR_DEPLOY.md`](docs/VULTR_DEPLOY.md).

## Safety

Scanned servers run only inside containers on ephemeral Vultr scanners (or local Docker in `local` mode). Egress is sinkholed. Decys are planted by ToolPain. Model-written scripts must pass AST/shell guards before execution.

The only deliberately-bad test server is `demo/decoy-trap-server` — it reads a planted decoy and talks only to the in-sandbox sinkhole.

## License

MIT (hackathon prototype).
