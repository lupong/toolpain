# ToolPain Architecture

ToolPain is a **harness for an agentic MCP security scan** that runs on Vultr.

A user pastes a GitHub URL. ToolPain does not apply a fixed script to every repo. It **runs an agent loop on Vultr**: provision compute, ask Vultr Inference (Qwen) to read the repository and emit the bootstrap/scan programs, execute those programs in an isolated scanner, observe runtime behavior, and turn observations into a report and certificate.

The product thesis: **prove what MCP tools do at runtime**, inside throwaway infrastructure, before they are trusted by an agent.

---

## 1. What ToolPain is

| Piece | Role |
|-------|------|
| **Harness** | Control plane + runner orchestrate the scan lifecycle, guards, and teardown |
| **Agent** | Vultr Inference models (notably **Qwen** for codegen) review the repo and write the executable scan artifacts |
| **Infra** | Vultr VMs, snapshots, networking, and Serverless Inference — the scan does not live on the operator’s laptop in production |

ToolPain owns containment (Docker, sinkhole, decoys, AST/shell guards) and the observation pipeline. The model owns adapting to each MCP server’s language, layout, and entrypoint.

---

## 2. Vultr as the substrate

Production ToolPain is built around Vultr end to end:

```
                    ┌─────────────────────────────────────────┐
                    │           Vultr account                  │
                    │                                         │
  Browser ──HTTPS──►│  Control plane VM (long-lived)          │
                    │   FastAPI · SQLite · web UI             │
                    │   VULTR_API_KEY → create/destroy VMs    │
                    │   VULTR_INFERENCE_API_KEY → LLM proxy   │
                    │                                         │
                    │         │ provision scanner             │
                    │         ▼                               │
                    │  Scanner VM (ephemeral, from snapshot)  │
                    │   cloud-init → runner agent loop        │
                    │   Docker sandbox · sinkhole · strace    │
                    │   callbacks → CONTROL_PLANE_URL         │
                    │   destroyed when scan ends              │
                    │                                         │
                    │  Vultr Serverless Inference             │
                    │   Qwen (codegen) · research models      │
                    └─────────────────────────────────────────┘
```

| Vultr capability | How ToolPain uses it |
|------------------|----------------------|
| **Compute (VMs)** | One long-lived **control plane**; one **ephemeral scanner** per scan (or warm-pool members) from a baked snapshot |
| **Snapshots** | Scanner image with Docker, ToolPain install, and cloud-init entrypoint |
| **Serverless Inference** | Sole production LLM backend; keys stay on the control plane |
| **API** | Create/poll/destroy scanners; optional warm pool heartbeats |

Local `PROVISIONER=demo|local` exists for offline demos and development. **Hackathon / production path is `PROVISIONER=vultr` + `LLM_MODE=live`.**

---

## 3. Agentic flow (the harness loop)

Each scan is an **agentic pipeline**: observe → generate → run → repair → observe → report.

```
Intake (GitHub URL)
   │
   ▼
Provision Vultr scanner VM (or claim warm-pool member)
   │
   ▼
Fetch / clone repository on the scanner
   │
   ▼
┌──────────────────────────────────────────────────────┐
│  Agent loop (via CP → Vultr Inference)               │
│                                                      │
│  Qwen reviews tree + manifests + brief               │
│       │                                              │
│       ▼                                              │
│  Emits executable artifacts (guarded):               │
│    • setup_sh     — install / build the MCP server   │
│    • launch_sh    — how to start stdio MCP           │
│    • probe_py     — safe tool call plans             │
│    • oracle_py    — post-probe review hooks          │
│    • workdir_pick — monorepo package selection       │
│       │                                              │
│       ▼                                              │
│  Harness runs artifact → on failure, feeds error     │
│  back to the model and retries (bounded)             │
└──────────────────────────────────────────────────────┘
   │
   ▼
Discover tools (docs + static + runtime)
   │
   ▼
Research profiles (LLM) + probe every tool under strace / isolation
   │
   ▼
Analyze (discrepancy, privilege, SoD, egress, decoys)
   │
   ▼
Report + certificate narrative (LLM) → control plane
   │
   ▼
Destroy scanner VM (or release pool member)
```

**ToolPain is the harness:** it never lets the model run arbitrary host RCE. Generated shell/Python must pass AST and shell guards; execution happens inside Docker on the scanner VM.

**Qwen (codegen)** is the primary model that **reads the repo** and writes bootstrap/setup, launch, probe, and oracle programs so diverse MCP servers can be scanned without a hand-written adapter per language.

Other Vultr Inference models handle **research profiles** (claimed behavior / risk per tool) and **certificate / findings copy** for IT reviewers.

---

## 4. Components

### 4.1 Control plane (`control_plane/`)

Long-lived FastAPI service on Vultr.

- Serves `web/` and the public scan API + SSE
- Provisions and destroys scanner VMs (`PROVISIONER=vultr`)
- Optional warm scanner pool
- **LLM proxy** (`/internal/llm/chat`) — only process that holds `VULTR_INFERENCE_API_KEY`
- SQLite for scans, events, reports
- Reaper for orphaned `toolpain-scan-*` instances

### 4.2 Runner (`runner/`)

Agent worker on the ephemeral scanner (started by cloud-init).

Stages: fetch → codegen/build → launch → discover → research → probe → analyze → report.

Posts events and the final report to the control plane with a per-scan token. All model calls go through the CP proxy (keys never land on the scanner as Inference credentials).

### 4.3 Sandbox (`sandbox/`)

Per-scan Docker isolation on the scanner VM:

- Internal Docker network + **sinkhole** DNS/HTTP/TLS logger
- Planted **decoy** workspace
- Optional sidecars for declared dependencies
- Strace / gVisor tracing correlated to tool calls

### 4.4 Web UI (`web/`)

Intake, live scan progress, findings, access graph, certificate download, least-privilege allowlist.

---

## 5. Pipeline stages (summary)

| Stage | Owner | What happens |
|-------|--------|--------------|
| Intake | CP | Validate GitHub URL, mint scan token, estimate |
| Provision | Vultr API | Create or claim scanner VM |
| Fetch | Runner | Clone repo at ref |
| Codegen / build | Qwen + harness | Generate and run setup/launch until MCP speaks |
| Discover | Runner | Docs + static + runtime tool inventory |
| Research | Inference | Per-tool claimed behavior / risk profiles |
| Probe | Runner | Call tools; capture files/net/process |
| Analyze | Runner | Discrepancies, privilege, SoD, anomalies |
| Report | Runner + Inference | JSON report, IT-facing findings, certificate narrative |
| Destroy | CP | Tear down VM / release pool |

---

## 6. Analysis outcomes

**Discovery sources:** Docs (D), Static (S), Runtime (R), Flags (F).

**Privilege tiers:** critical → info (code exec, credentials, network, scoped file, UI-only, …).

**Verdicts:** `clean` · `over_privileged` · `suspicious` · `flagged` (decoy / undeclared egress).

**Certificate:** PDF/HTML record with business summary, recommendations, integrity hash, and least-privilege config.

---

## 7. Safety

- Scanned MCP server runs only in a container on an ephemeral Vultr VM
- No production internet from the run network (sinkhole + nftables)
- Model outputs are data/programs under guards — not unconstrained host shell
- Inference and Vultr account keys stay on the control plane
- Scanner destroyed (or pool host wiped of scan state) after each run

---

## 8. Repository layout

```
toolpain/
  README.md                 # product overview
  docs/ARCHITECTURE.md      # this file
  docs/VULTR_DEPLOY.md      # deploy on Vultr
  docs/RUNBOOK.md           # scan error codes
  web/                      # UI
  control_plane/            # harness control plane
  runner/                   # agent worker pipeline
  sandbox/                  # isolation helpers
  infra/                    # cloud-init, bake, nftables, install
  demo/                     # contained decoy demo server
  tests/
```

---

## 9. Related docs

- Product / quick start: [`README.md`](../README.md)
- Deploy on Vultr: [`docs/VULTR_DEPLOY.md`](VULTR_DEPLOY.md)
- Operator error codes: [`docs/RUNBOOK.md`](RUNBOOK.md)
