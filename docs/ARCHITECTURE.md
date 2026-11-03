# ToolPain Architecture

ToolPain is a security scanner for AI agent MCP tools. A user pastes a GitHub link; ToolPain provisions an ephemeral sandbox, runs the MCP server with no internet, probes every tool, and reports what each tool really does versus what it claims.

## 1. Goals

- Prove runtime behavior of stdio MCP servers (Python + Node first).
- Contain all network egress via an in-sandbox sinkhole.
- Detect decoy reads, undeclared egress, undocumented tools, over-privilege, toxic combos.
- Never run a scanned server outside a container.
- Destroy the environment after every scan.

## 2. Components

### 2.1 Control plane (`control_plane/`)

FastAPI app on the long-lived Vultr VM (or localhost in `local`/`fake` mode).

- Public API + SSE for the web UI
- Serves `web/`
- Provisioner: `vultr` | `local` | `fake`
- Reaper for orphaned scan VMs
- SQLite (`scans`, `events`, `reports`)
- LLM proxy (sole holder of `VULTR_INFERENCE_API_KEY`)
- Runner callbacks authenticated by per-scan token (`X-Scan-Token`)

### 2.2 Runner (`runner/`)

Python process on the ephemeral scanner VM (or a container / subprocess in `local` mode).

Stages: fetch → build → isolate → discover → research → probe → analyze → report.

Posts events and the final report to the control plane. Calls the control-plane LLM proxy for research.

### 2.3 Sandbox (`sandbox/`)

- Per-scan Docker internal network `tp_internal_<scan>` subnet `10.66.<n>.0/24`
- `sinkhole` at `.53`: fake DNS (every name → self), catch-all HTTP/TLS/TCP logger
- `fixture-site`: static pages for browser-tool probing
- Decoy workspace planted at `/workspace` (read-only mount)
- Base images: node, python, playwright

### 2.4 Demo (`demo/decoy-trap-server/`)

Deliberately-bad FastMCP server for detection demos. Honest tools plus `fetch_report` that:

1. Reads only `/workspace/canaries/decoy_secret.txt` (planted by ToolPain)
2. Attempts a connection only to `collector.sinkhole.local` (in-sandbox sinkhole)

Never touches real secret paths or real hosts. README omits `fetch_report` so discovery flags it as undocumented.

## 3. Pipeline stages

| # | Stage | What happens |
|---|---|---|
| 0 | Intake | Validate GitHub URL, create scan record, mint token |
| 1 | Provision | Create VM / local sandbox / fake replay |
| 2 | Fetch | Clone repo at ref |
| 3 | Build | Install deps in networked build container; `docker commit` |
| 4 | Isolate | Start internal network, sinkhole, fixture-site, plant decoys |
| 5 | Discover | 4 sources: runtime default, runtime+flags, static, docs |
| 6 | Research | LLM profile per tool (claimed behavior, resources, risk) |
| 7 | Probe | Call each tool with safe args; capture strace window |
| 8 | Analyze | Discrepancy, privilege, SoD, egress, anomalies |
| 9 | Report | Assemble JSON report; POST to control plane |
| 10 | Destroy | Tear down containers/network/VM; scrub BYO key |

## 4. Analysis

### 4.1 Four-source discovery

- **D** Docs (README / LLM extraction)
- **S** Static source scan (regex)
- **R** Runtime default
- **F** Runtime with flags

Undocumented = present in S/R/F but not D. Hidden-behind-flag = only in F.

### 4.2 Discrepancy types

`undocumented`, `hidden_behind_flag`, `documented_missing`, `description_mismatch`, `fork_drift`

### 4.3 Privilege tiers

| Tier | Criteria (any match) |
|---|---|
| **critical** | Code exec / eval; arbitrary file write; credential / decoy read; unrestricted network + file read combo; subprocess spawn with shell |
| **high** | Arbitrary file read; browser automation with navigate+upload; network egress; file upload |
| **medium** | Scoped file access; PDF/screenshot save; limited network to declared hosts |
| **low** | Read-only UI actions (click, type, snapshot); no file/net/exec |
| **info** | Pure metadata / listing tools with no side effects |

### 4.4 Toxic combos (SoD)

Pairs that together enable: exfiltration, token theft, credential harvesting, covert channel, capability overlap.

### 4.5 Anomalies

Decoy reads, undeclared egress, subprocess spawns, metadata-endpoint access (`169.254.169.254`), obfuscation, prompt-injection text in tool descriptions.

### 4.6 Verdicts

| Verdict | When |
|---|---|
| `clean` | No high/critical findings; tools match claims |
| `over_privileged` | Privilege exceeds documentation; no decoy/egress trip |
| `suspicious` | Undocumented tools, fork drift, or medium anomalies |
| `flagged` | Decoy read and/or undeclared egress attempt |

Tool-level: `confirmed`, `exceeds_claim`, `not_observed`, `flagged`.

## 5. Network isolation

- Docker network `--internal`, fixed subnet `10.66.<n>.0/24`
- Sinkhole `.53` answers every DNS name with its own IP
- Logs DNS queries, HTTP request lines/headers, TLS SNI; then closes
- IP-literal outbound has no route; capture from `connect()` in strace
- Build stage has network; run stage does not

## 6. Tracing

- **gVisor (`runsc`)**: `--strace` + `--debug-log`
- **runc**: in-container `strace -f -tt -e trace=file,network,process`
- Events: `{ts, pid, kind: file|net|proc, detail}`
- Correlate to tool calls by window `[call_start, call_end + 500ms]`

## 7. LLM

- OpenAI-compatible client via Vultr Serverless Inference (`https://api.vultrinference.com/v1`)
- Control plane proxies; runner never holds the key
- `LLM_MODE=live|fake`; fake returns deterministic JSON fixtures
- All outputs JSON, Pydantic-validated, one retry on parse failure

## 8. Repository layout

```
toolpain/
  PROMPT.md
  PROGRESS.md
  DECISIONS.md
  BLOCKERS.md
  STATUS.md
  README.md
  Makefile
  pyproject.toml
  .env.example
  docs/ARCHITECTURE.md
  design/          # static design source (ported into web/)
  web/             # served by control plane
  control_plane/   # FastAPI
  runner/          # scan pipeline
  sandbox/         # sinkhole, fixture-site, helpers
  demo/decoy-trap-server/
  infra/           # cloud-init, nftables, deploy docs
  data/reports/
  tests/
```

## 9. API surface

### Public

- `POST /api/scans` — body `{repo_url, ref?, byo_vultr_key?}`
- `GET /api/scans`
- `GET /api/scans/{id}`
- `GET /api/scans/{id}/events` — SSE
- `GET /api/scans/{id}/report`

### Internal (runner)

- `POST /internal/scans/{id}/events` — header `X-Scan-Token`
- `POST /internal/scans/{id}/report` — header `X-Scan-Token`
- `POST /internal/llm/chat` — header `X-Scan-Token`

## 10. Safety

- No real secrets in sandbox; only planted decoys
- BYO Vultr key: process memory only, deleted after destroy; never in DB/logs/SSE
- Demo trap server targets only decoy path + sinkhole hostname
- Cap time, memory, pids; read-only root; cap-drop ALL
