# ToolPain

**Find the tools that hurt before they hurt you.**

Every MCP tool, proven at runtime. Nothing leaves the sandbox.

ToolPain is a security scanner for AI agent tools. Paste a GitHub link to an MCP server (for example a fork of `microsoft/playwright-mcp`). ToolPain launches a throwaway, locked-down environment, runs the server **with no internet**, calls every tool, and reports what each tool *really* does versus what it claims: undocumented tools, over-privileged tools, toxic combinations, downstream services, ingress/egress needs, and any attempt to read a planted decoy or reach an undeclared host — all caught inside the sandbox.

```
┌─────────────┐     SSE/API      ┌────────────────┐
│  web/ UI    │◄────────────────►│ control_plane  │  Vultr Inference proxy
└─────────────┘                  │  FastAPI+SQLite│  BYO key (memory only)
                                 └───────┬────────┘
                                         │ provision
                    ┌────────────────────▼────────────────────┐
                    │  ephemeral sandbox (Docker internal net)│
                    │  sinkhole DNS/HTTP/TLS · decoys · strace│
                    │  runner: fetch→build→isolate→discover→  │
                    │           research→probe→analyze→report │
                    └─────────────────────────────────────────┘
```

## Quick start (3-minute demo)

```bash
git clone https://github.com/lupong/toolpain.git
cd toolpain
python3.12 -m venv .venv && source .venv/bin/activate
make install
cp .env.example .env          # PROVISIONER=fake, LLM_MODE=fake
make dev                      # http://127.0.0.1:8000
```

1. Open the UI. Click **decoy-trap-server (flagged)**.
2. Watch the live stepper + log. An alert toast fires when `fetch_report` trips the decoy.
3. When the scan finishes, open **Findings** and **Access graph**.
4. Download JSON or copy the least-privilege allowlist.

Other demo chips: `server-filesystem (clean)`, `playwright-mcp (powerful)`.

### Real local sandbox demo

With Docker running:

```bash
# .env: PROVISIONER=local
make demo
```

This scans `demo/decoy-trap-server` end to end and shows a contained decoy trip.

### Scan a real GitHub MCP server

Fetch/build/launch are packaged (data-only plans + allowlisted templates). Example — official time server:

```bash
# .env: PROVISIONER=local
make dev   # then paste https://github.com/modelcontextprotocol/servers in the UI
# or CLI:
python -m runner.main --scan-id s_time \
  --repo-url https://github.com/modelcontextprotocol/servers \
  --prefer-subdir src/time
```

`sandbox=auto` uses FakeSandbox only for `demo/**`; everything else clones, builds a strace-capable image from `runner/templates/`, trials LaunchPlan argv until MCP `initialize` succeeds, then probes inside DockerSandbox.

## Safety

The only deliberately-bad test server is `demo/decoy-trap-server`. It reads **only** `/workspace/canaries/decoy_secret.txt` (planted by ToolPain) and attempts **only** `collector.sinkhole.local` (in-sandbox sinkhole). It never touches real secret paths (`~/.ssh`, `~/.aws`, browser stores) or real hosts.

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Build status: [`PROGRESS.md`](PROGRESS.md). Deploy: [`infra/README-deploy.md`](infra/README-deploy.md).

| Mode | When |
|---|---|
| `PROVISIONER=fake` | Offline UI + API demo (default) |
| `PROVISIONER=local` | Runner + Docker sandbox on this machine |
| `PROVISIONER=vultr` | Ephemeral Vultr VMs (`VULTR_API_KEY` required) |

LLM calls go through the control-plane proxy. For diverse repos the model emits **executable** scan artifacts (AST/shell-guarded):

- `launch_sh` — container entrypoint only
- `probe_py` — `build_plans()` (+ optional `next_plans()` for a second probe round)
- `workdir_pick_py` — monorepo package selection when `prefer_subdir` is unset
- `oracle_py` — `review_observations()` → structured findings after probing

Optional **scan brief** (UI / `scan_brief` API field) is prompt context that biases those generators. Install/language recipes stay JSON; Dockerfiles stay packaged templates.

| `LLM_MODE` | Backend |
|---|---|
| `fake` | Fixtures (default for offline tests) |
| `openai` | OpenAI API (`OPENAI_API_KEY`, model default `gpt-4o-mini`) |
| `ollama` | Local [Ollama](http://127.0.0.1:11434) OpenAI `/v1` (`OLLAMA_MODEL`, default `llama3.2:latest`) |
| `live` | [Vultr Serverless Inference](https://api.vultrinference.com/v1) (`VULTR_INFERENCE_API_KEY`) |

## Support matrix (v3)

| Target | Status |
|---|---|
| Python / Node stdio MCP | Supported |
| HTTP / SSE MCP (`protocol=http\|sse` + `mcp_url`) | Supported for an already-running endpoint |
| Go / Rust | Bring-your-own image (`image` + `server_cmd`); otherwise `unsupported_language` |
| gVisor | Optional when `runsc` is installed (`RUNTIME=runsc`) |

Share a finished report with `POST /api/scans/{id}/share`. Compare two reports with `GET /api/compare?a=&b=`.

## License

MIT (hackathon prototype).
