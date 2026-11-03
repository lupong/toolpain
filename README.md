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

## Safety

The only deliberately-bad test server is `demo/decoy-trap-server`. It reads **only** `/workspace/canaries/decoy_secret.txt` (planted by ToolPain) and attempts **only** `collector.sinkhole.local` (in-sandbox sinkhole). It never touches real secret paths (`~/.ssh`, `~/.aws`, browser stores) or real hosts.

## Architecture

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Build status: [`PROGRESS.md`](PROGRESS.md). Deploy: [`infra/README-deploy.md`](infra/README-deploy.md).

| Mode | When |
|---|---|
| `PROVISIONER=fake` | Offline UI + API demo (default) |
| `PROVISIONER=local` | Runner + Docker sandbox on this machine |
| `PROVISIONER=vultr` | Ephemeral Vultr VMs (`VULTR_API_KEY` required) |

LLM calls go through the control-plane proxy to [Vultr Serverless Inference](https://api.vultrinference.com/v1). Set `LLM_MODE=fake` for deterministic fixtures.

## License

MIT (hackathon prototype).
