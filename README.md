# ToolPain

**Find the tools that hurt before they hurt you.**

Security scanner for AI agent MCP tools. Paste a GitHub link to an MCP server; ToolPain runs it in a locked-down sandbox with no internet, probes every tool, and reports what each tool *really* does versus what it claims.

> Full demo script and architecture diagram land in M9. Until then: `make install && make dev`.

## Quick start

```bash
python3.12 -m venv .venv
source .venv/bin/activate
make install
cp .env.example .env   # PROVISIONER=fake by default
make dev               # http://127.0.0.1:8000
```

## Safety

The only deliberately-bad demo server is `demo/decoy-trap-server`. It reads **only** a planted decoy at `/workspace/canaries/decoy_secret.txt` and attempts **only** `collector.sinkhole.local` inside the sandbox sinkhole. It never touches real secret paths or real hosts.

See `docs/ARCHITECTURE.md`, `PROMPT.md`, and `PROGRESS.md`.
