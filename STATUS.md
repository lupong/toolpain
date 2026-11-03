# ToolPain Status (2026-11-03)

## Done

- Control plane (FastAPI): scans API, SSE, SQLite, FakeProvisioner, LLM proxy stub, rate limit, BYO key memory + redaction
- Web UI: design ported to `web/`, intake POST, SSE live view, report hooks, demo chips
- Runner pipeline: discover (D/S/R/F) → research → probe → analyze → report
- `demo/decoy-trap-server` with contained decoy + sinkhole trip; README omits `fetch_report`
- FakeSandbox with recorded fixture; DockerSandbox + sinkhole/fixture images for real Docker
- Vultr ops + reaper (respx-tested); cloud-init / nftables / Caddy deploy docs
- `make lint`, `make test` (48 passed), `make demo` (verdict=flagged, decoy_reads=1)

## Stubbed / gaps

- Live Vultr VM provision path needs real `VULTR_API_KEY` + snapshot; not exercised in CI
- Live LLM (`LLM_MODE=live`) needs `VULTR_INFERENCE_API_KEY`
- gVisor (`runsc`) not installed on build host — runc + strace mode documented
- Playwright browser smoke is optional/skipped when Chromium absent
- Docker containment tests marked `@pytest.mark.docker` (may skip if daemon busy/unavailable)
- Fork-diff against real GitHub upstreams is shallow (local `upstream_tools.json`)

## How to verify

```bash
python3.12 -m venv .venv && source .venv/bin/activate
make install && make lint test demo
make dev   # http://127.0.0.1:8000 — click decoy-trap-server demo chip
```
