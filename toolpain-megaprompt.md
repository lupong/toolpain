# ToolPain Megaprompt

**How to use this file**

| Tool | What to give it |
|---|---|
| **Claude Design** | Paste **Part 1** (and the sample data in Part 1.7). Export the result as HTML/CSS into the repo at `design/`. |
| **Cursor** | Put this whole file at the repo root as `PROMPT.md`, plus `docs/ARCHITECTURE.md`. Start an Agent run with: *"Read PROMPT.md and execute Part 2 end to end, unattended."* |

> **Safety note for the demo target (read first).** ToolPain proves it can *detect* a bad tool. To do that it needs one deliberately-bad test server. That server must **never** touch real credentials. It only ever reads a **decoy file that ToolPain itself plants** in the sandbox (e.g. `/workspace/canaries/decoy_secret.txt`) and tries to reach the **in-sandbox sinkhole**. It has no internet, targets nothing real, and works only inside the isolated network. Build the demo exactly this way. Do not write a tool that reads real secret paths (`~/.ssh`, `~/.aws`, browser stores) or contacts any real host.

---

# PART 1: Claude Design brief

## 1.1 Product

**ToolPain** (toolpain.com) is a security scanner for AI agent tools. A user pastes a GitHub link to an MCP server (for example a fork of `microsoft/playwright-mcp`). ToolPain launches a throwaway, locked-down Vultr VM, runs the server **with no internet**, calls every tool, and reports what each tool *really* does versus what it claims: undocumented tools, over-privileged tools, toxic tool combinations, downstream services, ingress/egress needs, and any attempt to read a planted decoy or reach an undeclared host — all caught inside the sandbox.

Tagline: **"Find the tools that hurt before they hurt you."**
Secondary line: *Every MCP tool, proven at runtime. Nothing leaves the sandbox.*

## 1.2 Audience & tone
- Security engineers, platform engineers, and developers adding MCP servers to agents.
- Tone: serious tool with a dry, slightly cheeky brand ("pain" puns used sparingly: *"Ouch: 3 critical findings"*). Never cartoonish.
- Visual direction: dark-first, terminal-adjacent security console. Precise, dense, readable. Incident console, not marketing site.

## 1.3 Constraints (must follow)
- Implementable in **plain HTML + CSS + vanilla JS**. No React, no build step.
- One shared `style.css` with CSS custom properties. Dark theme default, light theme via `[data-theme="light"]`.
- The graph view uses **cytoscape.js** (CDN). Design node/edge styles; don't ship a static image.
- Responsive down to 375 px. No horizontal page scroll.
- Accessible: WCAG AA contrast, visible focus states, severity never by color alone (icon + label too).

## 1.4 Design tokens (starting point)
- Background `#0B0D10`, surface `#12161B`, raised `#1A2027`, border `#2A323C`, text `#E6EAF0`, muted `#8A96A3`
- Accent `#FF5A36`; link/info `#4EA8FF`
- Severity: critical `#FF3B5C`, high `#FF8A3D`, medium `#F5C542`, low `#5AC8A0`, info `#8A96A3`
- Verdicts: confirmed `#5AC8A0`, exceeds_claim `#FF8A3D`, not_observed `#8A96A3`, flagged `#FF3B5C`
- Fonts: UI `Inter`, code/logs `JetBrains Mono` (Google Fonts)
- Radius 8 px; spacing 4/8/12/16/24/32/48

## 1.5 Screens to design

1. **Landing / intake (`index.html`)**
   - Hero: wordmark "ToolPain", tagline, one-line explainer.
   - Intake card: GitHub repo URL (required, validated, `owner/repo` chip when valid); branch/ref (optional, default `main`); "Advanced" disclosure with **Run in my own Vultr account** (toggle → API key field).
   - BYO-key warning panel when toggled: key used once, never stored; Vultr keys are account-wide; restrict the key to toolpain's IP; revoke after. Checkbox "I understand" required.
   - Primary button "Scan it". Secondary "Try a demo" with 3 chips: `server-filesystem (clean)`, `playwright-mcp (powerful)`, `decoy-trap-server (flagged)`.
   - "How it works" strip: Provision VM → Build → Isolate → Probe every tool → Destroy VM.
   - Recent scans list (repo, verdict badge, findings count, time).

2. **Live scan (`scan.html`, in-progress)**
   - Header: repo chip, scan ID, account-mode badge (`toolpain account` / `your account`), elapsed timer, Cancel.
   - Stage stepper (11): Intake, Provision, Fetch, Build, Isolate, Discover, Research, Probe, Analyze, Report, Destroy. States: pending / running / done / failed / skipped.
   - Containment panel (always visible): Network **BLOCKED**, runtime **gVisor**, CPU / memory meters, time-limit bar, decoys planted (count), undeclared-egress attempts caught (animated counter).
   - Live log console (monospace, autoscroll, level filter, pause).
   - Tool discovery list filling in as tools are found/probed (name, source badges D/S/R/F, spinner → verdict).
   - **Alert toast** for a decoy trip: "Flagged: `fetch_report` read the planted decoy and tried an undeclared host `collector.sinkhole.local`. Contained."

3. **Report (`scan.html`, done, tabbed)**
   - **Summary:** overall verdict (Clean / Over-privileged / Suspicious / Flagged), severity counts, stats (tools found, undocumented, critical-tier tools, toxic combos, undeclared egress hosts), "Ouch" headline for the top finding, buttons: Download JSON, Copy least-privilege config.
   - **Tools:** sortable/filterable table: name, privilege tier, verdict, source presence (D/S/R/F), egress, decoy reads. Row expands: claimed behavior, observed trace (files, processes, network), evidence snippets, downstream services.
   - **Access graph:** cytoscape canvas. Nodes: server, tool, capability (local files, network, code exec, browser data, subprocess), resource/host, decoy. Edges: claimed (dashed), observed (solid), toxic chain (thick red), blocked egress (red ⨯). Legend, zoom, click node → side panel.
   - **Findings:** grouped by severity; each card has type, tool(s), plain-English explanation, evidence (code block), recommendation.
   - **Toxic combos (SoD):** card list of tool pairs with risk type (exfiltration, token theft, credential harvesting, covert channel, overlap).
   - **Network:** ingress (listening ports) + egress table (host, declared?, attempted?, blocked, by which tool).
   - **Fork drift:** upstream vs. fork summary (tools added/changed/removed) with diff blocks.
   - **Least-privilege config:** generated JSON/YAML, copy button, short explanation.

4. **Error & edge states:** invalid repo, private repo, build failed (log excerpt), VM provisioning failed, scan timed out (partial-report banner), BYO key rejected, empty state.

## 1.6 Components
Buttons (primary, secondary, ghost, danger), validated inputs, toggle, disclosure, tabs, severity badge, verdict badge, source badges, stepper, meters, log console, toast, expandable-row table, code block with copy, finding card, graph legend, side panel, modal.

## 1.7 Sample report for mockups
```json
{
  "scan_id": "s_8f2c",
  "repo": {"url": "https://github.com/andrew/playwright-mcp", "commit": "a1b2c3d", "upstream": "microsoft/playwright-mcp",
           "fork_drift": [{"change": "added_tool", "tool": "fetch_report", "file": "src/tools/report.ts"}]},
  "verdict": "flagged",
  "stats": {"tools": 27, "undocumented": 1, "critical_tier": 3, "toxic_combos": 4, "egress_attempted": 2, "decoy_reads": 1},
  "tools": [
    {"name": "browser_navigate", "privilege": "high", "verdict": "confirmed", "sources": ["D","S","R"], "egress": ["fixture.local"], "decoy_reads": 0},
    {"name": "browser_evaluate", "privilege": "critical", "verdict": "confirmed", "sources": ["D","S","R"], "egress": [], "decoy_reads": 0},
    {"name": "browser_file_upload", "privilege": "high", "verdict": "exceeds_claim", "sources": ["D","S","R"], "egress": [], "decoy_reads": 0},
    {"name": "fetch_report", "privilege": "critical", "verdict": "flagged", "sources": ["S","R"], "egress": ["collector.sinkhole.local"], "decoy_reads": 1},
    {"name": "browser_click", "privilege": "low", "verdict": "confirmed", "sources": ["D","S","R"], "egress": [], "decoy_reads": 0},
    {"name": "browser_pdf_save", "privilege": "medium", "verdict": "confirmed", "sources": ["D","S","F"], "egress": [], "decoy_reads": 0}
  ],
  "toxic_combos": [
    {"tools": ["browser_file_upload","browser_navigate"], "risk": "exfiltration", "severity": "high"},
    {"tools": ["browser_evaluate","browser_navigate"], "risk": "token_theft", "severity": "high"}
  ],
  "findings": [
    {"id": "F1", "severity": "critical", "type": "decoy_read_and_egress", "tool": "fetch_report",
     "title": "Undocumented tool read a planted decoy and attempted an undeclared connection",
     "evidence": "openat(\"/workspace/canaries/decoy_secret.txt\") -> connect collector.sinkhole.local:443 (contained by sinkhole)"},
    {"id": "F2", "severity": "high", "type": "fork_added_tool", "tool": "fetch_report", "title": "Tool not present upstream"},
    {"id": "F3", "severity": "medium", "type": "hidden_behind_flag", "tool": "browser_pdf_save", "title": "Tool only appears with a capability flag"}
  ],
  "egress": {"declared": [], "attempted": [{"host": "collector.sinkhole.local", "tool": "fetch_report", "blocked": true},
                                          {"host": "cdn.thirdparty.local", "tool": "browser_navigate", "blocked": true}]},
  "least_privilege_config": {"allow_tools": ["browser_navigate","browser_snapshot","browser_click","browser_type"], "allow_hosts": ["your-app.example"]}
}
```

## 1.8 Deliverable
Static `index.html`, `scan.html` (with a state switcher for in-progress / done / error), `style.css`, and `design/README.md` listing components, tokens, and class names. Use semantic class names (`.tp-badge--critical`, `.tp-stepper__item--running`) so the build agent can wire them up.

---

# PART 2: Cursor autonomous build instructions

You are building **ToolPain** end to end, **unattended, up to 8 hours**. No human will answer questions. Read this whole part, then execute the milestones in order.

## 2.1 Operating rules (non-negotiable)
1. **Never stop to ask.** On ambiguity, choose the simplest option consistent with this spec, log it in `DECISIONS.md` (date, decision, reason), continue.
2. **Track progress in `PROGRESS.md`** — a checklist of milestones + acceptance checks. Update after every milestone. On restart, read it first and resume from the first unchecked item.
3. **Commit after every milestone** (and at least every 45 min): `M<n>: <summary>`. Never force-push, never rewrite history.
4. **Tests gate progress.** Run each milestone's checks. On failure, fix (max 3 attempts / ~30 min). If still failing, record in `BLOCKERS.md`, mark ⚠️ in `PROGRESS.md`, stub the piece behind an interface, move on. Never exceed 60 min on one blocker.
5. **No real secrets.** Never hard-code keys. Use `.env` (git-ignored) + `.env.example`. If `VULTR_API_KEY` or `VULTR_INFERENCE_API_KEY` is absent, use mock/fake implementations so everything still runs and tests pass.
6. **Safety on this machine and in the product.**
   - Never run a scanned MCP server outside a container.
   - Never `rm -rf` outside the repo, never `docker system prune`, never disable TLS verification.
   - The only deliberately-bad test server is `demo/decoy-trap-server` (§2.3). It must read **only** the planted decoy file and attempt **only** the in-sandbox sinkhole. It must not reference real secret paths or real hosts. If you ever find yourself writing code that reads `~/.ssh`, `~/.aws`, keychains, or browser credential stores, stop and use the decoy path instead.
7. **Environment detection (M0).** Detect Docker and gVisor (`runsc`); record in `DECISIONS.md`.
   - Docker + runsc → full mode. Docker only → `RUNTIME=runc` mode (internal network, cap-drop, default seccomp; note the gap). No Docker → build everything, mark docker tests `@pytest.mark.docker` (skipped), use `FakeSandbox` for pipeline tests.
8. **Scope.** Stdio MCP servers first; Python + Node targets only. No auth, no payments, no multi-tenant accounts.
9. **Quality.** Python 3.12, type hints, `ruff` clean, `pytest` green, small functions, module docstrings. Front end: plain HTML/CSS/JS, no build step.
10. **UI source.** If `design/` exists, port its HTML/CSS into `web/` and wire it up, keeping class names. Else build the UI from Part 1.

## 2.2 Spec references
- Full architecture: `docs/ARCHITECTURE.md` (wins on conflict).
- Hackathon requirements: backend on a Vultr VM; web app deployed on Vultr; **agent LLM calls use Vultr Serverless Inference** (OpenAI-compatible, `https://api.vultrinference.com/v1`); isolated sandbox execution; time + memory caps; no secrets in the sandbox; environment destroyed after each scan.

## 2.3 Architecture summary
- **control_plane/** (FastAPI, on your Vultr VM): public API + SSE, serves `web/`, provisioner (`vultr` | `local` | `fake`), reaper, SQLite, **LLM proxy** (only holder of the inference key), runner callbacks authenticated by a per-scan token.
- **runner/** (Python, on the ephemeral scanner VM, or a container in `local` mode): stages fetch → build → isolate → discover → research → probe → analyze → report. Calls the control plane for LLM and events.
- **sandbox/**: `sinkhole` (fake DNS + catch-all HTTP/TLS/TCP logger; one Python container, `dnslib` + asyncio), `fixture-site` (static pages: login, form, upload, page with a token in localStorage, page loading a third-party script), base images (node, python, playwright).
- **demo/decoy-trap-server/**: a Python FastMCP server with honest tools plus one tool, `fetch_report`, that (a) reads the planted decoy at `/workspace/canaries/decoy_secret.txt` and (b) attempts a connection to `collector.sinkhole.local`. Both are inside the isolated sandbox; the decoy is fake data ToolPain placed there and the host resolves only to the sinkhole. This exists solely to prove detection. Its README intentionally omits `fetch_report` so discovery flags it as undocumented.

## 2.4 Key technical decisions (already made; don't revisit)
- **MCP client:** official Python SDK `mcp` (`ClientSession`, `StdioServerParameters`, `mcp.client.stdio.stdio_client`). Start the target **through Docker**: stdio command is `docker run -i --rm --runtime=$RUNTIME --network tp_internal_<scan> --dns <sinkhole_ip> --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges --pids-limit 256 --memory 2g --cpus 2 -v <decoy_workspace>:/workspace:ro <image> <server cmd>`. In runc mode add `--cap-add SYS_PTRACE` only and wrap the server with `strace -f -tt -e trace=file,network,process -o /trace/trace.log`.
- **Network isolation:** per-scan Docker network, `--internal`, fixed subnet `10.66.<n>.0/24`. Sinkhole at `.53` answers **every** DNS name with its own IP, logs queries, accepts TCP on 80/443/any listed port, logs HTTP request lines + headers and the TLS SNI, then closes. IP-literal connections out have no route; capture them from the trace's `connect()` calls.
- **Build stage:** separate container with network allowed (build only). Node `npm ci` (trace to record install scripts); Python `pip install .` / `uv pip install`. Then `docker commit` → run image. The run stage has no internet.
- **Decoys:** per-scan unique values in `decoy_workspace/canaries/decoy_secret.txt`, `decoy_workspace/.env` (`API_TOKEN=decoy-<scanid>`), plus a fixture-site cookie and localStorage token. Detection: file opens in the trace, plus any decoy string found in sinkhole logs. (No real credential paths anywhere.)
- **Tracing:** gVisor mode = `runsc` with `--strace` + `--debug-log` (document in `infra/docker-daemon.json`). runc mode = in-container strace. Parse to events `{ts, pid, kind: file|net|proc, detail}`. Correlate to tool calls by time window `[call_start, call_end + 500ms]`.
- **LLM:** `openai` Python client, `base_url` = control-plane proxy (runner side) or Vultr inference (proxy side). Env `VULTR_INFERENCE_API_KEY`, `VULTR_INFERENCE_MODEL` (default: first chat model from `GET /v1/models`). `LLM_MODE=live|fake`; `fake` returns deterministic JSON fixtures so tests run offline. All LLM outputs requested as JSON, validated with Pydantic, one retry on parse failure.
- **Vultr API v2:** `https://api.vultr.com/v2`, Bearer auth. `POST /instances`, `GET /instances/{id}`, `DELETE /instances/{id}`, `GET /snapshots`, `POST /firewalls`, `POST /firewalls/{id}/rules`. `user_data` = base64 cloud-init. Tag `toolpain`, label `toolpain-scan-<id>`. Test with `respx`; never call the real API in tests.
- **BYO key:** process memory only (dict keyed by scan_id), deleted after destroy. Never in DB, logs, or SSE. Add a log-redaction filter for Vultr key patterns.
- **Storage:** SQLite (`scans`, `events`, `reports`); reports also as JSON in `data/reports/`.
- **Front end:** vanilla JS, `EventSource` for SSE, cytoscape.js via CDN, no framework.

## 2.5 Milestones (in order; ~8h total)

**M0 — Bootstrap (20 min).** Repo layout per `docs/ARCHITECTURE.md` §8; `pyproject.toml` (fastapi, uvicorn, pydantic, httpx, mcp, openai, dnslib, respx, pytest, pytest-asyncio, ruff); `Makefile` (`dev`, `test`, `lint`, `demo`); `.env.example`; `PROGRESS.md`, `DECISIONS.md`, `BLOCKERS.md`; environment detection.
✅ `make lint` and `make test` run; an empty test passes.

**M1 — Control plane skeleton (40 min).** FastAPI serving `web/`; `POST /api/scans` (validate `https://github.com/<owner>/<repo>`), `GET /api/scans`, `GET /api/scans/{id}`, `GET /api/scans/{id}/events` (SSE), `GET /api/scans/{id}/report`; internal `POST /internal/scans/{id}/events|report` with `X-Scan-Token`; SQLite; `FakeProvisioner` that replays a scripted scan emitting the sample events + sample report (Part 1.7).
✅ pytest: create scan → SSE yields stage events → report endpoint returns JSON. Invalid URL → 422. Wrong token → 401.

**M2 — Web UI (60 min).** Port `design/` (or build from Part 1) into `web/`. Wire intake → POST → `scan.html?id=` → SSE live view → report tabs → graph from report JSON. Demo chips start fake scans.
✅ With `PROVISIONER=fake`, a full scan plays out in-browser. Add a Python Playwright smoke test (skipped if browsers absent) that loads index, submits, waits for "Report".

**M3 — MCP client + discovery (50 min).** `runner/mcp_client.py` (stdio connect, initialize, list tools/resources/prompts, call with timeout); `discover.py` with 4 sources: runtime default, runtime with flags (parse `--help`/README, try each), static source scan (regexes for TS `name: '...'`, `server.tool(`, Python `@mcp.tool`, `Tool(name=`), docs (LLM extraction; fake mode = regex on README). Build `demo/decoy-trap-server`.
✅ Discovery on `demo/decoy-trap-server` (own code; running it as a local process is fine for this one test) finds all tools and flags `fetch_report` as undocumented.

**M4 — Sandbox + sinkhole + decoys (70 min)** *(docker-marked).* `sandbox.py`: per-scan internal network, start sinkhole + fixture-site, plant decoys, build the docker stdio command, tear everything down in `finally`. `sandbox/sinkhole/` service. `trace.py` parser.
✅ (docker) From inside the sandbox, `curl http://example.com` and a socket connect to `collector.sinkhole.local:443` are logged by the sinkhole and the real internet is unreachable; teardown leaves no `tp_*` networks/containers. (no docker) `FakeSandbox` replays a recorded trace fixture and the parser produces the expected events.

**M5 — Research + probe + trace correlation (60 min).** `research.py` (LLM tool profile per tool: claimed behavior, resources, downstream, risk; fake mode = fixtures). `probe.py`: generate safe args from each tool's `inputSchema` (empty/minimal values, fixture-site URLs for browser tools), call each tool, capture the trace window, retry once on schema error. Correlate trace events to calls.
✅ Probing `demo/decoy-trap-server` in the sandbox records, for `fetch_report`, a decoy file read plus a contained connection attempt to the sinkhole; honest tools show no such events.

**M6 — Analysis (60 min).** `analyze/`: `discrepancy.py` (4-source compare → undocumented / hidden-behind-flag / documented-missing / description-mismatch / fork drift), `privilege.py` (tiering rules from `docs/ARCHITECTURE.md` §4.3), `sod.py` (toxic combos incl. covert-channel/shared-storage pattern), `downstream.py` (SDK imports, env vars, hosts), `egress.py` (declared vs attempted, ingress ports), `anomalies.py` (decoy reads, undeclared egress, subprocess spawns, metadata-endpoint access, obfuscation, prompt-injection text in tool descriptions). `report.py` assembles the report model.
✅ Analysis of the decoy-trap scan yields: verdict `flagged`, ≥1 critical finding (`decoy_read_and_egress`), fork-drift note on `fetch_report`, and ≥1 toxic combo. Validate against the Part 1.7 shape.

**M7 — End-to-end local run (40 min).** Wire `runner/main.py` to run all stages and post events + report to the control plane; `LocalProvisioner` runs the runner against the sandbox on this machine. `make demo` runs a full real scan of `demo/decoy-trap-server` and (if Docker) upstream `server-filesystem`, end to end, no fakes.
✅ `make demo` produces a real report in the UI with a contained decoy trip; scanner teardown verified.

**M8 — Vultr provisioning (60 min).** `provisioner/vultr.py` (create/poll/delete, firewall group with no inbound, tags/labels, base64 cloud-init); `reaper.py` (delete any `toolpain-scan-*` older than 30 min); `infra/cloud-init.yaml`, `infra/build-snapshot.sh`, `infra/nftables.conf` (drop forward from docker bridges, block link-local metadata, host egress only to control plane + GitHub + npm + PyPI during build). BYO-key path (memory only) + redaction filter.
✅ `respx` tests: create → poll ready → runner callback → destroy; BYO key never appears in DB/logs/SSE (assert via a log-capture test).

**M9 — Deploy + harden + demo polish (50 min).** `Caddyfile` (HTTPS for toolpain.com), `infra/README-deploy.md` (snapshot build, control-plane deploy, DNS), rate-limit per IP, graceful partial report on timeout. Seed 3 demo scans. Top-level `README.md` with architecture diagram, the containment story, and a 3-minute demo script.
✅ Fresh checkout: `make dev` serves the UI; demo chips replay seeded reports; README demo script matches the UI.

**M10 — Buffer / hardening (remaining time).** Clear `BLOCKERS.md` items in priority order; raise test coverage on `analyze/` and `sandbox/`; re-run `make lint test demo`; final commit `M10: stabilize`. Leave a `STATUS.md` summarizing done / stubbed / known gaps for the human.

## 2.6 Definition of done
- `make lint test` green (docker-marked tests skipped when no Docker).
- `make demo` runs a real scan of `demo/decoy-trap-server` and shows a contained decoy trip with a full report + graph.
- With a real `VULTR_API_KEY` + `VULTR_INFERENCE_API_KEY` and `PROVISIONER=vultr`, a scan provisions a VM, scans, reports, and destroys the VM (document how to verify; don't require it in CI).
- `PROGRESS.md`, `DECISIONS.md`, `BLOCKERS.md`, `STATUS.md`, `README.md` all present and current.

## 2.7 If you get stuck
Log it in `BLOCKERS.md`, stub behind an interface, keep the pipeline runnable in fake mode, and keep moving. A working fake-mode end-to-end demo plus real sandbox containment is worth more than any single real integration. Never block the whole build on one external dependency.
