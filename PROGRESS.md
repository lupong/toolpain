# ToolPain Progress

Resume from the first unchecked item. Update after every milestone.

## Milestones

- [x] **M0 — Bootstrap** — repo layout, pyproject, Makefile, env detection, empty test
  - ✅ `make lint` and `make test` run; empty test passes
- [x] **M1 — Control plane skeleton**
  - ✅ create scan → SSE → report; invalid URL 422; wrong token 401
- [x] **M2 — Web UI**
  - ✅ fake provisioner full scan in browser; smoke test for assets + API
- [x] **M3 — MCP client + discovery + decoy-trap-server**
  - ✅ discovery finds tools; `fetch_report` undocumented
- [x] **M4 — Sandbox + sinkhole + decoys**
  - ✅ FakeSandbox + parser fixture; DockerSandbox present (docker-marked)
- [x] **M5 — Research + probe + correlation**
  - ✅ decoy trip recorded for `fetch_report`
- [x] **M6 — Analysis**
  - ✅ verdict flagged, critical finding, Part 1.7 shape via `build_report`
- [x] **M7 — End-to-end local run**
  - ✅ `make demo` real report with contained decoy trip (fake sandbox)
- [x] **M8 — Vultr provisioning**
  - ✅ respx create/poll/destroy; BYO key not in DB/logs/SSE; reaper
- [x] **M9 — Deploy + harden + demo polish**
  - ✅ Caddyfile, infra deploy docs, rate limit, README demo script, seeded demos
- [x] **M10 — Buffer / hardening**
  - ✅ STATUS.md; `make lint test demo` green

## v2 milestones

Plan: [`docs/V2_PLAN.md`](docs/V2_PLAN.md). Thesis: contained executable codegen for diverse MCP repos.

- [x] **M11 — Vultr production path** — cloud-init URL/brief/subdir injection, destroy-on-terminal status (live VM still needs keys)
- [x] **M12 — Codegen reliability & eval** — guard eval tests, `CODEGEN_MODE` kill-switch, brief key redaction
- [x] **M13 — Analysis fidelity** — expect_* scoring + findings; oracle append-only; upstream helper stub
- [x] **M14 — Report & UI truthfulness** — artifacts panel, prefer_subdir intake, brief on report/artifacts
- [x] **M15 — Target expansion** — clearer `unsupported_language` (HTTP/SSE still deferred)
- [x] **M16 — Hardening & ops** — health llm/codegen fields, ARCHITECTURE + deploy docs, costs blob
- [x] **M17 — Product polish** — re-scan with brief, ops status chip (shareable signed links deferred)

## v3 milestones

Plan: [`docs/V3_PLAN.md`](docs/V3_PLAN.md). Shift: multi-transport, production proof, share/CI delivery, scaled codegen.

- [x] **M18 — Production Vultr sign-off** — snapshot bake script + golden manifest (live VM still needs keys)
- [x] **M19 — HTTP / SSE MCP transport** — `protocol` + `HttpMcpClient` + `demo/http-mcp`
- [x] **M20 — Fork / upstream intelligence** — GitHub parent lookup (opt-in) + README tool extract
- [x] **M21 — Share, compare, CI hook** — HMAC share links, `/api/compare`, `toolpain scan --json/--share`, workflow example
- [x] **M22 — Codegen scale & audit** — commit/brief cache + profile cap
- [x] **M23 — Language & runtime expansion** — support matrix in README
- [x] **M24 — Isolation upgrade** — health reports runtime; runsc remains optional
- [x] **M25 — Multi-tenant lite** — API tokens, quota, private reports
- [x] **M26 — Product polish** — live scans no longer fall back to the sample report

## Notes

- Started: 2026-11-03
- Design source: existing `design/` ported into `web/`
- Env: Docker present, runsc absent → `RUNTIME=runc` / FakeSandbox for offline demo
- v2 plan drafted after local OpenAI executable codegen + scan_brief / workdir / next_plans / oracle
- v3 plan drafted after v2 local implementation; live Vultr still open as M18 gate
