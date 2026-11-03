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

## Notes

- Started: 2026-11-03
- Design source: existing `design/` ported into `web/`
- Env: Docker present, runsc absent → `RUNTIME=runc` / FakeSandbox for offline demo
