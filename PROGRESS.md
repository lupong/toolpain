# ToolPain Progress

Resume from the first unchecked item. Update after every milestone.

## Milestones

- [x] **M0 — Bootstrap** — repo layout, pyproject, Makefile, env detection, empty test
  - ✅ `make lint` and `make test` run; empty test passes
- [ ] **M1 — Control plane skeleton**
  - ✅ create scan → SSE → report; invalid URL 422; wrong token 401
- [ ] **M2 — Web UI**
  - ✅ fake provisioner full scan in browser; Playwright smoke (skip if no browsers)
- [ ] **M3 — MCP client + discovery + decoy-trap-server**
  - ✅ discovery finds tools; `fetch_report` undocumented
- [ ] **M4 — Sandbox + sinkhole + decoys**
  - ✅ docker containment OR FakeSandbox + parser fixture
- [ ] **M5 — Research + probe + correlation**
  - ✅ decoy trip recorded for `fetch_report`
- [ ] **M6 — Analysis**
  - ✅ verdict flagged, critical finding, toxic combo, Part 1.7 shape
- [ ] **M7 — End-to-end local run**
  - ✅ `make demo` real report with contained decoy trip
- [ ] **M8 — Vultr provisioning**
  - ✅ respx create/poll/destroy; BYO key not in DB/logs/SSE
- [ ] **M9 — Deploy + harden + demo polish**
  - ✅ `make dev` + demo chips + README demo script
- [ ] **M10 — Buffer / hardening**
  - ✅ STATUS.md; `make lint test demo`; final commit

## Notes

- Started: 2026-11-03
- Design source: existing `design/` ported from Claude Design brief
