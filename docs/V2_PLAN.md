# ToolPain v2 Plan

**Status:** implemented locally (2026-11-04) — live Vultr e2e still needs API keys + snapshot  
**Baseline:** v1 hackathon slice — M0–M10 + local OpenAI executable codegen (`launch_sh`, `probe_py`/`next_plans`, `workdir_pick`, `oracle_py`, `scan_brief`)  
**Thesis:** ToolPain adapts to arbitrary MCP repos by generating **contained executable scan code**, not by hard-coding every package layout.

---

## 1. Problem / opportunity

MCP servers vary wildly (language, monorepo layout, entrypoints, schemas, side effects). A fixed heuristic pipeline will always lag. v1 proved the product thesis locally: OpenAI emits install/launch/probe/oracle artifacts that the runner executes under Docker + AST/shell guards.

v2 turns that prototype into a **reliable, deployable scanner product**: production Vultr path, deeper analysis fidelity, broader MCP surface, eval-gated codegen quality, and a report UI that shows *what the model generated and what actually ran*.

---

## 2. What v1 already is (do not rebuild)

| Layer | Shipped |
|---|---|
| Control plane | FastAPI, SQLite, SSE, rate limit, LLM proxy, fake/local/vultr provisioners |
| Runner | fetch → recipe/codegen → build → launch trial → discover → research → probe (+ round 2) → oracle → analyze → report |
| Containment | DockerSandbox, sinkhole, fixture-site, decoys, strace correlation |
| Executable codegen | `EXECUTABLE_SCAN_CODE`, `WORKDIR_PICK_CODE`, shell_guard, ast_guard |
| Intake | GitHub URL, ref, prefer_subdir, scan_brief, demo chips, BYO Vultr key UI |
| Demo | `decoy-trap-server` end-to-end flagged path |

**Known gaps (inputs to v2):** Vultr never live-proven; `CONTROL_PLANE_URL` not injected in cloud-init; UI report still partially sample; harness `expect_*` not scored; fork drift shallow; stdio Python/Node only; gVisor optional; codegen cost/latency unbounded; no eval suite for generated code quality.

---

## 3. v2 goals

1. **Production scan path** — `PROVISIONER=vultr` creates ephemeral VMs, runs the same runner, posts report, destroys; reaper trustworthy.
2. **Executable-codegen productization** — generated artifacts are first-class in the report, versioned, eval-gated, and safe by construction.
3. **Analysis that matches the thesis** — compare *claimed vs observed*, score harness expectations, real upstream fork drift, oracle findings that affect verdict consistently.
4. **Operator UX** — intake brief + live stages that name codegen steps; report shows launch script, probe module summary, workdir pick, oracle notes.
5. **Broader targets** — Node maturity, HTTP/SSE MCP where feasible, clearer failures for unsupported languages.

### Non-goals (v2)

- Full multi-tenant SaaS billing / accounts
- Unrestricted host RCE or LLM-authored Dockerfiles
- Scanning non-GitHub arbitrary tarballs (unless explicitly added later)
- Replacing packaged analyzers with free-form LLM judgment as sole verdict

---

## 4. Principles (carry forward)

1. **Generated code runs only in named containment channels** (image entrypoint, AST-allowlisted modules).
2. **Dockerfiles and network policy stay packaged templates.**
3. **User brief is prompt context**, never a new execution channel.
4. **Reads free / writes confirm** for any external write integrations; BYO keys never persist.
5. **Fail closed to heuristics** when guards reject model output — scan must still complete when possible.
6. **Every codegen step emits provenance** (`source: llm|heuristic`, errors, truncated source) into the report.

---

## 5. Architecture deltas

```
v1:  UI → CP → LocalProvisioner → runner (OpenAI via CP proxy) → Docker on laptop

v2:  UI → CP (public) → VultrProvisioner → cloud-init VM (snapshot)
                      ↘ LocalProvisioner (dev)
         runner on VM → same codegen + Docker sandbox
         LLM always via CP `/internal/llm/chat` (openai | live | ollama)
```

### Must-fix for Vultr

| Item | Why |
|---|---|
| Inject `{{CONTROL_PLANE_URL}}` in `vultr_ops` cloud-init | VM cannot callback without it |
| Pass `scan_brief`, `prefer_subdir`, `ref` through cloud-init / scan.env | Feature parity with local |
| Snapshot bake script that pins ToolPain commit + Docker images | Cold clone of `main` lags local work |
| Report-driven destroy (not only soft wait) | Cost + security |
| Health: scanner VM posts `provision` / `runner_start` early | Distinguish boot vs scan failure |

### Codegen evolution (still contained)

| Artifact | v1 | v2 |
|---|---|---|
| `launch_sh` | yes | + richer arg allowlist; optional env allowlist file (data) |
| `probe_py` | `build_plans` + `next_plans` | + max rounds policy; cost budget; plan diff in report |
| `workdir_pick_py` | yes | + exclude nested `server.py`-only under strong parents (done); cache per commit |
| `oracle_py` | emits findings | + severity whitelist enforced on verdict; merge rules documented |
| *(new)* `flag_probe_py` | — | propose capability-flag argv sets from `--help` (AST) |
| *(new)* `schema_repair_py` | — | optional third-round arg repair after schema errors |

Keep **out** of executable surface: Dockerfile bodies, host shell, unrestricted analyzer, network clients in generated Python.

---

## 6. Product surface

### Intake

- Keep: repo URL, ref, brief, advanced BYO, demos
- Add: optional `prefer_subdir` in Advanced; language/protocol hint (auto|python|node|http)
- Show estimated stages + “executable codegen enabled” when `LLM_MODE` ≠ fake

### Live scan view

- Explicit events for: workdir pick, launch.sh generated, image build, launch trial, probe round 1/2, oracle
- Surface guard fallbacks as warnings (not silent)

### Report

- **Artifacts** panel: launch_sh, workdir, probe summary, oracle findings count, brief
- **Expectations**: harness `expect_decoy` / `expect_hosts` / `expect_files` vs observed (pass/fail)
- Real tool graph + findings (retire sample HTML leftovers)
- Download JSON + short markdown summary

---

## 7. Workstreams & milestones

### M11 — Vultr production path (P0)

**Outcome:** One public GitHub MCP repo scanned end-to-end on a real Vultr VM with OpenAI or Vultr Inference.

- Fix cloud-init placeholder injection (`CONTROL_PLANE_URL`, brief, prefer_subdir)
- Snapshot build runbook + `VULTR_SNAPSHOT_ID` verification checklist
- Destroy-on-report + reaper metrics/logs
- Staging env doc: CP VM + DNS + Caddy
- Acceptance: instance `toolpain-scan-*` appears, report lands, instance gone; BYO key never in SQLite/SSE

### M12 — Codegen reliability & eval (P0)

**Outcome:** Generated code quality is measurable; regressions catch prompt/guard breaks.

- Golden-repo suite (offline fixtures + optional live OpenAI nightly):
  - `decoy-trap-server` → flagged + decoy
  - `servers/src/time` → clean + `mcp-server-time` launch
  - Hostile README trying `os.system` / `curl|sh` → guard reject + heuristic fallback + scan completes
  - Monorepo without `prefer_subdir` + brief “prefer time” → `src/time`
- Assert report fields: `recipe.codegen`, `probe_codegen`, `workdir_pick`, `scan_brief`
- Token/latency budget per scan (cap tool-profile fanout or batch)
- Retire JSON `PROBE_HARNESS` as primary path (keep fallback)

### M13 — Analysis fidelity (P0/P1)

**Outcome:** Verdicts reflect expectations + better discrepancy.

- Score harness `expect_*` against probe windows → findings `expectation_miss` / `expectation_hit`
- Oracle merge policy: oracle may add findings; cannot downgrade `flagged` from decoy/egress
- Real GitHub upstream tool list for forks (API compare default branch tool names when possible)
- Prompt-injection detection in tool descriptions already partial — expand + test

### M14 — Report & UI truthfulness (P1)

**Outcome:** UI shows real report data only.

- Replace remaining sample panels with report JSON bindings
- Artifacts + expectations sections
- Empty/error/loading states for missing oracle/codegen
- Scan brief echoed on report header

### M15 — Target expansion (P1)

**Outcome:** More real-world MCP servers scan successfully.

- Node path hardening (npm/pnpm, bin layouts, long builds)
- Clear `unsupported_language` failure with remediation
- Spike: HTTP/SSE MCP transport (behind feature flag); stdio remains default
- Optional: Go/Rust “bring your own image” later — not required to close v2

### M16 — Hardening & ops (P1)

**Outcome:** Safer defaults for anything internet-facing.

- gVisor path documented + optional snapshot with `runsc`
- Resource limits audit (pids/memory already present — verify on Vultr plans)
- LLM key rotation guidance; redact brief if it looks like a secret
- Structured logging + scan cost fields (LLM tokens if available, VM minutes)
- CI: unit + codegen guard tests always; docker-marked optional; live OpenAI nightly optional secret

### M17 — Product polish (P2)

- Shareable report links (signed, expiring)
- Compare two scans / two refs
- “Re-scan with brief” from report
- Operator status page (provisioner mode, LLM mode, docker/runsc)

---

## 8. Trust & safety model (v2 explicit)

| Channel | Allowed | Forbidden |
|---|---|---|
| `launch_sh` | `exec` argv tokens (shell_guard) in scan image | pipes, redirects, network tools, `python -c` |
| `probe_py` / `next_plans` | AST allowlisted stdlib subset → plan dicts | `os`, `sys`, `socket`, `open`, `eval`, `getattr` |
| `workdir_pick_py` | return candidate string | filesystem walks via `os` |
| `oracle_py` | emit finding dicts from observation summaries | network, file I/O, verdict override API |
| Packaged analyzer | final verdict rules | replaced by LLM alone |
| User brief | ≤2k chars in prompts | shell interpolation into host |

**Incident response:** if a guard bypass is found, disable LLM executable path via `CODEGEN_MODE=heuristic|off` env and ship patch.

---

## 9. API / schema additions (backward compatible)

```text
POST /api/scans
  + scan_brief?          # shipped
  + prefer_subdir?       # shipped
  + protocol?: auto|stdio|http  # v2

Report JSON
  + scan_brief
  + recipe.workdir_pick / codegen / probe_codegen  # shipped
  + llm_oracle[]
  + expectations[]       # v2: expect_* vs observed
  + artifacts: { launch_sh, probe_summary, oracle_summary }
  + costs?: { llm_calls, vm_seconds }
```

---

## 10. Success metrics

| Metric | Target |
|---|---|
| Vultr e2e success rate (staging golden repos) | ≥ 90% over 20 runs |
| Guard bypass in eval suite | 0 |
| Heuristic fallback rate on golden set | < 30% for launch+probe |
| Time-to-report local (time server) | < 3 min typical |
| Time-to-report Vultr | < 12 min typical (incl. provision) |
| UI: sample data on done report | 0 panels |
| Decoy demo remains flagged | always |

---

## 11. Suggested sequencing

```text
M11 Vultr path ──────────────┐
M12 Codegen eval ────────────┼─► M13 Analysis ─► M14 UI truth ─► M15 Expand ─► M16 Ops ─► M17 Polish
     (can parallel with M11) ┘
```

**Critical path:** M11 + M12 → M13 → M14.  
**Parallelizable:** M15 Node work during M13; M16 docs/limits anytime after M11.

---

## 12. Open decisions (resolve during M11–M12)

1. Default production LLM: OpenAI vs Vultr Inference (`live`) vs both with failover?
2. Snapshot strategy: bake full repo vs cloud-init `git pull` pinned SHA each boot?
3. Should oracle findings ever flip verdict to `flagged` alone, or only packaged decoy/egress?
4. HTTP MCP in v2 or explicitly defer to v2.1?
5. Persist generated artifacts in object storage for audit, or report JSON only?

---

## 13. Deliverables checklist

- [ ] `docs/V2_PLAN.md` (this file)
- [ ] Update `PROGRESS.md` with M11–M17 unchecked
- [ ] Update `docs/ARCHITECTURE.md` LLM section: executable codegen + containment
- [ ] Staging Vultr runbook smoke signed off
- [ ] Eval suite green in CI (guards) + nightly live optional
- [ ] Report UI without sample placeholders
- [ ] STATUS.md rewritten for “v2 in progress / shipped”

---

## 14. One-line summary

**v2 = same adaptive executable-codegen scanner, made production-real on Vultr, eval-gated, analysis-honest, and UI-truthful — without widening the trust boundary.**
