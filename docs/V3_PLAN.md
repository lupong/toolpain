# ToolPain v3 Plan

**Status:** implemented locally (2026-11-05). Live Vultr sign-off remains key-gated.  
**Baseline:** v2 implemented locally (M11–M17) — contained executable codegen + expect_* scoring + artifacts UI; live Vultr e2e still key-gated  
**Thesis (unchanged):** Adapt to arbitrary MCP servers by generating **contained executable scan code**.  
**v3 shift:** From “scanner that works on laptop/staging” → **multi-transport, production-proven, shareable, CI-integrable security product**.

Companion: [`docs/V2_PLAN.md`](V2_PLAN.md) · Progress: [`PROGRESS.md`](../PROGRESS.md)

---

## 1. Why v3

v1 proved the pipeline. v2 made codegen the product core and wired Vultr *in code*. What’s left is not another demo — it’s **breadth, proof, and product edges**:

| Gap after v2 | Why it blocks “real product” |
|---|---|
| Live Vultr never signed off | No production containment story without a real VM run |
| Stdio Python/Node only | Many MCP servers are HTTP/SSE or other languages |
| Fork drift still shallow | Security buyers care about “added vs upstream” |
| Reports not shareable / no CI hook | Analysts and PRs need durable artifacts |
| Sample HTML leftovers / sample recent rows | Trust gap in the UI |
| Codegen cost unbounded under live LLM | Unit economics break at scale |
| No multi-user / org boundary | BYO key + single SQLite won’t hold |

v3 closes the production gap, expands protocol/language surface, and adds the **delivery surfaces** (share, CI, compare) without widening the executable trust boundary.

---

## 2. Goals

1. **Production proof** — staging Vultr golden-path signed off; snapshot bake automated; reaper + destroy measured.
2. **Multi-transport MCP** — stdio remains default; HTTP + SSE MCP scanning behind a clear protocol selector.
3. **Supply-chain honesty** — real upstream fork compare; optional SBOM / dependency risk notes (data, not RCE).
4. **Delivery** — signed expiring report links; GitHub Check / webhook “scan this PR/ref”; compare two scans.
5. **Codegen at scale** — budgets, caching by commit SHA, nightly live eval, artifact audit store.
6. **Hardening** — gVisor optional path proven; secret-in-brief / log redaction audited; rate limits per account mode.

### Non-goals (v3)

- Full SaaS billing / Stripe
- Marketplace of community scan recipes as unrestricted code
- LLM-authored Dockerfiles or host shell
- Guaranteeing zero false positives on all MCP servers
- Mobile apps

---

## 3. Principles (carry forward + v3)

1. Generated code only in named channels (image entrypoint + AST allowlist).
2. User brief / PR comments = **prompt context**, never new exec channels.
3. Packaged analyzers own verdict; oracle/expectations may add findings, never clear `flagged` from decoy/egress.
4. Prefer **native MCP transports** over “wrap everything in stdio shims” when the server is HTTP/SSE-native.
5. Every scan has **provenance**: commit, codegen sources, costs, snapshot/image digests when available.
6. Fail closed: unsupported protocol/language → explicit error, not a half-built image.

---

## 4. Architecture deltas

```
v2:  UI → CP → local | vultr(stdio Docker) → report JSON

v3:  UI / GitHub App / CLI
        → CP (authz: anon | token | installation)
        → Provisioner (local | vultr)
        → Runner
             ├ stdio path (existing)
             └ http/sse path (new launcher + network policy for MCP port only → sinkhole otherwise)
        → Report store (+ optional object storage for artifacts)
        → Share links / Checks API / compare API
```

### New components

| Component | Role |
|---|---|
| `runner/transport/` | Stdio vs HTTP/SSE launch + client adapters |
| `control_plane/share.py` | Signed report tokens (HMAC, TTL) |
| `control_plane/github_app.py` (optional) | PR checks / ref scans |
| `evals/golden/` | Pinned repos + expected verdicts (CI + nightly) |
| `infra/snapshot/` | Packer/scripted Vultr snapshot bake |
| Artifact blob store | Optional S3/R2 for `launch_sh` / `probe_py` full text |

---

## 5. Workstreams & milestones

### Gate: M18 — Production Vultr sign-off (P0)

**Outcome:** Written sign-off that a real Vultr scan completed for decoy + `servers/src/time`.

- Bake snapshot (Docker + Python 3.12 + pinned ToolPain SHA)
- Staging CP with public `CONTROL_PLANE_URL` + TLS
- Run golden scans; capture instance lifecycle screenshots/logs
- Measure: provision→report latency, destroy reliability, reaper hits
- Acceptance: ≥2 consecutive green runs; BYO key still absent from DB/logs/SSE

*If keys unavailable, M18 stays blocked; M19+ can proceed on local provisioner.*

---

### M19 — HTTP / SSE MCP transport (P0)

**Outcome:** Scan a public HTTP or SSE MCP server end-to-end with same report shape.

- `protocol: auto|stdio|http|sse` on `ScanCreate`
- Discovery/probe via streamable HTTP / SSE client (official MCP SDK where possible)
- Sandbox network: allow only fixture + sinkhole + MCP listen port on internal net; no open egress
- Codegen: `launch_sh` may `exec` HTTP server bind on `127.0.0.1:<port>`; shell_guard allowlist extended carefully
- Demo: minimal HTTP MCP decoy (or documented third-party sample)
- Acceptance: one HTTP sample flagged or clean with harness provenance; stdio path unregressed

---

### M20 — Fork / upstream intelligence (P0)

**Outcome:** Fork drift uses real upstream tool lists when possible.

- Resolve upstream via GitHub `parent` API or `repo.upstream` hint on intake
- Fetch upstream tool names (README + optional static clone of upstream tree at shallow depth)
- Diff added/removed/renamed; attach file evidence when static hits exist
- UI: Drift tab never sample when report has `fork_drift`
- Acceptance: known fork demo shows `fetch_report` (or equivalent) as added vs upstream

---

### M21 — Share, compare, CI hook (P1)

**Outcome:** Analysts can share and automate without logging into the CP UI.

- `POST /api/scans/{id}/share` → `{url, expires_at}` (HMAC token; read-only report)
- `GET /api/scans/compare?a=&b=` → verdict/tools/findings delta
- CLI: `toolpain scan … --json` / `--share`
- GitHub: sparse integration — workflow `repository_dispatch` or Check Run via PAT/App (start with workflow-callable API)
- Acceptance: shared link works logged-out; compare highlights new findings; CI example in `infra/`

---

### M22 — Codegen scale & audit (P1)

**Outcome:** Live LLM scans are cheaper, cached, and auditable.

- Cache workdir/launch/probe artifacts by `(repo, commit, brief_hash, codegen_semver)`
- Hard caps: max LLM calls / max probe rounds / max tools profiled (batch profiles)
- Nightly live eval job (optional secret) against golden set; fail on guard bypass or verdict regression
- Persist full generated sources to report store or object storage (not only 4k truncations)
- Acceptance: second scan of same commit hits cache; nightly job documented; no guard bypass

---

### M23 — Language & runtime expansion (P1)

**Outcome:** Clear matrix of supported targets; at least one new language path.

- Support matrix in README: Python/Node stdio/HTTP; experimental Go/Rust via **bring-your-own base image** + allowlisted entrypoint
- BYO image mode: user supplies `image` + `server_cmd` (already partially present) with policy checks
- Node: pnpm/yarn lockfile paths hardened; long-build timeouts surfaced in UI
- Acceptance: matrix published; one BYO-image scan documented; unsupported still fails closed

---

### M24 — Isolation upgrade (P1)

**Outcome:** Optional gVisor path is real, not aspirational.

- Snapshot or host with `runsc`; `RUNTIME=runsc` e2e on staging
- Document fallback to runc+strace when runsc absent (current behavior)
- Optional: Landlock/seccomp profile review for runc mode
- Acceptance: one runsc scan report with `runtime=runsc` in meta

---

### M25 — Multi-tenant lite (P2)

**Outcome:** Separate “toolpain account” vs BYO without full SaaS.

- API tokens / scan quotas per token (SQLite-backed)
- Report visibility: public share vs private-by-default
- Redaction audit: brief, BYO, Authorization headers in all log paths
- Soft multi-tenant: no cross-token list_scans leakage
- Acceptance: two tokens cannot read each other’s private reports; quota 429 works

---

### M26 — Product polish & retirement of samples (P2)

**Outcome:** UI never shows sample data when a real report exists; onboarding is crisp.

- Purge sample recent-scan rows / sample findings when API returns data (or empty state)
- Onboarding: first-run checklist (Docker, LLM mode, provisioner)
- Report PDF/markdown export
- “Explain this finding” optional LLM narrative (JSON-only, no exec)
- Acceptance: smoke UI test asserts no SAMPLE_REPORT when `?id=` loaded with done scan

---

## 6. Executable codegen in v3 (extensions only)

Keep v2 surfaces. Add only if transport needs them:

| Artifact | v3 change |
|---|---|
| `launch_sh` | Allow `exec … --port N` / bind 127.0.0.1 for HTTP MCP (guarded) |
| `probe_py` | May emit `transport` hints (`stdio` vs `http`) in plan metadata |
| `healthcheck_py` | Optional: AST module returning `{ready: bool}` from initialize payload |
| `policy_py` | **No** — policy stays packaged |

Still forbidden: Dockerfile bodies, host network clients in generated Python, unrestricted analyzer replacement.

---

## 7. API sketch (additive)

```text
POST /api/scans
  + protocol?: auto|stdio|http|sse
  + upstream_url?: https://github.com/org/repo
  + image? / server_cmd?          # BYO (policy-checked)

POST /api/scans/{id}/share → { url, expires_at }
GET  /share/{token}             # read-only report HTML/JSON

GET  /api/scans/compare?a=&b=

POST /api/github/webhook        # optional App
GET  /api/health                # + snapshot_id present?, runsc?, cache_stats
```

Report additions:

```text
+ transport: { kind, endpoint? }
+ runtime: runc|runsc
+ upstream: { url, tools_count, method }
+ cache: { hit: bool, key? }
+ artifacts_uri?: s3://… | local path
```

---

## 8. Success metrics

| Metric | Target |
|---|---|
| Vultr golden e2e (M18) | 2/2 consecutive success |
| HTTP/SSE scan success on designated sample | ≥ 90% over 10 runs |
| Fork-drift precision on decoy-vs-upstream fixture | 100% detects planted add |
| Share link works without session | 100% |
| Same-commit rescan LLM call reduction | ≥ 50% via cache |
| Guard bypass in eval | 0 |
| Sample UI on loaded done scan | 0 |
| p50 local stdio time-server | < 3 min |
| p50 Vultr time-server | < 12 min |

---

## 9. Sequencing

```text
M18 Vultr sign-off ──┐
                     ├─► M19 HTTP/SSE ─► M23 languages
M20 upstream ────────┤
M22 codegen scale ───┼─► M21 share/CI/compare ─► M25 multi-tenant lite
M24 gVisor ──────────┘                              │
                                                    └─► M26 polish
```

**Critical path:** M18 (if keys) + M19 + M20 → M21.  
**Parallel:** M22 anytime; M24 when runsc host exists; M25 after share tokens exist.

---

## 10. Open decisions

1. GitHub App vs workflow-only CI (App = better UX, more OAuth surface)?
2. Default share TTL (24h vs 7d) and revoke API?
3. Object storage required in v3 or “full text in SQLite/report JSON” enough?
4. Does HTTP MCP listen inside the scan container on the internal Docker network only, or host-mapped port (prefer internal-only)?
5. Oracle allowed to raise severity to `flagged` for HTTP exfil patterns, or still packaged-only for flagged?
6. Single-region Vultr or multi-region scanner pool?

---

## 11. Risks

| Risk | Mitigation |
|---|---|
| HTTP MCP needs egress-like connects to itself | Keep MCP on internal network; sinkhole everything else |
| Shell_guard too tight for HTTP launch | Explicit allowlist expansions with tests; no `curl\|sh` |
| Cache serves stale probe for changed brief | Include `brief_hash` + `codegen_semver` in key |
| Share links leak private repos’ findings | Default private; share is explicit opt-in; TTL + revoke |
| Vultr cost blowups | Quotas (M25), reaper, destroy-on-terminal (v2) |

---

## 12. Deliverables checklist

- [ ] `docs/V3_PLAN.md` (this file)
- [ ] `PROGRESS.md` v3 milestones M18–M26
- [ ] Support matrix in README
- [ ] `evals/golden/` harness
- [ ] Staging Vultr sign-off note in `STATUS.md`
- [ ] Share + compare API + minimal CI example
- [ ] HTTP/SSE demo or documented sample
- [ ] ARCHITECTURE transport section

---

## 13. One-line summary

**v3 = production-proven, multi-transport ToolPain with shareable/CI delivery and scaled codegen — still contained, still adaptive, still no free host RCE.**
