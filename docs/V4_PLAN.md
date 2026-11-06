# ToolPain v4 Plan

**Status:** implemented locally (2026-11-05). Live Vultr remains v6. `web/app.js` was not split; see DECISIONS.  
**Baseline:** v3 implemented locally (M18–M26) plus the UI1–UI7 design pass. Three demo stories render from report JSON. Live Vultr has not been signed off.  
**Thesis (unchanged):** Adapt to arbitrary MCP servers by generating **contained executable scan code**.  
**v4 shift:** From “the features exist” → **the local product is strict**. One report shape, sticky terminal states, honest verdicts, and failure screens that come from the scan.

Companion: [`docs/V3_PLAN.md`](V3_PLAN.md) · Progress: [`PROGRESS.md`](../PROGRESS.md)

**Version slots**

| Version | What it is |
|---|---|
| v4 (this plan) | Enhancements, code tightening, edge cases. All of it runs on `fake` and `local`. |
| v5 | Pre-live rehearsal. Runbook, golden-suite freeze, snapshot bake dry-run. No customer traffic and no sign-off. |
| v6 | Live. Staging Vultr golden path, measured destroy/reaper, BYO key absence proof. The unmet half of old M18. gVisor only if that host has `runsc`. |

---

## 1. Why v4

v3 added transports, share, compare, cache, and tokens. The design pass made the three demos look different. The seams underneath are still loose:

| Seam | Where it shows |
|---|---|
| A report that fails `Report` validation is stored anyway and the scan is marked `done` | `internal_report` catches `ValidationError` and saves the raw body |
| Cancel is not final | The same handler then sets `status="done"`, so a late runner report overwrites `cancelled` |
| HTTP/SSE “scan” is a different product | `_scan_http_endpoint` lists tools, special-cases the name `fetch_report`, and returns `suspicious` without the stdio assembler |
| Verdict copy lies at the edges | A flagged report with zero critical findings still says “N critical findings” because the headline uses `crit \|\| findings.length` |
| `suspicious` has a headline and no next step | `recommendation()` falls through to the finding text |
| Error screens are still sample copy | `scan.html` timeout banner says “15:00”; private-repo copy names `acme/internal-mcp`; `classify()` guesses from substrings (`build`, `npm`, `vultr`) |
| Share and compare are APIs only | `POST /share` returns `/share/{token}`, and that route returns raw JSON. `GET /api/compare` does not check report owners |
| Authz lookups are capped | The LLM proxy treats a token as valid only if it appears in the last 200 scans. Admin token defaults to `toolpain-dev-admin` |
| `mcp_url` is `localhost` or any `https://` | A scan can be aimed at an address the runner should not fetch |
| `web/` and `design/` can drift | They are copied by hand. Nothing fails CI when they diverge |
| Cost is a leftover counter | `report["costs"]` stores an LLM-call estimate and probe rounds. Nothing is shown before the scan, and nothing is priced |
| A finished scan is not an IT record | Share returns JSON. There is no previewable, downloadable certificate |

v4 closes those seams. It does not add a new execution channel.

---

## 2. Goals

1. **One report contract.** Stored reports validate as `Report`. Invalid payloads do not become `done`.
2. **Terminal states stick.** `cancelled`, `failed`, and `timeout` are not overwritten by a late report or a second cancel.
3. **Verdicts match the matrix.** `clean`, `over_privileged`, `suspicious`, and `flagged` each have a headline, a lede, and a “what to do next” line that match the counts in the JSON.
4. **Failures are typed.** The runner emits an error code. The UI picks a panel from that code and fills it with this scan’s repo, log excerpt, and duration.
5. **HTTP scans are honest.** A list-only HTTP/SSE pass is labeled `coverage: list_only` and does not pretend it probed, or it goes through `build_report`. It does not special-case a tool name.
6. **Two existing APIs become product.** A share link opens the report UI. Two scans can be compared in the UI. Both respect private-report ownership.
7. **Edges have tests.** Empty tools, all `not_observed`, cancel-vs-late-report, expired share, cross-owner compare, unknown ref, oversized tool output.
8. **Cost is shown before and after.** A rate-card estimate appears once the repo URL is valid. The finished report prices the infra and codegen that actually ran, and shows the delta.
9. **A done scan produces an audit record.** The same record can be previewed and downloaded as a PDF. It certifies that this scan ran and records the result. It does not certify that the server is safe.

### Non-goals (v4)

- Live Vultr sign-off, snapshot promotion, reaper measurement on a real account (v6)
- gVisor / `runsc` proof (v6, and only on a host that has it)
- Billing, Stripe, orgs, SSO
- A community recipe marketplace, or any new executable codegen surface
- LLM-authored Dockerfiles or host shell
- Mobile apps
- Guaranteeing zero false positives
- Scanning arbitrary non-GitHub tarballs
- Reconciling a Vultr invoice. v4 prices meters against a published rate card. Attaching the provider bill is v6
- A legal attestation, a third-party auditor’s signature, or a PKI seal. The record is ToolPain’s own scan certificate plus a hash of the report

---

## 3. Principles (carry forward)

1. Generated code only in named channels (image entrypoint + AST allowlist).
2. User brief stays prompt context.
3. Packaged analyzers own the verdict. Oracle and expectations may add findings. They may not clear `flagged`.
4. Fail closed. An unsupported input, a bad report, or a guard rejection ends in an explicit state, not a half report marked `done`.
5. Sample markup is not a fallback once a scan id is present.
6. Reads of scan data stay inside the owner check. Share is opt-in and expiring.

---

## 4. Architecture deltas

No new service. The runner grows a structured error. The control plane stops trusting raw report bodies. The UI grows a read-only share mode and a compare view on the same renderer.

```
v3:  UI → CP → runner → report JSON (validated, or stored raw)
      share token → JSON
      compare → JSON, no owner check

v4:  UI → CP → runner
        ├ events include {code} on failure
        └ report must validate, and only from a non-terminal scan
      share token → scan.html read-only (same renderer)
      compare → same-owner or public reports only → compare view
```

### Invariants to lock in tests

| Invariant | Rule |
|---|---|
| Report shape | `Report.model_validate` succeeds for every stored report, including the three demos and the HTTP path |
| Terminal stickiness | After `cancelled` / `failed` / `timeout`, `internal_report` returns 409 and does not change status or verdict |
| Verdict copy | Headline count equals the severity it names. `suspicious` has its own next-step sentence |
| Privacy | Compare and share of a token-owned report require that token. A missing or other token is 403 |
| Design parity | `design/{index,scan}.html`, `style.css`, and `app.js` match `web/` |
| Cost identity | Estimate and actual use the same rate-card version. The certificate prints that version, both amounts, and the delta |
| Certificate identity | The PDF and the HTML preview are rendered from one certificate model. The model’s report hash matches the stored report |

---

## 5. Workstreams and milestones

### M27 — Report contract (P0)

**Outcome:** A stored report is a `Report`. A scan becomes `done` only from a valid one.

- Delete the `except ValidationError: payload = body` path in `internal_report`.
- On validation failure: keep the scan `running` or mark it `failed` with `error: report_invalid` and the field errors in the event log. Do not persist the raw body as the report.
- Return 409 when the scan is already `cancelled`, `failed`, `timeout`, or `done`.
- Second cancel of a terminal scan returns the current status and does not emit another destroy.
- `Report` gains optional `coverage: full | list_only`, `partial: bool`, and `error: {code, detail}` so partial and list-only results are explicit.
- Acceptance: a pytest posts a body missing `verdict` and asserts the scan is not `done` and `get_report` 404s. A pytest cancels, then posts a valid report, and asserts status stays `cancelled`.

### M28 — Typed failures (P0)

**Outcome:** The error page describes this scan. `classify()` stops guessing from substrings.

- Runner failures emit `data.code` from a closed set: `invalid_repo`, `repo_unavailable`, `ref_missing`, `build_failed`, `launch_failed`, `no_mcp_server`, `probe_timeout`, `report_invalid`, `provision_failed`, `byo_rejected`, `cancelled`.
- Control plane stores `error_code` and `error_detail` on the scan row.
- UI selects the panel from `error_code`. Panels get the repo chip, the detail string, and the build-log excerpt from the event. Remove the hardcoded `acme/internal-mcp` and the hardcoded `15:00`.
- `timeout` with a saved partial report shows the partial banner and an “Open partial report” button that reveals that report. `timeout` without a report stays on the error panel.
- Unknown codes use the generic failed panel with the detail text.
- Acceptance: each code has a unit test that maps to one panel id. A fixture timeout with a partial report renders the banner and the report’s verdict, not the sample banner.

### M29 — Verdict matrix (P0)

**Outcome:** Every overall verdict is produced by `overall_verdict` and rendered with matching copy.

Lock this table. Tests construct findings and tools; they do not depend on a live model.

| Case | Verdict | Headline | Next step |
|---|---|---|---|
| No anomaly kinds, no exceeds-claim | `clean` | No pain found. | Safe to add. The least-privilege config is still the tightest setup. |
| `exceeds_claim` or `description_mismatch` only | `over_privileged` | Over-privileged: N tool(s) can do more than they claim. | Use the least-privilege config to turn off tools you don't need. |
| Undocumented, hidden-behind-flag, fork-added, or prompt-injection, and no decoy/egress | `suspicious` | Suspicious: worth a closer look. | Read the findings before you add this server. The least-privilege config drops the unexpected tools. |
| `decoy_read`, `decoy_read_and_egress`, or `undeclared_egress` | `flagged` | Ouch: N critical finding(s). | Block \<tool\>, then use the least-privilege config. |
| Zero tools | `suspicious` | Suspicious: worth a closer look. | Nothing spoke MCP. Check the ref, the subdirectory, and the launch log. |
| Tools present, all `not_observed` | `suspicious` | Suspicious: worth a closer look. | The server started, and no tool actually ran. Treat this as incomplete. |

- Fix the flagged headline so N is the critical count. When that count is 0, name the top severity instead of calling every finding critical.
- `lede` for `clean` uses `stats.tools`. `lede` for the others uses the top finding sentence.
- HTTP path must not invent `suspicious` by seeing the string `fetch_report`. It uses this matrix or M30’s list-only label.
- Acceptance: one parametrized test per row. A DOM-level or string-level test asserts a zero-critical flagged fixture does not contain the word “critical” in the headline.

### M30 — HTTP/SSE honesty and `mcp_url` (P0)

**Outcome:** A list-only HTTP scan cannot be mistaken for a probed one, and `mcp_url` cannot point at a link-local or metadata host.

- Either run discovered HTTP tools through `build_report` with empty probes (`not_observed` → `suspicious` per M29), or set `coverage: list_only` and `partial: true` and skip overall-verdict theater. Pick one in M30 and delete the `fetch_report` name check.
- UI: a `list_only` report shows a banner, “Listed, not probed.” Hide decoy and egress stats or render them as an em dash.
- `mcp_url` allowlist: `http://127.0.0.1`, `http://localhost`, and `https` hosts that resolve outside link-local, loopback-except-localhost, and cloud metadata names. Reject userinfo, non-default ports on metadata-like hosts, and raw IPs in private ranges. Document the rule next to the validator.
- Acceptance: the HTTP demo report validates as `Report`. A test rejects `https://169.254.169.254/` and `http://10.0.0.1/`. Stdio demos are unchanged.

### M31 — Authz, quotas, and lookup tightening (P1)

**Outcome:** Private data stays private. Dev defaults do not survive a non-dev boot.

- `GET /api/compare` requires both reports to be public, or both owned by the calling `X-Api-Token`. Otherwise 403. Do not reveal which side failed.
- `GET /share/{token}` stays token-capability based. Expired and tampered tokens stay 404.
- LLM proxy token check looks up the token directly. Remove the “last 200 scans” scan.
- `POST /api/tokens` refuses to boot the default admin secret when `TOOLPAIN_ENV` is `prod` or `staging`. Local and test keep the default.
- Quota `0` and exhausted quota both return 429 with `quota`. A negative quota in the body is 422.
- `list_scans` for a token returns only that owner’s rows. Anonymous list stays the public demo rows it returns today.
- Acceptance: two tokens, cross compare → 403. Token lookup of scan 201 still authorizes the LLM proxy. Prod settings without `TOOLPAIN_ADMIN_TOKEN` fail `get_settings`.

### M32 — Runner edges (P1)

**Outcome:** A bad repo or a stuck tool ends in a typed failure, and the sandbox is still destroyed.

- Unknown ref → `ref_missing` after fetch, before build.
- Repo with no detectable MCP server and no `server_cmd` → `no_mcp_server` after launch trials, with the tried argv list in the event.
- Per-tool probe timeout is separate from the scan timeout. One hung tool becomes `not_observed` with a finding, and the scan continues. The scan timeout still ends in `probe_timeout` or `timeout` with whatever partial report is safe to store.
- Cap tool-result bytes and evidence strings. Truncate with a marker. Do not drop the rest of the scan.
- Guard rejection of `launch_sh` / `probe_py` / `oracle_py` still falls back to the packaged heuristic and records `source: heuristic` plus the guard error. A fallback failure uses `launch_failed` or `build_failed`, not a bare `Exception` string.
- Replace bare `except Exception` on the scan path with the typed codes. Unexpected exceptions become `failed` with `error_code: internal` and a redacted message.
- Acceptance: tests for missing ref, no-server tree, one hanging tool among three, oversized tool output, and a guard-rejected `launch_sh` that still produces a heuristic report. Destroy runs on each of those paths.

### M33 — UI edges and the two enhancements (P1)

**Outcome:** Share and compare use the report renderer. Empty and partial states do not borrow sample markup.

- **Share.** `/share/{token}` serves `scan.html` in read-only mode (`?share=`). The page loads the report through the token, hides Cancel, Replay, and Share, and shows expiry. Invalid token uses the existing failed panel with “This link is invalid or expired.”
- **Compare.** A control on the report (“Compare with…”) calls `/api/compare` and renders added/removed tools and findings. Empty delta says the scans match. 403 says the other report is private.
- **Empty states.** Zero tools, zero findings, zero graph nodes, and hidden drift tab stay empty containers with one sentence each. No `SAMPLE_REPORT` when `?id=` or `?share=` is set.
- **Phone graph.** If no tool is `flagged`, fit the server neighborhood instead of calling `cy.$('#undefined')`.
- **Parity.** A test copies or diffs `web/` against `design/` for `index.html`, `scan.html`, `style.css`, `app.js`.
- **Tightening.** If `web/app.js` is still over 1000 lines after the edge work, split it into ordered plain scripts (`web/js/report.js`, `web/js/live.js`, `web/js/boot.js`) with no build step. Behavior and class names stay. Do this last in the milestone so the split is a move, not a rewrite.
- Acceptance: Playwright, skipped when Chromium is absent, opens a share link and a compare with a delta. A unit test asserts `design/app.js` equals `web/app.js` until the split, then asserts the design copies match the new script set.

### M34 — Regression net (P0, runs alongside M27–M33)

**Outcome:** `make lint test` covers the new invariants without a network, a key, or Chromium.

- Keep the three-demo probe test (verdict, one alert only on decoy-trap, per-tool probe events, 30–45s of beats at the default delay).
- Add the M27–M32 cases above to pytest.
- Playwright file stays skippable. Its skip reason says Chromium or the Playwright package is absent.
- Update `STATUS.md` so v3 is “implemented locally” and v4 points here. Do not mark v6 done.
- Acceptance: `make lint test` green. No test sleeps the demo’s 2.5s beats; tests pass `delay_sec`.

### M35 — Cost estimate, actual, and the delta (P1)

**Outcome:** The user sees a price before the scan starts, and the report shows what the scan actually cost against that same rate card.

Today `report["costs"]` is `{llm_codegen_calls_est, probe_rounds}`. v4 replaces that blob with a priced breakdown. Amounts are USD, computed locally. They are not a cloud invoice.

**Rate card.** One versioned file, `control_plane/rate_card.json`, loaded by the control plane and copied into every estimate and every actual. Lines:

| Line | What it prices |
|---|---|
| `codegen_call_usd` | One model call for workdir pick, launch script, probe module, or oracle |
| `research_call_usd` | One research profile call. The estimate multiplies by the assumed tool count |
| `local_usd_per_min` | Scanner container time on the local provisioner |
| `vultr_usd_per_min` | The configured scanner plan. Shown when the user has chosen Vultr. Not billed to a Vultr account in v4 |
| `fetch_usd_per_mb` | Bytes cloned, so a large repo costs more than a small one |

Changing a price means bumping `version` on the card. Old scans keep the version they were priced with.

**Estimate, before run.** `POST /api/estimate` with `{repo_url, ref, provisioner}`. It does not create a scan and does not clone.

- Repo size and primary language come from the public GitHub repo metadata (`size` is kilobytes). Demos and tests use a pinned fixture so they do not hit the network.
- Size band sets the assumptions, and the response lists them: small under 1 MB assumes 5 tools and 3 scanner minutes; medium under 20 MB assumes 15 tools and 8 minutes; large assumes 40 tools and 15 minutes.
- Codegen assumes four calls (workdir, launch, probe, oracle) plus one research call per assumed tool. A cache hit is not known yet, so the estimate does not assume one.
- Infra is `scanner minutes × the provisioner rate` plus `repo MB × fetch rate`.
- Response: `{rate_card, inputs, assumptions, lines: [{code, quantity, usd}], total_usd}`.

The intake form shows the total and the three groups (infra, codegen, fetch) once the URL validates, and again if the provisioner changes. Copy: “Estimate $X.XX before this scan. The report will show the actual.” A failed lookup shows “Estimate unavailable” and still allows the scan.

The estimate is saved on the scan row at create time, including the assumptions. The scan does not re-price the estimate after fetch.

**Actual, after run.** The runner and control plane record meters, then price them with the same card:

- `duration_sec` from the scan’s start and destroy events
- `repo_bytes` from fetch
- `llm_calls` counted at the LLM proxy for this scan id, split into codegen and research. The source-flag guess goes away
- `probe_rounds` as today
- `provisioner` and `runtime`

`report.costs` becomes:

```text
rate_card: <version>
estimate: { total_usd, lines, assumptions }
actual:   { total_usd, lines, meters }
delta_usd
delta_pct
```

The report summary shows “Estimate $0.42 · Actual $0.51 · +$0.09” and a short breakdown. A scan that finishes under the estimate shows a negative delta. Fake demos use the fixture inputs and the real card, so the number is stable in tests.

A cancelled or failed scan keeps the estimate and prices whatever meters ran. It does not invent a full actual.

- Acceptance: a pure-function test prices one small local repo and one large Vultr-shaped repo from fixtures. A scan stores the estimate it showed. The finished demo report’s `delta_usd` equals `actual − estimate` within half a cent. The intake page shows the estimate for a demo chip without a network call.

### M36 — Scan certificate (P1)

**Outcome:** A finished scan has a previewable, downloadable PDF that an IT record can store. The PDF and the on-screen preview are the same certificate.

The certificate attests that ToolPain ran this scan and records the result. The closing sentence is fixed: “This record certifies that the scan above was performed. It is not a warranty that the server is safe to run.”

**Model.** `control_plane/certificate.py` builds one document from the stored scan and report. Fields:

- Title: ToolPain Scan Record
- Record id (scan id) and generated-at time
- Repository, ref, full commit
- Started, finished, duration
- Account mode, provisioner, runtime, coverage (`full` or `list_only`)
- Verdict, severity counts, tool count
- Each tool: name, privilege, verdict
- Each finding: id, severity, title, tool
- Cost: rate-card version, estimate, actual, delta
- SHA-256 of the canonical report JSON
- The fixed statement above

No seal, no signature image, and no wording that implies a third-party auditor or a certificate authority. Integrity is the report hash. A later verifier recomputes it from the stored report.

**Preview and download.**

- `GET /api/scans/{id}/certificate` returns the HTML preview. Print stylesheet, one or two pages, readable at 375px as a stacked record.
- `GET /api/scans/{id}/certificate.pdf` returns `application/pdf` with `Content-Disposition: attachment` and a filename `toolpain-<scan_id>.pdf`.
- The report page gets “Preview record” and “Download PDF”. Preview opens the HTML in the page. Download hits the PDF route.
- A share link can open and download the same record. The share token is the capability. Private reports stay behind the owner token.
- Status must be `done`. `cancelled` and `failed` return 409. A partial timeout report may be certified only when a report was stored, and the document says “Partial scan” in the title.

**PDF library.** Add `fpdf2`. It is pure Python, so the PDF builds in tests without Chromium or system libraries. The HTML preview is a second renderer of the same model, not a browser print of the app shell. Tests compare the model’s fields to both outputs: the HTML contains the scan id, verdict, and report hash; the PDF starts with `%PDF` and extracts back to text containing those same three strings.

- Acceptance: the decoy demo’s certificate names verdict `flagged`, the commit, the cost delta, and the report hash. Changing the stored report changes the hash. A cancelled scan has no certificate.

---

## 6. Executable codegen in v4

No new artifacts. No new AST allowlist entries. No new shell allowlist entries.

Guard fallback and truncation (M32) are the only codegen changes, and they narrow what a bad model output can do.

---

## 7. API sketch

```text
POST /internal/scans/{id}/report
  201 only when the body validates and status is queued|running
  409 when status is cancelled|failed|timeout|done
  422 when the body is not a Report; scan becomes failed / report_invalid

Scan row
  + error_code?: <closed set>
  + error_detail?: str

Report
  + coverage?: full | list_only
  + partial?: bool

GET /share/{token}
  HTML shell when Accept prefers text/html
  JSON when Accept is application/json (CLI keeps working)

GET /api/compare?a=&b=
  403 when either report is private to someone else
  body: { tools_added, tools_removed, findings_added, findings_removed, verdict: {a, b} }

POST /api/estimate
  body: { repo_url, ref, provisioner }
  does not create a scan
  body: { rate_card, inputs, assumptions, lines, total_usd }

Report.costs
  rate_card, estimate, actual, delta_usd, delta_pct

GET /api/scans/{id}/certificate       # HTML preview
GET /api/scans/{id}/certificate.pdf   # attachment
  409 unless status is done
```

Event `data.code` uses the M28 set. Existing `stage` / `level` / `msg` stay.

---

## 8. Success metrics

| Metric | Target |
|---|---|
| Stored report failing `Report` validation | 0 |
| Terminal scan overwritten by a late report | 0 |
| Demo verdicts (filesystem clean, playwright over-privileged, decoy flagged) | unchanged |
| Error panels whose visible copy is still the sample sentence | 0 when a scan id is present |
| Cross-owner compare | 403 |
| Guard bypass in the existing eval suite | 0 |
| `make lint test` | green, offline |
| Estimate shown for a valid public repo before create | yes, or “unavailable” if metadata cannot be read |
| `delta_usd` vs `actual − estimate` | within $0.005 |
| Certificate for a `done` scan | HTML and PDF contain scan id, verdict, and report SHA-256 |
| Certificate for a cancelled scan | 409 |

---

## 9. Sequencing

```text
M27 report contract ─► M28 typed failures ─► M29 verdict matrix
        │                                            │
        └─► M31 authz (parallel)                     ├─► M30 HTTP honesty
                                                     └─► M33 UI + share/compare
M32 runner edges (parallel after M28 codes exist)
M35 cost estimate → actual delta (after M27, so the priced blob validates)
M36 certificate (after M35, so the record can print the delta)
M34 tests land with each milestone, not after
```

**Critical path:** M27 → M28 → M29 → M33.  
**Parallel:** M31 anytime after M27. M32 after the error codes exist. M30 after the verdict table is locked. M35 after M27. M36 after M35.

**Then, not in this plan:** v5 freezes the golden set and writes the runbook v6 will execute. v6 is the live Vultr sign-off.

---

## 10. Open decisions

Defaults are set so the milestones can be implemented without another planning pass. Change them in `DECISIONS.md` if a milestone finds a better fit.

1. **Invalid report.** Default: 422, persist nothing, mark the scan `failed` / `report_invalid`. The runner already finished; leaving it `running` would strand the UI.
2. **HTTP list-only.** Default: `coverage: list_only` and `partial: true`, verdict from the M29 table with every tool `not_observed` (so `suspicious`), banner in the UI. Do not fake probe results.
3. **Share HTML.** Default: the same `scan.html` with `?share=`. One renderer.
4. **Compare privacy.** Default: both public, or the same owner token. Mixed ownership is 403.
5. **`app.js` split.** Default: do it at the end of M33 only if the file is over 1000 lines. No behavior change in that commit.
6. **Prices.** Default: a checked-in rate card, not a live price feed. Vultr minutes use the card’s plan rate. v6 may attach the provider invoice beside it. The certificate keeps the card version either way.
7. **Incomplete scans.** Default: price the meters that ran, and issue a certificate only for `done` (including a stored partial). Cancelled and failed scans get no PDF.

---

## 11. Risks

| Risk | Mitigation |
|---|---|
| Stricter validation rejects today’s HTTP and demo reports | M27 starts by making the three demos and the HTTP fixture validate, then flips the handler |
| Sticky `done` blocks a legitimate report retry | Retry is a new scan. A second `internal_report` on `done` stays 409 |
| Share HTML exposes Cancel or the API token | Read-only mode hides those controls; the page fetches only `/share/{token}` |
| Splitting `app.js` breaks the scan page | Split is a move after tests, with the parity check in the same change |
| `mcp_url` tightening blocks a real localhost demo | Keep `127.0.0.1` and `localhost` on `http` |
| GitHub metadata is rate-limited or wrong for a monorepo | The estimate shows its assumptions. The actual replaces them. The scan still starts when the estimate is unavailable |
| A reader treats the PDF as a safety approval | The statement says the scan was performed and is not a warranty. No seal |
| The rate card drifts from a future Vultr bill | The certificate cites the card version. Invoice reconciliation stays on v6 |

---

## 12. Deliverables checklist

- [x] `docs/V4_PLAN.md` (this file)
- [x] `PROGRESS.md` v4 milestones M27–M36 unchecked
- [x] `STATUS.md` points at v4 and keeps live work on v6
- [x] Report validation is fail-closed
- [x] Typed error codes drive the error panels
- [x] Verdict matrix tests
- [x] Share HTML and compare view
- [x] `web/` and `design/` parity test
- [x] Rate card, pre-scan estimate, actual meters, and delta
- [x] HTML certificate preview and PDF download
- [x] `make lint test` green

---

## 13. One-line summary

**v4 = the same scanner, made strict: one report shape, sticky failures, honest verdicts, a priced estimate against the actual, and a PDF scan record an auditor can file — still local, still contained, with live held for v6.**
