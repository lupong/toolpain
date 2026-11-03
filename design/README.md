# ToolPain design (`design/`)

Static HTML/CSS/vanilla JS from the Claude Design brief (PROMPT.md Part 1). No build step. Port into `web/` and keep the class names.

| File | What it is |
|---|---|
| `index.html` | Landing + intake (repo URL validation, ref, Advanced → BYO Vultr key with warning + "I understand" gate, demo chips, how it works, recent scans) |
| `scan.html` | One page, three states via `body[data-state]`: `in-progress`, `done` (tabbed report), `error` (edge states). Preview with `?state=in-progress\|done\|error` or the header switcher |
| `style.css` | All tokens and components |
| `app.js` | Interactions, sample report, cytoscape graph, public hooks for SSE |

Open the files directly in a browser. The graph needs the cytoscape CDN (`cdnjs … cytoscape/3.28.1`).

## Wiring notes for the build agent

- **State:** call `TP.setState('in-progress'|'done'|'error')`. Elements with `[data-view="…"]` and `[data-when="…"]` show only in their state.
- **SSE hooks:** `TP.appendLog({ts, level:'info'|'warn'|'alert', stage, msg})`, `TP.bumpEgress(n)`. Show the decoy alert by un-hiding `#toast-decoy`.
- **Stepper:** set each `.tp-stepper__item--{pending|running|done|failed|skipped}`. The running icon spins automatically.
- **Meters:** set `--pct` on `.tp-meter__fill`, and `aria-valuenow` on its track.
- **Report:** `TP.report` holds the Part 1.7 sample. Replace it with `GET /api/scans/{id}/report` and render the rows using the markup in `scan.html` as the template. In the tools table, each tool is its own `<tbody data-name data-priv data-verdict data-decoy data-tags>` so sorting keeps the row and its detail row together. Rank values: priv critical 4 → low 1; verdict flagged 4, exceeds 3, not_observed 2, confirmed 1.
- **Intake submit:** currently redirects to `scan.html?state=in-progress`. Replace with `POST /api/scans`, then `scan.html?id=…`. The BYO key must never be written to the URL, storage or logs.
- **Theme:** `html[data-theme="light"|"dark"]`. The toggle saves to `localStorage` (wrapped in try/catch). The graph restyles on the `tp:theme` event.
- **Icons:** each page has an inline SVG sprite. Use `<svg class="tp-icon"><use href="#i-flag"/></svg>`. Severity icons are `#s-critical|high|medium|low|info`.

## Tokens (`:root`, overridden by `[data-theme="light"]`)

| Token | Dark | Light |
|---|---|---|
| `--bg` / `--surface` / `--raised` / `--border` | `#0B0D10` / `#12161B` / `#1A2027` / `#2A323C` | `#F5F6F8` / `#FFFFFF` / `#EEF1F4` / `#D3D9E0` |
| `--text` / `--muted` | `#E6EAF0` / `#8A96A3` | `#0F1419` / `#55606B` |
| `--accent` (fill, dark text on it) / `--accent-ink` (as text) | `#FF5A36` / `#FF7A5C` | `#FF5A36` / `#B8350F` |
| `--info`, `--focus` | `#4EA8FF` | `#1F6FC2` |
| `--crit` `--high` `--med` `--low` `--sev-info` | `#FF3B5C` `#FF8A3D` `#F5C542` `#5AC8A0` `#8A96A3` | `#C8213F` `#B4520A` `#8A6500` `#1C7A56` `#55606B` |
| Verdicts | confirmed = low, exceeds_claim = high, not_observed = sev-info, flagged = crit | same mapping |

Fonts: Inter (UI) and JetBrains Mono (code/logs) from Google Fonts. Radius 8px (6px badges, 999px pills/toggles). Spacing `--s1..--s7` = 4/8/12/16/24/32/48.

Light-theme severity colors are darkened so they pass 4.5:1 as text on white. White text on `--accent` fails contrast, so primary buttons always use `--on-accent` (`#0B0D10`).

## Components and class names

| Component | Classes |
|---|---|
| Buttons | `.tp-btn` + `--primary` `--secondary` `--ghost` `--danger`, sizes `--lg` `--sm` `--icon`; `:disabled` styled |
| Inputs | `.tp-field`, `.tp-label`, `.tp-help`, `.tp-error-text`, `.tp-input` + `--valid` `--error`, `.tp-input-wrap` + `--valid` `--error` (icon + chip) |
| Chips | `.tp-chip` + `--repo` `--valid` `--tool`, `.tp-demo-chip` (`--c` sets the dot color) |
| Toggle | `button.tp-toggle[aria-pressed]` |
| Disclosure | `details.tp-disclosure` > `summary` + `.tp-disclosure__body` |
| Warning panel | `.tp-warning`, `.tp-warning__title`, `.tp-check` |
| Segmented / pills | `.tp-segmented` (children use `aria-pressed` / `aria-current` / `aria-selected`), `.tp-pill[aria-pressed]` |
| Severity badge | `.tp-badge.tp-badge--critical\|high\|medium\|low\|info` (always icon + label) |
| Verdict badge | `.tp-badge.tp-verdict--confirmed\|exceeds_claim\|not_observed\|flagged`; overall verdict: `--clean` `--over` `--suspicious` `--flagged`; live: `--probing` `--queued` |
| Source badges | `.tp-sources` > `.tp-source` + `--on` `--missing` |
| Stepper | `.tp-stepper` > `.tp-stepper__item--{state}` > `__bar` `__label` `__meta` |
| Containment | `.tp-containment`, `.tp-netstatus`, `.tp-dl`, `.tp-meter` (`__head` `__track` `__fill`, `--time`), `.tp-counter` + `--alert`, `.tp-live`, `.tp-sinkhits` |
| Tool list (live) | `.tp-toollist` > `__item` `__name` `__status`, `__more` |
| Log console | `.tp-log__body` > `.tp-log__line--info\|warn\|alert` > `__ts` `__lvl` `__stage` `__msg` |
| Toast | `.tp-toast-region` > `.tp-toast--critical` > `__icon` `__body` `__title` `__close` |
| Tabs | `.tp-tabs[role=tablist]` > `.tp-tab[role=tab][aria-selected]` + `__count`; `.tp-tabpanel` |
| Summary | `.tp-verdict-hero`, `.tp-sevcounts` > `.tp-sevcount`, `.tp-stats` > `.tp-stat` + `--high` `--critical` `--alert`, `.tp-recap` |
| Tables | `.tp-table-wrap` (scrolls on mobile), `.tp-table` + `--comfy` `--expandable` `--min-560\|680\|820`, `.tp-sort`, `.tp-rowtoggle[aria-expanded]`, `.tp-row--flagged`, `.tp-row-detail` > `__grid` `__k`, `.tp-trace` |
| Code block | `.tp-code` > `pre` + `.tp-code__copy` (`.is-copied`) |
| Finding card | `.tp-findings-group--{sev}` > `__title`; `.tp-finding` > `__meta` `__id` `__title` `__explain` `__rec` |
| Toxic combo | `.tp-combo` > `__head` `__risk` `__pair` `__why` |
| Graph | `.tp-graph` (cytoscape container), `.tp-graph-toolbar`, `.tp-legend` (`__line--claimed\|toxic`, `__x`), `.tp-sidepanel` |
| Drift | `.tp-drift-counts`, `pre.tp-diff` > `span.add` / `span.hunk` |
| Banners / states | `.tp-banner--partial`, `.tp-states` > `.tp-state` (+ `--empty`), `__title` `__text` `__icon` |
| Layout | `.tp-container` (+ `--narrow`), `.tp-split` > `__main` `__side` (+ `--side-first`), `.tp-grid-auto`, `.tp-stack`, `.tp-row`, `.tp-eyebrow` |

## Cytoscape styling

Node classes: `server`, `tool`, `flagged`, `cap`, `host`, `blocked`, `decoy`.
Edge classes: `member` (server→tool), `observed` (solid), `claimed` (dashed), `exceeds` (orange), `toxic` (4.5px crit), `blocked` (crit with a "×" label).

`graphStyle()` in `app.js` reads colors from the CSS tokens, so both themes work. The demo uses a `preset` layout with fixed positions. For real reports, switch to columns by node type (for example a `breadthfirst` layout rooted at the server).

## Accessibility

- Severity and verdict always pair an icon with a text label.
- Focus rings use `:focus-visible` with `--focus`.
- Tabs follow the ARIA tab pattern (arrow keys, Home and End).
- Tools are rendered as a real table with `aria-sort` on sortable headers.
- The log is `role="log"` and the toast is `role="alert"`.
- Animations stop under `prefers-reduced-motion`.
- Touch targets are at least 44px.
- Tested at 375px and 1440px with no horizontal page scroll.

## Sample-data notes

- Part 1.7 says there are 4 toxic combos but lists only 2. Two were added to match: `fetch_report + browser_evaluate` (credential harvesting) and `browser_pdf_save + browser_file_upload` (covert channel).
- Log timestamps, recent-scan times and the fork diff snippet are placeholders.
