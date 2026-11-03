/* ToolPain front end — vanilla JS, no build step.
   Shared by index.html and scan.html. Each block no-ops when its elements are absent.
   The build agent replaces the sample data with GET /api/scans/{id}/report and SSE events. */
(function () {
  'use strict';

  var $ = function (s, r) { return (r || document).querySelector(s); };
  var $$ = function (s, r) { return Array.prototype.slice.call((r || document).querySelectorAll(s)); };
  var store = {
    get: function (k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) { /* storage unavailable */ } }
  };

  /* ---------------- Sample report (Part 1.7 shape) ---------------- */
  var SAMPLE_REPORT = {
    scan_id: 's_8f2c',
    repo: { url: 'https://github.com/andrew/playwright-mcp', commit: 'a1b2c3d', upstream: 'microsoft/playwright-mcp',
      fork_drift: [{ change: 'added_tool', tool: 'fetch_report', file: 'src/tools/report.ts' }] },
    verdict: 'flagged',
    stats: { tools: 27, undocumented: 1, critical_tier: 3, toxic_combos: 4, egress_attempted: 2, decoy_reads: 1 },
    tools: [
      { name: 'browser_navigate', privilege: 'high', verdict: 'confirmed', sources: ['D', 'S', 'R'], egress: ['fixture.local'], decoy_reads: 0 },
      { name: 'browser_evaluate', privilege: 'critical', verdict: 'confirmed', sources: ['D', 'S', 'R'], egress: [], decoy_reads: 0 },
      { name: 'browser_file_upload', privilege: 'high', verdict: 'exceeds_claim', sources: ['D', 'S', 'R'], egress: [], decoy_reads: 0 },
      { name: 'fetch_report', privilege: 'critical', verdict: 'flagged', sources: ['S', 'R'], egress: ['collector.sinkhole.local'], decoy_reads: 1 },
      { name: 'browser_click', privilege: 'low', verdict: 'confirmed', sources: ['D', 'S', 'R'], egress: [], decoy_reads: 0 },
      { name: 'browser_pdf_save', privilege: 'medium', verdict: 'confirmed', sources: ['D', 'S', 'F'], egress: [], decoy_reads: 0 }
    ],
    toxic_combos: [
      { tools: ['browser_file_upload', 'browser_navigate'], risk: 'exfiltration', severity: 'high' },
      { tools: ['browser_evaluate', 'browser_navigate'], risk: 'token_theft', severity: 'high' },
      { tools: ['fetch_report', 'browser_evaluate'], risk: 'credential_harvesting', severity: 'high' },
      { tools: ['browser_pdf_save', 'browser_file_upload'], risk: 'covert_channel', severity: 'medium' }
    ],
    findings: [
      { id: 'F1', severity: 'critical', type: 'decoy_read_and_egress', tool: 'fetch_report',
        title: 'Undocumented tool read a planted decoy and attempted an undeclared connection',
        evidence: 'openat("/workspace/canaries/decoy_secret.txt") -> connect collector.sinkhole.local:443 (contained by sinkhole)' },
      { id: 'F2', severity: 'high', type: 'fork_added_tool', tool: 'fetch_report', title: 'Tool not present upstream' },
      { id: 'F3', severity: 'medium', type: 'hidden_behind_flag', tool: 'browser_pdf_save', title: 'Tool only appears with a capability flag' }
    ],
    egress: { declared: [], attempted: [
      { host: 'collector.sinkhole.local', tool: 'fetch_report', blocked: true },
      { host: 'cdn.thirdparty.local', tool: 'browser_navigate', blocked: true }] },
    least_privilege_config: { allow_tools: ['browser_navigate', 'browser_snapshot', 'browser_click', 'browser_type'], allow_hosts: ['your-app.example'] }
  };

  /* ---------------- Theme ---------------- */
  var root = document.documentElement;
  var saved = store.get('tp-theme');
  if (saved === 'light' || saved === 'dark') root.setAttribute('data-theme', saved);
  function syncThemeButtons() {
    var light = root.getAttribute('data-theme') === 'light';
    $$('[data-theme-toggle]').forEach(function (b) {
      b.textContent = light ? 'Dark' : 'Light';
      b.setAttribute('aria-label', light ? 'Switch to dark theme' : 'Switch to light theme');
    });
  }
  $$('[data-theme-toggle]').forEach(function (b) {
    b.addEventListener('click', function () {
      var next = root.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
      root.setAttribute('data-theme', next);
      store.set('tp-theme', next);
      syncThemeButtons();
      document.dispatchEvent(new CustomEvent('tp:theme'));
    });
  });
  syncThemeButtons();

  /* ---------------- Copy helpers ---------------- */
  function copyText(text, btn) {
    var done = function () {
      if (!btn) return;
      btn.classList.add('is-copied');
      var label = btn.querySelector('span');
      var prev = label ? label.textContent : null;
      if (label) label.textContent = 'Copied';
      setTimeout(function () { btn.classList.remove('is-copied'); if (label) label.textContent = prev; }, 1600);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, done);
    else done();
  }
  $$('[data-copy-target]').forEach(function (b) {
    b.addEventListener('click', function () { var t = $(b.getAttribute('data-copy-target')); if (t) copyText(t.textContent, b); });
  });
  $$('.tp-code__copy').forEach(function (b) {
    b.addEventListener('click', function () { var pre = b.parentNode.querySelector('pre'); if (pre) copyText(pre.textContent, b); });
  });

  /* ================= index.html: intake ================= */
  var intake = $('#intake');
  if (intake) {
    var repo = $('#repo'), wrap = $('#repo-wrap'), chip = $('#repo-chip'), err = $('#repo-error');
    var toggle = $('#byo-toggle'), panel = $('#byo-panel'), ack = $('#byo-ack'), btn = $('#scan-btn'), mode = $('#account-mode');
    var RE = /^https:\/\/github\.com\/([A-Za-z0-9](?:[A-Za-z0-9-]{0,38}))\/([A-Za-z0-9._-]+?)(?:\.git)?\/?$/;

    var validate = function (showError) {
      var m = RE.exec(repo.value.trim());
      wrap.classList.toggle('tp-input-wrap--valid', !!m);
      wrap.classList.toggle('tp-input-wrap--error', !m && showError);
      repo.setAttribute('aria-invalid', String(!m && showError));
      chip.hidden = !m;
      if (m) chip.querySelector('span').textContent = m[1] + '/' + m[2];
      err.hidden = !!m || !showError;
      return m;
    };
    var syncByo = function () {
      var on = toggle.getAttribute('aria-pressed') === 'true';
      panel.hidden = !on;
      mode.textContent = on ? 'your account' : 'toolpain account';
      var blocked = on && !ack.checked;
      btn.disabled = blocked;
      btn.firstChild.textContent = blocked ? 'Confirm the key warning to scan ' : 'Scan it ';
    };
    repo.addEventListener('input', function () { validate(false); });
    repo.addEventListener('blur', function () { validate(repo.value.trim() !== ''); });
    toggle.addEventListener('click', function () {
      toggle.setAttribute('aria-pressed', String(toggle.getAttribute('aria-pressed') !== 'true'));
      syncByo();
    });
    ack.addEventListener('change', syncByo);
    intake.addEventListener('submit', function (e) {
      e.preventDefault();
      var m = validate(true);
      if (!m) { repo.focus(); return; }
      if (btn.disabled) return;
      // Build agent: POST /api/scans {repo_url, ref, byo_key?} then redirect to scan.html?id=<scan_id>.
      location.href = 'scan.html?state=in-progress&repo=' + encodeURIComponent(m[1] + '/' + m[2]);
    });
    validate(false);
    syncByo();
  }

  /* ================= scan.html ================= */
  if (!document.body.hasAttribute('data-state')) return;

  var cy = null;
  var params = new URLSearchParams(location.search);
  var STATES = ['in-progress', 'done', 'error'];

  function setState(s) {
    if (STATES.indexOf(s) < 0) s = 'in-progress';
    document.body.setAttribute('data-state', s);
    $$('[data-view]').forEach(function (v) { v.hidden = v.getAttribute('data-view') !== s; });
    $$('[data-when]').forEach(function (v) { v.hidden = v.getAttribute('data-when') !== s; });
    $$('#state-switch [data-set-state]').forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-set-state') === s)); });
    var t = $('#toast-decoy');
    if (t && s !== 'in-progress') t.hidden = true;
    var p = new URLSearchParams(location.search); p.set('state', s);
    history.replaceState(null, '', location.pathname + '?' + p.toString());
    if (s === 'done' && cy) { cy.resize(); cy.fit(undefined, 24); }
  }
  $$('[data-set-state]').forEach(function (b) {
    b.addEventListener('click', function () { setState(b.getAttribute('data-set-state')); window.scrollTo(0, 0); });
  });
  setState(params.get('state') || 'in-progress');

  /* ---- Elapsed timer + time-limit meter ---- */
  var secs = 161, LIMIT = 900, paused = false;
  var pad = function (n) { return String(n).padStart(2, '0'); };
  var fmt = function (s) { return pad(Math.floor(s / 60)) + ':' + pad(s % 60); };
  setInterval(function () {
    if (document.body.getAttribute('data-state') !== 'in-progress') return;
    secs += 1;
    var e = $('#elapsed'); if (e) e.textContent = fmt(secs);
    var l = $('#time-label'); if (l) l.textContent = fmt(secs) + ' / ' + fmt(LIMIT);
    var f = $('#time-fill'); if (f) {
      var pct = Math.min(100, Math.round(secs / LIMIT * 100));
      f.style.setProperty('--pct', pct + '%');
      f.parentNode.setAttribute('aria-valuenow', String(pct));
    }
  }, 1000);

  /* ---- Decoy toast ---- */
  var toast = $('#toast-decoy');
  if (toast) {
    setTimeout(function () { if (document.body.getAttribute('data-state') === 'in-progress') toast.hidden = false; }, 1200);
  }
  $$('[data-dismiss]').forEach(function (b) {
    b.addEventListener('click', function () { var el = document.getElementById(b.getAttribute('data-dismiss')); if (el) el.hidden = true; });
  });
  // Public hook for the SSE handler: TP.bumpEgress(n)
  window.TP = window.TP || {};
  window.TP.bumpEgress = function (n) {
    var c = $('#egress-count'); if (!c) return;
    c.textContent = String(n);
    c.classList.remove('is-bumped'); void c.offsetWidth; c.classList.add('is-bumped');
  };
  window.TP.setState = setState;
  window.TP.report = SAMPLE_REPORT;

  /* ---- Log: level filter, pause, autoscroll ---- */
  var log = $('#log');
  if (log) {
    var level = 'all';
    var applyFilter = function () {
      $$('.tp-log__line', log).forEach(function (ln) {
        ln.hidden = level !== 'all' && !ln.classList.contains('tp-log__line--' + level);
      });
    };
    $$('#log-filter [data-level]').forEach(function (b) {
      b.addEventListener('click', function () {
        level = b.getAttribute('data-level');
        $$('#log-filter [data-level]').forEach(function (x) { x.setAttribute('aria-pressed', String(x === b)); });
        applyFilter();
      });
    });
    var pauseBtn = $('#log-pause');
    pauseBtn.addEventListener('click', function () {
      paused = !paused;
      pauseBtn.setAttribute('aria-pressed', String(paused));
      pauseBtn.querySelector('span').textContent = paused ? 'Resume' : 'Pause';
      pauseBtn.querySelector('use').setAttribute('href', paused ? '#i-play' : '#i-pause');
      if (!paused) log.scrollTop = log.scrollHeight;
    });
    log.scrollTop = log.scrollHeight;
    // Public hook: TP.appendLog({ts, level:'info'|'warn'|'alert', stage, msg})
    window.TP.appendLog = function (e) {
      var row = document.createElement('div');
      row.className = 'tp-log__line tp-log__line--' + e.level;
      [['ts', e.ts], ['lvl', e.level.toUpperCase()], ['stage', e.stage], ['msg', e.msg]].forEach(function (p) {
        var s = document.createElement('span'); s.className = 'tp-log__' + p[0]; s.textContent = p[1]; row.appendChild(s);
      });
      row.hidden = level !== 'all' && level !== e.level;
      log.appendChild(row);
      if (!paused) log.scrollTop = log.scrollHeight;
    };
  }

  /* ---- Tabs (click + arrow keys) ---- */
  var tabs = $$('#tabs [role="tab"]');
  function selectTab(tab, focus) {
    tabs.forEach(function (t) {
      var on = t === tab;
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
      var p = document.getElementById(t.getAttribute('aria-controls'));
      if (p) p.hidden = !on;
    });
    if (focus) tab.focus();
    if (tab.id === 'tab-graph') initGraph();
  }
  tabs.forEach(function (t, i) {
    t.addEventListener('click', function () { selectTab(t); });
    t.addEventListener('keydown', function (e) {
      var j = null;
      if (e.key === 'ArrowRight') j = (i + 1) % tabs.length;
      if (e.key === 'ArrowLeft') j = (i - 1 + tabs.length) % tabs.length;
      if (e.key === 'Home') j = 0;
      if (e.key === 'End') j = tabs.length - 1;
      if (j !== null) { e.preventDefault(); selectTab(tabs[j], true); }
    });
  });

  /* ---- Tools table: expand, sort, filter ---- */
  var table = $('#tools-table');
  if (table) {
    $$('.tp-rowtoggle', table).forEach(function (b) {
      b.addEventListener('click', function () {
        var open = b.getAttribute('aria-expanded') !== 'true';
        b.setAttribute('aria-expanded', String(open));
        var d = document.getElementById(b.getAttribute('aria-controls'));
        if (d) d.hidden = !open;
      });
    });
    var sortKey = 'priv', dir = -1;
    var sortRows = function () {
      var bodies = $$('tbody', table);
      bodies.sort(function (a, b) {
        if (sortKey === 'name') return a.dataset.name < b.dataset.name ? -dir : dir;
        return (Number(a.dataset[sortKey]) - Number(b.dataset[sortKey])) * dir || (a.dataset.name < b.dataset.name ? -1 : 1);
      });
      bodies.forEach(function (b) { table.appendChild(b); });
      $$('thead th', table).forEach(function (th) {
        var btn = th.querySelector('.tp-sort');
        if (btn) th.setAttribute('aria-sort', btn.dataset.sort === sortKey ? (dir > 0 ? 'ascending' : 'descending') : 'none');
      });
    };
    $$('.tp-sort', table).forEach(function (b) {
      b.addEventListener('click', function () {
        dir = sortKey === b.dataset.sort ? -dir : (b.dataset.sort === 'name' ? 1 : -1);
        sortKey = b.dataset.sort;
        sortRows();
      });
    });
    var q = $('#tool-q'), filter = 'all';
    var applyTools = function () {
      var term = (q.value || '').trim().toLowerCase(), shown = 0;
      $$('tbody', table).forEach(function (b) {
        var ok = (!term || b.dataset.name.indexOf(term) >= 0) && (filter === 'all' || (' ' + b.dataset.tags + ' ').indexOf(' ' + filter + ' ') >= 0);
        b.hidden = !ok; if (ok) shown += 1;
      });
      $('#tool-count').textContent = String(shown);
    };
    q.addEventListener('input', applyTools);
    $$('#tool-filters [data-filter]').forEach(function (b) {
      b.addEventListener('click', function () {
        filter = b.dataset.filter;
        $$('#tool-filters [data-filter]').forEach(function (x) { x.setAttribute('aria-pressed', String(x === b)); });
        applyTools();
      });
    });
  }

  /* ---- Least-privilege config: JSON / YAML ---- */
  var cfg = $('#cfg-text');
  if (cfg) {
    var lp = SAMPLE_REPORT.least_privilege_config;
    var asYaml = function () {
      return 'allow_tools:\n' + lp.allow_tools.map(function (t) { return '  - ' + t; }).join('\n') +
        '\nallow_hosts:\n' + lp.allow_hosts.map(function (h) { return '  - ' + h; }).join('\n');
    };
    $$('#cfg-format [data-fmt]').forEach(function (b) {
      b.addEventListener('click', function () {
        $$('#cfg-format [data-fmt]').forEach(function (x) { x.setAttribute('aria-pressed', String(x === b)); });
        cfg.textContent = b.dataset.fmt === 'yaml' ? asYaml() : JSON.stringify(lp, null, 2);
      });
    });
  }

  /* ---- Download JSON ---- */
  var dl = $('#download-json');
  if (dl) {
    dl.addEventListener('click', function () {
      var blob = new Blob([JSON.stringify(SAMPLE_REPORT, null, 2)], { type: 'application/json' });
      dl.href = URL.createObjectURL(blob);
    });
  }

  /* ---------------- Access graph (cytoscape) ---------------- */
  var NODE_INFO = {
    server: ['MCP server', [['andrew/playwright-mcp @ a1b2c3d'], ['Fork of microsoft/playwright-mcp'], ['27 tools, 1 not in upstream', 'high']]],
    browser_navigate: ['Tool · high tier', [['Observed: network via fixture.local', 'low'], ['Loaded cdn.thirdparty.local, blocked', 'crit']]],
    browser_evaluate: ['Tool · critical tier', [['Observed: code exec in page', 'low'], ['Claimed access to browser data']]],
    browser_file_upload: ['Tool · high tier', [['Exceeds claim: reads outside upload dir', 'high']]],
    fetch_report: ['Tool · critical tier', [['Missing from README (found in source + runtime)', 'high'], ['Added in fork: src/tools/report.ts', 'high'], ['Read decoy /workspace/canaries/decoy_secret.txt', 'crit'], ['Tried collector.sinkhole.local:443, blocked', 'crit']]],
    browser_pdf_save: ['Tool · medium tier', [['Only appears with --caps=pdf', 'high'], ['Writes to tmpfs']]],
    network: ['Capability', [['Used by browser_navigate, fetch_report']]],
    code_exec: ['Capability', [['Used by browser_evaluate']]],
    browser_data: ['Capability', [['Claimed by browser_evaluate, browser_file_upload']]],
    local_files: ['Capability', [['Used by browser_file_upload, fetch_report'], ['Claimed by browser_pdf_save']]],
    fixture: ['Host · in-sandbox fixture', [['ToolPain test site, allowed', 'low']]],
    cdn: ['Host · undeclared', [['Attempted by browser_navigate', 'crit'], ['Resolved to sinkhole, blocked', 'crit']]],
    collector: ['Host · undeclared', [['Attempted by fetch_report', 'crit'], ['TLS SNI logged, connection closed', 'crit']]],
    decoy: ['Decoy · planted by ToolPain', [['Unique per scan, fake data'], ['Read by fetch_report', 'crit']]]
  };
  var COLOR_VAR = { crit: '--crit', high: '--high', low: '--low' };

  function showNode(id, label) {
    var info = NODE_INFO[id]; if (!info) return;
    $('#node-kind').textContent = info[0];
    $('#node-title').textContent = label;
    var ul = $('#node-lines'); ul.textContent = '';
    info[1].forEach(function (l) {
      var li = document.createElement('li');
      li.textContent = l[0];
      if (l[1]) li.style.setProperty('--c', 'var(' + COLOR_VAR[l[1]] + ')');
      ul.appendChild(li);
    });
  }

  function cssVars() {
    var cs = getComputedStyle(root), v = function (n) { return cs.getPropertyValue(n).trim(); };
    return { bg: v('--bg'), surface: v('--surface'), raised: v('--raised'), border: v('--border'), text: v('--text'), muted: v('--muted'),
      accent: v('--accent'), info: v('--info'), crit: v('--crit'), high: v('--high'), mono: 'JetBrains Mono, monospace' };
  }

  function graphStyle() {
    var c = cssVars();
    return [
      { selector: 'node', style: { label: 'data(label)', 'font-family': c.mono, 'font-size': 11, color: c.text, 'text-valign': 'center', 'text-halign': 'center',
        shape: 'round-rectangle', width: 'label', height: 30, padding: '10px', 'background-color': c.surface, 'border-width': 1, 'border-color': c.border } },
      { selector: 'node.server', style: { 'font-size': 13, 'font-weight': 700, 'background-color': c.raised, 'border-color': c.text, height: 40 } },
      { selector: 'node.flagged', style: { 'border-color': c.crit, 'border-width': 2, 'font-weight': 600 } },
      { selector: 'node.cap', style: { shape: 'round-rectangle', 'corner-radius': 15, 'border-color': c.info, 'background-color': c.bg } },
      { selector: 'node.host', style: { 'border-style': 'dashed', 'border-color': c.muted, 'background-color': c.bg } },
      { selector: 'node.host.blocked', style: { 'border-color': c.crit, color: c.crit, 'font-weight': 600 } },
      { selector: 'node.decoy', style: { 'border-color': c.crit, color: c.crit, 'background-color': c.bg, 'font-weight': 600 } },
      { selector: 'node:selected', style: { 'overlay-color': c.accent, 'overlay-opacity': 0.18, 'overlay-padding': 6, 'border-color': c.accent, 'border-width': 3 } },
      { selector: 'edge', style: { width: 1.5, 'line-color': c.muted, 'curve-style': 'bezier', 'target-arrow-shape': 'none' } },
      { selector: 'edge.member', style: { 'line-color': c.border } },
      { selector: 'edge.claimed', style: { 'line-style': 'dashed', 'line-dash-pattern': [5, 4] } },
      { selector: 'edge.exceeds', style: { 'line-color': c.high, width: 2 } },
      { selector: 'edge.toxic', style: { 'line-color': c.crit, width: 4.5 } },
      { selector: 'edge.blocked', style: { 'line-color': c.crit, width: 2, label: '×', color: c.crit, 'font-size': 18, 'font-weight': 700,
        'text-background-color': c.bg, 'text-background-opacity': 1, 'text-background-padding': '2px' } },
      { selector: 'edge.toxic.blocked', style: { width: 4.5 } }
    ];
  }

  function initGraph() {
    var el = $('#graph');
    if (!el || typeof window.cytoscape !== 'function') return;
    if (cy) { cy.resize(); return; }
    var n = function (id, label, cls, x, y) { return { data: { id: id, label: label }, classes: cls, position: { x: x, y: y } }; };
    var e = function (s, t, cls) { return { data: { id: s + '>' + t, source: s, target: t }, classes: cls }; };
    cy = window.cytoscape({
      container: el,
      boxSelectionEnabled: false,
      wheelSensitivity: 0.2,
      layout: { name: 'preset', padding: 24 },
      style: graphStyle(),
      elements: [
        n('server', 'playwright-mcp (fork)', 'server', 100, 262),
        n('browser_navigate', 'browser_navigate', 'tool', 385, 78),
        n('browser_evaluate', 'browser_evaluate', 'tool', 385, 168),
        n('browser_file_upload', 'browser_file_upload', 'tool', 385, 258),
        n('fetch_report', 'fetch_report', 'tool flagged', 385, 348),
        n('browser_pdf_save', 'browser_pdf_save', 'tool', 385, 438),
        n('network', 'network', 'cap', 620, 87),
        n('code_exec', 'code exec', 'cap', 620, 187),
        n('browser_data', 'browser data', 'cap', 620, 267),
        n('local_files', 'local files', 'cap', 620, 357),
        n('fixture', 'fixture.local', 'host', 840, 40),
        n('cdn', 'cdn.thirdparty.local', 'host blocked', 840, 127),
        n('collector', 'collector.sinkhole.local', 'host blocked', 840, 307),
        n('decoy', 'decoy_secret.txt', 'decoy', 840, 417),
        e('server', 'browser_navigate', 'member'), e('server', 'browser_evaluate', 'member'), e('server', 'browser_file_upload', 'member'),
        e('server', 'fetch_report', 'member'), e('server', 'browser_pdf_save', 'member'),
        e('browser_navigate', 'network', 'observed'), e('browser_evaluate', 'code_exec', 'observed'),
        e('browser_evaluate', 'browser_data', 'claimed'), e('browser_file_upload', 'browser_data', 'claimed'),
        e('browser_file_upload', 'local_files', 'exceeds'), e('browser_pdf_save', 'local_files', 'claimed'),
        e('fetch_report', 'local_files', 'toxic'), e('fetch_report', 'network', 'toxic'),
        e('network', 'fixture', 'observed'), e('network', 'cdn', 'blocked'),
        e('network', 'collector', 'toxic blocked'), e('local_files', 'decoy', 'toxic')
      ]
    });
    cy.on('tap', 'node', function (evt) { showNode(evt.target.id(), evt.target.data('label')); });
    cy.$('#fetch_report').select();
    showNode('fetch_report', 'fetch_report');
    cy.fit(undefined, 24);
    $$('[data-zoom]').forEach(function (b) {
      b.addEventListener('click', function () {
        var z = b.dataset.zoom, center = { x: el.clientWidth / 2, y: el.clientHeight / 2 };
        if (z === 'fit') cy.fit(undefined, 24);
        else cy.zoom({ level: cy.zoom() * (z === 'in' ? 1.25 : 0.8), renderedPosition: center });
      });
    });
    document.addEventListener('tp:theme', function () { cy.style(graphStyle()); });
    window.addEventListener('resize', function () { cy.resize(); });
  }
})();
