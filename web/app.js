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

  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) node.className = cls;
    if (text != null) node.textContent = text;
    return node;
  }
  function svgIcon(href, lg) {
    var svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    svg.setAttribute('class', lg ? 'tp-icon' : 'tp-icon tp-icon--sm');
    svg.setAttribute('aria-hidden', 'true');
    var use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', href);
    svg.appendChild(use);
    return svg;
  }
  function badge(cls, icon, label, lg) {
    var node = el('span', 'tp-badge ' + cls);
    if (icon) node.appendChild(svgIcon(icon, lg));
    node.appendChild(document.createTextNode(label));
    return node;
  }
  function clear(node) {
    if (!node) return;
    while (node.firstChild) node.removeChild(node.firstChild);
  }
  function verdictPresentation(verdict, status) {
    var v = verdict || status || 'queued';
    var map = {
      flagged: ['Flagged', '#i-flag', 'tp-verdict--flagged'],
      clean: ['Clean', '#i-check', 'tp-verdict--clean'],
      over_privileged: ['Over-privileged', '#i-up', 'tp-verdict--over'],
      suspicious: ['Suspicious', '#i-warn', 'tp-verdict--suspicious'],
      running: ['Running', '#i-spin', 'tp-verdict--probing'],
      queued: ['Queued', '#i-dash', 'tp-verdict--queued'],
      failed: ['Failed', '#i-x', 'tp-verdict--flagged'],
      cancelled: ['Cancelled', '#i-x', 'tp-verdict--queued'],
      timeout: ['Timed out', '#i-clock', 'tp-verdict--suspicious'],
      done: ['Done', '#i-check', 'tp-verdict--confirmed']
    };
    return map[v] || [String(v).replace(/_/g, ' '), '#i-alert', 'tp-verdict--queued'];
  }
  function relTime(iso) {
    var t = Date.parse(iso || '');
    if (!t) return '—';
    var s = Math.max(0, (Date.now() - t) / 1000);
    if (s < 45) return 'just now';
    if (s < 3600) return Math.round(s / 60) + ' min ago';
    if (s < 86400) return Math.round(s / 3600) + ' hr ago';
    return Math.round(s / 86400) + ' d ago';
  }

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
      var use = b.querySelector('use');
      b.setAttribute('aria-label', light ? 'Switch to dark theme' : 'Switch to light theme');
      if (use) use.setAttribute('href', light ? '#i-moon' : '#i-sun');
      else b.textContent = light ? 'Dark' : 'Light';
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
  document.addEventListener('click', function (e) {
    var copyBtn = e.target.closest('[data-copy-target], .tp-code__copy');
    if (!copyBtn) return;
    var targetSel = copyBtn.getAttribute('data-copy-target');
    var node = targetSel ? $(targetSel) : copyBtn.parentNode.querySelector('pre');
    if (node) copyText(node.textContent, copyBtn);
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
      var refEl = $('#ref');
      var briefEl = $('#scan-brief');
      var payload = {
        repo_url: repo.value.trim().replace(/\/$/, ''),
        ref: (refEl && refEl.value.trim()) || 'main',
        protocol: ($('#protocol') && $('#protocol').value) || 'auto'
      };
      if (briefEl && briefEl.value.trim()) payload.scan_brief = briefEl.value.trim().slice(0, 2000);
      var subEl = $('#prefer-subdir');
      if (subEl && subEl.value.trim()) payload.prefer_subdir = subEl.value.trim().replace(/^\/+|\/+$/g, '');
      var mcpEl = $('#mcp-url');
      if (mcpEl && mcpEl.value.trim()) payload.mcp_url = mcpEl.value.trim();
      var byoOn = toggle.getAttribute('aria-pressed') === 'true';
      var vkey = $('#vkey');
      if (byoOn && vkey && vkey.value) payload.byo_vultr_key = vkey.value;
      btn.disabled = true;
      fetch('/api/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      }).then(function (r) {
        return r.json().then(function (j) {
          if (!r.ok) {
            var detail = j && j.detail;
            var msg = detail && detail[0] && detail[0].msg ? detail[0].msg : (detail ? JSON.stringify(detail) : 'scan failed');
            var ex = new Error(msg);
            ex.status = r.status;
            throw ex;
          }
          return j;
        });
      }).then(function (j) {
        location.href = 'scan.html?id=' + encodeURIComponent(j.id) + '&state=in-progress';
      }).catch(function (ex) {
        if (ex.status === 422) {
          location.href = 'scan.html?state=error&reason=invalid&url=' + encodeURIComponent(repo.value.trim());
          return;
        }
        btn.disabled = false;
        if (err) {
          err.hidden = false;
          err.textContent = String(ex.message || ex);
        }
      });
    });

    // Demo chips → POST with demo key, then live scan view
    $$('.tp-demo-chip').forEach(function (a) {
      a.addEventListener('click', function (ev) {
        ev.preventDefault();
        var href = a.getAttribute('href') || '';
        var demo = (new URLSearchParams((href.split('?')[1] || ''))).get('demo');
        if (!demo) return;
        var demoRepos = {
          'server-filesystem': 'https://github.com/modelcontextprotocol/servers',
          'playwright-mcp': 'https://github.com/microsoft/playwright-mcp',
          'decoy-trap-server': 'https://github.com/lupong/toolpain'
        };
        fetch('/api/scans', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            repo_url: demoRepos[demo] || 'https://github.com/lupong/toolpain',
            ref: 'main',
            demo: demo
          })
        }).then(function (r) { return r.json(); }).then(function (j) {
          location.href = 'scan.html?id=' + encodeURIComponent(j.id) + '&state=in-progress&demo=' + encodeURIComponent(demo);
        });
      });
    });

    // Recent scans from API
    var recentTable = $('#recent-table');
    if (recentTable) {
      fetch('/api/scans').then(function (r) { return r.json(); }).then(function (rows) {
        if (!rows || !rows.length) return;
        var tb = recentTable.querySelector('tbody');
        if (!tb) return;
        tb.textContent = '';
        rows.slice(0, 8).forEach(function (s) {
          var tr = document.createElement('tr');
          var repoName = (s.repo_url || '').replace('https://github.com/', '');
          var view = s.status === 'done' ? 'done' : (s.status === 'failed' || s.status === 'timeout' || s.status === 'cancelled' ? 'error' : 'in-progress');
          var href = 'scan.html?id=' + encodeURIComponent(s.id) + '&state=' + view;
          var pres = verdictPresentation(s.verdict, s.status);
          var tdRepo = document.createElement('td');
          var link = document.createElement('a');
          link.className = 'mono';
          link.href = href;
          link.style.color = 'var(--text)';
          link.style.textDecoration = 'none';
          link.textContent = repoName;
          tdRepo.appendChild(link);
          var tdVerdict = document.createElement('td');
          tdVerdict.appendChild(badge(pres[2], pres[1], pres[0]));
          var tdCount = document.createElement('td');
          tdCount.className = 'mono';
          tdCount.textContent = String(s.findings_count || 0);
          var tdWhen = document.createElement('td');
          tdWhen.className = 'muted';
          tdWhen.style.textAlign = 'right';
          tdWhen.textContent = relTime(s.updated_at || s.created_at);
          tr.appendChild(tdRepo);
          tr.appendChild(tdVerdict);
          tr.appendChild(tdCount);
          tr.appendChild(tdWhen);
          tb.appendChild(tr);
        });
      }).catch(function () { /* keep sample rows */ });
    }

    validate(false);
    syncByo();
    var ops = $('#ops-status');
    if (ops) {
      fetch('/api/health').then(function (r) { return r.json(); }).then(function (h) {
        ops.textContent = (h.provisioner || '?') + ' · ' + (h.llm_mode || '?') + ' · cg=' + (h.codegen_mode || 'llm');
      }).catch(function () { ops.textContent = 'offline'; });
    }
  }

  /* ================= scan.html ================= */
  if (!document.body.hasAttribute('data-state')) return;

  var cy = null;
  var graphEpoch = 0;
  var graphDrawn = -1;
  var params = new URLSearchParams(location.search);
  var STATES = ['in-progress', 'done', 'error'];
  var scanId = params.get('id');
  var es = null;
  var replayTimer = null;
  var secs = scanId ? 0 : 161;
  var LIMIT = 900;
  var paused = false;
  var liveTools = [];
  var egressN = 0;
  var STAGE_ORDER = ['intake','provision','fetch','build','isolate','discover','research','probe','analyze','report','destroy'];
  var SEV_ICON = { critical: '#s-critical', high: '#s-high', medium: '#s-medium', low: '#s-low', info: '#s-info' };
  var HERO = {
    flagged: ['FLAGGED', '#i-flag', 'tp-badge--lg tp-verdict--flagged'],
    clean: ['CLEAN', '#i-check', 'tp-badge--lg tp-verdict--clean'],
    over_privileged: ['OVER-PRIVILEGED', '#i-up', 'tp-badge--lg tp-verdict--over'],
    suspicious: ['SUSPICIOUS', '#i-warn', 'tp-badge--lg tp-verdict--suspicious']
  };
  var PRIV = { critical: ['Critical', '#s-critical', 'tp-badge--critical', 4], high: ['High', '#s-high', 'tp-badge--high', 3], medium: ['Medium', '#s-medium', 'tp-badge--medium', 2], low: ['Low', '#s-low', 'tp-badge--low', 1], info: ['Info', '#s-info', 'tp-badge--info', 0] };
  var TVERDICT = { flagged: ['flagged', '#i-flag', 'tp-verdict--flagged', 4], exceeds_claim: ['exceeds claim', '#i-up', 'tp-verdict--exceeds_claim', 3], confirmed: ['confirmed', '#i-check', 'tp-verdict--confirmed', 1], not_observed: ['not observed', '#i-dash', 'tp-verdict--not_observed', 0] };

  function pad(n) { return String(n).padStart(2, '0'); }
  function fmt(s) { return pad(Math.floor(s / 60)) + ':' + pad(s % 60); }
  function reportNow() {
    if (window.TP && window.TP.report) return window.TP.report;
    if (scanId) return { findings: [], tools: [], verdict: 'clean', stats: {}, repo: {} };
    return SAMPLE_REPORT;
  }

  function setState(s) {
    if (STATES.indexOf(s) < 0) s = 'in-progress';
    document.body.setAttribute('data-state', s);
    $$('[data-view]').forEach(function (v) { v.hidden = v.getAttribute('data-view') !== s; });
    $$('[data-when]').forEach(function (v) { v.hidden = v.getAttribute('data-when') !== s; });
    $$('#state-switch [data-set-state]').forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-set-state') === s)); });
    var t = $('#toast-decoy');
    if (t && s !== 'in-progress') t.hidden = true;
    var p = new URLSearchParams(location.search);
    p.set('state', s);
    history.replaceState(null, '', location.pathname + '?' + p.toString());
    if (s === 'done' && cy) { cy.resize(); cy.fit(undefined, 24); }
  }

  function showError(reason, detail) {
    var known = { invalid: 1, private: 1, build: 1, vm: 1, key: 1, timeout: 1, failed: 1, cancelled: 1 };
    if (!known[reason]) reason = 'failed';
    document.body.setAttribute('data-error', reason);
    var repoLabel = $('#repo-chip-name') ? $('#repo-chip-name').textContent : '';
    if (repoLabel && repoLabel !== '—') {
      var priv = $('#err-private-name');
      if (priv) priv.textContent = repoLabel;
    }
    if (detail && reason === 'build' && $('#err-build-log')) $('#err-build-log').textContent = detail;
    if (detail && reason === 'vm' && $('#err-vm-detail')) $('#err-vm-detail').textContent = detail;
    if (detail && reason === 'key' && $('#err-key-detail')) $('#err-key-detail').textContent = detail.replace(/^Scan failed:\s*/, '');
    if (detail && reason === 'failed' && $('#err-failed-detail')) $('#err-failed-detail').textContent = detail.replace(/^Scan failed:\s*/, '');
    var bad = $('#bad-url');
    if (bad && params.get('url')) bad.value = params.get('url');
    setState('error');
  }

  function classify(status, error, msg) {
    if (status === 'timeout') return 'timeout';
    if (status === 'cancelled') return 'cancelled';
    if (error) return error;
    var m = (msg || '').toLowerCase();
    if (m.indexOf('401') >= 0 || m.indexOf('api key') >= 0 || m.indexOf('unauthorized') >= 0) return 'key';
    if (m.indexOf('build') >= 0 || m.indexOf('npm') >= 0) return 'build';
    if (m.indexOf('vultr') >= 0 || m.indexOf('instance') >= 0) return 'vm';
    if (m.indexOf('not found') >= 0 || m.indexOf('private') >= 0) return 'private';
    if (m.indexOf('invalid') >= 0) return 'invalid';
    return 'failed';
  }

  $$('[data-set-state]').forEach(function (b) {
    b.addEventListener('click', function () {
      if (!scanId) document.body.removeAttribute('data-error');
      setState(b.getAttribute('data-set-state'));
      window.scrollTo(0, 0);
    });
  });
  document.addEventListener('click', function (e) {
    var go = e.target.closest('[data-goto-tab]');
    if (!go) return;
    var tab = document.getElementById(go.getAttribute('data-goto-tab'));
    if (tab) selectTab(tab);
  });

  function setText(id, text) { var n = $(id); if (n) n.textContent = text; }

  function setRepo(url, ref, commit) {
    setText('#repo-chip-name', url ? String(url).replace('https://github.com/', '') : '—');
    var bits = [];
    if (ref) bits.push('@ ' + ref);
    if (commit) bits.push(String(commit).slice(0, 7));
    setText('#repo-chip-ref', bits.join(' · '));
  }

  function setMeter(valueId, fillId, text, pct) {
    setText(valueId, text);
    var fill = $(fillId);
    if (!fill) return;
    var shown = pct == null ? 0 : pct;
    fill.style.setProperty('--pct', shown + '%');
    if (fill.parentNode) fill.parentNode.setAttribute('aria-valuenow', pct == null ? '0' : String(pct));
  }

  function resetStepper() {
    $$('#stepper .tp-stepper__item').forEach(function (li) {
      li.className = 'tp-stepper__item tp-stepper__item--pending';
      li.removeAttribute('aria-current');
      var use = li.querySelector('use');
      if (use) use.setAttribute('href', '#i-dot');
      var meta = li.querySelector('.tp-stepper__meta');
      if (meta) meta.textContent = 'pending';
    });
  }

  function markStep(stage, status) {
    var items = $$('#stepper .tp-stepper__item');
    var idx = STAGE_ORDER.indexOf(stage);
    if (idx < 0 || !items[idx]) return;
    function paint(li, st) {
      li.className = 'tp-stepper__item tp-stepper__item--' + st;
      var use = li.querySelector('use');
      var icon = st === 'done' ? '#i-check' : st === 'running' ? '#i-spin' : st === 'failed' ? '#i-x' : '#i-dot';
      if (use) use.setAttribute('href', icon);
      if (st === 'running') li.setAttribute('aria-current', 'step');
      else li.removeAttribute('aria-current');
      var meta = li.querySelector('.tp-stepper__meta');
      if (meta && (st === 'pending' || st === 'running' || meta.textContent === 'pending' || meta.textContent === 'running')) {
        meta.textContent = st === 'done' ? 'done' : st;
      }
    }
    paint(items[idx], status);
    if (status !== 'failed') {
      for (var i = 0; i < idx; i++) {
        if (items[i].className.indexOf('--failed') < 0) paint(items[i], 'done');
      }
    }
  }

  function sourcesEl(sources) {
    var have = {};
    (sources || []).forEach(function (s) { have[s] = true; });
    var wrap = el('span', 'tp-sources');
    ['D', 'S', 'R', 'F'].forEach(function (letter) {
      var cls = 'tp-source';
      if (have[letter]) cls += ' tp-source--on';
      else if (letter === 'D' && (have.S || have.R || have.F)) cls += ' tp-source--missing';
      wrap.appendChild(el('span', cls, letter));
    });
    return wrap;
  }

  function renderLiveTools() {
    var list = $('#toollist');
    if (!list) return;
    clear(list);
    if (!liveTools.length) {
      list.appendChild(el('li', 'tp-toollist__empty muted', "Tools appear as they're discovered"));
      return;
    }
    var probed = 0;
    liveTools.forEach(function (t) {
      if (t.status && t.status !== 'queued' && t.status !== 'probing') probed += 1;
      var li = el('li', 'tp-toollist__item');
      li.appendChild(el('span', 'tp-toollist__name', t.name));
      li.appendChild(sourcesEl(t.sources));
      var status = el('span', 'tp-toollist__status');
      var spec = TVERDICT[t.status] || (t.status === 'queued' ? ['queued', '#i-dash', 'tp-verdict--queued'] : ['probing', '#i-spin', 'tp-verdict--probing']);
      status.appendChild(badge(spec[2], spec[1], spec[0]));
      li.appendChild(status);
      list.appendChild(li);
    });
    setText('#tool-heading-meta', liveTools.length + ' found · ' + probed + ' probed');
    var more = $('#tool-more');
    if (more) more.hidden = true;
  }

  function resetLive() {
    liveTools = [];
    egressN = 0;
    secs = 0;
    setText('#elapsed', '00:00');
    setText('#time-label', '00:00 / 15:00');
    var timeFill = $('#time-fill');
    if (timeFill) timeFill.style.setProperty('--pct', '0%');
    setMeter('#cpu-value', '#cpu-fill', '—', null);
    setMeter('#mem-value', '#mem-fill', '—', null);
    setText('#net-value', '—');
    setText('#net-meta', scanId ? ('tp_internal_' + scanId) : '—');
    setText('#decoy-planted', '0');
    setText('#egress-count', '0');
    setText('#tool-heading-meta', '');
    var sink = $('#sink-list');
    if (sink) { clear(sink); sink.appendChild(el('li', 'muted', 'None yet')); }
    var log = $('#log');
    if (log) {
      clear(log);
      log.appendChild(el('div', 'tp-log__line tp-log__line--info tp-log__placeholder', ''));
      var hold = log.lastChild;
      hold.appendChild(el('span', 'tp-log__msg', 'Waiting for the scanner…'));
    }
    renderLiveTools();
    resetStepper();
    var toast = $('#toast-decoy');
    if (toast) toast.hidden = true;
    setRepo('', '', '');
    if (scanId) setText('#scan-id', 'scan ' + scanId);
  }

  function addSink(host) {
    var sink = $('#sink-list');
    if (!sink || !host) return;
    if (sink.querySelector('.muted')) clear(sink);
    var exists = false;
    $$('li', sink).forEach(function (li) { if (li.textContent === host) exists = true; });
    if (!exists) sink.appendChild(el('li', '', host));
  }

  function handleStage(data) {
    if (!data || (data.msg || '').indexOf('status=') === 0) return;
    var ts = (data.ts || '').toString();
    if (ts.indexOf('T') >= 0) ts = ts.split('T')[1].slice(0, 8);
    if (window.TP.appendLog) {
      window.TP.appendLog({ ts: ts || '--:--:--', level: data.level || 'info', stage: data.stage || '', msg: data.msg || '' });
    }
    var payload = data.data || {};
    if (payload.error) markStep(data.stage || 'analyze', 'failed');
    else if (data.stage) markStep(data.stage, 'running');
    if (data.stage === 'isolate' || payload.network === 'blocked') {
      setText('#net-value', 'BLOCKED');
      setText('#net-meta', 'tp_internal_' + (scanId || 'scan') + ' · --internal');
    }
    if (payload.decoys != null) setText('#decoy-planted', String(payload.decoys));
    if (typeof payload.cpu === 'number') setMeter('#cpu-value', '#cpu-fill', Math.round(payload.cpu) + '%', Math.round(payload.cpu));
    if (typeof payload.mem === 'number') setMeter('#mem-value', '#mem-fill', Math.round(payload.mem) + '%', Math.round(payload.mem));
    if (payload.tools && payload.tools.length) {
      payload.tools.forEach(function (t) {
        var found = null;
        liveTools.forEach(function (row) { if (row.name === t.name) found = row; });
        if (!found) liveTools.push({ name: t.name, sources: t.sources || [], status: t.status || 'queued' });
        else {
          if (t.sources) found.sources = t.sources;
          if (t.status) found.status = t.status;
        }
      });
      renderLiveTools();
    }
    if (payload.tool) {
      var status = payload.verdict || payload.status || 'probing';
      var row = null;
      liveTools.forEach(function (t) { if (t.name === payload.tool) row = t; });
      if (!row) liveTools.push({ name: payload.tool, sources: payload.sources || [], status: status });
      else {
        row.status = status;
        if (payload.sources && payload.sources.length) row.sources = payload.sources;
      }
      renderLiveTools();
    }
    if (data.level === 'alert') {
      egressN += 1;
      setText('#egress-count', String(egressN));
      var count = $('#egress-count');
      if (count) { count.classList.remove('is-bumped'); void count.offsetWidth; count.classList.add('is-bumped'); }
      var toast = $('#toast-decoy');
      if (toast) {
        setText('#toast-msg', data.msg || 'Contained.');
        toast.hidden = false;
      }
      if (payload.host) addSink(payload.host);
    }
  }

  function headline(report) {
    var findings = report.findings || [];
    var tools = report.tools || [];
    if (report.verdict === 'clean') return 'No pain found.';
    if (report.verdict === 'over_privileged') {
      var extra = tools.filter(function (t) { return t.verdict === 'exceeds_claim'; }).length;
      return 'Over-privileged: ' + extra + ' tools can do more than they claim.';
    }
    if (report.verdict === 'suspicious') return 'Suspicious: worth a closer look.';
    var crit = findings.filter(function (f) { return f.severity === 'critical'; }).length;
    var n = crit || findings.length || 1;
    return 'Ouch: ' + n + ' critical finding' + (n === 1 ? '' : 's') + '.';
  }

  function lede(report) {
    var findings = report.findings || [];
    var stats = report.stats || {};
    if (report.verdict === 'clean') {
      var n = stats.tools != null ? stats.tools : (report.tools || []).length;
      return 'All ' + n + ' tools did what they claimed. No decoy reads, no undeclared egress.';
    }
    var top = findings[0];
    if (top && (top.explanation || top.title)) return top.explanation || top.title;
    return 'Open the findings for the evidence.';
  }

  function recommendation(report) {
    var findings = report.findings || [];
    var top = findings[0];
    if (report.verdict === 'clean') {
      return 'Safe to add. The least-privilege config is still the tightest setup.';
    }
    if (report.verdict === 'over_privileged') {
      return "Use the least-privilege config to turn off tools you don't need.";
    }
    if (report.verdict === 'flagged') {
      var tool = top && top.tool;
      if (!tool) {
        (report.tools || []).some(function (t) {
          if (t.verdict === 'flagged') { tool = t.name; return true; }
          return false;
        });
      }
      if (tool) return 'Block ' + tool + ', then use the least-privilege config.';
    }
    return (top && top.recommendation) || 'Review the findings, then use the least-privilege config.';
  }

  function renderArtifacts(report) {
    var panel = $('#artifacts-panel');
    var body = $('#artifacts-body');
    var rescan = $('#rescan-brief');
    if (!panel || !body) return;
    var art = report.artifacts || {};
    var launch = report.launch || {};
    var has =
      art.launch_sh ||
      art.probe_summary ||
      art.workdir ||
      report.scan_brief ||
      (report.expectations && report.expectations.length);
    panel.hidden = !has;
    if (!has) return;
    clear(body);
    function row(label, value) {
      if (value == null || value === '') return;
      var wrap = el('div', '');
      wrap.appendChild(el('div', 'tp-eyebrow', label));
      var pre = document.createElement('pre');
      pre.className = 'mono';
      pre.style.cssText = 'margin:4px 0 0;white-space:pre-wrap;word-break:break-word;font-size:12px;opacity:0.9';
      pre.textContent = String(value);
      wrap.appendChild(pre);
      body.appendChild(wrap);
    }
    if (report.scan_brief) row('Scan brief', report.scan_brief);
    row(
      'Workdir',
      (art.workdir || '') + (art.workdir_source ? ' (' + art.workdir_source + ')' : '')
    );
    row(
      'Launch',
      (launch.argv && launch.argv.join(' ')) ||
        (art.launch_source ? 'source=' + art.launch_source : '')
    );
    if (art.launch_sh) row('launch_sh', art.launch_sh);
    row(
      'Probe',
      (art.probe_summary || '') +
        (art.probe_source ? ' [' + art.probe_source + ']' : '') +
        (art.round2_plans ? ' · round2=' + art.round2_plans : '')
    );
    var exp = report.expectations || [];
    if (exp.length) {
      var hits = exp.filter(function (e) { return e.hit; }).length;
      row('Expectations', hits + '/' + exp.length + ' hit');
    }
    if (rescan) {
      rescan.hidden = false;
      rescan.onclick = function () {
        var repo = (report.repo && report.repo.url) || (window.TP.scan && window.TP.scan.repo_url);
        if (!repo) return;
        var brief = window.prompt('Scan brief for re-scan', report.scan_brief || '');
        if (brief === null) return;
        var payload = {
          repo_url: repo,
          ref: (report.repo && report.repo.ref) || (window.TP.scan && window.TP.scan.ref) || 'main'
        };
        if (brief.trim()) payload.scan_brief = brief.trim().slice(0, 2000);
        if (report.repo && report.repo.workdir && report.repo.workdir !== '.') {
          payload.prefer_subdir = report.repo.workdir;
        }
        rescan.disabled = true;
        fetch('/api/scans', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        })
          .then(function (r) { return r.json().then(function (j) { if (!r.ok) throw new Error('rescan failed'); return j; }); })
          .then(function (j) {
            location.href = 'scan.html?id=' + encodeURIComponent(j.id) + '&state=in-progress';
          })
          .catch(function () { rescan.disabled = false; });
      };
    }
  }

  function renderReport(report) {
    window.TP.report = report;
    graphEpoch += 1;
    var repo = report.repo || {};
    var scan = window.TP.scan || {};
    setRepo(repo.url || scan.repo_url, scan.ref, repo.commit);
    if (report.scan_id) setText('#scan-id', 'scan ' + report.scan_id);
    document.title = 'Scan ' + (report.scan_id || scanId || '') + ' · ToolPain';

    var vb = $('#verdict-badge');
    var hero = HERO[report.verdict] || HERO.flagged;
    if (vb) {
      clear(vb);
      vb.className = 'tp-badge ' + hero[2];
      vb.style.alignSelf = 'flex-start';
      vb.appendChild(svgIcon(hero[1], true));
      vb.appendChild(document.createTextNode(hero[0]));
    }
    setText('#verdict-title', headline(report));
    setText('#verdict-text', lede(report));
    setText('#verdict-rec', recommendation(report));
    renderArtifacts(report);

    var findings = report.findings || [];
    var counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(function (f) { if (counts[f.severity] != null) counts[f.severity] += 1; });
    var maxSev = 1;
    Object.keys(counts).forEach(function (k) { if (counts[k] > maxSev) maxSev = counts[k]; });
    $$('#sev-panel .tp-sevcount').forEach(function (row) {
      var key = row.getAttribute('data-sev');
      var n = counts[key] || 0;
      var num = row.querySelector('.tp-sevcount__n');
      var bar = row.querySelector('.tp-sevcount__bar span');
      if (num) num.textContent = String(n);
      if (bar) bar.style.setProperty('--pct', Math.round(n / maxSev * 100) + '%');
    });
    var top = $('#top-findings');
    if (top) {
      clear(top);
      top.appendChild(el('h3', 'tp-eyebrow', 'Top findings'));
      var shown = findings.slice(0, 3);
      if (!shown.length) top.appendChild(el('p', 'tp-topfindings__empty', 'No findings. Claims matched what the tools did.'));
      shown.forEach(function (f) {
        var btn = el('button', 'tp-topfindings__item');
        btn.type = 'button';
        btn.setAttribute('data-goto-tab', 'tab-findings');
        var sev = f.severity || 'info';
        btn.appendChild(badge('tp-badge--' + sev, SEV_ICON[sev] || '#s-info', sev.charAt(0).toUpperCase() + sev.slice(1)));
        btn.appendChild(el('span', '', f.title || f.type || 'Finding'));
        top.appendChild(btn);
      });
    }

    var stats = report.stats || {};
    var statHost = $('#stats');
    if (statHost) {
      var tiles = [
        ['Tools found', stats.tools != null ? stats.tools : (report.tools || []).length, ''],
        ['Undocumented', stats.undocumented || 0, stats.undocumented ? 'tp-stat--high' : ''],
        ['Critical-tier tools', stats.critical_tier || 0, stats.critical_tier ? 'tp-stat--critical' : ''],
        ['Toxic combos', stats.toxic_combos != null ? stats.toxic_combos : (report.toxic_combos || []).length, (stats.toxic_combos || (report.toxic_combos || []).length) ? 'tp-stat--high' : ''],
        ['Undeclared egress hosts', stats.egress_attempted || 0, stats.egress_attempted ? 'tp-stat--critical' : ''],
        ['Decoy reads', stats.decoy_reads || 0, stats.decoy_reads ? 'tp-stat--critical tp-stat--alert' : '']
      ];
      clear(statHost);
      tiles.forEach(function (tile) {
        var box = el('div', 'tp-stat' + (tile[2] ? ' ' + tile[2] : ''));
        box.appendChild(el('span', 'tp-stat__label', tile[0]));
        box.appendChild(el('span', 'tp-stat__value', String(tile[1])));
        statHost.appendChild(box);
      });
    }

    var recap = $('#recap');
    if (recap) {
      clear(recap);
      var attempted = (report.egress && report.egress.attempted) || [];
      var blocked = attempted.filter(function (a) { return a.blocked !== false; }).length;
      var decoy = stats.decoy_reads || 0;
      var bits = [
        'Network blocked for the whole run',
        blocked + ' egress attempt' + (blocked === 1 ? '' : 's') + ' contained',
        decoy + ' decoy read' + (decoy === 1 ? '' : 's'),
        'VM ' + (report.scan_id || scanId || '') + ' destroyed'
      ];
      bits.forEach(function (text, i) {
        var span = el('span', '', text);
        if (i === 0) span.insertBefore(svgIcon('#i-lock'), span.firstChild);
        recap.appendChild(span);
      });
    }
    var doneText = $('#done-meta-text');
    if (doneText) {
      var dur = 'VM destroyed';
      if (scan.created_at && scan.updated_at) {
        var seconds = Math.max(0, Math.round((Date.parse(scan.updated_at) - Date.parse(scan.created_at)) / 1000));
        dur = fmt(seconds) + ' · VM destroyed';
      }
      doneText.textContent = dur;
    }

    setText('#count-tools', String((report.tools || []).length));
    setText('#count-findings', String(findings.length));
    setText('#count-combos', String((report.toxic_combos || []).length));
    var netRows = networkRows(report);
    setText('#count-network', String(netRows.length));
    var drift = (repo.fork_drift || []);
    setText('#count-drift', String(drift.length));
    var driftTab = $('#tab-drift');
    if (driftTab) driftTab.hidden = drift.length === 0;

    renderTools(report.tools || []);
    renderFindings(findings);
    renderCombos(report.toxic_combos || []);
    renderNetwork(report, netRows);
    renderDrift(report, drift);
    renderConfig(report);
    var dl = $('#download-json');
    if (dl) dl.setAttribute('download', (report.scan_id || 'toolpain') + '.json');
    if ($('#tab-graph') && $('#tab-graph').getAttribute('aria-selected') === 'true') initGraph();
  }

  function renderTools(tools) {
    var table = $('#tools-table');
    if (!table) return;
    $$('tbody', table).forEach(function (tb) { tb.remove(); });
    tools.forEach(function (t, index) {
      var priv = PRIV[t.privilege] || ['Info', '#s-info', 'tp-badge--info', 0];
      var verd = TVERDICT[t.verdict] || ['confirmed', '#i-check', 'tp-verdict--confirmed', 1];
      var tags = [t.verdict || '', t.privilege || ''].join(' ');
      var body = document.createElement('tbody');
      body.dataset.name = (t.name || '').toLowerCase();
      body.dataset.priv = String(priv[3]);
      body.dataset.verdict = String(verd[3]);
      body.dataset.decoy = String(t.decoy_reads || 0);
      body.dataset.tags = tags;
      var open = index === 0 && (t.verdict === 'flagged' || t.verdict === 'exceeds_claim');
      var tr = document.createElement('tr');
      if (t.verdict === 'flagged') tr.className = 'tp-row--flagged';
      var tdName = document.createElement('td');
      var toggle = el('button', 'tp-rowtoggle');
      toggle.type = 'button';
      toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
      toggle.setAttribute('aria-controls', 'd-' + t.name);
      toggle.appendChild(svgIcon('#i-chev'));
      toggle.appendChild(document.createTextNode(t.name));
      tdName.appendChild(toggle);
      var tdPriv = document.createElement('td');
      tdPriv.appendChild(badge(priv[2], priv[1], priv[0]));
      var tdVerd = document.createElement('td');
      tdVerd.appendChild(badge(verd[2], verd[1], verd[0]));
      var tdSrc = document.createElement('td');
      tdSrc.appendChild(sourcesEl(t.sources));
      var egress = (t.egress || []).join(', ');
      var tdEg = el('td', 'tp-cell-egress' + (t.verdict === 'flagged' && egress ? ' tp-cell-alert' : (egress ? '' : ' tp-cell-none')), egress || '—');
      var tdDec = el('td', 'mono' + ((t.decoy_reads || 0) > 0 ? ' tp-cell-alert' : ' tp-cell-none'), String(t.decoy_reads || 0));
      [tdName, tdPriv, tdVerd, tdSrc, tdEg, tdDec].forEach(function (td) { tr.appendChild(td); });
      var detail = document.createElement('tr');
      detail.className = 'tp-row-detail' + (t.verdict === 'flagged' ? ' tp-row--flagged' : '');
      detail.id = 'd-' + t.name;
      if (!open) detail.hidden = true;
      var td = document.createElement('td');
      td.colSpan = 6;
      var grid = el('div', 'tp-row-detail__grid');
      grid.appendChild(detailBlock('Claimed behavior', t.claimed || 'Not documented.'));
      var observed = t.observed || {};
      var obs = [];
      (observed.files || []).forEach(function (f) { obs.push('file ' + f); });
      (observed.network || []).forEach(function (f) { obs.push('net ' + f); });
      (observed.processes || []).forEach(function (f) { obs.push('proc ' + f); });
      (t.evidence || []).forEach(function (f) { obs.push(f); });
      grid.appendChild(detailBlock('Observed', obs.length ? obs.join(' · ') : 'Nothing beyond the claim.'));
      grid.appendChild(detailBlock('Downstream', (t.downstream || []).join(', ') || 'None'));
      td.appendChild(grid);
      if ((t.evidence || []).length) {
        var code = el('div', 'tp-code');
        var pre = el('pre', '', t.evidence.join('\n'));
        var copy = el('button', 'tp-code__copy');
        copy.type = 'button';
        copy.setAttribute('aria-label', 'Copy evidence');
        copy.appendChild(svgIcon('#i-copy'));
        code.appendChild(pre);
        code.appendChild(copy);
        td.appendChild(code);
      }
      detail.appendChild(td);
      body.appendChild(tr);
      body.appendChild(detail);
      table.appendChild(body);
    });
    setText('#tool-total', String(tools.length));
    if (typeof applyTools === 'function') applyTools();
  }

  function detailBlock(k, text) {
    var box = el('div');
    box.appendChild(el('span', 'tp-row-detail__k', k));
    box.appendChild(el('span', '', text));
    return box;
  }

  function renderFindings(findings) {
    var root = $('#p-findings');
    if (!root) return;
    clear(root);
    if (!findings.length) {
      root.appendChild(el('p', 'muted', 'No findings. Every tool matched its claim.'));
      return;
    }
    var order = ['critical', 'high', 'medium', 'low', 'info'];
    order.forEach(function (sev) {
      var group = findings.filter(function (f) { return f.severity === sev; });
      if (!group.length) return;
      var wrap = el('div', 'tp-findings-group tp-findings-group--' + (sev === 'medium' ? 'medium' : sev));
      if (sev === 'low' || sev === 'info') wrap.className = 'tp-findings-group';
      var title = el('h2', 'tp-findings-group__title');
      title.appendChild(svgIcon(SEV_ICON[sev] || '#s-info', true));
      title.appendChild(document.createTextNode(sev.charAt(0).toUpperCase() + sev.slice(1) + ' '));
      title.appendChild(el('span', 'count', String(group.length)));
      wrap.appendChild(title);
      group.forEach(function (f) {
        var card = el('article', 'tp-panel tp-finding');
        var meta = el('div', 'tp-finding__meta');
        meta.appendChild(el('span', 'tp-finding__id', f.id || ''));
        meta.appendChild(badge('tp-badge--' + sev, SEV_ICON[sev], sev.charAt(0).toUpperCase() + sev.slice(1)));
        if (f.type) meta.appendChild(el('span', 'tp-badge tp-badge--outline', f.type));
        if (f.tool) meta.appendChild(el('span', 'tp-chip tp-chip--tool', f.tool));
        card.appendChild(meta);
        card.appendChild(el('h3', 'tp-finding__title', f.title || f.type || 'Finding'));
        if (f.explanation) card.appendChild(el('p', 'tp-finding__explain', f.explanation));
        if (f.evidence) {
          var code = el('div', 'tp-code');
          code.appendChild(el('pre', '', f.evidence));
          var copy = el('button', 'tp-code__copy');
          copy.type = 'button';
          copy.setAttribute('aria-label', 'Copy evidence');
          copy.appendChild(svgIcon('#i-copy'));
          code.appendChild(copy);
          card.appendChild(code);
        }
        if (f.recommendation) {
          var rec = el('p', 'tp-finding__rec');
          rec.appendChild(el('strong', '', 'Recommendation: '));
          rec.appendChild(document.createTextNode(f.recommendation));
          card.appendChild(rec);
        }
        wrap.appendChild(card);
      });
      root.appendChild(wrap);
    });
  }

  function renderCombos(combos) {
    var grid = $('#combo-grid');
    if (!grid) return;
    clear(grid);
    if (!combos.length) {
      grid.appendChild(el('p', 'muted', 'No toxic combinations.'));
      return;
    }
    combos.forEach(function (c) {
      var card = el('article', 'tp-panel tp-combo');
      var head = el('div', 'tp-combo__head');
      head.appendChild(el('span', 'tp-combo__risk', (c.risk || 'combo').replace(/_/g, ' ')));
      var sev = c.severity || 'medium';
      head.appendChild(badge('tp-badge--' + sev, SEV_ICON[sev] || '#s-medium', sev.charAt(0).toUpperCase() + sev.slice(1)));
      var pair = el('div', 'tp-combo__pair');
      (c.tools || []).forEach(function (name, i) {
        if (i) pair.appendChild(el('span', 'muted', '+'));
        pair.appendChild(el('span', 'tp-chip', name));
      });
      card.appendChild(head);
      card.appendChild(pair);
      if (c.why) card.appendChild(el('p', 'tp-combo__why', c.why));
      grid.appendChild(card);
    });
  }

  function networkRows(report) {
    var declared = (report.egress && report.egress.declared) || [];
    var attempted = (report.egress && report.egress.attempted) || [];
    var rows = [];
    var seen = {};
    attempted.forEach(function (a) {
      seen[a.host] = true;
      rows.push({
        host: a.host,
        declared: declared.indexOf(a.host) >= 0 ? 'Yes' : 'No',
        attempted: 'Yes',
        blocked: a.blocked !== false,
        tool: a.tool || '',
        fixture: false
      });
    });
    (report.tools || []).forEach(function (t) {
      (t.egress || []).forEach(function (host) {
        if (seen[host]) return;
        seen[host] = true;
        rows.push({ host: host, declared: 'Fixture', attempted: 'Yes', blocked: false, tool: t.name, fixture: true });
      });
    });
    return rows;
  }

  function renderNetwork(report, rows) {
    var root = $('#p-network');
    if (!root) return;
    clear(root);
    var ingress = report.ingress || [];
    var inStack = el('div', 'tp-stack');
    inStack.style.gap = '12px';
    var hIn = el('h2', '', 'Ingress ');
    hIn.style.fontSize = '16px';
    hIn.appendChild(el('span', 'muted', ingress.length ? ingress.length + ' listening' : 'none'));
    inStack.appendChild(hIn);
    if (!ingress.length) inStack.appendChild(el('p', 'muted', 'No listening ports observed.'));
    ingress.forEach(function (p) {
      var line = el('div', 'tp-panel tp-row');
      line.style.padding = '14px 16px';
      line.appendChild(el('span', 'mono', p.addr || p.host || 'port'));
      rootNote(line, p.note || p.process || '');
      inStack.appendChild(line);
    });
    root.appendChild(inStack);
    var eg = el('div', 'tp-stack');
    eg.style.gap = '12px';
    var declaredN = ((report.egress && report.egress.declared) || []).length;
    var hEg = el('h2', '', 'Egress ');
    hEg.style.fontSize = '16px';
    hEg.appendChild(el('span', 'muted', declaredN + ' declared · ' + rows.length + ' observed'));
    eg.appendChild(hEg);
    if (!rows.length) eg.appendChild(el('p', 'muted', 'No outbound hosts. The sinkhole stayed quiet.'));
    else {
      var wrap = el('div', 'tp-table-wrap');
      var table = el('table', 'tp-table tp-table--comfy tp-table--min-680');
      var thead = document.createElement('thead');
      var hr = document.createElement('tr');
      ['Host', 'Declared', 'Attempted', 'Result', 'Tool'].forEach(function (h) {
        hr.appendChild(el('th', '', h));
      });
      thead.appendChild(hr);
      var tb = document.createElement('tbody');
      rows.forEach(function (r) {
        var tr = document.createElement('tr');
        tr.appendChild(el('td', 'mono', r.host));
        tr.appendChild(el('td', r.declared === 'No' ? 'tp-cell-alert' : 'muted', r.declared));
        tr.appendChild(el('td', '', r.attempted));
        var td = document.createElement('td');
        if (r.fixture) td.appendChild(badge('tp-badge--low', '#i-check', 'Allowed (in-sandbox)'));
        else if (r.blocked) td.appendChild(badge('tp-badge--critical', '#i-x', 'Blocked (sinkhole)'));
        else td.appendChild(badge('tp-badge--high', '#i-up', 'Reached'));
        tr.appendChild(td);
        tr.appendChild(el('td', 'mono', r.tool));
        tb.appendChild(tr);
      });
      table.appendChild(thead);
      table.appendChild(tb);
      wrap.appendChild(table);
      eg.appendChild(wrap);
    }
    root.appendChild(eg);
  }

  function rootNote(parent, text) {
    if (text) parent.appendChild(el('span', 'muted', text));
  }

  function renderDrift(report, drift) {
    var root = $('#p-drift');
    if (!root) return;
    clear(root);
    var repo = report.repo || {};
    var row = el('div', 'tp-row');
    row.style.gap = '12px';
    row.style.fontSize = '14px';
    if (repo.upstream) {
      row.appendChild(el('span', 'tp-chip tp-chip--repo', repo.upstream));
      row.appendChild(el('span', 'muted', 'upstream'));
    }
    var self = (repo.url || '').replace('https://github.com/', '');
    if (repo.commit) self += ' @ ' + String(repo.commit).slice(0, 7);
    if (self) row.appendChild(el('span', 'tp-chip tp-chip--repo', self));
    root.appendChild(row);
    var counts = el('div', 'tp-drift-counts');
    var added = drift.filter(function (d) { return d.change === 'added_tool' || d.change === 'added'; }).length;
    var changed = drift.filter(function (d) { return d.change && d.change.indexOf('add') < 0 && d.change.indexOf('remov') < 0; }).length;
    var removed = drift.filter(function (d) { return d.change && d.change.indexOf('remov') >= 0; }).length;
    [['Tools added', added, added ? 'tp-stat tp-stat--critical tp-stat--alert' : 'tp-stat'], ['Changed', changed, 'tp-stat'], ['Removed', removed, 'tp-stat']].forEach(function (item) {
      var box = el('div', item[2]);
      box.appendChild(el('span', 'tp-stat__label', item[0]));
      box.appendChild(el('span', 'tp-stat__value', String(item[1])));
      counts.appendChild(box);
    });
    root.appendChild(counts);
    if (!drift.length) {
      root.appendChild(el('p', 'muted', 'No fork drift. Nothing was added beyond upstream.'));
      return;
    }
    drift.forEach(function (d) {
      var panel = el('div', 'tp-panel');
      panel.style.overflow = 'hidden';
      var head = el('div', 'tp-panel__head');
      head.style.padding = '12px 16px';
      head.style.fontSize = '13px';
      head.appendChild(el('span', 'mono', (d.file || d.tool || 'change') + ' · ' + (d.change || '')));
      if (d.tool) head.appendChild(el('span', 'muted', d.tool));
      panel.appendChild(head);
      root.appendChild(panel);
    });
  }

  function renderConfig(report) {
    var lp = report.least_privilege_config || { allow_tools: [], allow_hosts: [] };
    var cfg = $('#cfg-text');
    if (cfg) cfg.textContent = JSON.stringify(lp, null, 2);
    var intro = $('#cfg-intro');
    if (!intro) return;
    var blocked = (report.tools || []).filter(function (t) {
      return t.verdict === 'flagged' || t.verdict === 'exceeds_claim';
    }).map(function (t) { return t.name; });
    clear(intro);
    if (!blocked.length) {
      intro.appendChild(document.createTextNode('These tools matched their claims. Paste this allowlist into your agent config.'));
    } else {
      intro.appendChild(document.createTextNode('Allow only the tools this server needs. Everything else, including '));
      intro.appendChild(el('span', 'mono', blocked.join(', ')));
      intro.appendChild(document.createTextNode(', stays off.'));
    }
  }

  function loadReport(id) {
    return fetch('/api/scans/' + encodeURIComponent(id) + '/report').then(function (r) {
      if (!r.ok) throw new Error('no report');
      return r.json();
    }).then(function (report) {
      renderReport(report);
      setState('done');
      var view = $('#view-report');
      if (view) view.hidden = true;
      var replay = $('#replay-scan');
      if (replay) replay.hidden = false;
      var shareBtn = $('#share-report');
      if (shareBtn && scanId) {
        shareBtn.hidden = false;
        shareBtn.onclick = function () {
          shareBtn.disabled = true;
          fetch('/api/scans/' + encodeURIComponent(scanId) + '/share', { method: 'POST' })
            .then(function (r) { if (!r.ok) throw new Error('share failed'); return r.json(); })
            .then(function (body) {
              var link = location.origin + (body.url || '');
              if (navigator.clipboard && navigator.clipboard.writeText) {
                navigator.clipboard.writeText(link).catch(function () {});
              }
              shareBtn.textContent = 'Link copied';
              shareBtn.disabled = false;
            })
            .catch(function () {
              shareBtn.textContent = 'Share failed';
              shareBtn.disabled = false;
            });
        };
      }
      return report;
    });
  }

  function openEvents() {
    if (!scanId || typeof EventSource === 'undefined') return;
    if (es) es.close();
    es = new EventSource('/api/scans/' + encodeURIComponent(scanId) + '/events');
    es.addEventListener('stage', function (ev) {
      var data;
      try { data = JSON.parse(ev.data); } catch (e) { return; }
      handleStage(data);
    });
    es.addEventListener('done', function (ev) {
      var data = {};
      try { data = JSON.parse(ev.data); } catch (e) { /* keep empty */ }
      if (data.status === 'done') {
        markStep('destroy', 'done');
        offerReport();
      } else if (data.status === 'cancelled') {
        showCancelled();
      } else if (data.status === 'timeout') {
        loadReport(scanId).then(function () { showError('timeout', data.detail); }, function () { showError('timeout', data.detail); });
      } else {
        showError(classify(data.status, data.error, data.detail), data.detail);
      }
      es.close();
    });
    es.onerror = function () { /* browser retries */ };
  }

  function offerReport() {
    var cancel = $('#cancel-scan');
    if (cancel) cancel.hidden = true;
    var view = $('#view-report');
    if (view) {
      view.hidden = false;
      view.onclick = function () { loadReport(scanId); };
    }
    setTimeout(function () {
      if (document.body.getAttribute('data-state') === 'in-progress') loadReport(scanId);
    }, 3000);
  }

  function showCancelled() {
    var items = $$('#stepper .tp-stepper__item');
    var current = null;
    items.forEach(function (li) {
      if (li.className.indexOf('--running') >= 0) current = li;
    });
    if (!current) {
      items.forEach(function (li) {
        if (!current && li.className.indexOf('--pending') >= 0) current = li;
      });
    }
    if (current) markStep(STAGE_ORDER[items.indexOf(current)] || 'destroy', 'failed');
    var banner = $('#cancel-banner');
    if (banner) banner.hidden = false;
    var cancel = $('#cancel-scan');
    if (cancel) cancel.hidden = true;
  }

  function replayScan() {
    if (!scanId) return;
    if (replayTimer) clearTimeout(replayTimer);
    if (es) { es.close(); es = null; }
    resetLive();
    if (window.TP.scan) setRepo(window.TP.scan.repo_url, window.TP.scan.ref, (reportNow().repo || {}).commit);
    setState('in-progress');
    window.scrollTo(0, 0);
    fetch('/api/scans/' + encodeURIComponent(scanId) + '/log').then(function (r) { return r.json(); }).then(function (events) {
      events = (events || []).filter(function (e) { return (e.msg || '').indexOf('status=') !== 0; });
      var gap = Math.max(700, Math.min(2200, Math.round(38000 / Math.max(events.length, 1))));
      var i = 0;
      var step = function () {
        if (i >= events.length) {
          markStep('destroy', 'done');
          setState('done');
          return;
        }
        handleStage(events[i]);
        i += 1;
        replayTimer = setTimeout(step, gap);
      };
      step();
    });
  }

  if (scanId) {
    resetLive();
    setState('in-progress');
    setText('#verdict-title', 'Loading report…');
    setText('#verdict-text', '');
    setText('#verdict-rec', '');
    ['#p-findings', '#p-tools', '#p-combos', '#p-network', '#p-drift', '#top-findings', '#stats'].forEach(function (sel) {
      var node = $(sel);
      if (node) clear(node);
    });
    setText('#node-title', 'Select a tool');
    var replayBtn = $('#replay-scan');
    if (replayBtn) {
      replayBtn.hidden = false;
      replayBtn.addEventListener('click', replayScan);
    }
    var cancelBtn = $('#cancel-scan');
    if (cancelBtn) {
      cancelBtn.addEventListener('click', function () {
        cancelBtn.disabled = true;
        cancelBtn.textContent = 'Cancelling…';
        fetch('/api/scans/' + encodeURIComponent(scanId) + '/cancel', { method: 'POST' })
          .then(function () { showCancelled(); });
      });
    }
    fetch('/api/scans/' + encodeURIComponent(scanId)).then(function (r) { return r.json(); }).then(function (s) {
      window.TP.scan = s;
      setRepo(s.repo_url, s.ref, '');
      setText('#scan-id', 'scan ' + s.id);
      setText('#account-mode-live', s.account_mode === 'byo' ? 'your account' : 'toolpain account');
      document.title = 'Scan ' + s.id + ' · ToolPain';
      if (s.status === 'done') loadReport(scanId);
      else if (s.status === 'failed' || s.status === 'cancelled' || s.status === 'timeout') {
        fetch('/api/scans/' + encodeURIComponent(scanId) + '/log').then(function (r) { return r.json(); }).then(function (events) {
          var last = null;
          (events || []).forEach(function (ev) {
            if (ev.data && ev.data.error) last = ev;
            else if ((ev.msg || '').toLowerCase().indexOf('scan failed') === 0) last = ev;
          });
          var reason = classify(s.status, last && last.data && last.data.error, last && last.msg);
          showError(reason, last && last.msg);
        }).catch(function () { showError(classify(s.status), ''); });
      } else openEvents();
    }).catch(function () { openEvents(); });
  } else {
    setState(params.get('state') || 'in-progress');
    if (params.get('reason')) showError(params.get('reason'));
    renderReport(SAMPLE_REPORT);
  }

  var sw = $('#state-switch');
  if (sw && scanId) sw.hidden = true;

  setInterval(function () {
    if (document.body.getAttribute('data-state') !== 'in-progress') return;
    secs += 1;
    setText('#elapsed', fmt(secs));
    setText('#time-label', fmt(secs) + ' / ' + fmt(LIMIT));
    var f = $('#time-fill');
    if (f) {
      var pct = Math.min(100, Math.round(secs / LIMIT * 100));
      f.style.setProperty('--pct', pct + '%');
      if (f.parentNode) f.parentNode.setAttribute('aria-valuenow', String(pct));
    }
  }, 1000);

  var toast = $('#toast-decoy');
  if (toast) toast.hidden = true;
  $$('[data-dismiss]').forEach(function (b) {
    b.addEventListener('click', function () {
      var node = document.getElementById(b.getAttribute('data-dismiss'));
      if (node) node.hidden = true;
    });
  });
  window.TP = window.TP || {};
  window.TP.bumpEgress = function (n) { setText('#egress-count', String(n)); };
  window.TP.setState = setState;
  window.TP.report = window.TP.report || (scanId
    ? { findings: [], tools: [], verdict: 'clean', stats: {}, repo: {} }
    : SAMPLE_REPORT);

  var log = $('#log');
  if (log) {
    var level = 'all';
    function applyFilter() {
      $$('.tp-log__line', log).forEach(function (ln) {
        ln.hidden = level !== 'all' && !ln.classList.contains('tp-log__line--' + level);
      });
    }
    $$('#log-filter [data-level]').forEach(function (b) {
      b.addEventListener('click', function () {
        level = b.getAttribute('data-level');
        $$('#log-filter [data-level]').forEach(function (x) { x.setAttribute('aria-pressed', String(x === b)); });
        applyFilter();
      });
    });
    var pauseBtn = $('#log-pause');
    if (pauseBtn) {
      pauseBtn.addEventListener('click', function () {
        paused = !paused;
        pauseBtn.setAttribute('aria-pressed', String(paused));
        var label = pauseBtn.querySelector('span');
        if (label) label.textContent = paused ? 'Resume' : 'Pause';
        var use = pauseBtn.querySelector('use');
        if (use) use.setAttribute('href', paused ? '#i-play' : '#i-pause');
        if (!paused) log.scrollTop = log.scrollHeight;
      });
    }
    log.scrollTop = log.scrollHeight;
    window.TP.appendLog = function (e) {
      var row = el('div', 'tp-log__line tp-log__line--' + (e.level || 'info'));
      [['ts', e.ts], ['lvl', (e.level || 'info').toUpperCase()], ['stage', e.stage], ['msg', e.msg]].forEach(function (p) {
        row.appendChild(el('span', 'tp-log__' + p[0], p[1] || ''));
      });
      row.hidden = level !== 'all' && level !== e.level;
      var placeholder = log.querySelector('.tp-log__placeholder');
      if (placeholder) placeholder.remove();
      log.appendChild(row);
      if (!paused) log.scrollTop = log.scrollHeight;
    };
  }

  var tabs = $$('#tabs [role="tab"]');
  function selectTab(tab, focus) {
    tabs.forEach(function (t) {
      var on = t === tab;
      t.setAttribute('aria-selected', String(on));
      t.tabIndex = on ? 0 : -1;
      var panel = document.getElementById(t.getAttribute('aria-controls'));
      if (panel) panel.hidden = !on;
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

  var table = $('#tools-table');
  var applyTools = function () {};
  if (table) {
    table.addEventListener('click', function (e) {
      var toggle = e.target.closest('.tp-rowtoggle');
      if (toggle) {
        var open = toggle.getAttribute('aria-expanded') !== 'true';
        toggle.setAttribute('aria-expanded', String(open));
        var detail = document.getElementById(toggle.getAttribute('aria-controls'));
        if (detail) detail.hidden = !open;
        return;
      }
      var sortBtn = e.target.closest('.tp-sort');
      if (!sortBtn) return;
      var key = sortBtn.dataset.sort;
      dir = sortKey === key ? -dir : (key === 'name' ? 1 : -1);
      sortKey = key;
      sortRows();
    });
    var sortKey = 'priv';
    var dir = -1;
    var sortRows = function () {
      var bodies = $$('tbody', table);
      bodies.sort(function (a, b) {
        if (sortKey === 'name') return a.dataset.name < b.dataset.name ? -dir : dir;
        return (Number(a.dataset[sortKey]) - Number(b.dataset[sortKey])) * dir || (a.dataset.name < b.dataset.name ? -1 : 1);
      });
      bodies.forEach(function (b) { table.appendChild(b); });
    };
    var toolQ = $('#tool-q');
    var filter = 'all';
    applyTools = function () {
      var term = (toolQ && toolQ.value || '').trim().toLowerCase();
      var shown = 0;
      $$('tbody', table).forEach(function (b) {
        var ok = (!term || (b.dataset.name || '').indexOf(term) >= 0) && (filter === 'all' || (' ' + (b.dataset.tags || '') + ' ').indexOf(' ' + filter + ' ') >= 0);
        b.hidden = !ok;
        if (ok) shown += 1;
      });
      setText('#tool-count', String(shown));
    };
    if (toolQ) toolQ.addEventListener('input', applyTools);
    $$('#tool-filters [data-filter]').forEach(function (b) {
      b.addEventListener('click', function () {
        filter = b.dataset.filter;
        $$('#tool-filters [data-filter]').forEach(function (x) { x.setAttribute('aria-pressed', String(x === b)); });
        applyTools();
      });
    });
  }

  var cfg = $('#cfg-text');
  if (cfg) {
    $$('#cfg-format [data-fmt]').forEach(function (b) {
      b.addEventListener('click', function () {
        $$('#cfg-format [data-fmt]').forEach(function (x) { x.setAttribute('aria-pressed', String(x === b)); });
        var lp = (reportNow().least_privilege_config) || { allow_tools: [], allow_hosts: [] };
        if (b.dataset.fmt === 'yaml') {
          cfg.textContent = 'allow_tools:\n' + (lp.allow_tools || []).map(function (t) { return '  - ' + t; }).join('\n') +
            '\nallow_hosts:\n' + (lp.allow_hosts || []).map(function (h) { return '  - ' + h; }).join('\n');
        } else cfg.textContent = JSON.stringify(lp, null, 2);
      });
    });
  }

  var dl = $('#download-json');
  if (dl) {
    dl.addEventListener('click', function () {
      var blob = new Blob([JSON.stringify(reportNow(), null, 2)], { type: 'application/json' });
      dl.href = URL.createObjectURL(blob);
    });
  }

  var COLOR_VAR = { crit: '--crit', high: '--high', low: '--low' };

  function showNode(id, label) {
    var report = reportNow();
    var kind = $('#node-kind');
    var title = $('#node-title');
    var ul = $('#node-lines');
    if (!kind || !title || !ul) return;
    title.textContent = label || id;
    clear(ul);
    var tool = null;
    (report.tools || []).forEach(function (t) { if (t.name === id) tool = t; });
    var lines = [];
    if (id === 'server') {
      kind.textContent = 'MCP server';
      var repo = report.repo || {};
      lines.push([(repo.url || '').replace('https://github.com/', '') + (repo.commit ? ' @ ' + String(repo.commit).slice(0, 7) : '')]);
      if (repo.upstream) lines.push(['Upstream ' + repo.upstream]);
      lines.push([((report.stats && report.stats.tools) || (report.tools || []).length) + ' tools']);
    } else if (tool) {
      kind.textContent = 'Tool · ' + (tool.privilege || 'unknown') + ' tier';
      if (tool.claimed) lines.push(['Claimed: ' + tool.claimed]);
      if (tool.verdict) lines.push(['Verdict: ' + tool.verdict, tool.verdict === 'flagged' ? 'crit' : tool.verdict === 'exceeds_claim' ? 'high' : 'low']);
      (tool.egress || []).forEach(function (h) { lines.push(['Egress ' + h, tool.verdict === 'flagged' ? 'crit' : 'low']); });
      if (tool.decoy_reads) lines.push(['Read a planted decoy', 'crit']);
      (tool.evidence || []).forEach(function (ev) { lines.push([ev, 'crit']); });
    } else if (id === 'decoy' || (label || '').indexOf('decoy') >= 0) {
      kind.textContent = 'Decoy';
      lines.push(['Planted by ToolPain', 'crit']);
    } else {
      kind.textContent = 'Node';
      lines.push(['Part of the access graph']);
    }
    if (!lines.length) lines.push(['No extra detail']);
    lines.forEach(function (l) {
      var li = el('li', '', l[0]);
      if (l[1]) li.style.setProperty('--c', 'var(' + COLOR_VAR[l[1]] + ')');
      ul.appendChild(li);
    });
  }

  function cssVars() {
    var cs = getComputedStyle(root);
    var v = function (n) { return cs.getPropertyValue(n).trim(); };
    return { bg: v('--bg'), surface: v('--surface'), raised: v('--raised'), border: v('--border'), text: v('--text'), muted: v('--muted'), accent: v('--accent'), info: v('--info'), crit: v('--crit'), high: v('--high'), mono: 'JetBrains Mono, monospace' };
  }

  function graphStyle() {
    var c = cssVars();
    return [
      { selector: 'node', style: { label: 'data(label)', 'font-family': c.mono, 'font-size': 11, color: c.text, 'text-valign': 'center', 'text-halign': 'center', 'text-wrap': 'wrap', 'text-max-width': 140, shape: 'round-rectangle', width: 'label', height: 30, padding: '10px', 'background-color': c.surface, 'border-width': 1, 'border-color': c.border } },
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
      { selector: 'edge.blocked', style: { 'line-color': c.crit, width: 2 } }
    ];
  }

  function graphElements(report) {
    var g = report.graph || {};
    var nodes = (g.nodes || []).slice();
    var edges = (g.edges || []).slice();
    if (!nodes.length) {
      nodes.push({ data: { id: 'server', label: 'MCP server', kind: 'server' } });
      (report.tools || []).forEach(function (t) {
        nodes.push({ data: { id: t.name, label: t.name, kind: 'tool', flagged: t.verdict === 'flagged' } });
        edges.push({ data: { id: 'm-' + t.name, source: 'server', target: t.name, kind: 'member' } });
      });
    }
    return {
      nodes: nodes.map(function (n) {
        var d = n.data || n;
        var cls = d.kind || 'tool';
        if (d.flagged) cls += ' flagged';
        if (d.blocked) cls += ' blocked';
        return { data: { id: String(d.id), label: d.label || d.id }, classes: cls };
      }),
      edges: edges.map(function (e) {
        var d = e.data || e;
        return { data: { id: String(d.id || (d.source + '>' + d.target)), source: String(d.source), target: String(d.target) }, classes: d.kind || 'observed' };
      })
    };
  }

  function initGraph() {
    var graphEl = $('#graph');
    if (!graphEl || typeof window.cytoscape !== 'function') return;
    if (cy && graphDrawn === graphEpoch) { cy.resize(); cy.fit(undefined, 24); return; }
    if (cy) { cy.destroy(); cy = null; }
    var elements = graphElements(reportNow());
    cy = window.cytoscape({
      container: graphEl,
      boxSelectionEnabled: false,
      wheelSensitivity: 0.2,
      layout: { name: 'preset', fit: false },
      style: graphStyle(),
      elements: elements.nodes.concat(elements.edges)
    });
    cy.on('tap', 'node', function (evt) { showNode(evt.target.id(), evt.target.data('label')); });
    function place() {
      if (!cy) return;
      cy.resize();
      var columns = ['server', 'tool', 'cap', 'host', 'decoy'];
      var groups = { server: [], tool: [], cap: [], host: [], decoy: [] };
      cy.nodes().forEach(function (node) {
        var kind = 'tool';
        columns.forEach(function (name) { if (node.hasClass(name)) kind = name; });
        groups[kind].push(node);
      });
      var x = 40;
      columns.forEach(function (kind) {
        var nodes = groups[kind];
        if (!nodes.length) return;
        nodes.forEach(function (node, index) {
          node.position({ x: x, y: 40 + index * 72 });
        });
        x += 220;
      });
      cy.fit(undefined, 28);
      var flagged = cy.nodes('.flagged');
      var pick = flagged.length ? flagged[0] : cy.nodes()[0];
      if (pick) { pick.select(); showNode(pick.id(), pick.data('label')); }
    }
    place();
    requestAnimationFrame(place);
    graphDrawn = graphEpoch;
    graphEl.setAttribute('aria-label', 'Access graph for ' + ((reportNow().repo && reportNow().repo.url) || 'this scan'));
  }

  $$('[data-zoom]').forEach(function (b) {
    b.addEventListener('click', function () {
      if (!cy) return;
      var graphEl = $('#graph');
      var z = b.dataset.zoom;
      var center = { x: graphEl.clientWidth / 2, y: graphEl.clientHeight / 2 };
      if (z === 'fit') cy.fit(undefined, 24);
      else cy.zoom({ level: cy.zoom() * (z === 'in' ? 1.25 : 0.8), renderedPosition: center });
    });
  });
  document.addEventListener('tp:theme', function () { if (cy) cy.style(graphStyle()); });
  window.addEventListener('resize', function () { if (cy) cy.resize(); });
})();
