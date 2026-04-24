/* Dashboard – professional KPI cards + period selector + customisable widgets */

// ── Sparkline SVG ─────────────────────────────────────────────────────────────

function _sl(data, color, w = 100, h = 36) {
  if (!data || data.length < 2) return `<svg width="${w}" height="${h}"></svg>`;
  const min = Math.min(0, ...data);
  const max = Math.max(...data, 1);
  const r   = max - min || 1;
  const pad = 3;
  const xs  = data.map((_, i) => ((i / (data.length - 1)) * w).toFixed(1));
  const ys  = data.map(v => (h - pad - ((v - min) / r) * (h - pad * 2)).toFixed(1));
  const pts = xs.map((x, i) => `${x},${ys[i]}`).join(' ');
  const lx  = xs[xs.length - 1], ly = ys[ys.length - 1];
  const area = `M${xs[0]},${h} ` + xs.map((x, i) => `L${x},${ys[i]}`).join(' ') + ` L${lx},${h}Z`;
  const gid  = `slg${color.replace(/[^a-f0-9]/gi, '')}`;
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" preserveAspectRatio="none" style="display:block;overflow:visible">
    <defs><linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="${color}" stop-opacity="0.3"/>
      <stop offset="100%" stop-color="${color}" stop-opacity="0.02"/>
    </linearGradient></defs>
    <path d="${area}" fill="url(#${gid})"/>
    <polyline points="${pts}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>
    <circle cx="${lx}" cy="${ly}" r="2.5" fill="${color}"/>
  </svg>`;
}

// ── KPI Card ──────────────────────────────────────────────────────────────────

function _kpi(id, label, value, sub, delta, goodDir, slData, slColor, onClick) {
  const dv    = delta;
  const good  = dv == null ? null : goodDir === 'down' ? dv <= 0 : dv >= 0;
  const dc    = dv == null ? 'var(--text-muted)' : (good ? '#22c55e' : '#ef4444');
  const di    = dv == null ? '' : dv > 0 ? '▲' : dv < 0 ? '▼' : '→';
  const dtext = dv != null ? `${di} ${Math.abs(dv).toFixed(1)}%` : '';
  const fmt   = v => (v == null ? '–' : typeof v === 'number' ? v.toLocaleString() : v);

  return `<div class="kpi-card${onClick ? ' kpi-link' : ''}" id="kpi-${id}"${onClick ? ` onclick="${onClick}"` : ''}>
    <div class="kpi-top">
      <span class="kpi-label">${label}</span>
      ${dtext ? `<span class="kpi-delta" style="color:${dc}">${dtext}</span>` : ''}
    </div>
    <div class="kpi-value">${fmt(value)}</div>
    ${sub ? `<div class="kpi-sub">${sub}</div>` : '<div style="height:4px"></div>'}
    <div class="kpi-spark">${slData ? _sl(slData, slColor || '#3b82f6') : ''}</div>
  </div>`;
}

// ── Widget layout (localStorage) ──────────────────────────────────────────────

const _DEFAULT_WIDGETS = ['trend', 'severity', 'top_assets', 'status', 'exploit', 'activity', 'risk_age', 'accepted'];

function _loadLayout() {
  try { return JSON.parse(localStorage.getItem('dash_layout2')) || { order: [..._DEFAULT_WIDGETS], hidden: [] }; }
  catch { return { order: [..._DEFAULT_WIDGETS], hidden: [] }; }
}
function _saveLayout(l) { localStorage.setItem('dash_layout2', JSON.stringify(l)); }

// ── Dashboard page ────────────────────────────────────────────────────────────

const DashboardPage = {
  period:      localStorage.getItem('dash_period') || '7d',
  charts:      {},
  _layout:     _loadLayout(),
  _customizing: false,
  _dragSrc:    null,

  async render(el) {
    el.innerHTML = `
      <!-- Top bar: title + period selector -->
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:20px;flex-wrap:wrap;gap:10px">
        <div>
          <h2 style="font-size:18px;font-weight:700;color:var(--text-primary);margin:0">Security Dashboard</h2>
          <p style="font-size:12px;color:var(--text-muted);margin:3px 0 0" id="dash-last-updated">Loading…</p>
        </div>
        <div style="display:flex;align-items:center;gap:8px">
          <div class="period-tabs" id="period-tabs">
            ${['24h','7d','30d','1y'].map(p => `
              <button class="period-btn${this.period === p ? ' active' : ''}" onclick="DashboardPage.setPeriod('${p}')">${p}</button>
            `).join('')}
          </div>
          <button class="btn btn-secondary btn-sm" onclick="DashboardPage.toggleCustomize()" id="dash-customize-btn">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:4px">
              <circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-4 0v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83-2.83l.06-.06A1.65 1.65 0 0 0 4.68 15a1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1 0-4h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 2.83-2.83l.06.06A1.65 1.65 0 0 0 9 4.68a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 2.83l-.06.06A1.65 1.65 0 0 0 19.4 9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
            </svg>Customize
          </button>
        </div>
      </div>

      <!-- Customize panel -->
      <div id="dash-customize-panel" style="display:none;background:var(--bg-card);border:1px solid var(--border);border-radius:var(--radius-lg);padding:16px;margin-bottom:16px">
        <div style="font-size:12px;font-weight:600;color:var(--text-secondary);margin-bottom:12px">
          Toggle widgets · Drag to reorder
        </div>
        <div id="dash-widget-toggles" style="display:flex;flex-wrap:wrap;gap:8px"></div>
      </div>

      <!-- KPI cards -->
      <div class="kpi-grid" id="dash-kpi">
        ${[...Array(8)].map(() => `<div class="kpi-card kpi-skeleton"></div>`).join('')}
      </div>

      <!-- Widget grid -->
      <div class="widget-grid" id="dash-widgets"></div>
    `;

    this.reload();
  },

  async reload() {
    this._updatePeriodTabs();
    this._updateTimestamp();
    this.loadKPI();
    this._renderWidgets();
    this.updateScannerStatus();
  },

  setPeriod(p) {
    this.period = p;
    localStorage.setItem('dash_period', p);
    this.reload();
  },

  _updatePeriodTabs() {
    document.querySelectorAll('.period-btn').forEach(b => {
      b.classList.toggle('active', b.textContent.trim() === this.period);
    });
  },

  _updateTimestamp() {
    const el = document.getElementById('dash-last-updated');
    if (el) el.textContent = `Last updated: ${new Date().toLocaleTimeString()}`;
  },

  // ── KPI section ─────────────────────────────────────────────────────────────

  async loadKPI() {
    const el = document.getElementById('dash-kpi');
    if (!el) return;
    try {
      const d = await API.get('/dashboard/kpi', { period: this.period });
      const s = d.snap, m = d.metrics, sl = d.sparklines;
      const period_label = { '24h': 'last 24h', '7d': 'last 7d', '30d': 'last 30d', '1y': 'last year' }[this.period];

      el.innerHTML = [
        _kpi('total',    'Total Findings',
          s.total, `Across ${s.assets_covered.toLocaleString()} assets`,
          m.new.pct, 'down', sl.total, '#3b82f6',
          "VulnsPage.state={page:1,per_page:25,severity:'',status:'open',source:'',search:'',asset_id:null,host:'',category:'vulnerability'};navigate('vulnerabilities')"),

        _kpi('critical', 'Critical',
          s.critical, `${m.critical.v.toLocaleString()} new ${period_label}`,
          m.critical.pct, 'down', sl.critical, '#ef4444',
          "VulnsPage.state.severity='critical';VulnsPage.state.status='open';navigate('vulnerabilities')"),

        _kpi('high',     'High',
          s.high, `${m.high.v.toLocaleString()} new ${period_label}`,
          m.high.pct, 'down', sl.high, '#f97316',
          "VulnsPage.state.severity='high';VulnsPage.state.status='open';navigate('vulnerabilities')"),

        _kpi('medium',   'Medium',
          s.snap?.medium ?? s.medium, null,
          null, 'down', null, '#eab308', null),

        _kpi('assets',   'Assets Covered',
          s.assets_covered, `of ${s.total_assets.toLocaleString()} total assets`,
          null, 'up', null, '#06b6d4',
          "navigate('assets')"),

        _kpi('new',      'New Findings',
          m.new.v, period_label,
          m.new.pct, 'down', sl.total, '#8b5cf6', null),

        _kpi('remediated','Remediated',
          m.remediated.v, period_label,
          m.remediated.pct, 'up', sl.remediated, '#22c55e', null),

        _kpi('mttr',     'MTTR',
          m.mttr.v != null ? `${m.mttr.v}d` : '–', `Avg days to remediate ${period_label}`,
          m.mttr.pct, 'down', null, '#06b6d4', null),
      ].join('');

      const badge = document.getElementById('nav-badge-vulns');
      if (badge) badge.textContent = s.total;
    } catch(e) {
      console.error('KPI load failed', e);
    }
  },

  // ── Widget system ────────────────────────────────────────────────────────────

  _WIDGET_META: {
    trend:      { title: 'Vulnerability Trend' },
    severity:   { title: 'Severity Distribution', narrow: true },
    top_assets: { title: 'Top Vulnerable Assets' },
    status:     { title: 'Status Distribution', narrow: true },
    exploit:    { title: 'Exploit Intelligence', narrow: true },
    activity:   { title: 'Recent Scan Activity' },
    risk_age:   { title: 'Open Vuln Age' },
    accepted:   { title: 'Accepted Risk' },
  },

  _renderWidgets() {
    const container = document.getElementById('dash-widgets');
    if (!container) return;

    const { order, hidden } = this._layout;
    const visible = order.filter(id => !hidden.includes(id));

    container.innerHTML = visible.map(id => {
      const meta = this._WIDGET_META[id] || {};
      return `<div class="widget-card${meta.narrow ? ' widget-narrow' : ''}" id="widget-${id}"
        draggable="true"
        ondragstart="DashboardPage._wDragStart(event,'${id}')"
        ondragover="DashboardPage._wDragOver(event,'${id}')"
        ondragleave="DashboardPage._wDragLeave(event,'${id}')"
        ondrop="DashboardPage._wDrop(event,'${id}')">
        <div class="card-header" style="cursor:grab">
          <span class="card-title">${meta.title || id}</span>
          <div style="display:flex;gap:6px;align-items:center">
            ${id === 'trend' || id === 'top_assets' || id === 'accepted'
              ? `<span style="font-size:10px;color:var(--text-muted);cursor:default">period: ${this.period}</span>` : ''}
            <span class="widget-drag-handle" title="Drag to reorder">⠿</span>
          </div>
        </div>
        <div id="widget-body-${id}"></div>
      </div>`;
    }).join('');

    this._renderCustomizePanel();

    // Load each widget
    visible.forEach(id => this._loadWidget(id));
  },

  _loadWidget(id) {
    const loaders = {
      trend:      () => this.loadTrend(),
      severity:   () => this.loadSeverityDist(),
      top_assets: () => this.loadTopAssets(),
      status:     () => this.loadStatusDist(),
      exploit:    () => this.loadExploit(),
      activity:   () => this.loadActivity(),
      risk_age:   () => this.loadRiskAge(),
      accepted:   () => this.loadAccepted(),
    };
    loaders[id]?.();
  },

  _renderCustomizePanel() {
    const el = document.getElementById('dash-widget-toggles');
    if (!el) return;
    const { order, hidden } = this._layout;
    el.innerHTML = order.map(id => {
      const meta = this._WIDGET_META[id] || {};
      const isHidden = hidden.includes(id);
      return `<label style="display:flex;align-items:center;gap:6px;padding:6px 10px;background:var(--bg-secondary);border:1px solid var(--border);border-radius:6px;cursor:pointer;font-size:12px;color:var(--text-primary);user-select:none">
        <input type="checkbox" ${isHidden ? '' : 'checked'} onchange="DashboardPage._toggleWidget('${id}',this.checked)" style="accent-color:var(--accent)">
        ${meta.title || id}
      </label>`;
    }).join('');
  },

  _toggleWidget(id, visible) {
    if (visible) {
      this._layout.hidden = this._layout.hidden.filter(h => h !== id);
    } else {
      if (!this._layout.hidden.includes(id)) this._layout.hidden.push(id);
    }
    _saveLayout(this._layout);
    this._renderWidgets();
  },

  toggleCustomize() {
    this._customizing = !this._customizing;
    const panel = document.getElementById('dash-customize-panel');
    const btn   = document.getElementById('dash-customize-btn');
    if (panel) panel.style.display = this._customizing ? '' : 'none';
    if (btn)   btn.style.background = this._customizing ? 'var(--accent)' : '';
  },

  // ── Widget drag-to-reorder ────────────────────────────────────────────────

  _wDragStart(e, id) {
    this._dragSrc = id;
    e.dataTransfer.effectAllowed = 'move';
    setTimeout(() => { const el = document.getElementById(`widget-${id}`); if (el) el.style.opacity = '0.4'; }, 0);
  },

  _wDragOver(e, id) {
    e.preventDefault();
    e.dataTransfer.dropEffect = 'move';
    if (id !== this._dragSrc) {
      document.querySelectorAll('.widget-card').forEach(c => c.style.outline = '');
      const el = document.getElementById(`widget-${id}`);
      if (el) el.style.outline = '2px solid var(--accent)';
    }
  },

  _wDragLeave(e, id) {
    const el = document.getElementById(`widget-${id}`);
    if (el) el.style.outline = '';
  },

  _wDrop(e, targetId) {
    e.preventDefault();
    document.querySelectorAll('.widget-card').forEach(c => { c.style.opacity = ''; c.style.outline = ''; });
    const src = this._dragSrc; this._dragSrc = null;
    if (!src || src === targetId) return;
    const order = this._layout.order;
    const si = order.indexOf(src), ti = order.indexOf(targetId);
    if (si < 0 || ti < 0) return;
    order.splice(si, 1);
    order.splice(ti, 0, src);
    _saveLayout(this._layout);
    this._renderWidgets();
  },

  // ── Chart loaders ─────────────────────────────────────────────────────────

  async loadTrend() {
    const el = document.getElementById('widget-body-trend');
    if (!el) return;
    el.innerHTML = `<div class="chart-wrap"><canvas id="chart-trend" height="90"></canvas></div>`;
    const points = await API.get('/dashboard/trend', { period: this.period });
    const ctx = document.getElementById('chart-trend');
    if (!ctx) return;
    if (this.charts.trend) this.charts.trend.destroy();
    const mkDs = (label, key, color) => ({
      label, data: points.map(p => p[key]),
      borderColor: color, backgroundColor: color + '15',
      borderWidth: 1.5, pointRadius: 0, fill: false, tension: 0.3,
    });
    this.charts.trend = new Chart(ctx, {
      type: 'line',
      data: {
        labels: points.map(p => p.date),
        datasets: [
          mkDs('Critical', 'critical', '#ef4444'),
          mkDs('High',     'high',     '#f97316'),
          mkDs('Medium',   'medium',   '#eab308'),
          mkDs('Low',      'low',      '#22c55e'),
        ],
      },
      options: {
        responsive: true,
        interaction: { mode: 'index', intersect: false },
        scales: {
          x: { ticks: { color: '#4d5f80', font: { size: 10 }, maxTicksLimit: 10 }, grid: { color: '#1c2840' } },
          y: { ticks: { color: '#4d5f80', font: { size: 10 } }, grid: { color: '#1c2840' }, beginAtZero: true },
        },
        plugins: {
          legend: { labels: { color: '#8a9abf', font: { size: 11 }, boxWidth: 12, padding: 12 } },
        },
      },
    });
  },

  async loadSeverityDist() {
    const el = document.getElementById('widget-body-severity');
    if (!el) return;
    el.innerHTML = `<div class="chart-wrap" style="max-width:200px;margin:0 auto"><canvas id="chart-sev" height="180"></canvas></div>`;
    try {
      const d = await API.get('/dashboard/severity-distribution');
      const ctx = document.getElementById('chart-sev');
      if (!ctx) return;
      if (this.charts.sev) this.charts.sev.destroy();
      this.charts.sev = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: ['Critical','High','Medium','Low','Info'],
          datasets: [{ data: [d.critical, d.high, d.medium, d.low, d.info],
            backgroundColor: ['#ef4444','#f97316','#eab308','#22c55e','#64748b'], borderWidth: 0, hoverOffset: 6 }],
        },
        options: {
          cutout: '68%',
          plugins: {
            legend: { position: 'bottom', labels: { color: '#8a9abf', font: { size: 11 }, boxWidth: 10, padding: 12 } },
            tooltip: { callbacks: { label: c => ` ${c.label}: ${c.parsed.toLocaleString()}` } },
          },
        },
      });
    } catch {}
  },

  async loadTopAssets() {
    const el = document.getElementById('widget-body-top_assets');
    if (!el) return;
    el.innerHTML = `<div class="loader"><div class="spinner"></div></div>`;
    const items = await API.get('/dashboard/top-assets', { limit: 8 });
    if (!items.length) { el.innerHTML = emptyState('No assets found'); return; }
    el.innerHTML = `
      <table>
        <thead><tr><th>Host</th><th>IP</th><th>Criticality</th><th>Vulns</th><th>Risk</th></tr></thead>
        <tbody>${items.map(a => `
          <tr style="cursor:pointer" onclick="loadAssetDetail(${a.id})">
            <td class="primary truncate" style="max-width:130px">${a.hostname || '–'}</td>
            <td style="font-family:monospace;font-size:12px">${a.ip_address || '–'}</td>
            <td>${critBadge(a.criticality)}</td>
            <td><span style="font-weight:600;color:${a.vuln_count > 10 ? 'var(--critical)' : 'var(--text-secondary)'}">${a.vuln_count}</span></td>
            <td style="min-width:100px">
              <div class="risk-bar-wrap">
                <div class="risk-bar"><div class="risk-bar-fill ${a.risk_score > 60 ? 'critical' : a.risk_score > 30 ? 'high' : ''}" style="width:${Math.min(a.risk_score,100)}%"></div></div>
                <span class="risk-score-num">${a.risk_score.toFixed(0)}</span>
              </div>
            </td>
          </tr>`).join('')}
        </tbody>
      </table>
      <div style="text-align:right;padding:8px 0 0">
        <a class="btn btn-secondary btn-sm" onclick="navigate('assets')">View all assets →</a>
      </div>`;
  },

  async loadStatusDist() {
    const el = document.getElementById('widget-body-status');
    if (!el) return;
    el.innerHTML = `<div class="chart-wrap" style="max-width:200px;margin:0 auto"><canvas id="chart-status" height="180"></canvas></div>`;
    try {
      const d = await API.get('/dashboard/status-distribution');
      const ctx = document.getElementById('chart-status');
      if (!ctx) return;
      if (this.charts.status) this.charts.status.destroy();
      this.charts.status = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: ['Open','In Progress','Accepted','Remediated'],
          datasets: [{ data: [d.open, d.in_progress, d.accepted, d.remediated],
            backgroundColor: ['#ef4444','#f97316','#eab308','#22c55e'], borderWidth: 0, hoverOffset: 6 }],
        },
        options: {
          cutout: '68%',
          plugins: {
            legend: { position: 'bottom', labels: { color: '#8a9abf', font: { size: 11 }, boxWidth: 10, padding: 12 } },
            tooltip: { callbacks: { label: c => ` ${c.label}: ${c.parsed.toLocaleString()}` } },
          },
        },
      });
    } catch {}
  },

  async loadExploit() {
    const el = document.getElementById('widget-body-exploit');
    if (!el) return;
    try {
      const stats = await API.get('/dashboard/enrichment-stats');
      el.innerHTML = `
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;padding:8px 0">
          <div style="text-align:center;padding:16px;background:var(--bg-secondary);border-radius:8px;border:1px solid var(--border)">
            <div style="font-size:28px;font-weight:700;color:#f97316">${stats.exploit_available}</div>
            <div style="font-size:11px;color:var(--text-muted);margin-top:4px;text-transform:uppercase;letter-spacing:0.5px">Exploit Available</div>
          </div>
          <div style="text-align:center;padding:16px;background:var(--bg-secondary);border-radius:8px;border:1px solid var(--border)">
            <div style="font-size:28px;font-weight:700;color:#ef4444">${stats.cisa_kev}</div>
            <div style="font-size:11px;color:var(--text-muted);margin-top:4px;text-transform:uppercase;letter-spacing:0.5px">CISA KEV</div>
          </div>
        </div>
        ${stats.avg_vpr != null ? `
        <div style="padding:12px;background:var(--bg-secondary);border-radius:8px;border:1px solid var(--border);margin-top:4px">
          <div style="display:flex;justify-content:space-between;align-items:center">
            <span style="font-size:12px;color:var(--text-muted)">Avg VPR (open vulns)</span>
            <span style="font-size:20px;font-weight:700;color:#f97316">${stats.avg_vpr}</span>
          </div>
          <div style="margin-top:6px;background:var(--border);border-radius:4px;height:6px">
            <div style="background:#f97316;width:${Math.min(stats.avg_vpr*10,100)}%;height:100%;border-radius:4px"></div>
          </div>
        </div>` : ''}`;
    } catch {}
  },

  async loadActivity() {
    const el = document.getElementById('widget-body-activity');
    if (!el) return;
    const items = await API.get('/dashboard/recent-activity', { limit: 8 });
    const icons = { nessus:'🔵', mde:'🔷', openvas:'🟢', nmap:'🟡', pac:'🟣', aws:'🟠', nuclei:'🟤' };
    el.innerHTML = items.length ? `
      <div style="display:flex;flex-direction:column;gap:0">
        ${items.map(j => `
          <div style="display:flex;align-items:center;gap:10px;padding:9px 0;border-bottom:1px solid var(--border)">
            <span style="font-size:15px">${icons[j.scanner_type] || '⚪'}</span>
            <div style="flex:1;min-width:0">
              <div style="font-size:12.5px;font-weight:500;color:var(--text-primary)">${j.scanner}</div>
              <div style="font-size:11px;color:var(--text-muted)">${fmtDate(j.started_at)}</div>
            </div>
            <span class="status-badge status-${j.status === 'completed' ? 'remediated' : j.status === 'failed' ? 'open' : 'in_progress'}">${j.status}</span>
            <span style="font-size:11px;color:var(--text-muted);min-width:60px;text-align:right">${j.findings_count} findings</span>
          </div>`).join('')}
      </div>` : emptyState('No scan jobs yet');
  },

  async loadRiskAge() {
    const el = document.getElementById('widget-body-risk_age');
    if (!el) return;
    el.innerHTML = `<div class="chart-wrap"><canvas id="chart-age" height="100"></canvas></div>`;
    try {
      const items = await API.get('/dashboard/risk-age');
      const ctx = document.getElementById('chart-age');
      if (!ctx || !items.length) return;
      if (this.charts.age) this.charts.age.destroy();
      const colors = ['#22c55e','#eab308','#f97316','#ef4444'];
      this.charts.age = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: items.map(i => i.label),
          datasets: [{ data: items.map(i => i.count),
            backgroundColor: colors.map(c => c + 'cc'),
            borderColor: colors, borderWidth: 1, borderRadius: 4 }],
        },
        options: {
          responsive: true,
          plugins: { legend: { display: false }, tooltip: { callbacks: { label: c => ` ${c.parsed.y} vulns` } } },
          scales: {
            x: { ticks: { color: '#8a9abf', font: { size: 11 } }, grid: { color: '#1c2840' } },
            y: { ticks: { color: '#4d5f80', font: { size: 10 } }, grid: { color: '#1c2840' }, beginAtZero: true },
          },
        },
      });
    } catch {}
  },

  async loadAccepted() {
    const el = document.getElementById('widget-body-accepted');
    if (!el) return;
    try {
      const items = await API.get('/dashboard/accepted-risks', { limit: 15 });
      if (!items.length) { el.innerHTML = emptyState('No accepted risks'); return; }
      el.innerHTML = `
        <table>
          <thead><tr><th style="width:40%">Title</th><th>Severity</th><th>CVSS</th><th>VPR</th><th>Asset</th><th>Flags</th></tr></thead>
          <tbody>${items.map(v => `
            <tr style="cursor:pointer" onclick="VulnsPage.openDetail(${v.id})">
              <td class="primary truncate" style="max-width:260px" title="${esc(v.title)}">${esc(v.title)}</td>
              <td>${sevBadge(v.severity)}</td>
              <td><span class="cvss-score cvss-${v.severity}">${v.cvss_score != null ? v.cvss_score.toFixed(1) : '–'}</span></td>
              <td><span style="font-size:12px;font-weight:600;color:${v.vpr_score >= 7 ? 'var(--critical)' : v.vpr_score >= 4 ? '#f97316' : 'var(--text-muted)'}">${v.vpr_score != null ? v.vpr_score.toFixed(1) : '–'}</span></td>
              <td style="font-size:12px">${v.asset_hostname || v.asset_ip || '–'}</td>
              <td style="white-space:nowrap">
                ${v.cisa_kev_date ? `<span style="font-size:10px;background:#ef444420;color:#ef4444;border:1px solid #ef444440;border-radius:3px;padding:1px 4px;margin-right:2px">KEV</span>` : ''}
                ${v.exploit_available ? `<span style="font-size:10px;background:#f9731620;color:#f97316;border:1px solid #f9731640;border-radius:3px;padding:1px 4px">EXP</span>` : ''}
              </td>
            </tr>`).join('')}
          </tbody>
        </table>
        <div style="text-align:right;padding:8px 0 0">
          <a class="btn btn-secondary btn-sm" onclick="VulnsPage.state.status='accepted';navigate('vulnerabilities')">View all →</a>
        </div>`;
    } catch {}
  },

  async updateScannerStatus() {
    const items = await API.get('/dashboard/scanner-status');
    const el = document.getElementById('sidebar-scanner-status');
    if (!el) return;
    el.innerHTML = items.map(s => `
      <div class="scanner-pill">
        <span class="dot dot-${s.status}"></span>
        <span class="truncate" style="max-width:130px">${s.name}</span>
      </div>`).join('');
  },
};
